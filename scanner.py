# -*- coding: utf-8 -*-
"""网段扫描 + 设备识别（精准版）

端口语法：
  支持 "80,443,1-1024,3306" 等混合写法，含范围展开。
  范围上限 PORT_RANGE_LIMIT，防止用户误输 1-65535 拖垮扫描。
"""

import re
import socket
import subprocess
import threading
import time

from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from netutils import (
    run_cmd, is_valid_ip, ip_to_int, int_to_ip, hidden_startupinfo,
    prefix_to_mask,
)
from oui import OUI_VENDORS

MAC_RE = re.compile(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(\d+\.\d+\.\d+\.\d+)\b")

# 端口范围展开上限（防止 1-65535 这类输入）
PORT_RANGE_LIMIT = 1024


def parse_port_list(text):
    """
    解析端口列表。支持：
      · 单个端口：80,443
      · 端口范围：1-1024
      · 混合：22,80-88,3306
    返回排序后的端口列表。
    """
    ports = set()
    for part in re.split(r"[,，\s]+", (text or "").strip()):
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                a = max(1, a)
                b = min(65535, b)
                if b - a + 1 > PORT_RANGE_LIMIT:
                    b = a + PORT_RANGE_LIMIT - 1
                for p in range(a, b + 1):
                    ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)


def subnet_range(ip, mask):
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(mask)
    net = ip_int & mask_int
    bcast = net | (~mask_int & 0xFFFFFFFF)
    return net + 1, bcast - 1


def parse_scan_range(text):
    """
    解析扫描范围。支持：
      - 单 IP:    192.168.1.5
      - CIDR:     192.168.1.0/24
      - 完整区间: 192.168.1.1-192.168.1.100
      - 简写区间: 192.168.1.1-100
    返回 (start_int, end_int) 或 None
    """
    s = (text or "").strip()
    if not s:
        return None

    if "/" in s:
        try:
            ip, pre = s.split("/", 1)
            ip, pre = ip.strip(), int(pre.strip())
            if not (is_valid_ip(ip) and 0 <= pre <= 32):
                return None
            return subnet_range(ip, prefix_to_mask(pre))
        except Exception:
            return None

    if "-" in s:
        left, right = s.split("-", 1)
        left, right = left.strip(), right.strip()
        if not is_valid_ip(left):
            return None
        if is_valid_ip(right):
            s_i, e_i = ip_to_int(left), ip_to_int(right)
            if s_i > e_i:
                s_i, e_i = e_i, s_i
            return s_i, e_i
        if right.isdigit():
            parts = left.split(".")
            if len(parts) == 4:
                try:
                    a, b, c = int(parts[0]), int(parts[1]), int(parts[2])
                    d1, d2 = int(parts[3]), int(right)
                    if not (0 <= d1 <= 255 and 0 <= d2 <= 255):
                        return None
                    lo, hi = min(d1, d2), max(d1, d2)
                    return (ip_to_int("%d.%d.%d.%d" % (a, b, c, lo)),
                            ip_to_int("%d.%d.%d.%d" % (a, b, c, hi)))
                except Exception:
                    return None
        return None

    if is_valid_ip(s):
        n = ip_to_int(s)
        return n, n

    return None


def get_arp_table():
    """返回 {ip: mac}"""
    table = {}
    try:
        rc, out = run_cmd(["arp", "-a"])
        if rc != 0:
            return table
        for line in out.splitlines():
            ip_m = IP_RE.search(line)
            mac_m = MAC_RE.search(line)
            if ip_m and mac_m:
                ip = ip_m.group(1)
                mac = mac_m.group(0).replace("-", ":").upper()
                if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                    table[ip] = mac
    except Exception:
        pass
    return table


def mac_vendor(mac):
    if not mac or len(mac) < 8:
        return ""
    mac_u = mac.upper()
    return OUI_VENDORS.get(mac_u[:8], OUI_VENDORS.get(mac_u[:5], ""))


def resolve_hostname(ip, timeout=0.5):
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return ""


def _hostname_hint(hostname):
    hn = (hostname or "").lower()
    if not hn:
        return ""
    if any(k in hn for k in ("synology", "qnap", "nas", "dsm", "openmediavault")):
        return "NAS"
    if any(k in hn for k in ("router", "openwrt", "dd-wrt", "padavan",
                              "asus", "tplink", "tenda", "mercury",
                              "mi-router", "xiaomi-router", "miwifi",
                              "huawei-router", "honor-router")):
        return "路由器"
    if any(k in hn for k in ("printer", "print", "hp-", "epson", "brother",
                              "canon", "xerox", "ricoh")):
        return "打印机"
    if any(k in hn for k in ("camera", "ipcam", "ipc", "hikvision",
                              "dahua", "rtsp", "onvif", "cam-")):
        return "摄像头"
    if any(k in hn for k in ("vmware", "virtualbox", "vbox", "qemu",
                              "hyper-v", "xen", "kvm")):
        return "虚拟机"
    if any(k in hn for k in ("android", "iphone", "ipad", "phone",
                              "mobile", "redmi", "honor", "huawei-",
                              "xiaomi-", "oppo", "vivo", "oneplus")):
        return "手机/平板"
    if any(k in hn for k in ("desktop", "laptop", "pc-", "-pc",
                              "workstation", "thinkpad", "macbook",
                              "imac", "surface")):
        return "电脑"
    if any(k in hn for k in ("server", "srv", "db-", "web-", "app-")):
        return "服务器"
    if any(k in hn for k in ("esp", "esp32", "esp8266", "tuya",
                              "smart", "iot", "shelly", "sonoff")):
        return "IoT 设备"
    if any(k in hn for k in ("tv", "androidtv", "appletv", "firetv",
                              "mi-box", "tvbox", "shield")):
        return "电视盒子"
    return ""


def guess_device_type(ports, mac, hostname=""):
    ports_set = set(ports or [])
    hn = (hostname or "").lower()
    vendor = mac_vendor(mac) if mac else ""

    if vendor:
        if any(k in vendor for k in ("VMware", "VirtualBox", "QEMU",
                                      "Hyper-V", "Xen")):
            return "虚拟机"
        if "Synology" in vendor or "QNAP" in vendor:
            return "NAS"
        if "Raspberry Pi" in vendor:
            return "树莓派"
        if "Hikvision" in vendor or "Dahua" in vendor:
            return "摄像头"
        if "Espressif" in vendor:
            return "IoT 设备 (ESP32)"
        if "Apple" in vendor:
            if 62078 in ports_set:
                return "iPhone/iPad"
            if 88 in ports_set or 3689 in ports_set:
                return "Apple TV"
            if 22 in ports_set or 445 in ports_set:
                return "Mac 电脑"
            return "Apple 设备"
        if any(k in vendor for k in ("Huawei", "Honor")):
            return "华为设备"
        if "Xiaomi" in vendor:
            if 54321 in ports_set:
                return "小米路由器"
            if 5555 in ports_set:
                return "小米电视/盒子"
            return "小米设备"
        if "Samsung" in vendor:
            if 8001 in ports_set or 8002 in ports_set:
                return "三星电视"
            return "三星设备"
        if "Sony" in vendor:
            return "PlayStation" if "PS" in vendor else "索尼设备"
        if "Microsoft" in vendor and "Xbox" in vendor:
            return "Xbox"
        if any(k in vendor for k in ("Epson", "Brother", "Xerox", "HP",
                                      "Ricoh", "Canon", "Printer")):
            return "打印机"
        if any(k in vendor for k in ("Sonos", "Squeezebox", "Amazon")):
            return "智能音箱"
        if any(k in vendor for k in ("TP-Link", "Tenda", "D-Link",
                                      "Netgear", "Cisco", "H3C",
                                      "Ruijie", "Edimax", "Ralink")):
            return "路由器/网络设备"
        if "Google" in vendor:
            if 8008 in ports_set or 8009 in ports_set:
                return "Google Cast"
            return "Google 设备"

    hn_type = _hostname_hint(hn)
    if hn_type:
        return hn_type

    if 554 in ports_set or 8554 in ports_set:
        return "摄像头 (RTSP)"
    if 9100 in ports_set or 515 in ports_set or 631 in ports_set:
        return "打印机"
    if 3389 in ports_set:
        return "Windows 主机"
    if 445 in ports_set or 139 in ports_set:
        if 5000 in ports_set or 5001 in ports_set:
            return "NAS"
        return "Windows/NAS"
    if ports_set & {5000, 5001, 5005, 5006}:
        return "NAS"
    if ports_set & {3306, 5432, 1433, 6379, 27017}:
        return "数据库服务"
    if 22 in ports_set and (ports_set & {80, 443, 8080, 8443}):
        return "Linux 服务器"
    if 22 in ports_set:
        return "SSH 设备"
    if 53 in ports_set:
        return "DNS 服务"
    if ports_set & {80, 443, 8080, 8000, 8443}:
        return "Web 设备"
    return "未知"


# ---------------------------------------------------------------------------
# 精确扫描
# ---------------------------------------------------------------------------
def probe_ping(ip, timeout_ms=500):
    try:
        p = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), "-4", ip],
            capture_output=True,
            timeout=timeout_ms / 1000.0 + 1.0,
            startupinfo=hidden_startupinfo(),
        )
        return p.returncode == 0
    except Exception:
        return False


def probe_tcp_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_host(ip, ports, timeout, strict=True):
    """
    单主机扫描。返回 (open_ports, ping_alive)

    strict=True : 仅当 ping 通过才探测端口，避免误报杂乱设备。
    strict=False: 无论 ping 是否通都探测端口。
    """
    ping_alive = probe_ping(ip)
    open_ports = []
    if strict and not ping_alive:
        return open_ports, ping_alive
    for port in ports:
        if probe_tcp_port(ip, port, timeout):
            open_ports.append(port)
    return open_ports, ping_alive


def scan_subnet(start_int, end_int, ports, timeout, max_threads,
                on_result, on_progress, stop_flag):
    """并发扫描 [start_int, end_int]。"""
    total = end_int - start_int + 1
    done = [0]
    lock = threading.Lock()

    def _task(ip_str):
        if stop_flag():
            return ip_str, [], False
        open_ports, alive = scan_host(ip_str, ports, timeout, strict=True)
        return ip_str, open_ports, alive

    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        futures = {}
        for i in range(start_int, end_int + 1):
            if stop_flag():
                break
            futures[ex.submit(_task, int_to_ip(i))] = i

        pending = set(futures.keys())
        while pending:
            if stop_flag():
                for f in pending:
                    f.cancel()
                break
            finished, pending = wait(pending, timeout=0.2,
                                     return_when=FIRST_COMPLETED)
            for fut in finished:
                try:
                    ip, open_ports, alive = fut.result()
                except Exception:
                    ip, open_ports, alive = None, [], False
                with lock:
                    done[0] += 1
                    cur_done = done[0]
                if ip and (alive or open_ports):
                    on_result(ip, open_ports)
                on_progress(cur_done, total)