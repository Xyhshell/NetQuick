# -*- coding: utf-8 -*-
"""Windows API 封装 + 基础工具函数"""

import ctypes
import os
import re
import socket
import struct
import subprocess
import sys

from constants import IF_TYPE_SOFTWARE_LOOPBACK


# ---------------------------------------------------------------------------
# Windows GetIfTable2
# ---------------------------------------------------------------------------
class _MIB_IF_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceGuid", ctypes.c_ubyte * 16),
        ("Alias", ctypes.c_wchar * 257),
        ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TunnelType", ctypes.c_uint32),
        ("MediaType", ctypes.c_uint32),
        ("PhysicalMediumType", ctypes.c_uint32),
        ("AccessType", ctypes.c_uint32),
        ("DirectionType", ctypes.c_uint32),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", ctypes.c_uint32),
        ("AdminStatus", ctypes.c_uint32),
        ("MediaConnectState", ctypes.c_uint32),
        ("NetworkGuid", ctypes.c_ubyte * 16),
        ("ConnectionType", ctypes.c_uint32),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


def _with_if_table2(callback):
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        GetIfTable2 = iphlpapi.GetIfTable2
        GetIfTable2.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        GetIfTable2.restype = ctypes.c_uint32
        FreeMibTable = iphlpapi.FreeMibTable
        FreeMibTable.argtypes = [ctypes.c_void_p]
        FreeMibTable.restype = None

        table_ptr = ctypes.c_void_p()
        ret = GetIfTable2(ctypes.byref(table_ptr))
        if ret != 0 or not table_ptr.value:
            return None
        try:
            num_entries = ctypes.cast(
                table_ptr, ctypes.POINTER(ctypes.c_uint32)).contents.value
            if num_entries <= 0 or num_entries > 1000:
                return None
            base = table_ptr.value + 8
            row_size = ctypes.sizeof(_MIB_IF_ROW2)
            if row_size < 1000 or row_size > 2000:
                return None
            results = []
            for i in range(num_entries):
                row = _MIB_IF_ROW2.from_address(base + i * row_size)
                results.append(row)
            return callback(results)
        finally:
            FreeMibTable(table_ptr)
    except Exception:
        return None


def get_api_desc_map():
    """从 GetIfTable2 拿 {接口名: 设备描述}"""
    def _collect(rows):
        result = {}
        for row in rows:
            if row.Type == IF_TYPE_SOFTWARE_LOOPBACK:
                continue
            alias = (row.Alias or "").strip()
            desc = (row.Description or "").strip()
            if alias and desc and desc != alias:
                result[alias] = desc
        return result
    return _with_if_table2(_collect) or {}


def read_net_bytes_api():
    def _sum(rows):
        rx = tx = 0
        for row in rows:
            if row.OperStatus == 1:
                rx += row.InOctets
                tx += row.OutOctets
        return rx, tx
    return _with_if_table2(_sum)


_NETSTAT_NUM_RE = re.compile(r"[\d,]+")


def read_net_bytes_netstat():
    try:
        p = subprocess.run(
            ["netstat", "-e"],
            capture_output=True,
            timeout=2,
            startupinfo=hidden_startupinfo(),
        )
        out = p.stdout.decode("gbk", errors="ignore")
        for line in out.splitlines():
            s = line.strip()
            for lab in ("Bytes", "字节"):
                if s.startswith(lab):
                    nums = _NETSTAT_NUM_RE.findall(s)
                    nums = [n for n in nums if n]
                    if len(nums) >= 2:
                        try:
                            return (int(nums[0].replace(",", "")),
                                    int(nums[1].replace(",", "")))
                        except ValueError:
                            return None
    except Exception:
        pass
    return None


def read_net_bytes():
    r = read_net_bytes_api()
    return r if r is not None else read_net_bytes_netstat()


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def hidden_startupinfo():
    if os.name != "nt":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return si


def run_cmd(args, timeout=None):
    """执行命令并返回 (returncode, 输出文本)"""
    try:
        p = subprocess.run(
            args, capture_output=True,
            startupinfo=hidden_startupinfo(),
            timeout=timeout,
        )
        raw = p.stdout + b"\n" + p.stderr
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return p.returncode, raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return p.returncode, raw.decode("latin-1", errors="ignore")
    except Exception as e:
        return 1, str(e)


def is_valid_ip(s):
    if not s or s.count(".") != 3:
        return False
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack("!I", n))


def prefix_to_mask(p):
    if p <= 0:
        return "0.0.0.0"
    if p >= 32:
        return "255.255.255.255"
    return socket.inet_ntoa(struct.pack("!I", (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF))


def mask_to_prefix(mask):
    if not is_valid_ip(mask):
        return None
    bits = "".join(format(int(x), "08b") for x in mask.split("."))
    if "01" in bits:
        return None
    return bits.count("1")


def mask_display(m):
    p = mask_to_prefix(m)
    return "%s (/24)" % m if p == 24 else (
        "%s (/%d)" % (m, p) if p is not None else m)


def parse_mask_text(raw):
    if not raw:
        return None
    s = raw.strip()
    if s.startswith("/"):
        s = s[1:].strip()
    if " " in s:
        s = s.split()[0]
    if not s:
        return None
    if s.isdigit():
        n = int(s)
        return prefix_to_mask(n) if 0 <= n <= 32 else None
    return s if mask_to_prefix(s) is not None else None


def is_admin():
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    try:
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, sys.argv[1:]
        else:
            exe, params = sys.executable, sys.argv
        param_str = " ".join('"%s"' % p for p in params)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, param_str, None, 1)
        return True
    except Exception:
        return False