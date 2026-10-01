# -*- coding: utf-8 -*-
"""网卡列表和网络配置读写

兼容性策略：
  1. netsh 命令 name=xxx 不带字面引号，由 subprocess 处理空格转义。
  2. 接口名做规范化（去空白/不可见字符），避免 USB 网卡驱动写入的脏数据。
  3. netsh 失败时回退到 PowerShell 的 *-NetIPAddress / Set-DnsClientServerAddress，
     对含空格、#、&、( ) 等特殊字符的网卡名兼容性更好。
"""

import re
import time

from netutils import (
    get_api_desc_map, run_cmd, is_valid_ip, prefix_to_mask, mask_to_prefix,
)
from constants import IF_TYPE_SOFTWARE_LOOPBACK


# ---------------------------------------------------------------------------
# 名称规范化
# ---------------------------------------------------------------------------
def normalize_iface_name(name):
    """清理接口名首尾空白和不可见字符。"""
    if not name:
        return ""
    s = name.strip()
    # 不换行空格 -> 普通空格
    s = s.replace("\u00a0", " ").replace("\u3000", " ")
    # 去除控制字符
    s = "".join(ch for ch in s if ord(ch) >= 0x20)
    return s.strip()


def make_name_param(iface):
    """构造 netsh 的 name 参数。

    重要：不能手动加引号。subprocess 传参时会自动为含空格参数加引号，
    手工加引号会让引号成为字面字符，导致含空格的 USB 网卡无法被识别。
    """
    return "name=%s" % normalize_iface_name(iface)


# ---------------------------------------------------------------------------
# 网卡列表
# ---------------------------------------------------------------------------
def _get_all_iface_names_with_state():
    """用 netsh interface show interface 获取所有网卡（含禁用）。
    返回 {接口名: 'enabled'/'disabled'}，失败返回 None。
    """
    rc, out = run_cmd(["netsh", "interface", "show", "interface"])
    if rc != 0:
        return None
    states = {}
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("-"):
            continue
        if "接口名称" in s or "Interface Name" in s:
            continue
        parts = s.split(None, 3)
        if len(parts) < 4:
            continue
        admin = parts[0]
        name = normalize_iface_name(parts[3])
        if not name:
            continue
        if "回环" in name or "Loopback" in name:
            continue
        low = admin.lower()
        if "已禁用" in admin or "disabled" in low:
            states[name] = "disabled"
        elif "已启用" in admin or "enabled" in low:
            states[name] = "enabled"
    return states if states else None


def list_interfaces():
    """返回 [(显示名, 真实接口名), ...]"""
    states = _get_all_iface_names_with_state()
    all_names = list(states.keys()) if states else []
    desc_map = get_api_desc_map()

    if all_names:
        result = []
        for name in all_names:
            desc = desc_map.get(name, "")
            if desc and desc != name:
                result.append(("%s （%s）" % (name, desc), name))
            else:
                result.append((name, name))
        return result

    # 回退：从 API 获取
    from netutils import _with_if_table2

    def _collect(rows):
        result = []
        for row in rows:
            if row.Type == IF_TYPE_SOFTWARE_LOOPBACK:
                continue
            alias = normalize_iface_name(row.Alias or "")
            desc = (row.Description or "").strip()
            if not alias:
                continue
            if desc and desc != alias:
                result.append(("%s （%s）" % (alias, desc), alias))
            else:
                result.append((alias, alias))
        return result if result else None

    pairs = _with_if_table2(_collect)
    if pairs:
        return pairs

    names = []
    rc, out = run_cmd(["netsh", "interface", "ipv4", "show", "interfaces"])
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            parts = line.split(None, 4)
            if len(parts) < 5 or not parts[0].isdigit():
                continue
            name = normalize_iface_name(parts[4])
            if "Loopback" in name or "回环" in name:
                continue
            names.append(name)
    return [(n, n) for n in names]


def get_iface_admin_state(iface):
    states = _get_all_iface_names_with_state()
    if states is None:
        return "unknown"
    return states.get(normalize_iface_name(iface), "unknown")


def set_iface_admin_state(iface, enable):
    """启用/禁用网卡。netsh 失败时回退 PowerShell。"""
    name = normalize_iface_name(iface)
    n = make_name_param(name)
    action = "enable" if enable else "disable"
    rc, out = run_cmd(
        ["netsh", "interface", "set", "interface", n, "admin=%s" % action]
    )
    if rc == 0:
        return True, out.strip()

    # PowerShell 回退
    safe = name.replace("'", "''")
    ps_action = "Enable-NetAdapter" if enable else "Disable-NetAdapter"
    ps = "%s -Name '%s' -Confirm:$false -ErrorAction Stop" % (ps_action, safe)
    rc2, out2 = run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-Command", ps], timeout=20)
    if rc2 == 0:
        return True, ""
    return False, (out.strip() + "\n[PowerShell 回退也失败] " + out2.strip())


def detect_default_gateway():
    rc, out = run_cmd(["ipconfig"])
    if rc != 0:
        return None
    m = re.search(r"(?:默认网关|Default Gateway)[\s.:]*([\d.]+)", out)
    if m and m.group(1) != "0.0.0.0":
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# 读取网卡当前配置
# ---------------------------------------------------------------------------
def get_iface_config(iface):
    """读取接口当前 IPv4 配置。返回 dict 或 None。"""
    name = normalize_iface_name(iface)
    n = make_name_param(name)
    rc, out = run_cmd(["netsh", "interface", "ipv4", "show", "config", n])
    if rc != 0 or not out.strip():
        return None

    cfg = {"ip": "", "mask": "", "gateway": "",
           "dns1": "", "dns2": "", "dhcp": False}
    all_dns = []
    in_dns_block = False

    for line in out.splitlines():
        s = line.strip()
        if not s:
            in_dns_block = False
            continue

        m = re.search(r"(?:DHCP enabled|DHCP 已启用)\s*[:：]\s*(\S+)", s)
        if m:
            cfg["dhcp"] = m.group(1).lower() in ("yes", "是")
            in_dns_block = False
            continue

        m = re.search(
            r"(?:DNS servers configured through DHCP|"
            r"Statically Configured DNS Servers|"
            r"通过 DHCP 配置的 DNS 服务器|"
            r"静态配置的 DNS 服务器|"
            r"DNS servers|DNS 服务器)\s*[:：]\s*(.*)$",
            s)
        if m:
            all_dns.extend(re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(1)))
            in_dns_block = True
            continue

        if re.search(r"(?:IP Address|IP 地址|Subnet Prefix|子网前缀|"
                     r"Default Gateway|默认网关|Interface|接口)\s*[:：]", s):
            in_dns_block = False

        m = re.search(r"(?:IP Address|IP 地址)\s*[:：]\s*([\d.]+)", s)
        if m:
            cfg["ip"] = m.group(1)
            continue

        m = re.search(
            r"(?:Subnet Prefix|子网前缀)\s*[:：]\s*[\d.]+\s*/\s*\d+\s*"
            r"(?:\(mask\s+|（掩码\s*)([\d.]+)", s)
        if m:
            cfg["mask"] = m.group(1)
            continue
        m = re.search(
            r"(?:Subnet Prefix|子网前缀)\s*[:：]\s*[\d.]+\s*/\s*(\d+)", s)
        if m and not cfg["mask"]:
            cfg["mask"] = prefix_to_mask(int(m.group(1)))
            continue

        m = re.search(r"(?:Default Gateway|默认网关)\s*[:：]\s*([\d.]+)", s)
        if m:
            cfg["gateway"] = m.group(1)
            continue

        if in_dns_block:
            all_dns.extend(re.findall(r"\d+\.\d+\.\d+\.\d+", s))

    if all_dns:
        seen, uniq = set(), []
        for d in all_dns:
            if d not in seen:
                seen.add(d)
                uniq.append(d)
        cfg["dns1"] = uniq[0] if len(uniq) > 0 else ""
        cfg["dns2"] = uniq[1] if len(uniq) > 1 else ""

    return cfg


# ---------------------------------------------------------------------------
# netsh 命令构建
# ---------------------------------------------------------------------------
BENIGN_DHCP = ("已在此接口上启用", "已经启用", "already enabled")
BENIGN_NOTFOUND = ("无法找到", "找不到", "not find", "not found",
                   "does not exist", "不存在")


def build_commands(iface, cfg, dhcp=False):
    """返回 [(cmd_list, ignore_flag), ...]"""
    n = make_name_param(iface)
    if dhcp:
        return [
            (["netsh", "interface", "ipv4", "set", "address", n, "source=dhcp"],
             "dhcp_enabled"),
            (["netsh", "interface", "ipv4", "set", "dnsservers", n, "source=dhcp"],
             "dhcp_enabled"),
        ]

    cmds = []
    addr = ["netsh", "interface", "ipv4", "set", "address", n,
            "static", cfg["ip"], cfg["mask"]]
    if cfg.get("gateway"):
        addr.append(cfg["gateway"])
    cmds.append((addr, None))

    cmds.append((["netsh", "interface", "ipv4", "delete", "dnsservers", n, "all"],
                 "not_found"))
    if cfg.get("dns1"):
        cmds.append((["netsh", "interface", "ipv4", "set", "dnsservers", n,
                      "static", cfg["dns1"], "primary"], None))
    if cfg.get("dns2"):
        cmds.append((["netsh", "interface", "ipv4", "add", "dnsservers", n,
                      cfg["dns2"], "index=2"], None))
    return cmds


def should_ignore(flag, out):
    if not flag:
        return False
    low = out.lower()
    if flag == "dhcp_enabled":
        return any(k.lower() in low for k in BENIGN_DHCP)
    if flag == "not_found":
        return any(k.lower() in low for k in BENIGN_NOTFOUND)
    return False


# ---------------------------------------------------------------------------
# PowerShell 回退
# ---------------------------------------------------------------------------
def _try_powershell(iface, cfg, dhcp=False):
    """当 netsh 失败时，用 PowerShell 尝试配置。"""
    name = normalize_iface_name(iface)
    safe = name.replace("'", "''")  # PS 单引号转义

    try:
        if dhcp:
            ps = (
                "Set-NetIPInterface -InterfaceAlias '%s' -Dhcp Enabled "
                "-ErrorAction SilentlyContinue; "
                "Remove-NetIPAddress -InterfaceAlias '%s' -Confirm:$false "
                "-ErrorAction SilentlyContinue; "
                "Remove-NetRoute -InterfaceAlias '%s' -Confirm:$false "
                "-ErrorAction SilentlyContinue; "
                "Set-DnsClientServerAddress -InterfaceAlias '%s' "
                "-ResetServerAddresses -ErrorAction SilentlyContinue"
            ) % (safe, safe, safe, safe)
        else:
            ip = cfg.get("ip", "")
            mask = cfg.get("mask", "")
            gw = cfg.get("gateway", "")
            dns1 = cfg.get("dns1", "")
            dns2 = cfg.get("dns2", "")
            plen = mask_to_prefix(mask)
            if plen is None:
                return False, "掩码无效"

            cmds = [
                "Set-NetIPInterface -InterfaceAlias '%s' -Dhcp Disabled "
                "-ErrorAction SilentlyContinue" % safe,
                "Remove-NetIPAddress -InterfaceAlias '%s' -Confirm:$false "
                "-ErrorAction SilentlyContinue" % safe,
                "Remove-NetRoute -InterfaceAlias '%s' -Confirm:$false "
                "-ErrorAction SilentlyContinue" % safe,
            ]

            if gw:
                cmds.append(
                    "New-NetIPAddress -InterfaceAlias '%s' -IPAddress %s "
                    "-PrefixLength %d -DefaultGateway %s -ErrorAction Stop"
                    % (safe, ip, plen, gw))
            else:
                cmds.append(
                    "New-NetIPAddress -InterfaceAlias '%s' -IPAddress %s "
                    "-PrefixLength %d -ErrorAction Stop"
                    % (safe, ip, plen))

            if dns1 and dns2:
                cmds.append(
                    "Set-DnsClientServerAddress -InterfaceAlias '%s' "
                    "-ServerAddresses %s,%s -ErrorAction Stop"
                    % (safe, dns1, dns2))
            elif dns1:
                cmds.append(
                    "Set-DnsClientServerAddress -InterfaceAlias '%s' "
                    "-ServerAddresses %s -ErrorAction Stop"
                    % (safe, dns1))
            else:
                cmds.append(
                    "Set-DnsClientServerAddress -InterfaceAlias '%s' "
                    "-ResetServerAddresses -ErrorAction SilentlyContinue"
                    % safe)

            ps = "; ".join(cmds)

        rc, out = run_cmd(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", ps], timeout=30)
        if rc != 0:
            return False, out.strip()
        return True, ""
    except Exception as e:
        return False, str(e)


def execute_config(iface, cfg, dhcp=False):
    """
    统一执行网卡配置。
    返回 (success, error_message, used_fallback)
    """
    # 尝试 netsh
    net_err = ""
    for cmd, flag in build_commands(iface, cfg, dhcp):
        rc, out = run_cmd(cmd)
        if rc != 0 and not should_ignore(flag, out):
            net_err = out.strip()
            break
    else:
        return True, "", False

    # netsh 失败，尝试 PowerShell
    ok, ps_err = _try_powershell(iface, cfg, dhcp)
    if ok:
        return True, "", True
    return False, net_err + "\n[PowerShell 回退也失败] " + ps_err, False