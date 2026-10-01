# -*- coding: utf-8 -*-
"""网卡配置备份栈

每个网卡单独一个栈，只保留最近 MAX_PER_IFACE 份快照。
快照内容就是 get_iface_config() 的返回值，含 dhcp 标志。
"""

import json
import time

from constants import CONFIG_FILE

BACKUP_FILE = CONFIG_FILE.parent / "backups.json"
MAX_PER_IFACE = 5


def _load_all():
    try:
        if BACKUP_FILE.exists():
            return json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_all(data):
    try:
        BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
        BACKUP_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8")
        return True
    except Exception:
        return False


def push(iface, cfg):
    """把一份配置快照压入网卡的备份栈"""
    data = _load_all()
    stack = data.setdefault(iface, [])
    stack.append({"ts": time.time(), "cfg": dict(cfg)})
    if len(stack) > MAX_PER_IFACE:
        stack = stack[-MAX_PER_IFACE:]
    data[iface] = stack
    return _save_all(data)


def peek(iface):
    stack = _load_all().get(iface, [])
    return stack[-1] if stack else None


def pop(iface):
    data = _load_all()
    stack = data.get(iface, [])
    if not stack:
        return None
    last = stack.pop()
    data[iface] = stack
    _save_all(data)
    return last


def has(iface):
    return peek(iface) is not None


def clear(iface):
    data = _load_all()
    data.pop(iface, None)
    return _save_all(data)