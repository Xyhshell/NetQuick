# -*- coding: utf-8 -*-
"""延迟检测 + 下载测速"""

import random
import socket
import ssl
import struct
import threading
import time
import urllib.request
import re

from netutils import run_cmd
from constants import (
    SPEED_CHUNK, SPEED_DURATION, SPEED_WARMUP, SPEED_MIN_BYTES,
    SPEED_CONNECT_GRACE, SPEED_SAMPLE_INTERVAL, SPEED_DISPLAY_WINDOW,
    SPEED_THREADS,
)

_PING_TIME_RE = re.compile(
    r"(?:时间|time)[\s:]*([=<])\s*(\d+)\s*ms",
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# 延迟
# ---------------------------------------------------------------------------
def icmp_ping_once(host, timeout_ms=1500):
    try:
        rc, out = run_cmd(
            ["ping", "-n", "1", "-w", str(timeout_ms), "-4", host],
            timeout=timeout_ms / 1000.0 + 2,
        )
        m = _PING_TIME_RE.search(out)
        if m:
            op, val = m.group(1), int(m.group(2))
            return 0 if op == "<" else val
        return None
    except Exception:
        return None


def tcp_latency(host, port, timeout=1.5):
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return (time.time() - start) * 1000
    except Exception:
        return None


def dns_latency(host, timeout=2.0):
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in "example.com".split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            start = time.time()
            s.sendto(q, (host, 53))
            s.recvfrom(512)
            return (time.time() - start) * 1000
    except Exception:
        return None


def latency_once(host, kind="dns", timeout_ms=1500):
    t = icmp_ping_once(host, timeout_ms)
    if t is not None:
        return t
    if kind == "dns":
        t = dns_latency(host, timeout_ms / 1000.0)
        if t is not None:
            return t
        for port in (53, 80, 443):
            t = tcp_latency(host, port, timeout_ms / 1000.0)
            if t is not None:
                return t
    elif kind == "gw":
        for port in (80, 443, 53):
            t = tcp_latency(host, port, timeout_ms / 1000.0)
            if t is not None:
                return t
    else:
        for port in (443, 80, 53):
            t = tcp_latency(host, port, timeout_ms / 1000.0)
            if t is not None:
                return t
    return None


def ping_stats(host, kind="dns", count=4, timeout_ms=1500, stop_flag=None):
    times, lost = [], 0
    for _ in range(count):
        if stop_flag and stop_flag():
            break
        t = latency_once(host, kind, timeout_ms)
        if t is None:
            lost += 1
        else:
            times.append(t)
    if not times:
        return {"min": None, "avg": None, "max": None, "loss": 100.0}
    return {"min": min(times), "avg": sum(times) / len(times),
            "max": max(times), "loss": lost * 100.0 / count}


def fmt_ms(v):
    if v is None:
        return "超时"
    return "<1" if v < 1 else "%.0f" % round(v)


# ---------------------------------------------------------------------------
# 下载测速
# ---------------------------------------------------------------------------
def make_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )


def _speed_worker(url, stop_evt, counter, lock, stats):
    opener = make_opener()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Cache-Control": "no-cache",
        "Accept-Encoding": "identity",
        "Connection": "keep-alive",
    }
    while not stop_evt.is_set():
        try:
            req = urllib.request.Request(url, headers=headers)
            with opener.open(req, timeout=10) as resp:
                with lock:
                    stats["active_conns"] += 1
                    stats["connected"] = True
                try:
                    while not stop_evt.is_set():
                        chunk = resp.read(SPEED_CHUNK)
                        if not chunk:
                            break
                        with lock:
                            counter[0] += len(chunk)
                finally:
                    with lock:
                        stats["active_conns"] -= 1
        except Exception as e:
            with lock:
                stats["last_error"] = str(e)
            if stop_evt.is_set():
                break
            time.sleep(0.15)


def _trimmed_peak(intervals):
    if not intervals:
        return 0.0
    s = sorted(intervals)
    idx = min(len(s) - 1, int(len(s) * 0.9))
    return s[idx]


def _stability(intervals):
    if len(intervals) < 4:
        return None
    s = sorted(intervals)
    q1 = s[len(s) // 4]
    q3 = s[len(s) * 3 // 4]
    median = s[len(s) // 2]
    if median <= 1.0:
        return None
    cv = (q3 - q1) / (2.0 * median)
    return max(0.0, min(100.0, 100.0 * (1.0 - cv)))


def measure_speed(url, cancel_evt, on_tick, threads=SPEED_THREADS,
                  duration=SPEED_DURATION, warmup=SPEED_WARMUP):
    """多连接下载测速。"""
    stop_evt = threading.Event()
    lock = threading.Lock()
    counter = [0]
    stats = {"active_conns": 0, "last_error": None, "connected": False}

    def worker():
        _speed_worker(url, stop_evt, counter, lock, stats)

    workers = [threading.Thread(target=worker, daemon=True,
                                 name="SpeedWorker-%d" % i)
               for i in range(max(1, int(threads)))]
    for t in workers:
        t.start()

    samples = []
    start = time.monotonic()
    deadline_no_data = start + SPEED_CONNECT_GRACE
    last_sample_t = start

    try:
        while True:
            time.sleep(0.05)
            now = time.monotonic()
            if cancel_evt.is_set():
                break

            elapsed = now - start
            if elapsed >= duration:
                break

            with lock:
                total = counter[0]
                active = stats["active_conns"]
                connected = stats["connected"]

            if total == 0 and now >= deadline_no_data and active == 0:
                err = stats["last_error"] or ("未收到任何数据" if connected
                                              else "无法建立连接")
                raise RuntimeError(err)

            if now - last_sample_t >= SPEED_SAMPLE_INTERVAL:
                samples.append((now, total))
                last_sample_t = now

                if on_tick:
                    window_start = now - SPEED_DISPLAY_WINDOW
                    base = None
                    for ts, bts in reversed(samples[:-1]):
                        if ts <= window_start:
                            base = (ts, bts)
                            break
                    if base is None and len(samples) >= 2:
                        base = samples[max(0, len(samples) - 5)]
                    if base is None:
                        inst = 0.0
                    else:
                        dt = now - base[0]
                        db = total - base[1]
                        inst = max(0.0, db * 8.0 / max(dt, 1e-6) / 1e6)
                    on_tick(elapsed, total, inst)
    finally:
        stop_evt.set()
        for t in workers:
            t.join(timeout=1.5)

    total_bytes = counter[0]
    if total_bytes < SPEED_MIN_BYTES:
        raise RuntimeError(stats["last_error"] or "下载数据过少，测速失败")

    if len(samples) < 2:
        raise RuntimeError("采样数据不足")

    effective_start = start + (0.0 if cancel_evt.is_set() else warmup)
    stable = [s for s in samples if s[0] >= effective_start]
    if len(stable) < 2:
        stable = samples
    if len(stable) < 2:
        raise RuntimeError("采样数据不足")

    e0, b0 = stable[0]
    e1, b1 = stable[-1]
    dt_total = e1 - e0
    if dt_total <= 0 or b1 <= b0:
        raise RuntimeError("有效测速区间数据不足")
    avg = (b1 - b0) * 8.0 / dt_total / 1e6

    intervals = []
    for i in range(1, len(stable)):
        de = stable[i][0] - stable[i - 1][0]
        db = stable[i][1] - stable[i - 1][1]
        if de > 0 and db >= 0:
            intervals.append(db * 8.0 / de / 1e6)

    peak = _trimmed_peak(intervals)
    stability = _stability(intervals)
    elapsed = samples[-1][0] - start

    return {"avg": avg, "peak": peak, "stability": stability,
            "total_bytes": total_bytes, "elapsed": elapsed}


def fmt_speed(v):
    if v is None:
        return "-- Mbps"
    if v >= 1000:
        return "%.0f Mbps" % v
    if v >= 100:
        return "%.1f Mbps" % v
    if v >= 10:
        return "%.2f Mbps" % v
    return "%.3f Mbps" % v


def normalize_url(url):
    u = (url or "").strip()
    if not u:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    return u


def derive_lan_sources(ip, mask, gateway):
    from netutils import is_valid_ip, ip_to_int, int_to_ip
    sources = []
    seen = set()

    def _add(name, url):
        if url and url not in seen:
            seen.add(url)
            sources.append((name, url))

    if gateway and is_valid_ip(gateway):
        _add("网关", "http://%s/test.bin" % gateway)
        _add("网关:8080", "http://%s:8080/test.bin" % gateway)

    if ip and mask and is_valid_ip(ip) and is_valid_ip(mask):
        try:
            ip_int = ip_to_int(ip)
            mask_int = ip_to_int(mask)
            net = ip_int & mask_int
            bcast = net | (~mask_int & 0xFFFFFFFF)
            for offset, tag, port in (
                (1,   "同网段 .1",   None),
                (10,  "同网段 .10",  8080),
                (100, "同网段 .100", None),
                (200, "同网段 .200", 8080),
            ):
                cand = net + offset
                if cand >= bcast:
                    continue
                cand_ip = int_to_ip(cand)
                if cand_ip == gateway or cand_ip == ip:
                    continue
                url = ("http://%s:%d/test.bin" % (cand_ip, port)
                       if port else "http://%s/test.bin" % cand_ip)
                _add(tag, url)
        except Exception:
            pass

    if not sources:
        _add("示例（请修改）", "http://192.168.1.10:8080/test.bin")
    return sources