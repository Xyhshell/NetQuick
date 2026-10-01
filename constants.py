# -*- coding: utf-8 -*-
"""全局常量定义"""

from pathlib import Path

APP_NAME = "网络切换器 V0.5   By: jingmo"
CONFIG_FILE = Path.home() / ".net_switcher" / "configs.json"

FIELD_WIDTH = 20

COMMON_DNS = [
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "119.29.29.29", "182.254.116.116",
    "180.76.76.76",
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "101.226.4.6", "218.30.118.6",
    "123.125.81.6", "140.207.198.6",
    "192.168.1.1", "192.168.0.1", "10.0.0.1",
]

COMMON_MASKS = [
    "255.255.255.0", "255.255.0.0", "255.0.0.0",
    "255.255.255.128", "255.255.255.192", "255.255.255.224",
    "255.255.255.240", "255.255.255.248", "255.255.255.252",
    "255.255.255.254", "255.255.255.255",
    "255.255.254.0", "255.255.252.0", "255.255.248.0",
    "255.255.240.0", "255.255.224.0", "255.255.192.0",
    "255.255.128.0", "255.254.0.0", "255.240.0.0",
]

SPEED_SOURCES = {
    "cn": [
        ("阿里云镜像",   "https://mirrors.aliyun.com/ubuntu/ls-lR.gz"),
        ("腾讯云镜像",   "https://mirrors.cloud.tencent.com/ubuntu/ls-lR.gz"),
        ("华为云镜像",   "https://mirrors.huaweicloud.com/ubuntu/ls-lR.gz"),
        ("网易镜像",     "https://mirrors.163.com/ubuntu/ls-lR.gz"),
        ("南京大学镜像", "https://mirrors.nju.edu.cn/ubuntu/ls-lR.gz"),
        ("中科大镜像",   "https://mirrors.ustc.edu.cn/ubuntu/ls-lR.gz"),
        ("清华镜像",     "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ls-lR.gz"),
    ],
    "intl": [
        ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=500000000"),
        ("Hetzner",    "https://speed.hetzner.de/100MB.bin"),
        ("Tele2",      "http://speedtest.tele2.net/100MB.zip"),
        ("OVH",        "http://proof.ovh.net/files/100Mb.dat"),
    ],
    "lan": [
        ("示例（请修改）", "http://192.168.1.10:8080/test.bin"),
    ],
}
REGION_LABEL = {"cn": "国内", "intl": "国外", "lan": "内网", "custom": "自定义"}

LAN_TIP = ("内网测速请在目标设备上放一个较大文件（建议 ≥ 500 MB），"
           "如 NAS 共享目录、Nginx/Apache 静态文件、iPerf3 HTTP 模式等，"
           "然后把下载地址填到下方。")

SPEED_THREADS = 16
SPEED_DURATION = 10.0
SPEED_WARMUP = 3.0
SPEED_CHUNK = 1024 * 1024
SPEED_MIN_BYTES = 500000
SPEED_CONNECT_GRACE = 8.0
SPEED_SAMPLE_INTERVAL = 0.25
SPEED_DISPLAY_WINDOW = 1.0

RT_INTERVAL = 1.0

IF_TYPE_SOFTWARE_LOOPBACK = 24

# ---- 网段扫描 ----
DEFAULT_SCAN_PORTS = (
    "21,22,23,25,53,80,110,135,139,143,443,445,465,587,631,993,995,"
    "1080,1433,1521,2049,3306,3389,5000,5001,5432,5555,5900,6379,"
    "8000,8006,8080,8081,8443,8888,9000,9090,9100,27017,32400,50000,62078"
)
DEFAULT_SCAN_TIMEOUT = 0.35
DEFAULT_SCAN_THREADS = 60
MAX_SCAN_HOSTS = 2048

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP", 5001: "Synology", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8006: "Proxmox", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9000: "PHP-FPM", 9090: "WebPanel", 9100: "JetDirect",
    27017: "MongoDB", 32400: "Plex", 50000: "SAP", 5555: "ADB",
    62078: "iPhone",
}


def port_label(p):
    name = PORT_NAMES.get(p)
    return "%d(%s)" % (p, name) if name else str(p)