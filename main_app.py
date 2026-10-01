# -*- coding: utf-8 -*-
"""主界面"""

import os
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from constants import (
    APP_NAME, FIELD_WIDTH, COMMON_DNS, COMMON_MASKS,
    SPEED_SOURCES, REGION_LABEL, LAN_TIP, SPEED_THREADS,
    SPEED_DURATION, SPEED_WARMUP, RT_INTERVAL,
)
from netutils import (
    is_valid_ip, mask_to_prefix, mask_display, parse_mask_text,
    read_net_bytes, is_admin, elevate,
)
from interfaces import (
    list_interfaces, get_iface_admin_state, set_iface_admin_state,
    detect_default_gateway, get_iface_config, build_commands,
    should_ignore, execute_config,
)
from diagnostics import (
    ping_stats, fmt_ms, fmt_speed, measure_speed, normalize_url,
    derive_lan_sources,
)
from config_store import load_configs, save_configs
from backup import (
    push as backup_push, peek as backup_peek, pop as backup_pop,
)
from icon import make_app_icon
from scan_dialog import ScanDialog


class App(tk.Tk):

    WIN_W = 1060
    WIN_H = 760

    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("%dx%d" % (self.WIN_W, self.WIN_H))
        self.resizable(False, False)

        self._rt_stop = threading.Event()
        self._rt_thread = None

        self.configs = []
        self.ifaces = []
        self._iface_map = {}
        self._iface_rev = {}

        self.busy = False
        self.pinging = False
        self._stop_ping = threading.Event()
        self.speeding = False
        self._stop_speed = threading.Event()

        self._lan_sources = []
        self._region_urls = {"lan": "", "custom": ""}
        self._prev_region = "cn"

        self._live_peak = 0.0
        self._admin_state = "unknown"
        self._admin_busy = False

        # ---- 批量操作 ----
        self._batch_ifaces = []

        self._set_icon()
        self._build_ui()
        self._center_window()

        self.configs = load_configs()
        self._refresh_tree()
        self.refresh_ifaces()
        self._start_realtime_monitor()

    def _set_icon(self):
        try:
            self._icon_img = make_app_icon()
            self.iconphoto(True, self._icon_img)
        except Exception:
            self._icon_img = None

    def _center_window(self):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - self.WIN_W) // 2)
        y = max(0, (sh - self.WIN_H) // 2)
        self.geometry("%dx%d+%d+%d" % (self.WIN_W, self.WIN_H, x, y))

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------
    def _build_ui(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=22)
        style.configure("Hint.TLabel", foreground="#888888")
        style.configure("Speed.TLabel", font=("Segoe UI", 18, "bold"),
                        foreground="#0a8f5a")
        style.configure("SpeedPeak.TLabel", font=("Segoe UI", 10, "bold"),
                        foreground="#d2691e")
        style.configure("SpeedSmall.TLabel", font=("", 9), foreground="#555555")
        style.configure("Prefix.TLabel", foreground="#0a8f5a")
        style.configure("RtSpeed.TLabel", foreground="#0a8f5a",
                        font=("Consolas", 9, "bold"))
        style.configure("DhcpState.TLabel", foreground="#0a8f5a", font=("", 8))
        style.configure("WarnState.TLabel", foreground="#c0392b", font=("", 8))

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self, textvariable=self.status_var, anchor="w",
                  relief="sunken", padding=(8, 3)).pack(side="bottom", fill="x")

        main = ttk.Frame(self, padding=8)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=6, uniform="col")
        main.columnconfigure(1, weight=4, uniform="col")

        self._build_topbar(main)
        self._build_params(main)
        self._build_diag(main)
        self._build_saved(main)
        self._build_speed_section(main)

    def _build_topbar(self, parent):
        """顶栏：第一行网卡选择 + 右侧竖排按钮，第二行操作按钮。"""
        bar = ttk.Frame(parent)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        bar.columnconfigure(0, weight=1)

        # ===== 第一行：网卡选择 =====
        row1 = ttk.Frame(bar)
        row1.grid(row=0, column=0, sticky="ew")
        row1.columnconfigure(1, weight=1)

        ttk.Label(row1, text="网卡").grid(row=0, column=0, padx=(0, 6))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(
            row1, textvariable=self.iface_var,
            state="readonly", width=110)
        self.iface_combo.grid(row=0, column=1, sticky="ew")
        self.iface_combo.bind("<<ComboboxSelected>>", self._on_iface_change)
        ttk.Button(row1, text="刷新", width=8,
                   command=self.refresh_ifaces).grid(
            row=0, column=2, sticky="e", padx=(8, 0))

        # ===== 第二行：操作按钮 =====
        row2 = ttk.Frame(bar)
        row2.grid(row=1, column=0, sticky="ew", pady=(6, 0))

        self.batch_btn = ttk.Button(row2, text="网卡批量选择", width=12,
                                    command=self.select_batch_ifaces)
        self.batch_btn.pack(side="left", padx=(0, 6))

        ttk.Button(row2, text="所有网卡重置为 DHCP", width=18,
                   command=self.apply_dhcp_all).pack(side="left", padx=(0, 6))
        ttk.Button(row2, text="当前网卡开启 DHCP", width=16,
                   command=self.apply_dhcp).pack(side="left", padx=(0, 6))

        self.rollback_btn = ttk.Button(row2, text="回滚上一次配置", width=12,
                                       command=self.rollback_iface)
        self.rollback_btn.pack(side="left", padx=(0, 6))

        ttk.Label(row2,
                  text="提示：批量选择后可对多块网卡同时应用相同配置",
                  foreground="#888888").pack(side="left", padx=(12, 0))

        ttk.Button(row2, text="网络中心", width=10,
                   command=self.open_network_center).pack(side="right")

    def _build_params(self, parent):
        f = ttk.LabelFrame(parent, text=" 当前网卡配置 ", padding=(12, 6))
        f.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        f.columnconfigure(1, weight=1)
        f.columnconfigure(3, weight=1)

        self.ip_var = tk.StringVar()
        self.mask_var = tk.StringVar()
        self.gw_var = tk.StringVar()
        self.dns1_var = tk.StringVar()
        self.dns2_var = tk.StringVar()

        LW = 8

        ttk.Label(f, text="IP 地址", width=LW, anchor="e").grid(
            row=0, column=0, sticky="e", padx=(0, 6), pady=4)
        ttk.Entry(f, textvariable=self.ip_var, width=FIELD_WIDTH).grid(
            row=0, column=1, sticky="ew", pady=4)

        ttk.Label(f, text="子网掩码", width=LW, anchor="e").grid(
            row=0, column=2, sticky="e", padx=(10, 6), pady=4)
        mf = ttk.Frame(f)
        mf.grid(row=0, column=3, sticky="ew", pady=4)
        mf.columnconfigure(0, weight=1)
        self.mask_combo = ttk.Combobox(
            mf, textvariable=self.mask_var, width=FIELD_WIDTH - 2,
            values=[mask_display(m) for m in COMMON_MASKS])
        self.mask_combo.grid(row=0, column=0, sticky="ew")
        self.prefix_lbl = ttk.Label(mf, text="", width=4,
                                    style="Prefix.TLabel")
        self.prefix_lbl.grid(row=0, column=1, sticky="w", padx=(4, 0))
        self.mask_combo.bind("<KeyRelease>", self._on_mask_key)
        self.mask_combo.bind("<FocusOut>", self._on_mask_focusout)
        self.mask_combo.bind("<Return>", self._on_mask_focusout)
        self.mask_combo.bind("<<ComboboxSelected>>", self._on_mask_focusout)

        ttk.Label(f, text="默认网关", width=LW, anchor="e").grid(
            row=1, column=0, sticky="e", padx=(0, 6), pady=4)
        ttk.Entry(f, textvariable=self.gw_var, width=FIELD_WIDTH).grid(
            row=1, column=1, sticky="ew", pady=4)

        ttk.Label(f, text="首选 DNS", width=LW, anchor="e").grid(
            row=1, column=2, sticky="e", padx=(10, 6), pady=4)
        self.dns1_combo = ttk.Combobox(f, textvariable=self.dns1_var,
                                       width=FIELD_WIDTH, values=COMMON_DNS)
        self.dns1_combo.grid(row=1, column=3, sticky="ew", pady=4)
        self._attach_dns_complete(self.dns1_combo)

        ttk.Label(f, text="备用 DNS", width=LW, anchor="e").grid(
            row=2, column=0, sticky="e", padx=(0, 6), pady=4)
        self.dns2_combo = ttk.Combobox(f, textvariable=self.dns2_var,
                                       width=FIELD_WIDTH, values=COMMON_DNS)
        self.dns2_combo.grid(row=2, column=1, sticky="ew", pady=4)
        self._attach_dns_complete(self.dns2_combo)

        self.iface_state_var = tk.StringVar(value="")
        self.iface_state_lbl = ttk.Label(f, textvariable=self.iface_state_var,
                                         style="DhcpState.TLabel")
        self.iface_state_lbl.grid(row=2, column=3, sticky="w", padx=(10, 0))

        btns = ttk.Frame(f)
        btns.grid(row=3, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Button(btns, text="应用设置", width=9,
                   command=self.apply_form).pack(side="left")
        ttk.Button(btns, text="读取当前", width=9,
                   command=self.load_current_iface_config).pack(
            side="left", padx=(6, 0))
        ttk.Button(btns, text="清空表单", width=9,
                   command=self.clear_form).pack(side="left", padx=(6, 0))
        self.admin_btn = ttk.Button(btns, text="禁用网卡", width=9,
                                    command=self.toggle_iface_admin)
        self.admin_btn.pack(side="left", padx=(6, 0))
        ttk.Button(btns, text="扫描网段", width=9,
                   command=self.open_scan_dialog).pack(side="left", padx=(6, 0))

    def _build_diag(self, parent):
        f = ttk.LabelFrame(parent, text=" 延迟检测 ", padding=(8, 6))
        f.grid(row=1, column=1, sticky="nsew", padx=(5, 0))

        cols = ("target", "min", "avg", "max", "loss")
        heads = {"target": "目标", "min": "最小", "avg": "平均",
                 "max": "最大", "loss": "丢包"}
        widths = {"target": 60, "min": 80, "avg": 80, "max": 80, "loss": 80}
        self.lat_tree = ttk.Treeview(f, columns=cols, show="headings",
                                     height=3, selectmode="none")
        for c in cols:
            self.lat_tree.heading(c, text=heads[c])
            self.lat_tree.column(c, width=widths[c], anchor="center",
                                 stretch=False)
        self.lat_tree.column("target", anchor="w")
        self.lat_tree.pack(fill="x", pady=(4, 0))

        for key, label in (("gw", "网关"), ("dns", "DNS"), ("pub", "公网")):
            self.lat_tree.insert("", "end", iid=key,
                                 values=(label, "-", "-", "-", "-"))

        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(6, 0))
        self.ping_btn = ttk.Button(bar, text="开始检测", width=9,
                                   command=self.start_ping)
        self.ping_btn.pack(side="left")

        sbar = ttk.Frame(f)
        sbar.pack(anchor="w", pady=(4, 0))
        self.ping_gw_var = tk.StringVar(value="网关 --")
        self.ping_dns_var = tk.StringVar(value="DNS --")
        self.ping_pub_var = tk.StringVar(value="公网 --")
        ttk.Label(sbar, textvariable=self.ping_gw_var, style="Hint.TLabel",
                  width=11, anchor="w").pack(side="left")
        ttk.Label(sbar, textvariable=self.ping_dns_var, style="Hint.TLabel",
                  width=11, anchor="w").pack(side="left")
        ttk.Label(sbar, textvariable=self.ping_pub_var, style="Hint.TLabel",
                  width=11, anchor="w").pack(side="left")

    def _build_saved(self, parent):
        f = ttk.LabelFrame(parent, text=" 配置列表 ", padding=(10, 6))
        f.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        top = ttk.Frame(f)
        top.pack(fill="x", pady=(0, 4))
        ttk.Label(top, text="配置名").pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.name_var, width=18).pack(
            side="left", padx=(6, 8))
        ttk.Button(top, text="保存当前参数",
                   command=self.save_current).pack(side="left")
        ttk.Button(top, text="覆盖选中",
                   command=self.update_selected).pack(side="left", padx=6)

        tvf = ttk.Frame(f)
        tvf.pack(fill="x", expand=False)

        cols = ("name", "iface", "ip", "mask", "gateway", "dns")
        heads = {"name": "配置名", "iface": "网卡", "ip": "IP 地址",
                 "mask": "掩码", "gateway": "网关", "dns": "DNS"}
        widths = {"name": 60, "iface": 150, "ip": 118,
                  "mask": 120, "gateway": 110, "dns": 180}
        self.tree = ttk.Treeview(tvf, columns=cols, show="headings",
                                 selectmode="browse", height=4)
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=True)

        vsb = ttk.Scrollbar(tvf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="x", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.apply_selected())

        act = ttk.Frame(f)
        act.pack(fill="x", pady=(6, 0))
        ttk.Button(act, text="一键应用",
                   command=self.apply_selected).pack(side="left")
        ttk.Button(act, text="载入到表单",
                   command=self.load_selected).pack(side="left", padx=6)
        ttk.Button(act, text="删除",
                   command=self.delete_selected).pack(side="left")
        ttk.Label(act, text="双击列表项可直接应用",
                  style="Hint.TLabel").pack(side="right")

    def _build_speed_section(self, parent):
        f = ttk.LabelFrame(parent, text=" 下载测速 ", padding=(10, 6))
        f.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        f.columnconfigure(0, weight=1)

        row1 = ttk.Frame(f)
        row1.grid(row=0, column=0, sticky="ew")

        ttk.Label(row1, text="区域").pack(side="left", padx=(0, 4))
        self.speed_region = tk.StringVar(value="cn")
        for val, text in (("cn", "国内"), ("intl", "国外"),
                          ("lan", "内网"), ("custom", "自定义")):
            ttk.Radiobutton(row1, text=text, variable=self.speed_region,
                            value=val,
                            command=self._on_region_change).pack(
                side="left", padx=(0, 4))

        ttk.Label(row1, text="测速源").pack(side="left", padx=(8, 4))
        self.speed_source_var = tk.StringVar()
        self.speed_source_combo = ttk.Combobox(
            row1, textvariable=self.speed_source_var,
            state="readonly", width=FIELD_WIDTH + 6)
        self.speed_source_combo.pack(side="left")
        self.speed_source_combo.bind("<<ComboboxSelected>>",
                                     self._on_source_selected)

        self.rt_var = tk.StringVar(value="实时  ↑ -- Mbps   ↓ -- Mbps")
        ttk.Label(row1, textvariable=self.rt_var,
                  style="RtSpeed.TLabel").pack(side="right")

        row2 = ttk.Frame(f)
        row2.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.url_label = ttk.Label(row2, text="URL", width=4, anchor="e")
        self.url_label.pack(side="left", padx=(0, 4))
        self.speed_url_var = tk.StringVar()
        self.speed_url_entry = ttk.Entry(row2, textvariable=self.speed_url_var,
                                         width=1)
        self.speed_url_entry.pack(side="left", fill="x", expand=True)
        self.speed_url_entry.bind("<Return>", lambda e: self.toggle_speed())

        row3 = ttk.Frame(f)
        row3.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        self.speed_value = tk.StringVar(value="-- Mbps")
        ttk.Label(row3, textvariable=self.speed_value,
                  style="Speed.TLabel", width=11, anchor="w").pack(side="left")
        self.speed_peak_var = tk.StringVar(value="峰值 --")
        ttk.Label(row3, textvariable=self.speed_peak_var,
                  style="SpeedPeak.TLabel", width=15, anchor="w").pack(
            side="left", padx=(4, 0))
        self.speed_bar = ttk.Progressbar(row3, mode="determinate",
                                         maximum=100, length=300)
        self.speed_bar.pack(side="left", padx=(10, 0), fill="x", expand=True)

        self.speed_line1 = tk.StringVar(value="点击开始测速")
        ttk.Label(f, textvariable=self.speed_line1,
                  foreground="#333333").grid(
            row=3, column=0, sticky="w", pady=(6, 0))
        self.speed_line2 = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.speed_line2,
                  style="SpeedSmall.TLabel").grid(
            row=4, column=0, sticky="w", pady=(2, 0))

        row6 = ttk.Frame(f)
        row6.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        self.speed_btn = ttk.Button(row6, text="开始测速", width=10,
                                    command=self.toggle_speed)
        self.speed_btn.pack(side="left")
        ttk.Label(row6,
                  text="%d 线程 · 采样 %.0f 秒 · 丢弃前 %.1f 秒慢启动"
                       % (SPEED_THREADS, SPEED_DURATION, SPEED_WARMUP),
                  style="Hint.TLabel").pack(side="left", padx=(10, 0))

        self._refresh_speed_sources()
        self._sync_url_field()

    # ------------------------------------------------------------------
    # 测速源下拉
    # ------------------------------------------------------------------
    def _current_region(self):
        return self.speed_region.get()

    def _refresh_speed_sources(self):
        region = self._current_region()
        if region == "lan":
            srcs = self._lan_sources or SPEED_SOURCES.get("lan", [])
            names = [n for n, _ in srcs] or ["自定义 URL"]
        elif region == "custom":
            names = ["自定义 URL"]
        else:
            base = SPEED_SOURCES.get(region, [])
            names = ["自动（按顺序尝试）"] + [n for n, _ in base]
        self.speed_source_combo["values"] = names
        self.speed_source_var.set(names[0])

    def _on_source_selected(self, event=None):
        if self._current_region() != "lan":
            return
        chosen = self.speed_source_var.get()
        srcs = self._lan_sources or SPEED_SOURCES.get("lan", [])
        for n, u in srcs:
            if n == chosen:
                self.speed_url_var.set(u)
                return

    def _on_region_change(self):
        new_region = self._current_region()
        prev_region = self._prev_region

        if prev_region in ("lan", "custom"):
            self._region_urls[prev_region] = self.speed_url_var.get()

        if new_region == "lan":
            url = self._region_urls.get("lan", "")
            if not url and self._lan_sources:
                url = self._lan_sources[0][1]
            self.speed_url_var.set(url)
        elif new_region == "custom":
            self.speed_url_var.set(self._region_urls.get("custom", ""))
        else:
            self.speed_url_var.set("")

        self._prev_region = new_region
        self._refresh_speed_sources()
        self._sync_url_field()
        self.speed_line1.set("已切换测速源，点击开始测速")
        self.speed_line2.set("")
        self.speed_value.set("-- Mbps")
        self.speed_peak_var.set("峰值 --")
        self.speed_bar["value"] = 0
        if new_region == "lan":
            self.speed_line2.set(LAN_TIP)

    def _sync_url_field(self):
        region = self._current_region()
        if region in ("lan", "custom"):
            self.speed_url_entry.config(state="normal")
            self.url_label.config(text="URL")
        else:
            self.speed_url_entry.config(state="disabled")
            self.url_label.config(text="URL（仅内网/自定义）")

    def _resolve_sources(self):
        region = self._current_region()
        if region in ("lan", "custom"):
            url = normalize_url(self.speed_url_var.get())
            if not url:
                return []
            tag = "内网" if region == "lan" else "自定义"
            if region == "custom":
                self._region_urls["custom"] = url
            return [("%s源" % tag, url)]
        base = SPEED_SOURCES.get(region, [])
        chosen = self.speed_source_var.get()
        if chosen.startswith("自动"):
            return list(base)
        for n, u in base:
            if n == chosen:
                return [(n, u)]
        return list(base)

    # ------------------------------------------------------------------
    # 网卡
    # ------------------------------------------------------------------
    def _current_iface_name(self):
        """多重兜底：优先 iface_var，为空则读 iface_combo.get()。"""
        d = ""
        try:
            d = (self.iface_var.get() or "").strip()
        except Exception:
            d = ""
        if not d:
            try:
                d = (self.iface_combo.get() or "").strip()
            except Exception:
                d = ""
        if not d:
            return ""
        return self._iface_map.get(d, d)

    def refresh_ifaces(self):
        def work():
            pairs = list_interfaces()
            self.after(0, lambda: self._set_ifaces(pairs))
        threading.Thread(target=work, daemon=True).start()

    def _set_ifaces(self, pairs):
        cur_real = self._current_iface_name()
        cur_display = self.iface_var.get()

        self.ifaces = [real for _, real in pairs]
        self._iface_map = {d: r for d, r in pairs}
        self._iface_rev = {r: d for d, r in pairs}
        displays = [d for d, _ in pairs]
        self.iface_combo["values"] = displays

        if cur_real and cur_real in self._iface_rev:
            new_display = self._iface_rev[cur_real]
            if new_display != cur_display:
                self.iface_var.set(new_display)
                self._on_iface_change()
        elif displays and not self.iface_var.get():
            self.iface_var.set(displays[0])
            self._on_iface_change()
        elif not displays:
            self.set_status("未检测到网卡，请确认以管理员身份运行")

    # ---------- 批量选择 ----------
    def select_batch_ifaces(self):
        from batch_dialog import BatchSelectDialog
        dlg = BatchSelectDialog(self, self._batch_ifaces)
        self.wait_window(dlg)
        if dlg.result:
            self._batch_ifaces = dlg.result
            self.batch_btn.config(text="批量(%d)" % len(self._batch_ifaces))
            self.set_status("已选择 %d 块网卡用于批量操作"
                            % len(self._batch_ifaces))
        else:
            self._batch_ifaces = []
            self.batch_btn.config(text="网卡批量选择")

    # ---------- 网络连接窗口 ----------
    def open_network_center(self):
        """打开「网络连接」窗口（网络和共享中心 -> 更改适配器设置）。"""
        try:
            os.startfile("ncpa.cpl")
            self.set_status("已打开网络连接窗口")
        except Exception:
            try:
                subprocess.Popen(
                    ["control.exe", "/name",
                     "Microsoft.NetworkAndSharingCenter"],
                )
                self.set_status("已打开网络和共享中心")
            except Exception as e:
                messagebox.showerror("打开失败", str(e))

    def _on_iface_change(self, event=None):
        iface = self._current_iface_name()
        if not iface:
            return
        threading.Thread(target=self._load_iface_config_async,
                         args=(iface,), daemon=True).start()

    def load_current_iface_config(self):
        iface = self._current_iface_name()
        if not iface:
            messagebox.showwarning("提示", "请先选择网卡")
            return
        self.set_status("正在读取「%s」的当前配置…" % iface)
        threading.Thread(target=self._load_iface_config_async,
                         args=(iface,), daemon=True).start()

    def _load_iface_config_async(self, iface):
        admin_state = get_iface_admin_state(iface)
        cfg = get_iface_config(iface) if admin_state != "disabled" else None
        self.after(0, lambda: self._apply_iface_config(iface, cfg, admin_state))

    def _apply_iface_config(self, iface, cfg, admin_state):
        if self._current_iface_name() != iface:
            return

        self._admin_state = admin_state
        self._update_admin_button()

        if admin_state == "disabled":
            for v in (self.ip_var, self.mask_var, self.gw_var,
                      self.dns1_var, self.dns2_var):
                v.set("")
            self.prefix_lbl.config(text="")
            self.iface_state_var.set("网卡已禁用")
            self.iface_state_lbl.config(style="WarnState.TLabel")
            self.set_status("「%s」当前已被禁用，可点击「启用网卡」恢复" % iface)
            return

        if cfg is None:
            self.iface_state_var.set("网卡已启用（无法读取配置）")
            self.iface_state_lbl.config(style="DhcpState.TLabel")
            self.set_status("无法读取「%s」的当前配置" % iface)
            return

        self.ip_var.set(cfg["ip"])
        self.mask_var.set(cfg["mask"])
        self.gw_var.set(cfg["gateway"])
        self.dns1_var.set(cfg["dns1"])
        self.dns2_var.set(cfg["dns2"])
        self._on_mask_focusout()

        state_txt = "已启用 DHCP" if cfg["dhcp"] else "静态配置"
        if not cfg["ip"]:
            state_txt += "（未获取到地址）"
        state_txt += " · 网卡已启用"
        self.iface_state_var.set(state_txt)
        self.iface_state_lbl.config(style="DhcpState.TLabel")

        old_candidates = {u for _, u in self._lan_sources}
        self._lan_sources = derive_lan_sources(
            cfg["ip"], cfg["mask"], cfg["gateway"])
        cur_url = self._region_urls.get("lan", "")
        if not cur_url or cur_url in old_candidates:
            new_default = self._lan_sources[0][1] if self._lan_sources else ""
            self._region_urls["lan"] = new_default
            if self._current_region() == "lan":
                self.speed_url_var.set(new_default)
                self._refresh_speed_sources()

        self.set_status("已读取「%s」的当前配置（%s）" % (iface, state_txt))

    def _update_admin_button(self):
        if self._admin_state == "disabled":
            self.admin_btn.config(text="启用网卡", state="normal")
        elif self._admin_state == "enabled":
            self.admin_btn.config(text="禁用网卡", state="normal")
        else:
            self.admin_btn.config(text="禁用/启用", state="normal")

    def toggle_iface_admin(self):
        if self._admin_busy:
            messagebox.showinfo("提示", "正在执行上一个操作，请稍候")
            return
        if self.busy:
            messagebox.showinfo("提示", "正在执行网络配置操作，请稍候")
            return

        iface = self._current_iface_name()
        if not iface:
            messagebox.showwarning("提示", "请先选择网卡")
            return

        state = get_iface_admin_state(iface)
        self._admin_state = state
        self._update_admin_button()

        if state == "disabled":
            action_desc, target_enable = "启用", True
        elif state == "enabled":
            action_desc, target_enable = "禁用", False
        else:
            messagebox.showwarning(
                "提示",
                "无法识别「%s」当前的管理状态。\n"
                "请点「刷新」重新加载网卡列表后重试。" % iface)
            return

        confirm_msg = (
            "将【%s】网卡「%s」。\n\n"
            "禁用后该网卡的所有网络通信会中断，需要再次启用才能恢复。\n"
            "确定继续？" % (action_desc, iface)
        )
        if not messagebox.askyesno("确认" + action_desc, confirm_msg):
            return

        self._admin_busy = True
        self.admin_btn.config(state="disabled")
        self.set_status("正在%s网卡「%s」…" % (action_desc, iface))

        def work():
            ok, out = set_iface_admin_state(iface, target_enable)
            self.after(0, lambda: self._admin_done(action_desc, iface, ok, out))

        threading.Thread(target=work, daemon=True).start()

    def _admin_done(self, action_desc, iface, ok, out):
        self._admin_busy = False
        self.admin_btn.config(state="normal")
        if not ok:
            self.set_status("%s网卡失败" % action_desc)
            messagebox.showerror("%s失败" % action_desc,
                                 "网卡：%s\n\n%s" % (iface, out or "未知错误"))
            return
        self.set_status("已%s网卡「%s」" % (action_desc, iface))
        self.after(500, self._reload_current_iface)
        self.after(1000, self.refresh_ifaces)

    def _reload_current_iface(self):
        iface = self._current_iface_name()
        if not iface:
            return
        threading.Thread(target=self._load_iface_config_async,
                         args=(iface,), daemon=True).start()

    # ------------------------------------------------------------------
    # 备份回滚
    # ------------------------------------------------------------------
    def rollback_iface(self, iface=None):
        if self.busy:
            messagebox.showinfo("提示", "正在执行上一个操作，请稍候")
            return

        # 参数校验：必须是有效字符串；否则用当前选中网卡
        if not isinstance(iface, str) or not iface.strip():
            iface = ""
        if not iface:
            iface = self._current_iface_name()
        if not iface:
            messagebox.showwarning(
                "提示",
                "未识别到当前网卡。\n\n"
                "请先在顶部的「网卡」下拉框中明确选择一块网卡，"
                "再点击「回滚上一次配置」。")
            return

        snap = backup_peek(iface)
        if not snap:
            messagebox.showinfo("提示", "「%s」没有可用的历史配置" % iface)
            return

        # ★ 关键修复：把 iface 塞回 cfg，否则 _apply 里会拿不到网卡名
        cfg = dict(snap.get("cfg") or {})
        cfg["iface"] = iface

        ts = time.strftime("%Y-%m-%d %H:%M:%S",
                           time.localtime(snap.get("ts", 0)))
        dhcp = cfg.get("dhcp", False)

        if dhcp:
            tip = ("将把网卡「%s」回滚到 [%s] 的记录：\n\n"
                   "模式：自动获取（DHCP）\n\n确定继续？" % (iface, ts))
        else:
            tip = ("将把网卡「%s」回滚到 [%s] 的记录：\n\n"
                   "IP 地址：%s\n子网掩码：%s\n默认网关：%s\n"
                   "首选 DNS：%s\n备用 DNS：%s\n\n确定继续？"
                   % (iface, ts, cfg.get("ip", "-"), cfg.get("mask", "-"),
                      cfg.get("gateway") or "-",
                      cfg.get("dns1") or "-", cfg.get("dns2") or "-"))
        if not messagebox.askyesno("确认回滚", tip):
            return

        backup_pop(iface)
        self._apply(cfg, dhcp=dhcp, _skip_backup=True)

    # ------------------------------------------------------------------
    # 实时网速
    # ------------------------------------------------------------------
    def _start_realtime_monitor(self):
        self._rt_thread = threading.Thread(target=self._rt_loop, daemon=True)
        self._rt_thread.start()

    def _rt_loop(self):
        last_rx = last_tx = None
        last_t = None
        while not self._rt_stop.is_set():
            sample = read_net_bytes()
            now = time.monotonic()
            if sample is not None:
                if last_rx is not None and last_t is not None:
                    dt = now - last_t
                    db_rx = sample[0] - last_rx
                    db_tx = sample[1] - last_tx
                    if db_rx < 0 or db_tx < 0 or dt <= 0:
                        last_rx, last_tx, last_t = sample[0], sample[1], now
                    elif dt >= 0.5:
                        rx = db_rx * 8.0 / dt / 1e6
                        tx = db_tx * 8.0 / dt / 1e6
                        if 0 <= rx <= 100000 and 0 <= tx <= 100000:
                            self.after(0, self._update_rt, rx, tx)
                        last_rx, last_tx, last_t = sample[0], sample[1], now
                else:
                    last_rx, last_tx, last_t = sample[0], sample[1], now
            self._rt_stop.wait(RT_INTERVAL)

    def _update_rt(self, rx, tx):
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return
        self.rt_var.set("实时  ↑ %.2f Mbps   ↓ %.2f Mbps" % (tx, rx))

    # ------------------------------------------------------------------
    # 掩码交互
    # ------------------------------------------------------------------
    def _on_mask_key(self, event=None):
        txt = self.mask_var.get().strip()
        if txt.isdigit():
            n = int(txt)
            self.prefix_lbl.config(text="/%d" % n if 0 <= n <= 32 else "")
            return
        m = parse_mask_text(txt)
        self.prefix_lbl.config(text="/%d" % mask_to_prefix(m) if m else "")

    def _on_mask_focusout(self, event=None):
        m = parse_mask_text(self.mask_var.get())
        if m:
            self.mask_var.set(m)
            self.prefix_lbl.config(text="/%d" % mask_to_prefix(m))
        else:
            self.prefix_lbl.config(text="")

    @staticmethod
    def _attach_dns_complete(combo):
        skip = {"Up", "Down", "Left", "Right", "Return", "Escape", "Tab",
                "Shift_L", "Shift_R", "Control_L", "Control_R",
                "Alt_L", "Alt_R"}

        def on_key(event):
            if event.keysym in skip:
                return
            txt = combo.get().strip()
            combo["values"] = ([d for d in COMMON_DNS if d.startswith(txt)]
                               or COMMON_DNS) if txt else COMMON_DNS

        combo.bind("<KeyRelease>", on_key)

    # ------------------------------------------------------------------
    # 配置持久化
    # ------------------------------------------------------------------
    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for i, c in enumerate(self.configs):
            dns = " / ".join([x for x in (c.get("dns1", ""),
                                          c.get("dns2", "")) if x])
            self.tree.insert("", "end", iid=str(i), values=(
                c.get("name", ""), c.get("iface", ""), c.get("ip", ""),
                c.get("mask", ""), c.get("gateway", "") or "-", dns or "-",
            ))

    def _persist(self):
        ok, err = save_configs(self.configs)
        if not ok:
            messagebox.showerror("保存失败", err)

    def _selected_index(self):
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except (ValueError, IndexError):
            return None

    # ------------------------------------------------------------------
    # 表单校验
    # ------------------------------------------------------------------
    def validate_form(self):
        iface = self._current_iface_name()
        if not iface:
            messagebox.showwarning("提示", "请先选择网卡")
            return None
        ip = self.ip_var.get().strip()
        if not is_valid_ip(ip):
            messagebox.showwarning("提示", "IP 地址格式不正确，例如 192.168.1.100")
            return None
        mask = parse_mask_text(self.mask_var.get())
        if not mask:
            messagebox.showwarning("提示",
                                   "子网掩码不正确，可输入 24 或选择 255.255.255.0")
            return None
        self.mask_var.set(mask)
        self.prefix_lbl.config(text="/%d" % mask_to_prefix(mask))
        gw = self.gw_var.get().strip()
        if gw and not is_valid_ip(gw):
            messagebox.showwarning("提示", "网关格式不正确")
            return None
        dns1 = self.dns1_var.get().strip()
        dns2 = self.dns2_var.get().strip()
        for d in (dns1, dns2):
            if d and not is_valid_ip(d):
                messagebox.showwarning("提示", "DNS 格式不正确：%s" % d)
                return None
        return {"iface": iface, "ip": ip, "mask": mask,
                "gateway": gw, "dns1": dns1, "dns2": dns2}

    # ------------------------------------------------------------------
    # 应用配置
    # ------------------------------------------------------------------
    def apply_form(self):
        if self._batch_ifaces:
            self._apply_batch()
            return
        if self._admin_state == "disabled":
            messagebox.showwarning("提示",
                                   "当前网卡已禁用，请先点击「启用网卡」")
            return
        cfg = self.validate_form()
        if cfg:
            self._apply(cfg)

    def apply_selected(self):
        i = self._selected_index()
        if i is None:
            messagebox.showinfo("提示", "请先在列表中选择一个配置")
            return
        cfg = dict(self.configs[i])
        if not cfg.get("iface"):
            cfg["iface"] = self._current_iface_name()
        self._apply(cfg)

    def apply_dhcp(self):
        if self._batch_ifaces:
            self._apply_batch_dhcp()
            return
        iface = self._current_iface_name()
        if not iface:
            messagebox.showwarning("提示", "请先选择网卡")
            return
        if self._admin_state == "disabled":
            messagebox.showwarning("提示",
                                   "当前网卡已禁用，请先点击「启用网卡」")
            return
        self._apply({"iface": iface}, dhcp=True)

    def apply_dhcp_all(self):
        if self.busy:
            messagebox.showinfo("提示", "正在执行上一个操作，请稍候")
            return
        iface_names = [r for _, r in list_interfaces()]
        if not iface_names:
            messagebox.showwarning("提示", "未检测到任何网卡")
            return
        names_str = "\n".join("   · " + n for n in iface_names)
        tip = ("将把以下 %d 个网卡全部恢复为自动获取 IP 和 DNS：\n\n"
               "%s\n\n"
               "注意：所有被重置的网卡会短暂断网，需要重新从路由器获取地址。\n"
               "确定继续？" % (len(iface_names), names_str))
        if not messagebox.askyesno("确认全部重置", tip):
            return

        self.busy = True
        self.set_status("正在重置 %d 个网卡，请稍候…" % len(iface_names))

        def work():
            success, failed = [], []
            for iface in iface_names:
                try:
                    cur = get_iface_config(iface)
                    if cur is not None:
                        backup_push(iface, cur)
                except Exception:
                    pass

                ok, err, _ = execute_config(iface, {}, dhcp=True)
                if ok:
                    success.append(iface)
                else:
                    first_line = err.strip().splitlines()[0] if err.strip() \
                        else "未知错误"
                    failed.append((iface, first_line))
            self.after(0, lambda: self._dhcp_all_done(success, failed))

        threading.Thread(target=work, daemon=True).start()

    def _dhcp_all_done(self, success, failed):
        self.busy = False
        if not failed:
            self.set_status("已将 %d 个网卡重置为自动获取" % len(success))
            messagebox.showinfo(
                "全部完成",
                "已成功重置以下 %d 个网卡为自动获取：\n\n%s"
                % (len(success), "\n".join("   · " + n for n in success)))
            self._on_iface_change()
            return
        if not success:
            self.set_status("全部重置失败")
            lines = ["所有网卡均重置失败：", ""]
            for n, e in failed:
                lines.append("   · %s：%s" % (n, e))
            messagebox.showerror("重置失败", "\n".join(lines))
            return
        self.set_status("部分重置成功（成功 %d / 失败 %d）"
                        % (len(success), len(failed)))
        lines = ["成功 %d 个：" % len(success)]
        lines.extend("   · " + n for n in success)
        lines.append("")
        lines.append("失败 %d 个：" % len(failed))
        for n, e in failed:
            lines.append("   · %s：%s" % (n, e))
        messagebox.showwarning("部分完成", "\n".join(lines))
        self._on_iface_change()

    def _apply(self, cfg, dhcp=False, _skip_backup=False):
        if self.busy:
            messagebox.showinfo("提示", "正在执行上一个操作，请稍候")
            return

        # ★ 兜底：如果 cfg 里没有 iface，就用当前选中网卡补上
        iface = (cfg.get("iface") or "").strip()
        if not iface:
            iface = self._current_iface_name()
            if iface:
                cfg = dict(cfg)
                cfg["iface"] = iface
        if not iface:
            messagebox.showwarning(
                "提示",
                "未识别到网卡。\n\n"
                "请在顶部的「网卡」下拉框中选择一块网卡后重试。")
            return

        if self.ifaces and iface not in self.ifaces:
            if not messagebox.askyesno(
                    "网卡不存在",
                    "网卡「%s」当前未在系统中检测到，仍要继续吗？" % iface):
                return
        if dhcp:
            tip = "将把网卡「%s」恢复为自动获取 IP 和 DNS？" % iface
        else:
            tip = ("即将修改网卡「%s」的网络配置：\n\n"
                   "IP 地址：%s\n子网掩码：%s\n默认网关：%s\n"
                   "首选 DNS：%s\n备用 DNS：%s\n\n"
                   "确定继续？（修改过程中网络会短暂中断）"
                   % (iface, cfg.get("ip", "-"), cfg.get("mask", "-"),
                      cfg.get("gateway") or "-",
                      cfg.get("dns1") or "-", cfg.get("dns2") or "-"))
        if not messagebox.askyesno("确认", tip):
            return

        if not _skip_backup:
            try:
                cur = get_iface_config(iface)
                if cur is not None:
                    backup_push(iface, cur)
            except Exception:
                pass

        self.busy = True
        self.set_status("正在应用配置，请稍候…")

        def work():
            ok, err, used_fallback = execute_config(iface, cfg, dhcp)
            self.after(0, lambda: self._apply_done(
                ok, err, iface, used_fallback))

        threading.Thread(target=work, daemon=True).start()

    def _apply_done(self, ok, err, iface, used_fallback):
        self.busy = False
        if not ok:
            self.set_status("应用失败")
            messagebox.showerror("应用失败", err[:2000] if err else "未知错误")
            if backup_peek(iface):
                if messagebox.askyesno(
                        "应用失败",
                        "是否立即回滚到应用前的配置？"):
                    self.rollback_iface(iface)
        else:
            if used_fallback:
                self.set_status("已通过 PowerShell 应用到「%s」" % iface)
            else:
                self.set_status("已成功应用到「%s」" % iface)
            self._reload_current_iface()

    # ------------------------------------------------------------------
    # 批量应用
    # ------------------------------------------------------------------
    def _apply_batch(self):
        if self.busy:
            messagebox.showinfo("提示", "正在执行上一个操作，请稍候")
            return
        iface = self._current_iface_name()
        if not iface:
            messagebox.showwarning("提示", "请先在表单里选择一块网卡作为模板")
            return

        ip = self.ip_var.get().strip()
        mask = parse_mask_text(self.mask_var.get())
        gw = self.gw_var.get().strip()
        dns1 = self.dns1_var.get().strip()
        dns2 = self.dns2_var.get().strip()
        if not is_valid_ip(ip) or not mask:
            messagebox.showwarning("提示", "请先在表单里填写合法的 IP / 掩码")
            return
        cfg_template = {"ip": ip, "mask": mask, "gateway": gw,
                        "dns1": dns1, "dns2": dns2}

        names = "\n".join("   · " + n for n in self._batch_ifaces)
        tip = ("将把以下 %d 块网卡应用相同配置：\n\n%s\n\n"
               "IP：%s   掩码：%s   网关：%s\n"
               "首选 DNS：%s   备用 DNS：%s\n\n"
               "⚠ 多块网卡使用相同 IP 会产生冲突，仅建议用于主备网卡"
               "或纯测试场景。\n\n确定继续？"
               % (len(self._batch_ifaces), names, ip, mask, gw or "-",
                  dns1 or "-", dns2 or "-"))
        if not messagebox.askyesno("确认批量应用", tip):
            return

        self.busy = True
        self.set_status("正在批量应用配置到 %d 块网卡…" % len(self._batch_ifaces))

        def work():
            success, failed = [], []
            for ifc in self._batch_ifaces:
                cur = get_iface_config(ifc)
                if cur is not None:
                    try:
                        backup_push(ifc, cur)
                    except Exception:
                        pass
                cfg = dict(cfg_template)
                cfg["iface"] = ifc
                ok, err, _ = execute_config(ifc, cfg, dhcp=False)
                if ok:
                    success.append(ifc)
                else:
                    first_line = err.strip().splitlines()[0] if err.strip() \
                        else "未知错误"
                    failed.append((ifc, first_line))
            self.after(0, lambda: self._batch_apply_done(success, failed))

        threading.Thread(target=work, daemon=True).start()

    def _apply_batch_dhcp(self):
        if self.busy:
            messagebox.showinfo("提示", "正在执行上一个操作，请稍候")
            return
        names = "\n".join("   · " + n for n in self._batch_ifaces)
        if not messagebox.askyesno(
                "确认批量恢复 DHCP",
                "将把以下 %d 块网卡恢复为自动获取：\n\n%s\n\n确定继续？"
                % (len(self._batch_ifaces), names)):
            return

        self.busy = True
        self.set_status("正在批量恢复 %d 块网卡为 DHCP…"
                        % len(self._batch_ifaces))

        def work():
            success, failed = [], []
            for ifc in self._batch_ifaces:
                cur = get_iface_config(ifc)
                if cur is not None:
                    try:
                        backup_push(ifc, cur)
                    except Exception:
                        pass
                ok, err, _ = execute_config(ifc, {}, dhcp=True)
                if ok:
                    success.append(ifc)
                else:
                    first_line = err.strip().splitlines()[0] if err.strip() \
                        else "未知错误"
                    failed.append((ifc, first_line))
            self.after(0, lambda: self._batch_apply_done(success, failed))

        threading.Thread(target=work, daemon=True).start()

    def _batch_apply_done(self, success, failed):
        self.busy = False
        if not failed:
            self.set_status("批量操作完成：成功 %d" % len(success))
            messagebox.showinfo("完成",
                                "已成功处理 %d 块网卡：\n\n%s"
                                % (len(success),
                                   "\n".join("   · " + n for n in success)))
            self._reload_current_iface()
            return
        lines = ["成功 %d 块：" % len(success)]
        lines += ["   · " + n for n in success]
        lines.append("")
        lines.append("失败 %d 块：" % len(failed))
        for n, e in failed:
            lines.append("   · %s：%s" % (n, e))
        messagebox.showwarning("部分完成", "\n".join(lines))
        self._reload_current_iface()

    # ------------------------------------------------------------------
    # 延迟检测
    # ------------------------------------------------------------------
    def start_ping(self):
        if self.pinging:
            return
        gw = self.gw_var.get().strip()
        dns = self.dns1_var.get().strip()
        if not is_valid_ip(dns):
            dns = "114.114.114.114"
        pub = "223.5.5.5"

        targets = []
        if is_valid_ip(gw):
            targets.append(("gw", gw, "gw"))
        else:
            auto = detect_default_gateway()
            if auto:
                targets.append(("gw", auto, "gw"))
        targets.append(("dns", dns, "dns"))
        targets.append(("pub", pub, "pub"))

        self.pinging = True
        self.ping_btn.config(state="disabled")
        self._stop_ping.clear()

        for k in ("gw", "dns", "pub"):
            self.lat_tree.item(k, values=(self._target_label(k),
                                          "…", "…", "…", "…"))
        self.ping_gw_var.set("网关 …")
        self.ping_dns_var.set("DNS …")
        self.ping_pub_var.set("公网 …")
        self.set_status("正在检测网络延迟…")

        def work():
            results = {}
            for key, host, kind in targets:
                if self._stop_ping.is_set():
                    break
                st = ping_stats(host, kind=kind, count=4, timeout_ms=1500,
                                stop_flag=self._stop_ping.is_set)
                results[key] = st
                self.after(0, lambda k=key, s=st: self._update_ping_row(k, s))
            self.after(0, lambda r=dict(results): self._ping_done(r))

        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def _target_label(key):
        return {"gw": "网关", "dns": "DNS", "pub": "公网"}.get(key, key)

    def _update_ping_row(self, key, s):
        self.lat_tree.item(key, values=(
            self._target_label(key),
            fmt_ms(s["min"]), fmt_ms(s["avg"]), fmt_ms(s["max"]),
            "%d%%" % round(s["loss"]),
        ))

    def _ping_done(self, results):
        self.pinging = False
        self.ping_btn.config(state="normal")

        def fmt(key, label):
            if key not in results:
                return "%s --" % label
            st = results[key]
            if st["avg"] is None:
                return "%s 无响应" % label
            return "%s %s ms" % (label, fmt_ms(st["avg"]))

        self.ping_gw_var.set(fmt("gw", "网关"))
        self.ping_dns_var.set(fmt("dns", "DNS"))
        self.ping_pub_var.set(fmt("pub", "公网"))
        self.set_status("延迟检测完成")

    # ------------------------------------------------------------------
    # 下载测速
    # ------------------------------------------------------------------
    def toggle_speed(self):
        if self.speeding:
            self._stop_speed.set()
            self.speed_btn.config(state="disabled")
            return
        self.start_speed()

    def start_speed(self):
        region = self._current_region()
        region_name = REGION_LABEL.get(region, region)
        chosen = self.speed_source_var.get()

        if region in ("lan", "custom"):
            url = normalize_url(self.speed_url_var.get())
            if not url:
                messagebox.showwarning(
                    "提示", "请先填写测速 URL，例如 http://192.168.1.10/test.bin")
                return
            self.speed_url_var.set(url)

        sources = self._resolve_sources()
        if not sources:
            messagebox.showwarning("提示", "当前没有可用的测速源")
            return

        self.speeding = True
        self._stop_speed.clear()
        self._live_peak = 0.0
        self.speed_btn.config(text="停止测速")
        self.speed_value.set("-- Mbps")
        self.speed_peak_var.set("峰值 --")
        self.speed_bar["value"] = 0
        self.speed_line1.set("正在准备测速（%s · %s）…" % (region_name, chosen))
        self.speed_line2.set("")
        self.set_status("正在测速（%s源），请稍候…" % region_name)

        def on_tick(elapsed, total, inst):
            pct = min(100.0, elapsed * 100.0 / SPEED_DURATION)
            self.after(0, lambda: self._update_speed_live(elapsed, total,
                                                          inst, pct))

        def work():
            last_err = None
            for name, url in sources:
                if self._stop_speed.is_set():
                    self.after(0, lambda: self._speed_done(None, "已取消"))
                    return
                self.after(0, lambda u=url: self.speed_url_var.set(u))
                self.after(0, lambda n=name: self.speed_line1.set(
                    "正在尝试：%s …" % n))
                try:
                    result = measure_speed(url, self._stop_speed, on_tick)
                    result["source"] = name
                    result["region"] = region_name
                    result["url"] = url
                    self.after(0, lambda r=result: self._speed_done(r, None))
                    return
                except Exception as e:
                    last_err = "%s：%s" % (name, e)
                    continue
            self.after(0, lambda: self._speed_done(
                None, last_err or "所有测速源均不可用"))

        threading.Thread(target=work, daemon=True).start()

    def _update_speed_live(self, elapsed, total, inst, pct):
        self.speed_value.set(fmt_speed(inst))
        if inst > self._live_peak:
            self._live_peak = inst
        self.speed_peak_var.set("峰值 " + fmt_speed(self._live_peak))
        self.speed_bar["value"] = pct
        self.speed_line1.set(
            "已下载 %.1f MB   ·   已用 %.1f / %.0f 秒"
            % (total / 1048576, elapsed, SPEED_DURATION))

    def _speed_done(self, result, err):
        self.speeding = False
        self.speed_btn.config(state="normal", text="开始测速")

        if err:
            self.speed_value.set("-- Mbps")
            self.speed_peak_var.set("峰值 --")
            self.speed_bar["value"] = 0
            self.speed_line1.set("测速失败：" + err)
            self.speed_line2.set("可尝试切换测速源或检查 URL 是否可访问")
            self.set_status("测速失败")
            return

        avg = result["avg"]
        peak = result["peak"]
        stab = result["stability"]
        total_mb = result["total_bytes"] / 1048576
        elapsed = result["elapsed"]
        source = result.get("source", "")
        region = result.get("region", "")
        url = result.get("url", "")

        self.speed_value.set(fmt_speed(avg))
        self.speed_peak_var.set("峰值 " + fmt_speed(peak))
        self.speed_bar["value"] = 100
        self.speed_line1.set(
            "平均 %s   ·   稳健峰值 %s   ·   共下载 %.1f MB / %.1f 秒"
            % (fmt_speed(avg), fmt_speed(peak), total_mb, elapsed))
        if stab is not None:
            self.speed_line2.set(
                "%s源 %s   ·   稳定性 %.0f%%   ·   %d 线程   ·   IQR 法评估"
                % (region, source, stab, SPEED_THREADS))
        else:
            self.speed_line2.set(
                "%s源 %s   ·   %d 线程" % (region, source, SPEED_THREADS))

        if region in ("内网", "自定义") and url:
            self.speed_line2.set(self.speed_line2.get() + "   ·   " + url)

        self.set_status("测速完成（%s源）：平均 %s，峰值 %s"
                        % (region, fmt_speed(avg), fmt_speed(peak)))

    # ------------------------------------------------------------------
    # 配置增删改
    # ------------------------------------------------------------------
    def save_current(self):
        cfg = self.validate_form()
        if not cfg:
            return
        name = self.name_var.get().strip() or ("%s-%s" % (cfg["iface"], cfg["ip"]))
        cfg["name"] = name

        for i, c in enumerate(self.configs):
            if c.get("name") == name:
                if messagebox.askyesno("重名",
                                       "已存在名为「%s」的配置，是否覆盖？" % name):
                    self.configs[i] = cfg
                    self._persist()
                    self._refresh_tree()
                    self.set_status("已覆盖配置「%s」" % name)
                return

        self.configs.append(cfg)
        self._persist()
        self._refresh_tree()
        self.name_var.set("")
        self.set_status("已保存配置「%s」" % name)

    def update_selected(self):
        i = self._selected_index()
        if i is None:
            messagebox.showinfo("提示", "请先选择要覆盖的配置")
            return
        cfg = self.validate_form()
        if not cfg:
            return
        cfg["name"] = self.configs[i].get("name", cfg["ip"])
        self.configs[i] = cfg
        self._persist()
        self._refresh_tree()
        self.tree.selection_set(str(i))
        self.set_status("已更新配置「%s」" % cfg["name"])

    def delete_selected(self):
        i = self._selected_index()
        if i is None:
            messagebox.showinfo("提示", "请先选择要删除的配置")
            return
        name = self.configs[i].get("name", "")
        if not messagebox.askyesno("确认删除", "确定删除配置「%s」？" % name):
            return
        del self.configs[i]
        self._persist()
        self._refresh_tree()
        self.set_status("已删除配置「%s」" % name)

    def load_selected(self):
        i = self._selected_index()
        if i is None:
            messagebox.showinfo("提示", "请先选择一个配置")
            return
        c = self.configs[i]
        real = c.get("iface")
        if real:
            display = self._iface_rev.get(real, real)
            vals = list(self.iface_combo["values"])
            if display not in vals:
                vals.append(display)
                self.iface_combo["values"] = vals
                self._iface_map[display] = real
                self._iface_rev[real] = display
            self.iface_var.set(display)
        self.ip_var.set(c.get("ip", ""))
        self.mask_var.set(c.get("mask", ""))
        self._on_mask_focusout()
        self.gw_var.set(c.get("gateway", ""))
        self.dns1_var.set(c.get("dns1", ""))
        self.dns2_var.set(c.get("dns2", ""))
        self.name_var.set(c.get("name", ""))
        self.iface_state_var.set("（来自配置列表）")
        self.iface_state_lbl.config(style="DhcpState.TLabel")
        self.set_status("已载入配置「%s」到表单" % c.get("name", ""))

    def clear_form(self):
        for v in (self.ip_var, self.mask_var, self.gw_var,
                  self.dns1_var, self.dns2_var, self.name_var):
            v.set("")
        self.prefix_lbl.config(text="")
        self.iface_state_var.set("")
        self.set_status("表单已清空")

    # ------------------------------------------------------------------
    # 其它
    # ------------------------------------------------------------------
    def set_status(self, text):
        self.status_var.set(text)

    def open_scan_dialog(self):
        ip = self.ip_var.get().strip()
        mask = self.mask_var.get().strip()
        ScanDialog(self, ip, mask)

    def _prompt_elevate(self):
        if messagebox.askyesno(
                "需要管理员权限",
                "修改网络配置需要管理员权限。\n\n"
                "是否立即以管理员身份重新启动程序？\n"
                "（选择「否」可继续浏览界面，但应用设置时会失败）"):
            if elevate():
                self.destroy()
            else:
                messagebox.showerror("提权失败",
                                     "请手动右键选择「以管理员身份运行」。")

    def destroy(self):
        try:
            self._rt_stop.set()
        except Exception:
            pass
        try:
            self._stop_ping.set()
            self._stop_speed.set()
        except Exception:
            pass
        super().destroy()