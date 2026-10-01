# -*- coding: utf-8 -*-
"""网段扫描窗口端口范围支持"""

import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from constants import (
    DEFAULT_SCAN_PORTS, DEFAULT_SCAN_TIMEOUT, DEFAULT_SCAN_THREADS,
    MAX_SCAN_HOSTS, port_label,
)
from netutils import is_valid_ip, ip_to_int, int_to_ip
from scanner import (
    parse_port_list, parse_scan_range, subnet_range, get_arp_table,
    resolve_hostname, guess_device_type, mac_vendor, scan_subnet,
    PORT_RANGE_LIMIT,
)


class ScanDialog(tk.Toplevel):

    def __init__(self, parent, default_ip="", default_mask=""):
        super().__init__(parent)
        self.title("网段扫描")
        self.geometry("1100x600")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._stop_flag = threading.Event()
        self._scanning = False
        self._sort_column = "ip"
        self._sort_reverse = False
        self._copy_menu = None
        self._scan_start_ip = ""
        self._scan_end_ip = ""
        self._include_arp = tk.BooleanVar(value=False)

        self._build_ui()
        self._apply_default_range(default_ip, default_mask)
        self._center(parent)

    def _center(self, parent):
        self.update_idletasks()
        try:
            px, py = parent.winfo_rootx(), parent.winfo_rooty()
            pw, ph = parent.winfo_width(), parent.winfo_height()
            w, h = self.winfo_width(), self.winfo_height()
            x = px + max(0, (pw - w) // 2)
            y = py + max(0, (ph - h) // 2)
            self.geometry("+%d+%d" % (x, y))
        except Exception:
            pass

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.pack(fill="both", expand=True)

        # ===== 第一行：扫描范围 =====
        row1 = ttk.Frame(main)
        row1.pack(fill="x")
        ttk.Label(row1, text="扫描范围", width=9, anchor="e").pack(side="left")
        self.range_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.range_var, width=52).pack(
            side="left", padx=(4, 8))
        ttk.Label(row1,
                  text="支持：192.168.1.1-100 / 192.168.1.0/24 / 单个 IP",
                  foreground="#888888").pack(side="left", padx=(0, 8))
        ttk.Button(row1, text="按掩码推算", width=11,
                   command=self._from_mask).pack(side="left")
        ttk.Button(row1, text="恢复默认端口", width=13,
                   command=self._fill_extended_ports).pack(side="left",
                                                           padx=(6, 0))

        # ===== 第二行：探测端口（带范围支持）=====
        row2 = ttk.Frame(main)
        row2.pack(fill="x", pady=(8, 0))
        ttk.Label(row2, text="探测端口", width=9, anchor="e").pack(side="left")
        self.ports_var = tk.StringVar(value=DEFAULT_SCAN_PORTS)
        self.ports_entry = ttk.Entry(row2, textvariable=self.ports_var,
                                     width=86)
        self.ports_entry.pack(side="left", padx=(4, 8))
        ttk.Label(row2,
                  text="支持 80,443 或 1-1024 或 22,80-88,3306（范围单次上限 %d 个）"
                       % PORT_RANGE_LIMIT,
                  foreground="#888888").pack(side="left")

        # ===== 第三行：超时/并发 =====
        row3 = ttk.Frame(main)
        row3.pack(fill="x", pady=(6, 0))

        # ===== 选项 =====
        ttk.Checkbutton(row3, text="显示 ARP 表中无响应设备（可能导致结果杂乱）",
                        variable=self._include_arp).pack(side="left")

        ttk.Label(row3, text="探测超时", width=9, anchor="e").pack(side="left")
        self.timeout_var = tk.StringVar(value=str(DEFAULT_SCAN_TIMEOUT))
        ttk.Entry(row3, textvariable=self.timeout_var, width=8).pack(
            side="left", padx=(4, 6))
        ttk.Label(row3, text="秒").pack(side="left")

        ttk.Label(row3, text="并发线程", width=9, anchor="e").pack(
            side="left", padx=(20, 0))
        self.threads_var = tk.StringVar(value=str(DEFAULT_SCAN_THREADS))
        ttk.Entry(row3, textvariable=self.threads_var, width=8).pack(
            side="left", padx=(4, 6))
        ttk.Label(row3, text="个").pack(side="left")


        # ===== 第四行：控制 + 进度 =====
        row4 = ttk.Frame(main)
        row4.pack(fill="x", pady=(10, 4))
        self.scan_btn = ttk.Button(row4, text="开始扫描", width=11,
                                   command=self._toggle_scan)
        self.scan_btn.pack(side="left")
        self.progress_var = tk.StringVar(value="就绪")
        ttk.Label(row4, textvariable=self.progress_var).pack(
            side="left", padx=(12, 0))

        self.progress_bar = ttk.Progressbar(row4, mode="determinate",
                                            maximum=100, length=360)
        self.progress_bar.pack(side="right")


        # ===== 结果列表 =====
        cols = ("ip", "mac", "vendor", "hostname", "type", "ports")
        heads = {"ip": "IP 地址", "mac": "MAC 地址", "vendor": "厂商",
                 "hostname": "主机名", "type": "设备类型",
                 "ports": "开放端口"}
        widths = {"ip": 100, "mac": 120, "vendor": 130,
                  "hostname": 160, "type": 120, "ports": 440}

        tvf = ttk.Frame(main)
        tvf.pack(fill="both", expand=True, pady=(6, 0))
        self.tree = ttk.Treeview(tvf, columns=cols, show="headings",
                                 selectmode="browse")
        for c in cols:
            self.tree.heading(c, text=heads[c],
                              command=lambda col=c: self._sort_by_column(col))
            self.tree.column(c, width=widths[c], anchor="w", stretch=True)
        vsb = ttk.Scrollbar(tvf, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tvf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        self.tree.bind("<Button-3>", self._tree_right_click)

        # ===== 底部按钮 =====
        row6 = ttk.Frame(main)
        row6.pack(fill="x", pady=(8, 0))
        ttk.Button(row6, text="清空结果", command=self._clear).pack(side="left")
        ttk.Label(row6,
                  text="提示：ping 通、有开放端口或 ARP 表中的设备都会被列出",
                  foreground="#888888").pack(side="left", padx=(10, 0))
        ttk.Button(row6, text="关闭", command=self._on_close).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _fill_extended_ports(self):
        self.ports_var.set(DEFAULT_SCAN_PORTS)

    def _apply_default_range(self, ip, mask):
        if ip and mask and is_valid_ip(ip) and is_valid_ip(mask):
            try:
                s, e = subnet_range(ip, mask)
                self.range_var.set("%s-%s" % (int_to_ip(s), int_to_ip(e)))
                return
            except Exception:
                pass
        self.range_var.set("192.168.1.1-254")

    def _from_mask(self):
        parent = self.master
        ip = parent.ip_var.get().strip()
        mask = parent.mask_var.get().strip()
        if not ip or not mask:
            messagebox.showinfo("提示", "主窗口当前没有 IP/掩码信息", parent=self)
            return
        self._apply_default_range(ip, mask)

    def _toggle_scan(self):
        if self._scanning:
            self._stop_flag.set()
            self.scan_btn.config(state="disabled")
            self.progress_var.set("正在停止…")
            return
        self._start_scan()

    def _start_scan(self):
        range_text = self.range_var.get().strip()
        parsed = parse_scan_range(range_text)
        if not parsed:
            messagebox.showwarning(
                "提示",
                "扫描范围格式不正确。\n\n"
                "支持格式：\n"
                "  · 192.168.1.1-192.168.1.100\n"
                "  · 192.168.1.1-100\n"
                "  · 192.168.1.0/24\n"
                "  · 192.168.1.5",
                parent=self)
            return
        s_int, e_int = parsed

        total = e_int - s_int + 1
        if total > MAX_SCAN_HOSTS:
            if not messagebox.askyesno(
                    "范围较大",
                    "本次将扫描 %d 个地址，可能耗时较长。\n是否继续？" % total,
                    parent=self):
                return

        ports = parse_port_list(self.ports_var.get())
        if not ports:
            messagebox.showwarning("提示",
                                   "请填写至少一个有效端口，例如 80,443 或 1-1024",
                                   parent=self)
            return
        if len(ports) > PORT_RANGE_LIMIT:
            if not messagebox.askyesno(
                    "端口数量较大",
                    "本次将探测 %d 个端口，扫描会非常慢。\n是否继续？"
                    % len(ports), parent=self):
                return

        try:
            timeout = float(self.timeout_var.get())
            if timeout <= 0 or timeout > 5:
                raise ValueError
        except ValueError:
            messagebox.showwarning("提示", "超时时间应在 0～5 秒之间", parent=self)
            return

        try:
            max_threads = int(self.threads_var.get())
            if max_threads < 1 or max_threads > 500:
                raise ValueError
        except ValueError:
            messagebox.showwarning("提示", "并发数应在 1～500 之间", parent=self)
            return

        self._scan_start_ip = int_to_ip(s_int)
        self._scan_end_ip = int_to_ip(e_int)

        self._clear()
        self._scanning = True
        self._stop_flag.clear()
        self.scan_btn.config(text="停止", state="normal")
        self.progress_bar["value"] = 0
        self.progress_var.set("扫描中…（%d 个地址，%d 个端口）"
                              % (total, len(ports)))

        def on_result(ip, open_ports):
            self.after(0, lambda: self._add_result(ip, open_ports))

        def on_progress(done, tot):
            self.after(0, lambda: self._update_progress(done, tot))

        def work():
            try:
                scan_subnet(s_int, e_int, ports, timeout, max_threads,
                            on_result, on_progress, self._stop_flag.is_set)
            except Exception as e:
                self.after(0, lambda: self.progress_var.set("扫描出错：%s" % e))
            finally:
                self.after(0, self._scan_done)

        threading.Thread(target=work, daemon=True).start()

    def _add_result(self, ip, ports):
        for iid in self.tree.get_children():
            if self.tree.item(iid, "values")[0] == ip:
                return
        ports_str = ", ".join(port_label(p) for p in sorted(ports)) if ports else ""
        self.tree.insert("", "end", values=(ip, "", "", "", "", ports_str))
        if self._sort_column is not None:
            self._sort_tree(self._sort_column, self._sort_reverse)

    def _tree_right_click(self, event):
        row_id = self.tree.identify_row(event.y)
        col_id = self.tree.identify_column(event.x)
        if not row_id or not col_id:
            return
        try:
            col_index = int(col_id[1:]) - 1
            columns = self.tree["columns"]
            if col_index < 0 or col_index >= len(columns):
                return
            column = columns[col_index]
            value = self.tree.set(row_id, column)
        except Exception:
            return

        self.tree.selection_set(row_id)
        self.tree.focus(row_id)
        if self._copy_menu is None:
            self._copy_menu = tk.Menu(self, tearoff=False)
        self._copy_menu.delete(0, "end")
        self._copy_menu.add_command(
            label="复制当前值",
            command=lambda v=value: self._copy_scan_value(v))
        try:
            self._copy_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._copy_menu.grab_release()

    def _copy_scan_value(self, value):
        try:
            self.clipboard_clear()
            self.clipboard_append(value or "")
            self.update()
        except Exception:
            pass

    def _sort_by_column(self, column):
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False
        self._sort_tree(column, self._sort_reverse)

    @staticmethod
    def _sort_value(column, value):
        text = (value or "").strip()
        if column == "ip":
            return (0, ip_to_int(text)) if is_valid_ip(text) else (1, text.lower())
        if column == "ports":
            nums = [int(x) for x in re.findall(r"\d+", text)]
            return (0, nums[0], tuple(nums)) if nums else (1, ())
        return text.lower()

    def _sort_tree(self, column, reverse=False):
        items = list(self.tree.get_children(""))
        items.sort(
            key=lambda iid: self._sort_value(column, self.tree.set(iid, column)),
            reverse=reverse)
        for index, iid in enumerate(items):
            self.tree.move(iid, "", index)

        cols = ("ip", "mac", "vendor", "hostname", "type", "ports")
        heads = {"ip": "IP 地址", "mac": "MAC 地址", "vendor": "厂商",
                 "hostname": "主机名", "type": "设备类型",
                 "ports": "开放端口"}
        for c in cols:
            suffix = " ↑" if c == column and not reverse else (
                " ↓" if c == column else "")
            self.tree.heading(c, text=heads[c] + suffix,
                              command=lambda col=c: self._sort_by_column(col))

    def _update_progress(self, done, total):
        pct = 100.0 * done / total if total else 0
        self.progress_bar["value"] = pct
        self.progress_var.set("已扫描 %d / %d，发现 %d 台"
                              % (done, total, len(self.tree.get_children())))

    def _scan_done(self):
        self._scanning = False
        self.scan_btn.config(text="开始扫描", state="normal")
        if self._stop_flag.is_set():
            self.progress_var.set("已停止。正在补齐设备信息…")
        else:
            self.progress_bar["value"] = 100
            self.progress_var.set("扫描完成。正在补齐设备信息…")
        self.after(600, self._fill_device_info)

    def _fill_device_info(self):
        table = get_arp_table()

        try:
            s_int = ip_to_int(self._scan_start_ip) if self._scan_start_ip else 0
            e_int = ip_to_int(self._scan_end_ip) if self._scan_end_ip else 0
        except Exception:
            s_int, e_int = 0, 0

        existing_ips = set()
        for iid in self.tree.get_children():
            values = self.tree.item(iid, "values")
            if values:
                existing_ips.add(values[0])

        if self._include_arp.get() and s_int and e_int:
            for ip in sorted(table.keys(),
                             key=lambda x: ip_to_int(x) if is_valid_ip(x) else 0):
                if not is_valid_ip(ip):
                    continue
                ip_i = ip_to_int(ip)
                if s_int <= ip_i <= e_int and ip not in existing_ips:
                    self.tree.insert("", "end",
                                     values=(ip, table[ip], "", "", "", ""))
                    existing_ips.add(ip)

        rows = []
        for iid in self.tree.get_children():
            values = list(self.tree.item(iid, "values"))
            rows.append((iid, values))

        hostname_map = {}
        lock = threading.Lock()

        def _resolve(ip):
            hn = resolve_hostname(ip, timeout=0.5)
            with lock:
                hostname_map[ip] = hn

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=30) as ex:
            for iid, values in rows:
                if values and values[0]:
                    ex.submit(_resolve, values[0])

        for iid, values in rows:
            ip = values[0]
            ports_str = values[5] if len(values) > 5 else ""
            ports = []
            if ports_str:
                for p in ports_str.split(","):
                    p = p.strip()
                    m = re.match(r"(\d+)", p)
                    if m:
                        ports.append(int(m.group(1)))
            mac = table.get(ip, "") or (values[1] if len(values) > 1 else "")
            hostname = hostname_map.get(ip, "")
            vendor = mac_vendor(mac) if mac else ""
            dev_type = guess_device_type(ports, mac, hostname)
            values[1] = mac
            values[2] = vendor
            values[3] = hostname
            values[4] = dev_type
            self.tree.item(iid, values=values)

        if self._sort_column is not None:
            self._sort_tree(self._sort_column, self._sort_reverse)

        n_total = len(self.tree.get_children())
        n_type = {}
        for iid in self.tree.get_children():
            v = self.tree.item(iid, "values")
            t = (v[4] if len(v) > 4 else "") or "未知"
            n_type[t] = n_type.get(t, 0) + 1
        summary = "，".join("%s %d" % (k, v)
                           for k, v in sorted(n_type.items()))
        self.progress_var.set("扫描完成：共 %d 台（%s）" % (n_total, summary))

    def _clear(self):
        self.tree.delete(*self.tree.get_children())

    def _on_close(self):
        if self._scanning:
            self._stop_flag.set()
        self.destroy()