# -*- coding: utf-8 -*-
"""多网卡批量选择对话框（加长窗口）"""

import tkinter as tk
from tkinter import ttk, messagebox

from interfaces import list_interfaces


class BatchSelectDialog(tk.Toplevel):

    def __init__(self, parent, preselected=None):
        super().__init__(parent)
        self.title("批量选择网卡(测试 - 非本工具重点开发方向)")
        self.geometry("680x400")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.result = None
        preselected = set(preselected or [])

        ttk.Label(self, text="勾选需要同时操作的网卡：",
                  padding=(14, 12, 14, 6)).pack(anchor="w")

        frame = ttk.Frame(self, padding=(14, 0))
        frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(frame, highlightthickness=0)
        sb = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        canvas.create_window((0, 0), window=inner, anchor="nw",
                             width=620)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        self._vars = {}
        pairs = list_interfaces()
        if not pairs:
            ttk.Label(inner, text="未检测到任何网卡").pack(anchor="w", pady=4)
        for disp, real in pairs:
            var = tk.BooleanVar(value=(real in preselected))
            cb = ttk.Checkbutton(inner, text=disp, variable=var)
            cb.pack(anchor="w", pady=2, fill="x")
            self._vars[real] = var

        ttk.Label(self,
                  text="提示：多网卡使用同一 IP 会产生冲突，"
                       "仅建议用于主备网卡或纯测试。",
                  foreground="#888888",
                  padding=(14, 8, 14, 0),
                  wraplength=640).pack(anchor="w")

        btns = ttk.Frame(self, padding=(14, 10))
        btns.pack(fill="x")
        ttk.Button(btns, text="全选",
                   command=lambda: [v.set(True)
                                    for v in self._vars.values()]).pack(
            side="left")
        ttk.Button(btns, text="全不选",
                   command=lambda: [v.set(False)
                                    for v in self._vars.values()]).pack(
            side="left", padx=6)
        ttk.Button(btns, text="取消",
                   command=self.destroy).pack(side="right", padx=6)
        ttk.Button(btns, text="确定", command=self._ok).pack(side="right")

        self._center(parent)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

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

    def _ok(self):
        picked = [k for k, v in self._vars.items() if v.get()]
        if not picked:
            messagebox.showwarning("提示", "请至少选择一块网卡", parent=self)
            return
        self.result = picked
        self.destroy()