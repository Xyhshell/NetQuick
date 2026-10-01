# -*- coding: utf-8 -*-
"""程序图标"""

import tkinter as tk


def make_app_icon():
    s = 64
    img = tk.PhotoImage(width=s, height=s)
    img.put("#0a8f5a", to=(0, 0, s, s))
    img.put("#ffffff", to=(19, 8, 25, 38))
    img.put("#ffffff", to=(9, 34, 35, 42))
    img.put("#ffffff", to=(14, 42, 30, 47))
    img.put("#ffffff", to=(19, 47, 25, 52))
    img.put("#ffffff", to=(39, 26, 45, 56))
    img.put("#ffffff", to=(29, 22, 55, 30))
    img.put("#ffffff", to=(34, 14, 50, 22))
    img.put("#ffffff", to=(39, 8, 45, 14))
    return img