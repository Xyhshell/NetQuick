# -*- coding: utf-8 -*-
"""网络切换器入口
pyinstaller --noconfirm --onefile --windowed --name NetQuick --ico favicon.ico --paths . main.py
"""

import os
import sys

# 让脚本直接运行也能找到同目录下的模块
if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netutils import is_admin
from main_app import App


def main():
    if os.name != "nt":
        print("本程序仅支持 Windows 系统。")
        return
    app = App()
    if not is_admin():
        app.after(400, app._prompt_elevate)
    app.mainloop()


if __name__ == "__main__":
    main()