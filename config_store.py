# -*- coding: utf-8 -*-
"""配置持久化"""

import json
from constants import CONFIG_FILE


def load_configs():
    try:
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return data.get("configs", [])
    except Exception:
        pass
    return []


def save_configs(configs):
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps({"configs": configs}, ensure_ascii=False, indent=2),
            encoding="utf-8")
        return True, ""
    except Exception as e:
        return False, str(e)