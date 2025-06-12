from __future__ import annotations
"""Wazuh 告警消費者（正式環境用）。"""


import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from .utils import retry_with_backoff

from .. import config

logger = logging.getLogger(__name__)

# 紀錄檔案來源的讀取位置
_FILE_OFFSET = 0

def _read_from_file() -> List[Dict[str, Any]]:
    """自設定的檔案讀取新增的告警"""
    path_str = config.WAZUH_ALERTS_FILE
    if not path_str:
        return []
    path = Path(path_str)
    if not path.exists():
        return []
    global _FILE_OFFSET
    alerts = []
    with path.open("r", encoding="utf-8") as f:
        f.seek(_FILE_OFFSET)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                logger.error("無法解析的告警 JSON：%s", line)
        _FILE_OFFSET = f.tell()
    return alerts

def _read_from_http() -> List[Dict[str, Any]]:
    """從 HTTP 端點取得告警 (應回傳 JSON 陣列)"""
    url = config.WAZUH_ALERTS_URL
    if not url:
        return []
    try:
        resp = retry_with_backoff(requests.get, url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return data.get("alerts", [])
        return []
    except Exception as exc:  # pragma: no cover - optional network failure
        logger.error("無法自 %s 取得告警: %s", url, exc)
        return []

def get_alerts_for_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """比對並回傳與指定日誌行相符的告警"""
    if not lines:
        return []
    alerts = []
    alerts.extend(_read_from_file())
    alerts.extend(_read_from_http())
    if not alerts:
        return []

    alert_map: Dict[str, List[Dict[str, Any]]] = {}
    for alert in alerts:
        original = alert.get("full_log") or alert.get("original_log")
        if not original:
            continue
        alert_map.setdefault(original, []).append(alert)

    matched = []
    for line in lines:
        for alert in alert_map.get(line, []):
            matched.append({"line": line, "alert": alert})
    return matched
