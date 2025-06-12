from __future__ import annotations
"""日誌解析與啟發式評分輔助函式"""

from typing import Dict, Optional

import re

# 常見的可疑關鍵字，命中越多得分越高
SUSPICIOUS_KEYWORDS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "denied",
    "segfault",
    "kernel panic",
    "unauthorized",
    "refused",
    "error",
]

# Regex patterns for RFC5424 and RFC3164 syslog messages
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<msg>.*)$"
)

RFC3164_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<app>[^\[]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

SEVERITY_MAP = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

FACILITY_MAP = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "clock",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "audit",
    14: "alert",
    15: "clock",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


def parse_syslog_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a syslog line in either RFC5424 or RFC3164 format."""

    m = RFC5424_RE.match(line)
    if not m:
        m = RFC3164_RE.match(line)
    if not m:
        return None

    pri = int(m.group("pri"))
    facility_num = pri // 8
    severity_num = pri % 8

    parsed = {
        "facility": FACILITY_MAP.get(facility_num, str(facility_num)),
        "severity": SEVERITY_MAP.get(severity_num, str(severity_num)),
        "timestamp": m.group("timestamp"),
        "host": m.group("host"),
        "app": m.group("app"),
        "msg": m.group("msg"),
    }

    pid = m.groupdict().get("pid")
    if pid:
        parsed["pid"] = pid
    return parsed


def fast_score(line: str) -> float:
    """以啟發式方式替日誌行計算 0 到 1 的分數"""

    parsed = parse_syslog_line(line)
    if not parsed:
        return 0.0

    score = 0.0

    severity = parsed.get("severity")
    if severity in {"crit", "alert", "emerg"}:
        score += 0.5
    elif severity == "err":
        score += 0.3
    elif severity == "warning":
        score += 0.1

    facility = parsed.get("facility")
    if facility in {"auth", "authpriv"}:
        score += 0.2

    msg = parsed.get("msg", "").lower()
    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in msg)
    if keyword_hits:
        score += min(0.3, keyword_hits * 0.1)

    return min(score, 1.0)
