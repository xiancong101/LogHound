"""日志类型自动识别。

给定一行日志，判断它属于 nginx / ssh / app 中的哪一类，
识别不出返回 None。判断顺序：JSON 行最明确 → nginx → ssh。
"""

from __future__ import annotations

import json
import re

from .base import LOG_TYPE_APP, LOG_TYPE_NGINX, LOG_TYPE_SSH

# nginx access log 特征：以 IP 开头，且含方括号时间戳 [dd/Mon/yyyy:hh:mm:ss
# 示例：127.0.0.1 - - [12/Mar/2025:10:23:45 +0800] "GET ...
_NGINX_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}\s+.*\[[^]]+\]\s+"[A-Z]+\s')

# ssh auth log 特征：以 ``Mon dd hh:mm:ss host sshd[pid]:`` 开头
# 示例：Mar 12 10:23:45 host sshd[1234]: Failed password ...
_SSH_RE = re.compile(
    r'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+'
    r'\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:'
)


def sniff_type(line: str) -> str | None:
    """识别单行日志的类型，返回 ``nginx`` / ``ssh`` / ``app``，无法识别返回 None。

    判断顺序（从最明确到最模糊）：
    1. JSON 行 → ``app``
    2. nginx 特征 → ``nginx``
    3. ssh 特征 → ``ssh``
    """
    text = line.strip()
    if not text:
        return None

    # 1) JSON 行：以 { 开头且能解析为 JSON 对象
    if text.startswith("{"):
        try:
            if isinstance(json.loads(text), dict):
                return LOG_TYPE_APP
        except (json.JSONDecodeError, ValueError):
            pass

    # 2) nginx access log
    if _NGINX_RE.match(text):
        return LOG_TYPE_NGINX

    # 3) ssh auth log
    if _SSH_RE.match(text):
        return LOG_TYPE_SSH

    return None
