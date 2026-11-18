"""SSH auth 日志解析器。

示例行：:

    Mar 12 10:23:45 host sshd[1234]: Failed password for root from 10.0.0.5 port 5512 ssh2

典型 OpenSSH auth 行形如：
    ``<月> <日> <时:分:秒> <host> sshd[<pid>]: <事件> ...``
其中认证失败/成功的字段为：
    ``Failed password for <user> from <ip> port <port> ssh2``
"""

from __future__ import annotations

import re
from typing import Any

from .base import LOG_TYPE_SSH, make_event, to_int, to_iso8601

# 主通道正则：匹配 SSH 认证失败/成功行。
# 分组说明（按括号顺序）：
#   1. time  —— 时间，如 Mar 12 10:23:45
#   2. user  —— 尝试登录的用户名
#   3. ip    —— 来源 IP
#   4. port  —— 来源端口（存进 fields 不单独成字段，仅提取备用）
_MAIN_RE = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?:Failed|Accepted)\s+password\s+for\s+(?P<user>\S+)\s+'
    r'from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
)


def parse_ssh(line: str) -> dict[str, Any] | None:
    """把一行 SSH auth 日志解析为统一事件 dict。

    主通道用预编译正则；失配时回退到分隔符切分；仍失败返回 None。
    """
    raw = line.rstrip("\n")

    # —— 主通道：正则 ——
    m = _MAIN_RE.search(raw)
    if m is not None:
        ts = to_iso8601(m.group("time"))
        if ts is not None:
            ip = m.group("ip")
            # 端口信息并入 path 无意义，这里仅用 ip 构建事件
            return make_event(
                ts=ts,
                ip=ip,
                method=None,
                path=None,
                status=None,
                size=None,
                ua=None,
                raw=raw,
                log_type=LOG_TYPE_SSH,
            )

    # —— 备通道：分隔符切分 ——
    return _parse_by_split(raw)


def _parse_by_split(raw: str) -> dict[str, Any] | None:
    """分隔符切分兜底：定位 ``from <ip>`` 与 ``port <n>`` 提取来源 IP。"""
    tokens = raw.split()
    # 时间 = 前 3 个 token 拼接（Mar 12 10:23:45）
    if len(tokens) < 4:
        return None
    ts = to_iso8601(" ".join(tokens[0:3]))
    if ts is None:
        return None

    # 在 token 序列中找 "from" 后面的 IP
    ip = None
    for i, tok in enumerate(tokens):
        if tok == "from" and i + 1 < len(tokens):
            ip = tokens[i + 1]
            break
    if ip is None:
        return None

    return make_event(
        ts=ts,
        ip=ip,
        method=None,
        path=None,
        status=None,
        size=None,
        ua=None,
        raw=raw,
        log_type=LOG_TYPE_SSH,
    )
