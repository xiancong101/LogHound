"""控制台告警输出：带颜色，格式如::

    [HIGH] 12:00:01 ip=10.0.0.5 rule=bruteforce_ssh count=12 T1110.001

颜色通过 ANSI 转义实现；当输出流不是 TTY（如重定向到文件）时自动关闭颜色，
避免污染日志文件。
"""

from __future__ import annotations

import sys
from typing import TextIO

from .base import Alert, OutputBackend, SEVERITY_COLORS

# ANSI 颜色码
_ANSI = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "green": "\033[32m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}


class ConsoleOutput(OutputBackend):
    """把告警以带颜色、可读的一行文本打印到输出流。"""

    def __init__(self, stream: TextIO | None = None, color: bool | None = None) -> None:
        """初始化。

        参数：
            stream: 输出流，默认 stdout。
            color: 是否启用颜色；None 时自动判断（TTY 才着色）。
        """
        self.stream = stream or sys.stdout
        if color is None:
            color = bool(getattr(self.stream, "isatty", lambda: False)())
        self.color = color

    def send(self, alert: Alert) -> None:
        """格式化并打印一条告警。"""
        line = self._format(alert)
        print(line, file=self.stream, flush=True)

    def _format(self, alert: Alert) -> str:
        """拼装一行告警文本。"""
        sev = alert.severity.upper()
        ts = alert.ts
        # 只取时分秒，避免过长的日期前缀
        if "T" in ts:
            ts = ts.split("T")[1]
        elif " " in ts:
            ts = ts.split(" ")[1]
        ts = ts[:8]  # HH:MM:SS

        attack = f" {alert.attack}" if alert.attack else ""
        body = (
            f"[{sev}] {ts} ip={alert.group_value} "
            f"rule={alert.rule_id} count={alert.count}{attack}"
        )

        if self.color:
            color = _ANSI.get(SEVERITY_COLORS.get(alert.severity, "white"), "")
            return f"{color}{body}{_ANSI['reset']}"
        return body
