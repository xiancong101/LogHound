"""日志解析模块：将原始日志行解析为结构化事件。

对外暴露：
- ``parse_nginx`` / ``parse_ssh`` / ``parse_app``：三类日志解析函数
- ``sniff_type``：日志类型自动识别
- ``iter_events`` / ``ParseStats``：流式读取与统计
- ``make_event`` / ``validate_event``：统一 dict 的构造与校验
"""

from .app import parse_app
from .base import (
    LOG_TYPE_APP,
    LOG_TYPE_NGINX,
    LOG_TYPE_SSH,
    make_event,
    validate_event,
)
from .nginx import parse_nginx
from .sniff import sniff_type
from .ssh import parse_ssh
from .stream import ParseStats, iter_events

__all__ = [
    "parse_nginx",
    "parse_ssh",
    "parse_app",
    "sniff_type",
    "iter_events",
    "ParseStats",
    "make_event",
    "validate_event",
    "LOG_TYPE_NGINX",
    "LOG_TYPE_SSH",
    "LOG_TYPE_APP",
]
