"""流式日志读取：逐行、多文件、gzip 透明解压、内存可控。

核心是 :func:`iter_events` 生成器：只保留当前处理的一行 + 已解析的事件，
不会把整个文件读进内存，因此百万行日志的峰值内存可控制在低位。
"""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Any, Iterator

from .app import parse_app
from .base import LOG_TYPE_APP, LOG_TYPE_NGINX, LOG_TYPE_SSH
from .nginx import parse_nginx
from .sniff import sniff_type
from .ssh import parse_ssh

# 日志类型 -> 对应解析函数
_PARSERS: dict[str, Any] = {
    LOG_TYPE_NGINX: parse_nginx,
    LOG_TYPE_SSH: parse_ssh,
    LOG_TYPE_APP: parse_app,
}


class ParseStats:
    """解析过程统计：用于观察各通道命中与失配计数。"""

    __slots__ = ("total", "parsed", "failed", "by_type")

    def __init__(self) -> None:
        self.total = 0
        self.parsed = 0
        self.failed = 0
        self.by_type: dict[str, int] = {}

    def __repr__(self) -> str:  # pragma: no cover - 仅调试用
        return (
            f"ParseStats(total={self.total}, parsed={self.parsed}, "
            f"failed={self.failed}, by_type={self.by_type})"
        )


def iter_events(
    paths: str | Path | list[str | Path],
    *,
    stats: ParseStats | None = None,
) -> Iterator[dict[str, Any]]:
    """遍历一个或多个日志文件，逐行解析并产出统一事件 dict。

    参数：
        paths: 单个路径，或路径列表。支持 ``.log`` 与 ``.log.gz``（gzip 自动解压）。
        stats: 可选的 :class:`ParseStats` 实例，用于累计解析统计。

    说明：
        - 逐行读取，使用生成器惰性产出，整个文件不驻留内存。
        - 每行先 ``sniff_type`` 识别类型，再调用对应解析器；
          解析失败（返回 None）的行被跳过并计入 ``stats.failed``。
    """
    if stats is None:
        stats = ParseStats()

    path_list = _normalize_paths(paths)

    for path in path_list:
        opener = _open(path)
        try:
            for raw_line in opener:
                stats.total += 1
                line = raw_line
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="replace")

                log_type = sniff_type(line)
                if log_type is None:
                    stats.failed += 1
                    continue

                parser = _PARSERS.get(log_type)
                if parser is None:  # 理论上不会发生
                    stats.failed += 1
                    continue

                event = parser(line)
                if event is None:
                    stats.failed += 1
                    continue

                stats.parsed += 1
                stats.by_type[log_type] = stats.by_type.get(log_type, 0) + 1
                yield event
        finally:
            opener.close()


def _normalize_paths(paths: str | Path | list[str | Path]) -> list[Path]:
    """把 paths 统一为 Path 列表。"""
    if isinstance(paths, (str, Path)):
        return [Path(paths)]
    return [Path(p) for p in paths]


def _open(path: Path):
    """按扩展名返回文本或 gzip 文件对象（惰性、可逐行迭代）。"""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")
