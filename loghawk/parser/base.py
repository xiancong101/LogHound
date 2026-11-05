"""日志解析公共基础设施：统一 dict 的构造、校验与类型转换。

所有解析器（nginx / ssh / app）最终都产出一个统一结构的 dict，
字段见 :func:`make_event`。这样下游（规则匹配、基线统计、告警输出）
只需面对一种数据结构。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# 统一输出 dict 的标准字段顺序（用于构造有序字典，保证可读性）
FIELD_ORDER: tuple[str, ...] = (
    "ts",
    "ip",
    "method",
    "path",
    "status",
    "size",
    "ua",
    "raw",
    "log_type",
)

# 三种日志类型常量
LOG_TYPE_NGINX = "nginx"
LOG_TYPE_SSH = "ssh"
LOG_TYPE_APP = "app"


def make_event(
    *,
    ts: str,
    ip: str | None,
    method: str | None,
    path: str | None,
    status: int | None,
    size: int | None,
    ua: str | None,
    raw: str,
    log_type: str,
) -> dict[str, Any]:
    """按统一字段顺序构造一条日志事件 dict。

    仅负责“组装 + 轻量类型规整”，不校验业务字段是否合法；
    字段级校验交给 :func:`validate_event`。
    """
    return {
        "ts": ts,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "size": size,
        "ua": ua,
        "raw": raw,
        "log_type": log_type,
    }


def validate_event(event: dict[str, Any]) -> list[str]:
    """校验事件 dict 的结构与字段类型，返回问题列表（空列表表示通过）。

    校验项：
    - 必须包含全部标准字段
    - ``ts`` 必须为 ISO8601 字符串
    - ``status`` / ``size`` 若存在必须为 int 或 None
    - ``raw`` / ``log_type`` 必须为非空字符串
    """
    problems: list[str] = []
    for key in FIELD_ORDER:
        if key not in event:
            problems.append(f"缺少字段: {key}")
            continue

    if "ts" in event and not _is_iso8601(event["ts"]):
        problems.append(f"ts 不是 ISO8601 字符串: {event['ts']!r}")

    for int_field in ("status", "size"):
        if int_field in event and event[int_field] is not None:
            if isinstance(event[int_field], bool) or not isinstance(event[int_field], int):
                problems.append(f"{int_field} 应为 int 或 None: {event[int_field]!r}")

    for str_field in ("raw", "log_type"):
        if str_field in event and not isinstance(event[str_field], str):
            problems.append(f"{str_field} 应为 str: {event[str_field]!r}")

    return problems


def to_int(value: Any) -> int | None:
    """把任意值安全转换为 int，失败返回 None（不抛异常）。"""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    text = str(value).strip()
    if text == "" or text == "-":
        return None
    try:
        return int(text)
    except (ValueError, TypeError):
        return None


def to_iso8601(value: str) -> str | None:
    """把常见时间字符串统一成 ISO8601（``YYYY-MM-DDTHH:MM:SS``）字符串。

    支持的输入格式（按需扩展）：
    - ``2025-03-12T10:23:45``（原样返回）
    - ``2025-03-12 10:23:45``（空格分隔）
    - ``12/Mar/2025:10:23:45``（nginx 默认时间）
    - ``Mar 12 10:23:45``（ssh 默认时间，年份补当前年）

    无法识别时返回 None，调用方据此决定是否走备通道。
    """
    if not value:
        return None
    text = value.strip()

    # 已经是 ISO8601（带 T 或空格分隔的日期时间）
    if "T" in text:
        try:
            return datetime.fromisoformat(text).isoformat(timespec="seconds")
        except ValueError:
            return None

    candidates: list[tuple[str, str]] = [
        ("%Y-%m-%d %H:%M:%S", text),
        ("%Y-%m-%dT%H:%M:%S", text),
    ]
    for fmt, s in candidates:
        try:
            return datetime.strptime(s, fmt).isoformat(timespec="seconds")
        except ValueError:
            continue

    # nginx: 12/Mar/2025:10:23:45 +0800（可能带时区后缀，先剥离）
    nginx_text = text.split(" ")[0]
    try:
        return datetime.strptime(nginx_text, "%d/%b/%Y:%H:%M:%S").isoformat(timespec="seconds")
    except ValueError:
        pass

    # ssh: Mar 12 10:23:45（无年份，先补占位年份再替换为当前年份）
    # 显式补年份可避免 Python 3.13+ 对无年份日期解析的 DeprecationWarning。
    try:
        dt = datetime.strptime(f"{datetime.now().year} {text}", "%Y %b %d %H:%M:%S")
        return dt.isoformat(timespec="seconds")
    except ValueError:
        pass

    return None


def _is_iso8601(value: Any) -> bool:
    """判断字符串是否为合法的 ISO8601 时间（宽松，兼容秒级）。"""
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False
