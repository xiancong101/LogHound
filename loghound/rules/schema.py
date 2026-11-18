"""规则 schema 校验：加载 YAML 后校验字段完整性、类型与取值范围。

校验失败不抛异常，而是返回结构化的 :class:`SchemaError` 列表，
每条错误都带「文件路径 + 字段名 + 原因」，方便定位问题规则。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import GROUP_BY_CHOICES, SEVERITIES

# 顶层必填字段
_REQUIRED_TOP = ("id", "name", "severity", "match", "window")
# match 允许出现的字段
_MATCH_FIELDS = ("log_type", "status", "path_regex", "ua_regex", "method", "min_size")
# window 允许出现的字段
_WINDOW_FIELDS = ("seconds", "threshold", "group_by", "sliding")
# suppress 允许出现的字段
_SUPPRESS_FIELDS = ("seconds")
# 合法 log_type
_LOG_TYPES = ("nginx", "ssh", "app")


@dataclass
class SchemaError:
    """一条校验错误。"""

    path: str
    field: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}: 字段 '{self.field}' {self.reason}"


def validate_rule(raw: dict[str, Any], source: str) -> list[SchemaError]:
    """校验单条规则 dict，返回错误列表（空列表表示通过）。

    参数：
        raw: 从 YAML 解析出的规则 dict。
        source: 规则文件路径（用于错误定位）。
    """
    errors: list[SchemaError] = []

    if not isinstance(raw, dict):
        return [SchemaError(source, "<root>", "规则顶层必须是映射(dict)")]

    # 1) 必填字段
    for key in _REQUIRED_TOP:
        if key not in raw:
            errors.append(SchemaError(source, key, "缺少必填字段"))

    # 2) 字段类型校验（存在才校验）
    _check_str(errors, raw, source, "id")
    _check_str(errors, raw, source, "name")
    _check_str(errors, raw, source, "description")

    # severity 取值范围
    if "severity" in raw:
        if raw["severity"] not in SEVERITIES:
            errors.append(
                SchemaError(source, "severity", f"取值必须是 {SEVERITIES} 之一，得到 {raw['severity']!r}")
            )

    # attack 可为 null 或字符串
    if "attack" in raw and raw["attack"] is not None and not isinstance(raw["attack"], str):
        errors.append(SchemaError(source, "attack", "必须是字符串或 null"))

    # 3) match 子字段
    if "match" in raw:
        match = raw["match"]
        if not isinstance(match, dict):
            errors.append(SchemaError(source, "match", "必须是映射(dict)"))
        else:
            for key in match:
                if key not in _MATCH_FIELDS:
                    errors.append(SchemaError(source, f"match.{key}", "未知字段"))
            _validate_match(errors, match, source)

    # 4) window 子字段
    if "window" in raw:
        window = raw["window"]
        if not isinstance(window, dict):
            errors.append(SchemaError(source, "window", "必须是映射(dict)"))
        else:
            for key in window:
                if key not in _WINDOW_FIELDS:
                    errors.append(SchemaError(source, f"window.{key}", "未知字段"))
            _validate_window(errors, window, source)

    # 5) suppress 子字段
    if "suppress" in raw:
        suppress = raw["suppress"]
        if not isinstance(suppress, dict):
            errors.append(SchemaError(source, "suppress", "必须是映射(dict)"))
        else:
            for key in suppress:
                if key not in _SUPPRESS_FIELDS:
                    errors.append(SchemaError(source, f"suppress.{key}", "未知字段"))
            if "seconds" in suppress:
                _check_int(errors, suppress, source, "seconds", display="suppress.seconds", min_value=1)

    return errors


def _validate_match(errors: list[SchemaError], match: dict, source: str) -> None:
    """校验 match 各字段的类型与取值范围。"""
    if "log_type" in match and match["log_type"] is not None:
        if match["log_type"] not in _LOG_TYPES:
            errors.append(
                SchemaError(source, "match.log_type", f"必须是 {_LOG_TYPES} 之一，得到 {match['log_type']!r}")
            )
    if "status" in match and match["status"] is not None:
        st = match["status"]
        if not isinstance(st, list) or not all(isinstance(x, int) for x in st):
            errors.append(SchemaError(source, "match.status", "必须是 int 列表，如 [401, 403]"))
    if "method" in match and match["method"] is not None:
        mt = match["method"]
        if not isinstance(mt, list) or not all(isinstance(x, str) for x in mt):
            errors.append(SchemaError(source, "match.method", "必须是字符串列表"))
    if "path_regex" in match and match["path_regex"] is not None:
        if not isinstance(match["path_regex"], str):
            errors.append(SchemaError(source, "match.path_regex", "必须是字符串"))
    if "ua_regex" in match and match["ua_regex"] is not None:
        if not isinstance(match["ua_regex"], str):
            errors.append(SchemaError(source, "match.ua_regex", "必须是字符串"))
    if "min_size" in match and match["min_size"] is not None:
        _check_int(errors, match, source, "min_size", display="match.min_size", min_value=0)


def _validate_window(errors: list[SchemaError], window: dict, source: str) -> None:
    """校验 window 各字段。"""
    _check_int(errors, window, source, "seconds", display="window.seconds", min_value=1)
    _check_int(errors, window, source, "threshold", display="window.threshold", min_value=1)

    if "group_by" in window:
        if window["group_by"] not in GROUP_BY_CHOICES:
            errors.append(
                SchemaError(source, "window.group_by", f"必须是 {GROUP_BY_CHOICES} 之一，得到 {window['group_by']!r}")
            )

    if "sliding" in window and not isinstance(window["sliding"], bool):
        errors.append(SchemaError(source, "window.sliding", "必须是布尔值 true/false"))


def _check_str(errors: list[SchemaError], raw: dict, source: str, field: str) -> None:
    """校验字段为非空字符串。"""
    if field in raw and raw[field] is not None:
        if not isinstance(raw[field], str) or not raw[field].strip():
            errors.append(SchemaError(source, field, "必须是非空字符串"))


def _check_int(
    errors: list[SchemaError],
    raw: dict,
    source: str,
    field: str,
    display: str | None = None,
    min_value: int | None = None,
) -> None:
    """校验字段为 int 且（可选）不小于 min_value。

    参数：
        field: 在 raw 中取值的键名。
        display: 报错时展示的字段路径（默认等于 field）。
    """
    if field not in raw:
        return
    shown = display or field
    value = raw[field]
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(SchemaError(source, shown, f"必须是整数，得到 {value!r}"))
        return
    if min_value is not None and value < min_value:
        errors.append(SchemaError(source, shown, f"必须 >= {min_value}，得到 {value}"))
