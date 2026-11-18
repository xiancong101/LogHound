"""规则加载器与热加载 RuleSet。

- :class:`RuleLoader`：从单个 YAML 文件或整个目录加载规则，逐条做 schema 校验。
- :class:`RuleSet`：规则集合的运行时容器，支持基于 mtime 的热加载
  （``watch=True`` 时每次访问前检查目录变化，变化则原子重载，不中断正在进行的检测）。
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Callable, Optional

import yaml

from .models import Match, Rule, Suppress, Window
from .schema import SchemaError, validate_rule

_YAML_SUFFIXES = (".yaml", ".yml")


class RuleLoadError(Exception):
    """规则加载失败（YAML 解析错误或 schema 校验失败）时抛出。"""

    def __init__(self, errors: list[SchemaError], yaml_errors: list[str] | None = None):
        self.errors = errors
        self.yaml_errors = yaml_errors or []
        super().__init__(self._format())

    def _format(self) -> str:
        parts: list[str] = []
        for y in self.yaml_errors:
            parts.append(f"[YAML] {y}")
        for e in self.errors:
            parts.append(str(e))
        return "\n".join(parts)


class RuleLoader:
    """从 YAML 文件加载并校验规则。"""

    def load(self, path: Path) -> list[Rule]:
        """从单个 YAML 文件加载一条规则（文件内顶层必须是规则字段）。

        规则文件格式为「一条规则一个文件」，故顶层即规则本身。
        """
        raw = self._read_yaml(path)
        errors = validate_rule(raw, str(path))
        if errors:
            raise RuleLoadError(errors)
        return [self._build_rule(raw, str(path))]

    def load_dir(self, directory: Path, on_error: Optional[Callable[[Exception], None]] = None) -> list[Rule]:
        """从目录加载所有 ``*.yaml`` / ``*.yml`` 规则文件。

        单个文件出错时：若提供 ``on_error`` 回调则调用并跳过该文件，
        否则抛出 :class:`RuleLoadError`。
        """
        directory = Path(directory)
        rules: list[Rule] = []
        for path in sorted(directory.glob("*")):
            if path.suffix.lower() not in _YAML_SUFFIXES:
                continue
            try:
                rules.extend(self.load(path))
            except RuleLoadError as exc:
                if on_error is not None:
                    on_error(exc)
                else:
                    raise
        return rules

    # ---- 内部辅助 ----

    @staticmethod
    def _read_yaml(path: Path) -> dict:
        """读取并解析 YAML，语法错误包装为 RuleLoadError。"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise RuleLoadError([], [f"{path}: YAML 解析失败: {exc}"]) from exc
        except OSError as exc:
            raise RuleLoadError([], [f"{path}: 读取失败: {exc}"]) from exc

        if not isinstance(data, dict):
            raise RuleLoadError([SchemaError(str(path), "<root>", "顶层必须是映射(dict)")])
        return data

    @staticmethod
    def _build_rule(raw: dict, source: str) -> Rule:
        """把校验通过的 dict 构造为 Rule，并预编译正则。"""
        match_raw = raw.get("match") or {}
        window_raw = raw.get("window") or {}
        suppress_raw = raw.get("suppress") or {}

        match = Match(
            log_type=match_raw.get("log_type"),
            status=match_raw.get("status"),
            path_regex=match_raw.get("path_regex"),
            ua_regex=match_raw.get("ua_regex"),
            method=match_raw.get("method"),
            min_size=match_raw.get("min_size"),
        )
        window = Window(
            seconds=int(window_raw.get("seconds", 300)),
            threshold=int(window_raw.get("threshold", 10)),
            group_by=str(window_raw.get("group_by", "ip")),
            sliding=bool(window_raw.get("sliding", True)),
        )
        suppress = Suppress(seconds=int(suppress_raw.get("seconds", 600)))

        rule = Rule(
            id=str(raw["id"]),
            name=str(raw["name"]),
            severity=str(raw["severity"]),
            description=str(raw.get("description") or ""),
            attack=raw.get("attack"),
            match=match,
            window=window,
            suppress=suppress,
            source=source,
        )
        # 预编译正则（失败时静默置 None，匹配阶段视为不设该条件）
        rule.compiled_path = _compile(match.path_regex)
        rule.compiled_ua = _compile(match.ua_regex)
        return rule


def _compile(pattern: Optional[str]) -> Optional[re.Pattern]:
    """安全编译正则，失败返回 None。"""
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


class RuleSet:
    """规则集合容器，支持基于 mtime 的热加载。

    用法示例（热加载）::

        rs = RuleSet(loader, rules_dir, watch=True)
        for event in stream:
            rs.reload_if_changed()          # 目录变化才重载，否则几乎零开销
            for alert in rs.process(event):  # 处理事件
                ...

    线程安全：内部用锁保护重载过程，重载采用「先构建新列表再原子替换」，
    不会中断正在进行的检测。
    """

    def __init__(
        self,
        loader: RuleLoader,
        rules_dir: Path,
        watch: bool = False,
        on_reload_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        self.loader = loader
        self.rules_dir = Path(rules_dir)
        self.watch = watch
        self.on_reload_error = on_reload_error
        self._rules: list[Rule] = []
        self._lock = threading.Lock()
        self._last_mtimes: dict[str, float] = {}

        # 首次加载
        self.reload()

    # ---- 查询 ----

    @property
    def rules(self) -> list[Rule]:
        """返回当前规则快照（列表引用，读取安全）。"""
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self):
        return iter(self._rules)

    def get(self, rule_id: str) -> Optional[Rule]:
        """按 id 查找规则。"""
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    # ---- 加载与热加载 ----

    def reload(self) -> int:
        """立即重载规则目录，返回加载到的规则数。"""
        with self._lock:
            new_rules = self.loader.load_dir(self.rules_dir, on_error=self.on_reload_error)
            self._rules = new_rules
            self._last_mtimes = self._snapshot_mtimes()
            return len(self._rules)

    def reload_if_changed(self) -> bool:
        """若规则目录发生文件增删改则重载；返回是否发生重载。

        未启用 ``watch`` 时直接返回 False（不检测）。
        """
        if not self.watch:
            return False
        current = self._snapshot_mtimes()
        if current == self._last_mtimes:
            return False
        # 有变化：重载（内部重新快照 mtimes）
        self.reload()
        return True

    # ---- 内部 ----

    def _snapshot_mtimes(self) -> dict[str, float]:
        """扫描规则目录，返回 {文件路径: mtime} 快照。"""
        snapshot: dict[str, float] = {}
        if not self.rules_dir.is_dir():
            return snapshot
        for path in self.rules_dir.glob("*"):
            if path.suffix.lower() in _YAML_SUFFIXES and path.is_file():
                try:
                    snapshot[str(path)] = path.stat().st_mtime
                except OSError:
                    continue
        return snapshot
