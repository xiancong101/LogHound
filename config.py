"""LogHawk 配置加载：读取 config.yaml 并暴露类型化的配置对象。

配置示例（config.yaml）::

    rules_dir: rules/
    db_path: loghawk.db
    webhook_url: null
    baseline:
      enabled: true
      z_threshold: 3.0
      burst_ratio: 3.0
    output:
      console: true
      webhook: false
      prometheus_port: null
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class BaselineConfig:
    """baseline 相关配置。"""

    enabled: bool = True
    z_threshold: float = 3.0
    burst_ratio: float = 3.0


@dataclass
class OutputConfig:
    """output 相关配置。"""

    console: bool = True
    webhook: bool = False
    prometheus_port: Optional[int] = None


@dataclass
class Config:
    """LogHawk 全局配置。"""

    rules_dir: str = "rules/"
    db_path: str = "loghawk.db"
    webhook_url: Optional[str] = None
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    @property
    def rules_dir_path(self) -> Path:
        """规则目录的 Path 对象。"""
        return Path(self.rules_dir)

    @property
    def db_path_obj(self) -> Path:
        """数据库路径的 Path 对象。"""
        return Path(self.db_path)


def load_config(path: str | Path = "config.yaml") -> Config:
    """从 YAML 文件加载配置；文件不存在时返回默认配置。"""
    p = Path(path)
    if not p.exists():
        return Config()

    with open(p, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    baseline_raw = raw.get("baseline") or {}
    output_raw = raw.get("output") or {}

    return Config(
        rules_dir=str(raw.get("rules_dir", "rules/")),
        db_path=str(raw.get("db_path", "loghawk.db")),
        webhook_url=raw.get("webhook_url"),
        baseline=BaselineConfig(
            enabled=bool(baseline_raw.get("enabled", True)),
            z_threshold=float(baseline_raw.get("z_threshold", 3.0)),
            burst_ratio=float(baseline_raw.get("burst_ratio", 3.0)),
        ),
        output=OutputConfig(
            console=bool(output_raw.get("console", True)),
            webhook=bool(output_raw.get("webhook", False)),
            prometheus_port=output_raw.get("prometheus_port"),
        ),
    )


def default_config_yaml() -> str:
    """返回默认 config.yaml 内容（供首次生成配置文件使用）。"""
    return (
        "rules_dir: rules/\n"
        "db_path: loghawk.db\n"
        "webhook_url: null\n"
        "baseline:\n"
        "  enabled: true\n"
        "  z_threshold: 3.0\n"
        "  burst_ratio: 3.0\n"
        "output:\n"
        "  console: true\n"
        "  webhook: false\n"
        "  prometheus_port: null\n"
    )
