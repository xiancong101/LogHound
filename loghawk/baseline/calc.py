"""基线异常打分：z-score 与短时突增的综合评分。

打分模型：
    - ``z = (current - mean) / std``，当 ``std`` 为 0（或缺失）时视为 1，
      避免除零；当前值超出均值 3σ 视为异常。
    - 短时突增 ``burst_ratio = recent_5min / prev_5min``，比值 > 3 记为突增。
    - 综合分 ``score = w_z * z + w_burst * burst_ratio``（权重可配置）。

判定 ``is_anomaly``：``z > z_threshold``（默认 3.0）或
``burst_ratio > burst_threshold``（默认 3.0），阈值均可配置。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# 默认阈值
DEFAULT_Z_THRESHOLD = 3.0
DEFAULT_BURST_THRESHOLD = 3.0
# 默认权重
DEFAULT_W_Z = 0.6
DEFAULT_W_BURST = 0.4
# std 为 0 时的替代值（避免除零，同时让 z 不至于无穷大）
STD_FALLBACK = 1.0


@dataclass
class ScoreResult:
    """一次打分的完整结果。"""

    ip: str
    hour: int
    current: float
    mean: float
    std: float
    z: float
    burst_ratio: float
    score: float
    is_anomaly: bool

    def as_dict(self) -> dict:
        """转为可序列化 dict（与需求文档字段一一对应）。"""
        return {
            "ip": self.ip,
            "hour": self.hour,
            "current": self.current,
            "mean": self.mean,
            "std": self.std,
            "z": self.z,
            "burst_ratio": self.burst_ratio,
            "score": self.score,
            "is_anomaly": self.is_anomaly,
        }


def compute_z(current: float, mean: float, std: float) -> float:
    """计算 z-score；std 为 0 或缺失时用 STD_FALLBACK 代替。"""
    if std is None:
        std = STD_FALLBACK
    if std == 0.0:
        std = STD_FALLBACK
    return (current - mean) / std


def compute_burst_ratio(recent: float, prev: float) -> float:
    """计算短时突增比：最近 5 分钟量 / 前 5 分钟量。

    前一时段为 0 时：若当前有量则视为强突增（返回较大值），
    否则返回 0（无突增）。
    """
    if prev == 0.0:
        return float(recent) if recent > 0 else 0.0
    return recent / prev


def score(
    *,
    ip: str,
    hour: int,
    current: float,
    mean: float,
    std: float,
    recent: float,
    prev: float,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    burst_threshold: float = DEFAULT_BURST_THRESHOLD,
    w_z: float = DEFAULT_W_Z,
    w_burst: float = DEFAULT_W_BURST,
) -> ScoreResult:
    """对某 IP 当前小时的请求量做异常打分，返回 :class:`ScoreResult`。

    参数：
        ip: 来源 IP。
        hour: 当前小时（0-23）。
        current: 当前小时的请求量。
        mean / std: 该 (ip, hour) 的基线均值与标准差。
        recent: 最近 5 分钟的请求量。
        prev: 前 5 分钟的请求量。
        z_threshold / burst_threshold / w_z / w_burst: 阈值与权重（可配置）。
    """
    z = compute_z(current, mean, std)
    burst_ratio = compute_burst_ratio(recent, prev)
    combined = w_z * z + w_burst * burst_ratio
    is_anomaly = (z > z_threshold) or (burst_ratio > burst_threshold)

    return ScoreResult(
        ip=ip,
        hour=hour,
        current=current,
        mean=mean,
        std=std,
        z=z,
        burst_ratio=burst_ratio,
        score=combined,
        is_anomaly=is_anomaly,
    )
