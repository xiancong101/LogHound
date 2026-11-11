"""离线评估器：对比「固定阈值」与「基线 + 3σ」两种告警策略。

输入：一份带时间戳的请求量记录（正常业务日志 + 攻击日志），
以及一个标注「哪些时段是攻击时段」的 ground-truth。

输出：每种策略的告警数、误报数（把业务高峰误判为攻击）、漏报数
（真实攻击未告警），并给出可复现的对比结果。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .calc import DEFAULT_BURST_THRESHOLD, DEFAULT_Z_THRESHOLD, score


@dataclass
class EvalPoint:
    """一个评估时间点的观测值。"""

    ip: str
    hour: int
    current: float          # 当前小时请求量
    recent: float = 0.0     # 最近 5 分钟请求量
    prev: float = 0.0       # 前 5 分钟请求量
    is_attack: bool = False  # ground-truth：是否为真实攻击


@dataclass
class StrategyResult:
    """单一策略的评估结果。"""

    name: str
    alerts: int = 0
    false_positives: int = 0  # 波峰段被误判为攻击
    false_negatives: int = 0  # 真实攻击漏报
    true_positives: int = 0   # 正确告警
    total_points: int = 0

    @property
    def precision(self) -> float:
        """精确率 = 正确告警 / 总告警。"""
        return self.true_positives / self.alerts if self.alerts else 1.0

    @property
    def recall(self) -> float:
        """召回率 = 正确告警 / 真实攻击数。"""
        total_attack = self.true_positives + self.false_negatives
        return self.true_positives / total_attack if total_attack else 1.0


@dataclass
class Baseline:
    """一个 (ip, hour) 的基线。"""

    mean: float
    std: float


@dataclass
class EvalReport:
    """完整对比报告。"""

    fixed_threshold: StrategyResult
    baseline_3sigma: StrategyResult
    total_points: int = 0
    total_attacks: int = 0


def evaluate_fixed_threshold(
    points: list[EvalPoint],
    threshold: float,
    *,
    is_attack_fn: Callable[[EvalPoint], bool] | None = None,
) -> StrategyResult:
    """固定阈值策略：当前请求量 > threshold 即告警。"""
    result = StrategyResult(name=f"固定阈值({threshold:g} 次/小时)")
    result.total_points = len(points)
    for p in points:
        if p.current > threshold:
            result.alerts += 1
            if p.is_attack:
                result.true_positives += 1
            else:
                result.false_positives += 1
        else:
            if p.is_attack:
                result.false_negatives += 1
    return result


def evaluate_baseline_3sigma(
    points: list[EvalPoint],
    baselines: dict[tuple[str, int], Baseline],
    *,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    burst_threshold: float = DEFAULT_BURST_THRESHOLD,
) -> StrategyResult:
    """基线 + 3σ 策略：用 (ip, hour) 基线算 z 与突增，任一超阈值即告警。"""
    result = StrategyResult(name=f"基线+3σ (z>{z_threshold:g} 或 burst>{burst_threshold:g})")
    result.total_points = len(points)
    for p in points:
        bl = baselines.get((p.ip, p.hour))
        if bl is None:
            # 无基线：跳过（现实中也无法打分）
            continue
        s = score(
            ip=p.ip,
            hour=p.hour,
            current=p.current,
            mean=bl.mean,
            std=bl.std,
            recent=p.recent,
            prev=p.prev,
            z_threshold=z_threshold,
            burst_threshold=burst_threshold,
        )
        if s.is_anomaly:
            result.alerts += 1
            if p.is_attack:
                result.true_positives += 1
            else:
                result.false_positives += 1
        else:
            if p.is_attack:
                result.false_negatives += 1
    return result


def run_evaluation(
    points: list[EvalPoint],
    baselines: dict[tuple[str, int], Baseline],
    fixed_threshold: float,
    *,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    burst_threshold: float = DEFAULT_BURST_THRESHOLD,
) -> EvalReport:
    """运行两种策略并返回对比报告。"""
    fixed = evaluate_fixed_threshold(points, fixed_threshold)
    base = evaluate_baseline_3sigma(
        points, baselines, z_threshold=z_threshold, burst_threshold=burst_threshold
    )
    total_attacks = sum(1 for p in points if p.is_attack)
    return EvalReport(
        fixed_threshold=fixed,
        baseline_3sigma=base,
        total_points=len(points),
        total_attacks=total_attacks,
    )


def format_report(report: EvalReport) -> str:
    """把对比报告格式化为可读文本表格。"""
    rows = [report.fixed_threshold, report.baseline_3sigma]
    header = f"{'策略':<24} {'告警':>6} {'误报':>6} {'漏报':>6} {'精确率':>8} {'召回率':>8}"
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(
            f"{r.name:<24} {r.alerts:>6} {r.false_positives:>6} "
            f"{r.false_negatives:>6} {r.precision:>7.2%} {r.recall:>7.2%}"
        )
    lines.append("-" * len(header))
    lines.append(f"评估点总数: {report.total_points}   真实攻击点数: {report.total_attacks}")
    return "\n".join(lines)
