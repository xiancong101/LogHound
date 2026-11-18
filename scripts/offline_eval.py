"""离线评估：对比「固定阈值」与「基线 + 3σ」两种告警策略。

流程：
1. 读取正常业务日志（波峰波谷明显），按 (ip, hour) 建立基线（均值 + 标准差）。
2. 读取攻击日志（正常 + 攻击点混合，带 is_attack 标注）。
3. 分别用两种策略对攻击日志打分，统计告警/误报/漏报。
4. 打印对比表格（结果可复现，供写入 README）。

用法::

    python scripts/make_fake_logs.py --days 30 --seed 42
    python scripts/offline_eval.py --normal data/normal_logs.jsonl \\
        --attack data/attack_logs.jsonl --threshold 200
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# 允许直接以 ``python scripts/offline_eval.py`` 方式运行：把项目根目录加入 sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loghound.baseline import (
    Baseline,
    EvalPoint,
    format_report,
    run_evaluation,
)


def load_points(path: Path) -> list[dict]:
    """读取 JSON Lines 观测点文件。"""
    points: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                points.append(json.loads(line))
    return points


def build_baselines(normal_points: list[dict]) -> dict[tuple[str, int], Baseline]:
    """从正常日志按 (ip, hour) 聚合，计算均值与标准差作为基线。

    对每个 (ip, hour)，取其多天 ``current`` 值的均值与总体标准差。
    """
    grouped: dict[tuple[str, int], list[float]] = defaultdict(list)
    for p in normal_points:
        grouped[(p["ip"], p["hour"])].append(p["current"])

    baselines: dict[tuple[str, int], Baseline] = {}
    for (ip, hour), values in grouped.items():
        n = len(values)
        mean = sum(values) / n
        # 总体标准差
        variance = sum((v - mean) ** 2 for v in values) / n
        std = variance ** 0.5
        baselines[(ip, hour)] = Baseline(mean=mean, std=std)
    return baselines


def to_eval_points(points: list[dict]) -> list[EvalPoint]:
    """把 dict 观测点转为 EvalPoint 列表。"""
    return [
        EvalPoint(
            ip=p["ip"],
            hour=p["hour"],
            current=p["current"],
            recent=p.get("recent", 0.0),
            prev=p.get("prev", 0.0),
            is_attack=p.get("is_attack", False),
        )
        for p in points
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="离线评估两种告警策略")
    parser.add_argument("--normal", required=True, help="正常业务日志文件 (jsonl)")
    parser.add_argument("--attack", required=True, help="攻击日志文件 (jsonl)")
    parser.add_argument("--threshold", type=float, default=200.0, help="固定阈值（次/小时）")
    parser.add_argument("--z-threshold", type=float, default=3.0, help="z-score 阈值")
    parser.add_argument("--burst-threshold", type=float, default=3.0, help="突增比阈值")
    args = parser.parse_args()

    normal_path = Path(args.normal)
    attack_path = Path(args.attack)

    normal_points = load_points(normal_path)
    attack_points = load_points(attack_path)

    print(f"正常日志观测点: {len(normal_points)}")
    print(f"攻击日志观测点: {len(attack_points)}")

    baselines = build_baselines(normal_points)
    print(f"建立的基线数 (ip,hour): {len(baselines)}\n")

    eval_points = to_eval_points(attack_points)
    report = run_evaluation(
        eval_points,
        baselines,
        fixed_threshold=args.threshold,
        z_threshold=args.z_threshold,
        burst_threshold=args.burst_threshold,
    )

    print(format_report(report))


if __name__ == "__main__":
    main()
