"""生成假日志数据：正常业务日志（波峰波谷明显）+ 攻击日志。

产出两类文件（均为 JSON Lines，每行一个观测点）：
1. ``normal_logs.jsonl``：正常业务请求量，随小时呈明显波峰波谷。
2. ``attack_logs.jsonl``：在正常基础上叠加攻击时段（异常高流量），
   并带 ``is_attack`` 标注（ground-truth），供离线评估对比两种策略。

每行结构：:

    {"ip": "1.2.3.4", "hour": 12, "current": 320.0,
     "recent": 80.0, "prev": 75.0, "is_attack": false}

用法::

    python scripts/make_fake_logs.py --days 30 --out-dir data
"""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path

# 一天中每个小时的业务高峰系数（近似真实互联网业务：凌晨低谷、午晚高峰）
# 值为该小时相对均值的倍数。
HOURLY_PROFILE = [
    0.3, 0.2, 0.15, 0.15, 0.2, 0.4,   # 0-5 点
    0.7, 1.1, 1.4, 1.5, 1.4, 1.6,     # 6-11 点
    1.8, 1.5, 1.3, 1.2, 1.3, 1.7,     # 12-17 点
    2.0, 1.9, 1.6, 1.2, 0.9, 0.6,     # 18-23 点
]

# 每小时的“基线请求量”（均值量级）
BASE_MEAN = 100.0


def _normal_volume(hour: int, rng: random.Random) -> float:
    """生成某小时正常请求量：均值 = BASE_MEAN * 高峰系数，加噪声。"""
    mean = BASE_MEAN * HOURLY_PROFILE[hour]
    # 泊松近似 + 高斯抖动，让 std 有一定大小
    noise = rng.gauss(0.0, mean * 0.1)
    return max(0.0, mean + noise)


def _attack_volume(hour: int, rng: random.Random) -> float:
    """生成攻击时段的异常高流量：约为该小时正常均值的 5~10 倍。"""
    mean = BASE_MEAN * HOURLY_PROFILE[hour]
    multiplier = rng.uniform(5.0, 10.0)
    return mean * multiplier + rng.gauss(0.0, mean)


def generate(days: int, ips: list[str], seed: int) -> tuple[list[dict], list[dict]]:
    """生成正常点与攻击点序列，返回 (normal_points, attack_points)。"""
    rng = random.Random(seed)
    normal_points: list[dict] = []
    attack_points: list[dict] = []

    # 每个 IP 独立生成，且攻击时段随机分布（约 5% 的 (ip, hour) 为攻击）
    for ip in ips:
        for _ in range(days):
            for hour in range(24):
                recent = _normal_volume(hour, rng)
                prev = _normal_volume(hour, rng)
                current = _normal_volume(hour, rng)

                is_attack = rng.random() < 0.05  # 5% 概率是攻击时段
                point = {
                    "ip": ip,
                    "hour": hour,
                    "current": round(current, 1),
                    "recent": round(recent, 1),
                    "prev": round(prev, 1),
                    "is_attack": is_attack,
                }
                if is_attack:
                    # 攻击时段：current 显著抬升（突增量）
                    point["current"] = round(_attack_volume(hour, rng), 1)
                    # 短时突增：最近 5 分钟显著高于前 5 分钟
                    point["recent"] = round(point["current"] * 0.25, 1)
                    point["prev"] = round(point["current"] * 0.04, 1)
                    attack_points.append(point)
                else:
                    normal_points.append(point)

    return normal_points, attack_points


def write_jsonl(points: list[dict], path: Path) -> None:
    """把观测点列表写入 JSON Lines 文件。"""
    with open(path, "w", encoding="utf-8") as f:
        for p in points:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="生成假日志数据")
    parser.add_argument("--days", type=int, default=30, help="生成天数")
    parser.add_argument("--ips", type=int, default=5, help="IP 数量")
    parser.add_argument("--seed", type=int, default=42, help="随机种子（保证可复现）")
    parser.add_argument("--out-dir", type=str, default="data", help="输出目录")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ips = [f"10.0.0.{i}" for i in range(1, args.ips + 1)]
    normal_points, attack_points = generate(args.days, ips, args.seed)

    # 正常日志：不含攻击（纯业务波峰波谷）
    normal_path = out_dir / "normal_logs.jsonl"
    write_jsonl(normal_points, normal_path)

    # 攻击日志：正常 + 攻击点混合（按 (ip, hour) 排序便于阅读）
    all_points = normal_points + attack_points
    all_points.sort(key=lambda p: (p["ip"], p["hour"]))
    attack_path = out_dir / "attack_logs.jsonl"
    write_jsonl(all_points, attack_path)

    n_attack = len(attack_points)
    print(f"生成完成：")
    print(f"  正常日志: {normal_path}  ({len(normal_points)} 个观测点)")
    print(f"  攻击日志: {attack_path}  ({len(all_points)} 个观测点，含 {n_attack} 个攻击点)")
    print(f"  参数: days={args.days} ips={args.ips} seed={args.seed}")


if __name__ == "__main__":
    main()
