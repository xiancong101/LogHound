# LogHawk

LogHawk 是一个用 Python 写的日志异常检测与告警引擎：解析 Nginx / SSH / JSON 日志，用 YAML 规则 + 统计基线检测攻击行为，并输出告警到控制台、Webhook、SQLite 或 Prometheus。

```bash
pip install -e .
loghawk run samples/attack.log --rules rules/
# 输出示例：
# [HIGH] 10:23:45 ip=10.0.0.5 rule=scanner_ua_sqlmap count=1 T1595.002
# [HIGH] 10:23:57 ip=10.0.0.5 rule=webshell_access count=3 T1505.003
```

## 目录结构

```
LogHawk/
├── loghawk/                 # 核心包
│   ├── parser/              # 日志解析：三类日志 → 统一 dict 事件
│   ├── rules/               # 规则引擎：YAML 加载、schema 校验、窗口检测
│   ├── baseline/            # 统计基线：按 (ip, hour) 建基线 + 异常打分
│   └── output/              # 告警输出：控制台 / Webhook / SQLite / Prometheus
├── rules/                   # 用户规则 YAML（内置 20 条检测规则）
├── scripts/                 # 生成假数据 + 离线评估对比
├── tests/                   # 单元测试
├── samples/                 # 测试日志样例
├── cli.py                   # 命令行入口
├── config.py                # 配置加载
├── config.yaml              # 配置文件
└── pyproject.toml           # 打包与依赖声明
```

## 安装

依赖只有标准库 + PyYAML（Flask 仅在需要 `/metrics` HTTP 端点时安装）。

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## CLI 命令

```bash
loghawk parse samples/attack.log              # 只解析打印，调试用
loghawk run samples/attack.log --rules rules/ # 全量检测并输出告警
loghawk tail samples/attack.log --rules rules/ # 类似 tail -f 的实时检测
loghawk rules list                            # 列出已加载规则
loghawk eval                                  # 跑基线对比评估
```

## 规则编写教程

规则是 YAML 文件，每条规则一个文件，放在 `rules/` 目录。以 `bruteforce_ssh.yaml` 为例：

```yaml
id: bruteforce_ssh          # ① 唯一标识，全局不可重复
name: SSH 暴力破解          # ② 规则名称（告警里显示）
severity: high              # ③ 级别：high / medium / low
attack: T1110.001           # ④ ATT&CK 技术编号，没有就写 null
match:                      # ⑤ 单条日志的门槛条件（全部满足才算命中）
  log_type: ssh             #    只匹配 ssh 类型的日志
window:                     # ⑥ 时间窗 + 阈值
  seconds: 300              #    窗口长度（秒）
  threshold: 10             #    窗口内命中 >= 10 次才告警
  group_by: ip              #    聚合维度：按 IP 计数
  sliding: true             #    true=滑动窗口；false=固定窗口
suppress:                   # ⑦ 告警抑制
  seconds: 600              #    同一 IP 600 秒内只报一次
description: 同一 IP 在 5 分钟内 SSH 登录失败超过 10 次，疑似口令爆破。
```

逐字段说明：

| 字段 | 必填 | 说明 |
|------|:----:|------|
| `id` | 是 | 规则唯一标识，加载时校验不可重复 |
| `name` | 是 | 展示名称 |
| `severity` | 是 | `high` / `medium` / `low` 三选一 |
| `attack` | 否 | MITRE ATT&CK 技术编号（如 `T1110.001`），无对应写 `null` |
| `match` | 是 | 单条日志门槛条件，内部字段全部为 AND 关系 |
| `match.log_type` | 否 | 日志类型：`nginx` / `ssh` / `app` |
| `match.status` | 否 | 状态码列表，任一命中即可（OR），如 `[401, 403]` |
| `match.method` | 否 | 请求方法列表，如 `[POST, PUT]` |
| `match.path_regex` | 否 | 对请求路径做正则匹配 |
| `match.ua_regex` | 否 | 对 User-Agent 做正则匹配 |
| `match.min_size` | 否 | 响应体大小下限（字节） |
| `window.seconds` | 是 | 时间窗长度（秒） |
| `window.threshold` | 是 | 窗口内命中次数达到该值才告警 |
| `window.group_by` | 是 | 聚合维度：`ip` / `ip+path` / `ua` / `path` / `none` |
| `window.sliding` | 是 | 滑动窗口 `true`；固定窗口 `false`（按整点分片对齐） |
| `suppress.seconds` | 否 | 同一聚合键在 N 秒内只报一次，默认 600 |
| `description` | 否 | 告警说明文字 |

> 关键语义：`match` 是"单条日志是否值得关注"的门槛，`window` 是"一段时间内累计多少次才算攻击"。二者配合——比如 SSH 单条失败日志本身无害，但同一 IP 5 分钟内失败 10 次就值得告警。

## 如何写自己的规则

复制一份模板，改 `id`、`match` 和 `window` 即可：

```yaml
id: my_rule                  # 改成唯一 id
name: 我的规则
severity: medium             # high / medium / low
attack: null                 # 有对应 ATT&CK 编号就填，否则 null
match:
  log_type: nginx            # nginx / ssh / app，可省略
  status: [500]              # 可省略
  path_regex: "/api"         # 可省略
window:
  seconds: 300
  threshold: 10
  group_by: ip
  sliding: true
suppress:
  seconds: 600
description: 一句话说清这条规则在检测什么。
```

保存到 `rules/` 目录，运行 `loghawk rules list` 确认加载成功即可生效（已运行中的 `run`/`tail` 会通过热加载自动感知新规则）。

## 效果数据

「固定阈值」在业务高峰时段容易把正常流量误判为攻击。LogHawk 的 baseline 模块按 `(ip, hour_of_day)` 建立请求量基线，用 z-score + 短时突增比综合打分来降低误报。

下面的数字来自 `scripts/offline_eval.py` 在**合成数据**上的对比（`seed=42`，30 天 × 5 IP，共 3600 个观测点，其中 173 个攻击点）。复现方式：

```bash
python scripts/make_fake_logs.py --days 30 --seed 42 --out-dir data
python scripts/offline_eval.py --normal data/normal_logs.jsonl \
    --attack data/attack_logs.jsonl --threshold 200
```

| 策略 | 告警 | 误报 | 漏报 | 精确率 | 召回率 |
|------|-----:|-----:|-----:|-------:|-------:|
| 固定阈值（200 次/小时） | 285 | 134 | 22 | 52.98% | 87.28% |
| 基线 + 3σ（z>3 或 burst>3） | 176 | 3 | 0 | 98.30% | 100.00% |

在合成数据上，基线 + 3σ 把误报从 134 降到 3，漏报从 22 降到 0。

> 说明：这是**合成数据上的离线对比**，用于验证"基线法比固定阈值更抗业务高峰误报"这个思路，不代表生产环境的实际效果。

## 局限

- **不支持实时流式聚合**。`tail` 子命令是对日志文件的轮询式增量读取（`tail -f` 风格），不是对接 Kafka / Flume 这类实时流的消费框架。
- **基线需要足够历史数据**。baseline 的 `(ip, hour)` 统计基线至少需要约 7 天的历史日志才有意义，否则均值和标准差不稳定，误报/漏报会明显变差。新接入的业务应先积累一段历史再启用基线检测。
- **规则是正则 + 阈值**。检测能力取决于规则的正则写得准不准，不涉及机器学习或模型。
- **SQLite 是单机存储**。适合中小规模日志量，不适合高并发写入或分布式场景。
- **时间解析依赖日志自带时间戳**。日志时间戳缺失或格式特殊时，窗口统计会退化为按处理时间计时。
- **假数据结论不可外推**。上文的效果数据来自合成日志，真实环境的攻击类型和噪声分布不同，需要按实际数据重新评估阈值。

## 技术栈

- Python 3.11+
- 标准库 + PyYAML（必需）+ Flask（可选）
- SQLite（内置 `sqlite3`）
