# 贡献指南

欢迎提交新的检测规则。本文说明如何写一条规则并让它合入 `rules/` 目录。

## 提交新规则的步骤

1. **确认规则不重复**：先看 `rules/` 目录里是否已有覆盖同样场景的规则（`loghawk rules list` 可快速查看）。

2. **复制模板**：以 `rules/bruteforce_ssh.yaml` 为蓝本，或使用 README 里的 5 行模板，新建一个 `.yaml` 文件。

3. **命名规范**：
   - 文件名与 `id` 一致，例如 `id: scanner_ua_sqlmap` → `scanner_ua_sqlmap.yaml`。
   - `id` 用小写字母 + 下划线，描述性命名（如 `bruteforce_ssh`、`dir_bruteforce_404`）。

4. **填写字段**（详见 README「规则编写教程」）：
   - `severity` 只填 `high` / `medium` / `low`。
   - `attack` 有对应 MITRE ATT&CK 技术就填编号，否则填 `null`，不要硬凑。
   - `description` 用一句话说清检测什么，不要写空话。

5. **本地验证**：

   ```bash
   # 确认能加载、schema 校验通过
   loghawk rules list

   # 用样例日志跑一遍，确认规则能按预期触发
   loghawk run samples/attack.log --rules rules/
   ```

6. **写测试**（规则涉及新的匹配逻辑时建议）：在 `tests/test_rules.py` 里补一个用例，验证规则在构造的事件序列上能触发/不触发。

## 规则质量标准

- **可解释**：`description` 能让人一眼看懂"这条规则在抓什么"。
- **阈值有依据**：`window.threshold` 不要拍脑袋，尽量在注释或 description 里说明为什么是这个数。
- **避免误报倾向**：门槛条件（`match`）宁严勿松，优先保证精确率；宁可漏掉边缘 case，也不要让正常流量天天告警。
- **正则先测试**：`path_regex` / `ua_regex` 的正则先在本地样例上验证，避免写错导致静默不匹配。

## 提交方式

- 提交前跑一遍 `python -m pytest tests/` 确认全部通过。
- 一条规则一个文件，一次提交尽量只加一条规则（或一组强相关的规则），方便 review。
- 在提交信息里说明规则的背景：检测什么攻击、对应哪个 ATT&CK 技术、阈值如何定的。

## 目录约定

- 用户规则放顶层 `rules/` 目录，**不要**放到 `loghawk/rules/`（那是规则引擎的代码模块）。
- 内置规则与用户自定义规则目前都在同一个 `rules/` 目录下。注意：加载器只读取 `rules/` 目录**一级**下的 `*.yaml` / `*.yml` 文件，**不会递归读取子目录**，所以规则文件请直接放在 `rules/` 根下。

## 代码贡献

如果改动规则引擎本身（`loghawk/rules/` 下的代码），请：

- 保持纯标准库 + PyYAML 的依赖约束。
- 新增功能补测试。
- 说明改动对现有 20 条内置规则的兼容性影响。
