# 测试夹具说明

本目录里的文件**只用于测试**，全部是假数据：

| 文件 | 用途 | 说明 |
| --- | --- | --- |
| `sample_config.json` | `redact.py` / `audit.py` 的配置文件样本 | 值里的 `{key}` 占位符由测试在运行时替换成随机生成的假密钥 |
| `sample_git_log.txt` | `check_history.py` 的 `git log -p` 输出样本 | 同上；测试会拼上 `\x01<sha>\x02<subject>` 标记行 |
| `sample_report.md` | `redact.py` 的脱敏样本 | 邮箱、电话、公网 IP、用户名路径都是虚构的 |

**约定**

- 不要在这里放形状完整的假 Key（例如 `sk-ant-` 或 `AKIA` 开头的长串）：本仓库会用自己的扫描器自检，形状完整的假 Key 会被判为 `critical`。
- 需要在测试里用到"看起来像密钥"的字符串时，用运行时拼接（`"sk-ant-" + body`）或随机生成（见 `tests/test_audit.py` 的 `fake_key()`）。
- 提交前跑一遍 `python scripts/audit.py --path . --no-history`，应为 0 条发现。
