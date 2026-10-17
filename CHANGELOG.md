# Changelog

本项目的所有重要变更都记录在这里。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## Unreleased

### Planned

- `audit.py`：支持 `.gitattributes` 与本机全局 gitignore（`core.excludesFile`）的忽略判定。
- `check_history.py`：支持 `--staged` 模式，在提交前扫描暂存区。
- `redact.py`：增加组织名与合同号的脱敏规则。

## 0.1.1 — 2026-10-17

只修 CI 与 Windows 控制台编码，Skill 内容与 0.1.0 一致。

### Fixed

- CI（ruff）：ruff 0.17 扩大了默认规则集（`EXE001` / `UP009` / `UP035`），未改动的代码也开始报错。现在在 `pyproject.toml` 中显式固定 `select = ["E4", "E7", "E9", "F"]`，让 lint 结果不再随 ruff 版本漂移。
- CI（Windows）：`scripts/check_history.py` 在 cp1252 控制台打印中文时抛 `UnicodeEncodeError`，导致两个 windows job 失败。已补齐 stdout/stderr 的 UTF-8 重配置，并在 workflow 中设置 `PYTHONIOENCODING=utf-8`。

### Added

- `pyproject.toml`：ruff 规则集、line-length、pytest `testpaths`。
- 回归测试：用 cp1252 的 stdout 运行 `check_history.py`（测试数 36 → 37）。

### Changed

- 三个脚本在 git 中标记为可执行，与其 shebang 一致。
- CI 的 lint 步骤改为 `ruff check .`（规则由配置决定）。

## 0.1.0 — 2026-10-17

首个公开版本。

### Added

- `SKILL.md`：Agent Skill 入口，含触发场景、五步工作流、评分卡摘要、决策树、渐进式披露索引与合规红线。
- `references/ban-causes.md`：封禁归因六层模型，每层给出「信号 / 平台如何观测 / 用户可自查项 / 合规处置动作 / 证据强度分级」五段，并附六张自查清单（对应评分卡 N1–N5、P1–P4、U1–U4、K1–K5、T1–T4、C1–C3）。
- `references/risk-scorecard.md`：0–100 评分卡，六维度加权（25/20/15/15/15/10）、25 项判定标准、四档阈值、手算示例与 JSON 输入格式。
- `references/network-and-region.md`：一致性三角、IP 类型、企业出口邻居风险、跨境办公的正当解释与 A/B/C 级证据对照。
- `references/payment-and-identity.md`：BIN / 账单地址 / 接入 IP / 姓名的四重一致性、卡类型风险、争议退款的正确处置。
- `references/api-key-hygiene.md`：Key 全生命周期八步、泄露响应的强制顺序（吊销 → 换新 → 清历史）、`git filter-repo` 与 BFG 清理步骤、pre-commit 钩子。
- `references/third-party-risk.md`：中转/镜像/共享号池的结构性风险拆解、七项评估问卷、TCO 对比、迁移九步与常见辩护的反驳。
- `references/incident-response.md`：0–24h（止损）/ 24–72h（证据与判定）/ 72h+（跟进、迁移、复盘）三段行动清单与时间线模板。
- `references/appeal-templates.md`：中英双语申诉模板三套（疑似误封 / 共享账号 / 支付问题）+ 跟进与数据导出模板 + 语气规则与禁用句式。
- `references/myths.md`：12 个常见"偏方"的「说法 / 为什么听起来有道理 / 为什么有害 / 正确做法」拆解与对照表。
- `scripts/audit.py`：只读本地体检（环境变量与 `.env`、疑似密钥、非官方 `base_url`、多账号痕迹、git 历史、时区一致性），输出终端摘要 + `report.md` + `report.json`；支持 `--scorecard` 评分、`--fail-on` CI 门禁。
- `scripts/check_history.py`：扫描 git 历史新增行与提交信息中的密钥痕迹，输出脱敏结果，无 git 时优雅降级。
- `scripts/redact.py`：分享前脱敏（Key / Bearer / JWT / 私钥块 / Cookie / URL token / 邮箱 / 手机号 / 公网 IP / 用户名路径），幂等、支持 `--check` 门禁。
- `assets/scorecard-template.md`：可打印的 25 项自查表与计算区。
- `tests/`：37 项测试，覆盖密钥正则命中与不误报、脱敏函数、评分卡边界值（0/20/21/45/46/70/71/100）、三种目录场景、`--fail-on` 退出码、Windows 非 UTF-8 控制台的回归、以及"报告绝不泄漏密钥原文"。
- `.github/workflows/ci.yml`：Ubuntu / macOS / Windows × Python 3.9 / 3.12，跑 pytest、ruff、自检与历史扫描。

### Notes

- 三个脚本均为纯 Python 标准库实现，不联网、无遥测、不上传任何数据。
- 本项目定位为「合规加固 + 误封排查 + 事故响应」，**不提供**任何绕过地区限制、伪造身份、账号买卖或对抗风控的方法；此类需求按 `references/myths.md` 与 `SKILL.md` 第 7 节的标准回应拒绝并给出合规替代路径。

