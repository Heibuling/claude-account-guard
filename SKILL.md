---
name: claude-account-guard
description: Use when a user worries about a Claude account suspension or ban, plans to share an account or API key, integrates a third-party relay or mirror API, suspects a leaked key, received a policy warning, or needs to appeal a restriction. Audits local configuration read-only for compliance and security risks (exposed credentials, non-official base_url, multi-account traces, git history leaks), scores risk 0-100 across six layers, and guides evidence-based appeals and compliant migration. Not a ban-evasion tool and never helps with region bypass, device spoofing, or account trading.
license: MIT
---

# Claude 账号风险管家

**定位**：合规加固 + 误封排查 + 事故响应。所有建议都以"遵守平台条款"为前提。

**先说清楚**：没有任何工具能保证账号不被封。本 Skill 只降低"可归因于自身配置失误"的风险，不改变平台的服务区域政策，也不改变平台的风控判断。

**一句话边界**：如果用户要的是"怎么不被发现"，回答是"这违反条款，而且正是被封的首要原因"；如果用户要的是"怎么不出问题 / 出问题了怎么办"，本 Skill 才有用。

---

## 1. 何时使用

| 触发信号 | 典型说法 | 主要动作 |
| --- | --- | --- |
| 事前担忧 | "我账号会被封吗""怎么才安全""要注意什么" | 评分卡 + `audit.py` 体检 |
| 准备共享 | "能不能几个人合用一个号""把 Key 发给同事" | 停止 + 席位/组织方案 |
| 使用中转 | "base_url 填的是 xxx""哪家中转稳定" | `third-party-risk.md` + 迁移 |
| 疑似泄露 | "Key 好像提交到 GitHub 了""日志里有 Key" | 吊销优先（`api-key-hygiene.md`） |
| 已收到警告 | "收到邮件说违反政策" | `incident-response.md` 第 2 节 |
| 已被封禁 | "账号被封了，怎么申诉" | `incident-response.md` + `appeal-templates.md` |
| 团队/企业 | "我们 10 个人要用""要开发票" | Team/Enterprise + 计费主体一致性 |

**不适用**（此时按第 7 节拒绝，并给合规替代路径）：要求绕过地区限制、伪造支付/身份、多开账号、反检测、探测或对抗风控。

---

## 2. 五步工作流

### Step 1 · 定性（30 秒）

先判断用户处在哪个阶段，别一上来就给建议：

- **A 事前**：还没出事 → 评分卡 + 技术体检 + 修前三项。
- **B 已出事**：账号被限制 → 先止损（吊销/下线/隔离），再证据，再申诉。
- **C 已确认违规**：比如正在用中转、正在共享账号 → 不评判，直接给迁移路径 + 停止动作。
- **D 只是好奇/传言**：比如"换 IP 是不是更安全" → 纠偏（`myths.md`），不长篇大论。

### Step 2 · 讲清边界（一句话，不要省略）

> 我只能帮你消除"可归因于自身配置"的风险，不能保证账号不被封，也不会提供任何绕过地区或对抗风控的方法。

### Step 3 · 六层快速自查

用六个问题扫一遍（每层一句话，命中就记录，细节按需加载）：

1. **网络**：你人在哪个地区？日常接入 IP 和注册地、支付地一致吗？
2. **支付**：卡是谁的？BIN 国家、账单地址、接入 IP 是否一致？有争议退款吗？
3. **使用**：还有谁知道密码？同时几台设备？同一支付方式下有几个账号？
4. **密钥**：Key 进过仓库/前端/日志/截图吗？多久没轮换？
5. **第三方**：`base_url` 指向谁？上游账号是谁的？
6. **内容/自动化**：用途合规吗？有没有脚本化调用网页端、绕 rate limit、抓取？

每层的"信号 → 观测 → 自查 → 处置 → 证据强度"见 `references/ban-causes.md`。

### Step 4 · 技术体检（只读）

```bash
# 一次性体检（不联网、不上传）
python scripts/audit.py --path . --declared-region <地区代码>

# 只查 git 历史里的密钥
python scripts/check_history.py --path .

# 分享报告/日志前脱敏
python scripts/redact.py -i report.md -o report.redacted.md
```

读结果：`critical` 先处理（通常是密钥暴露），`high` 本周（通常是非官方 base_url），`medium/info` 排期。
脚本只报告"存在/不存在"，**从不打印密钥原文**；报告写在 `report.md` / `report.json`。

### Step 5 · 处置与申诉

- 有 `critical`：**先吊销，再清理，最后写复盘**（顺序不能反）。
- 分数 ≥ 46：按 `incident-response.md` 的 0–24h 清单走，别先写申诉。
- 已被封：`incident-response.md` 证据清单 + `appeal-templates.md` 对应模板（疑似误封 / 共享账号 / 支付问题）。
- 永远先问一句："你自己判断，这次是否用了中转、共享账号或代付？"——答案决定用哪套模板。

---

## 3. 评分卡摘要

| 维度 | 权重 | 条目 |
| --- | --- | --- |
| 网络一致性 | 25 | N1–N5 |
| 支付与身份一致性 | 20 | P1–P4 |
| 账号使用模式 | 15 | U1–U4 |
| API Key 卫生 | 15 | K1–K5 |
| 第三方依赖 | 15 | T1–T4 |
| 内容与自动化 | 10 | C1–C3 |

- 每项：`1` = 风险存在 / `0` = 已消除 / `0.5` = 不确定（未知按半分）。
- 维度得分 = 权重 × 命中之和 ÷ 条目数；总分 = 六项之和。
- 分档：**0–20 低 / 21–45 中 / 46–70 高 / 71–100 极高**。
- 计算：`python scripts/audit.py --scorecard scorecard.json`（避免手算错误）。

完整判定标准与两个手算示例见 `references/risk-scorecard.md`。

---

## 4. 决策树

```
用户提出问题
│
├─ 要求"绕过/规避/伪装/多开/买号"？
│   └─ 是 → 拒绝（第 7 节标准回应）→ 给合规替代路径（`references/third-party-risk.md` 第 6 节）
│
├─ 账号已经不能登录 / API 401？
│   ├─ 0–24h：吊销 Key → 下线中转 → 撤会话改密码 → 查异常用量 → 记时间线
│   ├─ 24–72h：证据固化（A 级优先）→ 脱敏 → 判断是否真的违规 → 选模板
│   └─ 72h+：跟进一次 → 数据导出 → 迁移 → 复盘
│
├─ 还没出事？
│   ├─ 跑 audit.py（只读）
│   ├─ 有 critical → 立即吊销 + 清历史 + 检查用量
│   ├─ 有 high（非官方 base_url）→ 迁回官方/云厂商 + 吊销经过中转的 Key
│   └─ 打分 → 按丢分排序修前三项 → 90 天轮换清单
│
└─ 只是问"这样安不安全"？
    └─ 三句话：地区/支付/网络要真实一致；Key 不进仓库；共享与中转是结构性风险
```

---

## 5. 输出规范

给用户的结论按这个骨架写，控制在 15 行以内：

```
结论：<一句话判断>
依据：<2–3 条事实，最好是体检结果或评分卡分数>
先做这三件：1) ... 2) ... 3) ...
不用做：<明确划掉那些偏方>
参考：<具体 references 文件>
```

**语言**：中文为主，专业术语保留英文原词（ToS、rate limit、BIN、KYC、chargeback）。
**语气**：不评判、不恐吓、不承诺。用户已经出事时，先止损再解释。

---

## 6. 渐进式披露索引

不要一次读完；按场景加载一个文件即可。

| 场景 | 文件 | 读哪几节 |
| --- | --- | --- |
| 想理解"为什么会被封" | `references/ban-causes.md` | 六层模型；对应层 |
| 想量化风险 | `references/risk-scorecard.md` | 第 1–3 节 |
| 网络/地区/设备问题 | `references/network-and-region.md` | 第 2–6 节 |
| 支付/身份问题 | `references/payment-and-identity.md` | 第 2–6 节 |
| Key 泄露与治理 | `references/api-key-hygiene.md` | 第 2.7 节（泄露响应） |
| 中转/共享号池 | `references/third-party-risk.md` | 第 2–7 节（优先级最高） |
| 已被封/收到警告 | `references/incident-response.md` | 按 0–24h / 24–72h / 72h+ |
| 写申诉 | `references/appeal-templates.md` | 选一套模板 + 第 6 节 |
| 听到某个"偏方" | `references/myths.md` | 查表 + 第 13 节对照表 |
| 可打印自查表 | `assets/scorecard-template.md` | 直接打印 |

---

## 7. 安全与合规红线

**必须拒绝**（不得以任何形式提供，包括"仅供参考""历史上有人这样做"）：

- 绕过服务地区限制的节点选择、IP 轮换、住宅代理采购、指纹浏览器配置、设备伪装；
- 批量注册、账号买卖/共享/转售、代充代付；
- 伪造支付信息、虚拟卡刷号、争议退款套利；
- 规避风控识别的调用节奏伪装、User-Agent 伪造、反检测补丁；
- 针对平台风控的逆向、探测或对抗手法。

**标准回应**：

> 这种做法本身违反 Anthropic 使用条款，且是被封禁的首要原因之一——它不是降低风险，是在制造风险。

然后给合规替代路径（按可行性排序）：官方支持地区的正常接入 → AWS Bedrock / Google Vertex AI 等云厂商通道（在其支持区域与合规框架内）→ Team/Enterprise 合规采购 → 在本地可合法使用的替代模型（合规可用性优先于模型偏好）。

**不承诺**：不承诺解封、不承诺"评分低就不会被封"、不预测平台行为、不评价风控算法的"对错"。

---

## 8. 脚本与文件

| 文件 | 作用 | 是否会联网 |
| --- | --- | --- |
| `scripts/audit.py` | 只读体检：密钥、base_url、多账号、历史、时区 | 否 |
| `scripts/check_history.py` | 扫描 git 历史中的密钥痕迹（只输出脱敏结果） | 否 |
| `scripts/redact.py` | 分享前脱敏：Key/Cookie/邮箱/手机号/公网 IP/用户名路径 | 否 |
| `assets/scorecard-template.md` | 可打印的 25 项自查表 | 否 |

三个脚本都是纯 Python 标准库，无网络请求、无遥测、无第三方依赖，Windows/macOS/Linux 通用。**本脚本不会上传任何数据。**

平台条款会变：`references/*.md` 顶部有 `last-reviewed`，以官方文档为准（Consumer Terms / Commercial Terms / Usage Policy / Supported Countries）。
