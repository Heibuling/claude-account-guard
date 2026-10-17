---
title: 中英双语申诉模板
last-reviewed: 2026-10
scope: 事实陈述型申诉。模板只提供结构，事实必须由你自己填。
related: incident-response.md, risk-scorecard.md
---

# 申诉模板（中英对照）

## 0. 使用前

1. **模板不制造证据。** 如果你的情况是"确实用了中转/共享账号"，用第 2 套模板并如实说明，不要套第 1 套。
2. **每段方括号都要替换。** 保留 `[...]` 发出去等于告诉对方"这是模板"。
3. **长度控制在 250 词以内。** 支持人员每天读几十封，短、清楚、可核验的更容易被处理。
4. **附件按编号命名**：`01-payment-statement.pdf`、`02-key-revocation.png`、`03-network-proof.pdf`。正文用编号引用。
5. **一个渠道提交一次。** 保留工单号，跟进时引用它。

**语气规则**

| 要 | 不要 |
| --- | --- |
| 陈述事实（时间、动作、可核验材料） | 形容词强化（absolutely / completely / ridiculous） |
| 用 "I would like to request..." 提请求 | 指控（"your system wrongly banned me"） |
| 承认自己配置上的问题并说明已修正 | 威胁（法律、媒体、社交平台曝光） |
| 只写自己能证明的事 | 写"我什么都没做"这种无法证明的绝对陈述 |

---

## 1. 疑似误封（未使用中转/共享账号）

**Subject:** `Account restriction review request — [account email] — ticket [optional]`

**English**

```
Hello,

I am writing to request a review of the restriction placed on my account
[account email] on [YYYY-MM-DD, timezone].

Account details:
- Plan: [Claude Pro / Max / Team seat]
- Billing country: [country]
- Primary access country: [country]

What I observe:
- [e.g. "Since 2026-10-12 09:00 UTC+8 I cannot sign in; the page shows
  '...'." Attach a screenshot as 01-screenshot.png.]

What I have verified on my side:
- The account is used only by me. I have revoked all sessions and changed
  the password (02-session-revocation.png).
- I pay with my own card issued in [country]; the billing address matches
  my residence (03-payment-statement.pdf, card number redacted).
- I access the service from my home connection in [country]; my employer
  can confirm the office egress IP if needed (04-network-proof.pdf).
- No API key of mine has been published. I ran a local check on my
  repositories and history; no credentials were found (05-scan-result.png).

What I have already changed:
- [e.g. "I removed a third-party base_url from my development config on
  2026-10-13 and rotated all API keys."]

Request:
I would like to ask for a review of this restriction, and — if restoration
is not possible — for a brief statement of the reason and an export of my
data.

If any specific document would help, please tell me which one and I will
provide it.

Thank you for your time.

[Full name]
[Account email]
[Date, timezone]
```

**中文**

```
你好，

我希望申请复核我在 [YYYY-MM-DD，时区] 被限制的账号 [邮箱]。

账号信息：
- 订阅类型：[Pro / Max / Team 席位]
- 账单国家：[国家]
- 主要接入国家：[国家]

我观察到的现象：
- [例：自 2026-10-12 09:00 UTC+8 起无法登录，页面提示"..."。截图见附件 01。]

我已核实的情况：
- 账号仅本人使用，已登出全部设备并修改密码（附件 02）。
- 使用本人名下、[国家] 发行的卡支付，账单地址与居住地址一致（附件 03，卡号已遮盖）。
- 我在 [国家] 的家中网络接入；如需，公司可出具办公出口说明（附件 04）。
- 我的 API Key 未公开，已用本地工具扫描仓库与历史，无凭据泄露（附件 05）。

我已经做出的修正：
- [例：2026-10-13 已从开发配置中移除第三方 base_url，并轮换了全部 API Key。]

请求：
希望复核该限制；若无法恢复，希望能说明原因，并允许我导出数据。

如需补充任何材料，请告知具体是哪一份，我会尽快提供。

谢谢。

[姓名]
[账号邮箱]
[日期，时区]
```

---

## 2. 共享账号 / 多人使用（承认 + 迁移）

**用法**：团队共用一个账号被发现时用这套。**不要**假装是自己一个人用——设备列表和多地登录记录会直接推翻。

**Subject:** `Account restriction — shared account, migration plan — [account email]`

**English**

```
Hello,

I am the owner of the account [account email], restricted on
[YYYY-MM-DD]. I am writing to explain the situation accurately.

What happened:
Between [start date] and [end date], [N] colleagues used this account
under my login, because we had not yet purchased individual seats. This
was a mistake on my part: the consumer terms do not permit sharing an
account this way.

What we have done:
- All shared access stopped on [date].
- Every API key that was used by the team has been revoked
  (01-key-revocation.png).
- We have purchased [N] Team seats / started an enterprise procurement
  process, order [order number] (02-order-confirmation.pdf).

Request:
I understand that a violation occurred. I would like to ask for a review
of the account's status and, if restoration is not possible, for an export
of the account data so the team can migrate.

We are prepared to proceed entirely on licensed seats from now on. If
there is a formal process we should follow to close this out, please let
me know.

Thank you.

[Full name]
[Account email]
[Date]
```

**中文**

```
你好，

我是账号 [邮箱] 的所有者，该账号于 [日期] 被限制。我希望准确说明情况。

发生了什么：
在 [开始日期] 至 [结束日期] 期间，[N] 位同事使用了我的账号登录，因为
我们尚未购买独立席位。这是我的错误：消费者条款不允许以这种方式共享账号。

我们已经做的：
- 已于 [日期] 停止全部共享访问。
- 团队使用过的所有 API Key 已吊销（附件 01）。
- 已购买 [N] 个 Team 席位 / 已启动企业采购流程，订单号 [订单号]（附件 02）。

请求：
我理解这构成了违规。希望复核账号状态；若无法恢复，希望允许导出账号数据，
以便团队迁移。

此后我们将完全使用已授权席位。如果有需要走的正式流程，请告知。

谢谢。

[姓名]
[账号邮箱]
[日期]
```

---

## 3. 支付问题（拒付 / 卡片被拒 / 重复扣款）

**Subject:** `Billing issue and account restriction — [account email] — invoice [number]`

**English**

```
Hello,

My account [account email] was restricted on [date], shortly after a
payment problem. I would like to clarify the payment side and ask how to
resolve it.

Payment facts:
- Invoice / receipt: [number], date [YYYY-MM-DD], amount [amount].
- Card: issued in [country] by [bank]; billing address in [country].
- What happened: [e.g. "The charge was declined on 2026-10-10. I did not
  request a chargeback; my bank opened a dispute automatically after a
  fraud alert on my card."]
- Current status: [e.g. "The dispute was withdrawn on 2026-10-12; the bank
  has confirmed this (03-bank-confirmation.pdf)."]

What I have done:
- Updated the payment method to a card in my own name
  (04-payment-method.png).
- Paid the outstanding balance on [date] (05-receipt.pdf).

Request:
Could you confirm whether the account can be reinstated once the payment
record is clean? If a different payment method or a direct invoice is
preferred, I am happy to follow that process.

Thank you.

[Full name]
[Account email]
[Date]
```

**中文**

```
你好，

我的账号 [邮箱] 在 [日期] 被限制，时间紧接在一次支付问题之后。我希望把支付
情况说明清楚，并询问如何解决。

支付情况：
- 发票/收据号：[编号]，日期 [YYYY-MM-DD]，金额 [金额]。
- 卡片：[国家] 的 [银行] 发行；账单地址在 [国家]。
- 经过：[例：2026-10-10 扣款失败。我并未申请争议退款，是银行在触发欺诈
  提醒后自动发起了争议。]
- 当前状态：[例：争议已于 2026-10-12 撤销，银行已出具确认（附件 03）。]

我已经做的：
- 支付方式已改为本人名下的卡（附件 04）。
- 已于 [日期] 结清欠款（附件 05）。

请求：
能否确认在支付记录恢复正常后账号是否可以恢复？如果你们更希望我使用其他
支付方式或对公付款，我愿意按你们的流程办理。

谢谢。

[姓名]
[账号邮箱]
[日期]
```

---

## 4. 追加跟进（模板，别重复全文）

```
Hello,

Following up on ticket [number] submitted on [date].

New information since then:
- [one verifiable item, with attachment number]

The rest of my earlier message still applies. Please let me know if a
specific document would help.

Thank you.
[Name]
```

中文：

```
你好，

跟进 [日期] 提交的工单 [编号]。

此后新增的信息：
- [一条可核验的信息，附附件编号]

此前的说明仍然适用。如需补充具体材料，请告知。

谢谢。
[姓名]
```

---

## 5. 数据导出请求（比"恢复账号"更容易被满足）

```
Hello,

I would like to request an export of the data associated with
[account email]: conversation history, uploaded files, and project
contents, in a machine-readable format if possible.

I understand the account may not be restored. The export is for
[personal archival / migration to a licensed account / compliance
record-keeping].

Please let me know the process and any identity verification you need.

Thank you.
[Name]
```

## 6. 绝对不要写进申诉的句子

| 不要写 | 为什么 |
| --- | --- |
| "I did absolutely nothing wrong." | 无法证明的绝对陈述，且通常不成立（总有某项配置有问题）。 |
| "Your automated system made a mistake." | 指控且无依据；对方不会与你争论算法，只会归档。 |
| "My colleague uses the same setup and is fine." | 与你的账号无关，属于比较而非事实。 |
| "I will sue you / post this on social media." | 威胁会降低处理优先级，且可能违反条款。 |
| "I need this for my business, I will lose money." | 损失陈述不构成证据；只写事实与请求。 |
| 编造的用途或伪造的附件 | 一旦被发现，所有陈述失效，且可能涉及欺诈。 |

## 7. 提交前自查

- [ ] 所有 `[...]` 都已替换为真实信息
- [ ] 正文 ≤ 250 词，无情绪化形容词
- [ ] 每条事实都有附件编号对应
- [ ] 附件已脱敏（无完整 Key、卡号、身份证号）
- [ ] 请求明确（恢复 / 说明原因 / 导出数据，选了一个）
- [ ] 只提交一次，记下工单号与时间
- [ ] 没有要求对方"必须"在某个时间内回复
- [ ] 如果确实违规，用的是第 2 套模板而不是第 1 套
