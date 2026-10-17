---
title: API Key 全生命周期管理
last-reviewed: 2026-10
scope: 密钥卫生。所有命令都是本地只读或明文可审计的操作。
related: ban-causes.md#l4-api-与密钥层对应评分卡-k1k5, third-party-risk.md
---

# API Key 全生命周期管理

## 1. 威胁模型：Key 会从哪里漏出去

| 泄露途径 | 典型场景 | 发现难度 |
| --- | --- | --- |
| 公开仓库 | `git add .` 把 `.env` 推上去；fork 后 PR | 容易（有自动化扫描） |
| git 历史 | 提交后删除文件，历史里仍在 | 中（需要专门扫） |
| 前端 bundle | Key 写进 JS / 移动端安装包 / Electron 的 `app.asar` | 低（等于公开） |
| 日志 | `logging.debug(headers)`；CI 打印环境变量 | 中 |
| 截图与工单 | 报错截图里带 Key；把配置贴进 issue | 高（无自动化） |
| npm/PyPI 包 | 示例代码里带真实 Key | 低 |
| Docker 镜像层 | `ENV ANTHROPIC_API_KEY=...` 或 `COPY .env` | 中 |
| 共享号池/中转 | 中间层直接持有你的 Key | 高（结构性） |
| 笔记本/手机 | 明文 `.env`、备份、同步盘 | 中 |

**一个前提**：只要 Key 出现在上面任何一个地方，就必须假定它已经泄露。不要在"有没有人真的用过"上纠结——你无法知道。

## 2. 生命周期八步

### 2.1 创建

- 一个用途一个 Key，命名写清楚：`prod-api-service`、`dev-local-alice`、`ci-github-actions`。
- 创建时就想好：**它属于哪个环境、哪个服务、谁能吊销它**。
- 记录创建时间与负责人（一份 `keys.md`，不含 Key 值）。

### 2.2 存储

| 场景 | 推荐做法 | 不要做 |
| --- | --- | --- |
| 本地开发 | 系统密钥链，或 `.env` + `.gitignore`（且只在本机） | 写进源码、写进 `settings.py` 默认值 |
| CI | 平台 secret 变量（GitHub Actions Secrets 等） | 写进 workflow 文件、写进 `Dockerfile` |
| 服务器 | 云 KMS / Vault / SSM Parameter Store | 写进 `docker-compose.yml`、systemd unit 明文 |
| 前端/客户端 | **不下发长期 Key**，走后端代理 | 写进 JS、`app.asar`、移动端配置 |
| 团队共享 | 每人独立 Key，或组织级密钥管理 | 一个 Key 全员用、贴在共享文档里 |

`.gitignore` 最小集合：

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
secrets/
report.md
report.json
```

`.env.example` 只放占位符，并且**在文件头写明真实值不要提交**。

### 2.3 使用

- 代码里只读环境变量：`os.environ["ANTHROPIC_API_KEY"]`，不要有默认值兜底成明文。
- 不要打印请求头：`print(client.headers)`、`logging.debug(request)` 都可能带出 `x-api-key` / `Authorization`。
- 本地调试用 `httpx`/`requests` 的日志时，把 header 过滤器关掉。
- curl 命令别写进 shell 历史：用 `--config` 文件或 `HISTIGNORE`。

### 2.4 分级

```
组织 (Organization)
├── prod-*     生产，权限最大、限额最高、必须能单独吊销
├── staging-*  预发，允许更大日志量
├── dev-*      个人开发，限额最低
└── ci-*       CI 专用，只读必要的模型与端点
```

**判断标准**：如果某个 Key 泄露，你能不能只吊销它而不影响其他服务？不能 → 说明分级没做到。

### 2.5 轮换（90 天）

两步走，避免停机：

1. 创建新 Key（`prod-api-service-2026q1`），部署到所有使用者。
2. 观察 24–72 小时，确认旧 Key 调用量降到 0。
3. 吊销旧 Key，记录轮换时间。

轮换不是"有空再做"的事：把它做成日历提醒，或者写进季度 checklist。历史上大量泄露事件都是"Key 用了两年没人动过"。

### 2.6 吊销

- 泄露确认 → **第一步就是吊销**，不要先清理代码、不要先写复盘。
- 吊销后检查用量曲线：吊销前的异常调用量就是"已被滥用"的证据（截图留档，B 级）。
- 离职/外包结束 → 当天吊销其个人 Key。

### 2.7 泄露响应（顺序不能反）

```bash
# 1) 先在 Console 吊销该 Key（人肉操作，最优先）
# 2) 生成新 Key，替换部署配置
# 3) 确认新 Key 生效、旧 Key 拒绝
# 4) 再清理仓库与历史
# 5) 最后写复盘
```

清理历史（**在吊销之后做**）：

```bash
# 方案 A：git-filter-repo（推荐）
pip install git-filter-repo
cat > replacements.txt <<'EOF'
literal:<PASTE_THE_LEAKED_KEY_HERE>==>***REMOVED***
EOF
git filter-repo --replace-text replacements.txt

# 方案 B：BFG
java -jar bfg.jar --replace-text replacements.txt repo.git
```

然后：

```bash
git push --force --all
git push --force --tags
```

并**通知所有协作者重新克隆**（旧克隆里仍有原文）。如果仓库是公开的：假定已被抓取，吊销才是唯一有效动作，清理历史只是止损。

### 2.8 审计

- 每季度跑一次：`python scripts/audit.py --path . --report-dir .`
- 每次发版前跑：`python scripts/check_history.py --path . --fail-on high`（在 CI 里）
- 打开平台侧的密钥扫描/推送保护（GitHub Secret Scanning + Push Protection），把"提交前拦截"做在源头。

提交前钩子（粗粒度但有效）：

```sh
#!/bin/sh
# .git/hooks/pre-commit
files=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$files" ] && exit 0
if echo "$files" | xargs grep -nE 'sk-ant-[A-Za-z0-9_-]{16,}' 2>/dev/null; then
  echo "检测到疑似 API Key，提交已阻止。请改用环境变量。"
  exit 1
fi
```

## 3. 日志与对外分享

日志里最常见的泄露不是 Key 本身，而是"带 Key 的完整请求"和"带个人信息的报告"。

- 应用层：只记录 `request_id`、模型名、token 数、状态码，**不记录 header 与 body 原文**。
- 分享前：`python scripts/redact.py -i report.md -o report.redacted.md`
- 工单里贴日志：先脱敏，再检查一遍有没有 IP、邮箱、路径、订单号。
- 截图：用工具把 URL 栏与侧边栏裁掉；不要截 Console 的 Key 列表页。

`redact.py` 会替换：API Key / Bearer / JWT / 私钥块 / Cookie / URL token / 邮箱 / 手机号 / 公网 IP / 用户名路径。它不保证 100% 覆盖，**发出去之前自己再读一遍**。

## 4. 团队规则（写进 onboarding）

1. 一人一 Key，禁止共用。
2. Key 只存在于密钥管理系统与进程环境，禁止进仓库、聊天记录、文档。
3. 90 天轮换；离职/转岗当天吊销。
4. 泄露 → 5 分钟内吊销，不需要等审批。
5. 任何人发现疑似泄露都可以直接吊销并上报，不追责（追责文化只会让人隐瞒）。

## 5. 自查清单

- [ ] 仓库与历史都没有密钥（`audit.py` + `check_history.py` 均无命中）
- [ ] `.env` 已被 `.gitignore` 覆盖，仓库里只有 `.env.example`
- [ ] 前端/客户端不含任何长期 Key
- [ ] 每个环境/服务有独立 Key，可以单独吊销
- [ ] 有 90 天轮换记录与负责人
- [ ] 日志不打印 header/body，分享前会跑 `redact.py`
- [ ] 团队有"5 分钟内吊销"的授权与流程（含离场回收）

## 6. 证据强度（申诉时会用到）

| 材料 | 级别 | 用途 |
| --- | --- | --- |
| Console 的 Key 列表与吊销时间戳 | A | 证明"发现即处置" |
| 轮换记录（含负责人） | A | 证明有管理制度 |
| 用量曲线截图（异常段） | B | 解释"突增不是你用的" |
| CI secret 配置截图（值不可见） | B | 证明未硬编码 |
| 代码提交时间线 | B | 佐证泄露窗口 |
