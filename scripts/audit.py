#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit.py — claude-account-guard 的只读本地风险体检。

它检查什么
----------
1. 环境变量 / .env 中是否存在 ANTHROPIC_API_KEY，以及 .env 是否被 .gitignore 覆盖。
2. 工作区里是否出现疑似密钥（``sk-ant-``、``sk-``、``x-api-key``、``Authorization: Bearer``
   等高熵长串）。
3. ``base_url`` / ``proxy`` 一类配置是否指向官方或云厂商之外的域名（中转风险）。
4. 是否存在多账号 / 多凭据切换痕迹。
5. git 历史中是否留下过密钥（调用同目录的 ``check_history.py``）。
6. 时区 / 语言设置与申报地区是否存在明显矛盾（只提示，不判定）。

它不做什么
----------
* 不联网、不读取密钥的值、不上传任何数据；
* 不修改任何文件（只在 ``--report-dir`` 写出 ``report.md`` / ``report.json``）；
* 不判断平台风控的"真实分值"——评分卡是启发式自查，与平台内部实现无关。

本脚本不会上传任何数据。
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_history  # noqa: E402

VERSION = "0.1.0"

DISCLAIMER = (
    "本报告是启发式自查工具的结果，不是平台风控结论，也不能保证账号不被限制或封禁。"
    "它只帮助你发现「可归因于自身配置失误」的风险；不提供、也不支持任何绕过服务地区、"
    "伪造身份或对抗风控的做法。"
)

DOCS = {
    "consumer_terms": "https://www.anthropic.com/legal/consumer-terms",
    "commercial_terms": "https://www.anthropic.com/legal/commercial-terms",
    "aup": "https://www.anthropic.com/legal/aup",
    "supported_countries": "https://www.anthropic.com/supported-countries",
    "rate_limits": "https://docs.anthropic.com/en/api/rate-limits",
    "getting_help": "https://docs.anthropic.com/en/api/getting-help",
    "api_overview": "https://docs.anthropic.com/en/api/overview",
}

# ---------------------------------------------------------------------------
# 域名判定
# ---------------------------------------------------------------------------
OFFICIAL_DOMAINS = (
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "anthropicusercontent.com",
)

CLOUD_DOMAINS = (
    "amazonaws.com",
    "aws.amazon.com",
    "googleapis.com",
    "cloud.google.com",
    "azure.com",
    "microsoftonline.com",
    "openai.azure.com",
)

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal")


def url_host(value: str) -> str:
    """从一个 URL 中取出小写主机名；解析失败返回空串。"""
    text = value.strip().strip("\"'")
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text.lstrip("/")
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    host = parts.hostname or ""
    return host.lower().strip(".")


def classify_host(host: str) -> str:
    """把主机名归类为 official / cloud / local / third_party / unknown。"""
    if not host:
        return "unknown"
    for domain in OFFICIAL_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "official"
    for domain in CLOUD_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "cloud"
    if host in LOCAL_HOSTS:
        return "local"
    if host.startswith(("10.", "192.168.")) or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", host):
        return "local"
    return "third_party"


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "info": "INFO",
}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    why: str
    fix: str
    docs: str = ""
    location: str = ""
    evidence: List[str] = field(default_factory=list)

    def sort_key(self) -> Tuple[int, str, str]:
        return (SEVERITY_RANK.get(self.severity, 9), self.check_id, self.location)


@dataclass
class AuditReport:
    root: str
    generated_at: str
    findings: List[Finding]
    files_scanned: int = 0
    bytes_scanned: int = 0
    checks_run: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    history: Dict[str, object] = field(default_factory=dict)
    context: Dict[str, object] = field(default_factory=dict)
    declared_region: str = ""

    def counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def verdict_of(counts: Dict[str, int]) -> str:
    if counts.get("critical"):
        return "发现需要立即处理的凭据暴露风险：先吊销密钥，再谈其他。"
    if counts.get("high"):
        return "发现高风险配置线索，建议 72 小时内处理。"
    if counts.get("medium"):
        return "发现中风险线索，建议排期处理，不必恐慌。"
    return "未发现可归因于本地配置的高风险信号（这不代表账号不会被封）。"


# ---------------------------------------------------------------------------
# 文件遍历
# ---------------------------------------------------------------------------
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".idea",
    ".gradle",
    "Pods",
    "site-packages",
    "target",
    ".next",
    ".nuxt",
    ".dart_tool",
    ".terraform",
}

TEXT_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat",
    ".cmd", ".md", ".markdown", ".rst", ".txt", ".log", ".sql", ".rb", ".go", ".rs",
    ".java", ".kt", ".kts", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".swift",
    ".pl", ".lua", ".r", ".scala", ".gradle", ".dockerfile", ".tf", ".tfvars",
    ".html", ".htm", ".xml", ".csv", ".ipynb", ".lock", ".npmrc", ".yamlrc",
}

TEXT_NAMES = {
    ".env", ".env.local", ".envrc", ".npmrc", ".pypirc", ".netrc", ".gitignore",
    ".gitconfig", "dockerfile", "makefile", "procfile", "gemfile", "rakefile",
}

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 4000
SNIPPET_LIMIT = 160


def is_probably_text(path: Path) -> bool:
    name = path.name.lower()
    if name in TEXT_NAMES or name.startswith(".env"):
        return True
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return True
    return suffix == ""


def iter_scan_files(
    root: Path, max_files: int = MAX_FILES
) -> Tuple[List[Path], List[str], bool]:
    """广度优先遍历，返回 (文件列表, 跳过说明, 是否被截断)。"""
    files: List[Path] = []
    skipped: List[str] = []
    truncated = False
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            try:
                if path.is_symlink():
                    continue
                if not path.is_file():
                    continue
                size = path.stat().st_size
            except OSError:
                skipped.append("无法读取元数据: {}".format(path))
                continue
            if size > MAX_FILE_BYTES:
                skipped.append("文件过大已跳过: {} ({} 字节)".format(path, size))
                continue
            if not is_probably_text(path):
                continue
            if len(files) >= max_files:
                truncated = True
                break
            files.append(path)
        if truncated:
            break
    return files, skipped, truncated


def read_text(path: Path, limit: int = MAX_FILE_BYTES) -> Optional[str]:
    """尽力读取文本；二进制或不可读返回 None。会自动去掉 UTF-8 BOM。"""
    try:
        raw = path.read_bytes()[:limit]
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8-sig", "replace")


class IgnoreRules:
    """极简 .gitignore 匹配器（不做否定规则，宁可漏判"已忽略"）。"""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.patterns: List[str] = []
        gitignore = root / ".gitignore"
        if gitignore.is_file():
            text = read_text(gitignore) or ""
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("!"):
                    continue
                self.patterns.append(stripped)

    @property
    def exists(self) -> bool:
        return (self.root / ".gitignore").is_file()

    def matches(self, rel_posix: str) -> bool:
        rel_posix = rel_posix.replace("\\", "/")
        while rel_posix.startswith("./"):
            rel_posix = rel_posix[2:]
        name = rel_posix.rsplit("/", 1)[-1]
        for raw in self.patterns:
            pattern = raw.lstrip("/")
            if pattern.endswith("/"):
                pattern = pattern[:-1]
            if pattern.startswith("**/"):
                pattern = pattern[3:]
            if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(name, pattern):
                return True
            # 「dir/file」形式的规则也匹配目录下的任意层级
            if "/" not in pattern and fnmatch.fnmatch(name, pattern):
                return True
        return False


def is_ignored_path(rel: str, rules: IgnoreRules) -> bool:
    return rules.matches(rel)


# ---------------------------------------------------------------------------
# 检查 1：环境变量与 .env
# ---------------------------------------------------------------------------
DOTENV_KEY_RE = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$"
)
SECRETISH_KEY_NAMES = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "OPENAI_API_KEY",
    "CLAUDE_API_KEY",
)


def _env_value_is_set(raw: str) -> bool:
    value = raw.strip()
    if not value:
        return False
    if value in ("''", '""', "null", "None", "xxx", "your-api-key-here"):
        return False
    return True


def check_env_and_dotenv(
    root: Path, files: Sequence[Path], rules: IgnoreRules
) -> Tuple[List[Finding], Dict[str, object]]:
    findings: List[Finding] = []
    dotenv_files: List[str] = []
    detail: Dict[str, object] = {"dotenv_files": dotenv_files, "keys_present": []}

    for path in files:
        if not (path.name == ".env" or path.name.startswith(".env.")):
            continue
        rel = os.path.relpath(str(path), str(root)).replace("\\", "/")
        dotenv_files.append(rel)
        text = read_text(path) or ""
        for match in DOTENV_KEY_RE.finditer(text):
            key, raw_value = match.group(1), match.group(2)
            if key not in SECRETISH_KEY_NAMES or not _env_value_is_set(raw_value):
                continue
            detail["keys_present"] = list(detail["keys_present"]) + [key]  # type: ignore[arg-type]
            ignored = is_ignored_path(rel, rules)
            severity = "info" if ignored else "critical"
            if ignored:
                why = (
                    "该文件已被 .gitignore 覆盖，风险主要来自误提交（例如 `git add -f`）"
                    "和本地截图/日志分享，而不是正常提交。"
                )
            else:
                why = (
                    "明文密钥放在未被忽略的文件里，一次 `git add .` 就会把它推到远端；"
                    "推到公开仓库后，密钥在几分钟内就会被自动化爬虫采集。"
                )
            findings.append(
                Finding(
                    check_id="AG-011",
                    title="{} 中存在明文密钥".format(path.name),
                    severity=severity,
                    why=why,
                    fix=(
                        "把密钥移出仓库（放进系统密钥管理或 CI secret），"
                        "在 .gitignore 中忽略 `.env*`，只提交 `.env.example`（值为占位符），"
                        "然后按 references/api-key-hygiene.md 吊销并轮换该密钥。"
                    ),
                    docs=DOCS["getting_help"],
                    location="{}:{}".format(rel, text[: match.start()].count("\n") + 1),
                    evidence=["{} = <redacted:len={}>".format(key, len(raw_value.strip()))],
                )
            )

    if not rules.exists and dotenv_files:
        findings.append(
            Finding(
                check_id="AG-060",
                title="仓库缺少 .gitignore",
                severity="medium",
                why="没有 .gitignore 时，.env、日志、报告等文件很容易被误提交。",
                fix="添加 .gitignore，至少包含 `.env*`、`*.log`、`report.md`、`report.json`。",
                docs=DOCS["commercial_terms"],
                location="(仓库根目录)",
            )
        )

    env_key_set = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    auth_token_set = bool(os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip())
    base_url_env = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    detail.update(
        {
            "anthropic_api_key_in_env": env_key_set,
            "anthropic_auth_token_in_env": auth_token_set,
            "anthropic_base_url_in_env": base_url_env,
            "keys_present": sorted(set(detail["keys_present"])),  # type: ignore[arg-type]
        }
    )
    if env_key_set:
        findings.append(
            Finding(
                check_id="AG-010",
                title="当前环境变量中存在 ANTHROPIC_API_KEY",
                severity="info",
                why=(
                    "用环境变量注入密钥是官方推荐做法之一。这里只报告「存在」，"
                    "本脚本从不读取、也从不打印它的值。"
                ),
                fix=(
                    "确认该变量只存在于当前会话/CI 变量中，没有被写进 shell 启动脚本"
                    "（.bashrc / .zshrc / PowerShell $PROFILE）或系统级环境变量。"
                ),
                docs=DOCS["api_overview"],
                location="进程环境 (os.environ)",
            )
        )
    if env_key_set and auth_token_set:
        findings.append(
            Finding(
                check_id="AG-030",
                title="同时设置了 ANTHROPIC_API_KEY 与 ANTHROPIC_AUTH_TOKEN",
                severity="info",
                why="两套凭据同时生效时，很容易在不同工具里用到不同账号，排查时会失去线索。",
                fix="只保留一套凭据，并在 shell 启动脚本中清理另一套。",
                docs=DOCS["api_overview"],
                location="进程环境 (os.environ)",
            )
        )
    return findings, detail


# ---------------------------------------------------------------------------
# 检查 2：工作区疑似密钥
# ---------------------------------------------------------------------------
def scan_files_for_secrets(
    root: Path, files: Sequence[Path], extra_skip: Sequence[Path] = ()
) -> Tuple[List[Finding], int, int]:
    findings: List[Finding] = []
    scanned_bytes = 0
    hits_total = 0
    skip_set = {str(p.resolve()) for p in extra_skip}

    for path in files:
        try:
            if str(path.resolve()) in skip_set:
                continue
        except OSError:
            continue
        text = read_text(path)
        if text is None:
            continue
        scanned_bytes += len(text.encode("utf-8", "replace"))
        rel = os.path.relpath(str(path), str(root)).replace("\\", "/")
        evidence: List[str] = []
        kinds: List[str] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            matches = check_history.find_secrets(line)
            if not matches:
                continue
            hits_total += len(matches)
            kinds.extend(m.kind for m in matches)
            masked, _ = check_history.mask_text(line)
            masked = masked.replace("`", "'").strip()
            if len(masked) > SNIPPET_LIMIT:
                masked = masked[:SNIPPET_LIMIT] + "…"
            if len(evidence) < 3:
                evidence.append("{}:{}  {}".format(rel, lineno, masked))
        if not evidence:
            continue
        severity = "critical" if "anthropic_api_key" in kinds else "high"
        findings.append(
            Finding(
                check_id="AG-012",
                title="文件中出现疑似密钥：{}".format(rel),
                severity=severity,
                why=(
                    "密钥一旦进入代码库，就会沿着 remote、fork、PR、CI 日志、"
                    "截图和聊天记录扩散；撤销之前，任何拿到它的人都能以你的账号身份调用。"
                ),
                fix=(
                    "1) 立即在 Console 撤销该 Key；2) 生成新 Key 并放进密钥管理；"
                    "3) 用环境变量引用；4) 历史清理见 references/api-key-hygiene.md。"
                ),
                docs=DOCS["getting_help"],
                location=rel,
                evidence=evidence,
            )
        )
    return findings, scanned_bytes, hits_total


# ---------------------------------------------------------------------------
# 检查 3：base_url / proxy 指向
# ---------------------------------------------------------------------------
CONFIG_SUFFIXES = {
    ".env", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".ps1", ".sh", ".bat", ".cmd", ".txt", ".md",
}

BASE_URL_RE = re.compile(
    r"""(?im)
    ^[ \t\-#]*(?:export[ \t]+)?
    ["']?
    (anthropic_base_url|anthropic_proxy|anthropic_api_base|api_base|apiBase|
     base_url|baseUrl|baseURL|openai_base_url|proxy|https?_proxy|all_proxy)
    ["']?[ \t]*[:=][ \t]*
    ["']?(https?://[^\s"',;)]+)
    """,
    re.VERBOSE,
)


def check_base_urls(root: Path, files: Sequence[Path]) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()
    for path in files:
        name = path.name.lower()
        if name.startswith(".env"):
            pass
        elif path.suffix.lower() not in CONFIG_SUFFIXES:
            continue
        text = read_text(path)
        if text is None:
            continue
        rel = os.path.relpath(str(path), str(root)).replace("\\", "/")
        for match in BASE_URL_RE.finditer(text):
            key = match.group(1)
            raw_url = match.group(2)
            host = url_host(raw_url)
            category = classify_host(host)
            if category == "official":
                continue
            lineno = text[: match.start()].count("\n") + 1
            dedupe = (host, category)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            safe_url = "https://" + host
            if category == "cloud":
                findings.append(
                    Finding(
                        check_id="AG-022",
                        title="检测到云厂商通道配置：{}".format(host),
                        severity="info",
                        why=(
                            "通过 AWS Bedrock / Google Vertex AI 等云厂商通道接入是合规路径之一，"
                            "但要确认调用发生在该云厂商支持的区域，且计费主体与合同一致。"
                        ),
                        fix="确认区域、计费账号与合同主体；不要把云厂商 Key 与 consumer 账号混用。",
                        docs=DOCS["supported_countries"],
                        location="{}:{}".format(rel, lineno),
                        evidence=["{} = {}".format(key, safe_url)],
                    )
                )
                continue
            if category == "local":
                findings.append(
                    Finding(
                        check_id="AG-021",
                        title="检测到本地/自建网关地址：{}".format(host),
                        severity="medium",
                        why=(
                            "本地网关通常意味着你在中间转发请求。转发层会看到明文请求内容，"
                            "并且一旦它对外暴露，凭据和对话内容都可能被第三方持有。"
                        ),
                        fix=(
                            "确认该网关只监听 127.0.0.1、不记录请求正文、不转发给未知上游；"
                            "非必需时改回官方 endpoint。"
                        ),
                        docs=DOCS["aup"],
                        location="{}:{}".format(rel, lineno),
                        evidence=["{} = {}".format(key, safe_url)],
                    )
                )
                continue
            findings.append(
                Finding(
                    check_id="AG-020",
                    title="配置指向非官方域名（疑似中转/代理）：{}".format(host or "未知"),
                    severity="high",
                    why=(
                        "第三方中转把「谁在用、用了多少」和「凭据本身」都握在手里；"
                        "上游账号池被封时，下游会被连带处置，而且你无法审计它的行为，"
                        "申诉时也说不清请求到底经过了谁。"
                    ),
                    fix=(
                        "把 base_url 改回官方 endpoint（或你所在云厂商的合规 endpoint），"
                        "吊销经过中转的 Key，并按 references/third-party-risk.md 做迁移评估。"
                    ),
                    docs=DOCS["commercial_terms"],
                    location="{}:{}".format(rel, lineno),
                    evidence=["{} = {}".format(key, safe_url)],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 检查 4：多账号 / 多凭据痕迹
# ---------------------------------------------------------------------------
def check_multi_account(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    candidates: List[str] = []
    home = Path.home()
    for base in (home, root):
        try:
            if not base.is_dir():
                continue
            entries = sorted(base.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name.lower()
            try:
                is_dir = entry.is_dir()
            except OSError:
                continue
            # 只把「.claude 的兄弟目录」当作多份凭据的痕迹
            if is_dir and name.startswith(".claude") and entry.name != ".claude":
                candidates.append(str(entry))
    for config in (home / ".claude.json", root / ".claude.json"):
        try:
            if not config.is_file():
                continue
            data = json.loads(read_text(config) or "{}")
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            for key in ("accounts", "profiles", "organizations", "teams"):
                value = data.get(key)
                if isinstance(value, list) and len(value) > 1:
                    candidates.append("{} → {}[{}]".format(config, key, len(value)))
    if candidates:
        findings.append(
            Finding(
                check_id="AG-030",
                title="检测到多账号 / 多凭据痕迹（需人工确认）",
                severity="medium",
                why=(
                    "同一台设备上维护多个账号，平台侧看到的会是同一设备指纹、同一出口 IP、"
                    "可能的同一支付方式；这类关联是「一个账号出问题、其他账号被连带」的常见原因。"
                ),
                fix=(
                    "确认这些凭据是否属于同一主体的合规用途；不要用多开账号分摊风险，"
                    "需要多人协作时走 Team/Enterprise 的成员授权。"
                ),
                docs=DOCS["commercial_terms"],
                location="; ".join(candidates[:5]),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 检查 5：git 历史
# ---------------------------------------------------------------------------
def check_git_history(root: Path, enabled: bool) -> Tuple[List[Finding], Dict[str, object]]:
    findings: List[Finding] = []
    if not enabled:
        return findings, {"available": False, "reason": "用户通过 --no-history 跳过"}
    result = check_history.scan_git_history(str(root))
    if not result.get("available"):
        findings.append(
            Finding(
                check_id="AG-041",
                title="未能扫描 git 历史",
                severity="info",
                why="原因：{}。这不代表历史干净，只是本次没能检查。".format(
                    result.get("reason") or "未知"
                ),
                fix="在仓库根目录手动运行 `python scripts/check_history.py --path .`。",
                docs=DOCS["api_overview"],
                location="git 历史",
            )
        )
        return findings, result
    hits = result.get("hits") or []
    if hits:
        evidence = [
            "commit {}  {}  {}".format(h.get("commit", ""), h.get("path", ""), h.get("kind", ""))
            for h in hits[:5]
        ]
        severity = "critical" if any(
            h.get("kind") == "anthropic_api_key" for h in hits  # type: ignore[union-attr]
        ) else "high"
        findings.append(
            Finding(
                check_id="AG-040",
                title="git 历史中发现 {} 处疑似密钥（已脱敏）".format(len(hits)),
                severity=severity,
                why=(
                    "即使文件后来被删除，历史提交里仍然保留原文；任何克隆过仓库的人都能恢复。"
                    "公开仓库的这类泄露通常在被推送后数分钟内就被自动化工具采集。"
                ),
                fix=(
                    "先吊销再清理：撤销 Key → 生成新 Key → 用 git-filter-repo / BFG 清理历史"
                    "并强推 → 通知协作者重新克隆。顺序见 references/api-key-hygiene.md。"
                ),
                docs=DOCS["getting_help"],
                location="git 历史 ({} 个提交)".format(result.get("commits_scanned", 0)),
                evidence=evidence,
            )
        )
    return findings, result


# ---------------------------------------------------------------------------
# 检查 6：时区 / 语言
# ---------------------------------------------------------------------------
TZ_REGION_HINTS = {
    "Asia/Shanghai": "CN",
    "Asia/Chongqing": "CN",
    "Asia/Urumqi": "CN",
    "Asia/Hong_Kong": "HK",
    "Asia/Macau": "MO",
    "Asia/Taipei": "TW",
    "Asia/Singapore": "SG",
    "Asia/Tokyo": "JP",
    "Asia/Seoul": "KR",
    "Asia/Bangkok": "TH",
    "Asia/Jakarta": "ID",
    "Asia/Kuala_Lumpur": "MY",
    "Asia/Manila": "PH",
    "Asia/Kolkata": "IN",
    "Europe/London": "GB",
    "Europe/Berlin": "DE",
    "Europe/Paris": "FR",
    "Europe/Amsterdam": "NL",
    "Europe/Dublin": "IE",
    "Europe/Zurich": "CH",
    "America/New_York": "US",
    "America/Chicago": "US",
    "America/Denver": "US",
    "America/Los_Angeles": "US",
    "America/Toronto": "CA",
    "America/Vancouver": "CA",
    "America/Sao_Paulo": "BR",
    "Australia/Sydney": "AU",
    "Pacific/Auckland": "NZ",
}


def detect_locale_context(declared_region: str) -> Dict[str, object]:
    tz_env = os.environ.get("TZ", "") or ""
    local_tz = ""
    try:
        local_tz = str(datetime.now().astimezone().tzinfo or "")
    except (OSError, ValueError):
        local_tz = ""
    hint = TZ_REGION_HINTS.get(tz_env, "") if tz_env else ""
    language = (
        os.environ.get("LC_ALL")
        or os.environ.get("LC_CTYPE")
        or os.environ.get("LANG")
        or ""
    )
    proxy_keys = ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"]
    proxy_env = sorted({key for key in proxy_keys if os.environ.get(key, "").strip()})
    return {
        "tz_env": tz_env,
        "local_tz": local_tz,
        "tz_region_hint": hint,
        "language": language,
        "proxy_env": proxy_env,
        "declared_region": declared_region.upper(),
        "utc_offset_minutes": int(time.timezone / -60) if time.timezone else 0,
    }


def check_locale(context: Dict[str, object]) -> List[Finding]:
    findings: List[Finding] = []
    declared = str(context.get("declared_region") or "").upper()
    hint = str(context.get("tz_region_hint") or "")
    if declared and hint and hint != declared:
        findings.append(
            Finding(
                check_id="AG-050",
                title="时区设置与申报地区不一致（仅提示）",
                severity="info",
                why=(
                    "时区/语言/系统区域与申报地区不一致本身不是违规，但它在申诉或人工复核时"
                    "需要解释得清楚：如果你申报的地区与设备设置长期矛盾，说明成本会变高。"
                ),
                fix=(
                    "如属跨境工作/旅行，保留行程与发票作为解释材料；"
                    "不要为了「看起来一致」而伪造设置。"
                ),
                docs=DOCS["supported_countries"],
                location="进程环境 (TZ/LANG)",
                evidence=[
                    "TZ={}".format(context.get("tz_env") or "(未设置)"),
                    "提示地区={} 申报地区={}".format(hint, declared),
                ],
            )
        )
    proxy_env = context.get("proxy_env") or []
    if proxy_env:
        findings.append(
            Finding(
                check_id="AG-051",
                title="环境中存在代理变量：{}".format(", ".join(proxy_env)),  # type: ignore[arg-type]
                severity="medium",
                why=(
                    "代理本身是常见的企业网络设施，但如果它的出口在服务区域之外，"
                    "或者被大量用户共用，就会让账号表现出与你申报地区不一致的网络特征。"
                ),
                fix=(
                    "确认代理是公司合规出口且出口地区与你的申报一致；不要为了「换个地区」"
                    "而使用共享代理、住宅代理或轮换节点。"
                ),
                docs=DOCS["supported_countries"],
                location="进程环境 (proxy)",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 报告渲染
# ---------------------------------------------------------------------------
COLOR = {
    "critical": "1;31",
    "high": "31",
    "medium": "33",
    "info": "36",
    "ok": "32",
    "dim": "2",
}


def paint(text: str, style: str, enabled: bool) -> str:
    if not enabled:
        return text
    return "\x1b[{}m{}\x1b[0m".format(COLOR.get(style, "0"), text)


def _supports_color() -> bool:
    stream = sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def render_terminal(report: AuditReport, color: bool = False) -> str:
    counts = report.counts()
    lines: List[str] = []
    lines.append(paint("claude-account-guard · audit.py " + VERSION, "dim", color))
    lines.append("扫描目录: {}".format(report.root))
    lines.append(
        "扫描文件: {} 个 / {} KB    git 提交: {}".format(
            report.files_scanned,
            max(1, report.bytes_scanned // 1024),
            report.history.get("commits_scanned", 0),
        )
    )
    lines.append("")
    summary = "  ".join(
        "{}={}".format(SEVERITY_LABEL[level], counts.get(level, 0))
        for level in ("critical", "high", "medium", "info")
    )
    lines.append("发现: " + summary)
    lines.append("结论: " + verdict_of(counts))
    lines.append("")
    if not report.findings:
        lines.append(paint("[OK] 没有发现可自动识别的风险信号。", "ok", color))
    for finding in sorted(report.findings, key=lambda f: f.sort_key()):
        header = "[{}] {} {}".format(
            SEVERITY_LABEL.get(finding.severity, finding.severity.upper()),
            finding.check_id,
            finding.title,
        )
        lines.append(paint(header, finding.severity, color))
        if finding.location:
            lines.append("      位置: {}".format(finding.location))
        lines.append("      为什么: {}".format(finding.why))
        lines.append("      怎么办: {}".format(finding.fix))
        if finding.docs:
            lines.append("      文档: {}".format(finding.docs))
        for item in finding.evidence[:3]:
            lines.append("      证据: {}".format(item))
        lines.append("")
    if report.skipped:
        lines.append(paint("以下项目未能检查：", "dim", color))
        for item in report.skipped[:5]:
            lines.append("  - {}".format(item))
        lines.append("")
    lines.append(paint("提示: {}".format(DISCLAIMER), "dim", color))
    if report.findings:
        lines.append("")
        lines.append("下一步（按严重度取前三项）:")
        for index, finding in enumerate(sorted(report.findings, key=lambda f: f.sort_key())[:3], 1):
            lines.append("  {}. {}".format(index, finding.title))
    return "\n".join(lines)


def to_json_dict(report: AuditReport) -> Dict[str, object]:
    counts = report.counts()
    findings = []
    for finding in sorted(report.findings, key=lambda f: f.sort_key()):
        item = {
            "check_id": finding.check_id,
            "severity": finding.severity,
            "title": finding.title,
            "why": finding.why,
            "fix": finding.fix,
            "docs": finding.docs,
            "location": finding.location,
            "evidence": finding.evidence,
        }
        findings.append(item)
    return {
        "tool": {"name": "claude-account-guard/audit.py", "version": VERSION},
        "generated_at": report.generated_at,
        "root": report.root,
        "declared_region": report.declared_region,
        "scan": {
            "files_scanned": report.files_scanned,
            "bytes_scanned": report.bytes_scanned,
            "checks_run": report.checks_run,
            "skipped": report.skipped,
        },
        "history": report.history,
        "context": report.context,
        "summary": {"counts": counts, "verdict": verdict_of(counts)},
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }


def _md_escape(text: str) -> str:
    """最小化转义：竖线会破坏表格，反引号保持原样以便渲染成行内代码。"""
    return text.replace("|", "\\|")


def render_markdown(report: AuditReport) -> str:
    counts = report.counts()
    ordered = sorted(report.findings, key=lambda f: f.sort_key())
    lines: List[str] = []
    lines.append("# claude-account-guard 体检报告")
    lines.append("")
    lines.append("- 生成时间：{}".format(report.generated_at))
    lines.append("- 扫描目录：`{}`".format(report.root))
    lines.append("- 扫描文件：{} 个".format(report.files_scanned))
    lines.append("- git 提交：{}".format(report.history.get("commits_scanned", 0)))
    if report.declared_region:
        lines.append("- 申报地区：{}".format(report.declared_region))
    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append(verdict_of(counts))
    lines.append("")
    lines.append("| CRITICAL | HIGH | MEDIUM | INFO |")
    lines.append("| --- | --- | --- | --- |")
    lines.append(
        "| {} | {} | {} | {} |".format(
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("info", 0),
        )
    )
    lines.append("")
    if not ordered:
        lines.append("没有发现可自动识别的风险信号。")
        lines.append("")
    for finding in ordered:
        lines.append(
            "## [{}] {} {}".format(
                SEVERITY_LABEL.get(finding.severity, finding.severity),
                finding.check_id,
                _md_escape(finding.title),
            )
        )
        lines.append("")
        if finding.location:
            lines.append("- **位置**：`{}`".format(_md_escape(finding.location)))
        lines.append("- **为什么有风险**：{}".format(_md_escape(finding.why)))
        lines.append("- **如何修复**：{}".format(_md_escape(finding.fix)))
        if finding.docs:
            lines.append("- **官方文档**：<{}>".format(finding.docs))
        if finding.evidence:
            lines.append("- **证据（已脱敏）**：")
            for item in finding.evidence:
                lines.append("  - `{}`".format(_md_escape(item)))
        lines.append("")
    lines.append("## 未能检查的项目")
    lines.append("")
    if report.skipped:
        for item in report.skipped:
            lines.append("- {}".format(item))
    else:
        lines.append("- 无")
    lines.append("")
    lines.append("## 免责声明")
    lines.append("")
    lines.append(DISCLAIMER)
    lines.append("")
    lines.append(
        "分享本报告前请先运行 `python scripts/redact.py --input report.md "
        "--output report.redacted.md`，报告中的路径与主机名可能包含个人信息。"
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 评分卡
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScoreItem:
    item_id: str
    label: str


@dataclass(frozen=True)
class Dimension:
    dim_id: str
    label: str
    weight: int
    items: Tuple[ScoreItem, ...]


DIMENSIONS: Tuple[Dimension, ...] = (
    Dimension(
        "network",
        "网络一致性",
        25,
        (
            ScoreItem("N1", "账号注册地/使用地在服务区域名单内，且接入 IP 属于该地区"),
            ScoreItem("N2", "接入 IP 国家与注册地、支付地一致"),
            ScoreItem("N3", "同一会话内没有短时间跨洲 IP 跳变"),
            ScoreItem("N4", "接入 IP 类型单一（数据中心/住宅/移动不混用）"),
            ScoreItem("N5", "企业出口 IP 为独享或有明确管理边界"),
        ),
    ),
    Dimension(
        "payment",
        "支付与身份一致性",
        20,
        (
            ScoreItem("P1", "卡 BIN 国家 = 账单地址国家 = 接入 IP 国家"),
            ScoreItem("P2", "使用本人名下的一手信用卡，非预付卡/虚拟卡/多人共卡"),
            ScoreItem("P3", "没有争议退款（chargeback）或拒付记录"),
            ScoreItem("P4", "注册姓名与支付姓名、身份证明一致"),
        ),
    ),
    Dimension(
        "usage",
        "账号使用模式",
        15,
        (
            ScoreItem("U1", "账号仅本人使用，没有共享凭据"),
            ScoreItem("U2", "同时在线设备数量稳定且在合理范围"),
            ScoreItem("U3", "没有用同一支付/设备/IP 关联多个账号"),
            ScoreItem("U4", "会话没有被工具或第三方客户端大量并发复用"),
        ),
    ),
    Dimension(
        "api_key",
        "API Key 卫生",
        15,
        (
            ScoreItem("K1", "密钥从未出现在公开仓库、前端代码或客户端安装包"),
            ScoreItem("K2", "密钥按环境分级，可单独吊销"),
            ScoreItem("K3", "有轮换机制（至少 90 天一次）"),
            ScoreItem("K4", "密钥只存在于服务端密钥管理，未进日志/截图/issue"),
            ScoreItem("K5", "调用量在设计限额内，没有异常突增"),
        ),
    ),
    Dimension(
        "third_party",
        "第三方依赖",
        15,
        (
            ScoreItem("T1", "没有中转站/镜像站/共享号池依赖"),
            ScoreItem("T2", "所有接入域名属于官方或合规云厂商"),
            ScoreItem("T3", "第三方依赖可审计（源码可见或供应商资质可查）"),
            ScoreItem("T4", "若走云厂商通道，处于其支持区域且计费主体合规"),
        ),
    ),
    Dimension(
        "content",
        "内容与自动化",
        10,
        (
            ScoreItem("C1", "生成内容用途符合 Usage Policy"),
            ScoreItem("C2", "没有脚本化批量模拟人类交互或绕过 rate limit"),
            ScoreItem("C3", "没有自动化抓取/爬取平台内容"),
        ),
    ),
)

DIMENSION_INDEX = {dim.dim_id: dim for dim in DIMENSIONS}
TOTAL_ITEMS = sum(len(dim.items) for dim in DIMENSIONS)
BAND_LABELS = {
    "low": "低风险 (0-20)",
    "medium": "中风险 (21-45)",
    "high": "高风险 (46-70)",
    "extreme": "极高风险 (71-100)",
}
BAND_ADVICE = {
    "low": "保持现状：定期轮换密钥、复核第三方依赖即可。",
    "medium": "先处理得分最高的两个维度，尤其是支付身份与第三方依赖。",
    "high": "停止新增依赖与共享行为，先做凭据轮换与 base_url 审计，再做申诉预案。",
    "extreme": "按事故响应处理：立即吊销全部可吊销凭据、下线中转、把证据固化，再评估迁移。",
}


def risk_band(score: float) -> str:
    """按分数返回风险档：0-20 低 / 21-45 中 / 46-70 高 / 71-100 极高。"""
    if score < 0 or score > 100:
        raise ValueError("分数必须在 0-100 之间: {}".format(score))
    if score <= 20:
        return "low"
    if score <= 45:
        return "medium"
    if score <= 70:
        return "high"
    return "extreme"


def dimension_scores(answers: Dict[str, Sequence[float]]) -> List[Dict[str, object]]:
    """把答案映射成每个维度的加权得分。"""
    unknown_dims = sorted(set(answers) - set(DIMENSION_INDEX))
    if unknown_dims:
        raise ValueError("未知维度: {}".format(", ".join(unknown_dims)))
    rows: List[Dict[str, object]] = []
    for dim in DIMENSIONS:
        values = answers.get(dim.dim_id)
        if values is None:
            raise ValueError("缺少维度答案: {}".format(dim.dim_id))
        if len(values) != len(dim.items):
            raise ValueError(
                "维度 {} 需要 {} 个答案，收到 {}".format(dim.dim_id, len(dim.items), len(values))
            )
        for value in values:
            if value not in (0, 0.5, 1):
                raise ValueError(
                    "维度 {} 的答案只能是 0 / 0.5 / 1，收到 {!r}".format(dim.dim_id, value)
                )
        hits = float(sum(values))
        earned = dim.weight * (hits / len(dim.items))
        rows.append(
            {
                "dim_id": dim.dim_id,
                "label": dim.label,
                "weight": dim.weight,
                "hits": hits,
                "items": len(dim.items),
                "earned": round(earned, 2),
                "lost": round(dim.weight - earned, 2),
            }
        )
    return rows


def compute_score(answers: Dict[str, Sequence[float]]) -> float:
    rows = dimension_scores(answers)
    total = sum(float(row["earned"]) for row in rows)
    return round(min(100.0, max(0.0, total)), 1)


def top_fix_items(answers: Dict[str, Sequence[float]], limit: int = 3) -> List[str]:
    """按「丢分最多」排序，返回最该先补的条目（1 = 风险存在，0 = 已消除）。"""
    scored: List[Tuple[float, int, int, str]] = []
    for dim_index, dim in enumerate(DIMENSIONS):
        per_item = dim.weight / len(dim.items)
        values = answers.get(dim.dim_id) or []
        for item_index, (item, value) in enumerate(zip(dim.items, values)):
            if value <= 0:
                continue
            tag = "" if value >= 1 else "（不确定，需查清）"
            scored.append(
                (
                    round(per_item * value, 3),
                    dim_index,
                    item_index,
                    "{} 的 {}（{}）{}".format(dim.label, item.item_id, item.label, tag),
                )
            )
    scored.sort(key=lambda entry: (-entry[0], entry[1], entry[2]))
    return [entry[3] for entry in scored[:limit]]


def _pad_label(text: str, width: int = 22) -> str:
    """按显示宽度（CJK 记 2 格）右侧补空格。"""
    display = len(text) + sum(1 for ch in text if ord(ch) > 127)
    return text + " " * max(1, width - display)


def render_scorecard(result: Dict[str, object]) -> str:
    rows = result["rows"]  # type: ignore[index]
    lines: List[str] = ["claude-account-guard · 风险评分卡", ""]
    lines.append("{}{:>6}{:>10}{:>8}".format(_pad_label("维度"), "权重", "命中项", "得分"))
    for row in rows:  # type: ignore[union-attr]
        lines.append(
            "{}{:>6}{:>10}{:>8}".format(
                _pad_label(str(row["label"])),
                row["weight"],
                "{:.1f}/{}".format(row["hits"], row["items"]),
                "{:.1f}".format(row["earned"]),
            )
        )
    lines.append("")
    lines.append("总分: {}/100  → {}".format(result["score"], BAND_LABELS[result["band"]]))  # type: ignore[index]
    lines.append("建议: {}".format(BAND_ADVICE[result["band"]]))  # type: ignore[index]
    fixed = result.get("top_fixes") or []
    if fixed:
        lines.append("")
        lines.append("优先补齐:")
        for index, item in enumerate(fixed, 1):
            lines.append("  {}. {}".format(index, item))
    lines.append("")
    lines.append("说明: 0=风险已消除 / 1=风险存在 / 0.5=不确定；评分是启发式自查，")
    lines.append("      不与平台内部风险分相关。")
    return "\n".join(lines)


def evaluate_scorecard(payload: Dict[str, object]) -> Dict[str, object]:
    answers = payload.get("answers")
    if not isinstance(answers, dict):
        raise ValueError("评分卡 JSON 缺少 answers 字段")
    normalized: Dict[str, Sequence[float]] = {}
    for key, value in answers.items():
        if isinstance(value, (int, float)):
            raise ValueError("维度 {} 的答案必须是数组，例如 [1, 0, 0.5]".format(key))
        if not isinstance(value, (list, tuple)):
            raise ValueError("维度 {} 的答案格式不正确".format(key))
        normalized[str(key)] = [float(item) for item in value]
    rows = dimension_scores(normalized)
    score = round(min(100.0, max(0.0, sum(float(r["earned"]) for r in rows))), 1)
    band = risk_band(score)
    return {
        "score": score,
        "band": band,
        "band_label": BAND_LABELS[band],
        "rows": rows,
        "top_fixes": top_fix_items(normalized),
        "advice": BAND_ADVICE[band],
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run_audit(
    root: Path,
    declared_region: str = "",
    include_history: bool = True,
    max_files: int = MAX_FILES,
) -> AuditReport:
    rules = IgnoreRules(root)
    files, skipped, truncated = iter_scan_files(root, max_files=max_files)
    if truncated:
        skipped.append("文件数超过上限 {}，只扫描了前 {} 个".format(max_files, max_files))

    findings: List[Finding] = []
    checks_run: List[str] = []

    env_findings, env_detail = check_env_and_dotenv(root, files, rules)
    findings.extend(env_findings)
    checks_run.append("env_and_dotenv")

    skip_for_secrets = [root / "report.md", root / "report.json"]
    secret_findings, scanned_bytes, _hits = scan_files_for_secrets(
        root, files, extra_skip=skip_for_secrets
    )
    findings.extend(secret_findings)
    checks_run.append("secret_scan")

    findings.extend(check_base_urls(root, files))
    checks_run.append("base_url")

    findings.extend(check_multi_account(root))
    checks_run.append("multi_account")

    history_findings, history = check_git_history(root, include_history)
    findings.extend(history_findings)
    checks_run.append("git_history")

    context = detect_locale_context(declared_region)
    context["dotenv_files"] = env_detail.get("dotenv_files", [])
    context["env_keys_present"] = env_detail.get("keys_present", [])
    findings.extend(check_locale(context))
    checks_run.append("locale")

    # 去重：同一条 finding 在同一位置只报一次
    deduped: Dict[Tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.check_id, finding.title, finding.location)
        deduped.setdefault(key, finding)
    ordered = sorted(deduped.values(), key=lambda f: f.sort_key())

    return AuditReport(
        root=str(root),
        generated_at=datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
        findings=ordered,
        files_scanned=len(files),
        bytes_scanned=scanned_bytes,
        checks_run=checks_run,
        skipped=skipped,
        history=history,
        context=context,
        declared_region=declared_region.upper(),
    )


def _ensure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue


def main(argv: Optional[Sequence[str]] = None) -> int:
    _ensure_utf8_streams()
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description=(
            "只读本地风险体检：检查密钥暴露、第三方 base_url、多账号痕迹与 git 历史。"
            "不联网、不上传任何数据。"
        ),
    )
    parser.add_argument("--path", "-p", default=".", help="扫描目录，默认当前目录")
    parser.add_argument("--report-dir", default=".", help="报告输出目录，默认当前目录")
    parser.add_argument("--declared-region", default="",
                        help="你申报的地区（如 US / JP / SG），用于时区一致性提示")
    parser.add_argument("--no-history", action="store_true", help="跳过 git 历史扫描")
    parser.add_argument("--no-md", action="store_true", help="不写 report.md")
    parser.add_argument("--no-json", action="store_true", help="不写 report.json")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--quiet", action="store_true", help="只输出一行结论")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, help="最多扫描多少文件")
    parser.add_argument("--fail-on", choices=["none", "critical", "high", "medium", "info"],
                        default="none", help="达到该严重度时以退出码 1 结束，默认 none")
    parser.add_argument("--scorecard", default="",
                        help="只评估一份评分卡 JSON（不扫描目录）")
    parser.add_argument("--json", action="store_true",
                        help="配合 --scorecard 使用：以 JSON 输出评分结果")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args(argv)

    if args.scorecard:
        try:
            payload = json.loads(Path(args.scorecard).read_text(encoding="utf-8-sig"))
            result = evaluate_scorecard(payload)
        except (OSError, ValueError) as exc:
            print("评分卡读取失败: {}".format(exc), file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        print(render_scorecard(result))
        return 0

    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print("目录不存在: {}".format(root), file=sys.stderr)
        return 2

    report = run_audit(
        root,
        declared_region=args.declared_region,
        include_history=not args.no_history,
        max_files=max(1, args.max_files),
    )

    report_dir = Path(args.report_dir).expanduser().resolve()
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("无法创建报告目录: {}".format(exc), file=sys.stderr)
        return 2

    if not args.no_md:
        (report_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    if not args.no_json:
        (report_dir / "report.json").write_text(
            json.dumps(to_json_dict(report), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    if args.quiet:
        counts = report.counts()
        print(
            "critical={} high={} medium={} info={}".format(
                counts.get("critical", 0),
                counts.get("high", 0),
                counts.get("medium", 0),
                counts.get("info", 0),
            )
        )
    else:
        print(render_terminal(report, color=_supports_color() and not args.no_color))
        written = []
        if not args.no_md:
            written.append("report.md")
        if not args.no_json:
            written.append("report.json")
        if written:
            print("")
            print("已写出: {} (目录: {})".format(", ".join(written), report_dir))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    worst = min(
        (SEVERITY_RANK[f.severity] for f in report.findings), default=99
    )
    return 1 if report.findings and worst <= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
