#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_history.py — 扫描 git 历史中的疑似密钥痕迹（只读、完全离线）。

设计原则
--------
* 只读取本地 git 对象，不发起任何网络请求，**不上传任何数据**。
* 命中结果一律先脱敏再输出：只保留类型与长度，绝不打印密钥原文。
* 纯 Python 标准库；Windows / macOS / Linux 均可运行。

用法
----
    python check_history.py --path .
    python check_history.py --path . --json
    python check_history.py --path . --max-commits 2000
    python check_history.py --path . --fail-on critical     # 供 CI 使用

退出码
------
    0  扫描完成（默认即使发现命中也不失败）
    1  使用了 --fail-on 且命中达到该严重度
    2  参数错误
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "0.1.0"
MAX_DIFF_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_COMMITS = 500

# ---------------------------------------------------------------------------
# 密钥特征
# ---------------------------------------------------------------------------
# 每个条目: (类型名, 正则, 取值分组号)。分组号 0 表示用整个匹配。
SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern", int], ...] = (
    (
        "anthropic_api_key",
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
        0,
    ),
    (
        "openai_style_key",
        re.compile(r"(?<![A-Za-z0-9_\-])sk-(?!ant-)[A-Za-z0-9]{20,}(?![A-Za-z0-9_\-])"),
        0,
    ),
    (
        "aws_access_key_id",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
        0,
    ),
    (
        "google_api_key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        0,
    ),
    (
        "bearer_token",
        re.compile(r"(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9._\-+/=]{16,})"),
        1,
    ),
    (
        "x_api_key_header",
        re.compile(r"(?i)x-api-key\s*[:=]\s*[\"']?([A-Za-z0-9._\-]{16,})"),
        1,
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
        0,
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        0,
    ),
)

# 高熵长串：base64 / urlsafe-base64 风格的连续 token，长度 >= 40。
# 注意 '=' 只允许出现在结尾（base64 padding），否则 "key=VALUE" 里的 '=' 会把键名吞进来。
_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-]{40,}={0,2}")
_HEX_ONLY = set("0123456789abcdefABCDEF")
MIN_ENTROPY_BITS = 3.5

SECRET_PREFIXES = ("sk-ant-", "sk-", "AKIA", "ASIA", "AIza", "Bearer ", "bearer ")


@dataclass(frozen=True)
class SecretMatch:
    """一处命中：类型 + 在文本中的半开区间 [start, end)。"""

    kind: str
    start: int
    end: int


def shannon_entropy(text: str) -> float:
    """按字符统计的香农熵（bit/字符）。用于把"字母表""正则字符类"这类低熵长串排除掉。"""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def is_sequential(token: str, threshold: float = 0.5) -> bool:
    """判断是否为"字母表 / 字符表"式的连续序列（相邻码位多为 +1）。

    base64 字母表、`abcdefghij...` 这类常量没有秘密价值，但看着像高熵长串。
    """
    if len(token) < 2:
        return False
    steps = sum(1 for a, b in zip(token, token[1:]) if ord(b) == ord(a) + 1)
    return steps / (len(token) - 1) >= threshold


def _looks_like_secret_token(token: str) -> bool:
    """高熵长串的启发式判定，尽可能压低误报（git sha、uuid、字母表、普通单词等）。"""
    if len(token) < 40:
        return False
    if set(token) <= _HEX_ONLY:  # 纯十六进制：通常是 commit sha / 文件摘要
        return False
    if token.count("=") > 2 or ("=" in token and not token.endswith("=")):
        return False
    if not any(c.isdigit() for c in token):
        return False
    if not any(c.isupper() for c in token):
        return False
    if not any(c.islower() for c in token):
        return False
    if "----" in token:  # markdown 分隔线、ASCII 表格
        return False
    if re.search(r"(.)\1{9,}", token):  # 单字符长时间重复
        return False
    if is_sequential(token):  # 字母表 / 字符表
        return False
    if shannon_entropy(token) < MIN_ENTROPY_BITS:  # 低熵模板串
        return False
    return True


def find_secrets(text: str, include_entropy: bool = True) -> List[SecretMatch]:
    """在一段文本里找出疑似密钥的位置（不返回值本身）。"""
    matches: List[SecretMatch] = []
    for kind, pattern, group in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span(group)
            if end > start:
                matches.append(SecretMatch(kind, start, end))
    if include_entropy:
        for m in _ENTROPY_CANDIDATE.finditer(text):
            token = m.group(0)
            if _looks_like_secret_token(token):
                matches.append(SecretMatch("high_entropy_token", m.start(), m.end()))
    return merge_matches(matches)


def merge_matches(matches: Iterable[SecretMatch]) -> List[SecretMatch]:
    """按位置排序并合并重叠区间，避免同一段文本被重复计费。"""
    ordered = sorted(matches, key=lambda item: (item.start, -item.end))
    merged: List[SecretMatch] = []
    for match in ordered:
        if merged and match.start < merged[-1].end:
            last = merged[-1]
            if match.end > last.end:
                merged[-1] = SecretMatch(last.kind, last.start, match.end)
            continue
        merged.append(match)
    return merged


def mask_secret(value: str, kind: str = "secret") -> str:
    """把疑似密钥替换成可安全展示的占位串：保留已知前缀 + 长度。"""
    prefix = ""
    for candidate in SECRET_PREFIXES:
        if value.startswith(candidate):
            prefix = candidate
            break
    return "{}<redacted:{}:len={}>".format(prefix, kind, len(value))


def mask_text(text: str, include_entropy: bool = True) -> Tuple[str, int]:
    """给整行/整段文本脱敏，返回 (脱敏后文本, 命中数)。"""
    matches = find_secrets(text, include_entropy=include_entropy)
    if not matches:
        return text, 0
    out = text
    for match in sorted(matches, key=lambda item: item.start, reverse=True):
        original = out[match.start : match.end]
        out = out[: match.start] + mask_secret(original, match.kind) + out[match.end :]
    return out, len(matches)


# ---------------------------------------------------------------------------
# git 历史扫描
# ---------------------------------------------------------------------------
def parse_log_output(text: str, max_hits: int = 200) -> List[Dict[str, str]]:
    """解析 `git log -p -U0 --format=%x01%H%x02%s` 的输出，只看新增行。"""
    hits: List[Dict[str, str]] = []
    commit = ""
    path = ""
    for raw in text.splitlines():
        if raw.startswith("\x01"):
            parts = raw[1:].split("\x02", 1)
            commit = parts[0][:12]
            subject = parts[1] if len(parts) > 1 else ""
            for match in find_secrets(subject):
                hits.append(
                    _hit(commit, "(commit message)", match.kind,
                         mask_secret(subject[match.start : match.end], match.kind),
                         "commit-message")
                )
            continue
        if raw.startswith("+++ b/"):
            path = raw[6:]
            continue
        if raw.startswith("+++ "):
            path = raw[4:]
            continue
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        added = raw[1:]
        for match in find_secrets(added):
            hits.append(
                _hit(commit, path or "(unknown)", match.kind,
                     mask_secret(added[match.start : match.end], match.kind), "added-line")
            )
            if len(hits) >= max_hits:
                return hits[:max_hits]
    return hits[:max_hits]


def _hit(commit: str, path: str, kind: str, masked: str, where: str) -> Dict[str, str]:
    return {
        "commit": commit,
        "path": path,
        "kind": kind,
        "masked": masked,
        "where": where,
    }


def _git_env() -> Dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_PAGER"] = "cat"
    env.setdefault("LC_ALL", "C")
    return env


def run_git(
    args: Sequence[str], cwd: str, timeout: int = 120
) -> Tuple[bool, bytes, str]:
    """调用 git，返回 (成功?, 原始字节, 错误信息)。从不抛异常。"""
    git = shutil.which("git")
    if not git:
        return False, b"", "git 未安装或不在 PATH 中"
    command = [git, "-c", "core.quotepath=false", "-c", "core.pager=cat"] + list(args)
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=_git_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:  # 权限、超时、可执行位等
        return False, b"", "git 调用失败: {}".format(exc)
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", "replace").strip()
        return False, proc.stdout, message or "git 返回非零退出码"
    return True, proc.stdout, ""


def scan_git_history(
    root: str,
    max_commits: int = DEFAULT_MAX_COMMITS,
    max_hits: int = 200,
    log_runner=None,
) -> Dict[str, object]:
    """扫描仓库历史中的疑似密钥。返回可 JSON 序列化的字典。"""
    result: Dict[str, object] = {
        "available": False,
        "reason": "",
        "commits_scanned": 0,
        "truncated": False,
        "hits": [],
        "git_version": "",
    }
    runner = log_runner or run_git
    ok, out, err = runner(["--version"], root)
    if not ok:
        result["reason"] = err
        return result
    result["git_version"] = out.decode("utf-8", "replace").strip()

    ok, out, err = runner(["rev-list", "--all", "--max-count={}".format(max_commits)], root)
    if not ok:
        result["reason"] = "无法读取历史（不是 git 仓库或历史为空）: {}".format(err)
        return result
    commits = [line for line in out.decode("utf-8", "replace").splitlines() if line.strip()]
    result["commits_scanned"] = len(commits)
    if not commits:
        result["available"] = True
        result["reason"] = "仓库没有任何提交历史"
        return result

    ok, out, err = runner(
        [
            "log",
            "--all",
            "--max-count={}".format(max_commits),
            "-p",
            "-U0",
            "--no-color",
            "--no-merges",
            "--format=%x01%H%x02%s",
        ],
        root,
    )
    if not ok:
        result["reason"] = "读取历史 diff 失败: {}".format(err)
        return result
    if len(out) > MAX_DIFF_BYTES:
        out = out[:MAX_DIFF_BYTES]
        result["truncated"] = True
    hits = parse_log_output(out.decode("utf-8", "replace"), max_hits=max_hits)
    result["available"] = True
    result["hits"] = hits
    if err:
        result["reason"] = err
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _severity_for(kind: str) -> str:
    if kind in ("anthropic_api_key", "private_key_block"):
        return "critical"
    return "high"


def render_text(result: Dict[str, object]) -> str:
    lines: List[str] = []
    lines.append("claude-account-guard · check_history {}".format(VERSION))
    if not result.get("available"):
        lines.append("[info] 无法扫描 git 历史：{}".format(result.get("reason") or "未知原因"))
        lines.append("[info] 这并不代表安全，只是本机缺少可扫描的 git 仓库。")
        return "\n".join(lines)
    lines.append("[info] 扫描提交数：{}".format(result.get("commits_scanned", 0)))
    if result.get("truncated"):
        lines.append("[info] diff 体积过大，已截断，结果可能不完整")
    hits = result.get("hits") or []
    if not hits:
        lines.append("[ok] 未在历史新增行中发现疑似密钥")
        return "\n".join(lines)
    lines.append("[high] 历史中发现 {} 处疑似密钥（已脱敏）".format(len(hits)))
    lines.append("")
    lines.append("{:<12}  {:<10}  {:<22}  {}".format("commit", "kind", "path", "masked"))
    for hit in hits:  # type: ignore[union-attr]
        lines.append(
            "{:<12}  {:<10}  {:<22}  {}".format(
                hit.get("commit", ""),
                hit.get("kind", "")[:10],
                (hit.get("path") or "")[:22],
                hit.get("masked", ""),
            )
        )
    lines.append("")
    lines.append("[fix] 光删掉文件不够：历史里仍可恢复。请按 references/api-key-hygiene.md")
    lines.append("[fix] 的「吊销 → 轮换 → 清洗」顺序处理，并假定该密钥已泄露。")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_history.py",
        description="扫描 git 历史中的疑似密钥痕迹（只读、离线、不打印原文）。",
    )
    parser.add_argument("--path", "-p", default=".", help="仓库路径，默认当前目录")
    parser.add_argument("--max-commits", type=int, default=DEFAULT_MAX_COMMITS,
                        help="最多扫描多少提交，默认 500")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--fail-on", choices=["none", "critical", "high"], default="none",
                        help="命中达到该级别时以非零码退出，默认 none")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print("路径不存在: {}".format(root), file=sys.stderr)
        return 2

    result = scan_git_history(root, max_commits=max(1, args.max_commits))
    result["root"] = root
    result["tool"] = {"name": "claude-account-guard/check_history.py", "version": VERSION}

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_text(result))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    hits = result.get("hits") or []
    worst = min((SEVERITY_RANK[_severity_for(h["kind"])] for h in hits), default=99)
    return 1 if hits and worst <= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
