#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""redact.py — 对外分享前的敏感信息脱敏（离线、纯标准库）。

适用场景
--------
把 ``report.md``、终端日志、工单截图前的文本、客服邮件草稿发给别人（同事、厂商支持、
公开 issue）之前，先用它把凭据、Cookie、邮箱、手机号、公网 IP、用户名路径替换成占位符。

它做什么
--------
* 识别并替换 API Key / Bearer Token / JWT / 私钥块 / 高熵长串；
* 替换 Cookie、URL 中的 token 参数、邮箱、手机号、**公网** IP；
* 把 ``C:\\Users\\xxx``、``/Users/xxx``、``/home/xxx`` 里的用户名替换成 ``<USER>``；
* 打印每一类替换的计数，便于你确认「脱敏确实生效」。

它不做什么
----------
* 不联网、不上传任何数据、不写入除 ``--output``/``--in-place`` 之外的文件；
* 不保证 100% 覆盖：脱敏后仍建议人工通读一遍再发出去；
* 不会尝试「还原」被脱敏的内容。

用法
----
    python redact.py --input report.md --output report.redacted.md
    python redact.py --input report.md            # 输出到 stdout
    type log.txt | python redact.py               # 从 stdin 读
    python redact.py --input report.md --check    # 只检查，发现敏感信息则退出码 1
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_history  # noqa: E402

VERSION = "0.2.0"

PLACEHOLDER_BY_KIND = {
    "anthropic_api_key": "<ANTHROPIC_API_KEY>",
    "openai_style_key": "<API_KEY>",
    "aws_access_key_id": "<AWS_ACCESS_KEY_ID>",
    "google_api_key": "<GOOGLE_API_KEY>",
    "bearer_token": "<BEARER_TOKEN>",
    "x_api_key_header": "<X_API_KEY>",
    "jwt": "<JWT>",
    "private_key_block": "<PRIVATE_KEY>",
    "high_entropy_token": "<TOKEN>",
}

# 整块私钥（含正文）必须优先处理，否则只会被替换掉 BEGIN 那一行。
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# (名称, 正则, 替换模板)。替换模板里可用 \1、\g<1> 回填分组。
EXTRA_PATTERNS: Tuple[Tuple[str, "re.Pattern", str], ...] = (
    (
        "cookie",
        re.compile(
            r"(?i)\b(cookie|set-cookie|cf_clearance|sessionkey|session_key|"
            r"claude_session|_session)\b\s*[:=]\s*\S{8,}"
        ),
        r"\1: <REDACTED_COOKIE>",
    ),
    (
        "url_token",
        re.compile(
            r"(?i)([?&](?:token|key|api_key|access_token|sig|signature)=)[^&\s\"']{8,}"
        ),
        r"\1<REDACTED_URL_TOKEN>",
    ),
    (
        "email",
        re.compile(r"(?<![\w.%+-])[\w.%+-]+@[\w-]+(?:\.[\w-]+)+"),
        "<EMAIL>",
    ),
    (
        "cn_mobile",
        re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"),
        "<PHONE>",
    ),
    (
        "intl_phone",
        re.compile(r"(?<![\w+])\+\d{8,15}(?!\d)"),
        "<PHONE>",
    ),
)

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

PATH_PATTERNS: Tuple[Tuple[str, "re.Pattern", str], ...] = (
    ("win_home", re.compile(r"([A-Za-z]:\\Users\\)([^\\\s\"'<>|]+)"), r"\1<USER>"),
    ("mac_home", re.compile(r"(/Users/)([^/\s\"'<>|]+)"), r"\1<USER>"),
    ("linux_home", re.compile(r"(/home/)([^/\s\"'<>|]+)"), r"\1<USER>"),
)


def _add(stats: Dict[str, int], name: str, count: int) -> None:
    if count:
        stats[name] = stats.get(name, 0) + count


def _redact_home_paths(text: str, stats: Dict[str, int]) -> str:
    out = text
    for name, pattern, template in PATH_PATTERNS:
        out, count = pattern.subn(template, out)
        _add(stats, name, count)
    return out


def _redact_public_ips(text: str, stats: Dict[str, int]) -> str:
    def replace(match: "re.Match") -> str:
        candidate = match.group(1)
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return candidate
        _add(stats, "public_ip", 1)
        return "<PUBLIC_IP>"

    return IPV4_RE.sub(replace, text)


def redact_text(
    text: str,
    redact_emails: bool = True,
    redact_phones: bool = True,
    redact_ips: bool = True,
    redact_paths: bool = True,
    redact_tokens: bool = True,
) -> Tuple[str, Dict[str, int]]:
    """对一段文本做脱敏，返回 (脱敏结果, 各类替换计数)。"""
    stats: Dict[str, int] = {}
    if redact_tokens:
        text, count = PRIVATE_KEY_BLOCK_RE.subn("<PRIVATE_KEY>", text)
        _add(stats, "private_key", count)

        # 从右往左替换，避免前面的替换影响后面的位置
        matches = check_history.find_secrets(text)
        if matches:
            for match in sorted(matches, key=lambda item: item.start, reverse=True):
                placeholder = PLACEHOLDER_BY_KIND.get(match.kind, "<REDACTED>")
                text = text[: match.start] + placeholder + text[match.end :]
                _add(stats, match.kind, 1)

        for name, pattern, template in EXTRA_PATTERNS:
            if name == "email" and not redact_emails:
                continue
            if name in ("cn_mobile", "intl_phone") and not redact_phones:
                continue
            text, count = pattern.subn(template, text)
            _add(stats, name, count)

    if redact_ips:
        text = _redact_public_ips(text, stats)
    if redact_paths:
        text = _redact_home_paths(text, stats)
    return text, stats


def total_replacements(stats: Dict[str, int]) -> int:
    return sum(stats.values())


def format_stats(stats: Dict[str, int]) -> str:
    if not stats:
        return "未发现需要脱敏的内容"
    parts = ["{}={}".format(name, count) for name, count in sorted(stats.items())]
    return "脱敏替换: " + "  ".join(parts)


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8-sig", errors="replace")


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
        prog="redact.py",
        description="对外分享前的文本脱敏：去掉凭据、Cookie、邮箱、手机号、公网 IP 与用户名路径。",
    )
    parser.add_argument("--input", "-i", default="-", help="输入文件，默认从 stdin 读取")
    parser.add_argument("--output", "-o", default="-", help="输出文件，默认写到 stdout")
    parser.add_argument("--in-place", action="store_true", help="直接改写 --input 指定的文件")
    parser.add_argument("--check", action="store_true",
                        help="只报告会替换多少处，不输出正文；有发现时退出码 1")
    parser.add_argument("--stats-json", action="store_true", help="以 JSON 打印统计信息")
    parser.add_argument("--keep-emails", action="store_true", help="保留邮箱")
    parser.add_argument("--keep-phones", action="store_true", help="保留手机号")
    parser.add_argument("--keep-ips", action="store_true", help="保留公网 IP")
    parser.add_argument("--keep-paths", action="store_true", help="保留本地路径中的用户名")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args(argv)

    try:
        original = _read_input(args.input)
    except OSError as exc:
        print("读取输入失败: {}".format(exc), file=sys.stderr)
        return 2

    redacted, stats = redact_text(
        original,
        redact_emails=not args.keep_emails,
        redact_phones=not args.keep_phones,
        redact_ips=not args.keep_ips,
        redact_paths=not args.keep_paths,
    )
    replaced = total_replacements(stats)

    if args.check:
        if args.stats_json:
            print(json.dumps({"stats": stats, "total": replaced}, ensure_ascii=False))
        else:
            print(format_stats(stats))
        return 1 if replaced else 0

    if args.in_place:
        if args.input == "-":
            print("--in-place 需要配合 --input 指定文件", file=sys.stderr)
            return 2
        try:
            Path(args.input).write_text(redacted, encoding="utf-8")
        except OSError as exc:
            print("写入失败: {}".format(exc), file=sys.stderr)
            return 2
    elif args.output == "-":
        sys.stdout.write(redacted)
    else:
        try:
            Path(args.output).write_text(redacted, encoding="utf-8")
        except OSError as exc:
            print("写入失败: {}".format(exc), file=sys.stderr)
            return 2

    if args.stats_json:
        print(json.dumps({"stats": stats, "total": replaced}, ensure_ascii=False), file=sys.stderr)
    else:
        print(format_stats(stats), file=sys.stderr)
    if replaced == 0:
        print("提示: 没有命中任何规则，但请仍然人工通读一遍再分享。", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
