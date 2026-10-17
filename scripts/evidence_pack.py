#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence_pack.py — 把申诉材料整理成结构化、已脱敏、带完整性清单的压缩包。

为什么需要它
------------
账号被限制之后，最容易犯的两个错误是：① 证据散落在下载文件夹、聊天记录和邮箱里，
提交时说不清哪份是哪份；② 把带 Key、卡号、邮箱的原始截图直接发给支持人员。

这个脚本把 `references/incident-response.md` 的证据清单变成一个目录骨架：
你按编号把材料丢进去，它负责**脱敏文本、统一命名、算哈希、出清单、打包**。

它做什么
--------
* ``--init``   建出 8 个编号目录 + 时间线模板 + 说明文件；
* ``--add``    把一份文件按编号复制进对应目录；
* ``--list``   列出每个目录里有几份材料、哪些必需项还缺；
* ``--build``  生成 ``dist/``：文本类文件自动脱敏、二进制原样复制并**明确警告**、
               生成 ``MANIFEST.md`` / ``manifest.json`` / ``timeline.md``，最后打包 zip。

它不做什么
----------
* 不联网、不上传任何数据；
* 不能对 PDF/图片做内容脱敏（标准库做不到）——这些文件会原样复制，并在清单里标为
  "未自动脱敏，请人工检查"；
* 不判断你的材料是否足以让平台恢复账号——它只保证"材料整齐、可核对、可追溯"。

用法
----
    python evidence_pack.py --init --dir ./evidence-pack
    python evidence_pack.py --add 02-payment ~/Downloads/statement.pdf --dir ./evidence-pack
    python evidence_pack.py --list --dir ./evidence-pack
    python evidence_pack.py --build --dir ./evidence-pack

注意：材料里含个人信息，``--build`` 生成的目录不要提交到任何仓库。
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import redact  # noqa: E402

VERSION = "0.3.0"
DEFAULT_DIR = ".evidence-pack"

# (目录名, 标题, 是否必需, 放什么)
CATEGORIES: Tuple[Tuple[str, str, bool, str], ...] = (
    (
        "01-identity",
        "身份与账号归属",
        True,
        "注册邮箱的归属证明、身份材料、能说明「这个账号是我的」的文件。"
        "可以打码，但要保留姓名与日期的对应关系。",
    ),
    (
        "02-payment",
        "支付与账单",
        True,
        "银行对账单（遮盖卡号，保留姓名/地址/日期/金额）、平台发票、订阅确认邮件。",
    ),
    (
        "03-network",
        "网络与所在地",
        False,
        "公司出口说明、宽带账单、机票/酒店订单——用来解释「为什么我的接入地和注册地不同」。",
    ),
    (
        "04-usage",
        "使用与设备",
        False,
        "设备列表截图、会话时间线、自己的调用日志。先删掉或脱敏再放进来。",
    ),
    (
        "05-remediation",
        "已做的止损动作",
        False,
        "Key 吊销截图、base_url 修改前后对比、停用脚本的提交记录。证明「发现即处置」。",
    ),
    (
        "06-third-party",
        "第三方服务（如适用）",
        False,
        "与中转/共享服务的合同、账单、SLA。用于说明「当时的善意使用」，不要隐瞒。",
    ),
    (
        "07-timeline",
        "时间线",
        True,
        "用根目录的 timeline.csv 填写，构建时会自动生成 timeline.md。",
    ),
    (
        "08-appeal-draft",
        "申诉正文草稿",
        False,
        "用 references/appeal-templates.md 里的模板写的正文，便于附在材料前面。",
    ),
)

SKIP_NAMES = {"PUT-FILES-HERE.md", "README.md", ".gitkeep", "desktop.ini", "Thumbs.db"}
BINARY_SUFFIXES = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
    ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".zip", ".7z", ".gz", ".tar", ".rar",
    ".heic", ".mp4", ".mov", ".avi", ".pages", ".numbers", ".key",
}
MAX_FILE_BYTES = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------
def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def safe_name(name: str) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\s]+', "-", name).strip("-. ")
    return cleaned or "file"


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return False
    try:
        raw = path.read_bytes()[:8192]
    except OSError:
        return False
    if b"\x00" in raw:
        return False
    # 截断点可能正好落在多字节字符中间，最多回退 3 个字节再判断
    for trim in range(4):
        chunk = raw[: len(raw) - trim] if trim else raw
        try:
            chunk.decode("utf-8")
            return True
        except UnicodeDecodeError:
            continue
    return False


def _ensure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue


# ---------------------------------------------------------------------------
# --init
# ---------------------------------------------------------------------------
def init_pack(root: Path) -> int:
    root.mkdir(parents=True, exist_ok=True)
    for name, title, required, guidance in CATEGORIES:
        folder = root / name
        folder.mkdir(parents=True, exist_ok=True)
        marker = folder / "PUT-FILES-HERE.md"
        if not marker.exists():
            marker.write_text(
                "# {}\n\n{}\n\n{}".format(
                    title,
                    "必需材料。" if required else "可选材料，有就放。",
                    guidance,
                )
                + "\n\n把文件放进本目录即可；`--build` 时本文件会被忽略。\n",
                encoding="utf-8",
            )

    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(
            "# 申诉材料包\n\n"
            "1. 按编号把材料放进对应目录（每个目录里的 `PUT-FILES-HERE.md` 说明了该放什么）。\n"
            "2. 在 `timeline.csv` 里按时间顺序填写事件。\n"
            "3. 运行 `python scripts/evidence_pack.py --build --dir <本目录>`：\n"
            "   - 文本类文件会被自动脱敏（Key、Bearer、Cookie、邮箱、手机号、公网 IP、用户名路径）；\n"
            "   - PDF/图片**不会**被自动脱敏，清单里会标出来，需要你自己检查截图和扫描件；\n"
            "   - 生成 `dist/MANIFEST.md`、`dist/manifest.json` 和一份 zip。\n"
            "4. 打开 `dist/MANIFEST.md` 核对清单，再人工过一遍二进制文件，然后提交。\n\n"
            "**这个目录含个人信息，不要提交到任何仓库，也不要发给无关的人。**\n",
            encoding="utf-8",
        )

    timeline = root / "timeline.csv"
    if not timeline.exists():
        timeline.write_text(
            "time,action,evidence,result\n"
            "2026-01-01 10:00 +08:00,最后正常使用,04-usage/日志截图,-\n"
            "2026-01-02 09:30 +08:00,发现无法登录,04-usage/报错截图,-\n"
            "2026-01-02 10:10 +08:00,吊销全部 API Key,05-remediation/console.png,已完成\n",
            encoding="utf-8",
        )

    print("已初始化材料包: {}".format(root))
    print("下一步：把文件放进 8 个编号目录，然后运行 --build")
    return 0


# ---------------------------------------------------------------------------
# --add / --list
# ---------------------------------------------------------------------------
def find_category(token: str) -> Optional[Tuple[str, str, bool, str]]:
    for category in CATEGORIES:
        if category[0] == token or category[0].startswith(token):
            return category
    return None


def next_index(folder: Path) -> int:
    highest = 0
    if folder.is_dir():
        for path in folder.iterdir():
            match = re.match(r"^(\d{2})-", path.name)
            if match:
                highest = max(highest, int(match.group(1)))
    return highest + 1


def add_file(root: Path, category_token: str, source: str) -> int:
    category = find_category(category_token)
    if category is None:
        print("未知分类: {}（可用: {}）".format(
            category_token, ", ".join(c[0] for c in CATEGORIES)), file=sys.stderr)
        return 2
    src = Path(source).expanduser()
    if not src.is_file():
        print("文件不存在: {}".format(src), file=sys.stderr)
        return 2
    folder = root / category[0]
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "{:02d}-{}".format(next_index(folder), safe_name(src.name))
    shutil.copy2(str(src), str(target))
    print("已加入 {}: {} ({} 字节)".format(category[0], target.name, target.stat().st_size))
    return 0


def list_pack(root: Path) -> int:
    if not root.is_dir():
        print("目录不存在: {}（先运行 --init）".format(root), file=sys.stderr)
        return 2
    print("材料包: {}".format(root))
    missing_required = []
    total = 0
    for name, title, required, _guidance in CATEGORIES:
        folder = root / name
        files = []
        if folder.is_dir():
            files = [p for p in sorted(folder.iterdir()) if p.is_file() and p.name not in SKIP_NAMES]
        total += len(files)
        flag = "必需" if required else "可选"
        state = "{} 份".format(len(files)) if files else "空"
        print("  {:<18} {:<12} {:<6} {}".format(name, title, flag, state))
        if required and not files:
            missing_required.append(name)
    print("合计: {} 份材料".format(total))
    if missing_required:
        print("缺少必需项: {}".format(", ".join(missing_required)))
    return 0


# ---------------------------------------------------------------------------
# --build
# ---------------------------------------------------------------------------
def process_file(
    path: Path,
    out_dir: Path,
    index: int,
    do_redact: bool,
    warnings: List[str],
) -> Dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "{:02d}-{}".format(index, safe_name(path.name))
    counter = 2
    while target.exists():
        target = out_dir / "{:02d}-{}-{}".format(index, counter, safe_name(path.name))
        counter += 1

    replacements: Dict[str, int] = {}
    redacted = False
    if path.stat().st_size > MAX_FILE_BYTES:
        warnings.append("{} 超过 50MB，未纳入材料包。".format(path.name))
        return {}

    if do_redact and is_text_file(path):
        text = path.read_text(encoding="utf-8", errors="replace")
        cleaned, replacements = redact.redact_text(text)
        target.write_text(cleaned, encoding="utf-8")
        redacted = True
    else:
        shutil.copy2(str(path), str(target))
        if path.suffix.lower() in BINARY_SUFFIXES:
            warnings.append(
                "{} 是二进制文件（{}），未自动脱敏——请人工确认截图/PDF 里没有 Key、卡号、邮箱、"
                "订单号。".format(path.name, path.suffix.lower() or "无扩展名")
            )

    return {
        "file": path.name,
        "output": "{}/{}".format(out_dir.name, target.name),
        "bytes": target.stat().st_size,
        "sha256": sha256_of(target),
        "redacted": redacted,
        "replacements": replacements,
    }


def render_timeline(csv_path: Path) -> str:
    rows: List[List[str]] = []
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            if not row or not any(cell.strip() for cell in row):
                continue
            rows.append([cell.strip() for cell in row])
    if not rows:
        return ""
    header = rows[0]
    if len(header) < 2 or header[0].lower() not in ("time", "时间", "timestamp"):
        rows.insert(0, ["time", "action", "evidence", "result"])
        header = rows[0]

    lines = ["# 时间线", "", "| {} |".format(" | ".join(header)), "|{}|".format(
        "|".join([" --- "] * len(header)))]
    for row in rows[1:]:
        padded = (row + [""] * len(header))[: len(header)]
        lines.append("| {} |".format(" | ".join(cell.replace("|", "\\|") for cell in padded)))
    lines.append("")
    lines.append("> 时间必须带时区。记不清的写「不确定」，不要编。")
    return "\n".join(lines)


def build_pack(root: Path, do_redact: bool = True, make_zip: bool = True, strict: bool = False) -> int:
    if not root.is_dir():
        print("目录不存在: {}（先运行 --init）".format(root), file=sys.stderr)
        return 2

    dist = root / "dist"
    if dist.exists():
        shutil.rmtree(str(dist))
    dist.mkdir(parents=True)

    entries: List[Dict[str, object]] = []
    warnings: List[str] = []
    missing: List[str] = []

    for name, title, required, _guidance in CATEGORIES:
        folder = root / name
        files: List[Path] = []
        if folder.is_dir():
            files = [p for p in sorted(folder.iterdir()) if p.is_file() and p.name not in SKIP_NAMES]
        if required and not files and name != "07-timeline":
            missing.append(name)
        for index, path in enumerate(files, 1):
            entry = process_file(path, dist / name, index, do_redact, warnings)
            if entry:
                entry["category"] = name
                entry["category_title"] = title
                entries.append(entry)

    # 时间线
    timeline_md = ""
    csv_path = root / "timeline.csv"
    if csv_path.is_file():
        timeline_md = render_timeline(csv_path)
    if timeline_md:
        (dist / "07-timeline").mkdir(parents=True, exist_ok=True)
        target = dist / "07-timeline" / "timeline.md"
        target.write_text(timeline_md + "\n", encoding="utf-8")
        entries.append(
            {
                "category": "07-timeline",
                "category_title": "时间线",
                "file": "timeline.csv",
                "output": "07-timeline/timeline.md",
                "bytes": target.stat().st_size,
                "sha256": sha256_of(target),
                "redacted": False,
                "replacements": {},
            }
        )
    elif "07-timeline" not in missing:
        missing.append("07-timeline")

    total_bytes = sum(int(entry["bytes"]) for entry in entries)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pack_name = root.name

    manifest = {
        "tool": {"name": "claude-account-guard/evidence_pack.py", "version": VERSION},
        "generated_at": stamp,
        "pack": pack_name,
        "entries": entries,
        "warnings": warnings,
        "missing_required": missing,
        "notes": "二进制文件未自动脱敏；发送前请人工检查。本文件不含原始密钥。",
    }
    (dist / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    lines = ["# 申诉材料清单", ""]
    lines.append("- 生成时间：{}".format(stamp))
    lines.append("- 材料包：`{}`".format(pack_name))
    lines.append("- 文件数：{}，合计 {:.1f} KB".format(len(entries), total_bytes / 1024))
    lines.append("")
    if missing:
        lines.append("## 缺少的必需项")
        lines.append("")
        for item in missing:
            lines.append("- `{}`".format(item))
        lines.append("")
    if warnings:
        lines.append("## 需要人工检查")
        lines.append("")
        for item in warnings:
            lines.append("- {}".format(item))
        lines.append("")
    lines.append("## 材料")
    lines.append("")
    lines.append("| 编号 | 分类 | 文件 | 自动脱敏 | SHA-256（前 16 位） |")
    lines.append("| --- | --- | --- | --- | --- |")
    for index, entry in enumerate(entries, 1):
        replaced = sum(int(value) for value in dict(entry["replacements"]).values())
        flag = "是（{} 处）".format(replaced) if entry["redacted"] else "否"
        lines.append(
            "| {:02d} | {} | `{}` | {} | `{}` |".format(
                index,
                entry["category"],
                entry["output"],
                flag,
                str(entry["sha256"])[:16],
            )
        )
    lines.append("")
    lines.append("## 发送前自查")
    lines.append("")
    lines.append("- [ ] 每个二进制文件都人工看过（截图里的 Key、卡号、邮箱、订单号）")
    lines.append("- [ ] 时间线带时区，记不清的写「不确定」而不是猜")
    lines.append("- [ ] 正文里没有「我什么都没做」这类无法证明的绝对表述")
    lines.append("- [ ] 诉求明确（恢复 / 说明原因 / 导出数据，选一个）")
    lines.append("- [ ] 只通过官方渠道提交一次，保留工单号")
    lines.append("")
    (dist / "MANIFEST.md").write_text("\n".join(lines), encoding="utf-8")

    zip_path = None
    if make_zip:
        zip_path = dist / "evidence-pack-{}.zip".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(dist.rglob("*")):
                if path.is_file() and path != zip_path:
                    archive.write(str(path), str(path.relative_to(dist)))

    print("材料包已生成: {}".format(dist))
    print("  文件: {} 份，{:.1f} KB".format(len(entries), total_bytes / 1024))
    if missing:
        print("  缺少必需项: {}".format(", ".join(missing)))
    if warnings:
        print("  需要人工检查: {} 项（见 MANIFEST.md）".format(len(warnings)))
    if zip_path:
        print("  压缩包: {}".format(zip_path))
    print("  提醒: 二进制文件未自动脱敏；提交前请按 MANIFEST.md 的自查清单过一遍。")

    if strict and (missing or warnings):
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    _ensure_utf8_streams()
    parser = argparse.ArgumentParser(
        prog="evidence_pack.py",
        description="把申诉材料整理成结构化、已脱敏、带完整性清单的压缩包（离线，不上传）。",
    )
    parser.add_argument("--dir", default=DEFAULT_DIR, help="材料包目录，默认 .evidence-pack")
    parser.add_argument("--init", action="store_true", help="建出 8 个编号目录与模板")
    parser.add_argument("--list", action="store_true", help="列出已有材料与缺失项")
    parser.add_argument("--add", nargs=2, metavar=("CATEGORY", "FILE"),
                        help="把文件加入某个分类（可用 02 或 02-payment）")
    parser.add_argument("--build", action="store_true", help="脱敏、出清单并打包")
    parser.add_argument("--no-redact", action="store_true", help="不做文本脱敏（不推荐）")
    parser.add_argument("--no-zip", action="store_true", help="不生成压缩包")
    parser.add_argument("--strict", action="store_true", help="有缺失项或警告时以退出码 1 结束")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args(argv)

    root = Path(args.dir).expanduser()
    actions = [args.init, args.list, args.build, args.add is not None]
    if sum(1 for action in actions if action) != 1:
        parser.print_help()
        return 2

    if args.init:
        return init_pack(root)
    if args.list:
        return list_pack(root)
    if args.add:
        return add_file(root, args.add[0], args.add[1])
    return build_pack(root, do_redact=not args.no_redact, make_zip=not args.no_zip, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
