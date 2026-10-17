"""tests/test_audit.py — claude-account-guard 的回归测试。

覆盖范围（对应第 7 节验收标准）：
* 密钥正则的命中与不误报；
* 脱敏函数（redact.py）与「绝不打印原文」的约束；
* 评分卡边界值（0 / 20 / 21 / 45 / 46 / 70 / 71 / 100）；
* audit.py 在空目录、含假密钥目录、含第三方 base_url 目录下的输出。

测试里出现的所有密钥都是随机拼出来的假串，仓库中没有任何真实凭据。
"""

from __future__ import annotations

import json
import os
import random
import shutil
import string
import sys
import tempfile
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import audit  # noqa: E402
import check_history  # noqa: E402
import redact  # noqa: E402

ALPHABET = string.ascii_letters + string.digits


def fake_key(seed: int = 7, length: int = 48) -> str:
    """生成一个形状像 Anthropic Key 的假字符串。"""
    rnd = random.Random(seed)
    body = "".join(rnd.choice(ALPHABET) for _ in range(length))
    return "sk-ant-api03-" + body + "FakeTestOnly"


def key_body(key: str) -> str:
    """取假密钥的随机主体，用于断言它没有出现在输出里。"""
    return key.split("-api03-", 1)[1]


@contextmanager
def temp_workspace():
    """临时目录；系统临时目录不可写时退回测试目录旁（例如受限沙箱里）。"""
    holder = None
    try:
        holder = tempfile.TemporaryDirectory()
        path = Path(holder.name)
    except OSError:
        holder = None
        path = Path(tempfile.mkdtemp(prefix=".tmp-tests-", dir=str(Path(__file__).parent)))
    try:
        yield path
    finally:
        if holder is not None:
            try:
                holder.cleanup()
            except OSError:
                pass
        else:
            shutil.rmtree(str(path), ignore_errors=True)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def audit_dir(root: Path, declared_region: str = ""):
    return audit.run_audit(root, declared_region=declared_region, include_history=False)


def ids(report) -> list:
    return [finding.check_id for finding in report.findings]


def severity_of(report, check_id: str) -> str:
    for finding in report.findings:
        if finding.check_id == check_id:
            return finding.severity
    return ""


# ---------------------------------------------------------------------------
# 1. 密钥正则：命中
# ---------------------------------------------------------------------------
def test_detects_anthropic_key():
    key = fake_key()
    text = "api_key = " + key
    matches = check_history.find_secrets(text)
    assert matches, "应当命中 sk-ant- 形式的密钥"
    assert matches[0].kind == "anthropic_api_key"
    assert text[matches[0].start : matches[0].end] == key


def test_detects_bearer_header():
    token = "AbCdEf0123456789AbCdEf0123456789"
    matches = check_history.find_secrets("Authorization: Bearer " + token)
    assert any(m.kind == "bearer_token" for m in matches)
    hit = [m for m in matches if m.kind == "bearer_token"][0]
    assert "AbCdEf0123456789" in ("Authorization: Bearer " + token)[hit.start : hit.end]


def test_detects_x_api_key():
    value = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    matches = check_history.find_secrets("x-api-key: " + value)
    assert any(m.kind == "x_api_key_header" for m in matches)


def test_detects_aws_key():
    # 拼接构造，避免本仓库被自己的扫描器命中（fixtures 里不放形状完整的假 Key）
    sample = "aws_access_key_id = " + "AKIA" + "IOSFODNN7EXAMPLE"
    matches = check_history.find_secrets(sample)
    assert any(m.kind == "aws_access_key_id" for m in matches)


def test_detects_long_base64_token():
    token = "Zm9vYmFyQmF6" + "UXV4MTIzNDU2" + "Nzg5MEFCQ0RFRk" + "dISUpLTE1O"
    matches = check_history.find_secrets("token=" + token)
    assert any(m.kind == "high_entropy_token" for m in matches)


# ---------------------------------------------------------------------------
# 2. 密钥正则：不误报
# ---------------------------------------------------------------------------
def test_no_false_positive_on_ordinary_words():
    samples = [
        "pip install scikit-learn  # sk-learn",
        "task-management and risk-free refactoring",
        "Skoda, skin, skip, sky, skeleton",
        "the sk-ant- prefix alone is not a key",
        "sk-ant-short",
    ]
    for sample in samples:
        assert check_history.find_secrets(sample) == [], sample


def test_no_false_positive_on_hex_digest():
    digest = "de9b0a1c4f5e6d7c8b9a0f1e2d3c4b5a69788796a5b4c3d2e1f0011223344556"
    assert check_history.find_secrets("commit " + digest) == []


def test_no_false_positive_on_low_entropy_long_strings():
    # 字母表、正则字符类这类"长但不随机"的串不应被判为密钥
    samples = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    ]
    for sample in samples:
        assert check_history.find_secrets(sample) == [], sample


def test_no_false_positive_on_uuid_and_paths():
    samples = [
        "550e8400-e29b-41d4-a716-446655440000",
        "C:/Users/someone/projects/claude-account-guard/scripts/audit.py",
        "https://docs.anthropic.com/en/api/overview",
    ]
    for sample in samples:
        assert check_history.find_secrets(sample) == [], sample


def test_mask_never_contains_original():
    key = fake_key()
    masked = check_history.mask_secret(key, "anthropic_api_key")
    assert key_body(key)[:24] not in masked
    assert "redacted" in masked
    assert "len=" in masked


# ---------------------------------------------------------------------------
# 3. 评分卡边界值
# ---------------------------------------------------------------------------
ZERO_ANSWERS = {dim.dim_id: [0] * len(dim.items) for dim in audit.DIMENSIONS}
UNKNOWN_ANSWERS = {dim.dim_id: [0.5] * len(dim.items) for dim in audit.DIMENSIONS}
FULL_ANSWERS = {dim.dim_id: [1] * len(dim.items) for dim in audit.DIMENSIONS}


def test_weights_sum_to_100():
    assert sum(dim.weight for dim in audit.DIMENSIONS) == 100
    assert audit.TOTAL_ITEMS == sum(len(dim.items) for dim in audit.DIMENSIONS)


def test_score_all_zero():
    assert audit.compute_score(ZERO_ANSWERS) == 0.0


def test_score_all_unknown_is_half():
    assert audit.compute_score(UNKNOWN_ANSWERS) == 50.0


def test_score_all_ones_is_100():
    assert audit.compute_score(FULL_ANSWERS) == 100.0


def test_band_boundaries():
    assert audit.risk_band(0) == "low"
    assert audit.risk_band(20) == "low"
    assert audit.risk_band(20.1) == "medium"
    assert audit.risk_band(21) == "medium"
    assert audit.risk_band(45) == "medium"
    assert audit.risk_band(45.5) == "high"
    assert audit.risk_band(46) == "high"
    assert audit.risk_band(70) == "high"
    assert audit.risk_band(70.1) == "extreme"
    assert audit.risk_band(71) == "extreme"
    assert audit.risk_band(100) == "extreme"


def test_band_rejects_out_of_range():
    for value in (-1, 101):
        try:
            audit.risk_band(value)
        except ValueError:
            continue
        raise AssertionError("应当拒绝 {} 这样的分数".format(value))


def test_scorecard_validation():
    broken = {dim.dim_id: [0] * len(dim.items) for dim in audit.DIMENSIONS}
    broken["network"] = [0]  # 数量不对
    for bad in (broken,):
        try:
            audit.compute_score(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("答案数量不匹配时应当报错")

    invalid_value = {dim.dim_id: [0] * len(dim.items) for dim in audit.DIMENSIONS}
    invalid_value["payment"] = [2] * len(audit.DIMENSION_INDEX["payment"].items)
    try:
        audit.compute_score(invalid_value)
    except ValueError:
        pass
    else:
        raise AssertionError("答案取值越界时应当报错")


def test_scorecard_matches_manual_arithmetic():
    # 网络 25 分全中 → 25；支付 20 分 2/4 → 10；其余全 0。
    answers = {dim.dim_id: [0] * len(dim.items) for dim in audit.DIMENSIONS}
    answers["network"] = [1, 1, 1, 1, 1]
    answers["payment"] = [1, 1, 0, 0]
    assert audit.compute_score(answers) == 35.0
    assert audit.risk_band(audit.compute_score(answers)) == "medium"
    assert len(audit.top_fix_items(answers, limit=3)) == 3


def test_scorecard_cli_roundtrip():
    with temp_workspace() as root:
        payload = {"answers": {dim.dim_id: [0.5] * len(dim.items) for dim in audit.DIMENSIONS}}
        path = write(root / "scorecard.json", "\ufeff" + json.dumps(payload))
        buffer = StringIO()
        with redirect_stdout(buffer):
            assert audit.main(["--scorecard", str(path), "--json"]) == 0
            assert audit.main(["--scorecard", str(path)]) == 0
        assert "总分" in buffer.getvalue()

        bad = write(root / "bad.json", json.dumps({"answers": []}))
        with redirect_stdout(StringIO()):
            assert audit.main(["--scorecard", str(bad)]) == 2


# ---------------------------------------------------------------------------
# 4. 脱敏函数
# ---------------------------------------------------------------------------
def test_redact_removes_key():
    key = fake_key(seed=3)
    text = "配置如下：ANTHROPIC_API_KEY={}".format(key)
    cleaned, stats = redact.redact_text(text)
    assert key_body(key)[:20] not in cleaned
    assert "<ANTHROPIC_API_KEY>" in cleaned
    assert stats["anthropic_api_key"] == 1


def test_redact_removes_pii_but_keeps_private_ip():
    text = (
        "邮箱 eric.example@example.com 手机 13800138000 "
        "公网 8.8.8.8 内网 192.168.1.20"
    )
    cleaned, stats = redact.redact_text(text)
    assert "eric.example" not in cleaned
    assert "13800138000" not in cleaned
    assert "8.8.8.8" not in cleaned
    assert "192.168.1.20" in cleaned
    assert stats["public_ip"] == 1
    assert stats["cn_mobile"] == 1


def test_redact_home_paths():
    text = r"C:\Users\eric\Desktop\x.md 和 /Users/eric/x.md 与 /home/eric/x.md"
    cleaned, stats = redact.redact_text(text)
    assert "eric" not in cleaned
    assert "<USER>" in cleaned
    assert stats["win_home"] == 1


def test_redact_private_key_block():
    block = (
        "-----BEGIN RSA " + "PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAx9F0abcdefghijklmnop\n"
        "-----END RSA " + "PRIVATE KEY-----"
    )
    cleaned, stats = redact.redact_text(block)
    assert "MIIEowIBAAKCAQEA" not in cleaned
    assert "<PRIVATE_KEY>" in cleaned
    assert stats["private_key"] == 1


def test_redact_is_idempotent():
    text = (
        "key={} mail=eric.example@example.com ip=8.8.8.8 "
        "path=C:\\Users\\eric\\a.txt".format(fake_key(seed=11))
    )
    once, _ = redact.redact_text(text)
    twice, stats = redact.redact_text(once)
    assert once == twice
    assert redact.total_replacements(stats) == 0


# ---------------------------------------------------------------------------
# 5. git 历史解析
# ---------------------------------------------------------------------------
def test_parse_git_log_detects_added_line():
    key = fake_key(seed=5)
    body = (FIXTURES / "sample_git_log.txt").read_text(encoding="utf-8")
    log = "\x01" + "a" * 40 + "\x02chore: add app\n" + body.replace("{key}", key)
    hits = check_history.parse_log_output(log)
    assert hits, "应当从新增行里发现密钥"
    assert all(key_body(key)[:20] not in hit["masked"] for hit in hits)
    assert any(hit["kind"] == "anthropic_api_key" for hit in hits)


def test_parse_git_log_ignores_deletions_and_context():
    key = fake_key(seed=9)
    log = (
        "\x01" + "b" * 40 + "\x02docs: note\n"
        "diff --git a/x.py b/x.py\n"
        "+++ b/x.py\n"
        "-ANTHROPIC_API_KEY = \"{}\"\n".format(key)
    )
    assert check_history.parse_log_output(log) == []


def test_scan_git_history_without_repo_is_graceful():
    with temp_workspace() as root:
        result = check_history.scan_git_history(str(root))
        assert result["available"] in (True, False)
        if not result["available"]:
            assert result["reason"]
        assert result["hits"] == []


# ---------------------------------------------------------------------------
# 6. audit.py 三种场景
# ---------------------------------------------------------------------------
def test_audit_empty_directory():
    with temp_workspace() as root:
        report = audit_dir(root)
        assert report.files_scanned == 0
        assert "AG-012" not in ids(report)
        assert report.counts()["critical"] == 0
        text = audit.render_terminal(report, color=False)
        assert "claude-account-guard" in text


def test_audit_finds_fake_key_without_leaking_it():
    key = fake_key(seed=13)
    with temp_workspace() as root:
        write(root / "app.py", 'ANTHROPIC_API_KEY = "{}"\n'.format(key))
        report = audit_dir(root)
        assert "AG-012" in ids(report)
        assert severity_of(report, "AG-012") == "critical"
        assert any("app.py" in item for f in report.findings for item in f.evidence)

        body = key_body(key)
        markdown = audit.render_markdown(report)
        payload = json.dumps(audit.to_json_dict(report), ensure_ascii=False)
        terminal = audit.render_terminal(report, color=False)
        for blob in (markdown, payload, terminal):
            assert body[:20] not in blob, "报告里泄漏了密钥原文"


def test_audit_flags_third_party_base_url():
    with temp_workspace() as root:
        write(
            root / ".env",
            "ANTHROPIC_API_KEY={}\nANTHROPIC_BASE_URL=https://relay.example.com/v1\n".format(
                fake_key(seed=17)
            ),
        )
        report = audit_dir(root)
        assert "AG-020" in ids(report)
        assert severity_of(report, "AG-020") == "high"
        finding = [f for f in report.findings if f.check_id == "AG-020"][0]
        assert "relay.example.com" in " ".join(finding.evidence)
        assert "v1" not in " ".join(finding.evidence), "证据只保留主机名，不带路径"


def test_audit_official_base_url_is_quiet():
    with temp_workspace() as root:
        write(root / ".env", "ANTHROPIC_BASE_URL=https://api.anthropic.com\n")
        report = audit_dir(root)
        assert "AG-020" not in ids(report)
        assert "AG-021" not in ids(report)


def test_audit_dotenv_ignored_vs_not_ignored():
    key_line = "ANTHROPIC_API_KEY={}\n".format(fake_key(seed=19))

    with temp_workspace() as root:
        write(root / ".env", key_line)
        report = audit_dir(root)
        assert severity_of(report, "AG-011") == "critical"
        assert "AG-060" in ids(report)

    with temp_workspace() as root:
        write(root / ".env", key_line)
        write(root / ".gitignore", ".env\n.env.*\n*.log\n")
        report = audit_dir(root)
        assert severity_of(report, "AG-011") == "info"
        assert "AG-060" not in ids(report)


def test_audit_cli_writes_reports():
    with temp_workspace() as root:
        write(root / "notes.md", "# 正常文档，没有密钥\n")
        with redirect_stdout(StringIO()) as buffer:
            code = audit.main(
                [
                    "--path", str(root),
                    "--report-dir", str(root),
                    "--no-history",
                    "--no-color",
                ]
            )
        assert code == 0
        assert "claude-account-guard" in buffer.getvalue()
        report_md = root / "report.md"
        report_json = root / "report.json"
        assert report_md.is_file() and report_json.is_file()
        payload = json.loads(report_json.read_text(encoding="utf-8"))
        assert payload["tool"]["name"].endswith("audit.py")
        assert "summary" in payload and "findings" in payload
        assert "不能保证" in payload["disclaimer"]


def test_audit_cli_fail_on_critical():
    with temp_workspace() as root:
        write(root / "leak.py", 'KEY = "{}"\n'.format(fake_key(seed=23)))
        with redirect_stdout(StringIO()):
            assert audit.main(["--path", str(root), "--report-dir", str(root),
                               "--no-history", "--no-color", "--fail-on", "critical"]) == 1
            assert audit.main(["--path", str(root), "--report-dir", str(root),
                               "--no-history", "--no-color"]) == 0


def test_audit_reports_env_var_presence_only():
    previous = os.environ.get("ANTHROPIC_API_KEY")
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-" + "placeholder-not-a-real-key-000000"
    try:
        with temp_workspace() as root:
            report = audit_dir(root)
            assert "AG-010" in ids(report)
            assert severity_of(report, "AG-010") == "info"
            blob = json.dumps(audit.to_json_dict(report), ensure_ascii=False)
            assert "placeholder-not-a-real-key" not in blob
    finally:
        if previous is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = previous


def test_official_and_cloud_host_classification():
    assert audit.classify_host("api.anthropic.com") == "official"
    assert audit.classify_host("claude.ai") == "official"
    assert audit.classify_host("bedrock-runtime.us-east-1.amazonaws.com") == "cloud"
    assert audit.classify_host("us-central1-aiplatform.googleapis.com") == "cloud"
    assert audit.classify_host("127.0.0.1") == "local"
    assert audit.classify_host("relay.example.com") == "third_party"
    assert audit.url_host("HTTPS://API.Anthropic.COM/v1/messages") == "api.anthropic.com"
