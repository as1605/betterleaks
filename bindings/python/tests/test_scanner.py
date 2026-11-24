import os
import tempfile
import zipfile

import pytest

import betterleaks
from betterleaks import BetterleaksError
from betterleaks._lib import _CLIBacking, _scanner_cache, get_cached_backing

GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"


def test_scanner_inline_config_and_lifecycle():
    config_toml = """
[[rules]]
id = "custom-inline"
description = "Inline rule"
regex = '''INLINE_[A-Z]{6}'''
keywords = ["INLINE_"]
"""
    with betterleaks.create_scanner(config_toml=config_toml) as scanner:
        findings = scanner.scan_string("key = INLINE_ABCDEF")
        assert len(findings) == 1
        assert findings[0].rule_id == "custom-inline"
        assert findings[0].secret == "INLINE_ABCDEF"

        # Embedded NUL byte should not truncate input in C ABI.
        findings_with_nul = scanner.scan_string("é\x00key = INLINE_ABCDEF")
        assert len(findings_with_nul) == 1
        assert findings_with_nul[0].rule_id == "custom-inline"

    # Closing again is idempotent; scanning after close raises BetterleaksError.
    scanner.close()
    with pytest.raises(BetterleaksError, match="closed"):
        scanner.scan_string("INLINE_ABCDEF")


def test_scanner_custom_config_file():
    config_toml = """
[[rules]]
id = "custom-file-rule"
description = "File config rule"
regex = '''FILERULE_[0-9]{6}'''
keywords = ["FILERULE_"]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as cfg:
        cfg.write(config_toml)
        cfg_path = cfg.name

    try:
        with betterleaks.create_scanner(config_path=cfg_path) as scanner:
            findings = scanner.scan_string("val = FILERULE_123456")
            assert len(findings) == 1
            assert findings[0].rule_id == "custom-file-rule"
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_relative_config_cache_key_resolves_abspath(monkeypatch):
    cfg_a = (
        "[[rules]]\nid = 'dir-a'\nregex = '''DIRA_[0-9]{4}'''\nkeywords = ['DIRA_']\n"
    )
    cfg_b = (
        "[[rules]]\nid = 'dir-b'\nregex = '''DIRB_[0-9]{4}'''\nkeywords = ['DIRB_']\n"
    )

    with tempfile.TemporaryDirectory() as dir_a, tempfile.TemporaryDirectory() as dir_b:
        with open(os.path.join(dir_a, "rules.toml"), "w", encoding="utf-8") as fh:
            fh.write(cfg_a)
        with open(os.path.join(dir_b, "rules.toml"), "w", encoding="utf-8") as fh:
            fh.write(cfg_b)

        monkeypatch.chdir(dir_a)
        res_a = betterleaks.scan_string("DIRA_1234 DIRB_1234", config_path="rules.toml")
        assert [f.rule_id for f in res_a] == ["dir-a"]
        assert os.path.abspath("rules.toml") in _scanner_cache

        monkeypatch.chdir(dir_b)
        res_b = betterleaks.scan_string("DIRA_1234 DIRB_1234", config_path="rules.toml")
        assert [f.rule_id for f in res_b] == ["dir-b"]
        assert get_cached_backing("rules.toml") is not get_cached_backing(
            os.path.join(dir_a, "rules.toml")
        )


def test_cli_backing_fallback(monkeypatch):
    """Verify the CLI subprocess fallback (used on Windows) mirrors native semantics."""
    # Inherited CLI env vars must not override explicit inline config or trigger validation.
    monkeypatch.setenv("BETTERLEAKS_VALIDATE", "true")
    monkeypatch.setenv("BETTERLEAKS_ANALYZE", "true")
    monkeypatch.setenv("BETTERLEAKS_CONFIG", "/nonexistent/override.toml")

    backing = _CLIBacking()
    try:
        res = backing.scan_string(f"token = '{GH_TOKEN}'")
        findings = [
            betterleaks.Finding.from_dict(item) for item in res.get("findings") or []
        ]
        assert len(findings) == 1
        assert findings[0].rule_id == "github-pat"
        assert findings[0].secret == GH_TOKEN

        clean = backing.scan_string("ordinary clean text")
        assert (clean.get("findings") or []) == []

        with tempfile.NamedTemporaryFile("w+", suffix=".env", delete=False) as f:
            f.write(f"GITHUB_TOKEN={GH_TOKEN}\n")
            f.flush()
            path = f.name
        try:
            file_res = backing.scan_file(path)
            file_findings = [
                betterleaks.Finding.from_dict(item)
                for item in file_res.get("findings") or []
            ]
            assert len(file_findings) == 1
            assert file_findings[0].rule_id == "github-pat"
            assert file_findings[0].location.path == path
        finally:
            if os.path.exists(path):
                os.remove(path)
    finally:
        backing.close()

    # Inline config_toml must win even when BETTERLEAKS_CONFIG is set in environment.
    inline = "[[rules]]\nid = 'win-inline'\nregex = '''WININLINE_[A-Z]{4}'''\nkeywords = ['WININLINE_']\n"
    inline_backing = _CLIBacking(config_toml=inline)
    try:
        res = inline_backing.scan_string("val = WININLINE_TEST")
        assert [item["rule_id"] for item in res.get("findings") or []] == ["win-inline"]
    finally:
        inline_backing.close()

    # Limits and archive rejection must match bindings/c semantics.
    limited = _CLIBacking(max_input_bytes=16, max_findings=1)
    try:
        with pytest.raises(BetterleaksError, match="max_input_bytes"):
            limited.scan_string("x" * 32)
        with pytest.raises(BetterleaksError, match="max_findings"):
            limited.scan_string("a") if False else limited._parse_cli_output(
                type("P", (), {"returncode": 0, "stdout": b"[{}, {}]", "stderr": b""})()
            )
    finally:
        limited.close()

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zpath = zf.name
    try:
        with zipfile.ZipFile(zpath, "w") as archive:
            archive.writestr("secret.txt", f"TOKEN={GH_TOKEN}\n")
        archive_backing = _CLIBacking()
        try:
            with pytest.raises(BetterleaksError, match="archive"):
                archive_backing.scan_file(zpath)
        finally:
            archive_backing.close()
    finally:
        if os.path.exists(zpath):
            os.remove(zpath)
