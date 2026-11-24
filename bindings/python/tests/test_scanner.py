import os
import tempfile

import pytest

import betterleaks
from betterleaks import BetterleaksError
from betterleaks._lib import _CLIBacking

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


def test_cli_backing_fallback():
    """Verify the CLI subprocess fallback (used on Windows) produces identical Findings."""
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
