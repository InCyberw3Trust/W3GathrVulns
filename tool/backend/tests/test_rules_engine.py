"""Unit tests for the rules engine.

Tests condition evaluation and action application without a database.
Uses mock objects to simulate Finding and Rule models.
"""
import pytest
from unittest.mock import MagicMock
from app.utils.rules_engine import _eval_condition, matches_rule
from app.models import SeverityEnum, StatusEnum, SourceEnum


def make_finding(**kwargs):
    """Create a mock Finding object with the given attributes."""
    f = MagicMock()
    f.title       = kwargs.get("title", "Test vulnerability")
    f.vuln_id     = kwargs.get("vuln_id", "")
    f.cve         = kwargs.get("cve", "")
    f.description = kwargs.get("description", "")
    f.file_path   = kwargs.get("file_path", "")
    f.component   = kwargs.get("component", "")
    f.tags        = kwargs.get("tags", [])
    sev = kwargs.get("severity", "HIGH")
    f.severity    = MagicMock(); f.severity.value = sev
    st = kwargs.get("status", "OPEN")
    f.status      = MagicMock(); f.status.value = st
    src = kwargs.get("source", "trivy")
    f.source      = MagicMock(); f.source.value = src
    return f


def make_rule(conditions, mode="all"):
    r = MagicMock()
    r.conditions      = conditions
    r.conditions_mode = mode
    return r


# ── _eval_condition ───────────────────────────────────────────────────────────

class TestEvalCondition:
    def test_equals_match(self):
        f = make_finding(severity="CRITICAL")
        assert _eval_condition(f, {"field": "severity", "operator": "equals", "value": "CRITICAL"})

    def test_equals_no_match(self):
        f = make_finding(severity="HIGH")
        assert not _eval_condition(f, {"field": "severity", "operator": "equals", "value": "CRITICAL"})

    def test_not_equals(self):
        f = make_finding(severity="HIGH")
        assert _eval_condition(f, {"field": "severity", "operator": "not_equals", "value": "CRITICAL"})

    def test_contains(self):
        f = make_finding(title="CVE-2023-44487 in nghttp2")
        assert _eval_condition(f, {"field": "title", "operator": "contains", "value": "nghttp2"})
        assert not _eval_condition(f, {"field": "title", "operator": "contains", "value": "openssl"})

    def test_not_contains(self):
        f = make_finding(title="SQL Injection in login")
        assert _eval_condition(f, {"field": "title", "operator": "not_contains", "value": "XSS"})

    def test_starts_with(self):
        f = make_finding(title="CVE-2023-12345 in package")
        assert _eval_condition(f, {"field": "title", "operator": "starts_with", "value": "CVE-"})
        assert not _eval_condition(f, {"field": "title", "operator": "starts_with", "value": "GHSA-"})

    def test_ends_with(self):
        f = make_finding(file_path="src/main/App.java")
        assert _eval_condition(f, {"field": "file_path", "operator": "ends_with", "value": ".java"})

    def test_in_operator(self):
        f = make_finding(severity="HIGH")
        assert _eval_condition(f, {"field": "severity", "operator": "in", "value": "CRITICAL,HIGH,MEDIUM"})
        assert not _eval_condition(f, {"field": "severity", "operator": "in", "value": "CRITICAL,LOW"})

    def test_regex_match(self):
        f = make_finding(title="CVE-2023-44487 in nghttp2")
        assert _eval_condition(f, {"field": "title", "operator": "regex", "value": r"CVE-\d{4}-\d+"})
        assert not _eval_condition(f, {"field": "title", "operator": "regex", "value": r"GHSA-\d+"})

    def test_invalid_regex_returns_false(self):
        f = make_finding(title="something")
        # Invalid regex should not raise, just return False
        result = _eval_condition(f, {"field": "title", "operator": "regex", "value": "[invalid"})
        assert result is False

    def test_unknown_field_returns_empty(self):
        f = make_finding()
        assert not _eval_condition(f, {"field": "nonexistent_field", "operator": "equals", "value": "x"})

    def test_case_insensitive(self):
        f = make_finding(severity="CRITICAL")
        assert _eval_condition(f, {"field": "severity", "operator": "equals", "value": "critical"})

    def test_source_field(self):
        f = make_finding(source="trivy")
        assert _eval_condition(f, {"field": "source", "operator": "equals", "value": "trivy"})


# ── matches_rule ──────────────────────────────────────────────────────────────

class TestMatchesRule:
    def test_all_mode_all_match(self):
        f = make_finding(severity="CRITICAL", source="trivy")
        rule = make_rule([
            {"field": "severity", "operator": "equals", "value": "CRITICAL"},
            {"field": "source",   "operator": "equals", "value": "trivy"},
        ], mode="all")
        assert matches_rule(f, rule)

    def test_all_mode_partial_match(self):
        f = make_finding(severity="HIGH", source="trivy")
        rule = make_rule([
            {"field": "severity", "operator": "equals", "value": "CRITICAL"},
            {"field": "source",   "operator": "equals", "value": "trivy"},
        ], mode="all")
        assert not matches_rule(f, rule)

    def test_any_mode_one_match(self):
        f = make_finding(severity="HIGH", source="nuclei")
        rule = make_rule([
            {"field": "severity", "operator": "equals", "value": "CRITICAL"},
            {"field": "source",   "operator": "equals", "value": "nuclei"},
        ], mode="any")
        assert matches_rule(f, rule)

    def test_any_mode_no_match(self):
        f = make_finding(severity="LOW", source="owasp_zap")
        rule = make_rule([
            {"field": "severity", "operator": "equals", "value": "CRITICAL"},
            {"field": "source",   "operator": "equals", "value": "trivy"},
        ], mode="any")
        assert not matches_rule(f, rule)

    def test_empty_conditions_returns_false(self):
        f = make_finding()
        rule = make_rule([])
        assert not matches_rule(f, rule)

    def test_single_condition(self):
        f = make_finding(severity="INFO")
        rule = make_rule([{"field": "severity", "operator": "equals", "value": "INFO"}])
        assert matches_rule(f, rule)
