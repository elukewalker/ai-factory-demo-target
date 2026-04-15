"""Tests for risk_scorer.py"""

import pytest
from risk_scorer import calculate_risk_score


class TestSeverityLevels:
    """Test each severity level contribution."""

    def test_critical_severity(self):
        """Critical severity contributes 0.5."""
        assert calculate_risk_score({"severity": "critical"}) == 0.5

    def test_high_severity(self):
        """High severity contributes 0.3."""
        assert calculate_risk_score({"severity": "high"}) == 0.3

    def test_medium_severity(self):
        """Medium severity contributes 0.1."""
        assert calculate_risk_score({"severity": "medium"}) == 0.1

    def test_low_severity(self):
        """Low severity contributes 0.0."""
        assert calculate_risk_score({"severity": "low"}) == 0.0

    def test_missing_severity(self):
        """Missing severity defaults to 0.0."""
        assert calculate_risk_score({}) == 0.0

    def test_unknown_severity(self):
        """Unknown severity defaults to 0.0."""
        assert calculate_risk_score({"severity": "unknown"}) == 0.0


class TestFlags:
    """Test each flag contribution."""

    def test_privileged_flag(self):
        """Privileged flag contributes 0.3."""
        assert calculate_risk_score({"privileged": True}) == 0.3

    def test_external_origin_flag(self):
        """External origin flag contributes 0.2."""
        assert calculate_risk_score({"external_origin": True}) == 0.2

    def test_repeated_flag(self):
        """Repeated flag contributes 0.1."""
        assert calculate_risk_score({"repeated": True}) == 0.1

    def test_false_flags_no_contribution(self):
        """False flags should not contribute to score."""
        assert calculate_risk_score({
            "privileged": False,
            "external_origin": False,
            "repeated": False
        }) == 0.0


class TestCombinations:
    """Test combinations of severity and flags."""

    def test_high_with_external_origin(self):
        """High severity + external origin = 0.5."""
        assert calculate_risk_score({
            "severity": "high",
            "external_origin": True
        }) == 0.5

    def test_critical_with_privileged(self):
        """Critical + privileged = 0.8."""
        assert calculate_risk_score({
            "severity": "critical",
            "privileged": True
        }) == 0.8

    def test_medium_with_all_flags(self):
        """Medium + all flags = 0.7."""
        assert calculate_risk_score({
            "severity": "medium",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }) == 0.7


class TestScoreCapping:
    """Test that scores are capped at 1.0."""

    def test_critical_with_all_flags_capped(self):
        """Critical (0.5) + all flags (0.6) = 1.1, capped at 1.0."""
        assert calculate_risk_score({
            "severity": "critical",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }) == 1.0

    def test_high_with_all_flags_capped(self):
        """High (0.3) + all flags (0.6) = 0.9, not capped."""
        assert calculate_risk_score({
            "severity": "high",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }) == 0.9


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_event(self):
        """Empty event dict returns 0.0."""
        assert calculate_risk_score({}) == 0.0

    def test_none_values_dont_contribute(self):
        """None values should not contribute to score."""
        assert calculate_risk_score({
            "privileged": None,
            "external_origin": None,
            "repeated": None
        }) == 0.0

    def test_severity_case_sensitive(self):
        """Severity matching is case-sensitive."""
        assert calculate_risk_score({"severity": "CRITICAL"}) == 0.0
        assert calculate_risk_score({"severity": "Critical"}) == 0.0
