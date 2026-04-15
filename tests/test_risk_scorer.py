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

    def test_unknown_severity(self):
        """Unknown severity defaults to 0.0 contribution."""
        assert calculate_risk_score({"severity": "unknown"}) == 0.0

    def test_missing_severity(self):
        """Missing severity defaults to 0.0 contribution."""
        assert calculate_risk_score({}) == 0.0

    def test_case_insensitive_severity(self):
        """Severity is case-insensitive."""
        assert calculate_risk_score({"severity": "CRITICAL"}) == 0.5
        assert calculate_risk_score({"severity": "High"}) == 0.3
        assert calculate_risk_score({"severity": "MeDiUm"}) == 0.1


class TestFlags:
    """Test each flag contribution."""

    def test_privileged_flag(self):
        """Privileged flag contributes 0.3."""
        assert calculate_risk_score({"severity": "low", "privileged": True}) == 0.3

    def test_external_origin_flag(self):
        """External origin flag contributes 0.2."""
        assert calculate_risk_score({"severity": "low", "external_origin": True}) == 0.2

    def test_repeated_flag(self):
        """Repeated flag contributes 0.1."""
        assert calculate_risk_score({"severity": "low", "repeated": True}) == 0.1

    def test_false_flags_contribute_nothing(self):
        """False flags should not contribute to score."""
        event = {
            "severity": "low",
            "privileged": False,
            "external_origin": False,
            "repeated": False
        }
        assert calculate_risk_score(event) == 0.0

    def test_missing_flags_contribute_nothing(self):
        """Missing flags should not contribute to score."""
        assert calculate_risk_score({"severity": "low"}) == 0.0


class TestCombinations:
    """Test combinations of conditions."""

    def test_critical_with_privileged(self):
        """Critical severity with privileged flag."""
        event = {"severity": "critical", "privileged": True}
        # 0.5 + 0.3 = 0.8
        assert calculate_risk_score(event) == 0.8

    def test_high_with_external_origin(self):
        """High severity with external origin flag."""
        event = {"severity": "high", "external_origin": True}
        # 0.3 + 0.2 = 0.5
        assert calculate_risk_score(event) == 0.5

    def test_all_flags_with_medium(self):
        """Medium severity with all flags."""
        event = {
            "severity": "medium",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }
        # 0.1 + 0.3 + 0.2 + 0.1 = 0.7
        assert calculate_risk_score(event) == 0.7

    def test_all_flags_without_severity(self):
        """All flags without severity."""
        event = {
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }
        # 0.3 + 0.2 + 0.1 = 0.6
        assert calculate_risk_score(event) == 0.6


class TestScoreCapping:
    """Test that score is capped at 1.0."""

    def test_critical_with_all_flags(self):
        """Critical with all flags should cap at 1.0."""
        event = {
            "severity": "critical",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }
        # 0.5 + 0.3 + 0.2 + 0.1 = 1.1, capped at 1.0
        assert calculate_risk_score(event) == 1.0

    def test_high_with_all_flags(self):
        """High with all flags should cap at 1.0."""
        event = {
            "severity": "high",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }
        # 0.3 + 0.3 + 0.2 + 0.1 = 0.9, not capped
        assert calculate_risk_score(event) == 0.9

    def test_score_never_exceeds_one(self):
        """Score should never exceed 1.0."""
        event = {
            "severity": "critical",
            "privileged": True,
            "external_origin": True,
            "repeated": True
        }
        assert calculate_risk_score(event) <= 1.0


class TestReturnType:
    """Test return type is float."""

    def test_return_type_is_float(self):
        """Return type should be float."""
        result = calculate_risk_score({"severity": "critical"})
        assert isinstance(result, float)

    def test_zero_returns_float(self):
        """Zero score should still be a float."""
        result = calculate_risk_score({})
        assert isinstance(result, float)
        assert result == 0.0
