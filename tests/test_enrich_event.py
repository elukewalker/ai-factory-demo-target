"""Tests for enrich_event function."""

import pytest
from risk_scorer import calculate_risk_score, enrich_event


class TestPriorityTiers:
    """Test each priority tier is assigned correctly."""

    def test_p1_critical_privileged(self):
        """Critical + privileged = 0.8 → P1."""
        event = {"severity": "critical", "privileged": True}
        result = enrich_event(event)
        assert result["priority"] == "P1"
        assert result["recommended_action"] == "Page on-call immediately"

    def test_p1_boundary(self):
        """Exactly 0.8 should be P1."""
        # High (0.3) + privileged (0.3) + external_origin (0.2) = 0.8
        event = {
            "severity": "high",
            "privileged": True,
            "external_origin": True,
        }
        result = enrich_event(event)
        assert result["risk_score"] == 0.8
        assert result["priority"] == "P1"

    def test_p1_max_score(self):
        """Maximum risk score (1.0) should be P1."""
        event = {
            "severity": "critical",
            "privileged": True,
            "external_origin": True,
            "repeated": True,
        }
        result = enrich_event(event)
        assert result["risk_score"] == 1.0
        assert result["priority"] == "P1"

    def test_p2_high_external(self):
        """High + external_origin = 0.5 → P2."""
        event = {"severity": "high", "external_origin": True}
        result = enrich_event(event)
        assert result["priority"] == "P2"
        assert result["recommended_action"] == "Investigate within 1 hour"

    def test_p2_boundary(self):
        """Exactly 0.5 should be P2."""
        event = {"severity": "critical"}
        result = enrich_event(event)
        assert result["risk_score"] == 0.5
        assert result["priority"] == "P2"

    def test_p2_below_p1_threshold(self):
        """0.7 should be P2 (< 0.8)."""
        # Medium (0.1) + all flags (0.6) = 0.7
        event = {
            "severity": "medium",
            "privileged": True,
            "external_origin": True,
            "repeated": True,
        }
        result = enrich_event(event)
        assert result["risk_score"] == 0.7
        assert result["priority"] == "P2"

    def test_p3_privileged_only(self):
        """Privileged flag alone = 0.3 → P3."""
        event = {"privileged": True}
        result = enrich_event(event)
        assert result["priority"] == "P3"
        assert result["recommended_action"] == "Investigate within 24 hours"

    def test_p3_boundary(self):
        """Exactly 0.2 should be P3."""
        event = {"external_origin": True}
        result = enrich_event(event)
        assert result["risk_score"] == 0.2
        assert result["priority"] == "P3"

    def test_p3_below_p2_threshold(self):
        """0.4 should be P3 (< 0.5)."""
        # High (0.3) + repeated (0.1) = 0.4
        event = {"severity": "high", "repeated": True}
        result = enrich_event(event)
        assert result["risk_score"] == 0.4
        assert result["priority"] == "P3"

    def test_p4_low_severity(self):
        """Low severity = 0.0 → P4."""
        event = {"severity": "low"}
        result = enrich_event(event)
        assert result["priority"] == "P4"
        assert result["recommended_action"] == "Log and monitor"

    def test_p4_empty_event(self):
        """Empty event = 0.0 → P4."""
        result = enrich_event({})
        assert result["risk_score"] == 0.0
        assert result["priority"] == "P4"

    def test_p4_below_p3_threshold(self):
        """0.1 should be P4 (< 0.2)."""
        event = {"severity": "medium"}
        result = enrich_event(event)
        assert result["risk_score"] == 0.1
        assert result["priority"] == "P4"


class TestEscalateField:
    """Test escalate field is set correctly."""

    def test_escalate_true_for_p1(self):
        """P1 events should escalate."""
        event = {"severity": "critical", "privileged": True}
        result = enrich_event(event)
        assert result["priority"] == "P1"
        assert result["escalate"] is True

    def test_escalate_true_for_p2(self):
        """P2 events should escalate."""
        event = {"severity": "critical"}
        result = enrich_event(event)
        assert result["priority"] == "P2"
        assert result["escalate"] is True

    def test_escalate_false_for_p3(self):
        """P3 events should not escalate."""
        event = {"privileged": True}
        result = enrich_event(event)
        assert result["priority"] == "P3"
        assert result["escalate"] is False

    def test_escalate_false_for_p4(self):
        """P4 events should not escalate."""
        event = {"severity": "low"}
        result = enrich_event(event)
        assert result["priority"] == "P4"
        assert result["escalate"] is False


class TestOriginalKeysPreserved:
    """Test that all original event keys are preserved."""

    def test_single_key_preserved(self):
        """Single key should be preserved."""
        event = {"severity": "high"}
        result = enrich_event(event)
        assert "severity" in result
        assert result["severity"] == "high"

    def test_multiple_keys_preserved(self):
        """All original keys should be preserved."""
        event = {
            "severity": "critical",
            "privileged": True,
            "external_origin": False,
            "repeated": True,
        }
        result = enrich_event(event)
        assert result["severity"] == "critical"
        assert result["privileged"] is True
        assert result["external_origin"] is False
        assert result["repeated"] is True

    def test_extra_keys_preserved(self):
        """Event with extra keys should preserve them."""
        event = {
            "severity": "medium",
            "user": "alice",
            "timestamp": 1234567890,
            "source_ip": "192.168.1.1",
        }
        result = enrich_event(event)
        assert result["user"] == "alice"
        assert result["timestamp"] == 1234567890
        assert result["source_ip"] == "192.168.1.1"

    def test_original_event_not_mutated(self):
        """Original event dict should not be mutated."""
        event = {"severity": "high"}
        original_keys = set(event.keys())
        result = enrich_event(event)
        assert set(event.keys()) == original_keys
        assert "risk_score" not in event
        assert "priority" not in event


class TestRiskScoreAccuracy:
    """Test that risk_score field matches calculate_risk_score output."""

    def test_risk_score_matches_calculate(self):
        """risk_score should match calculate_risk_score exactly."""
        event = {"severity": "critical", "privileged": True}
        result = enrich_event(event)
        expected_score = calculate_risk_score(event)
        assert result["risk_score"] == expected_score

    def test_risk_score_matches_for_empty_event(self):
        """risk_score for empty event should match."""
        event = {}
        result = enrich_event(event)
        assert result["risk_score"] == calculate_risk_score(event)

    def test_risk_score_matches_for_complex_event(self):
        """risk_score for complex event should match."""
        event = {
            "severity": "high",
            "privileged": True,
            "external_origin": True,
            "repeated": True,
        }
        result = enrich_event(event)
        assert result["risk_score"] == calculate_risk_score(event)
        assert result["risk_score"] == 0.9

    def test_risk_score_matches_for_capped_score(self):
        """risk_score should match for capped scores."""
        event = {
            "severity": "critical",
            "privileged": True,
            "external_origin": True,
            "repeated": True,
        }
        result = enrich_event(event)
        assert result["risk_score"] == calculate_risk_score(event)
        assert result["risk_score"] == 1.0


class TestDerivedFieldsPresent:
    """Test that all required derived fields are present."""

    def test_all_derived_fields_present(self):
        """All four derived fields should be in result."""
        result = enrich_event({"severity": "high"})
        assert "risk_score" in result
        assert "priority" in result
        assert "recommended_action" in result
        assert "escalate" in result

    def test_derived_field_types(self):
        """Derived fields should have correct types."""
        result = enrich_event({"severity": "critical"})
        assert isinstance(result["risk_score"], float)
        assert isinstance(result["priority"], str)
        assert isinstance(result["recommended_action"], str)
        assert isinstance(result["escalate"], bool)
