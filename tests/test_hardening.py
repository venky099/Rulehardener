"""
Unit and Integration Tests for Rule Hardening Engine
"""
from backend.rule_manager.sigma_loader import load_sigma_file
from backend.telemetry.synthetic_generator import generate_telemetry_for_scenarios, get_predefined_scenarios
from backend.hardening.rule_comparator import evaluate_and_compare_rules, generate_yaml_diff
from backend.config import settings

def test_rule_hardening_pipeline():
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    original_rule = load_sigma_file(rule_path)

    atk_events, ben_events = generate_telemetry_for_scenarios()
    atk_scenarios, ben_scenarios = get_predefined_scenarios()

    all_events = atk_events + ben_events
    all_scenarios = atk_scenarios + ben_scenarios

    proposal = evaluate_and_compare_rules(original_rule, all_events, all_scenarios)

    # 1. Verification of baseline metrics
    assert proposal.original_metrics.detected_attack_scenarios == 1
    assert proposal.original_metrics.detection_rate == 12.5

    # 2. Verification of improved metrics
    # Hardened rule detects ATK-001, ATK-002 (-enc), ATK-003 (-e), ATK-004 (pwsh.exe), ATK-006 (download cradle), ATK-007 (/enc), ATK-008 (bypass)
    assert proposal.improved_metrics.detected_attack_scenarios > proposal.original_metrics.detected_attack_scenarios
    assert proposal.improved_metrics.detection_rate >= 87.5

    # 3. FP Guardrail verification: No false positives introduced
    assert proposal.improved_metrics.false_positives == 0
    assert proposal.false_positive_impact == 0
    assert proposal.passed_guardrail is True
    assert proposal.status == "approved"

    # 4. Modification reasons and addressed scenarios
    assert len(proposal.modification_reasons) > 0
    assert len(proposal.addressed_scenarios) > 0
    assert "ATK-002" in proposal.addressed_scenarios
    assert "ATK-004" in proposal.addressed_scenarios

    # 5. Diff output verification
    assert "+  selection_cradle:" in proposal.diff or "selection_cradle" in proposal.improved_yaml
    assert "pwsh.exe" in proposal.improved_yaml

def test_yaml_diff_function():
    orig = "title: Test Rule\nlevel: low\n"
    imp = "title: Test Rule\nlevel: high\n"
    diff = generate_yaml_diff(orig, imp)
    assert "-level: low" in diff
    assert "+level: high" in diff
