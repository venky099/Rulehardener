"""
Tests for Detection Evaluator Pipeline
Verifies batch evaluation against synthetic datasets.
"""
from backend.rule_manager.sigma_loader import load_sigma_file
from backend.telemetry.synthetic_generator import generate_telemetry_for_scenarios, get_predefined_scenarios
from backend.detection.detection_evaluator import evaluate_rule_on_dataset
from backend.detection.metrics import calculate_detection_metrics
from backend.config import settings

def test_original_rule_evaluation_on_synthetic_data():
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule = load_sigma_file(rule_path)

    atk_events, ben_events = generate_telemetry_for_scenarios()
    atk_scenarios, ben_scenarios = get_predefined_scenarios()

    all_events = atk_events + ben_events
    all_scenarios = atk_scenarios + ben_scenarios

    event_results, scenario_results = evaluate_rule_on_dataset(rule, all_events, all_scenarios)
    assert len(event_results) == 20
    assert len(scenario_results) == 20

    # Original rule only detects ATK-001 (which has "EncodedCommand")
    atk_map = {s.scenario_id: s for s in scenario_results if s.is_attack}
    assert atk_map["ATK-001"].detected is True
    # ATK-002 uses -enc, should be missed by original rule
    assert atk_map["ATK-002"].detected is False
    # ATK-004 uses pwsh.exe, should be missed by original rule
    assert atk_map["ATK-004"].detected is False

    # Original rule should NOT trigger on any benign events (0 False Positives)
    ben_detected = [e for e in event_results if not e.is_attack and e.detected]
    assert len(ben_detected) == 0

    metrics = calculate_detection_metrics(event_results, scenario_results)
    assert metrics.total_attack_scenarios == 8
    assert metrics.detected_attack_scenarios == 1
    assert metrics.missed_attack_scenarios == 7
    assert metrics.false_positives == 0
    assert metrics.false_positive_rate == 0.0
    # Detection rate: 1 / 8 * 100 = 12.5%
    assert metrics.detection_rate == 12.5

def test_empty_dataset_evaluation():
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule = load_sigma_file(rule_path)

    event_results, scenario_results = evaluate_rule_on_dataset(rule, [], [])
    assert len(event_results) == 0
    assert len(scenario_results) == 0

    metrics = calculate_detection_metrics(event_results, scenario_results)
    assert metrics.total_attack_scenarios == 0
    assert metrics.detection_rate == 0.0
    assert metrics.false_positives == 0

def test_malformed_telemetry_handling():
    from backend.telemetry.log_loader import parse_uploaded_jsonl
    malformed_jsonl = """
    {"valid": "json", "image": "cmd.exe"}
    {malformed json line
    {"another": "valid", "CommandLine": "whoami"}
    """
    events, errors = parse_uploaded_jsonl(malformed_jsonl)
    assert len(events) == 2
    assert len(errors) == 1
    assert "Line 3" in errors[0]

def test_benign_event_handling_isolation():
    from backend.telemetry.event_normalizer import normalize_raw_event
    from backend.detection.sigma_matcher import evaluate_event_against_rule
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule = load_sigma_file(rule_path)

    # Benign administrative command
    benign_raw = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -Command Get-Service",
        "is_attack": False,
        "scenario_id": "BEN-TEST"
    }
    ben_evt = normalize_raw_event(benign_raw)
    res = evaluate_event_against_rule(rule, ben_evt)
    # Must NOT detect benign command
    assert res.detected is False
    assert res.is_attack is False
    assert "EncodedCommand" in str(res.non_matching_fields)
