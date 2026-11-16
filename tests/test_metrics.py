"""
Unit Tests for Detection Metrics Calculations
"""
from backend.detection.metrics import safe_divide, calculate_detection_metrics
from backend.models import EventEvaluationResult, ScenarioEvaluation

def test_safe_divide():
    assert safe_divide(10, 2) == 5.0
    assert safe_divide(0, 5) == 0.0
    assert safe_divide(5, 0) == 0.0
    assert safe_divide(1, 3, multiplier=100.0) == 33.33

def test_metric_calculations_edge_cases():
    # Empty sets
    metrics_empty = calculate_detection_metrics([], [])
    assert metrics_empty.detection_rate == 0.0
    assert metrics_empty.false_positive_rate == 0.0
    assert metrics_empty.f1_score == 0.0

def test_metric_calculations_normal():
    # 4 attack scenarios: 3 detected, 1 missed
    scenarios = [
        ScenarioEvaluation(scenario_id="A1", scenario_name="Atk1", is_attack=True, total_events=1, detected_events=1, detected=True),
        ScenarioEvaluation(scenario_id="A2", scenario_name="Atk2", is_attack=True, total_events=1, detected_events=1, detected=True),
        ScenarioEvaluation(scenario_id="A3", scenario_name="Atk3", is_attack=True, total_events=1, detected_events=1, detected=True),
        ScenarioEvaluation(scenario_id="A4", scenario_name="Atk4", is_attack=True, total_events=1, detected_events=0, detected=False),
        ScenarioEvaluation(scenario_id="B1", scenario_name="Ben1", is_attack=False, total_events=1, detected_events=0, detected=False),
        ScenarioEvaluation(scenario_id="B2", scenario_name="Ben2", is_attack=False, total_events=1, detected_events=1, detected=True),
    ]

    events = [
        EventEvaluationResult(event_id="E1", scenario_id="A1", rule_id="R1", is_attack=True, detected=True),
        EventEvaluationResult(event_id="E2", scenario_id="A2", rule_id="R1", is_attack=True, detected=True),
        EventEvaluationResult(event_id="E3", scenario_id="A3", rule_id="R1", is_attack=True, detected=True),
        EventEvaluationResult(event_id="E4", scenario_id="A4", rule_id="R1", is_attack=True, detected=False),
        EventEvaluationResult(event_id="EB1", scenario_id="B1", rule_id="R1", is_attack=False, detected=False),
        EventEvaluationResult(event_id="EB2", scenario_id="B2", rule_id="R1", is_attack=False, detected=True),  # 1 FP
    ]

    metrics = calculate_detection_metrics(events, scenarios)
    assert metrics.total_attack_scenarios == 4
    assert metrics.detected_attack_scenarios == 3
    assert metrics.missed_attack_scenarios == 1
    assert metrics.true_positives == 3
    assert metrics.false_negatives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    # DR: 3/4 * 100 = 75.0%
    assert metrics.detection_rate == 75.0
    # FPR: 1/2 * 100 = 50.0%
    assert metrics.false_positive_rate == 50.0
    # Precision: 3 / (3 + 1) = 0.75
    assert metrics.precision == 0.75
    # Recall: 3 / (3 + 1) = 0.75
    assert metrics.recall == 0.75
    # F1: 2 * (0.75 * 0.75) / (0.75 + 0.75) = 0.75
    assert metrics.f1_score == 0.75
