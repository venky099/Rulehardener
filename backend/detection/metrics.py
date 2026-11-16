"""
Detection Metrics Engine
Calculates Detection Rate, False Positive Rate, Precision, Recall, F1 Score, and confusion matrix.
Safely handles division by zero.
"""
from typing import List
from backend.models import (
    EventEvaluationResult, ScenarioEvaluation, EvaluationMetrics
)

def safe_divide(numerator: float, denominator: float, multiplier: float = 1.0) -> float:
    """Performs division with zero-division safeguard and rounded precision."""
    if denominator == 0 or numerator == 0:
        return 0.0
    return round((numerator / denominator) * multiplier, 2)

def calculate_detection_metrics(
    event_results: List[EventEvaluationResult],
    scenario_results: List[ScenarioEvaluation]
) -> EvaluationMetrics:
    """
    Computes rigorous metrics:
    - Attack coverage evaluated at Scenario level.
    - False positives evaluated at Benign Event level (and Benign Scenario level).
    - Precision, Recall, F1 computed using scenario TP/FN and event FP.
    """
    # 1. Attack Scenarios breakdown
    attack_scenarios = [s for s in scenario_results if s.is_attack]
    total_attack_scenarios = len(attack_scenarios)
    detected_attack_scenarios = sum(1 for s in attack_scenarios if s.detected)
    missed_attack_scenarios = total_attack_scenarios - detected_attack_scenarios

    # 2. Benign Events breakdown
    benign_events = [e for e in event_results if not e.is_attack]
    total_benign_events = len(benign_events)
    false_positives = sum(1 for e in benign_events if e.detected)
    true_negatives = total_benign_events - false_positives

    # 3. Scenario-level TP and FN
    true_positives = detected_attack_scenarios
    false_negatives = missed_attack_scenarios

    # 4. Standard formulas as prescribed in prompt.md:
    # Detection Rate = Detected Attack Scenarios / Total Attack Scenarios * 100
    detection_rate = safe_divide(detected_attack_scenarios, total_attack_scenarios, 100.0)

    # False Positive Rate = False Positives / Total Benign Events * 100
    false_positive_rate = safe_divide(false_positives, total_benign_events, 100.0)

    # Precision = TP / (TP + FP)
    precision = safe_divide(true_positives, true_positives + false_positives, 1.0)

    # Recall = TP / (TP + FN)
    recall = safe_divide(true_positives, true_positives + false_negatives, 1.0)

    # F1 = 2 * (Precision * Recall) / (Precision + Recall)
    if (precision + recall) > 0:
        f1_score = round(2 * (precision * recall) / (precision + recall), 2)
    else:
        f1_score = 0.0

    return EvaluationMetrics(
        total_attack_scenarios=total_attack_scenarios,
        detected_attack_scenarios=detected_attack_scenarios,
        missed_attack_scenarios=missed_attack_scenarios,
        total_benign_events=total_benign_events,
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        detection_rate=detection_rate,
        false_positive_rate=false_positive_rate,
        precision=precision,
        recall=recall,
        f1_score=f1_score
    )
