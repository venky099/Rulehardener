"""
Detection Evaluator
Orchestrates rule evaluation over attack and benign datasets, linking event and scenario levels.
"""
from typing import List, Dict, Tuple
from backend.models import (
    SigmaRule, TelemetryEvent, AttackScenario,
    EventEvaluationResult, ScenarioEvaluation
)
from backend.detection.sigma_matcher import evaluate_event_against_rule

def evaluate_rule_on_dataset(
    rule: SigmaRule,
    events: List[TelemetryEvent],
    scenarios: List[AttackScenario]
) -> Tuple[List[EventEvaluationResult], List[ScenarioEvaluation]]:
    """
    Evaluates rule against all events, aggregates per scenario, and returns:
    (event_results, scenario_results)
    """
    event_results: List[EventEvaluationResult] = []
    scenario_map: Dict[str, AttackScenario] = {s.scenario_id: s for s in scenarios}
    scenario_event_counts: Dict[str, int] = {}
    scenario_detected_counts: Dict[str, int] = {}

    for event in events:
        res = evaluate_event_against_rule(rule, event)
        event_results.append(res)
        
        sc_id = event.scenario_id
        scenario_event_counts[sc_id] = scenario_event_counts.get(sc_id, 0) + 1
        if res.detected:
            scenario_detected_counts[sc_id] = scenario_detected_counts.get(sc_id, 0) + 1

    scenario_results: List[ScenarioEvaluation] = []
    
    # Process all known scenarios
    for sc in scenarios:
        total_evts = scenario_event_counts.get(sc.scenario_id, 0)
        detected_evts = scenario_detected_counts.get(sc.scenario_id, 0)
        
        is_attack = sc.category.lower() == "attack"
        # Scenario is considered detected if at least one of its events is detected
        scenario_detected = detected_evts > 0

        scenario_results.append(
            ScenarioEvaluation(
                scenario_id=sc.scenario_id,
                scenario_name=sc.name,
                is_attack=is_attack,
                total_events=total_evts,
                detected_events=detected_evts,
                detected=scenario_detected,
                mitre_technique_id=sc.mitre_technique_id
            )
        )

    return event_results, scenario_results
