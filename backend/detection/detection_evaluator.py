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

    # Ensure all scenarios referenced in events are tracked (handles uploaded events with GEN-000 or custom IDs)
    known_scenario_ids = {s.scenario_id for s in scenarios}
    all_scenarios = list(scenarios)
    for sc_id, count in scenario_event_counts.items():
        if sc_id not in known_scenario_ids:
            is_atk = any(e.is_attack for e in events if e.scenario_id == sc_id)
            cat = "attack" if is_atk else "benign"
            new_sc = AttackScenario(
                scenario_id=sc_id,
                name=f"Custom Telemetry ({sc_id})",
                description=f"Auto-registered scenario for {count} uploaded telemetry event(s)",
                category=cat,
                mitre_technique_id="T1059.001" if is_atk else "None",
                technique_name=f"Uploaded {cat.title()} Telemetry"
            )
            all_scenarios.append(new_sc)
            known_scenario_ids.add(sc_id)

    scenario_results: List[ScenarioEvaluation] = []
    
    # Process all scenarios
    for sc in all_scenarios:
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
