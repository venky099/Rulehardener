"""
Rule Comparator and FP Guardrail Gatekeeper
Evaluates original and hardened rules side-by-side, enforces FP guardrail, and calculates unified diff.
"""
import difflib
import uuid
from typing import List, Dict, Any
from backend.models import (
    SigmaRule, TelemetryEvent, AttackScenario, HardeningProposal
)
from backend.detection.detection_evaluator import evaluate_rule_on_dataset
from backend.detection.metrics import calculate_detection_metrics
from backend.hardening.gap_analyzer import analyze_detection_gaps
from backend.hardening.rule_optimizer import optimize_rule
from backend.config import settings

def generate_yaml_diff(original_yaml: str, improved_yaml: str) -> str:
    """Generates a readable unified diff string between original and improved YAML."""
    orig_lines = original_yaml.splitlines(keepends=True)
    imp_lines = improved_yaml.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        imp_lines,
        fromfile="original_rule.yml",
        tofile="hardened_rule.yml",
        n=3
    )
    return "".join(diff)

def evaluate_and_compare_rules(
    original_rule: SigmaRule,
    events: List[TelemetryEvent],
    scenarios: List[AttackScenario]
) -> HardeningProposal:
    """
    Complete end-to-end hardening pipeline:
    1. Evaluates original rule.
    2. Identifies detection gaps.
    3. Synthesizes hardened rule.
    4. Evaluates hardened rule on identical datasets.
    5. Validates FP Guardrail.
    6. Produces HardeningProposal.
    """
    # 1. Baseline Evaluation
    orig_evts, orig_scens = evaluate_rule_on_dataset(original_rule, events, scenarios)
    orig_metrics = calculate_detection_metrics(orig_evts, orig_scens)

    # 2. Gap Analysis
    gaps = analyze_detection_gaps(original_rule, orig_scens, orig_evts, events)

    # 3. Rule Optimization
    hardened_rule, applied_mods, addressed_scenarios = optimize_rule(original_rule, gaps)

    # 4. Hardened Evaluation
    hard_evts, hard_scens = evaluate_rule_on_dataset(hardened_rule, events, scenarios)
    hard_metrics = calculate_detection_metrics(hard_evts, hard_scens)

    # 5. False Positive Guardrail Check
    fp_impact = hard_metrics.false_positives - orig_metrics.false_positives
    passed_guardrail = fp_impact <= settings.MAX_ALLOWED_NEW_FALSE_POSITIVES

    # 6. Generate Diff
    diff_str = generate_yaml_diff(original_rule.raw_yaml, hardened_rule.raw_yaml)

    return HardeningProposal(
        proposal_id=str(uuid.uuid4()),
        original_rule_id=original_rule.id,
        improved_rule_id=hardened_rule.id,
        rule_title=original_rule.title,
        original_yaml=original_rule.raw_yaml,
        improved_yaml=hardened_rule.raw_yaml,
        diff=diff_str,
        modification_reasons=applied_mods,
        addressed_scenarios=addressed_scenarios,
        original_metrics=orig_metrics,
        improved_metrics=hard_metrics,
        false_positive_impact=fp_impact,
        passed_guardrail=passed_guardrail,
        status="approved" if passed_guardrail else "rejected"
    )
