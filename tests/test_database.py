"""
Unit Tests for SQLite Persistence Layer
"""
import pytest
from pathlib import Path
from backend.database import (
    init_db, save_rule, get_rules, get_rule_by_id,
    save_scenarios, get_scenarios,
    save_telemetry_events, get_telemetry_events,
    save_evaluation_run, get_evaluation_runs,
    save_hardening_proposal, get_hardening_proposals,
    save_report, get_reports
)
from backend.models import (
    SigmaRule, AttackScenario, TelemetryEvent,
    EvaluationMetrics, EventEvaluationResult, HardeningProposal
)

@pytest.fixture(autouse=True)
def setup_database():
    init_db()

def test_rule_crud_and_versioning():
    rule = SigmaRule(
        id="RULE-DB-001",
        title="Database Test Rule",
        status="experimental",
        level="high",
        tags=["attack.execution"],
        raw_yaml="title: Database Test Rule\nlevel: high\n"
    )
    save_rule(rule, version=1, change_summary="Version 1 import")
    
    loaded = get_rule_by_id("RULE-DB-001")
    assert loaded is not None
    assert loaded.title == "Database Test Rule"
    assert loaded.level == "high"

    # Update version
    rule.level = "critical"
    save_rule(rule, version=2, change_summary="Bumped to critical")
    
    updated = get_rule_by_id("RULE-DB-001")
    assert updated.level == "critical"
    assert updated.version == 2

def test_scenarios_persistence():
    scenarios = [
        AttackScenario(scenario_id="TEST-ATK-1", name="Test Attack 1", description="desc", expected_behavior="exec", category="attack"),
        AttackScenario(scenario_id="TEST-BEN-1", name="Test Benign 1", description="desc", expected_behavior="admin", category="benign"),
    ]
    save_scenarios(scenarios)
    
    attacks = get_scenarios(category="attack")
    assert any(s.scenario_id == "TEST-ATK-1" for s in attacks)
    assert not any(s.scenario_id == "TEST-BEN-1" for s in attacks)

def test_telemetry_persistence():
    events = [
        TelemetryEvent(
            event_id="EVT-DB-1",
            image="powershell.exe",
            command_line="powershell.exe -enc AAAA",
            is_attack=True,
            scenario_id="TEST-ATK-1"
        )
    ]
    save_telemetry_events(events)
    loaded = get_telemetry_events(scenario_id="TEST-ATK-1")
    assert len(loaded) >= 1
    assert loaded[0].event_id == "EVT-DB-1"
    assert loaded[0].is_attack is True

def test_evaluation_run_persistence():
    rule = SigmaRule(id="RULE-DB-001", title="Database Test Rule", raw_yaml="dummy")
    metrics = EvaluationMetrics(
        total_attack_scenarios=5,
        detected_attack_scenarios=4,
        missed_attack_scenarios=1,
        detection_rate=80.0
    )
    evt_results = [
        EventEvaluationResult(
            event_id="EVT-DB-1",
            scenario_id="TEST-ATK-1",
            rule_id="RULE-DB-001",
            is_attack=True,
            detected=True,
            reason="Matched"
        )
    ]
    run_id = save_evaluation_run(rule, metrics, evt_results)
    assert run_id.startswith("RUN-")

    runs = get_evaluation_runs(rule_id="RULE-DB-001")
    assert len(runs) >= 1
    assert runs[0]["detection_rate"] == 80.0

def test_hardening_proposal_persistence():
    proposal = HardeningProposal(
        proposal_id="PROP-001",
        original_rule_id="RULE-DB-001",
        improved_rule_id="RULE-DB-002",
        rule_title="Database Test Rule",
        original_yaml="dummy_orig",
        improved_yaml="dummy_imp",
        diff="+ new line",
        modification_reasons=["Added -enc"],
        addressed_scenarios=["TEST-ATK-1"],
        original_metrics=EvaluationMetrics(detection_rate=20.0),
        improved_metrics=EvaluationMetrics(detection_rate=100.0),
        passed_guardrail=True,
        status="approved"
    )
    save_hardening_proposal(proposal)

    proposals = get_hardening_proposals(rule_id="RULE-DB-001")
    assert len(proposals) >= 1
    assert proposals[0]["passed_guardrail"] is True
    assert "Added -enc" in proposals[0]["modification_reasons"]

def test_reports_persistence():
    save_report("REP-001", "Audit Report 1", '{"status": "ok"}', run_id="RUN-001")
    reports = get_reports()
    assert any(r["report_id"] == "REP-001" for r in reports)
