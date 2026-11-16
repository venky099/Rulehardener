"""
Unit Tests for Sigma Matching Engine
Tests field modifiers, multi-value logic, and condition AST evaluation.
"""
import pytest
from backend.models import SigmaRule, TelemetryEvent
from backend.detection.sigma_matcher import (
    evaluate_event_against_rule, ConditionParser,
    match_single_criteria, evaluate_field_selection
)

@pytest.fixture
def base_event():
    return TelemetryEvent(
        event_id="EVT-TEST-001",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoProfile -enc SQBFAFgAIAA=",
        parent_image=r"C:\Windows\explorer.exe",
        parent_command_line=r"C:\Windows\explorer.exe",
        user=r"CORP\Administrator",
        process_id=4500,
        parent_process_id=1200,
        is_attack=True,
        scenario_id="ATK-002"
    )

def test_exact_and_wildcard_matching():
    assert match_single_criteria(r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe", []) is True
    assert match_single_criteria(r"C:\Windows\System32\cmd.exe", r"*cmd.exe", []) is True
    assert match_single_criteria(r"C:\Windows\System32\powershell.exe", r"*cmd.exe", []) is False

def test_modifier_contains():
    assert match_single_criteria("powershell.exe -enc SQBFAFgA", "-enc", ["contains"]) is True
    assert match_single_criteria("powershell.exe -File script.ps1", "-enc", ["contains"]) is False

def test_modifier_startswith():
    assert match_single_criteria("powershell.exe -enc", "powershell.exe", ["startswith"]) is True
    assert match_single_criteria("cmd.exe /c powershell.exe", "powershell.exe", ["startswith"]) is False

def test_modifier_endswith():
    assert match_single_criteria(r"C:\Windows\System32\powershell.exe", r"\powershell.exe", ["endswith"]) is True
    assert match_single_criteria(r"C:\Windows\System32\cmd.exe", r"\powershell.exe", ["endswith"]) is False

def test_modifier_re():
    assert match_single_criteria("powershell.exe -e SQBFAFgA", r"-(e|enc|encodedcommand)\b", ["re"]) is True
    assert match_single_criteria("powershell.exe -Help", r"-(e|enc|encodedcommand)\b", ["re"]) is False

def test_modifier_windash():
    # windash equates / and -
    assert match_single_criteria("powershell.exe /enc SQBFAFgA", "-enc", ["contains", "windash"]) is True
    assert match_single_criteria("powershell.exe -enc SQBFAFgA", "/enc", ["contains", "windash"]) is True

def test_list_or_criteria(base_event):
    # Image ends with either powershell.exe or pwsh.exe
    is_match, reason = evaluate_field_selection(base_event, "Image|endswith", [r"\powershell.exe", r"\pwsh.exe"])
    assert is_match is True

def test_list_all_criteria(base_event):
    # Both -NoProfile and -enc present
    is_match, _ = evaluate_field_selection(base_event, "CommandLine|contains|all", ["-NoProfile", "-enc"])
    assert is_match is True
    
    # -NoProfile present, but -WindowStyle is not
    is_match2, _ = evaluate_field_selection(base_event, "CommandLine|contains|all", ["-NoProfile", "-WindowStyle"])
    assert is_match2 is False

def test_condition_ast_evaluator():
    p1 = ConditionParser("selection and not filter")
    ast1 = p1.parse()
    assert ast1.evaluate({"selection": True, "filter": False}) is True
    assert ast1.evaluate({"selection": True, "filter": True}) is False

    p2 = ConditionParser("selection1 or selection2")
    ast2 = p2.parse()
    assert ast2.evaluate({"selection1": False, "selection2": True}) is True

    p3 = ConditionParser("1 of selection*")
    ast3 = p3.parse()
    assert ast3.evaluate({"selection_a": False, "selection_b": True}) is True
    assert ast3.evaluate({"selection_a": False, "selection_b": False}) is False

    p4 = ConditionParser("all of selection*")
    ast4 = p4.parse()
    assert ast4.evaluate({"selection_a": True, "selection_b": True}) is True
    assert ast4.evaluate({"selection_a": True, "selection_b": False}) is False

    p5 = ConditionParser("(sel_a or sel_b) and not filter")
    ast5 = p5.parse()
    assert ast5.evaluate({"sel_a": True, "sel_b": False, "filter": False}) is True
    assert ast5.evaluate({"sel_a": True, "sel_b": False, "filter": True}) is False

def test_event_against_rule_detection(base_event):
    rule = SigmaRule(
        id="RULE-01",
        title="Test Encoded PowerShell",
        detection={
            "selection": {
                "Image|endswith": r"\powershell.exe",
                "CommandLine|contains": "-enc"
            },
            "condition": "selection"
        },
        raw_yaml="dummy"
    )
    res = evaluate_event_against_rule(rule, base_event)
    assert res.detected is True
    assert "Image|endswith" in res.matching_fields
    assert "CommandLine|contains" in res.matching_fields

def test_event_against_rule_missed(base_event):
    rule = SigmaRule(
        id="RULE-02",
        title="Exact EncodedCommand Check",
        detection={
            "selection": {
                "Image|endswith": r"\powershell.exe",
                "CommandLine|contains": "EncodedCommand"
            },
            "condition": "selection"
        },
        raw_yaml="dummy"
    )
    # base_event uses -enc, so EncodedCommand should not match
    res = evaluate_event_against_rule(rule, base_event)
    assert res.detected is False
    assert "CommandLine|contains" in res.non_matching_fields
