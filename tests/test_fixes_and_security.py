"""
Verification and Regression Tests for Security, Correctness, and Guardrail Fixes
"""
import pytest
from backend.models import TelemetryEvent, AttackScenario, SigmaRule
from backend.detection.sigma_matcher import evaluate_event_against_rule, ConditionParser
from backend.rule_manager.sigma_validator import validate_sigma_rule
from backend.hardening.rule_optimizer import optimize_rule
from backend.hardening.rule_comparator import evaluate_and_compare_rules
from backend.telemetry.event_normalizer import normalize_raw_event
from backend.telemetry.log_loader import parse_uploaded_jsonl
from backend.database import save_rule, rollback_rule_version, get_rule_by_id, init_db
from backend.utils.pdf_generator import generate_pdf_report
from backend.rule_manager.sigma_loader import load_sigma_file
from backend.config import settings

def test_robocopy_and_git_no_false_positives():
    """Verify that hardened rule does NOT flag ordinary commands like robocopy /e or git config -e."""
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule = load_sigma_file(rule_path)
    
    # Generate hardened rule
    from backend.hardening.gap_analyzer import analyze_detection_gaps
    from backend.telemetry.synthetic_generator import generate_telemetry_for_scenarios, get_predefined_scenarios
    from backend.detection.detection_evaluator import evaluate_rule_on_dataset
    
    atk_events, ben_events = generate_telemetry_for_scenarios()
    atk_scens, ben_scens = get_predefined_scenarios()
    
    evts, scens = evaluate_rule_on_dataset(rule, atk_events + ben_events, atk_scens + ben_scens)
    gaps = analyze_detection_gaps(rule, scens, evts, atk_events + ben_events)
    hardened_rule, _, _ = optimize_rule(rule, gaps)

    # Benign test events with -e or /e flags
    robocopy_evt = TelemetryEvent(
        event_id="TEST-ROBO",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line='powershell.exe -Command "robocopy C:\\src C:\\dst /e"',
        is_attack=False,
        scenario_id="BEN-ROBO"
    )
    git_evt = TelemetryEvent(
        event_id="TEST-GIT",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="git config -e --global",
        is_attack=False,
        scenario_id="BEN-GIT"
    )

    res_robo = evaluate_event_against_rule(hardened_rule, robocopy_evt)
    res_git = evaluate_event_against_rule(hardened_rule, git_evt)

    assert res_robo.detected is False, "Hardened rule falsely flagged robocopy /e"
    assert res_git.detected is False, "Hardened rule falsely flagged git config -e"

def test_sccm_attacker_spoof_cannot_disable_rule():
    """Verify that attacker-created CcmExec.exe cannot disable encoded command detection."""
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule = load_sigma_file(rule_path)
    
    from backend.hardening.gap_analyzer import analyze_detection_gaps
    from backend.telemetry.synthetic_generator import generate_telemetry_for_scenarios, get_predefined_scenarios
    from backend.detection.detection_evaluator import evaluate_rule_on_dataset
    
    atk_events, ben_events = generate_telemetry_for_scenarios()
    atk_scens, ben_scens = get_predefined_scenarios()
    evts, scens = evaluate_rule_on_dataset(rule, atk_events + ben_events, atk_scens + ben_scens)
    gaps = analyze_detection_gaps(rule, scens, evts, atk_events + ben_events)
    hardened_rule, _, _ = optimize_rule(rule, gaps)

    # Attacker in Public folder running encoded command
    spoofed_attacker_evt = TelemetryEvent(
        event_id="TEST-SPOOF",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        parent_image=r"C:\Users\Public\CcmExec.exe",
        is_attack=True,
        scenario_id="ATK-SPOOF"
    )

    res = evaluate_event_against_rule(hardened_rule, spoofed_attacker_evt)
    assert res.detected is True, "Attacker spoofing CcmExec.exe parent bypassed detection!"

def test_keyword_list_selections():
    """Verify that keyword lists without field names match across telemetry strings."""
    keyword_yaml = """
title: Mimikatz Keyword Detection
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  keywords:
    - mimikatz
    - sekurlsa
  condition: keywords
"""
    from backend.rule_manager.sigma_loader import parse_sigma_yaml
    rule = parse_sigma_yaml(keyword_yaml)

    evt_match = TelemetryEvent(
        event_id="EVT-MIMI",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c mimikatz.exe privilege::debug exit",
        is_attack=True,
        scenario_id="ATK-MIMI"
    )
    evt_nomatch = TelemetryEvent(
        event_id="EVT-CLEAN",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c dir C:\\",
        is_attack=False,
        scenario_id="BEN-CLEAN"
    )

    res_m = evaluate_event_against_rule(rule, evt_match)
    res_nm = evaluate_event_against_rule(rule, evt_nomatch)

    assert res_m.detected is True
    assert res_nm.detected is False

def test_condition_parser_rejects_leftover_tokens():
    """Verify that ConditionParser rejects conditions with trailing/leftover tokens."""
    with pytest.raises(ValueError, match="Unexpected trailing tokens"):
        parser = ConditionParser("selection selection2")
        parser.parse()

    with pytest.raises(ValueError, match="Unexpected trailing tokens"):
        parser = ConditionParser("selection | count() > 5")
        parser.parse()

def test_validator_rejects_undeclared_selection_typo():
    """Verify validator catches typos in condition referencing non-existent selections."""
    typo_yaml = """
title: Typo Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: 'cmd.exe'
  condition: selection or selecton_typo
"""
    is_valid, errors, _ = validate_sigma_rule(typo_yaml)
    assert is_valid is False
    assert any("does not reference declared selections" in e for e in errors)

def test_redos_protection():
    """Verify catastrophic backtracking regex patterns are rejected safely."""
    rule_redos = """
title: ReDoS Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '(a+)+$'
  condition: selection
"""
    from backend.rule_manager.sigma_loader import parse_sigma_yaml
    rule = parse_sigma_yaml(rule_redos)
    long_input = "a" * 25 + "!"
    evt = TelemetryEvent(
        event_id="EVT-REDOS",
        image="cmd.exe",
        command_line=long_input,
        is_attack=False,
        scenario_id="BEN-01"
    )
    res = evaluate_event_against_rule(rule, evt)
    assert res.detected is False

def test_deterministic_event_id():
    """Verify normalize_raw_event generates identical event IDs regardless of Python hash seed."""
    raw = {"Image": "powershell.exe", "CommandLine": "powershell.exe -enc ABC"}
    evt1 = normalize_raw_event(raw)
    evt2 = normalize_raw_event(raw)
    assert evt1.event_id == evt2.event_id
    assert evt1.event_id.startswith("EVT-")

def test_pretty_printed_json_array_import():
    """Verify multi-line pretty-printed JSON arrays parse cleanly."""
    json_array = """
    [
      {
        "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
        "command_line": "whoami /all",
        "is_attack": "false"
      },
      {
        "image": "C:\\\\Windows\\\\System32\\\\powershell.exe",
        "command_line": "powershell.exe -enc test",
        "is_attack": "true"
      }
    ]
    """
    events, errors = parse_uploaded_jsonl(json_array)
    assert len(errors) == 0
    assert len(events) == 2
    assert events[0].is_attack is False
    assert events[1].is_attack is True

def test_rollback_functionality():
    """Verify rollback_rule_version accurately restores historical rule state."""
    init_db()
    rule_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule_v1 = load_sigma_file(rule_path)
    save_rule(rule_v1, version=1, change_summary="Version 1 baseline")

    # Save version 2
    rule_v2 = load_sigma_file(rule_path)
    rule_v2.title = "Modified Title v2"
    rule_v2.raw_yaml = rule_v2.raw_yaml.replace("Suspicious PowerShell Execution", "Modified Title v2")
    save_rule(rule_v2, version=2, change_summary="Version 2 modification")

    # Roll back to version 1
    restored = rollback_rule_version(rule_v1.id, 1)
    assert restored is not None
    assert restored.version == 3
    assert "Suspicious PowerShell Execution" in restored.title

def test_pdf_report_generation():
    """Verify PDF report generator creates valid PDF bytes."""
    run_meta = {
        "run_id": "RUN-TEST-001",
        "rule_id": "test-uuid-1234",
        "rule_title": "PowerShell Test",
        "rule_version": 1,
        "detection_rate": 100.0,
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "precision": 1.0,
        "recall": 1.0,
        "f1_score": 1.0,
        "total_scenarios": 8,
        "detected_scenarios": 8,
        "missed_scenarios": 0,
        "created_at": "2026-01-15 12:00:00"
    }
    pdf_bytes = generate_pdf_report(run_meta, proposals_count=1)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000
