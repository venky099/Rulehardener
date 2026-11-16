"""
Tests for Sigma Rule Loading and Validation
"""
import pytest
from backend.rule_manager.sigma_validator import validate_sigma_rule, validate_yaml_syntax
from backend.rule_manager.sigma_loader import parse_sigma_yaml, load_sigma_file, SigmaLoadError
from backend.rule_manager.rule_analyzer import analyze_rule, extract_field_and_modifiers
from backend.config import settings

VALID_RULE_YAML = """
title: Suspicious PowerShell Execution
id: 8c7b1e12-1111-4444-8888-123456789abc
status: experimental
description: Detects suspicious PowerShell command-line activity.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: 'EncodedCommand'
  condition: selection
level: medium
"""

INVALID_YAML = """
title: Broken YAML
detection: [unclosed list
"""

MISSING_TITLE_YAML = """
logsource:
  product: windows
detection:
  selection:
    Image: 'test.exe'
  condition: selection
"""

MISSING_DETECTION_YAML = """
title: No Detection Rule
logsource:
  product: windows
"""

INVALID_CONDITION_YAML = """
title: Bad Condition
logsource:
  product: windows
detection:
  selection:
    Image: 'test.exe'
  condition: non_existent_selection
"""

def test_valid_sigma_validation():
    is_valid, errors, warnings = validate_sigma_rule(VALID_RULE_YAML)
    assert is_valid is True
    assert len(errors) == 0

def test_invalid_yaml_syntax():
    is_valid, data, err = validate_yaml_syntax(INVALID_YAML)
    assert is_valid is False
    assert "YAML syntax error" in err

def test_missing_title():
    is_valid, errors, _ = validate_sigma_rule(MISSING_TITLE_YAML)
    assert is_valid is False
    assert any("title" in e for e in errors)

def test_missing_detection():
    is_valid, errors, _ = validate_sigma_rule(MISSING_DETECTION_YAML)
    assert is_valid is False
    assert any("detection" in e for e in errors)

def test_invalid_condition_reference():
    is_valid, errors, _ = validate_sigma_rule(INVALID_CONDITION_YAML)
    assert is_valid is False
    assert any("does not reference" in e for e in errors)

def test_parse_sigma_yaml_success():
    rule = parse_sigma_yaml(VALID_RULE_YAML)
    assert rule.title == "Suspicious PowerShell Execution"
    assert rule.id == "8c7b1e12-1111-4444-8888-123456789abc"
    assert rule.condition == "selection"
    assert "selection" in rule.detection

def test_parse_sigma_yaml_failure_raises():
    with pytest.raises(SigmaLoadError):
        parse_sigma_yaml(MISSING_TITLE_YAML)

def test_load_example_rule_file():
    example_path = settings.RULES_DIR / "powershell_suspicious_execution.yml"
    rule = load_sigma_file(example_path)
    assert rule.id == "8c7b1e12-1111-4444-8888-123456789abc"
    assert "EncodedCommand" in rule.raw_yaml

def test_extract_field_and_modifiers():
    field, mods = extract_field_and_modifiers("CommandLine|contains|all")
    assert field == "CommandLine"
    assert mods == ["contains", "all"]

def test_analyze_rule():
    rule = parse_sigma_yaml(VALID_RULE_YAML)
    analysis = analyze_rule(rule)
    assert analysis["title"] == "Suspicious PowerShell Execution"
    assert "Image" in analysis["target_fields"]
    assert "CommandLine" in analysis["target_fields"]
    assert "endswith" in analysis["modifiers_used"]
    assert "contains" in analysis["modifiers_used"]
    assert analysis["is_process_creation"] is True
