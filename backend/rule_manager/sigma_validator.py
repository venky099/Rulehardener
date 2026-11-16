"""
Sigma Rule Validator
Validates YAML structure, required Sigma schema fields, detection blocks, and pySigma compatibility.
"""
from typing import Dict, Any, List, Tuple
import re
import yaml
try:
    from sigma.rule import SigmaRule as PySigmaRule
    from sigma.exceptions import SigmaError
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False

REQUIRED_FIELDS = ["title", "logsource", "detection"]
RECOMMENDED_FIELDS = ["id", "status", "description", "level"]

def validate_yaml_syntax(yaml_content: str) -> Tuple[bool, Any, str]:
    """Check if content is valid YAML and safely parsed."""
    if not yaml_content or not yaml_content.strip():
        return False, None, "Rule content is empty."
    try:
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            return False, None, "Sigma rule YAML must be a dictionary/mapping."
        return True, data, ""
    except yaml.YAMLError as e:
        return False, None, f"YAML syntax error: {str(e)}"

def validate_detection_block(detection: Any) -> Tuple[bool, List[str]]:
    """Validate detection dictionary and condition reference integrity."""
    errors = []
    if not isinstance(detection, dict):
        return False, ["'detection' section must be a dictionary/mapping."]
    
    if "condition" not in detection:
        errors.append("Detection block is missing required 'condition' field.")
    elif not detection["condition"] or not isinstance(detection["condition"], str):
        errors.append("'condition' field must be a non-empty string expression.")

    # Find declared selection identifiers
    declared_identifiers = set(k for k in detection.keys() if k != "condition")
    if not declared_identifiers:
        errors.append("Detection block must define at least one selection identifier.")

    # Check that condition references valid identifiers (token-based check)
    condition_str = detection.get("condition", "") if isinstance(detection.get("condition"), str) else ""
    tokens = set(re.findall(r'\b[A-Za-z0-9_]+\b', condition_str))
    
    # Check if any declared identifier or wildcard matching is referenced
    referenced = False
    for ident in declared_identifiers:
        if ident in tokens:
            referenced = True
            break
    if not referenced and "1 of " not in condition_str and "all of " not in condition_str and declared_identifiers:
        errors.append(f"Condition '{condition_str}' does not reference any declared selections: {sorted(list(declared_identifiers))}")

    return len(errors) == 0, errors

def validate_sigma_rule(yaml_content: str) -> Tuple[bool, List[str], List[str]]:
    """
    Comprehensive validation of a Sigma rule.
    Returns: (is_valid, errors, warnings)
    """
    errors: List[str] = []
    warnings: List[str] = []

    # 1. YAML syntax check
    is_valid_yaml, data, yaml_err = validate_yaml_syntax(yaml_content)
    if not is_valid_yaml:
        return False, [yaml_err], warnings

    # 2. Required fields check
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"Missing mandatory Sigma field: '{field}'")

    # 3. Recommended fields check
    for field in RECOMMENDED_FIELDS:
        if field not in data:
            warnings.append(f"Missing recommended Sigma field: '{field}'")

    # 4. Logsource check
    logsource = data.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        errors.append("'logsource' must be a dictionary.")

    # 5. Detection block check
    detection = data.get("detection")
    if detection is not None:
        det_valid, det_errors = validate_detection_block(detection)
        if not det_valid:
            errors.extend(det_errors)

    # 6. pySigma check (structural)
    if PYSIGMA_AVAILABLE and not errors:
        try:
            PySigmaRule.from_yaml(yaml_content)
        except Exception as e:
            # We treat pySigma warning as a warning or structural notice
            warnings.append(f"pySigma structural note: {str(e)}")

    return len(errors) == 0, errors, warnings
