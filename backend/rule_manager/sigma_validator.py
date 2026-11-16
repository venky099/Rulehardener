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

    condition_str = detection.get("condition", "") if isinstance(detection.get("condition"), str) else ""

    # Validate condition syntax and reference integrity using ConditionParser
    if condition_str and declared_identifiers:
        try:
            from backend.detection.sigma_matcher import (
                ConditionParser, wildcard_match, IdentifierNode, QuantifierNode, NotNode, AndNode, OrNode
            )
            parser = ConditionParser(condition_str)
            ast_root = parser.parse()

            referenced_identifiers = []
            quantifier_patterns = []

            def collect_nodes(node):
                if isinstance(node, IdentifierNode):
                    referenced_identifiers.append(node.identifier)
                elif isinstance(node, QuantifierNode):
                    quantifier_patterns.append(node.pattern)
                elif isinstance(node, NotNode):
                    collect_nodes(node.child)
                elif isinstance(node, (AndNode, OrNode)):
                    collect_nodes(node.left)
                    collect_nodes(node.right)

            collect_nodes(ast_root)

            # Check that every referenced identifier exists in declared_identifiers
            undeclared = [ref for ref in referenced_identifiers if ref not in declared_identifiers]
            if undeclared:
                errors.append(f"Condition does not reference declared selections; references undeclared identifier(s): {undeclared}")

            # Check that quantifier patterns match at least one declared selection
            for pat in quantifier_patterns:
                if pat != "them":
                    matching = [k for k in declared_identifiers if wildcard_match(pat, k)]
                    if not matching:
                        errors.append(f"Condition quantifier pattern '{pat}' matches no declared selections: {sorted(list(declared_identifiers))}")

            # Ensure at least one declared selection is referenced
            if not referenced_identifiers and not quantifier_patterns:
                errors.append(f"Condition '{condition_str}' does not reference any declared selections.")

        except Exception as e:
            errors.append(f"Condition syntax error: {str(e)}")

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
