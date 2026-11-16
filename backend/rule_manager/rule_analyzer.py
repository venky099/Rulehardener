"""
Rule Analyzer
Inspects Sigma rule detection structure, targets, modifiers, and condition topology.
"""
from typing import Dict, Any, List, Set, Tuple
from backend.models import SigmaRule

def extract_field_and_modifiers(raw_field: str) -> Tuple[str, List[str]]:
    """
    Given a field key like 'Image|endswith' or 'CommandLine|contains|all',
    extract field name ('Image') and list of modifiers (['endswith']).
    """
    parts = raw_field.split("|")
    field_name = parts[0].strip()
    modifiers = [p.strip().lower() for p in parts[1:]]
    return field_name, modifiers

def analyze_rule(rule: SigmaRule) -> Dict[str, Any]:
    """
    Extract structured analytical summary of the rule.
    """
    selections: Dict[str, Any] = {}
    target_fields: Set[str] = set()
    modifiers_used: Set[str] = set()
    
    for key, val in rule.detection.items():
        if key == "condition":
            continue
        selections[key] = val
        if isinstance(val, dict):
            for field_expr, criteria in val.items():
                field_name, mods = extract_field_and_modifiers(field_expr)
                target_fields.add(field_name)
                modifiers_used.update(mods)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    for field_expr, criteria in item.items():
                        field_name, mods = extract_field_and_modifiers(field_expr)
                        target_fields.add(field_name)
                        modifiers_used.update(mods)

    # Check logsource compatibility
    logsource = rule.logsource or {}
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    is_process_creation = category == "process_creation" or product in ["windows", "sysmon"]

    return {
        "rule_id": rule.id,
        "title": rule.title,
        "condition": rule.condition,
        "selection_keys": list(selections.keys()),
        "target_fields": sorted(list(target_fields)),
        "modifiers_used": sorted(list(modifiers_used)),
        "is_process_creation": is_process_creation,
        "tags_count": len(rule.tags),
        "level": rule.level
    }
