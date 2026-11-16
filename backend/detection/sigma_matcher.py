"""
Deterministic Sigma Rule Matching Engine
Implements AST condition parsing, modifier evaluation, and detailed per-event match diagnostics.
"""
import re
import fnmatch
from typing import Dict, Any, List, Tuple, Optional, Set
from backend.models import SigmaRule, TelemetryEvent, EventEvaluationResult

class ConditionASTNode:
    """Base AST Node for Sigma Condition Expressions."""
    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        raise NotImplementedError

class IdentifierNode(ConditionASTNode):
    def __init__(self, identifier: str):
        self.identifier = identifier

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return selection_results.get(self.identifier, False)

class NotNode(ConditionASTNode):
    def __init__(self, child: ConditionASTNode):
        self.child = child

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return not self.child.evaluate(selection_results)

class AndNode(ConditionASTNode):
    def __init__(self, left: ConditionASTNode, right: ConditionASTNode):
        self.left = left
        self.right = right

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return self.left.evaluate(selection_results) and self.right.evaluate(selection_results)

class OrNode(ConditionASTNode):
    def __init__(self, left: ConditionASTNode, right: ConditionASTNode):
        self.left = left
        self.right = right

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return self.left.evaluate(selection_results) or self.right.evaluate(selection_results)

class QuantifierNode(ConditionASTNode):
    def __init__(self, quantifier: str, pattern: str):
        self.quantifier = quantifier.lower()  # "1 of" or "all of"
        self.pattern = pattern

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        if self.pattern == "them":
            matching_keys = list(selection_results.keys())
        else:
            matching_keys = [k for k in selection_results.keys() if fnmatch.fnmatch(k, self.pattern)]
        
        if not matching_keys:
            return False

        results = [selection_results.get(k, False) for k in matching_keys]
        if self.quantifier == "1 of":
            return any(results)
        elif self.quantifier == "all of":
            return all(results)
        return False

class ConditionParser:
    """
    Recursive descent parser for Sigma boolean condition expressions:
    Supports: and, or, not, nested parentheses (), 1 of <pattern>, all of <pattern>, identifiers.
    """
    def __init__(self, expr: str):
        self.expr = expr
        self.tokens = self._tokenize(expr)
        self.pos = 0

    def _tokenize(self, expr: str) -> List[str]:
        # Handle "1 of pattern" or "all of pattern"
        token_spec = [
            ("LPAREN", r"\("),
            ("RPAREN", r"\)"),
            ("QUANT", r"\b(1\s+of|all\s+of)\s+([A-Za-z0-9_*]+)"),
            ("NOT", r"\bnot\b"),
            ("AND", r"\band\b"),
            ("OR", r"\bor\b"),
            ("ID", r"[A-Za-z0-9_*]+"),
            ("SKIP", r"\s+"),
        ]
        tok_regex = "|".join(f"(?P<{pair[0]}>{pair[1]})" for pair in token_spec)
        tokens = []
        for mo in re.finditer(tok_regex, expr, re.IGNORECASE):
            kind = mo.lastgroup
            val = mo.group()
            if kind == "SKIP":
                continue
            elif kind == "QUANT":
                tokens.append(val.strip())
            else:
                tokens.append(val.lower() if kind in ("NOT", "AND", "OR") else val)
        return tokens

    def current_token(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def eat(self, expected: Optional[str] = None) -> str:
        tok = self.current_token()
        if tok is None:
            raise ValueError("Unexpected end of condition expression")
        if expected and tok != expected:
            raise ValueError(f"Expected token '{expected}', got '{tok}'")
        self.pos += 1
        return tok

    def parse(self) -> ConditionASTNode:
        if not self.tokens:
            return IdentifierNode("selection")
        node = self.parse_or()
        return node

    def parse_or(self) -> ConditionASTNode:
        node = self.parse_and()
        while self.current_token() == "or":
            self.eat("or")
            right = self.parse_and()
            node = OrNode(node, right)
        return node

    def parse_and(self) -> ConditionASTNode:
        node = self.parse_not()
        while self.current_token() == "and":
            self.eat("and")
            right = self.parse_not()
            node = AndNode(node, right)
        return node

    def parse_not(self) -> ConditionASTNode:
        if self.current_token() == "not":
            self.eat("not")
            child = self.parse_not()
            return NotNode(child)
        return self.parse_primary()

    def parse_primary(self) -> ConditionASTNode:
        tok = self.current_token()
        if tok == "(":
            self.eat("(")
            node = self.parse_or()
            self.eat(")")
            return node
        elif tok and (tok.lower().startswith("1 of") or tok.lower().startswith("all of")):
            parts = tok.split()
            quant = f"{parts[0]} {parts[1]}"
            pattern = parts[2]
            self.eat()
            return QuantifierNode(quant, pattern)
        elif tok:
            ident = self.eat()
            return IdentifierNode(ident)
        raise ValueError(f"Syntax error at end of expression: '{self.expr}'")

def get_event_field_value(event: TelemetryEvent, field_name: str) -> Optional[str]:
    """Retrieves standard or raw attribute from event, handling casing."""
    lower_field = field_name.lower().replace("_", "")
    
    attr_map = {
        "image": event.image,
        "commandline": event.command_line,
        "parentimage": event.parent_image,
        "parentcommandline": event.parent_command_line,
        "user": event.user,
        "processid": str(event.process_id),
        "parentprocessid": str(event.parent_process_id),
        "originalfilename": event.original_file_name,
        "currentdirectory": event.current_directory,
        "computer": event.computer,
    }
    
    if lower_field in attr_map:
        return attr_map[lower_field]
    
    # Check raw_event
    if event.raw_event:
        for k, v in event.raw_event.items():
            if k.lower().replace("_", "") == lower_field:
                return str(v) if v is not None else None
    return None

def match_single_criteria(field_value: str, criteria_val: Any, modifiers: List[str]) -> bool:
    """Evaluates a single expected criteria value against an actual field string."""
    target_val = str(criteria_val)
    actual_val = str(field_value)

    # Windows process fields are treated case-insensitively
    actual_norm = actual_val.lower()
    target_norm = target_val.lower()

    if "windash" in modifiers:
        # Standardize - and /
        actual_norm = actual_norm.replace("/", "-")
        target_norm = target_norm.replace("/", "-")

    if "re" in modifiers:
        try:
            return bool(re.search(target_val, actual_val, re.IGNORECASE))
        except re.error:
            return False

    if "contains" in modifiers:
        return target_norm in actual_norm
    elif "startswith" in modifiers:
        return actual_norm.startswith(target_norm)
    elif "endswith" in modifiers:
        return actual_norm.endswith(target_norm)
    else:
        # Default match: exact or wildcard matching
        if "*" in target_val or "?" in target_val:
            return fnmatch.fnmatch(actual_norm, target_norm)
        return actual_norm == target_norm

def evaluate_field_selection(event: TelemetryEvent, field_expr: str, criteria: Any) -> Tuple[bool, str]:
    """
    Evaluates a single field expression (e.g. 'Image|endswith') against an event.
    Returns (is_match, reason_string).
    """
    parts = field_expr.split("|")
    field_name = parts[0].strip()
    modifiers = [p.strip().lower() for p in parts[1:]]

    actual_val = get_event_field_value(event, field_name)
    if actual_val is None:
        return False, f"Field '{field_name}' not present in telemetry event"

    if isinstance(criteria, list):
        if "all" in modifiers:
            # All items in criteria list must match
            matches = [match_single_criteria(actual_val, item, modifiers) for item in criteria]
            is_match = all(matches)
            if is_match:
                return True, f"All criteria in '{field_expr}' matched '{actual_val}'"
            return False, f"Not all criteria in '{field_expr}' matched '{actual_val}' (expected all: {criteria})"
        else:
            # Any item in criteria list matches (OR)
            for item in criteria:
                if match_single_criteria(actual_val, item, modifiers):
                    return True, f"'{actual_val}' matched '{item}' via '{field_expr}'"
            return False, f"'{actual_val}' did not match any of {criteria} via '{field_expr}'"
    else:
        is_match = match_single_criteria(actual_val, criteria, modifiers)
        if is_match:
            return True, f"'{actual_val}' matched '{criteria}' via '{field_expr}'"
        return False, f"'{actual_val}' did not match '{criteria}' via '{field_expr}'"

def evaluate_selection_block(event: TelemetryEvent, selection_data: Any) -> Tuple[bool, Dict[str, Any], Dict[str, Any], List[str]]:
    """
    Evaluates a declared selection block (dictionary or list of dictionaries).
    Returns (matched, matching_fields, non_matching_fields, reasons).
    """
    matching_fields = {}
    non_matching_fields = {}
    reasons = []

    if isinstance(selection_data, dict):
        all_matched = True
        for field_expr, criteria in selection_data.items():
            is_match, reason = evaluate_field_selection(event, field_expr, criteria)
            if is_match:
                matching_fields[field_expr] = {"criteria": criteria, "reason": reason}
            else:
                all_matched = False
                non_matching_fields[field_expr] = {"criteria": criteria, "reason": reason}
                reasons.append(reason)
        return all_matched, matching_fields, non_matching_fields, reasons

    elif isinstance(selection_data, list):
        # List of maps is evaluated as OR of maps
        any_matched = False
        all_reasons = []
        for idx, sub_dict in enumerate(selection_data):
            if isinstance(sub_dict, dict):
                sub_matched, sub_m, sub_nm, sub_reasons = evaluate_selection_block(event, sub_dict)
                if sub_matched:
                    any_matched = True
                    matching_fields.update(sub_m)
                    reasons.append(f"Sub-block {idx+1} satisfied")
                    break
                else:
                    all_reasons.extend(sub_reasons)
                    non_matching_fields.update(sub_nm)
        if not any_matched:
            reasons.extend(all_reasons)
        return any_matched, matching_fields, non_matching_fields, reasons

    return False, {}, {}, ["Invalid selection data structure"]

def evaluate_event_against_rule(rule: SigmaRule, event: TelemetryEvent) -> EventEvaluationResult:
    """
    Evaluates a single telemetry event against a Sigma rule deterministically.
    """
    selection_results: Dict[str, bool] = {}
    all_matching_fields: Dict[str, Any] = {}
    all_non_matching_fields: Dict[str, Any] = {}
    all_reasons: List[str] = []

    # 1. Evaluate all selection / filter blocks
    for ident, block_data in rule.detection.items():
        if ident == "condition":
            continue
        is_match, m_fields, nm_fields, reasons = evaluate_selection_block(event, block_data)
        selection_results[ident] = is_match
        if is_match:
            all_matching_fields.update(m_fields)
        else:
            all_non_matching_fields.update(nm_fields)
            all_reasons.extend(reasons)

    # 2. Evaluate condition expression using AST parser
    condition_expr = rule.condition or "selection"
    try:
        parser = ConditionParser(condition_expr)
        ast = parser.parse()
        detected = bool(ast.evaluate(selection_results))
    except Exception as e:
        detected = False
        all_reasons.append(f"Condition evaluation syntax error: {str(e)}")

    if detected:
        summary_reason = f"Detected: condition '{condition_expr}' satisfied."
    else:
        failed_selections = [k for k, v in selection_results.items() if not v and not k.startswith("filter")]
        if failed_selections:
            summary_reason = f"Missed: selection '{failed_selections[0]}' failed ({'; '.join(all_reasons[:2])})"
        else:
            summary_reason = f"Filtered out or condition '{condition_expr}' not met."

    return EventEvaluationResult(
        event_id=event.event_id,
        scenario_id=event.scenario_id,
        rule_id=rule.id,
        is_attack=event.is_attack,
        detected=detected,
        matching_fields=all_matching_fields,
        non_matching_fields=all_non_matching_fields,
        reason=summary_reason
    )
