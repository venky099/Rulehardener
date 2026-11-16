"""
Deterministic Rule Optimizer
Applies defensive hardening patterns to generate hardened Sigma YAML detection rules.
"""
import copy
import uuid
from typing import List, Dict, Any, Tuple
import yaml
from backend.models import SigmaRule
from backend.rule_manager.sigma_validator import validate_sigma_rule
from backend.rule_manager.sigma_loader import parse_sigma_yaml

ENCODED_FLAG_VARIATIONS = [
    "EncodedCommand",
    "-enc",
    "-e ",
    "-en ",
    "/enc",
    "/e ",
    "/en ",
]

POWERSHELL_BINARIES = [
    r"\powershell.exe",
    r"\pwsh.exe"
]

def optimize_rule(rule: SigmaRule, gaps: List[Dict[str, Any]]) -> Tuple[SigmaRule, List[str], List[str]]:
    """
    Applies deterministic hardening strategies based on identified detection gaps.
    Returns: (hardened_rule, applied_modifications, addressed_scenarios)
    """
    applied_mods: List[str] = []
    addressed_scenarios: List[str] = []
    gap_types = set(g["gap_type"] for g in gaps)

    # Parse raw yaml to retain dictionary structure
    data = yaml.safe_load(rule.raw_yaml)
    detection = copy.deepcopy(data.get("detection", {}))
    
    # 1. Parameter Expansion & Binary Aliasing in primary selection
    for sel_key in list(detection.keys()):
        if sel_key == "condition":
            continue
        sel_block = detection[sel_key]
        if isinstance(sel_block, dict):
            # Check Image generalization
            for img_key in ["Image|endswith", "Image"]:
                if img_key in sel_block:
                    current_img = sel_block[img_key]
                    if current_img == r"\powershell.exe" or current_img == "powershell.exe":
                        sel_block["Image|endswith"] = POWERSHELL_BINARIES
                        if img_key != "Image|endswith":
                            del sel_block[img_key]
                        applied_mods.append("Generalized Image to include PowerShell Core ('\\pwsh.exe').")
                        break

            # Check CommandLine flag expansion
            for cmd_key in ["CommandLine|contains", "CommandLine"]:
                if cmd_key in sel_block:
                    current_cmd = sel_block[cmd_key]
                    if isinstance(current_cmd, str) and "encodedcommand" in current_cmd.lower():
                        sel_block["CommandLine|contains"] = ENCODED_FLAG_VARIATIONS
                        if cmd_key != "CommandLine|contains":
                            del sel_block[cmd_key]
                        applied_mods.append("Expanded CommandLine to match parameter abbreviations (-enc, -e, /enc).")
                        break

    # 2. Additional Selections for unhandled techniques
    condition_parts = [detection.get("condition", "selection")]
    
    if "download_cradle_miss" in gap_types:
        detection["selection_cradle"] = {
            "Image|endswith": POWERSHELL_BINARIES,
            "CommandLine|contains|all": ["IEX", "DownloadString"]
        }
        condition_parts.append("selection_cradle")
        applied_mods.append("Added 'selection_cradle' to detect in-memory IEX/DownloadString stages.")

    if "execution_policy_bypass_miss" in gap_types:
        detection["selection_bypass"] = {
            "Image|endswith": POWERSHELL_BINARIES,
            "CommandLine|contains": ["ExecutionPolicy Bypass", "-ep bypass", "/ep bypass"]
        }
        # Add legitimate enterprise management exclusion filter to prevent false positives from SCCM/CcmExec
        detection["filter_sccm"] = {
            "ParentImage|endswith": r"\CcmExec.exe"
        }
        condition_parts.append("selection_bypass")
        applied_mods.append("Added 'selection_bypass' to catch execution policy bypass invocations.")
        applied_mods.append("Synthesized 'filter_sccm' to whitelist legitimate enterprise CcmExec executions.")

    # Reconstruct condition
    if len(condition_parts) > 1:
        base_cond = condition_parts[0]
        additional_conds = " or ".join(condition_parts[1:])
        combined = f"({base_cond}) or ({additional_conds})"
        if "filter_sccm" in detection:
            detection["condition"] = f"({combined}) and not filter_sccm"
        else:
            detection["condition"] = combined

    # Update metadata
    new_id = str(uuid.uuid4())
    data["id"] = new_id
    data["title"] = f"{data.get('title', 'Rule')} (Hardened)"
    data["description"] = f"{data.get('description', '')}\n[Hardened]: Deterministically expanded coverage for parameter abbreviations, pwsh.exe, and download cradles."
    data["detection"] = detection
    
    tags = list(data.get("tags", []))
    if "attack.t1059.001" not in tags:
        tags.append("attack.t1059.001")
    if "rulehardener.hardened" not in tags:
        tags.append("rulehardener.hardened")
    data["tags"] = tags

    hardened_yaml = yaml.dump(data, sort_keys=False, default_flow_style=False)
    
    # Validate the generated rule
    is_valid, errors, _ = validate_sigma_rule(hardened_yaml)
    if not is_valid:
        raise ValueError(f"Failed to generate valid hardened Sigma rule: {'; '.join(errors)}")

    hardened_rule = parse_sigma_yaml(hardened_yaml)
    hardened_rule.version = rule.version + 1
    hardened_rule.parent_rule_id = rule.id

    for g in gaps:
        if g["scenario_id"] not in addressed_scenarios:
            addressed_scenarios.append(g["scenario_id"])

    return hardened_rule, applied_mods, addressed_scenarios
