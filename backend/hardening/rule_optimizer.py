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

# Supported interpreter executables
POWERSHELL_BINARIES = [
    r"\powershell.exe",
    r"\pwsh.exe",
    r"\powershell_ise.exe",
]

# Strict parameter regular expression:
# Requires CLI flag boundaries (-enc, -ec, -en, -e, /enc, /ec, /en, /e, or -EncodedCommand)
# followed by at least 4 base64 characters.
# Prevents false positives on benign arguments like 'robocopy A B /e', 'xcopy /e', or 'git config -e'.
STRICT_ENCODED_REGEX = r'(?i)(?:^|[\s"\'`])[-/](?:encodedcommand|enc|ec|en|e)(?:[\s:]|$)\s*[A-Za-z0-9+/=]{4,}'

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
                    if current_img in (r"\powershell.exe", "powershell.exe"):
                        sel_block["Image|endswith"] = POWERSHELL_BINARIES
                        if img_key != "Image|endswith":
                            del sel_block[img_key]
                        applied_mods.append("Generalized Image to include PowerShell Core ('\\pwsh.exe') and ISE ('\\powershell_ise.exe').")
                        break

            # Check CommandLine flag expansion with strict boundaries
            for cmd_key in ["CommandLine|contains", "CommandLine"]:
                if cmd_key in sel_block:
                    current_cmd = sel_block[cmd_key]
                    if isinstance(current_cmd, str) and "encodedcommand" in current_cmd.lower():
                        sel_block["CommandLine|re"] = STRICT_ENCODED_REGEX
                        del sel_block[cmd_key]
                        applied_mods.append("Upgraded CommandLine to strict regex parameter boundary matching (-enc, -ec, -en, -e, /enc, /e) with base64 boundary protection.")
                        break

    # 2. Additional Selections for unhandled techniques
    if "download_cradle_miss" in gap_types:
        detection["selection_cradle"] = {
            "Image|endswith": POWERSHELL_BINARIES,
            "CommandLine|contains|all": ["IEX", "DownloadString"]
        }
        applied_mods.append("Added 'selection_cradle' to detect in-memory IEX/DownloadString stages.")

    if "execution_policy_bypass_miss" in gap_types:
        detection["selection_bypass"] = {
            "Image|endswith": POWERSHELL_BINARIES,
            "CommandLine|contains": [
                "ExecutionPolicy Bypass",
                "ExecutionPolicy:Bypass",
                "-ep bypass",
                "-ep:bypass",
                "-exec bypass",
                "-exec:bypass",
                "-ex bypass",
                "-ex:bypass",
                "/ep bypass",
                "/ep:bypass",
                "/exec bypass",
                "/exec:bypass",
                "/executionpolicy bypass",
                "/executionpolicy:bypass",
            ]
        }
        # Legitimate enterprise management exclusion filter strictly scoped to legitimate CCM directory:
        # Prevents attacker bypass via arbitrary locations like C:\Users\Public\CcmExec.exe
        detection["filter_sccm"] = {
            "ParentImage|startswith": [
                "C:\\Windows\\CCM\\",
                "C:\\SMS_CCM\\"
            ],
            "ParentImage|endswith": "\\CcmExec.exe"
        }
        applied_mods.append("Added 'selection_bypass' covering ExecutionPolicy Bypass variations (-ep, -exec, -ex, /ep, /exec).")
        applied_mods.append("Synthesized path-scoped 'filter_sccm' for legitimate enterprise CcmExec path.")

    # Reconstruct condition:
    # Security Architecture: filter_sccm ONLY scopes benign execution policy bypasses.
    # Encoded commands and download cradles are NEVER suppressed by filter_sccm.
    cond_parts = []
    base_cond = detection.get("condition", "selection")
    cond_parts.append(f"({base_cond})")
    
    if "selection_cradle" in detection:
        cond_parts.append("(selection_cradle)")
        
    if "selection_bypass" in detection:
        if "filter_sccm" in detection:
            cond_parts.append("(selection_bypass and not filter_sccm)")
        else:
            cond_parts.append("(selection_bypass)")
            
    detection["condition"] = " or ".join(cond_parts)

    # Update metadata
    new_id = str(uuid.uuid4())
    data["id"] = new_id
    data["title"] = f"{data.get('title', 'Rule')} (Hardened)"
    mod_summary = "; ".join(applied_mods)
    data["description"] = f"{data.get('description', '')}\n[Hardened]: {mod_summary}"
    data["detection"] = detection
    data["status"] = data.get("status", "experimental")
    
    tags = list(data.get("tags", []))
    if any("powershell" in str(v).lower() for v in detection.values()):
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
