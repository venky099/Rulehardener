"""
Detection Gap Analyzer
Pinpoints exact field failures and behavioral discrepancies in missed attack scenarios.
"""
from typing import List, Dict, Any
from backend.models import (
    SigmaRule, ScenarioEvaluation, EventEvaluationResult, TelemetryEvent
)

def analyze_detection_gaps(
    rule: SigmaRule,
    scenario_results: List[ScenarioEvaluation],
    event_results: List[EventEvaluationResult],
    events: List[TelemetryEvent]
) -> List[Dict[str, Any]]:
    """
    Analyzes all missed attack scenarios to identify failure patterns.
    Returns structured list of detection gaps.
    """
    event_map = {e.event_id: e for e in events}
    eval_map = {e.event_id: e for e in event_results}
    
    missed_attacks = [s for s in scenario_results if s.is_attack and not s.detected]
    gaps: List[Dict[str, Any]] = []

    for sc in missed_attacks:
        # Find events corresponding to this scenario
        sc_events = [e for e in events if e.scenario_id == sc.scenario_id]
        for evt in sc_events:
            evt_eval = eval_map.get(evt.event_id)
            cmd = evt.command_line.lower()
            img = evt.image.lower()

            gap_type = "unknown"
            root_cause = "Rule conditions not satisfied"
            recommended_action = ""

            # Check 1: Encoded command variations (-enc, -e, /enc)
            if any(flg in cmd for flg in ["-enc", "-e ", "-en ", "/enc", "/e "]) and "encodedcommand" not in cmd:
                gap_type = "cli_abbreviation_miss"
                root_cause = "Rule only looks for 'EncodedCommand', missing PowerShell parameter abbreviation (-enc, -e, /enc)."
                recommended_action = "Expand CommandLine match list to include recognized parameter abbreviations."

            # Check 2: Binary name mismatch (pwsh.exe)
            elif "pwsh.exe" in img and "\\powershell.exe" in str(rule.detection):
                gap_type = "binary_alias_miss"
                root_cause = "Rule only checks for 'powershell.exe', missing PowerShell Core ('pwsh.exe')."
                recommended_action = "Add '\\pwsh.exe' to Image target selection."

            # Check 3: Download Cradle
            elif "iex" in cmd and "downloadstring" in cmd:
                gap_type = "download_cradle_miss"
                root_cause = "Malicious invocation uses in-memory download cradle without encoded command flags."
                recommended_action = "Add secondary selection for download cradles (IEX + DownloadString)."

            # Check 4: ExecutionPolicy Bypass
            elif ("bypass" in cmd) and ("executionpolicy" in cmd or "-ep" in cmd):
                gap_type = "execution_policy_bypass_miss"
                root_cause = "Attack invokes unapproved script via ExecutionPolicy bypass."
                recommended_action = "Add selection for suspicious execution policy bypass flags."

            # Check 5: Suspicious Parent
            elif evt.parent_image and "cmd.exe" in evt.parent_image.lower() and "powershell" in img:
                gap_type = "suspicious_parent_miss"
                root_cause = "PowerShell spawned from legacy cmd shell with evasion parameters."
                recommended_action = "Include parent process correlation (ParentImage: cmd.exe)."

            gaps.append({
                "scenario_id": sc.scenario_id,
                "scenario_name": sc.scenario_name,
                "event_id": evt.event_id,
                "gap_type": gap_type,
                "root_cause": root_cause,
                "recommended_action": recommended_action,
                "command_line": evt.command_line,
                "image": evt.image,
                "non_matching_fields": evt_eval.non_matching_fields if evt_eval else {}
            })

    return gaps
