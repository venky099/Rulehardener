"""
Telemetry Event Normalizer
Maps varied event schemas (Windows Event 4688, Sysmon Event 1, EDR formats) into standard TelemetryEvent fields.
"""
import hashlib
import json
from typing import Dict, Any
from backend.models import TelemetryEvent

# Common field mapping synonyms across Windows Security, Sysmon, and generic EDRs
FIELD_ALIASES = {
    "image": ["image", "newprocessname", "processpath", "process_name", "filepath", "executable"],
    "command_line": ["commandline", "processcommandline", "command_line", "cmdline", "args"],
    "parent_image": ["parentimage", "parentprocessname", "parent_image", "parentprocesspath"],
    "parent_command_line": ["parentcommandline", "parent_command_line", "parentcmdline"],
    "user": ["user", "subjectusername", "accountname", "username", "user_name"],
    "process_id": ["processid", "newprocessid", "process_id", "pid"],
    "parent_process_id": ["parentprocessid", "parent_process_id", "ppid"],
    "computer": ["computer", "computername", "workstation", "hostname", "device_name"],
    "current_directory": ["currentdirectory", "workingdirectory", "current_dir"],
    "original_file_name": ["originalfilename", "original_file_name", "orig_file_name"],
}

def normalize_raw_event(raw: Dict[str, Any], default_is_attack: bool = False, default_scenario_id: str = "GEN-000", source: str = "imported") -> TelemetryEvent:
    """
    Normalizes a dictionary into a standard TelemetryEvent model.
    Preserves raw event in `raw_event`.
    """
    # Create lookup map of lowercase cleaned keys
    clean_map = {k.lower().replace(" ", "").replace("_", ""): v for k, v in raw.items()}

    def extract_val(alias_key: str, default=None):
        for alias in FIELD_ALIASES.get(alias_key, []):
            stripped_alias = alias.lower().replace("_", "")
            if stripped_alias in clean_map and clean_map[stripped_alias] is not None:
                return clean_map[stripped_alias]
        return default

    raw_repr = json.dumps(raw, sort_keys=True, default=str)
    evt_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()[:8]
    event_id = str(raw.get("event_id") or raw.get("EventId") or raw.get("EventID") or f"EVT-{evt_hash}")
    
    # Do not fabricate false executable names; preserve what is actually present
    image = str(extract_val("image", "") or "")
    command_line = str(extract_val("command_line", image) or image)
    parent_image = str(extract_val("parent_image", "") or "")
    parent_command_line = str(extract_val("parent_command_line", "") or "")
    user = str(extract_val("user", "") or "")
    
    try:
        pid_val = extract_val("process_id", None)
        process_id = int(pid_val) if pid_val is not None else 0
    except (ValueError, TypeError):
        process_id = 0

    try:
        ppid_val = extract_val("parent_process_id", None)
        parent_process_id = int(ppid_val) if ppid_val is not None else 0
    except (ValueError, TypeError):
        parent_process_id = 0

    computer = str(extract_val("computer", "") or "")
    current_directory = str(extract_val("current_directory", "") or "")
    original_file_name = str(extract_val("original_file_name", "") or "")
    hashes = raw.get("hashes", {}) if isinstance(raw.get("hashes"), dict) else {}
    
    is_attack_raw = raw.get("is_attack")
    if is_attack_raw is None:
        is_attack = default_is_attack
    elif isinstance(is_attack_raw, str):
        is_attack = is_attack_raw.strip().lower() in ("true", "1", "yes")
    else:
        is_attack = bool(is_attack_raw)

    scenario_id = str(raw.get("scenario_id") or default_scenario_id)

    return TelemetryEvent(
        event_id=event_id,
        timestamp=str(raw.get("timestamp") or raw.get("Timestamp") or raw.get("TimeCreated") or "2026-01-15T12:00:00Z"),
        computer=computer,
        image=image,
        command_line=command_line,
        parent_image=parent_image,
        parent_command_line=parent_command_line,
        user=user,
        process_id=process_id,
        parent_process_id=parent_process_id,
        original_file_name=original_file_name,
        current_directory=current_directory,
        hashes=hashes,
        is_attack=is_attack,
        scenario_id=scenario_id,
        source=source,
        raw_event=raw
    )
