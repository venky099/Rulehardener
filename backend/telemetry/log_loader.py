"""
Telemetry Log Loader
Reads and validates JSON/JSONL telemetry data from files or uploaded strings.
"""
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from backend.models import TelemetryEvent
from backend.telemetry.event_normalizer import normalize_raw_event
from backend.utils.logger import logger

def load_telemetry_from_jsonl(file_path: Path, default_is_attack: bool = False, source: str = "imported") -> List[TelemetryEvent]:
    """Load events from a JSONL file."""
    events = []
    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return events

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                raw_data = json.loads(line_str)
                if isinstance(raw_data, dict):
                    evt = normalize_raw_event(raw_data, default_is_attack=default_is_attack, source=source)
                    events.append(evt)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed JSON line {line_num} in {file_path.name}: {e}")
    return events

def parse_uploaded_jsonl(content_str: str, default_is_attack: bool = False, source: str = "uploaded") -> Tuple[List[TelemetryEvent], List[str]]:
    """Parse raw JSONL text from an upload buffer. Returns (events, errors)."""
    events = []
    errors = []
    for line_num, line in enumerate(content_str.splitlines(), start=1):
        line_str = line.strip()
        if not line_str:
            continue
        try:
            raw_data = json.loads(line_str)
            if not isinstance(raw_data, dict):
                errors.append(f"Line {line_num}: JSON entry must be a dictionary.")
                continue
            evt = normalize_raw_event(raw_data, default_is_attack=default_is_attack, source=source)
            events.append(evt)
        except json.JSONDecodeError as e:
            errors.append(f"Line {line_num}: Invalid JSON ({str(e)})")
    return events, errors
