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
from backend.utils.validators import is_safe_path
from backend.config import settings

def load_telemetry_from_jsonl(file_path: Path, default_is_attack: bool = False, source: str = "imported") -> List[TelemetryEvent]:
    """Load events from a JSON or JSONL file safely."""
    events = []
    if not is_safe_path(settings.BASE_DIR, file_path):
        logger.error(f"Unsafe file path rejected: {file_path}")
        return events
    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return events

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Try parsing as standard JSON array/object first (handles pretty-printed JSON)
    trimmed = content.strip()
    if trimmed.startswith("[") or trimmed.startswith("{"):
        try:
            parsed = json.loads(trimmed)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        events.append(normalize_raw_event(item, default_is_attack=default_is_attack, source=source))
                return events
            elif isinstance(parsed, dict):
                events.append(normalize_raw_event(parsed, default_is_attack=default_is_attack, source=source))
                return events
        except json.JSONDecodeError:
            pass

    # Fallback to line-by-line JSONL format
    for line_num, line in enumerate(trimmed.splitlines(), start=1):
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
    """Parse raw JSON or JSONL text from an upload buffer. Handles pretty-printed JSON and JSONL."""
    events = []
    errors = []
    trimmed = content_str.strip()
    if not trimmed:
        return events, ["Uploaded content is empty."]

    # Try full JSON parsing first (supports pretty-printed and array JSON files)
    if trimmed.startswith("[") or trimmed.startswith("{"):
        try:
            parsed = json.loads(trimmed)
            if isinstance(parsed, list):
                for idx, item in enumerate(parsed, start=1):
                    if isinstance(item, dict):
                        events.append(normalize_raw_event(item, default_is_attack=default_is_attack, source=source))
                    else:
                        errors.append(f"Item {idx}: JSON array element must be a dictionary.")
                return events, errors
            elif isinstance(parsed, dict):
                events.append(normalize_raw_event(parsed, default_is_attack=default_is_attack, source=source))
                return events, errors
        except json.JSONDecodeError:
            pass

    # Line-by-line JSONL parsing (preserve original line numbers from content_str)
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
