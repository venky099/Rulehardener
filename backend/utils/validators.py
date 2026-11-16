"""
Security and File Validation Utilities
"""
import re
from pathlib import Path
from typing import Tuple
from backend.config import settings

def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Prevent path traversal vulnerabilities."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target.is_relative_to(resolved_base)
    except Exception:
        return False

def validate_rule_filename(filename: str) -> Tuple[bool, str]:
    """Validate uploaded rule filename and extension."""
    if not filename:
        return False, "Filename cannot be empty."
    path = Path(filename)
    if path.suffix.lower() not in settings.ALLOWED_RULE_EXTENSIONS:
        return False, f"Invalid rule file extension '{path.suffix}'. Allowed: {settings.ALLOWED_RULE_EXTENSIONS}"
    if not re.match(r"^[\w\-. ]+$", path.name):
        return False, "Filename contains unsafe characters."
    return True, ""

def validate_telemetry_filename(filename: str) -> Tuple[bool, str]:
    """Validate uploaded telemetry filename and extension."""
    if not filename:
        return False, "Filename cannot be empty."
    path = Path(filename)
    if path.suffix.lower() not in settings.ALLOWED_TELEMETRY_EXTENSIONS:
        return False, f"Invalid telemetry file extension '{path.suffix}'. Allowed: {settings.ALLOWED_TELEMETRY_EXTENSIONS}"
    if not re.match(r"^[\w\-. ]+$", path.name):
        return False, "Filename contains unsafe characters."
    return True, ""

def validate_payload_size(data_bytes: bytes) -> Tuple[bool, str]:
    """Validate data payload size within safety limit."""
    if len(data_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
        return False, f"Payload size exceeds maximum allowed limit ({settings.MAX_UPLOAD_SIZE_BYTES / (1024*1024):.1f}MB)."
    return True, ""
