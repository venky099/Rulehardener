"""
Sigma Rule Loader
Safely parses and loads Sigma YAML rules into SigmaRule domain models.
"""
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml

from backend.models import SigmaRule
from backend.rule_manager.sigma_validator import validate_sigma_rule
from backend.utils.logger import logger
from backend.utils.validators import is_safe_path
from backend.config import settings

class SigmaLoadError(Exception):
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or []

def parse_sigma_yaml(yaml_content: str, source_path: Optional[str] = None) -> SigmaRule:
    """
    Parse and validate a Sigma YAML string.
    Raises SigmaLoadError if invalid.
    """
    is_valid, errors, warnings = validate_sigma_rule(yaml_content)
    if not is_valid:
        raise SigmaLoadError(f"Validation failed: {'; '.join(errors)}", errors=errors)

    data = yaml.safe_load(yaml_content)
    rule_id = str(data.get("id") or str(uuid.uuid4()))
    title = str(data.get("title", "Untitled Rule"))
    status = str(data.get("status", "experimental"))
    description = str(data.get("description", ""))
    author = str(data.get("author", ""))
    date = str(data.get("date", ""))
    logsource = data.get("logsource", {})
    detection = data.get("detection", {})
    condition = str(detection.get("condition", ""))
    tags = list(data.get("tags", []))
    level = str(data.get("level", "medium"))
    falsepositives = list(data.get("falsepositives", []))

    return SigmaRule(
        id=rule_id,
        title=title,
        status=status,
        description=description,
        author=author,
        date=date,
        logsource=logsource,
        detection=detection,
        condition=condition,
        tags=tags,
        level=level,
        falsepositives=falsepositives,
        raw_yaml=yaml_content
    )

def load_sigma_file(file_path: Path) -> SigmaRule:
    """Load a Sigma rule from a file path safely."""
    if not is_safe_path(settings.BASE_DIR, file_path):
        raise ValueError(f"Path traversal detected or access outside base directory forbidden: {file_path}")
    if not file_path.exists():
        raise FileNotFoundError(f"Sigma rule file not found: {file_path}")
    content = file_path.read_text(encoding="utf-8")
    return parse_sigma_yaml(content, source_path=str(file_path))

def load_rules_from_directory(dir_path: Path) -> List[SigmaRule]:
    """Load all valid Sigma rules from a directory."""
    rules = []
    if not dir_path.exists():
        return rules
    for p in dir_path.glob("*.y*ml"):
        try:
            rule = load_sigma_file(p)
            rules.append(rule)
        except Exception as e:
            logger.warning(f"Could not load Sigma rule from {p.name}: {e}")
    return rules
