"""
Application Configuration for RuleHardener
"""
import os
from pathlib import Path
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent

def _resolve_database_path() -> Path:
    db_env = os.getenv("DATABASE_PATH")
    if db_env:
        return Path(db_env)
    
    default_db = BASE_DIR / "data" / "database" / "rulehardener.db"
    try:
        default_db.parent.mkdir(parents=True, exist_ok=True)
        test_file = default_db.parent / ".perm_check"
        with open(test_file, "a") as f:
            pass
        test_file.unlink(missing_ok=True)
        return default_db
    except (PermissionError, OSError):
        import tempfile
        fallback_dir = Path(tempfile.gettempdir()) / "rulehardener" / "database"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        return fallback_dir / "rulehardener.db"

class Settings(BaseModel):
    APP_NAME: str = "RuleHardener"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Paths
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = BASE_DIR / "data"
    DATABASE_PATH: Path = Field(default_factory=_resolve_database_path)
    RULES_DIR: Path = BASE_DIR / "data" / "rules"
    ATTACK_SCENARIOS_DIR: Path = BASE_DIR / "data" / "attack_scenarios"
    ATTACK_TELEMETRY_DIR: Path = BASE_DIR / "data" / "attack_telemetry"
    BENIGN_TELEMETRY_DIR: Path = BASE_DIR / "data" / "benign_telemetry"
    REPORTS_DIR: Path = BASE_DIR / "data" / "reports"
    
    # Security limits
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_RULE_EXTENSIONS: tuple = (".yml", ".yaml")
    ALLOWED_TELEMETRY_EXTENSIONS: tuple = (".json", ".jsonl")
    
    # Hardening guardrails
    MAX_ALLOWED_NEW_FALSE_POSITIVES: int = 0  # Zero-tolerance default

settings = Settings()

# Ensure directories exist where permissible
for directory in [
    settings.DATA_DIR,
    settings.DATABASE_PATH.parent,
    settings.RULES_DIR,
    settings.ATTACK_SCENARIOS_DIR,
    settings.ATTACK_TELEMETRY_DIR,
    settings.BENIGN_TELEMETRY_DIR,
    settings.REPORTS_DIR,
]:
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        pass
