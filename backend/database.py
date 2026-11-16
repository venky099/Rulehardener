"""
SQLite Database Layer
Implements schema creation, foreign key constraints, connection pooling, and CRUD operations.
"""
import sqlite3
import json
import uuid
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path
from backend.config import settings
from backend.models import (
    SigmaRule, AttackScenario, TelemetryEvent,
    EvaluationMetrics, EventEvaluationResult, HardeningProposal
)
from backend.utils.logger import logger

def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Returns a SQLite connection with row_factory configured."""
    target_path = db_path or settings.DATABASE_PATH
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: Optional[Path] = None) -> None:
    """Creates database tables if they do not already exist."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 1. Rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        status TEXT,
        description TEXT,
        author TEXT,
        date TEXT,
        level TEXT,
        tags TEXT,
        raw_yaml TEXT NOT NULL,
        current_version INTEGER DEFAULT 1,
        parent_rule_id TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # 2. Rule Versions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rule_versions (
        id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        raw_yaml TEXT NOT NULL,
        change_summary TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
    );
    """)

    # 3. Scenarios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scenarios (
        scenario_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        expected_behavior TEXT,
        mitre_technique_id TEXT,
        mitre_tactic TEXT,
        category TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 4. Telemetry Events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT,
        computer TEXT,
        image TEXT NOT NULL,
        command_line TEXT NOT NULL,
        parent_image TEXT,
        parent_command_line TEXT,
        user TEXT,
        process_id INTEGER,
        parent_process_id INTEGER,
        original_file_name TEXT,
        current_directory TEXT,
        is_attack INTEGER NOT NULL,
        scenario_id TEXT NOT NULL,
        source TEXT NOT NULL,
        raw_json TEXT
    );
    """)

    # 5. Evaluation Runs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evaluation_runs (
        run_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        rule_title TEXT,
        rule_version INTEGER,
        total_scenarios INTEGER,
        detected_scenarios INTEGER,
        missed_scenarios INTEGER,
        detection_rate REAL,
        false_positives INTEGER,
        false_positive_rate REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
    );
    """)

    # 6. Detection Results
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detection_results (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        scenario_id TEXT NOT NULL,
        is_attack INTEGER NOT NULL,
        detected INTEGER NOT NULL,
        matching_fields TEXT,
        non_matching_fields TEXT,
        reason TEXT,
        FOREIGN KEY(run_id) REFERENCES evaluation_runs(run_id) ON DELETE CASCADE
    );
    """)

    # 7. Hardening Proposals
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hardening_proposals (
        proposal_id TEXT PRIMARY KEY,
        original_rule_id TEXT NOT NULL,
        improved_rule_id TEXT NOT NULL,
        rule_title TEXT NOT NULL,
        original_yaml TEXT NOT NULL,
        improved_yaml TEXT NOT NULL,
        diff TEXT NOT NULL,
        modification_reasons TEXT,
        addressed_scenarios TEXT,
        orig_detection_rate REAL,
        imp_detection_rate REAL,
        false_positive_impact INTEGER,
        passed_guardrail INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 8. Reports
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        report_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        run_id TEXT,
        report_type TEXT,
        format TEXT,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

# ----------------- CRUD Operations -----------------

def save_rule(rule: SigmaRule, version: Optional[int] = None, change_summary: str = "Initial rule import") -> None:
    conn = get_connection()
    ver = version or rule.version or 1
    tags_json = json.dumps(rule.tags)
    
    # Check if rule exists
    existing = conn.execute("SELECT id, current_version FROM rules WHERE id = ?", (rule.id,)).fetchone()
    if existing:
        conn.execute("""
        UPDATE rules SET
            title = ?, status = ?, description = ?, author = ?, date = ?,
            level = ?, tags = ?, raw_yaml = ?, current_version = ?, parent_rule_id = ?
        WHERE id = ?;
        """, (
            rule.title, rule.status, rule.description, rule.author, rule.date,
            rule.level, tags_json, rule.raw_yaml, ver, rule.parent_rule_id, rule.id
        ))
    else:
        conn.execute("""
        INSERT INTO rules (id, title, status, description, author, date, level, tags, raw_yaml, current_version, parent_rule_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            rule.id, rule.title, rule.status, rule.description, rule.author, rule.date,
            rule.level, tags_json, rule.raw_yaml, ver, rule.parent_rule_id, rule.created_at
        ))

    # Add version snapshot
    version_id = f"{rule.id}_v{ver}_{uuid.uuid4().hex[:6]}"
    conn.execute("""
    INSERT INTO rule_versions (id, rule_id, version, raw_yaml, change_summary, created_at)
    VALUES (?, ?, ?, ?, ?, ?);
    """, (version_id, rule.id, ver, rule.raw_yaml, change_summary, rule.created_at))

    conn.commit()
    conn.close()

def get_rules() -> List[SigmaRule]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM rules ORDER BY created_at DESC;").fetchall()
    rules = []
    for r in rows:
        tags = json.loads(r["tags"]) if r["tags"] else []
        try:
            data = yaml.safe_load(r["raw_yaml"]) or {}
        except Exception:
            data = {}
        detection = data.get("detection", {})
        condition = str(detection.get("condition", ""))
        logsource = data.get("logsource", {})
        rules.append(SigmaRule(
            id=r["id"],
            title=r["title"],
            status=r["status"],
            description=r["description"],
            author=r["author"],
            date=r["date"],
            level=r["level"],
            tags=tags,
            logsource=logsource,
            detection=detection,
            condition=condition,
            raw_yaml=r["raw_yaml"],
            version=r["current_version"],
            parent_rule_id=r["parent_rule_id"],
            created_at=r["created_at"]
        ))
    conn.close()
    return rules

def get_rule_by_id(rule_id: str) -> Optional[SigmaRule]:
    conn = get_connection()
    r = conn.execute("SELECT * FROM rules WHERE id = ?;", (rule_id,)).fetchone()
    conn.close()
    if not r:
        return None
    tags = json.loads(r["tags"]) if r["tags"] else []
    try:
        data = yaml.safe_load(r["raw_yaml"]) or {}
    except Exception:
        data = {}
    detection = data.get("detection", {})
    condition = str(detection.get("condition", ""))
    logsource = data.get("logsource", {})
    return SigmaRule(
        id=r["id"],
        title=r["title"],
        status=r["status"],
        description=r["description"],
        author=r["author"],
        date=r["date"],
        level=r["level"],
        tags=tags,
        logsource=logsource,
        detection=detection,
        condition=condition,
        raw_yaml=r["raw_yaml"],
        version=r["current_version"],
        parent_rule_id=r["parent_rule_id"],
        created_at=r["created_at"]
    )

def get_rule_versions(rule_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute("""
    SELECT id, rule_id, version, change_summary, created_at, raw_yaml 
    FROM rule_versions 
    WHERE rule_id = ? 
    ORDER BY version DESC;
    """, (rule_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def save_scenarios(scenarios: List[AttackScenario]) -> None:
    conn = get_connection()
    for sc in scenarios:
        conn.execute("""
        INSERT OR REPLACE INTO scenarios (scenario_id, name, description, expected_behavior, mitre_technique_id, mitre_tactic, category, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'));
        """, (sc.scenario_id, sc.name, sc.description, sc.expected_behavior, sc.mitre_technique_id, sc.mitre_tactic, sc.category))
    conn.commit()
    conn.close()

def get_scenarios(category: Optional[str] = None) -> List[AttackScenario]:
    conn = get_connection()
    if category:
        rows = conn.execute("SELECT * FROM scenarios WHERE category = ? ORDER BY scenario_id ASC;", (category,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM scenarios ORDER BY category ASC, scenario_id ASC;").fetchall()
    conn.close()
    return [
        AttackScenario(
            scenario_id=r["scenario_id"],
            name=r["name"],
            description=r["description"],
            expected_behavior=r["expected_behavior"],
            mitre_technique_id=r["mitre_technique_id"],
            mitre_tactic=r["mitre_tactic"],
            category=r["category"]
        ) for r in rows
    ]

def save_telemetry_events(events: List[TelemetryEvent]) -> None:
    conn = get_connection()
    for ev in events:
        raw_json = json.dumps(ev.raw_event) if ev.raw_event else "{}"
        conn.execute("""
        INSERT OR REPLACE INTO telemetry_events (
            event_id, timestamp, computer, image, command_line, parent_image, parent_command_line,
            user, process_id, parent_process_id, original_file_name, current_directory,
            is_attack, scenario_id, source, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            ev.event_id, ev.timestamp, ev.computer, ev.image, ev.command_line, ev.parent_image, ev.parent_command_line,
            ev.user, ev.process_id, ev.parent_process_id, ev.original_file_name, ev.current_directory,
            1 if ev.is_attack else 0, ev.scenario_id, ev.source, raw_json
        ))
    conn.commit()
    conn.close()

def get_telemetry_events(is_attack: Optional[bool] = None, scenario_id: Optional[str] = None) -> List[TelemetryEvent]:
    conn = get_connection()
    query = "SELECT * FROM telemetry_events WHERE 1=1"
    params = []
    if is_attack is not None:
        query += " AND is_attack = ?"
        params.append(1 if is_attack else 0)
    if scenario_id:
        query += " AND scenario_id = ?"
        params.append(scenario_id)
    query += " ORDER BY event_id ASC;"
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    events = []
    for r in rows:
        raw_data = json.loads(r["raw_json"]) if r["raw_json"] else {}
        events.append(TelemetryEvent(
            event_id=r["event_id"],
            timestamp=r["timestamp"],
            computer=r["computer"],
            image=r["image"],
            command_line=r["command_line"],
            parent_image=r["parent_image"],
            parent_command_line=r["parent_command_line"],
            user=r["user"],
            process_id=r["process_id"],
            parent_process_id=r["parent_process_id"],
            original_file_name=r["original_file_name"],
            current_directory=r["current_directory"],
            is_attack=bool(r["is_attack"]),
            scenario_id=r["scenario_id"],
            source=r["source"],
            raw_event=raw_data
        ))
    return events

def save_evaluation_run(
    rule: SigmaRule,
    metrics: EvaluationMetrics,
    event_results: List[EventEvaluationResult]
) -> str:
    conn = get_connection()
    run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
    conn.execute("""
    INSERT INTO evaluation_runs (
        run_id, rule_id, rule_title, rule_version, total_scenarios, detected_scenarios,
        missed_scenarios, detection_rate, false_positives, false_positive_rate,
        precision, recall, f1_score, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));
    """, (
        run_id, rule.id, rule.title, rule.version, metrics.total_attack_scenarios, metrics.detected_attack_scenarios,
        metrics.missed_attack_scenarios, metrics.detection_rate, metrics.false_positives, metrics.false_positive_rate,
        metrics.precision, metrics.recall, metrics.f1_score
    ))

    for ev in event_results:
        res_id = str(uuid.uuid4())
        conn.execute("""
        INSERT INTO detection_results (
            id, run_id, event_id, scenario_id, is_attack, detected, matching_fields, non_matching_fields, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            res_id, run_id, ev.event_id, ev.scenario_id, 1 if ev.is_attack else 0,
            1 if ev.detected else 0, json.dumps(ev.matching_fields), json.dumps(ev.non_matching_fields), ev.reason
        ))

    conn.commit()
    conn.close()
    return run_id

def get_evaluation_runs(rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    if rule_id:
        rows = conn.execute("SELECT * FROM evaluation_runs WHERE rule_id = ? ORDER BY created_at DESC;", (rule_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM evaluation_runs ORDER BY created_at DESC;").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def save_hardening_proposal(proposal: HardeningProposal) -> None:
    conn = get_connection()
    conn.execute("""
    INSERT OR REPLACE INTO hardening_proposals (
        proposal_id, original_rule_id, improved_rule_id, rule_title, original_yaml,
        improved_yaml, diff, modification_reasons, addressed_scenarios,
        orig_detection_rate, imp_detection_rate, false_positive_impact,
        passed_guardrail, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        proposal.proposal_id, proposal.original_rule_id, proposal.improved_rule_id, proposal.rule_title,
        proposal.original_yaml, proposal.improved_yaml, proposal.diff,
        json.dumps(proposal.modification_reasons), json.dumps(proposal.addressed_scenarios),
        proposal.original_metrics.detection_rate, proposal.improved_metrics.detection_rate,
        proposal.false_positive_impact, 1 if proposal.passed_guardrail else 0, proposal.status, proposal.created_at
    ))
    conn.commit()
    conn.close()

def get_hardening_proposals(rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    if rule_id:
        rows = conn.execute("SELECT * FROM hardening_proposals WHERE original_rule_id = ? ORDER BY created_at DESC;", (rule_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM hardening_proposals ORDER BY created_at DESC;").fetchall()
    conn.close()
    proposals = []
    for r in rows:
        d = dict(r)
        d["modification_reasons"] = json.loads(d["modification_reasons"]) if d["modification_reasons"] else []
        d["addressed_scenarios"] = json.loads(d["addressed_scenarios"]) if d["addressed_scenarios"] else []
        d["passed_guardrail"] = bool(d["passed_guardrail"])
        proposals.append(d)
    return proposals

def save_report(report_id: str, title: str, content: str, run_id: Optional[str] = None, report_type: str = "audit", fmt: str = "json") -> None:
    conn = get_connection()
    conn.execute("""
    INSERT OR REPLACE INTO reports (report_id, title, run_id, report_type, format, content, created_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'));
    """, (report_id, title, run_id, report_type, fmt, content))
    conn.commit()
    conn.close()

def get_reports() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute("SELECT report_id, title, run_id, report_type, format, created_at FROM reports ORDER BY created_at DESC;").fetchall()
    conn.close()
    return [dict(r) for r in rows]
