"""
Pydantic Data Models for RuleHardener
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class SigmaRule(BaseModel):
    id: str
    title: str
    status: Optional[str] = "experimental"
    description: Optional[str] = ""
    author: Optional[str] = ""
    date: Optional[str] = ""
    logsource: Dict[str, Any] = Field(default_factory=dict)
    detection: Dict[str, Any] = Field(default_factory=dict)
    condition: str = ""
    tags: List[str] = Field(default_factory=list)
    level: Optional[str] = "medium"
    falsepositives: List[str] = Field(default_factory=list)
    raw_yaml: str
    version: int = 1
    parent_rule_id: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class AttackScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    expected_behavior: str
    mitre_technique_id: str = "T1059.001"
    mitre_tactic: str = "Execution"
    process_fields: Dict[str, Any] = Field(default_factory=dict)
    expected_detection_original: bool = True
    category: str = "attack"  # "attack" or "benign"

class TelemetryEvent(BaseModel):
    event_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    computer: str = "WIN-SRV-01"
    image: str
    command_line: str
    parent_image: Optional[str] = ""
    parent_command_line: Optional[str] = ""
    user: str = "NT AUTHORITY\\SYSTEM"
    process_id: int = 1234
    parent_process_id: int = 4321
    original_file_name: Optional[str] = ""
    current_directory: Optional[str] = "C:\\Windows\\System32"
    hashes: Optional[Dict[str, str]] = Field(default_factory=dict)
    is_attack: bool = True
    scenario_id: str
    source: str = "synthetic"  # "synthetic" or "imported"
    raw_event: Optional[Dict[str, Any]] = Field(default_factory=dict)

class EventEvaluationResult(BaseModel):
    event_id: str
    scenario_id: str
    rule_id: str
    is_attack: bool
    detected: bool
    matching_fields: Dict[str, Any] = Field(default_factory=dict)
    non_matching_fields: Dict[str, Any] = Field(default_factory=dict)
    reason: str = ""

class ScenarioEvaluation(BaseModel):
    scenario_id: str
    scenario_name: str
    is_attack: bool
    total_events: int
    detected_events: int
    detected: bool
    mitre_technique_id: str = ""

class EvaluationMetrics(BaseModel):
    total_attack_scenarios: int = 0
    detected_attack_scenarios: int = 0
    missed_attack_scenarios: int = 0
    total_benign_events: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

class HardeningProposal(BaseModel):
    proposal_id: str
    original_rule_id: str
    improved_rule_id: str
    rule_title: str
    original_yaml: str
    improved_yaml: str
    diff: str
    modification_reasons: List[str] = Field(default_factory=list)
    addressed_scenarios: List[str] = Field(default_factory=list)
    original_metrics: EvaluationMetrics
    improved_metrics: EvaluationMetrics
    false_positive_impact: int = 0
    passed_guardrail: bool = True
    status: str = "proposed"  # "proposed", "approved", "rejected"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
