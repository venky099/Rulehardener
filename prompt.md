# PROJECT: RuleHardener
## Offline MVP — Sigma Detection Rule Testing & Hardening Platform

Act as a senior Python developer, cybersecurity detection engineer, and software architect.

Your task is to BUILD a complete, functional offline MVP of a cybersecurity project called **RuleHardener**.

Do not just explain the implementation or generate a project plan. Create the actual files, write the code, run the application, execute tests, identify errors, and fix them.

Work directly inside the current project directory.

---

# 1. PROJECT OBJECTIVE

RuleHardener is a defensive cybersecurity platform that evaluates existing Sigma detection rules against controlled attack and benign telemetry datasets.

It identifies detection gaps, proposes rule improvements, and compares the performance of the original and improved rules.

The main objective is:

**Identify weaknesses in existing Sigma detection rules and measure whether proposed improvements actually increase detection coverage without introducing unnecessary false positives.**

Core principle:

AI can propose improvements in a future version, but deterministic code must evaluate whether those improvements work.

For this MVP, use deterministic rule-hardening logic. Do not integrate AI yet.

---

# 2. MVP SCOPE

Build the following six core modules:

1. Sigma Rule Manager
2. Attack Scenario Library
3. Synthetic Telemetry Engine
4. Sigma Detection Evaluation Engine
5. Rule Hardening Engine
6. Streamlit Dashboard

Everything must work locally.

Do not integrate:

- Ollama
- OpenAI API
- Gemini API
- Atomic Red Team
- Sysmon
- Chainsaw
- Cloud services
- Paid services

These integrations will be added in future versions.

---

# 3. TECHNOLOGY STACK

Use:

- Python 3.11+
- Streamlit
- SQLite
- PyYAML
- pySigma
- Pandas
- Plotly
- Pydantic
- Pytest

Use simple and maintainable Python architecture.

Avoid unnecessary dependencies.

---

# 4. PROJECT STRUCTURE

Create this structure:

RuleHardener/
│
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
├── backend/
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   │
│   ├── rule_manager/
│   │   ├── sigma_loader.py
│   │   ├── sigma_validator.py
│   │   └── rule_analyzer.py
│   │
│   ├── telemetry/
│   │   ├── synthetic_generator.py
│   │   ├── log_loader.py
│   │   └── event_normalizer.py
│   │
│   ├── detection/
│   │   ├── sigma_matcher.py
│   │   ├── detection_evaluator.py
│   │   └── metrics.py
│   │
│   ├── hardening/
│   │   ├── gap_analyzer.py
│   │   ├── rule_optimizer.py
│   │   └── rule_comparator.py
│   │
│   └── utils/
│       ├── logger.py
│       └── validators.py
│
├── data/
│   ├── rules/
│   ├── attack_scenarios/
│   ├── attack_telemetry/
│   ├── benign_telemetry/
│   ├── reports/
│   └── database/
│
├── tests/
│   ├── test_sigma_validation.py
│   ├── test_sigma_matching.py
│   ├── test_detection_evaluator.py
│   ├── test_hardening.py
│   ├── test_metrics.py
│   └── test_database.py
│
└── docs/
    ├── architecture.md
    └── usage.md

You may improve the architecture if required, but preserve modular separation.

---

# 5. MODULE 1: SIGMA RULE MANAGER

Build a module that allows users to:

- Upload Sigma YAML rules.
- Import example Sigma rules.
- Parse Sigma metadata.
- Display rule title.
- Display rule description.
- Display rule ID.
- Display status.
- Display log source.
- Display ATT&CK tags.
- Display detection selections.
- Display detection conditions.
- Validate Sigma YAML.
- Identify invalid YAML.
- Identify missing required metadata.
- Identify malformed detection logic.
- Save imported rules in SQLite.

Use safe YAML loading.

Do not accept malformed rules as valid.

Include at least one working example Sigma rule for PowerShell process creation.

Example rule:

title: Suspicious PowerShell Execution
id: 8c7b1e12-1111-4444-8888-123456789abc
status: experimental
description: Detects suspicious PowerShell command-line activity.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'EncodedCommand'
  condition: selection
level: medium

Use this as a starting example, not as a universal production detection rule.

---

# 6. MODULE 2: ATTACK SCENARIO LIBRARY

Create a predefined library of safe, synthetic attack scenarios.

Initially support PowerShell process execution detection.

Create at least five attack scenarios:

1. Standard PowerShell execution.
2. PowerShell with encoded-command argument.
3. PowerShell with different command-line formatting.
4. PowerShell launched through an alternative parent process.
5. PowerShell with a different suspicious argument pattern.

Each scenario must contain:

- Scenario ID.
- Scenario name.
- Description.
- Expected behavior.
- Relevant process fields.
- Expected detection status against the original rule.
- MITRE ATT&CK mapping where appropriate.

Also create at least ten benign scenarios:

- Normal PowerShell administration.
- System maintenance.
- Software installation.
- Routine scripts.
- Administrative command execution.

All datasets must be clearly labelled synthetic.

Do not execute actual attack commands.

These scenarios are telemetry fixtures only.

---

# 7. MODULE 3: SYNTHETIC TELEMETRY ENGINE

Create realistic synthetic Windows process-creation events.

Support fields such as:

- EventID
- Computer
- Image
- CommandLine
- ParentImage
- ParentCommandLine
- User
- ProcessId
- ParentProcessId
- Timestamp
- Hashes where applicable

Create separate attack and benign datasets.

Requirements:

- Store fixtures in JSON or JSONL.
- Allow users to upload JSONL telemetry.
- Validate uploaded fields.
- Normalize field names.
- Preserve original events.
- Label each event as attack or benign.
- Record its associated scenario ID.
- Do not generate random or fabricated evaluation results.

The source of every event must be identifiable as synthetic or imported.

---

# 8. MODULE 4: SIGMA DETECTION EVALUATION ENGINE

This is the most important component.

Implement an actual deterministic evaluator for a clearly documented subset of Sigma detection semantics.

Support:

- Exact field matching.
- Case-insensitive matching where required.
- Contains.
- Startswith.
- Endswith.
- AND conditions.
- OR conditions.
- NOT conditions.
- Multiple detection selections.
- Field modifiers.

Use pySigma for parsing and structural validation where appropriate.

Important:

Parsing a Sigma rule is not the same as evaluating it against telemetry.

Implement the actual matching logic.

Create a clear rule-to-event evaluation pipeline.

For every event, return:

- Event ID.
- Scenario ID.
- Rule ID.
- Detection status.
- Matching fields.
- Non-matching fields.
- Reason for match or failure.

The engine must be deterministic.

The same rule and event must always produce the same result.

Do not use an LLM to calculate results.

Do not hardcode detection percentages.

---

# 9. MODULE 5: DETECTION METRICS

Calculate:

- Total attack scenarios.
- Detected attack scenarios.
- Missed attack scenarios.
- True positives.
- False negatives.
- False positives.
- True negatives.
- Detection rate.
- False-positive rate.
- Precision.
- Recall.
- F1 score.

Use these formulas:

Detection Rate = Detected Attack Scenarios / Total Attack Scenarios × 100

False Positive Rate = False Positives / Total Benign Events × 100

Precision = TP / (TP + FP)

Recall = TP / (TP + FN)

F1 = 2 × (Precision × Recall) / (Precision + Recall)

Handle division by zero correctly.

Important:

Evaluate detection coverage at the scenario level, not just the event level.

For benign telemetry, count an event as a false positive only when the rule matches it.

Clearly explain the difference between event-level and scenario-level metrics.

Never claim a detection improvement unless the evaluator confirms it.

---

# 10. MODULE 6: RULE HARDENING ENGINE

Implement a deterministic rule improvement engine.

This module should:

1. Receive the original Sigma rule.
2. Receive missed attack scenarios.
3. Inspect their telemetry fields.
4. Identify which conditions caused detection failures.
5. Suggest possible modifications.
6. Generate an improved Sigma YAML rule.
7. Validate the improved rule.
8. Preserve the original rule.
9. Save the new rule as a separate version.

Example:

Original rule:

Image|endswith: '\powershell.exe'
CommandLine|contains: 'EncodedCommand'

Suppose a synthetic attack event is missed because it uses a different suspicious command-line argument.

The hardening engine should identify the missing condition and propose an appropriate alternative.

Important requirements:

- Do not blindly add every missed event to the detection rule.
- Do not weaken the original rule unnecessarily.
- Do not include benign patterns in the improved rule.
- Do not hardcode a 100% detection result.
- Validate every modification.
- Evaluate the improved rule against both attack and benign telemetry.
- Reject changes that introduce unacceptable false positives.
- Explain every proposed change.

Store:

- Original rule.
- Improved rule.
- Modification reason.
- Missed scenarios addressed.
- New detection metrics.
- False-positive impact.
- Validation status.

If no safe improvement is possible, report that honestly.

---

# 11. MODULE 7: STREAMLIT DASHBOARD

Build a professional cybersecurity dashboard.

Design:

- Dark theme.
- Clean navigation.
- Modern cards.
- Clear charts.
- Consistent typography.
- Responsive layout.

Create these pages:

### PAGE 1: OVERVIEW

Display:

- Total Sigma rules.
- Total attack scenarios.
- Total benign events.
- Detection rate.
- False-positive rate.
- Number of missed scenarios.
- Recent evaluation activity.

### PAGE 2: SIGMA RULE MANAGER

Allow users to:

- Upload Sigma rules.
- View existing rules.
- Inspect rule metadata.
- Validate YAML.
- View detection conditions.
- Select a rule for evaluation.

### PAGE 3: ATTACK SCENARIOS

Display:

- Scenario name.
- Scenario description.
- MITRE technique.
- Expected behavior.
- Associated synthetic telemetry.
- Test status.

### PAGE 4: TELEMETRY EXPLORER

Display:

- Imported events.
- Synthetic attack events.
- Benign events.
- Event fields.
- Process names.
- Command lines.
- Scenario IDs.

Include search and filtering.

### PAGE 5: DETECTION RESULTS

Display:

- Detected scenarios.
- Missed scenarios.
- False positives.
- True positives.
- Detection rate.
- False-positive rate.
- Precision.
- Recall.
- F1 score.

Include a confusion matrix and suitable visualizations.

### PAGE 6: RULE HARDENING

Display:

- Original Sigma rule.
- Identified detection gaps.
- Suggested modifications.
- Improved Sigma rule.
- Side-by-side comparison.
- Original metrics.
- Improved metrics.
- Validation results.

Allow users to approve or reject the proposed improved rule.

### PAGE 7: REPORTS

Allow users to export:

- JSON.
- CSV.
- PDF if practical.

Include:

- Rule metadata.
- Dataset details.
- Original detection results.
- Missed scenarios.
- Hardening suggestions.
- Improved detection results.
- False-positive impact.
- Limitations.
- Evaluation timestamp.

Every dashboard button must perform its stated function.

Do not create decorative buttons with no implementation.

---

# 12. SQLITE DATABASE

Use SQLite for persistence.

Create tables for:

- Sigma rules.
- Rule versions.
- Attack scenarios.
- Telemetry events or telemetry references.
- Evaluation runs.
- Detection results.
- Hardening suggestions.
- Reports.

Use proper primary keys, foreign keys and timestamps.

The application must retain data after restarting.

---

# 13. TESTING

Use pytest.

Create automated tests for:

1. Valid Sigma YAML.
2. Invalid Sigma YAML.
3. Missing metadata.
4. Exact field matching.
5. Contains matching.
6. Startswith matching.
7. Endswith matching.
8. AND conditions.
9. OR conditions.
10. NOT conditions.
11. Successful detections.
12. Missed detections.
13. False positives.
14. Metric calculations.
15. Improved rule validation.
16. Rule version persistence.
17. Database operations.
18. Malformed telemetry.
19. Empty datasets.
20. Benign event handling.

All supported Sigma semantics must have dedicated unit tests.

Fix failures before considering the MVP complete.

---

# 14. SECURITY REQUIREMENTS

Follow secure development practices:

- Use safe YAML parsing.
- Validate uploaded files.
- Restrict upload size.
- Prevent path traversal.
- Avoid eval() and exec().
- Treat imported telemetry as untrusted input.
- Sanitize dashboard output.
- Do not execute uploaded scripts.
- Do not execute attack commands.
- Do not expose secrets.
- Handle exceptions safely.

This MVP must not execute real attack simulations.

---

# 15. DEVELOPMENT WORKFLOW

Follow these phases in order.

PHASE 1 — Inspect the environment and initialize the project.

PHASE 2 — Build Sigma rule loading and validation.

PHASE 3 — Create synthetic attack and benign telemetry.

PHASE 4 — Implement the deterministic Sigma evaluator.

PHASE 5 — Implement metrics calculation.

PHASE 6 — Implement the rule hardening engine.

PHASE 7 — Implement SQLite persistence.

PHASE 8 — Build the Streamlit dashboard.

PHASE 9 — Integrate all modules.

PHASE 10 — Run automated tests and fix bugs.

PHASE 11 — Write complete documentation.

Do not skip phases.

At the end of each phase, report:

- Files created or modified.
- Features completed.
- Commands executed.
- Tests passed.
- Tests failed.
- Remaining issues.

---

# 16. FINAL ACCEPTANCE CRITERIA

The MVP is complete only when:

1. The application launches locally.
2. Users can import Sigma YAML files.
3. Sigma rules are validated.
4. Synthetic attack and benign datasets load correctly.
5. Detection evaluation works deterministically.
6. Missed detections are identified.
7. False positives are measured.
8. Detection metrics are correct.
9. The hardening engine proposes actual rule changes.
10. Improved rules are validated.
11. Original and improved rules are evaluated against the same datasets.
12. Results are persisted in SQLite.
13. The dashboard displays real evaluation results.
14. Users can export reports.
15. Automated tests pass.
16. The README contains complete Windows setup instructions.

Do not report a feature as complete unless it has been implemented and tested.

If something cannot be implemented correctly, explain the limitation instead of faking functionality.

---

# 17. START DEVELOPMENT

Begin by inspecting the current directory and installed Python environment.

Then:

1. Create the project structure.
2. Create requirements.txt.
3. Set up the database.
4. Implement the modules in the specified order.
5. Run tests after each major module.
6. Start the Streamlit application.
7. Verify the complete workflow.

Your final deliverable must be a working offline cybersecurity MVP, not just a prototype dashboard.

**Start building RuleHardener now.**