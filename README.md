# RuleHardener — Sigma Detection Rule Testing & Hardening Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-red.svg)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-46%20Passed-brightgreen.svg)]()

**RuleHardener** is a 100% offline, deterministic cybersecurity platform that evaluates existing Sigma detection rules against controlled attack and benign telemetry datasets. It identifies detection blind spots, deterministically proposes hardened rule improvements, and verifies that proposed modifications increase true positive coverage without introducing false positives.

---

## 🎯 Key Capabilities

- **Deterministic Sigma Evaluator**: Direct in-memory condition AST parser supporting `and`, `or`, `not`, nested parentheses, `1 of selection*`, and modifiers (`contains`, `startswith`, `endswith`, `re`, `windash`, `all`).
- **Pre-Seeded Scenario Library**: Out-of-the-box support for PowerShell execution testing with 8 attack scenarios (encoded commands, flag abbreviations, PowerShell Core `pwsh.exe`, download cradles, bypasses) and 12 benign administration baselines (SCCM, VS Code, Task Scheduler, etc.).
- **False-Positive Guardrail**: Automated gatekeeper that rejects candidate rule modifications if they increase benign false positives, safeguarding SOC analysts from alert fatigue.
- **Rule Lifecycle & Version Control**: SQLite persistence tracks rule version lineage, rollback capabilities, and visual unified YAML diffs.
- **Audit-Ready Reporting**: Export comprehensive test runs and hardening audits in JSON, CSV, and printable HTML/PDF formats.
- **No LLM / Cloud Dependencies**: 100% deterministic, offline, and reproducible execution.

---

## 🏗️ Project Architecture

```
RuleHardener/
├── app.py                      # Multi-page Streamlit Dashboard
├── requirements.txt            # Project dependencies
├── pytest.ini                  # Pytest configuration
├── backend/
│   ├── config.py               # Path constants & configuration
│   ├── database.py             # SQLite persistence & CRUD operations
│   ├── models.py               # Pydantic data schemas
│   ├── rule_manager/           # Sigma loader, validator & analyzer
│   ├── telemetry/              # Event normalizer, synthetic generator & loader
│   ├── detection/              # AST condition parser, matcher & metrics
│   ├── hardening/              # Gap analyzer, rule optimizer & comparator
│   └── utils/                  # Logging and security validators
├── data/
│   ├── rules/                  # Sigma YAML rules
│   ├── attack_scenarios/       # Attack and benign scenario metadata
│   ├── attack_telemetry/       # Synthetic attack telemetry (JSONL)
│   ├── benign_telemetry/       # Synthetic benign baseline telemetry (JSONL)
│   ├── database/               # SQLite database file (rulehardener.db)
│   └── reports/                # Exported audit reports
├── docs/
│   ├── architecture.md         # Detailed architectural documentation
│   └── usage.md                # Comprehensive user guide
└── tests/                      # Automated unit and integration test suite
```

---

## 🚀 Setup & Installation (Windows PowerShell)

### Prerequisites
- Python 3.11 or higher
- Windows PowerShell

### 1. Clone or Open Workspace
```powershell
cd C:\Users\DELL\projects\rulehardner
```

### 2. (Optional) Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

---

## 🧪 Running Automated Tests

Run the complete test suite covering Sigma validation, condition parsing, modifier matching, detection evaluation, hardening algorithms, metrics, ReDoS protection, regression gates, and SQLite persistence:

```powershell
python -m pytest
```

Expected output:
```text
============================= 46 passed in 1.45s ==============================
```

---

## 🖥️ Launching the Streamlit Application

Start the web dashboard:
```powershell
streamlit run app.py
```
Open your browser and navigate to `http://localhost:8501`.

---

## 📖 Step-by-Step Workflow

1. **Sigma Rule Manager**: Inspect the baseline rule (`Suspicious PowerShell Execution`). View target fields (`Image`, `CommandLine`) and detection logic.
2. **Detection Results**: Click **"Execute Deterministic Rule Evaluation"**. Notice that the baseline rule achieves only a **12.5% Detection Rate** because it only catches exact `EncodedCommand` syntax, completely missing variations like `-enc`, `-e`, `/enc`, `pwsh.exe`, and download cradles.
3. **Rule Hardening**: Click **"Trigger Deterministic Rule Hardening"**. The engine analyzes detection gaps, expands CLI parameter variants, adds PowerShell Core support, synthesizes download cradle detection, and generates an enterprise exclusion filter (`filter_sccm`).
4. **Guardrail Verification**: The FP Guardrail verifies that the hardened rule achieves a **100% Detection Rate** with **0 False Positives**.
5. **Approve & Save**: Click **"Approve & Promote Hardened Rule"** to save Version 2 into SQLite.
6. **Reports & Exports**: Navigate to Reports to download audit data in JSON, CSV, or formatted printable HTML/PDF.

---

## 🔒 Security Principles

- **Safe YAML Parsing**: Employs `yaml.safe_load` exclusively.
- **Path Traversal Protection**: All file paths are strictly validated against base directory boundaries.
- **No Remote Execution**: Telemetry events are static mock fixtures; commands are never executed on the host system.
- **No External Network Calls**: Operates 100% offline without telemetry phone-home or third-party API dependencies.

---

## 📜 Documentation
- [System Architecture](file:///C:/Users/DELL/projects/rulehardner/docs/architecture.md)
- [User Walkthrough Guide](file:///C:/Users/DELL/projects/rulehardner/docs/usage.md)
