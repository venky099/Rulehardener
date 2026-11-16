# RuleHardener User Guide

This guide walks through using the RuleHardener platform to test and harden Sigma detection rules.

---

## 1. Launching the Platform

In PowerShell:
```powershell
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 2. Navigating the 7 Dashboard Pages

### 1. 🏠 Overview
- View platform health, total rules, attack scenarios, and benign events.
- Check the latest Detection Rate and False Positive Rate.
- Click **"Run Immediate Test Suite"** for a quick one-click benchmark.

### 2. 📜 Sigma Rule Manager
- **Active Rule Inspector**: Review metadata, level, MITRE tags, target fields, and raw YAML for the selected rule.
- **Upload / Import New Rule**: Paste custom Sigma YAML or upload `.yml`/`.yaml` files. The platform performs real-time structural and condition validation before saving.

### 3. 🎯 Attack Scenarios
- Explore the pre-seeded library of 8 attack scenarios (PowerShell encoded commands, abbreviations `-enc`, minimal flags `-e`, PowerShell Core `pwsh.exe`, download cradles, slash notation `/enc`, execution policy bypasses) and 12 benign baseline scenarios (admin maintenance, SCCM, VS Code, disk cleanup, etc.).
- Inspect target process command lines and expected detection status.

### 4. 🔍 Telemetry Explorer
- Search and filter process creation events by event ID, image name, or command-line strings.
- Toggle between attack and benign datasets.
- Upload custom JSONL process telemetry for proprietary testing.

### 5. ⚡ Detection Results
- Click **"Execute Deterministic Rule Evaluation"** to run the active rule against all telemetry.
- Inspect the interactive **Confusion Matrix** (True Positives, False Positives, False Negatives, True Negatives).
- View overall Detection Rate, Precision, Recall, and F1 Score.
- Review scenario-by-scenario coverage status (`DETECTED` vs `MISSED`).

### 6. 🛡️ Rule Hardening
- Click **"Trigger Deterministic Rule Hardening"**.
- The engine isolates missed attack conditions, expands command-line abbreviations, aliases binaries, adds download cradle detection, and synthesizes benign filters.
- Review the **FP Guardrail Status** (ensuring 0 new false positives).
- Compare the original and hardened rules side-by-side and review the unified YAML diff.
- Click **"Approve & Promote Hardened Rule"** to increment the rule version and save it to SQLite.

### 7. 📊 Reports & Exports
- Export evaluation reports in multiple formats:
  - **JSON Audit Report**: Machine-readable audit file.
  - **CSV Performance Metrics**: Tabular format for spreadsheet analysis.
  - **Printable HTML/PDF Audit**: Formatted report ready for printing or executive presentation.
