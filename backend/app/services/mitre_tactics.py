"""MITRE ATT&CK Enterprise: technique -> tactics, in the order ATT&CK lists them.

Used to place findings in an incident phase from the techniques the analyst
tagged. Sub-techniques (T1059.001) take their parent's tactics. The table
covers the techniques most seen in endpoint investigations on Windows, Linux
and macOS; an unlisted technique simply yields no phase, never a wrong one.
"""

from __future__ import annotations

import re
from collections import Counter

# Tactic names follow the incident-phase vocabulary (snake_case ATT&CK tactics).
TECHNIQUE_TACTICS: dict[str, tuple[str, ...]] = {
    # Initial access
    "T1078": ("defense_evasion", "persistence", "privilege_escalation", "initial_access"),
    "T1133": ("persistence", "initial_access"),
    "T1189": ("initial_access",),
    "T1190": ("initial_access",),
    "T1195": ("initial_access",),
    "T1199": ("initial_access",),
    "T1200": ("initial_access",),
    "T1566": ("initial_access",),
    "T1091": ("lateral_movement", "initial_access"),
    # Execution
    "T1047": ("execution",),
    "T1053": ("execution", "persistence", "privilege_escalation"),
    "T1059": ("execution",),
    "T1106": ("execution",),
    "T1129": ("execution",),
    "T1203": ("execution",),
    "T1204": ("execution",),
    "T1559": ("execution",),
    "T1569": ("execution",),
    "T1609": ("execution",),
    "T1610": ("defense_evasion", "execution"),
    "T1072": ("execution", "lateral_movement"),
    # Persistence / privilege escalation
    "T1037": ("persistence", "privilege_escalation"),
    "T1098": ("persistence", "privilege_escalation"),
    "T1136": ("persistence",),
    "T1137": ("persistence",),
    "T1176": ("persistence",),
    "T1197": ("defense_evasion", "persistence"),
    "T1505": ("persistence",),
    "T1543": ("persistence", "privilege_escalation"),
    "T1546": ("privilege_escalation", "persistence"),
    "T1547": ("persistence", "privilege_escalation"),
    "T1554": ("persistence",),
    "T1556": ("credential_access", "defense_evasion", "persistence"),
    "T1574": ("persistence", "privilege_escalation", "defense_evasion"),
    "T1068": ("privilege_escalation",),
    "T1134": ("defense_evasion", "privilege_escalation"),
    "T1484": ("defense_evasion", "privilege_escalation"),
    "T1548": ("privilege_escalation", "defense_evasion"),
    "T1055": ("defense_evasion", "privilege_escalation"),
    # Defense evasion
    "T1027": ("defense_evasion",),
    "T1036": ("defense_evasion",),
    "T1070": ("defense_evasion",),
    "T1112": ("defense_evasion",),
    "T1127": ("defense_evasion",),
    "T1140": ("defense_evasion",),
    "T1202": ("defense_evasion",),
    "T1218": ("defense_evasion",),
    "T1220": ("defense_evasion",),
    "T1222": ("defense_evasion",),
    "T1480": ("defense_evasion",),
    "T1497": ("defense_evasion", "discovery"),
    "T1553": ("defense_evasion",),
    "T1562": ("defense_evasion",),
    "T1564": ("defense_evasion",),
    "T1620": ("defense_evasion",),
    # Credential access
    "T1003": ("credential_access",),
    "T1040": ("credential_access", "discovery"),
    "T1110": ("credential_access",),
    "T1111": ("credential_access",),
    "T1212": ("credential_access",),
    "T1552": ("credential_access",),
    "T1555": ("credential_access",),
    "T1557": ("credential_access", "collection"),
    "T1558": ("credential_access",),
    "T1539": ("credential_access",),
    "T1606": ("credential_access",),
    # Discovery
    "T1007": ("discovery",),
    "T1010": ("discovery",),
    "T1012": ("discovery",),
    "T1016": ("discovery",),
    "T1018": ("discovery",),
    "T1033": ("discovery",),
    "T1046": ("discovery",),
    "T1049": ("discovery",),
    "T1057": ("discovery",),
    "T1069": ("discovery",),
    "T1082": ("discovery",),
    "T1083": ("discovery",),
    "T1087": ("discovery",),
    "T1124": ("discovery",),
    "T1135": ("discovery",),
    "T1201": ("discovery",),
    "T1217": ("discovery",),
    "T1482": ("discovery",),
    "T1518": ("discovery",),
    "T1614": ("discovery",),
    # Lateral movement
    "T1021": ("lateral_movement",),
    "T1080": ("lateral_movement",),
    "T1210": ("lateral_movement",),
    "T1534": ("lateral_movement",),
    "T1550": ("defense_evasion", "lateral_movement"),
    "T1563": ("lateral_movement",),
    "T1570": ("lateral_movement",),
    # Collection
    "T1005": ("collection",),
    "T1039": ("collection",),
    "T1025": ("collection",),
    "T1056": ("collection", "credential_access"),
    "T1074": ("collection",),
    "T1113": ("collection",),
    "T1114": ("collection",),
    "T1115": ("collection",),
    "T1119": ("collection",),
    "T1123": ("collection",),
    "T1125": ("collection",),
    "T1213": ("collection",),
    "T1560": ("collection",),
    # Command and control
    "T1071": ("command_and_control",),
    "T1090": ("command_and_control",),
    "T1095": ("command_and_control",),
    "T1102": ("command_and_control",),
    "T1105": ("command_and_control",),
    "T1132": ("command_and_control",),
    "T1219": ("command_and_control",),
    "T1571": ("command_and_control",),
    "T1572": ("command_and_control",),
    "T1573": ("command_and_control",),
    # Exfiltration
    "T1011": ("exfiltration",),
    "T1020": ("exfiltration",),
    "T1029": ("exfiltration",),
    "T1030": ("exfiltration",),
    "T1041": ("exfiltration",),
    "T1048": ("exfiltration",),
    "T1052": ("exfiltration",),
    "T1537": ("exfiltration",),
    "T1567": ("exfiltration",),
    # Impact
    "T1485": ("impact",),
    "T1486": ("impact",),
    "T1489": ("impact",),
    "T1490": ("impact",),
    "T1491": ("impact",),
    "T1496": ("impact",),
    "T1529": ("impact",),
    "T1531": ("impact",),
    "T1561": ("impact",),
    "T1565": ("impact",),
}

_TECHNIQUE_ID = re.compile(r"\bT(\d{4})(?:\.\d{3})?\b", re.IGNORECASE)


def technique_ids(values: list[str] | None) -> list[str]:
    """Parent technique IDs found in free-form MITRE tags, in order."""
    found: list[str] = []
    for value in values or []:
        for match in _TECHNIQUE_ID.finditer(str(value)):
            technique = f"T{match.group(1)}"
            if technique not in found:
                found.append(technique)
    return found


def primary_tactic(values: list[str] | None) -> str | None:
    """Incident phase for a set of MITRE tags.

    The first tagged technique is taken as the finding's main one (analysts and
    detectors list it first). When that technique spans several tactics, the
    tactic the other techniques also support wins; a remaining tie keeps
    ATT&CK's order for the main technique.
    """
    techniques = [technique for technique in technique_ids(values) if technique in TECHNIQUE_TACTICS]
    if not techniques:
        return None
    main = TECHNIQUE_TACTICS[techniques[0]]
    if len(main) == 1:
        return main[0]
    support = Counter(tactic for technique in techniques[1:] for tactic in TECHNIQUE_TACTICS[technique])
    return max(main, key=lambda tactic: (support[tactic], -main.index(tactic)))

TECHNIQUE_NAMES: dict[str, str] = {
    "T1078": "Valid Accounts", "T1133": "External Remote Services", "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application", "T1195": "Supply Chain Compromise", "T1199": "Trusted Relationship",
    "T1200": "Hardware Additions", "T1566": "Phishing", "T1091": "Replication Through Removable Media",
    "T1047": "Windows Management Instrumentation", "T1053": "Scheduled Task/Job", "T1059": "Command and Scripting Interpreter",
    "T1106": "Native API", "T1129": "Shared Modules", "T1203": "Exploitation for Client Execution", "T1204": "User Execution",
    "T1559": "Inter-Process Communication", "T1569": "System Services", "T1609": "Container Administration Command",
    "T1610": "Deploy Container", "T1072": "Software Deployment Tools", "T1037": "Boot or Logon Initialization Scripts",
    "T1098": "Account Manipulation", "T1136": "Create Account", "T1137": "Office Application Startup",
    "T1176": "Browser Extensions", "T1197": "BITS Jobs", "T1505": "Server Software Component",
    "T1543": "Create or Modify System Process", "T1546": "Event Triggered Execution", "T1547": "Boot or Logon Autostart Execution",
    "T1554": "Compromise Host Software Binary", "T1556": "Modify Authentication Process", "T1574": "Hijack Execution Flow",
    "T1068": "Exploitation for Privilege Escalation", "T1134": "Access Token Manipulation", "T1484": "Domain or Tenant Policy Modification",
    "T1548": "Abuse Elevation Control Mechanism", "T1055": "Process Injection", "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading", "T1070": "Indicator Removal", "T1112": "Modify Registry",
    "T1127": "Trusted Developer Utilities Proxy Execution", "T1140": "Deobfuscate/Decode Files or Information",
    "T1202": "Indirect Command Execution", "T1218": "System Binary Proxy Execution", "T1220": "XSL Script Processing",
    "T1222": "File and Directory Permissions Modification", "T1480": "Execution Guardrails", "T1497": "Virtualization/Sandbox Evasion",
    "T1553": "Subvert Trust Controls", "T1562": "Impair Defenses", "T1564": "Hide Artifacts", "T1620": "Reflective Code Loading",
    "T1003": "OS Credential Dumping", "T1040": "Network Sniffing", "T1110": "Brute Force",
    "T1111": "Multi-Factor Authentication Interception", "T1212": "Exploitation for Credential Access", "T1552": "Unsecured Credentials",
    "T1555": "Credentials from Password Stores", "T1557": "Adversary-in-the-Middle", "T1558": "Steal or Forge Kerberos Tickets",
    "T1539": "Steal Web Session Cookie", "T1606": "Forge Web Credentials", "T1007": "System Service Discovery",
    "T1010": "Application Window Discovery", "T1012": "Query Registry", "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery", "T1033": "System Owner/User Discovery", "T1046": "Network Service Discovery",
    "T1049": "System Network Connections Discovery", "T1057": "Process Discovery", "T1069": "Permission Groups Discovery",
    "T1082": "System Information Discovery", "T1083": "File and Directory Discovery", "T1087": "Account Discovery",
    "T1124": "System Time Discovery", "T1135": "Network Share Discovery", "T1201": "Password Policy Discovery",
    "T1217": "Browser Information Discovery", "T1482": "Domain Trust Discovery", "T1518": "Software Discovery",
    "T1614": "System Location Discovery", "T1021": "Remote Services", "T1080": "Taint Shared Content",
    "T1210": "Exploitation of Remote Services", "T1534": "Internal Spearphishing", "T1550": "Use Alternate Authentication Material",
    "T1563": "Remote Service Session Hijacking", "T1570": "Lateral Tool Transfer", "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive", "T1025": "Data from Removable Media", "T1056": "Input Capture",
    "T1074": "Data Staged", "T1113": "Screen Capture", "T1114": "Email Collection", "T1115": "Clipboard Data",
    "T1119": "Automated Collection", "T1123": "Audio Capture", "T1125": "Video Capture",
    "T1213": "Data from Information Repositories", "T1560": "Archive Collected Data", "T1071": "Application Layer Protocol",
    "T1090": "Proxy", "T1095": "Non-Application Layer Protocol", "T1102": "Web Service", "T1105": "Ingress Tool Transfer",
    "T1132": "Data Encoding", "T1219": "Remote Access Tools", "T1571": "Non-Standard Port", "T1572": "Protocol Tunneling",
    "T1573": "Encrypted Channel", "T1011": "Exfiltration Over Other Network Medium", "T1020": "Automated Exfiltration",
    "T1029": "Scheduled Transfer", "T1030": "Data Transfer Size Limits", "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol", "T1052": "Exfiltration Over Physical Medium",
    "T1537": "Transfer Data to Cloud Account", "T1567": "Exfiltration Over Web Service", "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact", "T1489": "Service Stop", "T1490": "Inhibit System Recovery", "T1491": "Defacement",
    "T1496": "Resource Hijacking", "T1529": "System Shutdown/Reboot", "T1531": "Account Access Removal", "T1561": "Disk Wipe",
    "T1565": "Data Manipulation",
}

# Kill-chain order of the tactics, used to lay findings out as the attack ran.
TACTIC_ORDER = (
    "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
)

_FULL_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def tagged_techniques(values: list[str] | None) -> list[str]:
    """Technique IDs as tagged (sub-techniques kept), in order, without repeats."""
    found: list[str] = []
    for value in values or []:
        for match in _FULL_TECHNIQUE_ID.finditer(str(value)):
            technique = match.group(0).upper()
            if technique not in found:
                found.append(technique)
    return found


def technique_label(technique: str) -> str:
    parent = technique.split(".", 1)[0].upper()
    name = TECHNIQUE_NAMES.get(parent)
    return f"{technique} {name}" if name else technique


def tactic_for(technique: str, preferred: str | None = None) -> str | None:
    """Tactic to file a technique under: the finding's own phase when the
    technique supports it, otherwise the technique's first tactic."""
    tactics = TECHNIQUE_TACTICS.get(technique.split(".", 1)[0].upper())
    if not tactics:
        return None
    return preferred if preferred in tactics else tactics[0]
