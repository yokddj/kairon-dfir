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
