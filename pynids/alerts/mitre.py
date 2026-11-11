"""
MITRE ATT&CK names for the techniques PyNIDS detectors and rules report.

A small offline catalogue: technique id → (name, tactic).  It lets every
UI show "T1071.004 · DNS (Command and Control)" instead of a bare id and
group detections by tactic, without fetching anything.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

# Kill-chain order, used to sort the tactic view.
TACTICS: Tuple[str, ...] = (
    "Reconnaissance", "Initial Access", "Execution", "Persistence", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
)

TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB / Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("SSH", "Lateral Movement"),
    "T1021.005": ("VNC", "Lateral Movement"),
    "T1021.006": ("Windows Remote Management", "Lateral Movement"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1059.007": ("JavaScript", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1090": ("Proxy", "Command and Control"),
    "T1090.003": ("Multi-hop Proxy (Tor)", "Command and Control"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1102": ("Web Service", "Command and Control"),
    "T1102.002": ("Bidirectional Communication", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1187": ("Forced Authentication", "Credential Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1498.002": ("Reflection Amplification", "Impact"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1557.001": ("LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1568": ("Dynamic Resolution", "Command and Control"),
    "T1568.002": ("Domain Generation Algorithms", "Command and Control"),
    "T1569.002": ("Service Execution", "Execution"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1592.004": ("Gather Victim Host Information: Client Configurations", "Reconnaissance"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance"),
    "T1602.001": ("SNMP (MIB Dump)", "Collection"),
}


def technique(technique_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """``{"id", "name", "tactic", "url"}`` for *technique_id*, or None when empty."""
    if not technique_id:
        return None
    tid = str(technique_id).strip().upper()
    entry = TECHNIQUES.get(tid) or TECHNIQUES.get(tid.split(".")[0])
    name, tactic = entry if entry else (None, None)
    if entry and tid not in TECHNIQUES:
        name = f"{name} (sub-technique)"
    return {
        "id": tid,
        "name": name,
        "tactic": tactic,
        "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
    }
