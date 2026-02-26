

# ──────────────────────────────────────────────
# MITRE ATT&CK Tactic definitions
# ──────────────────────────────────────────────
TACTICS = {
    "TA0001": {"name": "Initial Access", "short": "initial-access"},
    "TA0002": {"name": "Execution", "short": "execution"},
    "TA0003": {"name": "Persistence", "short": "persistence"},
    "TA0004": {"name": "Privilege Escalation", "short": "priv-escalation"},
    "TA0005": {"name": "Defense Evasion", "short": "defense-evasion"},
    "TA0006": {"name": "Credential Access", "short": "credential-access"},
    "TA0007": {"name": "Discovery", "short": "discovery"},
    "TA0008": {"name": "Lateral Movement", "short": "lateral-movement"},
    "TA0009": {"name": "Collection", "short": "collection"},
    "TA0010": {"name": "Exfiltration", "short": "exfiltration"},
    "TA0011": {"name": "Command and Control", "short": "c2"},
    "TA0040": {"name": "Impact", "short": "impact"},
    "TA0042": {"name": "Resource Development", "short": "resource-dev"},
    "TA0043": {"name": "Reconnaissance", "short": "recon"},
}


# ──────────────────────────────────────────────
# Technique → Tactic mapping with detection rules
# ──────────────────────────────────────────────
TECHNIQUES = {
    # Initial Access
    "T1078": {
        "name": "Valid Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "keywords": ["login successful", "accepted password", "valid credentials",
                     "authenticated successfully", "event_id=4624"],
        "event_types": ["AUTH_SUCCESS"],
        "severity": "medium",
        "description": "Adversaries may use valid accounts to gain initial access."
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic_ids": ["TA0001", "TA0003"],
        "keywords": ["rdp", "ssh", "vpn", "remote desktop", "remote access"],
        "event_types": [],
        "severity": "medium",
        "description": "Leveraging external-facing remote services for access."
    },
    "T1566": {
        "name": "Phishing",
        "tactic_ids": ["TA0001"],
        "keywords": ["phishing", "spearphishing", "malicious attachment",
                     "suspicious email", "macro enabled"],
        "event_types": [],
        "severity": "high",
        "description": "Adversaries send phishing messages to gain access."
    },

    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic_ids": ["TA0002"],
        "keywords": ["powershell", "cmd.exe", "bash", "python", "wscript",
                     "cscript", "mshta", "invoke-expression"],
        "event_types": ["PROCESS_CREATE", "EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Command-line interpreters used to execute commands."
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic_ids": ["TA0002"],
        "keywords": ["powershell", "pwsh", "invoke-", "downloadstring",
                     "-encodedcommand", "-enc ", "iex("],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "critical",
        "description": "PowerShell used for execution of commands and scripts."
    },
    "T1204": {
        "name": "User Execution",
        "tactic_ids": ["TA0002"],
        "keywords": ["user executed", "double-click", "opened attachment"],
        "event_types": [],
        "severity": "medium",
        "description": "Adversary relies on user to execute malicious content."
    },

    # Persistence
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic_ids": ["TA0002", "TA0003", "TA0004"],
        "keywords": ["scheduled task", "cron", "at job", "schtasks",
                     "systemd timer"],
        "event_types": [],
        "severity": "high",
        "description": "Abuse task scheduling for persistence or execution."
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic_ids": ["TA0003", "TA0004"],
        "keywords": ["autostart", "startup folder", "run key", "registry run",
                     "init.d", "systemd enable"],
        "event_types": ["REGISTRY"],
        "severity": "high",
        "description": "Configuring settings to execute on boot or logon."
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic_ids": ["TA0003", "TA0004"],
        "keywords": ["service created", "service installed", "sc create",
                     "systemctl", "daemon"],
        "event_types": [],
        "severity": "high",
        "description": "Creating system services for persistence."
    },

    # Privilege Escalation
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic_ids": ["TA0004", "TA0005"],
        "keywords": ["sudo", "su ", "runas", "uac bypass", "setuid",
                     "privilege escalation", "elevated"],
        "event_types": ["PRIV_ESCALATION"],
        "severity": "critical",
        "description": "Bypassing elevation controls to gain higher privileges."
    },

    # Defense Evasion
    "T1070": {
        "name": "Indicator Removal",
        "tactic_ids": ["TA0005"],
        "keywords": ["clear log", "delete log", "wevtutil cl", "rm -rf /var/log",
                     "event log cleared", "file deleted", "shred"],
        "event_types": ["FILE_DELETE"],
        "severity": "critical",
        "description": "Deleting or modifying artifacts to cover tracks."
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic_ids": ["TA0005"],
        "keywords": ["encoded", "base64", "obfuscated", "packed",
                     "encrypted payload"],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Obfuscating content to evade security defenses."
    },
    "T1036": {
        "name": "Masquerading",
        "tactic_ids": ["TA0005"],
        "keywords": ["masquerade", "renamed binary", "fake process name"],
        "event_types": [],
        "severity": "high",
        "description": "Manipulating features of artifacts to look legitimate."
    },

    # Credential Access
    "T1110": {
        "name": "Brute Force",
        "tactic_ids": ["TA0006"],
        "keywords": ["brute force", "failed login", "failed password",
                     "authentication failure", "multiple failed",
                     "invalid credentials", "event_id=4625"],
        "event_types": ["AUTH_FAIL"],
        "severity": "high",
        "description": "Systematically guessing credentials through brute force."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic_ids": ["TA0006"],
        "keywords": ["mimikatz", "lsass", "sam dump", "credential dump",
                     "procdump", "sekurlsa", "hashdump"],
        "event_types": [],
        "severity": "critical",
        "description": "Dumping credentials from the operating system."
    },

    # Discovery
    "T1087": {
        "name": "Account Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["net user", "whoami", "id ", "getent passwd",
                     "ldap query", "enumeration"],
        "event_types": [],
        "severity": "medium",
        "description": "Attempting to enumerate accounts on the system."
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["port scan", "nmap", "service scan", "network scan"],
        "event_types": [],
        "severity": "high",
        "description": "Scanning for network services running on remote hosts."
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["systeminfo", "uname", "hostname", "os version",
                     "system information"],
        "event_types": [],
        "severity": "low",
        "description": "Gathering detailed system information."
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic_ids": ["TA0007"],
        "keywords": ["tasklist", "ps aux", "process list", "get-process"],
        "event_types": [],
        "severity": "low",
        "description": "Gathering information about running processes."
    },
    "T1092": {
        "name": "Communication Through Removable Media",
        "tactic_ids": ["TA0011"],
        "keywords": ["usb", "removable media", "mass storage", "thumb drive"],
        "event_types": ["USB"],
        "severity": "high",
        "description": "Using removable media for command and control."
    },

    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic_ids": ["TA0008"],
        "keywords": ["rdp session", "ssh to", "psexec", "winrm",
                     "lateral movement", "remote login"],
        "event_types": [],
        "severity": "high",
        "description": "Using remote services to move laterally."
    },

    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic_ids": ["TA0009"],
        "keywords": ["file copied", "data collection", "staging",
                     "sensitive file", "data gathered"],
        "event_types": ["FILE_COPY"],
        "severity": "high",
        "description": "Collecting data from the local system."
    },

    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic_ids": ["TA0010"],
        "keywords": ["exfiltration", "data transfer", "upload to",
                     "outbound data", "data exfil"],
        "event_types": ["NETWORK_CONN"],
        "severity": "critical",
        "description": "Stealing data over an existing C2 channel."
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic_ids": ["TA0010"],
        "keywords": ["dns tunnel", "dns exfil", "icmp tunnel", "ftp upload"],
        "event_types": [],
        "severity": "critical",
        "description": "Exfiltrating data over non-standard protocols."
    },

    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic_ids": ["TA0011"],
        "keywords": ["http beacon", "https callback", "c2 communication",
                     "beacon", "c2", "command and control"],
        "event_types": ["NETWORK_CONN", "MALWARE_INDICATOR"],
        "severity": "critical",
        "description": "Using application protocols for C2 communication."
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic_ids": ["TA0011"],
        "keywords": ["download tool", "wget ", "curl ", "certutil",
                     "bitsadmin", "tool transfer"],
        "event_types": ["EXECUTION_SUSPICIOUS"],
        "severity": "high",
        "description": "Transferring tools or files from external systems."
    },

    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic_ids": ["TA0040"],
        "keywords": ["ransomware", "encrypted files", "ransom note",
                     "file encryption"],
        "event_types": ["MALWARE_INDICATOR"],
        "severity": "critical",
        "description": "Encrypting data to interrupt availability."
    },
    "T1489": {
        "name": "Service Stop",
        "tactic_ids": ["TA0040"],
        "keywords": ["service stopped", "service disabled", "sc stop",
                     "systemctl stop", "kill process"],
        "event_types": [],
        "severity": "high",
        "description": "Stopping services to impair system functionality."
    },
}


# ──────────────────────────────────────────────
# Attack chain templates
# ──────────────────────────────────────────────
ATTACK_CHAINS = [
    {
        "name": "Credential Compromise → Lateral Movement",
        "description": "Brute force followed by successful login and remote service usage",
        "sequence": ["T1110", "T1078", "T1021"],
        "severity": "critical"
    },
    {
        "name": "Execution → Persistence → C2",
        "description": "Suspicious execution leading to persistence mechanism and C2",
        "sequence": ["T1059", "T1547", "T1071"],
        "severity": "critical"
    },
    {
        "name": "Initial Access → Collection → Exfiltration",
        "description": "Account compromise followed by data collection and exfiltration",
        "sequence": ["T1078", "T1005", "T1041"],
        "severity": "critical"
    },
    {
        "name": "Privilege Escalation → Defense Evasion",
        "description": "Elevation of privileges followed by log clearing",
        "sequence": ["T1548", "T1070"],
        "severity": "critical"
    },
    {
        "name": "Discovery → Lateral Movement → Collection",
        "description": "Network discovery leading to lateral movement and data staging",
        "sequence": ["T1046", "T1021", "T1005"],
        "severity": "high"
    },
]


def map_mitre(events):
    """
    Map events to MITRE ATT&CK techniques.
    Updates each event in-place with mitre_tactics and mitre_techniques.
    Returns summary of unique techniques found.
    """
    techniques_found = set()

    for event in events:
        raw_lower = event.get("raw", "").lower()
        event_type = event.get("type", "")

        for tech_id, tech in TECHNIQUES.items():
            matched = False

            # Check by event type
            if event_type in tech.get("event_types", []):
                matched = True

            # Check by keywords
            if not matched:
                for kw in tech.get("keywords", []):
                    if kw in raw_lower:
                        matched = True
                        break

            if matched:
                techniques_found.add(tech_id)

                tech_entry = {
                    "id": tech_id,
                    "name": tech["name"],
                    "severity": tech["severity"],
                    "description": tech["description"]
                }
                if tech_entry not in event["mitre_techniques"]:
                    event["mitre_techniques"].append(tech_entry)

                for tactic_id in tech["tactic_ids"]:
                    tactic = TACTICS.get(tactic_id, {})
                    tactic_entry = {
                        "id": tactic_id,
                        "name": tactic.get("name", "Unknown"),
                    }
                    if tactic_entry not in event["mitre_tactics"]:
                        event["mitre_tactics"].append(tactic_entry)

    return [f"{tid} – {TECHNIQUES[tid]['name']}" for tid in techniques_found]


def get_mitre_heatmap_data(events):
    """
    Generate heatmap data: tactic × technique counts.
    Returns dict: {tactic_id: {technique_id: count}}
    """
    heatmap = {}

    for tactic_id in TACTICS:
        heatmap[tactic_id] = {}

    for event in events:
        for tech in event.get("mitre_techniques", []):
            tech_id = tech["id"]
            tech_def = TECHNIQUES.get(tech_id, {})
            for tactic_id in tech_def.get("tactic_ids", []):
                if tactic_id in heatmap:
                    heatmap[tactic_id][tech_id] = heatmap[tactic_id].get(tech_id, 0) + 1

    return heatmap


def detect_attack_chains(events):
    """
    Detect known attack chain patterns in event sequence.
    Returns list of detected chains with evidence.
    """
    detected_chains = []

    # Gather all techniques seen
    all_techniques = set()
    for event in events:
        for tech in event.get("mitre_techniques", []):
            all_techniques.add(tech["id"])
            # Also check parent technique (e.g. T1059.001 → T1059)
            parent = tech["id"].split(".")[0]
            all_techniques.add(parent)

    for chain in ATTACK_CHAINS:
        sequence = chain["sequence"]
        match_count = sum(1 for t in sequence if t in all_techniques)

        if match_count >= 2:  # At least 2 out of chain steps present
            completeness = match_count / len(sequence)
            detected_chains.append({
                "name": chain["name"],
                "description": chain["description"],
                "severity": chain["severity"],
                "matched_techniques": [t for t in sequence if t in all_techniques],
                "total_steps": len(sequence),
                "completeness": round(completeness * 100),
            })

    return detected_chains


def get_coverage_score(events):
    """
    Calculate MITRE ATT&CK coverage score.
    Returns: tactics covered, techniques detected, total counts.
    """
    tactics_seen = set()
    techniques_seen = set()

    for event in events:
        for tac in event.get("mitre_tactics", []):
            tactics_seen.add(tac["id"])
        for tech in event.get("mitre_techniques", []):
            techniques_seen.add(tech["id"])

    return {
        "tactics_covered": len(tactics_seen),
        "tactics_total": len(TACTICS),
        "techniques_detected": len(techniques_seen),
        "techniques_total": len(TECHNIQUES),
        "coverage_pct": round(len(tactics_seen) / len(TACTICS) * 100) if TACTICS else 0,
    }
