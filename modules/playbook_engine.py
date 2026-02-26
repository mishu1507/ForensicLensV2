class PlaybookEngine:
    def __init__(self):
        self.playbooks = {
            "Authentication Attack (Brute Force)": {
                "title": "Brute Force Response Playbook",
                "severity": "High",
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Invoke account lockout for target user accounts.",
                        "details": "Threshold reached: 10+ failed attempts. Force password reset on recovery."
                    },
                    {
                        "phase": "Containment",
                        "action": "Block source IP addresses at the perimeter firewall.",
                        "details": "Identify top 5 source IPs from auth logs and blackhole them."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Review successful logins from the same source IP.",
                        "details": "Check for any 'Auth Success' after a long chain of failures."
                    },
                    {
                        "phase": "Recovery",
                        "action": "Implement Multi-Factor Authentication (MFA).",
                        "details": "Mandatory enrollment for all high-risk accounts identified."
                    }
                ],
                "contacts": ["Identity Team", "Security Operations Lead"]
            },
            "Credential Compromise": {
                "title": "Credential Compromise Response",
                "severity": "Critical",
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Disable affected user sessions globally.",
                        "details": "Clear all OAuth tokens and Kerberos tickets (TGT)."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Force credential rotation for all system admins.",
                        "details": "Compromise detected in privilege escalation paths."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Perform timeline analysis of the session.",
                        "details": "Identify every resource accessed during the compromised window."
                    }
                ],
                "contacts": ["Active Directory Admin", "CISO Office"]
            },
            "Insider Data Theft": {
                "title": "Insider Threat Response Playbook",
                "severity": "Critical",
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Disable USB port access via Group Policy (GPO).",
                        "details": "Targeted deployment to the investigated host."
                    },
                    {
                        "phase": "Containment",
                        "action": "Suspend user network access accounts.",
                        "details": "Legal hold initiated. Do not delete data; preserve for forensics."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Identify all files copied to external media.",
                        "details": "Review event ID 4663 and USB file system logs."
                    }
                ],
                "contacts": ["HR Department", "Legal/Compliance", "Internal Audit"]
            },
            "Data Exfiltration": {
                "title": "Data Exfiltration Response",
                "severity": "Critical",
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Terminate active network connections to external C2.",
                        "details": "Kill state on firewall for identified destination IPs."
                    },
                    {
                        "phase": "Containment",
                        "action": "Isolate evidence host from the network.",
                        "details": "Move to forensic VLAN to prevent further data egress."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Analyze exfiltrated data volume.",
                        "details": "Check NetFlow data for total outbound bytes to the target IP."
                    }
                ],
                "contacts": ["Network Security Team", "Privacy Officer"]
            },
            "Suspicious Network Activity": {
                "title": "Network Anomaly Investigation",
                "severity": "Medium",
                "steps": [
                    {
                        "phase": "Investigation",
                        "action": "DPI (Deep Packet Inspection) of traffic.",
                        "details": "Look for non-standard protocol usage on port 443 or 53."
                    },
                    {
                        "phase": "Mitigation",
                        "action": "Update EDR/IDS signatures.",
                        "details": "Apply pattern matching for the identified traffic signature."
                    }
                ],
                "contacts": ["Network Ops", "Threat Intel Team"]
            },
            "Policy Violation (Unauthorized USB Usage)": {
                "title": "General Policy Violation",
                "severity": "Low",
                "steps": [
                    {
                        "phase": "Notification",
                        "action": "Email user regarding unauthorized peripheral usage.",
                        "details": "Automated security awareness training link included."
                    },
                    {
                        "phase": "Remediation",
                        "action": "Scan host for malware introduced via USB.",
                        "details": "Full system scan with deep heuristic analysis."
                    }
                ],
                "contacts": ["IT Support", "Security Education Team"]
            },
            "Web Application Attack (SQLi/XSS)": {
                "title": "Web Application Attack Response",
                "severity": "High",
                "steps": [
                    {
                        "phase": "Containment",
                        "action": "Enable WAF (Web Application Firewall) blocking mode.",
                        "details": "Identify malicious payload patterns and apply virtual patching."
                    },
                    {
                        "phase": "Eradication",
                        "action": "Sanitize and validate all input fields.",
                        "details": "Check logs for successful SQL injection or cross-site scripting bypass."
                    },
                    {
                        "phase": "Investigation",
                        "action": "Review application logs for backend errors.",
                        "details": "Look for database error spikes correlating with the attack timeline."
                    }
                ],
                "contacts": ["AppSec Team", "Web Infrastructure Lead"]
            },
            "Suspicious Activity": {
                "title": "Generic Security Incident Response",
                "severity": "Medium",
                "steps": [
                    {
                        "phase": "Initial Response",
                        "action": "Snapshot the virtual machine / host state.",
                        "details": "Capture memory and disk state before any intervention."
                    },
                    {
                        "phase": "Assessment",
                        "action": "Qualify severity and impact.",
                        "details": "Determine if this is a true positive or false positive."
                    }
                ],
                "contacts": ["On-call Analyst"]
            }
        }

    def get_playbook(self, incident_type, events):
        pb = self.playbooks.get(incident_type, self.playbooks["Suspicious Activity"])
        
        # Inject context (like victims, bad IPs)
        victims = list(set([e.get("hostname") for e in events if e.get("hostname")]))
        bad_ips = list(set([e.get("ip") for e in events if e.get("ip")]))
        
        # Dynamic customization
        if victims:
            pb["steps"][0]["details"] += f" (Impacted Hosts: {', '.join(victims[:3])})"
        if bad_ips:
            for step in pb["steps"]:
                if "IP" in step["action"] or "IP" in step["details"]:
                    step["details"] += f" (Identified IPs: {', '.join(bad_ips[:3])})"
                    
        return pb
