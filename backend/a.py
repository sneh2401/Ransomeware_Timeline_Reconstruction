
import re
import json
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List
import warnings
from pathlib import Path
warnings.filterwarnings('ignore')

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class ForensicTimelineReconstructor:
    def __init__(self):
        self.events = []
        self.anomalies = []
        self.attack_phases = defaultdict(list)
        self.ioc_database = self._initialize_ioc_database()
        self.mitre_attack_mapping = self._initialize_mitre_mapping()
        
    def _initialize_ioc_database(self) -> Dict:
        """Initialize Indicators of Compromise database"""
        return {
            'suspicious_ips': [
                '192.168.100.50', '10.0.0.99', '172.16.50.100',
                '203.0.113.0', '198.51.100.0'
            ],
            'malicious_domains': [
                'evil.com', 'c2server.net', 'malware-download.org',
                'ransomware-c2.com', 'data-exfil.net'
            ],
            'suspicious_processes': [
                'mimikatz.exe', 'lazagne.exe', 'procdump.exe',
                'psexec.exe', 'wmic.exe', 'powershell.exe -enc',
                'certutil.exe', 'bitsadmin.exe', 'rundll32.exe'
            ],
            'suspicious_files': [
                'ransomware.exe', 'encrypt.dll', 'keylogger.exe',
                'backdoor.ps1', 'persistence.bat', 'exfiltrate.py'
            ],
            'suspicious_registry': [
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ],
            'ransomware_extensions': [
                '.locked', '.encrypted', '.crypto', '.enc',
                '.darkness', '.phantom', '.snake'
            ]
        }
    
    def _initialize_mitre_mapping(self) -> Dict:
        """Map activities to MITRE ATT&CK framework phases"""
        return {
            'initial_access': {
                'keywords': ['login failed', 'authentication', 'RDP connection', 
                           'VPN access', 'phishing', 'exploit'],
                'phase': 'T1078 - Valid Accounts / T1133 - External Remote Services'
            },
            'execution': {
                'keywords': ['powershell', 'cmd.exe', 'script execution',
                           'scheduled task', 'service created'],
                'phase': 'T1059 - Command and Scripting Interpreter'
            },
            'persistence': {
                'keywords': ['registry modification', 'startup folder',
                           'service installation', 'scheduled task created'],
                'phase': 'T1547 - Boot or Logon Autostart Execution'
            },
            'privilege_escalation': {
                'keywords': ['admin rights', 'UAC bypass', 'token manipulation',
                           'elevated privileges', 'SYSTEM access'],
                'phase': 'T1548 - Abuse Elevation Control Mechanism'
            },
            'defense_evasion': {
                'keywords': ['log cleared', 'defender disabled', 'firewall modified',
                           'process injection', 'timestomp'],
                'phase': 'T1070 - Indicator Removal on Host'
            },
            'credential_access': {
                'keywords': ['credential dump', 'LSASS access', 'SAM database',
                           'password spray', 'brute force'],
                'phase': 'T1003 - OS Credential Dumping'
            },
            'discovery': {
                'keywords': ['network scan', 'port scan', 'enumeration',
                           'whoami', 'net view', 'discovery'],
                'phase': 'T1087 - Account Discovery'
            },
            'lateral_movement': {
                'keywords': ['remote desktop', 'SMB connection', 'WMI execution',
                           'PSExec', 'remote service'],
                'phase': 'T1021 - Remote Services'
            },
            'collection': {
                'keywords': ['data staging', 'archive created', 'screenshot',
                           'keylogging', 'clipboard data'],
                'phase': 'T1074 - Data Staged'
            },
            'exfiltration': {
                'keywords': ['data transfer', 'upload', 'C2 communication',
                           'DNS tunneling', 'large outbound'],
                'phase': 'T1041 - Exfiltration Over C2 Channel'
            },
            'impact': {
                'keywords': ['ransomware', 'encryption', 'file locked',
                           'shadow copy deleted', 'backup deleted'],
                'phase': 'T1486 - Data Encrypted for Impact'
            }
        }
    
    def parse_windows_event_log(self, log_content: str) -> List[Dict]:
        """Parse Windows Event Log entries"""
        events = []
        lines = log_content.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse Windows Event Log format
            match = re.match(
                r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+EventID:(\d+)\s+Level:(\w+)\s+Source:(\w+)\s+(.+)',
                line
            )
            if match:
                timestamp, event_id, level, source, message = match.groups()
                
                event = {
                    'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                    'source': 'Windows Event Log',
                    'event_id': event_id,
                    'level': level,
                    'subsource': source,
                    'message': message,
                    'raw': line
                }
                
                # Check for anomalies
                self._check_windows_anomalies(event)
                events.append(event)
                
        return events
    
    def parse_firewall_log(self, log_content: str) -> List[Dict]:
        """Parse Firewall/Network log entries"""
        events = []
        lines = log_content.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse firewall log format
            match = re.match(
                r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+SRC:([^\s]+)\s+DST:([^\s]+)\s+PORT:(\d+)\s+PROTO:(\w+)\s*(.+)?',
                line
            )
            if match:
                timestamp, action, src_ip, dst_ip, port, proto, extra = match.groups()
                
                event = {
                    'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                    'source': 'Firewall',
                    'action': action,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'port': port,
                    'protocol': proto,
                    'message': f"{action} connection from {src_ip} to {dst_ip}:{port}",
                    'extra': extra or '',
                    'raw': line
                }
                
                # Check for network anomalies
                self._check_network_anomalies(event)
                events.append(event)
                
        return events
    
    def parse_application_log(self, log_content: str) -> List[Dict]:
        """Parse Application/System log entries"""
        events = []
        lines = log_content.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse application log format
            match = re.match(
                r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)',
                line
            )
            if match:
                timestamp, level, message = match.groups()
                
                event = {
                    'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                    'source': 'Application',
                    'level': level,
                    'message': message,
                    'raw': line
                }
                
                # Check for application anomalies
                self._check_application_anomalies(event)
                events.append(event)
                
        return events
    
    def _check_windows_anomalies(self, event: Dict):
        """Check for anomalies in Windows Event Logs"""
        anomaly_patterns = {
            'Failed Login Attempts': r'failed login|authentication failed|bad password',
            'Privilege Escalation': r'privilege|elevated|admin rights|UAC',
            'Service Manipulation': r'service (created|modified|deleted)|sc.exe',
            'Registry Modification': r'registry|HKLM|HKCU|regedit',
            'Process Creation': r'process created|new process|cmd.exe|powershell',
            'Log Clearing': r'log clear|event log deleted|cleared',
            'Shadow Copy Deletion': r'shadow copy|vssadmin|delete shadows',
            'Defender Tampering': r'defender|antivirus|real-time protection'
        }
        
        message_lower = event['message'].lower()
        for anomaly_type, pattern in anomaly_patterns.items():
            if re.search(pattern, message_lower, re.IGNORECASE):
                self.anomalies.append({
                    'timestamp': event['timestamp'],
                    'type': anomaly_type,
                    'severity': self._calculate_severity(anomaly_type),
                    'source': event['source'],
                    'details': event['message'],
                    'ioc_match': self._check_ioc_match(event['message'])
                })
    
    def _check_network_anomalies(self, event: Dict):
        """Check for anomalies in network traffic"""
        # Check for suspicious IPs
        if event['src_ip'] in self.ioc_database['suspicious_ips'] or \
           event['dst_ip'] in self.ioc_database['suspicious_ips']:
            self.anomalies.append({
                'timestamp': event['timestamp'],
                'type': 'Suspicious IP Communication',
                'severity': 'HIGH',
                'source': event['source'],
                'details': f"Communication with known malicious IP: {event['src_ip']} -> {event['dst_ip']}",
                'ioc_match': True
            })
        
        # Check for unusual ports
        suspicious_ports = [445, 3389, 4444, 5555, 8080, 8443]
        if int(event['port']) in suspicious_ports:
            self.anomalies.append({
                'timestamp': event['timestamp'],
                'type': 'Suspicious Port Activity',
                'severity': 'MEDIUM',
                'source': event['source'],
                'details': f"Activity on suspicious port {event['port']}",
                'ioc_match': False
            })
        
        # Check for potential data exfiltration
        if 'large' in event.get('extra', '').lower() or 'exfil' in event.get('extra', '').lower():
            self.anomalies.append({
                'timestamp': event['timestamp'],
                'type': 'Potential Data Exfiltration',
                'severity': 'CRITICAL',
                'source': event['source'],
                'details': event['message'],
                'ioc_match': True
            })
    
    def _check_application_anomalies(self, event: Dict):
        """Check for anomalies in application logs"""
        # Check for suspicious processes
        for proc in self.ioc_database['suspicious_processes']:
            if proc.lower() in event['message'].lower():
                self.anomalies.append({
                    'timestamp': event['timestamp'],
                    'type': 'Suspicious Process Execution',
                    'severity': 'HIGH',
                    'source': event['source'],
                    'details': f"Detected suspicious process: {proc}",
                    'ioc_match': True
                })
        
        # Check for ransomware indicators
        for ext in self.ioc_database['ransomware_extensions']:
            if ext in event['message']:
                self.anomalies.append({
                    'timestamp': event['timestamp'],
                    'type': 'Ransomware Activity Detected',
                    'severity': 'CRITICAL',
                    'source': event['source'],
                    'details': f"File encryption detected with extension: {ext}",
                    'ioc_match': True
                })
    
    def _check_ioc_match(self, text: str) -> bool:
        """Check if text contains known IOCs"""
        text_lower = text.lower()
        
        # Check all IOC categories
        for category, iocs in self.ioc_database.items():
            for ioc in iocs:
                if ioc.lower() in text_lower:
                    return True
        return False
    
    def _calculate_severity(self, anomaly_type: str) -> str:
        """Calculate severity level based on anomaly type"""
        critical_types = ['Shadow Copy Deletion', 'Ransomware', 'Data Exfiltration']
        high_types = ['Failed Login Attempts', 'Privilege Escalation', 'Log Clearing']
        medium_types = ['Service Manipulation', 'Registry Modification']
        
        if any(ct in anomaly_type for ct in critical_types):
            return 'CRITICAL'
        elif any(ht in anomaly_type for ht in high_types):
            return 'HIGH'
        elif any(mt in anomaly_type for mt in medium_types):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def correlate_events(self):
        """Layer 2: Temporal correlation of events"""
        # Sort all events by timestamp
        self.events.sort(key=lambda x: x['timestamp'])
        
        # Group events by time windows (5-minute windows)
        time_windows = defaultdict(list)
        for event in self.events:
            window_key = event['timestamp'].replace(
                minute=(event['timestamp'].minute // 5) * 5,
                second=0,
                microsecond=0
            )
            time_windows[window_key].append(event)
        
        # Find correlated event clusters
        correlations = []
        for window, events in time_windows.items():
            if len(events) > 3:  # Suspicious cluster of activity
                correlation = {
                    'timestamp': window,
                    'event_count': len(events),
                    'sources': list(set([e['source'] for e in events])),
                    'summary': self._summarize_cluster(events)
                }
                correlations.append(correlation)
        
        return correlations
    
    def _summarize_cluster(self, events: List[Dict]) -> str:
        """Summarize a cluster of correlated events"""
        sources = Counter([e['source'] for e in events])
        summary = f"Cluster of {len(events)} events from {', '.join(sources.keys())}"
        
        # Check for specific patterns
        messages = ' '.join([e.get('message', '') for e in events]).lower()
        if 'failed' in messages and 'login' in messages:
            summary += " - Possible brute force attempt"
        if 'powershell' in messages or 'cmd' in messages:
            summary += " - Command execution detected"
        if 'service' in messages or 'registry' in messages:
            summary += " - System modification detected"
            
        return summary
    
    def map_to_attack_phases(self):
        """Layer 3: Map events to MITRE ATT&CK phases"""
        for event in self.events:
            message = event.get('message', '').lower()
            
            for phase, details in self.mitre_attack_mapping.items():
                for keyword in details['keywords']:
                    if keyword in message:
                        self.attack_phases[phase].append({
                            'timestamp': event['timestamp'],
                            'technique': details['phase'],
                            'evidence': event['message'][:100],
                            'source': event['source']
                        })
                        break
    
    def attribute_threat_actor(self) -> Dict:
        """Layer 4: Attribution based on TTPs"""
        # Analyze attack patterns
        ttp_profile = {
            'techniques_used': list(self.attack_phases.keys()),
            'timeline_duration': None,
            'primary_targets': [],
            'sophistication_level': 'Unknown'
        }
        
        if self.events:
            first_event = min(self.events, key=lambda x: x['timestamp'])
            last_event = max(self.events, key=lambda x: x['timestamp'])
            duration = last_event['timestamp'] - first_event['timestamp']
            ttp_profile['timeline_duration'] = str(duration)
        
        # Determine sophistication based on techniques
        advanced_techniques = ['defense_evasion', 'credential_access', 'lateral_movement']
        if all(tech in ttp_profile['techniques_used'] for tech in advanced_techniques):
            ttp_profile['sophistication_level'] = 'HIGH - Likely APT Group'
        elif len(ttp_profile['techniques_used']) > 5:
            ttp_profile['sophistication_level'] = 'MEDIUM - Organized Cybercrime'
        else:
            ttp_profile['sophistication_level'] = 'LOW - Opportunistic Attacker'
        
        # Known APT group signatures (simplified)
        apt_signatures = {
            'APT28 (Fancy Bear)': ['credential_access', 'lateral_movement', 'exfiltration'],
            'APT29 (Cozy Bear)': ['defense_evasion', 'persistence', 'collection'],
            'Lazarus Group': ['impact', 'exfiltration', 'defense_evasion'],
            'REvil/Sodinokibi': ['privilege_escalation', 'impact', 'exfiltration']
        }
        
        possible_groups = []
        for group, signature in apt_signatures.items():
            if all(tech in ttp_profile['techniques_used'] for tech in signature[:2]):
                possible_groups.append(group)
        
        ttp_profile['possible_attribution'] = possible_groups if possible_groups else ['Unknown']
        
        return ttp_profile
    
    def generate_timeline_report(self):
        """Generate comprehensive forensic timeline report"""
        print(" FORENSIC TIMELINE RECONSTRUCTION REPORT")
        print("=" * 80 + Colors.RESET)
        
        # Summary statistics
        print(f"\n{Colors.BOLD}SUMMARY STATISTICS:{Colors.RESET}")
        print(f"Total Events Analyzed: {len(self.events)}")
        print(f"Anomalies Detected: {len(self.anomalies)}")
        print(f"Time Range: ", end="")
        if self.events:
            first = min(self.events, key=lambda x: x['timestamp'])['timestamp']
            last = max(self.events, key=lambda x: x['timestamp'])['timestamp']
            print(f"{first} to {last}")
            print(f"Attack Duration: {last - first}")
        else:
            print("No events to analyze")
        
        # Critical anomalies
        critical_anomalies = [a for a in self.anomalies if a['severity'] == 'CRITICAL']
        if critical_anomalies:
            print(f"\n{Colors.RED}{Colors.BOLD}CRITICAL ANOMALIES DETECTED:{Colors.RESET}")
            for anomaly in sorted(critical_anomalies, key=lambda x: x['timestamp']):
                print(f"{Colors.RED}[{anomaly['timestamp']}] {anomaly['type']}: {anomaly['details'][:80]}...{Colors.RESET}")
        
        # Timeline of events
        print(f"\n{Colors.BOLD}{Colors.YELLOW}ATTACK TIMELINE:{Colors.RESET}")
        
        # Group events by hour for cleaner display
        hourly_events = defaultdict(list)
        for event in sorted(self.events, key=lambda x: x['timestamp']):
            hour_key = event['timestamp'].replace(minute=0, second=0, microsecond=0)
            hourly_events[hour_key].append(event)
        
        for hour, events in sorted(hourly_events.items()):
            print(f"\n{Colors.BOLD}{hour.strftime('%Y-%m-%d %H:00')}:{Colors.RESET}")
            for event in events[:5]:  # Show first 5 events per hour
                severity_color = Colors.WHITE
                for anomaly in self.anomalies:
                    if anomaly['timestamp'] == event['timestamp']:
                        if anomaly['severity'] == 'CRITICAL':
                            severity_color = Colors.RED
                        elif anomaly['severity'] == 'HIGH':
                            severity_color = Colors.YELLOW
                        break
                
                print(f"  {severity_color}[{event['timestamp'].strftime('%H:%M:%S')}] "
                      f"{event['source']}: {event.get('message', '')[:60]}...{Colors.RESET}")
            
            if len(events) > 5:
                print(f"  {Colors.CYAN}... and {len(events) - 5} more events{Colors.RESET}")
        
        # MITRE ATT&CK Mapping
        if self.attack_phases:
            print(f"\n{Colors.BOLD}{Colors.MAGENTA}MITRE ATT&CK PHASES DETECTED:{Colors.RESET}")
            attack_sequence = [
                'initial_access', 'execution', 'persistence', 'privilege_escalation',
                'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
                'collection', 'exfiltration', 'impact'
            ]
            
            for phase in attack_sequence:
                if phase in self.attack_phases:
                    phase_events = self.attack_phases[phase]
                    print(f"\n{Colors.BOLD}{phase.upper().replace('_', ' ')}:{Colors.RESET}")
                    for pe in phase_events[:3]:
                        print(f"  [{pe['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] "
                              f"{pe['technique']}")
                        print(f"    Evidence: {pe['evidence']}")
        
        # Correlations
        correlations = self.correlate_events()
        if correlations:
            print(f"\n{Colors.BOLD}{Colors.BLUE}TEMPORAL CORRELATIONS:{Colors.RESET}")
            for corr in correlations[:5]:
                print(f"[{corr['timestamp']}] {corr['summary']}")
        
        # Attribution
        attribution = self.attribute_threat_actor()
        print(f"\n{Colors.BOLD}{Colors.CYAN}THREAT ATTRIBUTION:{Colors.RESET}")
        print(f"Sophistication Level: {attribution['sophistication_level']}")
        print(f"Techniques Observed: {', '.join(attribution['techniques_used'])}")
        print(f"Possible Attribution: {', '.join(attribution['possible_attribution'])}")
        
        # Recommendations
        print(f"\n{Colors.BOLD}{Colors.GREEN}RECOMMENDATIONS:{Colors.RESET}")
        recommendations = self._generate_recommendations()
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        if any(a['type'] == 'Shadow Copy Deletion' for a in self.anomalies):
            recommendations.append("URGENT: Isolate affected systems immediately - ransomware deployment imminent")
        
        if any(a['type'] == 'Failed Login Attempts' for a in self.anomalies):
            recommendations.append("Implement account lockout policies and multi-factor authentication")
        
        if 'lateral_movement' in self.attack_phases:
            recommendations.append("Segment network and implement zero-trust architecture")
        
        if 'credential_access' in self.attack_phases:
            recommendations.append("Reset all passwords and review privileged account management")
        
        if 'defense_evasion' in self.attack_phases:
            recommendations.append("Review and harden security tool configurations")
        
        if not recommendations:
            recommendations.append("Continue monitoring and implement proactive threat hunting")
        
        return recommendations
    
    def process_log_files(self, windows_log: str, firewall_log: str, app_log: str):
        """Main processing function"""
        print(f"{Colors.BOLD}{Colors.CYAN}Processing log files...{Colors.RESET}")
        
        # Parse different log types
        self.events.extend(self.parse_windows_event_log(windows_log))
        self.events.extend(self.parse_firewall_log(firewall_log))
        self.events.extend(self.parse_application_log(app_log))
        
        # Map to attack phases
        self.map_to_attack_phases()
        
        # Generate report
        self.generate_timeline_report()
        
        # Export findings
        self.export_findings()
    
    def export_findings(self):
        """Export findings to JSON format"""
        findings = {
            'summary': {
                'total_events': len(self.events),
                'anomalies_detected': len(self.anomalies),
                'critical_anomalies': len([a for a in self.anomalies if a['severity'] == 'CRITICAL']),
                'attack_phases': list(self.attack_phases.keys())
            },
            'anomalies': [
                {
                    'timestamp': a['timestamp'].isoformat(),
                    'type': a['type'],
                    'severity': a['severity'],
                    'details': a['details']
                }
                for a in self.anomalies
            ],
            'attribution': self.attribute_threat_actor()
        }
        
        with open('forensic_findings.json', 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        
        print(f"\n{Colors.GREEN}Findings exported to forensic_findings.json{Colors.RESET}")


# Sample log data generation


def analyze_sample_attack():
    """Analyze the sample APT attack scenario"""
    print(f"{Colors.BOLD}{Colors.CYAN}Multi-Layered Forensic Timeline Reconstruction Framework{Colors.RESET}")
    print(f"{Colors.CYAN}Analyzing simulated APT attack leading to ransomware deployment...{Colors.RESET}\n")
    
    # Generate sample logs
    sample_logs = generate_sample_logs()
    
    # Initialize the forensic reconstructor
    forensic_analyzer = ForensicTimelineReconstructor()
    
    # Process the log files
    forensic_analyzer.process_log_files(
        sample_logs['windows_log'],
        sample_logs['firewall_log'],
        sample_logs['application_log']
    )
    
    # Generate additional analysis
    print(f"\n{Colors.BOLD}{Colors.YELLOW}ADVANCED ANALYSIS:{Colors.RESET}")
    
    # IOC Summary
    ioc_matches = sum(1 for anomaly in forensic_analyzer.anomalies if anomaly['ioc_match'])
    print(f"IOC Matches Found: {ioc_matches}")
    
    # Attack Chain Reconstruction
    print(f"\n{Colors.BOLD}ATTACK KILL CHAIN RECONSTRUCTION:{Colors.RESET}")
    kill_chain_phases = [
        ('Reconnaissance', 'Pre-attack intelligence gathering'),
        ('Initial Access', 'RDP brute force attack from 192.168.100.50'),
        ('Execution', 'PowerShell and command execution'),
        ('Persistence', 'Service creation and registry modification'),
        ('Privilege Escalation', 'Admin rights acquisition'),
        ('Defense Evasion', 'Log clearing and AV disabling'),
        ('Credential Access', 'Mimikatz credential dumping'),
        ('Discovery', 'Network and system enumeration'),
        ('Lateral Movement', 'RDP and SMB lateral spreading'),
        ('Collection', 'Data staging and archiving'),
        ('Exfiltration', 'C2 communication and data theft'),
        ('Impact', 'Ransomware deployment and encryption')
    ]
    
    for i, (phase, description) in enumerate(kill_chain_phases, 1):
        print(f"{i:2d}. {Colors.BOLD}{phase}:{Colors.RESET} {description}")


def interactive_mode():
    """Interactive mode for custom log analysis"""
    print(f"{Colors.BOLD}{Colors.GREEN}Interactive Forensic Analysis Mode{Colors.RESET}")
    print("Enter your log data or press Enter to use sample data:\n")
    
    print("Windows Event Log (press Enter twice when done):")
    windows_lines = []
    while True:
        line = input()
        if line == "":
            if windows_lines and windows_lines[-1] == "":
                break
        windows_lines.append(line)
    
    if not any(windows_lines):
        print("Using sample data...")
        analyze_sample_attack()
        return
    
    print("\nFirewall Log (press Enter twice when done):")
    firewall_lines = []
    while True:
        line = input()
        if line == "":
            if firewall_lines and firewall_lines[-1] == "":
                break
        firewall_lines.append(line)
    
    print("\nApplication Log (press Enter twice when done):")
    app_lines = []
    while True:
        line = input()
        if line == "":
            if app_lines and app_lines[-1] == "":
                break
        app_lines.append(line)
    
    # Process custom logs
    forensic_analyzer = ForensicTimelineReconstructor()
    forensic_analyzer.process_log_files(
        '\n'.join(windows_lines),
        '\n'.join(firewall_lines), 
        '\n'.join(app_lines)
    )


# def main():
#     # The script expects log files in the current directory
#     windows_log_file = Path("sample_windows.log")
#     firewall_log_file = Path("sample_firewall.log")
#     app_log_file = Path("sample_application.log")

#     if windows_log_file.exists():
#         with open(windows_log_file) as f: windows_log = f.read()
#     else:
#         print(f"{Colors.RED}Missing file: {windows_log_file}{Colors.RESET}")
#         return
#     if firewall_log_file.exists():
#         with open(firewall_log_file) as f: firewall_log = f.read()
#     else:
#         print(f"{Colors.RED}Missing file: {firewall_log_file}{Colors.RESET}")
#         return
#     if app_log_file.exists():
#         with open(app_log_file) as f: app_log = f.read()
#     else:
#         print(f"{Colors.RED}Missing file: {app_log_file}{Colors.RESET}")
#         return

#     reconstructor = ForensicTimelineReconstructor()
#     reconstructor.process_log_files(windows_log, firewall_log, app_log)
import sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: python a.py <log_file_path>")
        return

    input_log_path = Path(sys.argv[1])

    if not input_log_path.exists():
        print(f"ERROR: File not found: {input_log_path}")
        return

    # Read log file content
    with open(input_log_path, "r") as f:
        log_text = f.read()

    # INFER LOG TYPE: Windows/FW/App (could use file naming, headers or inspection)
    # Here, for simplicity: Try all parsers, or design parser selection as required

    reconstructor = ForensicTimelineReconstructor()
    # Example: Try to parse as all three, or customize depending on file type
    reconstructor.events.extend(reconstructor.parse_windows_event_log(log_text))
    reconstructor.events.extend(reconstructor.parse_firewall_log(log_text))
    reconstructor.events.extend(reconstructor.parse_application_log(log_text))

    # Map to MITRE attack phases and generate findings as before
    reconstructor.map_to_attack_phases()
    reconstructor.export_findings()

# if __name__ == "__main__":
#     main()

if __name__ == "__main__":
    main()