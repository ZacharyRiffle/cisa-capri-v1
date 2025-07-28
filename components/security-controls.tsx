"use client"

import { useState, useMemo } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Shield,
  Clock,
  Target,
  Eye,
  Activity,
  RefreshCw,
  FileText,
  Users,
  Database,
  Network,
  Search,
} from "lucide-react"
import type { Alert as AlertType } from "@/types/alert"

interface SecurityControlsProps {
  alerts: AlertType[]
  capriScore: {
    score: number
    breakdown: any
    rationale: string
  }
}

interface SecurityControl {
  id: string
  title: string
  nistFunction: "Identify" | "Protect" | "Detect" | "Respond" | "Recover"
  nistControl: string
  mitreDefense?: string
  priority: "Critical" | "High" | "Medium" | "Low"
  implementation: string
  timeframe: string
  resources: string[]
  sector?: string
}

interface MitreTechnique {
  id: string
  name: string
  tactic: string
  description: string
  countermeasures: string[]
  nistMapping: string[]
}

export function SecurityControls({ alerts, capriScore }: SecurityControlsProps) {
  const [selectedLevel, setSelectedLevel] = useState<"critical" | "elevated" | "guarded" | "low">("elevated")
  const [selectedSector, setSelectedSector] = useState<string>("All Sectors")

  // Determine threat level based on CAPRI score
  const threatLevel = useMemo(() => {
    const score = capriScore.score
    if (score >= 4) return "critical"
    if (score >= 3) return "elevated"
    if (score >= 2) return "guarded"
    return "low"
  }, [capriScore.score])

  // NIST Controls mapped to CAPRI levels - Much more specific
  const nistControls = useMemo<Record<string, SecurityControl[]>>(
    () => ({
      critical: [
        {
          id: "AC-2(1)",
          title: "Automated Account Management - Disable Dormant Accounts",
          nistFunction: "Protect",
          nistControl: "AC-2(1): Account Management | Automated System Account Management",
          mitreDefense: "D3-AM: Account Monitoring",
          priority: "Critical",
          implementation:
            "Execute: Get-ADUser -Filter {LastLogonTimeStamp -lt (Get-Date).AddDays(-30)} | Disable-ADAccount. Implement automated PowerShell scripts to disable accounts inactive >30 days. Configure SIEM alerts for privileged account usage outside business hours.",
          timeframe: "0-2 hours",
          resources: ["Active Directory", "PowerShell", "SIEM", "Identity Management"],
          sector: "All Sectors",
        },
        {
          id: "AC-2(4)",
          title: "Account Management - Automated Audit Actions",
          nistFunction: "Detect",
          nistControl: "AC-2(4): Account Management | Automated Audit Actions",
          mitreDefense: "D3-UAM: User Account Monitoring",
          priority: "Critical",
          implementation:
            "Deploy: auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable. Configure Windows Event IDs 4720,4722,4724,4725,4726,4738,4740,4767,4781 forwarding to SIEM. Set up automated response for Event ID 4625 (failed logons) >5 attempts in 10 minutes.",
          timeframe: "0-4 hours",
          resources: ["Windows Event Forwarding", "SIEM", "PowerShell DSC"],
          sector: "All Sectors",
        },
        {
          id: "SI-4(2)",
          title: "System Monitoring - Automated Tools and Mechanisms",
          nistFunction: "Detect",
          nistControl: "SI-4(2): System Monitoring | Automated Tools",
          mitreDefense: "D3-NTM: Network Traffic Monitoring",
          priority: "Critical",
          implementation:
            "Deploy Zeek/Suricata with custom rules for lateral movement detection. Configure: alert tcp any any -> any any (msg:'Potential Lateral Movement'; flow:to_server; content:'net user'; sid:1001;). Enable full packet capture on critical network segments. Set up automated IOC hunting with YARA rules.",
          timeframe: "0-6 hours",
          resources: ["Zeek/Suricata", "Full Packet Capture", "YARA", "Threat Intel Feeds"],
          sector: "Energy, Finance, Healthcare",
        },
        {
          id: "IR-4(1)",
          title: "Incident Handling - Automated Incident Handling Processes",
          nistFunction: "Respond",
          nistControl: "IR-4(1): Incident Handling | Automated Incident Handling",
          mitreDefense: "D3-IRA: Incident Response Activation",
          priority: "Critical",
          implementation:
            "Activate SOAR playbooks: 1) Isolate affected systems via EDR API calls 2) Collect memory dumps using winpmem.exe 3) Execute network containment via firewall API 4) Initiate stakeholder notifications via PagerDuty/Slack webhooks 5) Create forensic timeline using Plaso/log2timeline",
          timeframe: "0-1 hour",
          resources: ["SOAR Platform", "EDR API", "Memory Acquisition Tools", "Timeline Analysis"],
          sector: "All Sectors",
        },
        {
          id: "AC-6(2)",
          title: "Least Privilege - Non-Privileged Access for Nonsecurity Functions",
          nistFunction: "Protect",
          nistControl: "AC-6(2): Least Privilege | Non-privileged Access",
          mitreDefense: "D3-AZPE: Authorization Policy Enforcement",
          priority: "Critical",
          implementation:
            "Remove local admin rights: Remove-LocalGroupMember -Group 'Administrators' -Member 'Domain Users'. Implement LAPS for local admin passwords. Deploy Privileged Access Workstations (PAWs) for Tier 0 admins. Configure JIT access with Azure PIM: New-AzureADMSPrivilegedRoleAssignment -RoleDefinitionId <role-id> -ResourceId <resource-id> -SubjectId <user-id> -Type 'eligible'",
          timeframe: "2-8 hours",
          resources: ["LAPS", "Azure PIM", "PAWs", "Group Policy"],
          sector: "All Sectors",
        },
        {
          id: "SC-7(3)",
          title: "Boundary Protection - Access Points",
          nistFunction: "Protect",
          nistControl: "SC-7(3): Boundary Protection | Access Points",
          mitreDefense: "D3-NI: Network Isolation",
          priority: "Critical",
          implementation:
            "Implement micro-segmentation: Configure Cisco ACI/VMware NSX policies to deny inter-VLAN communication by default. Deploy host-based firewalls: netsh advfirewall set allprofiles state on. Create network access control lists: ip access-list extended CRITICAL_SYSTEMS; deny ip any any; permit tcp host <mgmt-ip> any eq 22 443. Enable 802.1X authentication on all switch ports.",
          timeframe: "4-12 hours",
          resources: ["Network Segmentation", "Host Firewalls", "802.1X", "NAC"],
          sector: "Energy, Water, Transportation",
        },
        {
          id: "AU-6(1)",
          title: "Audit Review - Process Integration",
          nistFunction: "Detect",
          nistControl: "AU-6(1): Audit Review, Analysis, and Reporting | Process Integration",
          mitreDefense: "D3-LAM: Log Analysis and Monitoring",
          priority: "High",
          implementation:
            "Configure Splunk/Elastic correlation rules: index=windows EventCode=4624 | stats count by src_ip | where count>100. Deploy Sigma rules for detection: title: Suspicious PowerShell Execution; detection: selection: Image|endswith: '\\powershell.exe'; CommandLine|contains: '-enc'. Set up automated threat hunting with OSQuery: SELECT * FROM processes WHERE cmdline LIKE '%powershell%' AND cmdline LIKE '%-enc%';",
          timeframe: "6-12 hours",
          resources: ["Splunk/Elastic", "Sigma Rules", "OSQuery", "Threat Hunting Platform"],
          sector: "All Sectors",
        },
        {
          id: "CP-9(1)",
          title: "System Backup - Testing for Reliability/Integrity",
          nistFunction: "Recover",
          nistControl: "CP-9(1): System Backup | Testing for Reliability and Integrity",
          mitreDefense: "D3-BR: Backup and Recovery",
          priority: "High",
          implementation:
            "Execute backup integrity verification: veeam.backup.validator.exe -backup <backup-file> -verify. Implement immutable backups with Veeam/Commvault air-gapped storage. Test restore procedures: Restore-VeeamBackup -RestorePoint <point> -TargetHost <test-host>. Configure backup monitoring: Get-VBRBackupSession | Where {$_.Result -eq 'Failed'} | Send-MailMessage",
          timeframe: "8-24 hours",
          resources: ["Veeam/Commvault", "Air-gapped Storage", "Backup Validation Tools"],
          sector: "Healthcare, Finance, Energy",
        },
      ],
      elevated: [
        {
          id: "RA-5(2)",
          title: "Vulnerability Monitoring - Update Tool Capability",
          nistFunction: "Identify",
          nistControl: "RA-5(2): Vulnerability Monitoring and Scanning | Update Tool Capability",
          mitreDefense: "D3-VULN: Vulnerability Assessment",
          priority: "High",
          implementation:
            "Deploy Nessus/Qualys with authenticated scanning: nessus -T html -x -q <policy> <targets>. Configure OpenVAS for continuous scanning: omp -u admin -w password --create-task --name='Critical Assets' --config=<config-id> --target=<target-id>. Implement vulnerability correlation with MITRE CVE data: curl -s https://cve.mitre.org/data/downloads/allitems-cvrf.xml | grep -i <software>",
          timeframe: "12-24 hours",
          resources: ["Nessus/Qualys", "OpenVAS", "CVE Database", "Asset Inventory"],
          sector: "All Sectors",
        },
        {
          id: "CM-2(2)",
          title: "Baseline Configuration - Automation Support",
          nistFunction: "Protect",
          nistControl: "CM-2(2): Baseline Configuration | Automation Support for Accuracy/Currency",
          mitreDefense: "D3-SCM: System Configuration Monitoring",
          priority: "High",
          implementation:
            "Deploy Chef/Ansible configuration management: ansible-playbook -i inventory security-baseline.yml. Implement CIS benchmarks: ansible-galaxy install dev-sec.os-hardening. Configure SCAP compliance scanning: oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis --results results.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
          timeframe: "24-48 hours",
          resources: ["Ansible/Chef", "CIS Benchmarks", "SCAP Scanner", "Configuration Templates"],
          sector: "All Sectors",
        },
        {
          id: "AU-6(3)",
          title: "Audit Review - Correlate Audit Repositories",
          nistFunction: "Detect",
          nistControl: "AU-6(3): Audit Review, Analysis, and Reporting | Correlate Audit Repositories",
          mitreDefense: "D3-LAM: Log Analysis and Monitoring",
          priority: "High",
          implementation:
            "Configure log aggregation with rsyslog: *.* @@logserver:514. Deploy ELK stack correlation: GET /logs/_search { 'query': { 'bool': { 'must': [{'match': {'event_type': 'authentication'}}, {'range': {'@timestamp': {'gte': 'now-1h'}}}] } } }. Implement cross-platform correlation with Sigma: python sigmac -t splunk -c tools/config/generic/sysmon.yml rules/windows/process_creation/win_susp_powershell_enc_cmd.yml",
          timeframe: "48-72 hours",
          resources: ["ELK Stack", "Rsyslog", "Sigma", "Log Correlation Engine"],
          sector: "All Sectors",
        },
        {
          id: "AT-2(2)",
          title: "Literacy Training - Insider Threat",
          nistFunction: "Protect",
          nistControl: "AT-2(2): Literacy Training and Awareness | Insider Threat",
          mitreDefense: "D3-SAWA: Security Awareness and Training",
          priority: "Medium",
          implementation:
            "Deploy GoPhish phishing simulation: gophish --config config.json. Configure targeted campaigns based on threat intelligence: Create templates mimicking current APT tactics (credential harvesting, malicious attachments). Implement User and Entity Behavior Analytics (UEBA): Configure Splunk UBA to detect anomalous user behavior patterns. Track training effectiveness with metrics: phishing click rates, reporting rates, time-to-report.",
          timeframe: "1-2 weeks",
          resources: ["GoPhish", "Splunk UBA", "Training Platform", "Metrics Dashboard"],
          sector: "All Sectors",
        },
        {
          id: "SI-3(2)",
          title: "Malicious Code Protection - Automatic Updates",
          nistFunction: "Protect",
          nistControl: "SI-3(2): Malicious Code Protection | Automatic Updates",
          mitreDefense: "D3-MFA: Malware File Analysis",
          priority: "High",
          implementation:
            "Configure Windows Defender ATP: Set-MpPreference -SignatureUpdateInterval 1. Deploy ClamAV with automatic updates: freshclam --daemon --checks=24. Implement YARA rule automation: git clone https://github.com/Yara-Rules/rules.git && yara -r rules/ <target>. Configure VirusTotal API integration: curl -X POST 'https://www.virustotal.com/vtapi/v2/file/scan' -F 'key=<api-key>' -F 'file=@<file>'",
          timeframe: "24-48 hours",
          resources: ["Windows Defender ATP", "ClamAV", "YARA", "VirusTotal API"],
          sector: "All Sectors",
        },
      ],
      guarded: [
        {
          id: "ID-AM-1",
          title: "Physical Devices and Systems Inventory",
          nistFunction: "Identify",
          nistControl: "ID.AM-1: Physical devices and systems within the organization are inventoried",
          mitreDefense: "D3-ASSETD: Asset Discovery",
          priority: "Medium",
          implementation:
            "Deploy Lansweeper/ManageEngine for asset discovery: lansweeper.exe /scan /range:192.168.1.0/24. Implement network scanning with Nmap: nmap -sS -O -sV -sC -A -T4 <network-range>. Configure DHCP snooping for device tracking: ip dhcp snooping. Use PowerShell for Windows asset inventory: Get-WmiObject -Class Win32_ComputerSystem | Export-Csv assets.csv",
          timeframe: "1-2 weeks",
          resources: ["Lansweeper", "Nmap", "DHCP Logs", "PowerShell", "Asset Database"],
          sector: "All Sectors",
        },
        {
          id: "PR-AC-1",
          title: "Identity and Credential Management",
          nistFunction: "Protect",
          nistControl: "PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited",
          mitreDefense: "D3-ACH: Access Control Hardening",
          priority: "Medium",
          implementation:
            "Implement Azure AD Connect for hybrid identity: Install-Module AzureAD; Connect-AzureAD. Configure MFA with conditional access: New-AzureADMSConditionalAccessPolicy -DisplayName 'Require MFA' -State 'Enabled'. Deploy certificate-based authentication: certlm.msc -> Personal -> Certificates -> Request New Certificate. Audit service accounts: Get-ADServiceAccount -Filter * | Select Name,LastLogonDate",
          timeframe: "2-4 weeks",
          resources: ["Azure AD", "Certificate Authority", "MFA Solution", "Service Account Inventory"],
          sector: "All Sectors",
        },
        {
          id: "DE-CM-1",
          title: "Network Monitoring",
          nistFunction: "Detect",
          nistControl: "DE.CM-1: The network is monitored to detect potential cybersecurity events",
          mitreDefense: "D3-NTM: Network Traffic Monitoring",
          priority: "Medium",
          implementation:
            "Deploy Security Onion with Suricata IDS: sudo so-setup. Configure network taps: Configure SPAN ports on switches for traffic mirroring. Implement flow monitoring with nfcapd: nfcapd -w -D -p 9995 -l /var/cache/nfcapd. Set up DNS monitoring: dig @<dns-server> <domain> && tail -f /var/log/named/queries.log",
          timeframe: "2-3 weeks",
          resources: ["Security Onion", "Network Taps", "Flow Collectors", "DNS Logs"],
          sector: "All Sectors",
        },
        {
          id: "PR-DS-1",
          title: "Data-at-rest Protection",
          nistFunction: "Protect",
          nistControl: "PR.DS-1: Data-at-rest is protected",
          mitreDefense: "D3-DNSCE: Data Loss Prevention",
          priority: "Medium",
          implementation:
            "Enable BitLocker encryption: manage-bde -on C: -RecoveryPassword. Configure database encryption: ALTER DATABASE <database> SET ENCRYPTION ON. Implement file-level encryption with EFS: cipher /e /s:<directory>. Deploy Azure Information Protection: Install-Module AzureInformationProtection; Set-AIPFileClassification",
          timeframe: "3-4 weeks",
          resources: ["BitLocker", "Database Encryption", "EFS", "Azure Information Protection"],
          sector: "Healthcare, Finance",
        },
      ],
      low: [
        {
          id: "ID-GV-1",
          title: "Organizational Cybersecurity Policy",
          nistFunction: "Identify",
          nistControl: "ID.GV-1: Organizational cybersecurity policy is established and communicated",
          mitreDefense: "D3-PSEP: Process Security Enhancement",
          priority: "Low",
          implementation:
            "Develop comprehensive cybersecurity policy framework based on NIST CSF. Create incident response procedures with defined roles and responsibilities. Establish security awareness training program with annual requirements. Implement policy management system with version control and approval workflows. Conduct annual policy review and update cycle.",
          timeframe: "1-3 months",
          resources: ["Policy Management System", "Legal Review", "Compliance Team", "Training Platform"],
          sector: "All Sectors",
        },
        {
          id: "PR-IP-1",
          title: "Baseline Configuration",
          nistFunction: "Protect",
          nistControl:
            "PR.IP-1: A baseline configuration of information technology/industrial control systems is created and maintained",
          mitreDefense: "D3-SCM: System Configuration Monitoring",
          priority: "Low",
          implementation:
            "Develop CIS benchmark-based configuration standards. Create system hardening guides for Windows/Linux/network devices. Implement configuration management database (CMDB). Establish change control procedures for baseline modifications. Deploy configuration compliance monitoring tools.",
          timeframe: "2-4 months",
          resources: ["CIS Benchmarks", "CMDB", "Configuration Management Tools", "Change Control System"],
          sector: "All Sectors",
        },
      ],
    }),
    [],
  )

  // MITRE ATT&CK techniques relevant to current threat level - Much more specific
  const mitreTechniques = useMemo<Record<string, MitreTechnique[]>>(
    () => ({
      critical: [
        {
          id: "T1190",
          name: "Exploit Public-Facing Application",
          tactic: "Initial Access",
          description:
            "Adversaries exploit vulnerabilities in internet-facing applications including web servers, databases, and network devices. Common targets include unpatched CVEs in Apache, IIS, Exchange, and VPN appliances.",
          countermeasures: [
            "Deploy WAF with OWASP Top 10 rules",
            "Implement vulnerability scanning with Nessus/OpenVAS",
            "Configure fail2ban for brute force protection",
            "Enable application-layer DDoS protection",
            "Deploy network segmentation with DMZ isolation",
          ],
          nistMapping: ["SI-4", "RA-5", "SI-2", "SC-7", "SI-3"],
        },
        {
          id: "T1078.004",
          name: "Valid Accounts: Cloud Accounts",
          tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
          description:
            "Adversaries obtain and abuse credentials of cloud service accounts including Azure AD, AWS IAM, and Google Cloud accounts. Often involves credential stuffing, password spraying, or token theft.",
          countermeasures: [
            "Implement Azure AD Conditional Access policies",
            "Deploy AWS CloudTrail with anomaly detection",
            "Configure MFA for all cloud admin accounts",
            "Enable Azure AD Identity Protection",
            "Implement just-in-time (JIT) access with Azure PIM",
          ],
          nistMapping: ["AC-2", "AC-6", "AU-6", "IA-2", "IA-8"],
        },
        {
          id: "T1486",
          name: "Data Encrypted for Impact",
          tactic: "Impact",
          description:
            "Adversaries encrypt data on target systems using ransomware families like Conti, LockBit, or BlackCat. Often preceded by data exfiltration for double extortion.",
          countermeasures: [
            "Implement immutable backups with air-gapped storage",
            "Deploy behavioral analysis with CrowdStrike/SentinelOne",
            "Configure file integrity monitoring (OSSEC/Tripwire)",
            "Enable Windows Defender Controlled Folder Access",
            "Implement network segmentation to limit spread",
          ],
          nistMapping: ["CP-9", "SI-3", "SI-7", "SC-7", "IR-4"],
        },
        {
          id: "T1055.012",
          name: "Process Injection: Process Hollowing",
          tactic: "Defense Evasion, Privilege Escalation",
          description:
            "Adversaries hollow out legitimate processes and replace their memory with malicious code. Common targets include svchost.exe, explorer.exe, and other trusted processes.",
          countermeasures: [
            "Deploy EDR with process injection detection (CrowdStrike Falcon)",
            "Enable Windows Defender Exploit Guard",
            "Configure Sysmon Event ID 8 (CreateRemoteThread)",
            "Implement application control with Windows Defender Application Control",
            "Deploy memory protection with Intel CET/ARM Pointer Authentication",
          ],
          nistMapping: ["SI-4", "SI-3", "CM-7", "AU-6"],
        },
        {
          id: "T1021.001",
          name: "Remote Services: Remote Desktop Protocol",
          tactic: "Lateral Movement",
          description:
            "Adversaries use RDP to move laterally through networks, often after obtaining credentials through credential dumping or brute force attacks.",
          countermeasures: [
            "Implement RDP gateway with MFA",
            "Configure Windows Event ID 4624/4625 monitoring",
            "Deploy network access control (NAC) with 802.1X",
            "Enable RDP encryption and disable clipboard redirection",
            "Implement privileged access workstations (PAWs)",
          ],
          nistMapping: ["AC-17", "AU-6", "SC-8", "AC-6"],
        },
      ],
      elevated: [
        {
          id: "T1566.001",
          name: "Phishing: Spearphishing Attachment",
          tactic: "Initial Access",
          description:
            "Adversaries send targeted emails with malicious attachments including weaponized Office documents, PDFs, or executables disguised as legitimate files.",
          countermeasures: [
            "Deploy Microsoft Defender for Office 365 with Safe Attachments",
            "Configure email security gateway with sandboxing (Proofpoint/Mimecast)",
            "Implement DMARC/SPF/DKIM email authentication",
            "Deploy user training with GoPhish simulations",
            "Enable Office macro blocking via Group Policy",
          ],
          nistMapping: ["AT-2", "SI-8", "SC-7", "SI-3"],
        },
        {
          id: "T1055.001",
          name: "Process Injection: Dynamic-link Library Injection",
          tactic: "Defense Evasion, Privilege Escalation",
          description:
            "Adversaries inject malicious DLLs into running processes using techniques like SetWindowsHookEx, manual DLL loading, or DLL side-loading.",
          countermeasures: [
            "Enable Windows Defender Exploit Guard DLL protection",
            "Deploy Sysmon with Event ID 7 (Image/DLL loaded)",
            "Implement application whitelisting with AppLocker",
            "Configure PowerShell logging and monitoring",
            "Deploy behavioral analysis with Carbon Black/CrowdStrike",
          ],
          nistMapping: ["SI-4", "CM-7", "AU-6", "SI-3"],
        },
        {
          id: "T1003.001",
          name: "OS Credential Dumping: LSASS Memory",
          tactic: "Credential Access",
          description:
            "Adversaries dump credentials from LSASS memory using tools like Mimikatz, ProcDump, or custom techniques to obtain plaintext passwords and hashes.",
          countermeasures: [
            "Enable Windows Defender Credential Guard",
            "Configure LSASS protection with PPL (Protected Process Light)",
            "Deploy Sysmon Event ID 10 (ProcessAccess) monitoring",
            "Implement privileged access workstations (PAWs)",
            "Enable Windows Event ID 4688 with command line logging",
          ],
          nistMapping: ["AC-6", "AU-6", "SI-4", "IA-5"],
        },
        {
          id: "T1059.001",
          name: "Command and Scripting Interpreter: PowerShell",
          tactic: "Execution",
          description:
            "Adversaries abuse PowerShell for execution, including fileless attacks, encoded commands, and living-off-the-land techniques.",
          countermeasures: [
            "Enable PowerShell Script Block Logging (Event ID 4104)",
            "Configure PowerShell Constrained Language Mode",
            "Deploy PowerShell execution policy restrictions",
            "Implement AMSI (Antimalware Scan Interface) monitoring",
            "Configure Sysmon Event ID 1 for PowerShell process creation",
          ],
          nistMapping: ["AU-6", "CM-7", "SI-4", "SI-3"],
        },
      ],
      guarded: [
        {
          id: "T1083",
          name: "File and Directory Discovery",
          tactic: "Discovery",
          description:
            "Adversaries enumerate files and directories to find information of interest including sensitive documents, configuration files, and user data.",
          countermeasures: [
            "Deploy file integrity monitoring with OSSEC/Tripwire",
            "Configure Windows Event ID 4663 (object access auditing)",
            "Implement data loss prevention (DLP) with Microsoft Purview",
            "Enable file access logging on critical systems",
            "Deploy honeypots/canary files for early detection",
          ],
          nistMapping: ["SI-7", "AC-3", "AU-2", "AU-6"],
        },
        {
          id: "T1087.002",
          name: "Account Discovery: Domain Account",
          tactic: "Discovery",
          description:
            "Adversaries attempt to get a listing of domain accounts using tools like net user /domain, PowerView, or LDAP queries.",
          countermeasures: [
            "Enable Windows Event ID 4798 (user's local group membership enumerated)",
            "Configure LDAP query logging on domain controllers",
            "Implement privileged account monitoring with Azure AD",
            "Deploy deception technology with domain admin honeypots",
            "Enable PowerShell logging for Get-ADUser commands",
          ],
          nistMapping: ["AU-6", "AC-2", "SI-4"],
        },
      ],
      low: [
        {
          id: "T1018",
          name: "Remote System Discovery",
          tactic: "Discovery",
          description:
            "Adversaries attempt to get a listing of other systems by IP address, hostname, or other logical identifier using ping sweeps, port scans, or network enumeration.",
          countermeasures: [
            "Deploy network monitoring with Security Onion/Zeek",
            "Configure firewall logging for reconnaissance attempts",
            "Implement network access control (NAC) with device profiling",
            "Enable ICMP monitoring and rate limiting",
            "Deploy network segmentation to limit discovery scope",
          ],
          nistMapping: ["SI-4", "CM-8", "SC-7", "AU-6"],
        },
        {
          id: "T1016",
          name: "System Network Configuration Discovery",
          tactic: "Discovery",
          description:
            "Adversaries look for details about the network configuration and settings of systems including routing tables, network interfaces, and DNS configuration.",
          countermeasures: [
            "Monitor for ipconfig/ifconfig command execution",
            "Configure Windows Event ID 4688 for process creation",
            "Implement network configuration baselines",
            "Deploy configuration monitoring with Nessus/OpenVAS",
            "Enable command line auditing on critical systems",
          ],
          nistMapping: ["AU-6", "CM-2", "SI-4"],
        },
      ],
    }),
    [],
  )

  const currentControls = nistControls[threatLevel] || []
  const currentTechniques = mitreTechniques[threatLevel] || []

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case "critical":
        return "text-[#d92525] bg-red-50 border-red-200"
      case "elevated":
        return "text-amber-700 bg-amber-50 border-amber-200"
      case "guarded":
        return "text-blue-700 bg-blue-50 border-blue-200"
      default:
        return "text-green-700 bg-green-50 border-green-200"
    }
  }

  const getNistFunctionIcon = (func: string) => {
    switch (func) {
      case "Identify":
        return <Search className="h-4 w-4" />
      case "Protect":
        return <Shield className="h-4 w-4" />
      case "Detect":
        return <Eye className="h-4 w-4" />
      case "Respond":
        return <Activity className="h-4 w-4" />
      case "Recover":
        return <RefreshCw className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "Critical":
        return "bg-[#d92525] text-white"
      case "High":
        return "bg-amber-500 text-white"
      case "Medium":
        return "bg-blue-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  return (
    <div className="space-y-6">
      {/* Threat Level Header */}
      <Card
        className={`border-l-4 ${threatLevel === "critical" ? "border-l-[#d92525]" : threatLevel === "elevated" ? "border-l-amber-500" : threatLevel === "guarded" ? "border-l-blue-500" : "border-l-green-500"}`}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security Controls & Recommendations
          </CardTitle>
          <CardDescription>
            NIST Cybersecurity Framework and MITRE ATT&CK based recommendations for CAPRI Level:{" "}
            {capriScore.score.toFixed(1)}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className={`p-4 rounded-lg border ${getThreatLevelColor(threatLevel)}`}>
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-bold text-lg capitalize">{threatLevel} Threat Level</h3>
              <Badge className={getPriorityColor("Critical")}>
                {currentControls.filter((c) => c.priority === "Critical").length} Critical Controls
              </Badge>
            </div>
            <p className="text-sm">{capriScore.rationale}</p>
          </div>
        </CardContent>
      </Card>

      {/* Main Controls Interface */}
      <Tabs defaultValue="controls" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="controls">NIST Controls</TabsTrigger>
          <TabsTrigger value="mitre">MITRE Techniques</TabsTrigger>
          <TabsTrigger value="implementation">Implementation Guide</TabsTrigger>
        </TabsList>

        <TabsContent value="controls">
          <div className="space-y-4">
            {/* Priority Controls */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {["Critical", "High", "Medium", "Low"].map((priority) => {
                const priorityControls = currentControls.filter((c) => c.priority === priority)
                if (priorityControls.length === 0) return null

                return (
                  <Card key={priority}>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Badge className={getPriorityColor(priority)}>{priority} Priority</Badge>
                        <span className="text-sm text-gray-600">({priorityControls.length} controls)</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {priorityControls.map((control) => (
                          <div key={control.id} className="border rounded-lg p-3">
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center gap-2">
                                {getNistFunctionIcon(control.nistFunction)}
                                <h4 className="font-medium text-sm">{control.title}</h4>
                              </div>
                              <Badge variant="outline" className="text-xs">
                                {control.nistControl}
                              </Badge>
                            </div>
                            <p className="text-xs text-gray-600 mb-2">{control.implementation}</p>
                            <div className="flex items-center justify-between text-xs">
                              <div className="flex items-center gap-2">
                                <Clock className="h-3 w-3" />
                                <span>{control.timeframe}</span>
                              </div>
                              <Badge variant="secondary" className="text-xs">
                                {control.nistFunction}
                              </Badge>
                            </div>
                            {control.mitreDefense && (
                              <div className="mt-2 text-xs text-blue-600">MITRE D3FEND: {control.mitreDefense}</div>
                            )}
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="mitre">
          <div className="space-y-4">
            <Alert>
              <Target className="h-4 w-4" />
              <AlertDescription>
                MITRE ATT&CK techniques most relevant to current threat level with corresponding countermeasures
              </AlertDescription>
            </Alert>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {currentTechniques.map((technique) => (
                <Card key={technique.id}>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Badge variant="outline">{technique.id}</Badge>
                      <span className="text-sm">{technique.name}</span>
                    </CardTitle>
                    <CardDescription>{technique.tactic}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-gray-600 mb-3">{technique.description}</p>

                    <div className="space-y-2">
                      <h4 className="font-medium text-sm">Countermeasures:</h4>
                      <div className="flex flex-wrap gap-1">
                        {technique.countermeasures.map((counter) => (
                          <Badge key={counter} variant="secondary" className="text-xs">
                            {counter}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="mt-3 space-y-1">
                      <h4 className="font-medium text-sm">NIST Mapping:</h4>
                      <div className="flex flex-wrap gap-1">
                        {technique.nistMapping.map((nist) => (
                          <Badge key={nist} variant="outline" className="text-xs">
                            {nist}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="implementation">
          <div className="space-y-6">
            {/* Implementation Timeline */}
            <Card>
              <CardHeader>
                <CardTitle>Implementation Timeline</CardTitle>
                <CardDescription>Recommended implementation order based on threat level and priority</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {["0-4 hours", "4-24 hours", "1-7 days", "1-4 weeks", "1-3 months"].map((timeframe) => {
                    const timeframeControls = currentControls.filter(
                      (c) =>
                        c.timeframe.includes(timeframe.split("-")[0]) ||
                        (timeframe.includes("hours") && c.timeframe.includes("hours")) ||
                        (timeframe.includes("days") && c.timeframe.includes("days")) ||
                        (timeframe.includes("weeks") && c.timeframe.includes("weeks")) ||
                        (timeframe.includes("months") && c.timeframe.includes("months")),
                    )

                    if (timeframeControls.length === 0) return null

                    return (
                      <div key={timeframe} className="border-l-4 border-l-blue-500 pl-4">
                        <h3 className="font-medium text-blue-700 mb-2">{timeframe}</h3>
                        <div className="space-y-2">
                          {timeframeControls.map((control) => (
                            <div key={control.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                              <div className="flex items-center gap-2">
                                <Badge className={getPriorityColor(control.priority)} variant="default">
                                  {control.priority}
                                </Badge>
                                <span className="text-sm">{control.title}</span>
                              </div>
                              <Badge variant="outline">{control.nistControl}</Badge>
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Resource Requirements */}
            <Card>
              <CardHeader>
                <CardTitle>Resource Requirements</CardTitle>
                <CardDescription>Tools, teams, and resources needed for implementation</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <h4 className="font-medium mb-2 flex items-center gap-2">
                      <Database className="h-4 w-4" />
                      Technology
                    </h4>
                    <div className="space-y-1">
                      {Array.from(
                        new Set(
                          currentControls.flatMap((c) =>
                            c.resources.filter(
                              (r) =>
                                r.includes("System") ||
                                r.includes("Tool") ||
                                r.includes("Platform") ||
                                r.includes("Scanner"),
                            ),
                          ),
                        ),
                      ).map((resource) => (
                        <Badge key={resource} variant="outline" className="text-xs mr-1 mb-1">
                          {resource}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2 flex items-center gap-2">
                      <Users className="h-4 w-4" />
                      Teams
                    </h4>
                    <div className="space-y-1">
                      {Array.from(
                        new Set(
                          currentControls.flatMap((c) =>
                            c.resources.filter(
                              (r) => r.includes("Team") || r.includes("Administrators") || r.includes("Analysts"),
                            ),
                          ),
                        ),
                      ).map((resource) => (
                        <Badge key={resource} variant="outline" className="text-xs mr-1 mb-1">
                          {resource}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2 flex items-center gap-2">
                      <Network className="h-4 w-4" />
                      Infrastructure
                    </h4>
                    <div className="space-y-1">
                      {Array.from(
                        new Set(
                          currentControls.flatMap((c) =>
                            c.resources.filter(
                              (r) =>
                                r.includes("Network") ||
                                r.includes("Firewall") ||
                                r.includes("SIEM") ||
                                r.includes("EDR"),
                            ),
                          ),
                        ),
                      ).map((resource) => (
                        <Badge key={resource} variant="outline" className="text-xs mr-1 mb-1">
                          {resource}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
