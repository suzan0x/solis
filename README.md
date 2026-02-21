# SOLIS — System Security Auditor

![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)
![Python](https://img.shields.io/badge/python-3.8+-3776AB?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight Windows security auditing tool that scans your system for common misconfigurations, maps findings to MITRE ATT&CK, and generates a detailed HTML report with a security score.

Built for security professionals, sysadmins, and anyone who wants a quick security posture assessment without installing heavy enterprise tools.

## Features

- **10 scan modules** covering OS config, endpoint security, network, users, storage, and more
- **Security score** (0–100) with letter grades (A–F) based on weighted checks
- **MITRE ATT&CK mapping** for every finding
- **Actionable remediation** — each issue comes with step-by-step fix instructions and PowerShell commands
- **Scan comparison** — tracks changes between scans (new issues, resolved issues, score delta)
- **PDF export** — one-click export to PDF via the browser print dialog
- **Dark-themed HTML report** — clean, corporate design with collapsible sections
- **Zero dependencies** beyond `psutil` — no web server, no database, just run and get a report

## Quick Start

```bash
git clone https://github.com/suzan0x/solis.git
cd solis
pip install -r requirements.txt
python solis.py --open
```

The report will open automatically in your browser.

## Scan Modules

| # | Module | What it checks |
|---|--------|---------------|
| 1 | **System Info** | OS version, CPU, RAM, uptime, admin status |
| 2 | **Security Status** | Windows Defender, real-time protection, firewall profiles, UAC, Secure Boot |
| 3 | **Process Analysis** | Running processes, suspicious process detection (mimikatz, cobalt strike, etc.) |
| 4 | **Network Analysis** | Active connections, open ports, suspicious ports, LAN device discovery (ARP) |
| 5 | **Windows Updates** | Last 10 hotfixes with install dates |
| 6 | **Installed Software** | Full software inventory from registry |
| 7 | **Startup Programs** | Run/RunOnce registry keys (HKLM + HKCU) |
| 8 | **User Accounts** | Local accounts, admin membership, password policy, active sessions |
| 9 | **Storage & Encryption** | Disk usage, BitLocker encryption status |
| 10 | **USB History** | Previously connected USB storage devices |

## MITRE ATT&CK Mapping

Findings are mapped to relevant techniques:

| Finding | MITRE Technique |
|---------|----------------|
| Defender disabled | T1562.001 — Disable or Modify Tools |
| Firewall disabled | T1562.004 — Disable or Modify Firewall |
| Suspicious process | T1059 — Command and Scripting Interpreter |
| Suspicious port | T1571 — Non-Standard Port |
| No password set | T1078 — Valid Accounts |
| Startup persistence | T1547.001 — Registry Run Keys |
| No disk encryption | T1005 — Data from Local System |
| UAC disabled | T1548.002 — Bypass UAC |

## Remediation Engine

Every finding includes:
- **Risk explanation** — why this matters in plain English
- **Step-by-step remediation** — what to do to fix it
- **PowerShell command** — copy-paste fix where applicable

Example output for "Disk not encrypted":
> **Enable BitLocker disk encryption**
> If the PC is lost or stolen, all data on disk is accessible.
> 1. Open Control Panel > BitLocker Drive Encryption
> 2. Click "Turn on BitLocker" for the system drive (C:)
> 3. Save the recovery key
> ```powershell
> Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly
> ```

## Scan Comparison

Run SOLIS multiple times to track your security posture over time. The report automatically compares with the previous scan and shows:
- Score change (↑/↓ with point delta)
- Newly detected issues
- Resolved issues
- Individual check status changes

## Usage

```
python solis.py [OPTIONS]

Options:
  --open           Open the report in your default browser after scan
  --output, -o     Output directory for reports (default: reports/)
```

## Project Structure

```
solis/
├── solis.py              # entry point, CLI args, comparison logic
├── scanner/
│   ├── __init__.py
│   ├── core.py           # main scanner with all 10 modules
│   ├── console.py        # terminal output (colors, progress, banner)
│   ├── constants.py      # threat signatures, port lists, MITRE mapping, remediation data
│   └── report.py         # HTML report generator
├── reports/              # generated reports and scan JSON (gitignored)
├── requirements.txt
├── LICENSE
└── README.md
```

## Requirements

- Python 3.8+
- Windows 10/11
- `psutil` (installed via `pip install -r requirements.txt`)

Some checks (BitLocker, Secure Boot) require administrator privileges for full results. The tool works in standard user mode but will note limited checks.

## Use Cases

- **Security assessments** — quick baseline check before a pentest engagement
- **Hardening verification** — confirm security controls are enabled after deployment
- **Compliance auditing** — check against common security baselines
- **Incident response** — rapid triage of a potentially compromised system
- **IT onboarding** — verify new workstations meet security requirements

## License

MIT — see [LICENSE](LICENSE) for details.
