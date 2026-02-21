# Threat signatures and reference data for SOLIS scanner
# Port lists pulled from common pentest cheatsheets + personal experience
# Process names come from known offensive tooling (LOLBAS, impacket, etc.)

SUSPICIOUS_PROCESSES = {
    'mimikatz.exe', 'meterpreter.exe', 'cobaltstrike.exe',
    'beacon.exe', 'nc.exe', 'ncat.exe', 'netcat.exe',
    'psexec.exe', 'psexesvc.exe', 'procdump.exe',
    'lazagne.exe', 'keylogger.exe', 'xmrig.exe',
    'minergate.exe', 'cryptonight.exe', 'minerd.exe',
    'rat.exe', 'backdoor.exe', 'trojan.exe',
    'havoc.exe', 'sliver.exe', 'brute.exe',
    'hydra.exe', 'john.exe', 'hashcat.exe',
    'wce.exe', 'pwdump.exe', 'fgdump.exe',
    'gsecdump.exe', 'bloodhound.exe', 'sharphound.exe',
    'rubeus.exe', 'seatbelt.exe', 'certify.exe',
    'winpeas.exe', 'chisel.exe', 'ligolo.exe',
}

# ports commonly used by C2 frameworks, RATs, miners, etc.
SUSPICIOUS_PORTS = {
    4444: 'Metasploit Default',
    4445: 'Metasploit Alt',
    5555: 'Common RAT',
    1337: 'Common Backdoor',
    31337: 'Back Orifice',
    12345: 'NetBus',
    27374: 'SubSeven',
    6666: 'IRC Backdoor',
    6667: 'IRC C2',
    9001: 'Tor',
    9050: 'Tor SOCKS',
    50050: 'Cobalt Strike',
    2222: 'Alt SSH',
    3333: 'Mining Pool',
    8888: 'Common Backdoor',
    7777: 'Common RAT',
}

# standard service ports we want to track in the open ports table
MONITORED_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM-S',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
}

# mapping findings to MITRE ATT&CK technique IDs
MITRE_MAP = {
    'defender_disabled': 'T1562.001 - Disable or Modify Tools',
    'firewall_disabled': 'T1562.004 - Disable or Modify Firewall',
    'suspicious_process': 'T1059 - Command and Scripting Interpreter',
    'suspicious_port': 'T1571 - Non-Standard Port',
    'no_password': 'T1078 - Valid Accounts',
    'startup_persistence': 'T1547.001 - Registry Run Keys',
    'no_encryption': 'T1005 - Data from Local System',
    'uac_disabled': 'T1548.002 - Bypass UAC',
}

# remediation steps for each finding type
# each entry has: what to do, why it matters, step-by-step fix, and a powershell one-liner where possible
RECOMMENDATIONS = {
    'defender_disabled': {
        'summary': 'Enable Windows Defender',
        'risk': 'Without an antivirus, the system is exposed to malware, ransomware and other threats.',
        'steps': [
            'Open Settings > Update & Security > Windows Security',
            'Click "Virus & threat protection"',
            'Turn on "Real-time protection"',
        ],
        'command': 'Set-MpPreference -DisableRealtimeMonitoring $false',
    },
    'realtime_disabled': {
        'summary': 'Enable real-time protection',
        'risk': 'Files are not scanned on access, allowing malware to execute unchecked.',
        'steps': [
            'Open Windows Security > Virus & threat protection',
            'Under "Protection settings", enable "Real-time protection"',
        ],
        'command': 'Set-MpPreference -DisableRealtimeMonitoring $false',
    },
    'firewall_disabled': {
        'summary': 'Enable Windows Firewall',
        'risk': 'The system accepts all inbound connections without filtering.',
        'steps': [
            'Open Control Panel > System and Security > Windows Defender Firewall',
            'Click "Turn Windows Defender Firewall on or off"',
            'Enable the firewall for all profiles (Domain, Private, Public)',
        ],
        'command': 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True',
    },
    'uac_disabled': {
        'summary': 'Enable User Account Control (UAC)',
        'risk': 'Programs can run with elevated privileges without user confirmation.',
        'steps': [
            'Open Control Panel > User Accounts',
            'Click "Change User Account Control settings"',
            'Set the slider to "Always notify" or a middle level',
        ],
        'command': r'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f',
    },
    'secure_boot_disabled': {
        'summary': 'Enable Secure Boot in BIOS/UEFI',
        'risk': 'Unsigned code can run at boot time (bootkits, UEFI rootkits).',
        'steps': [
            'Restart the PC and enter BIOS/UEFI (usually Del, F2 or F12 at boot)',
            'Look for "Secure Boot" under Security or Boot tab',
            'Enable Secure Boot and save',
        ],
        'command': None,
    },
    'suspicious_process': {
        'summary': 'Investigate and kill the suspicious process',
        'risk': 'This process matches known offensive/pentest tooling signatures.',
        'steps': [
            'Check the full executable path — is it legitimate?',
            'Verify the digital signature of the file',
            'If not legitimate: kill the process and delete the binary',
            'Run a full antivirus scan',
            'Check network connections for the process (netstat -ano)',
        ],
        'command': 'Stop-Process -Name "<process_name>" -Force',
    },
    'suspicious_port': {
        'summary': 'Investigate the suspicious open port',
        'risk': 'This port is commonly used by offensive tools (C2, RAT, backdoor).',
        'steps': [
            'Identify the process using this port: netstat -ano | findstr <port>',
            'Verify the process is legitimate',
            'Block the port in the firewall if not needed',
            'Look for other signs of compromise (logs, outbound connections)',
        ],
        'command': 'New-NetFirewallRule -DisplayName "Block Port <port>" -Direction Inbound -LocalPort <port> -Protocol TCP -Action Block',
    },
    'no_password': {
        'summary': 'Set a password on the account',
        'risk': 'Anyone can log in with this account without authentication.',
        'steps': [
            'Open Settings > Accounts > Sign-in options',
            'Set a strong password (12+ chars, upper, digits, symbols)',
            'Consider enabling Windows Hello or a PIN',
        ],
        'command': 'net user <username> *',
    },
    'no_encryption': {
        'summary': 'Enable BitLocker disk encryption',
        'risk': 'If the PC is lost or stolen, all data on disk is accessible.',
        'steps': [
            'Open Control Panel > BitLocker Drive Encryption',
            'Click "Turn on BitLocker" for the system drive (C:)',
            'Save the recovery key (Microsoft account, USB, or print it)',
            'Choose "Encrypt entire drive" for maximum protection',
        ],
        'command': 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly',
    },
    'many_startup': {
        'summary': 'Reduce startup programs',
        'risk': 'Increases attack surface and slows down boot time.',
        'steps': [
            'Open Task Manager (Ctrl+Shift+Esc) > Startup tab',
            'Disable non-essential programs',
            'Verify remaining programs are legitimate and up to date',
        ],
        'command': None,
    },
}
