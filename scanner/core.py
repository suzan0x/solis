# main scanner logic — runs each check module and collects results
# designed for Windows, uses powershell + psutil + registry queries
# try to keep each scan method self-contained so they're easy to extend

import datetime
import json
import ctypes
import subprocess
import time
import os
import socket
import winreg
import platform
import psutil

from .console import ConsoleUI
from .constants import (
    SUSPICIOUS_PROCESSES, SUSPICIOUS_PORTS,
    MONITORED_PORTS, MITRE_MAP, RECOMMENDATIONS
)


class SolisScanner:
    """Runs all security checks and builds a results dict for the report."""

    def __init__(self):
        self.results = {}
        self.score_details = []
        self.findings = []
        self.scan_time = datetime.datetime.now()
        self.is_admin = self._check_admin()
        self.ui = ConsoleUI()

    # -- helpers --

    def _check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _ps(self, cmd, timeout=30):
        """Run a powershell command, return stdout as string.
        Force UTF-8 output to avoid encoding issues with non-ASCII program names."""
        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '[Console]::OutputEncoding=[Text.Encoding]::UTF8;' + cmd],
                capture_output=True, timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return r.stdout.decode('utf-8', errors='replace').strip()
        except Exception:
            return ""

    def _cmd(self, command, timeout=30):
        """Run a regular cmd command."""
        try:
            r = subprocess.run(
                command, capture_output=True, text=True,
                timeout=timeout, shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return r.stdout.strip()
        except Exception:
            return ""

    def _finding(self, category, severity, title, detail, mitre=None, rec_key=None):
        """Register a security finding with optional recommendation."""
        rec = RECOMMENDATIONS.get(rec_key, {}) if rec_key else {}
        self.findings.append({
            'category': category, 'severity': severity,
            'title': title, 'detail': detail,
            'mitre': mitre or '', 'recommendation': rec,
        })

    def _score(self, check, passed, points, detail=""):
        """Add a scored check (pass/fail with point value)."""
        self.score_details.append({
            'check': check, 'passed': passed,
            'points': points if passed else 0,
            'max_points': points, 'detail': detail,
        })

    def _parse_ps_date(self, val):
        """PowerShell serializes dates as /Date(timestamp)/ — handle that."""
        if isinstance(val, str) and '/Date(' in val:
            try:
                ts = int(val.split('(')[1].split(')')[0]) / 1000
                return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
            except Exception:
                return str(val)
        if isinstance(val, dict) and 'value' in val:
            return self._parse_ps_date(val['value'])
        return val or 'N/A'

    # -- scan modules --

    def scan_system_info(self):
        self.ui.section("System Information", "🖥️")
        self.ui.progress("Collecting system info")

        u = platform.uname()
        boot = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot
        ram = psutil.virtual_memory()
        freq = psutil.cpu_freq()

        self.results['system'] = {
            'hostname': u.node,
            'os': f"{u.system} {u.release}",
            'os_version': platform.version(),
            'os_edition': getattr(platform, 'win32_edition', lambda: 'N/A')(),
            'architecture': u.machine,
            'processor': u.processor or platform.processor(),
            'cpu_cores': psutil.cpu_count(logical=False),
            'cpu_threads': psutil.cpu_count(logical=True),
            'cpu_freq': round(freq.current) if freq else 'N/A',
            'ram_total': round(ram.total / (1024**3), 1),
            'ram_used': round(ram.used / (1024**3), 1),
            'ram_percent': ram.percent,
            'boot_time': boot.strftime('%Y-%m-%d %H:%M:%S'),
            'uptime': str(uptime).split('.')[0],
            'is_admin': self.is_admin,
        }

        self.ui.done(f"OS: {u.system} {u.release} ({u.machine})")
        self.ui.info(f"Hostname: {u.node}")
        self.ui.info(f"CPU: {psutil.cpu_count(logical=False)}C/{psutil.cpu_count(logical=True)}T")
        self.ui.info(f"RAM: {ram.percent}% ({round(ram.used/(1024**3),1)}/{round(ram.total/(1024**3),1)} GB)")
        self.ui.info(f"Uptime: {str(uptime).split('.')[0]}")

        if not self.is_admin:
            self.ui.warn("Running as standard user — some checks will be limited")

    def scan_security(self):
        self.ui.section("Security Status", "🛡️")
        sec = {}

        # windows defender
        self.ui.progress("Checking Windows Defender")
        out = self._ps(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
            "RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,"
            "QuickScanEndTime | ConvertTo-Json"
        )
        if out:
            try:
                d = json.loads(out)
                sec['defender'] = d.get('AntivirusEnabled', False)
                sec['realtime'] = d.get('RealTimeProtectionEnabled', False)
                sec['sig_date'] = self._parse_ps_date(d.get('AntivirusSignatureLastUpdated'))
                sec['last_scan'] = self._parse_ps_date(d.get('QuickScanEndTime'))

                if sec['defender']:
                    self.ui.ok("Windows Defender: Enabled")
                    self._score("Windows Defender", True, 15)
                else:
                    self.ui.fail("Windows Defender: Disabled")
                    self._score("Windows Defender", False, 15)
                    self._finding("Security", "critical", "Windows Defender disabled",
                                  "Antivirus is not enabled on this system.",
                                  MITRE_MAP['defender_disabled'], 'defender_disabled')

                if sec['realtime']:
                    self.ui.ok("Real-time protection: Enabled")
                    self._score("Real-time protection", True, 10)
                else:
                    self.ui.fail("Real-time protection: Disabled")
                    self._score("Real-time protection", False, 10)
                    self._finding("Security", "critical", "Real-time protection disabled",
                                  "Real-time protection is turned off.",
                                  MITRE_MAP['defender_disabled'], 'realtime_disabled')
            except json.JSONDecodeError:
                sec['defender'] = None
                self.ui.warn("Could not parse Defender status")
        else:
            sec['defender'] = None
            self.ui.warn("Windows Defender: unable to check (need admin?)")
            self._score("Windows Defender", False, 15, "Not verifiable")

        # firewall profiles
        self.ui.progress("Checking Firewall")
        out = self._ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
        sec['firewall'] = {}
        if out:
            try:
                profiles = json.loads(out)
                if not isinstance(profiles, list):
                    profiles = [profiles]
                all_ok = True
                for p in profiles:
                    name = p.get('Name', '?')
                    on = p.get('Enabled', False)
                    if isinstance(on, int):
                        on = on == 1
                    sec['firewall'][name] = on
                    if on:
                        self.ui.ok(f"Firewall {name}: Enabled")
                    else:
                        self.ui.fail(f"Firewall {name}: Disabled")
                        all_ok = False
                self._score("Firewall", all_ok, 15)
                if not all_ok:
                    self._finding("Security", "high", "Firewall partially disabled",
                                  "One or more firewall profiles are disabled.",
                                  MITRE_MAP['firewall_disabled'], 'firewall_disabled')
            except json.JSONDecodeError:
                self.ui.warn("Firewall: could not parse")

        # UAC — check via registry
        self.ui.progress("Checking UAC")
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            val, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            sec['uac'] = bool(val)
            if sec['uac']:
                self.ui.ok("UAC: Enabled")
                self._score("UAC", True, 10)
            else:
                self.ui.fail("UAC: Disabled")
                self._score("UAC", False, 10)
                self._finding("Security", "high", "UAC disabled",
                              "User Account Control is turned off.",
                              MITRE_MAP['uac_disabled'], 'uac_disabled')
        except Exception:
            sec['uac'] = None
            self.ui.warn("UAC: unable to check")

        # secure boot — needs UEFI
        self.ui.progress("Checking Secure Boot")
        out = self._ps("try { Confirm-SecureBootUEFI } catch { 'N/A' }")
        if out.lower() == 'true':
            sec['secure_boot'] = True
            self.ui.ok("Secure Boot: Enabled")
            self._score("Secure Boot", True, 5)
        elif out.lower() == 'false':
            sec['secure_boot'] = False
            self.ui.warn("Secure Boot: Disabled")
            self._score("Secure Boot", False, 5)
        else:
            sec['secure_boot'] = None
            self.ui.info("Secure Boot: Not supported / unable to verify")

        self.results['security'] = sec

    def scan_processes(self):
        self.ui.section("Process Analysis", "⚙️")
        self.ui.progress("Enumerating running processes")

        procs, suspicious, high_cpu, high_mem = [], [], [], []

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'exe']):
            try:
                i = proc.info
                p = {
                    'pid': i['pid'], 'name': i['name'] or '?',
                    'cpu': round(i['cpu_percent'] or 0, 1),
                    'memory': round(i['memory_percent'] or 0, 1),
                    'user': (i['username'] or 'N/A').split('\\')[-1],
                    'exe': i['exe'] or 'N/A',
                }
                procs.append(p)

                # check against known bad process names
                if i['name'] and i['name'].lower() in SUSPICIOUS_PROCESSES:
                    suspicious.append(p)
                    self._finding("Processes", "critical",
                                  f"Suspicious process: {i['name']}",
                                  f"PID {i['pid']}, User: {i['username']}, Path: {i['exe']}",
                                  MITRE_MAP['suspicious_process'], 'suspicious_process')
                if (i['cpu_percent'] or 0) > 80:
                    high_cpu.append(p)
                if (i['memory_percent'] or 0) > 20:
                    high_mem.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        procs.sort(key=lambda x: x['memory'], reverse=True)

        self.results['processes'] = {
            'total': len(procs), 'top': procs[:15],
            'suspicious': suspicious,
            'high_cpu': high_cpu[:5], 'high_mem': high_mem[:5],
        }

        self.ui.done(f"{len(procs)} running processes")
        if suspicious:
            for s in suspicious:
                self.ui.fail(f"SUSPICIOUS: {s['name']} (PID {s['pid']})")
            self._score("No suspicious processes", False, 15)
        else:
            self.ui.ok("No suspicious processes detected")
            self._score("No suspicious processes", True, 15)

        for p in high_cpu:
            self.ui.warn(f"High CPU: {p['name']} ({p['cpu']}%)")

    def scan_network(self):
        self.ui.section("Network Analysis", "🌐")

        # grab network interfaces with IPv4
        self.ui.progress("Listing network interfaces")
        interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            info = {'name': iface}
            for a in addrs:
                if a.family == socket.AF_INET:
                    info['ipv4'] = a.address
                    info['netmask'] = a.netmask
            if info.get('ipv4'):
                interfaces.append(info)

        # enumerate all connections and flag suspicious ones
        self.ui.progress("Scanning active connections")
        conns, suspicious_conns = [], []
        for c in psutil.net_connections(kind='all'):
            try:
                entry = {
                    'type': 'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                    'local': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else '-',
                    'local_port': c.laddr.port if c.laddr else None,
                    'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else '-',
                    'status': c.status, 'pid': c.pid,
                    'process': 'N/A',
                }
                if c.pid:
                    try:
                        entry['process'] = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                conns.append(entry)

                lp = c.laddr.port if c.laddr else None
                if lp and lp in SUSPICIOUS_PORTS:
                    entry['reason'] = f"Port {lp}: {SUSPICIOUS_PORTS[lp]}"
                    suspicious_conns.append(entry)
                    self._finding("Network", "high", f"Suspicious port: {lp}",
                                  f"{SUSPICIOUS_PORTS[lp]} — {entry['process']} (PID {c.pid})",
                                  MITRE_MAP['suspicious_port'], 'suspicious_port')
            except Exception:
                pass

        listening = [c for c in conns if c['status'] == 'LISTEN']
        established = [c for c in conns if c['status'] == 'ESTABLISHED']

        # build unique open ports list
        seen, open_ports = set(), []
        for c in listening:
            port = c['local_port']
            if port and port not in seen:
                seen.add(port)
                svc = MONITORED_PORTS.get(port, SUSPICIOUS_PORTS.get(port, 'Unknown'))
                open_ports.append({'port': port, 'service': svc,
                                   'process': c['process'], 'suspicious': port in SUSPICIOUS_PORTS})
        open_ports.sort(key=lambda x: x['port'])

        # ARP table for LAN device discovery
        self.ui.progress("Scanning local network (ARP)")
        arp = self._cmd("arp -a")
        devices = []
        if arp:
            for line in arp.split('\n'):
                parts = line.split()
                if len(parts) >= 3 and '.' in parts[0] and '-' in parts[1]:
                    devices.append({'ip': parts[0], 'mac': parts[1], 'type': parts[2]})

        self.results['network'] = {
            'interfaces': interfaces, 'total_conns': len(conns),
            'listening': len(listening), 'established': len(established),
            'suspicious': suspicious_conns, 'open_ports': open_ports,
            'devices': devices,
        }

        self.ui.done(f"{len(interfaces)} active interfaces")
        self.ui.info(f"{len(conns)} connections ({len(listening)} listening, {len(established)} established)")
        self.ui.info(f"{len(open_ports)} open ports · {len(devices)} LAN devices")

        if suspicious_conns:
            self._score("No suspicious ports", False, 10)
        else:
            self.ui.ok("No suspicious ports detected")
            self._score("No suspicious ports", True, 10)

    def scan_updates(self):
        self.ui.section("Windows Updates", "🔄")
        self.ui.progress("Checking update history")

        out = self._ps(
            "Get-HotFix | Sort-Object InstalledOn -Descending -EA SilentlyContinue | "
            "Select-Object -First 10 HotFixID,Description,InstalledOn | ConvertTo-Json", timeout=60
        )
        updates = []
        if out:
            try:
                items = json.loads(out)
                if not isinstance(items, list):
                    items = [items]
                for u in items:
                    updates.append({
                        'id': u.get('HotFixID', '?'),
                        'desc': u.get('Description', '?'),
                        'date': self._parse_ps_date(u.get('InstalledOn')),
                    })
            except Exception:
                pass

        self.results['updates'] = {
            'build': platform.version(),
            'list': updates,
            'last_date': updates[0]['date'] if updates else 'N/A',
        }

        if updates:
            self.ui.done(f"Latest: {updates[0]['id']} ({updates[0]['date']})")
            for u in updates[:5]:
                self.ui.info(f"{u['id']} — {u['desc']} ({u['date']})")
        else:
            self.ui.warn("Update history unavailable")

    def scan_software(self):
        self.ui.section("Installed Software", "📦")
        self.ui.progress("Enumerating programs from registry")

        out = self._ps(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Where-Object { $_.DisplayName } | "
            "Select-Object DisplayName,DisplayVersion,Publisher | "
            "Sort-Object DisplayName | ConvertTo-Json", timeout=30
        )
        sw = []
        if out:
            try:
                items = json.loads(out)
                if not isinstance(items, list):
                    items = [items]
                for s in items:
                    sw.append({
                        'name': s.get('DisplayName', '?'),
                        'version': s.get('DisplayVersion', '?'),
                        'publisher': s.get('Publisher', '?'),
                    })
            except Exception:
                pass

        self.results['software'] = {'total': len(sw), 'list': sw}
        self.ui.done(f"{len(sw)} programs installed")

    def scan_startup(self):
        self.ui.section("Startup Programs", "🚀")
        self.ui.progress("Reading registry Run keys")

        items = []
        for hive_name, hive in [("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)]:
            for path in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"]:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            items.append({'name': name, 'command': value,
                                          'location': f"{hive_name}\\{path.split(chr(92))[-1]}",
                                          'user': 'System' if hive_name == 'HKLM' else 'User'})
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass

        self.results['startup'] = {'total': len(items), 'list': items}
        self.ui.done(f"{len(items)} startup programs")

        if len(items) > 15:
            self.ui.warn(f"High number of startup programs ({len(items)})")
            self._finding("System", "low", "Many startup programs",
                          f"{len(items)} programs configured to run at startup.",
                          MITRE_MAP['startup_persistence'], 'many_startup')

    def scan_users(self):
        self.ui.section("User Accounts", "👤")
        self.ui.progress("Enumerating local accounts")

        out = self._ps(
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon,"
            "PasswordRequired,Description | ConvertTo-Json"
        )
        users, admin_count = [], 0

        # figure out who's in the Administrators group
        admin_names = set()
        admin_out = self._ps(
            "Get-LocalGroupMember -Group 'Administrators' -EA SilentlyContinue | "
            "Select-Object Name | ConvertTo-Json"
        )
        if admin_out:
            try:
                admins = json.loads(admin_out)
                if not isinstance(admins, list):
                    admins = [admins]
                for a in admins:
                    n = a.get('Name', '').split('\\')[-1]
                    admin_names.add(n.lower())
            except Exception:
                pass

        if out:
            try:
                items = json.loads(out)
                if not isinstance(items, list):
                    items = [items]
                for u in items:
                    name = u.get('Name', '?')
                    is_admin = name.lower() in admin_names
                    if is_admin:
                        admin_count += 1
                    users.append({
                        'name': name,
                        'enabled': u.get('Enabled', False),
                        'is_admin': is_admin,
                        'last_logon': self._parse_ps_date(u.get('LastLogon')),
                        'pwd_required': u.get('PasswordRequired', False),
                        'desc': u.get('Description', ''),
                    })
                    # flag accounts with no password
                    if u.get('Enabled') and not u.get('PasswordRequired'):
                        self._finding("Users", "high", f"Account without password: {name}",
                                      f"Account '{name}' is active with no password required.",
                                      MITRE_MAP['no_password'], 'no_password')
            except Exception:
                pass

        logged_in = []
        for u in psutil.users():
            logged_in.append({
                'name': u.name,
                'started': datetime.datetime.fromtimestamp(u.started).strftime('%Y-%m-%d %H:%M'),
            })

        self.results['users'] = {
            'total': len(users), 'admins': admin_count,
            'list': users, 'logged_in': logged_in,
        }

        self.ui.done(f"{len(users)} accounts ({admin_count} admins)")
        self.ui.info(f"{len(logged_in)} active session(s)")

    def scan_disks(self):
        self.ui.section("Storage & Encryption", "💾")
        self.ui.progress("Checking disk partitions")

        disks = []
        for part in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(part.mountpoint)
                disks.append({
                    'mount': part.mountpoint, 'fs': part.fstype,
                    'total': round(u.total / (1024**3), 1),
                    'used': round(u.used / (1024**3), 1),
                    'free': round(u.free / (1024**3), 1),
                    'percent': u.percent,
                })
            except Exception:
                pass

        # bitlocker status
        self.ui.progress("Checking BitLocker")
        bl_out = self._ps(
            "Get-BitLockerVolume -EA SilentlyContinue | "
            "Select-Object MountPoint,ProtectionStatus,EncryptionMethod | ConvertTo-Json"
        )
        bitlocker = {}
        bl_enabled = False
        if bl_out:
            try:
                items = json.loads(bl_out)
                if not isinstance(items, list):
                    items = [items]
                for v in items:
                    mp = v.get('MountPoint', '?')
                    prot = v.get('ProtectionStatus', 0) == 1
                    bitlocker[mp] = {'protected': prot, 'method': str(v.get('EncryptionMethod', 'N/A'))}
                    if prot:
                        bl_enabled = True
            except Exception:
                pass

        self.results['disks'] = {'partitions': disks, 'bitlocker': bitlocker, 'bl_enabled': bl_enabled}

        for d in disks:
            self.ui.info(f"{d['mount']} ({d['fs']}) — {d['used']}/{d['total']} GB ({d['percent']}%)")
            bl = bitlocker.get(d['mount'], {})
            if bl.get('protected'):
                self.ui.ok(f"  BitLocker: Active")
            elif bl:
                self.ui.warn(f"  BitLocker: Not protected")

        self._score("Disk encryption", bl_enabled, 10)
        if not bl_enabled:
            self._finding("Storage", "medium", "Disk not encrypted",
                          "BitLocker is not enabled. Data is vulnerable if the device is stolen.",
                          MITRE_MAP['no_encryption'], 'no_encryption')

    def scan_usb(self):
        self.ui.section("USB History", "🔌")
        self.ui.progress("Reading USB registry entries")

        devices = []
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(key, i)
                    parts = sub_name.split('&')
                    vendor = parts[1].replace('Ven_', '') if len(parts) > 1 else '?'
                    product = parts[2].replace('Prod_', '') if len(parts) > 2 else '?'
                    try:
                        subkey = winreg.OpenKey(key, sub_name)
                        j = 0
                        while True:
                            try:
                                serial = winreg.EnumKey(subkey, j)
                                devices.append({'vendor': vendor, 'product': product,
                                                'serial': serial[:16]})
                                j += 1
                            except OSError:
                                break
                        winreg.CloseKey(subkey)
                    except Exception:
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

        self.results['usb'] = {'total': len(devices), 'devices': devices}
        self.ui.done(f"{len(devices)} USB devices in history")
        for d in devices[:5]:
            self.ui.info(f"{d['vendor']} {d['product']}")
        if len(devices) > 5:
            self.ui.info(f"... and {len(devices) - 5} more")

    # -- scoring --

    def calculate_score(self):
        total = sum(s['max_points'] for s in self.score_details)
        earned = sum(s['points'] for s in self.score_details)
        self.score = round((earned / total) * 100) if total > 0 else 0

        grade = 'A' if self.score >= 90 else 'B' if self.score >= 80 else \
                'C' if self.score >= 70 else 'D' if self.score >= 60 else 'F'

        self.results['score'] = {
            'value': self.score, 'earned': earned, 'total': total,
            'grade': grade, 'details': self.score_details,
        }
        self.results['findings'] = self.findings
        self.results['scan_time'] = self.scan_time.strftime('%Y-%m-%d %H:%M:%S')

    def save_json(self, output_dir='reports'):
        """Dump results to JSON so we can compare between scans."""
        os.makedirs(output_dir, exist_ok=True)
        latest = os.path.join(output_dir, 'latest_scan.json')
        previous = os.path.join(output_dir, 'previous_scan.json')
        if os.path.exists(latest):
            import shutil
            shutil.copy2(latest, previous)
        with open(latest, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2, default=str)
        return latest

    @staticmethod
    def load_previous(output_dir='reports'):
        """Load the previous scan for diff/comparison."""
        previous = os.path.join(output_dir, 'previous_scan.json')
        if os.path.exists(previous):
            try:
                with open(previous, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    # -- main entry point --

    def run(self):
        ConsoleUI.enable_colors()
        ConsoleUI.banner()
        c = ConsoleUI.C

        print(f"  {c['dim']}Scan started: {self.scan_time.strftime('%H:%M:%S')}{c['reset']}")
        if self.is_admin:
            print(f"  {c['green']}▶ Running as Administrator{c['reset']}")
        else:
            print(f"  {c['yellow']}▶ Running as standard user{c['reset']}")

        start = time.time()

        self.scan_system_info()
        self.scan_security()
        self.scan_processes()
        self.scan_network()
        self.scan_updates()
        self.scan_software()
        self.scan_startup()
        self.scan_users()
        self.scan_disks()
        self.scan_usb()
        self.calculate_score()

        elapsed = round(time.time() - start, 1)
        score = self.score
        grade = self.results['score']['grade']

        sc = c['green'] if score >= 80 else c['yellow'] if score >= 60 else c['red']

        self.ui.section("Results", "📊")
        print(f"""
  {sc}{c['bold']}  ┌───────────────────────────────────┐
  │   SECURITY SCORE:   {score:>3} / 100     │
  │          Grade:  {grade}                │
  └───────────────────────────────────┘{c['reset']}
        """)

        crit = len([f for f in self.findings if f['severity'] == 'critical'])
        high = len([f for f in self.findings if f['severity'] == 'high'])
        med = len([f for f in self.findings if f['severity'] == 'medium'])
        low = len([f for f in self.findings if f['severity'] == 'low'])

        if crit:
            self.ui.fail(f"{crit} critical issue(s)")
        if high:
            self.ui.warn(f"{high} high issue(s)")
        if med:
            self.ui.info(f"{med} medium issue(s)")
        if low:
            self.ui.info(f"{low} low issue(s)")

        print(f"\n  {c['dim']}Scan completed in {elapsed}s{c['reset']}")

        return self.results
