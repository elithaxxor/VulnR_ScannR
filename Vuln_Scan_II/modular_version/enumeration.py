# enumeration.py

import os
import re
import sqlite3
import socket
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import wkst, srvs
except ImportError:
    # If not installed, you'd install it, but we skip logic for brevity
    pass

class SMBEnumerator:
    """
    Handles SMB host discovery and LAN-wide enumeration tasks.
    """
    def __init__(self, logger: logging.Logger, db_path="smb_enum.db"):
        self.logger = logger
        self.db_path = db_path

    def discover_smb_hosts(self, network_cidr: str) -> list:
        """
        Finds SMB hosts (port 445) in the given CIDR using nmap or fallback.
        """
        self.logger.info(f"[*] Scanning network {network_cidr} for SMB hosts...")
        hosts = []

        try:
            nm_proc = subprocess.run(
                ["nmap", "-p", "445", "--open", "-n", "-T4", "-oG", "-", network_cidr],
                capture_output=True, text=True, check=True
            )
            for line in nm_proc.stdout.splitlines():
                if "/open/tcp//microsoft-ds" in line or "/open/tcp//netbios-ssn" in line:
                    parts = line.split()
                    if len(parts) > 1:
                        ip = parts[1]
                        hosts.append(ip)
        except subprocess.CalledProcessError:
            self.logger.warning("[!] Nmap scan failed, using fallback.")
            base_net = network_cidr.rsplit('.', 1)[0] + '.'
            for i in range(1, 255):
                ip = base_net + str(i)
                for port in [139, 445]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            hosts.append(ip)
                            break
                    except socket.error:
                        continue

        unique_hosts = sorted(set(hosts))
        for ip in unique_hosts:
            self.logger.info(f"Host {ip} has SMB service.")
        return unique_hosts

    def enumerate_lan_hosts(self, hosts: list):
        """
        Enumerates each discovered SMB host for domain/workgroup info, shares, etc.
        """
        for ip in hosts:
            self.logger.info(f"[*] Enumerating {ip} (LAN-wide logic)...")
            # a) CME basic info
            try:
                cme = subprocess.run(["crackmapexec", "smb", ip],
                                     capture_output=True, text=True, check=True)
                self.logger.info("[crackmapexec info]\n" + cme.stdout.strip())
            except Exception:
                self.logger.warning(f"[!] crackmapexec failed for host {ip}")

            # b) SMB shares
            try:
                conn = SMBConnection(ip, ip)
                conn.login('', '')  # anonymous
                shares = conn.listShares()
                msg = "[Shares (anonymous)]:\n"
                for share in shares:
                    share_name = share['shi1_netname'].rstrip('\x00')
                    msg += f"  {share_name}\n"
                self.logger.info(msg)
                conn.logoff()
            except Exception:
                # fallback smbclient
                smbclient_cmd = ["smbclient", "-L", f"//{ip}/", "-N", "-g"]
                smb = subprocess.run(smbclient_cmd, capture_output=True, text=True)
                self.logger.info("[Shares via smbclient]\n" + smb.stdout)

            # c) Users
            try:
                sid_cmd = ["lookupsid.py", f"''@{ip}"]
                sid_result = subprocess.run(" ".join(sid_cmd), shell=True, capture_output=True, text=True)
                self.logger.info("[User accounts (RID lookup)]:\n" + sid_result.stdout.strip())
            except Exception:
                enum4linux_cmd = ["enum4linux", "-U", ip]
                enum4 = subprocess.run(enum4linux_cmd, capture_output=True, text=True)
                self.logger.info("[Users via enum4linux]\n" + enum4.stdout.strip())

            # d) NTLM hash attempts
            try:
                sam = subprocess.run(["crackmapexec", "smb", ip, "--sam"],
                                     capture_output=True, text=True, check=True)
                self.logger.info("[SAM dump]\n" + sam.stdout.strip())
                for line in sam.stdout.splitlines():
                    if re.search(r'[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}', line):
                        self.logger.info(f"[NTLM Hash Found] {ip} => {line}")
            except Exception:
                rpc = subprocess.run(["rpcclient", "-U", "", "-N", ip, "-c", "lsaquery"],
                                     capture_output=True, text=True)
                self.logger.info("[rpcclient lsaquery]\n" + rpc.stdout.strip())


class IntensityLevel:
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class ImpacketEnumerator:
    """
    Intensity-based enumeration with Impacket (SMBConnection, DCE/RPC).
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def enumerate_with_intensity(self, target, username, password, domain, intensity):
        """
        Perform enumeration on a single target depending on the intensity level.
        """
        self.logger.info(f"[+] Starting enumeration: target={target}, intensity={intensity}")
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import wkst, srvs

        try:
            conn = SMBConnection(target, target)
            conn.login(username, password, domain)

            if intensity == IntensityLevel.LOW:
                self._enum_low(conn)
            elif intensity == IntensityLevel.MEDIUM:
                self._enum_medium(conn)
            elif intensity == IntensityLevel.HIGH:
                self._enum_high(conn)
            conn.close()

        except Exception as e:
            self.logger.error(f"Error enumerating {target}: {e}")

    def _enum_low(self, conn):
        self.logger.info("[LOW] Listing SMB shares...")
        shares = conn.listShares()
        for share in shares:
            share_name = share['shi1_netname']
            self.logger.info(f"    Share: {share_name}")

    def _enum_medium(self, conn):
        self.logger.info("[MEDIUM] Enumerating logged-on users...")
        from impacket.dcerpc.v5 import wkst
        dce = conn.getDCE()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)
        request = wkst.NetrWkstaUserEnum()
        response = dce.request(request)
        for user in response['UserInfo']['WkstaUserInfo']:
            self.logger.info(f"    Logged-on User: {user['wkui1_username']}")

    def _enum_high(self, conn):
        self.logger.info("[HIGH] Advanced enumeration.")
        from impacket.dcerpc.v5 import srvs

        # 1) Sessions
        try:
            self.logger.info("Enumerating active sessions...")
            dce = conn.getDCE()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            request = srvs.NetrSessionEnum()
            response = dce.request(request)
            if response['SessionInfo']['Level'] == 10:
                for session in response['SessionInfo']['SessionInfo10']:
                    user = session['sesi10_username']
                    cname = session['sesi10_cname']
                    time = session['sesi10_time']
                    self.logger.info(f"    Session => {user} on {cname}, time={time}")
            else:
                self.logger.info("    No active sessions found.")
        except Exception as e:
            self.logger.warning(f"Error enumerating sessions: {e}")

        # 2) Check shares
        self.logger.info("Checking shares for accessibility...")
        try:
            shares = conn.listShares()
            for share in shares:
                share_name = share['shi1_netname']
                if not share_name.endswith('$'):
                    try:
                        conn.listPath(share_name, '*')
                        self.logger.info(f"    Share {share_name} is accessible.")
                    except Exception:
                        self.logger.info(f"    Share {share_name} NOT accessible.")
        except Exception as e:
            self.logger.warning(f"Error checking shares: {e}")

        # 3) Enumerate services
        try:
            dce.bind(srvs.MSRPC_UUID_SRVS)
            request = srvs.NetrServerGetInfo()
            response = dce.request(request)
            server_info = response['ServerInfo']['ServerName']
            self.logger.info(f"    Server Name: {server_info}")
        except Exception as e:
            self.logger.warning(f"Error enumerating services: {e}")


class NmapManager:
    """
    Handles parallel Nmap scans, logs them into a 'nmap_scans' table.
    """
    def __init__(self, logger: logging.Logger, db_path="smb_enum.db"):
        self.logger = logger
        self.db_path = db_path

    def run_parallel_scans(self, targets: list, script_category=None):
        """
        Runs Nmap scans concurrently on a list of targets.
        """
        self.logger.info(f"Running Nmap scans on {len(targets)} target(s). script_category={script_category}")
        max_workers = 5
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for target in targets:
                futures.append(executor.submit(self._run_single_scan, target, script_category))

            for f in futures:
                # we don't need the result
                pass
        self.logger.info("Parallel Nmap scans completed.")

    def _run_single_scan(self, target, script_category=None):
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_filename = f"nmap_results_{timestamp_str}_{target.replace('/', '_')}.xml"
        cmd = ["nmap", "-sV", "-oX", xml_filename]
        if script_category:
            cmd += ["--script", script_category]
        cmd += [target]

        self.logger.info(f"[Nmap] Running: {' '.join(cmd)}")
        try:
            run_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f"[Nmap Output for {target}]\n{run_result.stdout}")
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Nmap scan failed for {target}: {e}\n{e.output}")

        # Insert into DB
        self._log_nmap_scan(target, " ".join(cmd), os.path.abspath(xml_filename))

    def _log_nmap_scan(self, target, command, xml_path):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS nmap_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                command TEXT,
                xml_path TEXT
            )
        ''')
        conn.commit()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''
            INSERT INTO nmap_scans (timestamp, target, command, xml_path)
            VALUES (?, ?, ?, ?)
        ''', (ts, target, command, xml_path))
        conn.commit()
        conn.close()


class MetasploitManager:
    """
    Runs Metasploit modules in non-interactive mode and logs results.
    """
    def __init__(self, logger: logging.Logger, db_path="smb_enum.db"):
        self.logger = logger
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS metasploit_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                module TEXT,
                output TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def run_module(self, target, module_name, options=None):
        """
        options can be a dict of additional 'set' commands for msf.
        """
        if options is None:
            options = {}

        commands = [f"use {module_name}", f"set RHOSTS {target}"]
        for k, v in options.items():
            commands.append(f"set {k} {v}")
        commands.append("run")
        commands.append("exit")

        cmd_str = "; ".join(commands)
        self.logger.info(f"[Metasploit] Running: {cmd_str}")

        try:
            run_result = subprocess.run(
                ["msfconsole", "-q", "-x", cmd_str],
                capture_output=True, text=True, check=True
            )
            output = run_result.stdout
            self.logger.info(f"[Metasploit Output] {output}")
        except subprocess.CalledProcessError as e:
            output = f"Metasploit run failed: {e}\n{e.output}"
            self.logger.warning(output)

        # Insert into DB
        self._log_msf_run(target, module_name, output)

    def _log_msf_run(self, target, module_name, output):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''
            INSERT INTO metasploit_runs (timestamp, target, module, output)
            VALUES (?, ?, ?, ?)
        ''', (ts, target, module_name, output))
        conn.commit()
        conn.close()