#!/usr/bin/env python3
"""
Single, integrated script demonstrating:
  1) Logging to SQLite
  2) SMB/Network enumeration
  3) Impacket-based intensity enumeration
  4) Parallel Nmap scanning
  5) Metasploit usage via msfconsole
  6) Vulnerability scoring with additional criteria
  7) Charting final scores with a Matplotlib line plot
"""

import os
import re
import sys
import sqlite3
import logging
import subprocess
from enum import Enum
from datetime import datetime
import concurrent.futures

# We'll produce simple line plots with matplotlib
import matplotlib
matplotlib.use("Agg")  # Headless environment
import matplotlib.pyplot as plt

# ================== 1) LOGGING (SQLite + Console) ==================

class SQLiteHandler(logging.Handler):
    """
    A custom logging handler that writes log records to a SQLite database (logs table).
    """
    def __init__(self, db='smb_enum.db'):
        super().__init__()
        self.db = db
        self._initialize_database()

    def _initialize_database(self):
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                message TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def emit(self, record):
        try:
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
            level = record.levelname
            message = self.format(record)
            c.execute(
                "INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
                (timestamp, level, message)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB LOG FAILURE] {e}")

def setup_logger(db_path="smb_enum.db"):
    logger = logging.getLogger("SMBLogger")
    logger.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)

    # SQLite handler
    sqlite_handler = SQLiteHandler(db_path)
    # Keep message format short in DB
    sqlite_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(sqlite_handler)

    return logger


# ================== 2) SETUP & SUPPORT FUNCTIONS ==================

logger = None  # We'll set this in main()

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import wkst, srvs
except ImportError:
    if logger:
        logger.info("[*] Installing impacket library...")
    subprocess.run(["pip", "install", "impacket"], check=True)
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import wkst, srvs

required_tools = ["nmap", "crackmapexec", "enum4linux", "msfconsole"]
for tool in required_tools:
    if not shutil.which(tool):
        if logger:
            logger.info(f"[*] Installing missing tool: {tool}")
        try:
            subprocess.run(["apt-get", "update", "-y"], check=True)
            subprocess.run(["apt-get", "install", "-y", tool], check=True)
        except Exception as e:
            if logger:
                logger.warning(f"[!] Failed to install {tool}: {e}")

# ================== 3) SMB DISCOVERY & ENUMERATION ==================

def discover_smb_hosts(network_cidr):
    """
    Finds SMB hosts (port 445) in a given network range using nmap or fallback socket scan.
    Returns a list of IPs.
    """
    logger.info(f"[*] Scanning network {network_cidr} for SMB hosts...")
    hosts = []

    # Attempt nmap
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
        logger.warning("[!] Nmap scan failed, falling back to manual scan.")
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
        logger.info(f"Host {ip} has SMB service.")
    return unique_hosts

def enumerate_lan_hosts(hosts):
    """
    Enumerates each discovered SMB host for:
      - Domain/workgroup info (CME)
      - Shares (anonymous)
      - Users (lookupsid or enum4linux)
      - Attempt hash dumping
      - Basic NTLM hash pattern check
    """
    for ip in hosts:
        logger.info(f"[*] Enumerating {ip} (LAN-wide logic)...")

        # a) Basic info (CME)
        try:
            cme = subprocess.run(["crackmapexec", "smb", ip],
                                 capture_output=True, text=True, check=True)
            logger.info("[crackmapexec info]\n" + cme.stdout.strip())
        except Exception:
            logger.warning("[!] crackmapexec failed or not installed for host %s.", ip)

        # b) List shares (anonymous) with Impacket
        try:
            conn = SMBConnection(ip, ip)
            conn.login('', '')  # Attempt anonymous
            shares = conn.listShares()
            msg = "[Shares (anonymous) via Impacket]:\n"
            for share in shares:
                share_name = share['shi1_netname'].rstrip('\x00')
                msg += f"  {share_name}\n"
            logger.info(msg)
            conn.logoff()
        except Exception:
            # fallback smbclient
            smbclient_cmd = ["smbclient", "-L", f"//{ip}/", "-N", "-g"]
            smb = subprocess.run(smbclient_cmd, capture_output=True, text=True)
            logger.info("[Shares (anonymous) via smbclient]:\n" + smb.stdout)

        # c) Enumerate users
        try:
            sid_cmd = ["lookupsid.py", f"''@{ip}"]
            sid_result = subprocess.run(" ".join(sid_cmd), shell=True, capture_output=True, text=True)
            logger.info("[User accounts (RID lookup)]:\n" + sid_result.stdout.strip())
        except Exception:
            enum4linux_cmd = ["enum4linux", "-U", ip]
            enum4 = subprocess.run(enum4linux_cmd, capture_output=True, text=True)
            logger.info("[Users via enum4linux]:\n" + enum4.stdout.strip())

        # d) Attempt to retrieve NTLM hashes (SAM)
        try:
            sam = subprocess.run(["crackmapexec", "smb", ip, "--sam"],
                                 capture_output=True, text=True, check=True)
            logger.info("[SAM dump output]:\n" + sam.stdout.strip())

            # Quick pattern check
            for line in sam.stdout.splitlines():
                if re.search(r'[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}', line):
                    logger.info(f"[NTLM Hash Found] {ip} => {line}")

        except Exception:
            # fallback
            rpc = subprocess.run(["rpcclient", "-U", "", "-N", ip, "-c", "lsaquery"],
                                 capture_output=True, text=True)
            logger.info("[rpcclient lsaquery output]:\n" + rpc.stdout.strip())


# ================== 4) INTENSITY-BASED IMPACKET ENUM ==================

class IntensityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

def enumerate_with_intensity(target, username, password, domain, intensity):
    """
    Uses Impacket-based enumeration for a single target based on intensity.
    """
    logger.info(f"[+] Starting {intensity.name} enumeration for {target}")
    try:
        conn = SMBConnection(target, target)
        conn.login(username, password, domain)

        if intensity == IntensityLevel.LOW:
            logger.info("[LOW] Listing SMB shares...")
            shares = conn.listShares()
            for share in shares:
                share_name = share['shi1_netname']
                logger.info(f"    Share found: {share_name}")

        elif intensity == IntensityLevel.MEDIUM:
            logger.info("[MEDIUM] Enumerating logged-on users...")
            dce = conn.getDCE()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            request = wkst.NetrWkstaUserEnum()
            response = dce.request(request)
            for user in response['UserInfo']['WkstaUserInfo']:
                logger.info(f"    Logged-on User: {user['wkui1_username']}")

        elif intensity == IntensityLevel.HIGH:
            logger.info("[HIGH] Advanced enumeration...")

            # 1) Sessions
            try:
                logger.info("Enumerating active sessions...")
                dce = conn.getDCE()
                dce.connect()
                dce.bind(srvs.MSRPC_UUID_SRVS)
                request = srvs.NetrSessionEnum()
                response = dce.request(request)
                if response['SessionInfo']['Level'] == 10:
                    for session in response['SessionInfo']['SessionInfo10']:
                        logger.info(
                            f"    Session => User: {session['sesi10_username']}, "
                            f"Client: {session['sesi10_cname']}, Time: {session['sesi10_time']}"
                        )
                else:
                    logger.info("    No active sessions found.")
            except Exception as e:
                logger.warning(f"Error enumerating sessions on {target}: {e}")

            # 2) Check for writable/exploitable shares
            logger.info("Checking for writable shares...")
            try:
                shares = conn.listShares()
                for share in shares:
                    share_name = share['shi1_netname']
                    if not share_name.endswith('$'):
                        try:
                            conn.listPath(share_name, '*')
                            logger.info(f"    Share '{share_name}' is accessible/writable.")
                        except Exception:
                            logger.info(f"    Share '{share_name}' is NOT accessible.")
            except Exception as e:
                logger.warning(f"Error checking shares on {target}: {e}")

            # 3) Enumerate services/server info
            logger.info("Enumerating services/server info...")
            try:
                dce.bind(srvs.MSRPC_UUID_SRVS)
                request = srvs.NetrServerGetInfo()
                response = dce.request(request)
                server_info = response['ServerInfo']['ServerName']
                logger.info(f"    Server Name: {server_info}")
            except Exception as e:
                logger.warning(f"Error enumerating services on {target}: {e}")

        conn.close()

    except Exception as e:
        logger.error(f"Error during Impacket enumeration of {target}: {e}")


# ================== 5) ADVANCED PARALLEL NMAP ==================

def log_nmap_scan_to_db(db_path, target, command, xml_path):
    """
    Insert an Nmap scan record into the nmap_scans table.
    If the table doesn't exist, create it.
    """
    conn = sqlite3.connect(db_path)
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

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO nmap_scans (timestamp, target, command, xml_path)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, target, command, xml_path))
    conn.commit()
    conn.close()

def run_nmap_scan(target, script_category=None, db_path="smb_enum.db"):
    """
    Run an nmap scan on one target, with optional script categories.
    Save XML output, insert record into DB.
    """
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_filename = f"nmap_results_{timestamp_str}_{target.replace('/', '_')}.xml"
    cmd = ["nmap", "-sV", "-oX", xml_filename]

    if script_category:
        cmd += ["--script", script_category]
    cmd += [target]

    logger.info(f"[Nmap] Scanning {target} with script category: {script_category or 'None'}")
    logger.info(f"[Nmap] Command: {' '.join(cmd)}")

    try:
        run_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(f"[Nmap Output for {target}]\n{run_result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Nmap scan failed for {target}: {e}\n{e.output}")

    # Log to DB
    full_cmd_str = " ".join(cmd)
    log_nmap_scan_to_db(db_path, target, full_cmd_str, os.path.abspath(xml_filename))

def advanced_nmap_menu(db_path="smb_enum.db"):
    """
    Allows user to specify multiple targets for parallel scanning,
    choose an NSE script category, and run them concurrently.
    """
    logger.info("\n=== ADVANCED NMAP PARALLEL SCANS ===")
    targets_input = input("Enter targets (comma-separated, e.g. '192.168.1.10,192.168.1.20/24'): ").strip()
    if not targets_input:
        logger.warning("No targets provided. Returning.")
        return

    targets = [t.strip() for t in targets_input.split(",") if t.strip()]

    logger.info("Common NSE categories: 'discovery', 'safe', 'default', 'vuln'")
    script_category = input("Enter an NSE script category or leave blank for none: ").strip()

    max_workers = 5
    logger.info(f"Starting parallel Nmap scans on {len(targets)} target(s) with up to {max_workers} workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for target in targets:
            future = executor.submit(run_nmap_scan, target, script_category, db_path)
            futures.append(future)

        for f in concurrent.futures.as_completed(futures):
            # We don't need the result specifically
            pass
    logger.info("Parallel Nmap scans completed.")


# ================== 6) METASPLOIT INTEGRATION ==================

def log_metasploit_run_to_db(db_path, target, module_name, output):
    """
    Insert a row for Metasploit runs into the metasploit_runs table.
    """
    conn = sqlite3.connect(db_path)
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

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO metasploit_runs (timestamp, target, module, output)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, target, module_name, output))
    conn.commit()
    conn.close()

def run_metasploit_module(target, module_name, options=None, db_path="smb_enum.db"):
    """
    Launch msfconsole non-interactively with a specific module, set RHOSTS, run, exit.
    """
    if options is None:
        options = {}

    commands = [f"use {module_name}", f"set RHOSTS {target}"]
    for k, v in options.items():
        commands.append(f"set {k} {v}")
    commands.append("run")
    commands.append("exit")

    msf_command_str = "; ".join(commands)
    logger.info(f"[Metasploit] Running: {msf_command_str}")

    try:
        run_result = subprocess.run(
            ["msfconsole", "-q", "-x", msf_command_str],
            capture_output=True, text=True, check=True
        )
        output = run_result.stdout
        logger.info(f"[Metasploit Output for {target}, module={module_name}]\n{output}")
    except subprocess.CalledProcessError as e:
        output = f"Metasploit run failed: {e}\n{e.output}"
        logger.warning(output)

    # Log result
    log_metasploit_run_to_db(db_path, target, module_name, output)

def metasploit_menu(db_path="smb_enum.db"):
    while True:
        logger.info("\n=== METASPLOIT MENU ===")
        logger.info("1) SMB Version (auxiliary/scanner/smb/smb_version)")
        logger.info("2) MS17-010 (auxiliary/scanner/smb/smb_ms17_010)")
        logger.info("3) FTP Anonymous (auxiliary/scanner/ftp/anonymous)")
        logger.info("0) Return to main menu")

        choice = input("Select a Metasploit module (0 to exit): ").strip()
        if choice == '0':
            break

        target = input("Enter target IP or range (RHOSTS): ").strip()
        if not target:
            logger.warning("No target specified.")
            continue

        if choice == '1':
            run_metasploit_module(target, "auxiliary/scanner/smb/smb_version", db_path=db_path)
        elif choice == '2':
            run_metasploit_module(target, "auxiliary/scanner/smb/smb_ms17_010", db_path=db_path)
        elif choice == '3':
            run_metasploit_module(target, "auxiliary/scanner/ftp/anonymous", db_path=db_path)
        else:
            logger.info("Invalid choice. Please pick 0-3.")


# ================== 7) VULNERABILITY SCORING ==================

def setup_vulnerability_scores_table(db_path: str):
    """
    Create or ensure existence of a 'vulnerability_scores' table.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            open_ports INT,
            vulnerabilities INT,
            high_risk_ports INT,
            plaintext_creds INT,
            missing_patches INT,
            final_score INT,
            risk_category TEXT
        )
    ''')
    conn.commit()
    conn.close()

def calculate_vulnerability_score(host_data: dict):
    """
    Additional criteria included:
      - Plaintext creds (subtract 10 each)
      - Missing patches (subtract 5 each)
    Returns:
      (final_score, vuln_count, open_port_count, high_risk_count, plaintext_creds, missing_patches, category)
    """
    score = 100

    vulnerabilities = host_data.get("vulnerabilities", [])
    open_ports = host_data.get("open_ports", [])
    plaintext_creds = host_data.get("plaintext_creds", 0)
    missing_patches = host_data.get("missing_patches", 0)

    vuln_count = len(vulnerabilities)
    open_port_count = len(open_ports)

    # Subtract for each vulnerability
    score -= (vuln_count * 15)
    # Subtract for each open port
    score -= (open_port_count * 5)
    # Subtract for discovered plaintext creds
    score -= (plaintext_creds * 10)
    # Subtract for missing patches
    score -= (missing_patches * 5)

    # Additional penalty for high-risk ports
    high_risk_list = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
    high_risk_count = sum(1 for p in open_ports if p in high_risk_list)
    score -= (high_risk_count * 3)

    final_score = max(score, 0)

    # Risk category
    if final_score >= 80:
        category = "Low"
    elif final_score >= 50:
        category = "Medium"
    elif final_score >= 20:
        category = "High"
    else:
        category = "Critical"

    return (final_score, vuln_count, open_port_count, high_risk_count, plaintext_creds, missing_patches, category)

def log_vulnerability_score(db_path: str,
                            host: str,
                            open_ports: int,
                            vulnerabilities: int,
                            high_risk_ports: int,
                            plaintext_creds: int,
                            missing_patches: int,
                            final_score: int,
                            category: str):
    """
    Insert a row into vulnerability_scores table.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute('''
        INSERT INTO vulnerability_scores (
            timestamp, host, open_ports, vulnerabilities,
            high_risk_ports, plaintext_creds, missing_patches,
            final_score, risk_category
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, host, open_ports, vulnerabilities,
          high_risk_ports, plaintext_creds, missing_patches,
          final_score, category))
    conn.commit()
    conn.close()

def run_vulnerability_scoring_workflow(db_path: str, discovered_data: dict):
    """
    discovered_data example:
      {
        "192.168.1.10": {
          "vulnerabilities": ["MS17-010", "Weak SMB Signing"],
          "open_ports": [139, 445],
          "plaintext_creds": 1,
          "missing_patches": 2
        },
        ...
      }
    """
    setup_vulnerability_scores_table(db_path)

    host_scores = {}

    for host, data in discovered_data.items():
        (final_score, vuln_count, open_count, high_risk_count,
         plain_creds, missing_patches, category) = calculate_vulnerability_score(data)

        logger.info(f"[Score] {host}: final_score={final_score}, category={category}")
        # Insert into DB
        log_vulnerability_score(db_path,
                                host,
                                open_count,
                                vuln_count,
                                high_risk_count,
                                plain_creds,
                                missing_patches,
                                final_score,
                                category)
        host_scores[host] = final_score

    # Create line plot of final scores
    create_line_plot_of_scores(host_scores)


# ================== 8) PLOTTING A LINE OF SCORES ==================

def create_line_plot_of_scores(host_scores: dict, output_file="vulnerability_scores_line.png"):
    """
    Make a line plot of final scores (descending).
    X-axis = host, Y-axis = final score.
    """
    if not host_scores:
        logger.warning("No host scores to plot. Skipping.")
        return

    # Sort by descending score
    sorted_hosts = sorted(host_scores.keys(), key=lambda h: host_scores[h], reverse=True)
    scores = [host_scores[h] for h in sorted_hosts]

    plt.figure(figsize=(8, 4))
    plt.plot(range(len(scores)), scores, marker='o')  # line plot
    plt.xticks(range(len(scores)), sorted_hosts, rotation=45, ha='right')
    plt.xlabel("Host")
    plt.ylabel("Score")
    plt.title("Vulnerability Scores (Line Plot)")
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()

    logger.info(f"[LINE PLOT] Saved {output_file}")


# ================== 9) MAIN SCRIPT ==================

def main():
    global logger
    logger = setup_logger("smb_enum.db")

    logger.info("=== SMB Enumeration, Scanning, Metasploit, Vulnerability Scoring ===")

    # 1) Optionally discover SMB hosts
    network_cidr = input("Enter the network CIDR to scan (e.g. 192.168.1.0/24) or blank to skip: ").strip()
    discovered_hosts = []
    if network_cidr:
        discovered_hosts = discover_smb_hosts(network_cidr)
        # Perform LAN-wide enumeration
        enumerate_lan_hosts(discovered_hosts)

    # 2) Intensity-based enumeration?
    do_intensity = input("Run Impacket intensity-based enumeration? (y/n): ").lower()
    if do_intensity == 'y':
        target_ip = input("Target IP (or 'all'): ").strip()
        user = input("Username (blank for anonymous): ").strip()
        pwd = input("Password (blank for anonymous): ").strip()
        dom = input("Domain (blank if none): ").strip()

        print("\nSelect intensity level:")
        for level in IntensityLevel:
            logger.info(f"{level.value}. {level.name}")

        try:
            selected_level = int(input("Enter your choice: "))
            intensity_level = IntensityLevel(selected_level)
        except ValueError:
            logger.error("Invalid intensity level.")
            return

        if target_ip.lower() == 'all':
            if not discovered_hosts:
                logger.warning("No discovered hosts. Skipping intensity enumeration.")
            else:
                for ip in discovered_hosts:
                    enumerate_with_intensity(ip, user, pwd, dom, intensity_level)
        else:
            enumerate_with_intensity(target_ip, user, pwd, dom, intensity_level)

    # 3) Advanced Nmap?
    do_advanced_nmap = input("Perform advanced parallel Nmap scanning? (y/n): ").lower()
    if do_advanced_nmap == 'y':
        advanced_nmap_menu("smb_enum.db")

    # 4) Metasploit menu?
    do_msf = input("Open Metasploit menu? (y/n): ").lower()
    if do_msf == 'y':
        metasploit_menu("smb_enum.db")

    # 5) Example: Vulnerability data => run scoring
    # In real usage, you'd gather discovered data from your enumerations, store in a dict.
    # For demonstration, we'll define some sample data:
    discovered_data = {
        "192.168.1.10": {
            "vulnerabilities": ["MS17-010", "Weak SMB Signing"],
            "open_ports": [135, 139, 445],
            "plaintext_creds": 1,
            "missing_patches": 2
        },
        "192.168.1.11": {
            "vulnerabilities": [],
            "open_ports": [80, 443],
            "plaintext_creds": 0,
            "missing_patches": 0
        },
        "server.domain.local": {
            "vulnerabilities": ["Apache Struts CVE-2017-5638"],
            "open_ports": [22, 80, 443, 3306],
            "plaintext_creds": 2,
            "missing_patches": 1
        }
    }

    # If you have real data from enumerations, construct a dictionary in this same format.

    run_vulnerability_scoring_workflow("smb_enum.db", discovered_data)

    logger.info("All tasks done. Check the DB (logs, nmap_scans, metasploit_runs, vulnerability_scores) and line plot.")


if __name__ == "__main__":
    main()