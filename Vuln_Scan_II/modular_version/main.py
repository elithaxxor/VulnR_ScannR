# main.py

import argparse
import sys
from logging_db import DBLogger
from enumeration import SMBEnumerator, NmapManager, MetasploitManager, ImpacketEnumerator, IntensityLevel
from scoring import VulnerabilityScorer

def main():
    # 1) Parse CLI arguments
    parser = argparse.ArgumentParser(description="Network Enumeration, Vulnerability Scoring, and more.")
    parser.add_argument("-d", "--db", default="smb_enum.db", help="SQLite database path (default: smb_enum.db)")
    parser.add_argument("--discover-cidr", help="CIDR to discover SMB hosts")
    parser.add_argument("--intensity", type=int, choices=[1,2,3], help="Impacket intensity level (1=LOW,2=MEDIUM,3=HIGH)")
    parser.add_argument("--intensity-target", help="Target IP or 'all' for discovered hosts")
    parser.add_argument("--run-nmap", action="store_true", help="Run advanced Nmap scanning (asks for targets/scripts).")
    parser.add_argument("--metasploit", action="store_true", help="Open Metasploit menu for scanning.")
    parser.add_argument("--score-json", help="Path to a JSON file containing discovered data for scoring.")

    args = parser.parse_args()

    # 2) Initialize logger
    db_logger = DBLogger(args.db)
    logger = db_logger.get_logger()
    logger.info("=== Security Script Started ===")

    # 3) Initialize enumerators
    smb_enum = SMBEnumerator(logger, args.db)
    nmap_manager = NmapManager(logger, args.db)
    msf_manager = MetasploitManager(logger, args.db)
    impacket_enum = ImpacketEnumerator(logger)

    discovered_hosts = []

    # 4) Possibly discover hosts
    if args.discover_cidr:
        discovered_hosts = smb_enum.discover_smb_hosts(args.discover_cidr)
        # LAN-wide enumeration
        smb_enum.enumerate_lan_hosts(discovered_hosts)

    # 5) Intensity-based enumerations
    if args.intensity:
        if not args.intensity_target:
            logger.warning("No intensity target specified. Skipping Impacket enumeration.")
        else:
            if args.intensity_target.lower() == "all":
                if not discovered_hosts:
                    logger.warning("No discovered hosts for 'all'.")
                else:
                    for ip in discovered_hosts:
                        impacket_enum.enumerate_with_intensity(ip, "", "", "", args.intensity)
            else:
                impacket_enum.enumerate_with_intensity(args.intensity_target, "", "", "", args.intensity)

    # 6) Nmap scanning
    if args.run_nmap:
        # For parallel scans, we'll ask user for input or you could add more CLI
        raw_tgts = input("Enter Nmap targets (comma-separated): ").strip()
        if raw_tgts:
            tgts = [x.strip() for x in raw_tgts.split(",")]
            script_cat = input("Enter Nmap script category (discovery,safe, etc.) or blank: ").strip() or None
            nmap_manager.run_parallel_scans(tgts, script_cat)

    # 7) Metasploit usage
    if args.metasploit:
        while True:
            print("\n=== Metasploit Menu ===")
            print("1) SMB Version (auxiliary/scanner/smb/smb_version)")
            print("2) MS17-010 (auxiliary/scanner/smb/smb_ms17_010)")
            print("3) FTP Anonymous (auxiliary/scanner/ftp/anonymous)")
            print("0) Exit Metasploit menu")
            choice = input("Select: ").strip()
            if choice == '0':
                break
            target = input("Enter target IP or range: ").strip()
            mod_map = {
                '1': "auxiliary/scanner/smb/smb_version",
                '2': "auxiliary/scanner/smb/smb_ms17_010",
                '3': "auxiliary/scanner/ftp/anonymous"
            }
            module_name = mod_map.get(choice)
            if module_name and target:
                msf_manager.run_module(target, module_name)

    # 8) Vulnerability scoring
    # If user passed --score-json, we'll load that discovered data from JSON
    # Or you could gather from enumerations, etc.
    if args.score_json:
        import json
        import os

        if os.path.exists(args.score_json):
            with open(args.score_json, 'r') as f:
                discovered_data = json.load(f)
            scorer = VulnerabilityScorer(logger, args.db)
            scorer.score_and_store(discovered_data)
        else:
            logger.warning(f"JSON file not found: {args.score_json}")

    logger.info("All tasks complete. Check the DB and logs.")

if __name__ == "__main__":
    main()