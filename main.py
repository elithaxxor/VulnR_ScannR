# ================== 13) MAIN SCRIPT ==================

def main():
    """
    Enhanced main function with modular approach and all new features.
    """
    global logger
    logger = setup_logger("smb_enum.db")

    logger.info("=== SMB-Scor3 Enhanced: Network Scanning, Enumeration, and Assessment Tool ===")
    logger.info("Version 2.0 - Comprehensive SMB Security Assessment Suite")
    
    # Check for command-line arguments first for scheduled scanning
    import sys
    if len(sys.argv) > 1 and '--schedule' in sys.argv:
        add_scheduled_scanning()
        return

    # Ensure dependencies are installed
    check_dependencies()
    
    # Main menu-driven interface
    while True:
        print("\n=== SMB-Scor3 MAIN MENU ===")
        print("1) Discover and enumerate SMB hosts")
        print("2) Intensity-based SMB enumeration")
        print("3) Advanced Nmap scanning")
        print("4) Metasploit integration")
        print("5) Active Directory enumeration")
        print("6) Password policy assessment")
        print("7) Generate vulnerability scores and reports")
        print("8) Export data (CSV/JSON/XML)")
        print("9) Launch web dashboard")
        print("10) Set up scheduled scanning")
        print("0) Exit")
        
        choice = input("\nSelect an option (0-10): ").strip()
        
        # Initialize the host data dictionary to track results
        host_data = {}
        
        if choice == '0':
            logger.info("Exiting SMB-Scor3. Goodbye!")
            break
            
        elif choice == '1':
            # Discover and enumerate SMB hosts
            network_cidr = input("Enter the network CIDR to scan (e.g. 192.168.1.0/24): ").strip()
            if network_cidr:
                discovered_hosts = discover_smb_hosts(network_cidr)
                if discovered_hosts:
                    host_data = enumerate_lan_hosts(discovered_hosts)
                    logger.info(f"Discovered and enumerated {len(discovered_hosts)} SMB hosts.")
                else:
                    logger.warning("No SMB hosts discovered in the specified range.")
        
        elif choice == '2':
            # Intensity-based enumeration
            target_ip = input("Target IP (or enter to skip): ").strip()
            if target_ip:
                user = input("Username (blank for anonymous): ").strip()
                pwd = input("Password (blank for anonymous): ").strip()
                dom = input("Domain (blank if none): ").strip()
                
                print("\nSelect intensity level:")
                for level in IntensityLevel:
                    print(f"{level.value}. {level.name}")
                
                try:
                    selected_level = int(input("Enter your choice (1-3): "))
                    intensity_level = IntensityLevel(selected_level)
                    
                    if target_ip not in host_data:
                        host_data[target_ip] = {
                            "vulnerabilities": [],
                            "open_ports": [],
                            "plaintext_creds": 0,
                            "missing_patches": 0,
                            "host": target_ip
                        }
                    
                    host_data[target_ip] = enumerate_with_intensity(
                        target_ip, user, pwd, dom, intensity_level, host_data[target_ip]
                    )
                except ValueError:
                    logger.error("Invalid intensity level.")
        
        elif choice == '3':
            # Advanced Nmap scanning
            host_data = advanced_nmap_menu("smb_enum.db", host_data)
        
        elif choice == '4':
            # Metasploit integration
            host_data = metasploit_menu("smb_enum.db", host_data)
        
        elif choice == '5':
            # Active Directory enumeration
            domain = input("Enter the domain (e.g., contoso.local): ").strip()
            username = input("Enter domain username: ").strip()
            password = input("Enter password: ").strip()
            target_dc = input("Enter domain controller (or leave blank to auto-detect): ").strip()
            
            if domain and username and password:
                ad_results = add_ad_enumeration(domain, username, password, target_dc, "smb_enum.db")
                logger.info(f"AD enumeration completed with {len(ad_results.get('users', []))} users found.")
            else:
                logger.warning("Domain, username, and password are required for AD enumeration.")
        
        elif choice == '6':
            # Password policy assessment
            target = input("Enter target IP: ").strip()
            domain = input("Enter domain (blank if workgroup): ").strip()
            username = input("Enter username (blank for anonymous): ").strip()
            password = input("Enter password (blank for anonymous): ").strip()
            
            if target:
                policy_results = add_password_policy_assessment(target, domain, username, password)
                if policy_results:
                    logger.info(f"Found {len(policy_results)} password policy issues.")
            else:
                logger.warning("Target IP is required for password policy assessment.")
        
        elif choice == '7':
            # Vulnerability scoring and reporting
            if not host_data:
                use_example = input("No host data collected yet. Use example data for demonstration? (y/n): ").lower()
                if use_example == 'y':
                    # Example data for demonstration
                    host_data = {
                        "192.168.1.10": {
                            "vulnerabilities": ["MS17-010", "Weak SMB Signing"],
                            "open_ports": [135, 139, 445],
                            "plaintext_creds": 1,
                            "missing_patches": 2,
                            "host": "192.168.1.10",
                            "cvss_score": 9.8,
                            "critical_vulns": 1
                        },
                        "192.168.1.11": {
                            "vulnerabilities": [],
                            "open_ports": [80, 443],
                            "plaintext_creds": 0,
                            "missing_patches": 0,
                            "host": "192.168.1.11",
                            "cvss_score": 0,
                            "critical_vulns": 0
                        },
                        "192.168.1.15": {
                            "vulnerabilities": ["Anonymous FTP Access", "Default Credentials"],
                            "open_ports": [21, 22, 80, 3306],
                            "plaintext_creds": 2,
                            "missing_patches": 1,
                            "host": "192.168.1.15",
                            "cvss_score": 7.5,
                            "critical_vulns": 0
                        }
                    }
            
            if host_data:
                logger.info(f"Running vulnerability scoring workflow for {len(host_data)} hosts")
                host_scores, remediation_results = run_vulnerability_scoring_workflow("smb_enum.db", host_data)
                logger.info(f"Generated scores and {sum(len(recs) for recs in remediation_results.values())} remediation recommendations")
                
                # Generate reports
                report_files = generate_reports("smb_enum.db", host_scores, remediation_results)
                logger.info(f"Generated reports: {', '.join(report_files.get('html', []))}")
            else:
                logger.warning("No host data available. Please run some scans first.")
        
        elif choice == '8':
            # Export data
            export_files = add_export_functionality("smb_enum.db")
            logger.info(f"Data exported to {', '.join(export_files.values())}")
        
        elif choice == '9':
            # Launch web dashboard
            port = input("Enter port for web dashboard (default 8080): ").strip()
            if not port:
                port = 8080
            else:
                port = int(port)
            
            logger.info(f"Starting web dashboard on port {port}. Press Ctrl+C to stop.")
            try:
                start_web_dashboard("smb_enum.db", port)
            except KeyboardInterrupt:
                logger.info("Web dashboard stopped by user.")
        
        elif choice == '10':
            # Set up scheduled scanning
            print("\n=== SCHEDULED SCANNING SETUP ===")
            schedule_type = input("Schedule type (daily/weekly): ").strip().lower()
            if schedule_type not in ['daily', 'weekly']:
                logger.error("Invalid schedule type. Must be 'daily' or 'weekly'.")
                continue
                
            schedule_time = input("Time to run (HH:MM, 24-hour format): ").strip()
            if not re.match(r'^\d{1,2}:\d{2}_score": 9.8,
                            "critical_vulns": 1
                        },
                        "192.168.1.11": {
                            "vulnerabilities": [],
                            "open_ports": [80, 443],
                            "plaintext_creds": 0,
                            "missing_patches": 0,
                            "host": "192.168.1.11",
                            "cvss# ================== 10) ACTIVE DIRECTORY INTEGRATION ==================

def add_ad_enumeration(domain, username, password, target_dc=None, db_path="smb_enum.db"):
    """
    Perform Active Directory enumeration using impacket tools.
    """
    logger.info(f"[AD] Starting Active Directory enumeration for domain {domain}")
    
    ad_data = {
        "users": [],
        "groups": [],
        "vulnerable_accounts": [],
        "risky_settings": [],
        "domain": domain
    }
    
    try:
        from impacket.ldap import ldap
        from impacket.ldap import ldapasn1
        from impacket.smbconnection import SMBConnection
        
        # Connect to LDAP
        if not target_dc:
            # Try to find DC
            smb = SMBConnection('*SMBSERVER', '')
            smb.login('', '')
            primary_dc = smb.getServerDNSDomainName()
            target_dc = primary_dc
            logger.info(f"[AD] Detected domain controller: {target_dc}")
        
        logger.info(f"[AD] Connecting to LDAP on {target_dc}")
        
        ldap_conn = ldap.LDAPConnection(f'ldap://{target_dc}', domain, username, password)
        base_dn = ','.join(f"DC={part}" for part in domain.split('.'))
        
        # Get domain users
        logger.info("[AD] Enumerating domain users")
        user_search_filter = ldapasn1.SubstringFilter()
        user_search_filter['type'] = 'samAccountName'
        user_search_filter['any'] = '*'
        
        ldap_filter = ldapasn1.Filter()
        ldap_filter['present'] = 'objectClass'
        
        user_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                       attributes=['sAMAccountName', 'userAccountControl', 
                                                  'pwdLastSet', 'memberOf'],
                                       searchBase=f"CN=Users,{base_dn}")
        
        for item in user_results:
            user = {}
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    user['username'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'userAccountControl':
                    uac = int(attr['vals'][0])
                    # Check for password never expires
                    if uac & 0x10000:
                        user['password_never_expires'] = True
                    # Check for password not required
                    if uac & 0x0020:
                        user['password_not_required'] = True
                    # Check for account not required to pre-authenticate
                    if uac & 0x400000:
                        user['no_preauth_required'] = True
                    # Check if account is disabled
                    if uac & 0x0002:
                        user['account_disabled'] = True
                elif attr['type'] == 'pwdLastSet':
                    pwd_last_set = int(attr['vals'][0])
                    if pwd_last_set == 0:
                        user['password_change_required'] = True
                    else:
                        # Convert Windows filetime to datetime
                        delta = datetime(1601, 1, 1)
                        seconds = pwd_last_set / 10**7
                        pwd_date = delta + timedelta(seconds=seconds)
                        user['password_last_set'] = pwd_date.strftime("%Y-%m-%d")
                        
                        # Check if password is old (>90 days)
                        if (datetime.now() - pwd_date).days > 90:
                            user['password_age_issue'] = True
                elif attr['type'] == 'memberOf':
                    user['groups'] = [g.decode('utf-8') for g in attr['vals']]
            
            if 'username' in user:
                ad_data['users'].append(user)
                
                # Check for weak account settings
                if any(k for k in user if k.startswith('password_') or k == 'no_preauth_required'):
                    ad_data['vulnerable_accounts'].append(user)
                    logger.warning(f"[AD] Vulnerable account settings for {user['username']}")
        
        # Get domain groups
        logger.info("[AD] Enumerating domain groups")
        group_search_filter = ldapasn1.SubstringFilter()
        group_search_filter['type'] = 'objectClass'
        group_search_filter['any'] = 'group'
        
        group_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                        attributes=['sAMAccountName', 'member'],
                                        searchBase=f"CN=Users,{base_dn}")
        
        for item in group_results:
            group = {}
            members = []
            
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    group['name'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'member':
                    members = [m.decode('utf-8') for m in attr['vals']]
            
            if 'name' in group:
                group['members'] = members
                ad_data['groups'].append(group)
                
                # Check if this is a privileged group
                privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators']
                if any(pg.lower() in group['name'].lower() for pg in privileged_groups):
                    group['privileged'] = True
                    ad_data['risky_settings'].append({
                        'type': 'Privileged Group',
                        'name': group['name'],
                        'members_count': len(members),
                        'risk': 'HIGH' if len(members) > 5 else 'MEDIUM',
                        'recommendation': 'Review privileged group membership and minimize number of accounts'
                    })
                    logger.warning(f"[AD] Privileged group {group['name']} has {len(members)} members")
        
        # Check for Kerberoasting vulnerabilities
        logger.info("[AD] Checking for Kerberoastable service accounts")
        service_filter = ldapasn1.Filter()
        service_filter['present'] = 'servicePrincipalName'
        
        service_results = ldap_conn.search(
            searchFilter=str(service_filter),
            attributes=['sAMAccountName', 'servicePrincipalName', 'userAccountControl'],
            searchBase=base_dn
        )
        
        kerberoastable_accounts = []
        for item in service_results:
            service_account = {'spns': []}
            
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    service_account['username'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'servicePrincipalName':
                    service_account['spns'] = [spn.decode('utf-8') for spn in attr['vals']]
                elif attr['type'] == 'userAccountControl':
                    uac = int(attr['vals'][0])
                    service_account['uac'] = uac
                    # Check if account doesn't require Kerberos pre-authentication
                    if uac & 0x400000:
                        service_account['asreproastable'] = True
            
            if 'username' in service_account and service_account['spns']:
                kerberoastable_accounts.append(service_account)
                ad_data['risky_settings'].append({
                    'type': 'Kerberoastable Account',
                    'name': service_account['username'],
                    'spn_count': len(service_account['spns']),
                    'risk': 'HIGH',
                    'recommendation': 'Use strong password for service accounts with SPNs and rotate regularly'
                })
                logger.warning(f"[AD] Kerberoastable account: {service_account['username']} with {len(service_account['spns'])} SPNs")
                
                if service_account.get('asreproastable'):
                    ad_data['risky_settings'].append({
                        'type': 'ASREPRoastable Account',
                        'name': service_account['username'],
                        'risk': 'CRITICAL',
                        'recommendation': 'Enable Kerberos pre-authentication for this account immediately'
                    })
                    logger.warning(f"[AD] CRITICAL: {service_account['username']} doesn't require Kerberos pre-authentication!")
        
        # Check domain password policy
        logger.info("[AD] Checking domain password policy")
        try:
            policy_filter = ldapasn1.Filter()
            policy_filter['present'] = 'objectClass'
            
            policy_results = ldap_conn.search(
                searchFilter=str(policy_filter),
                attributes=['maxPwdAge', 'minPwdLength', 'lockoutThreshold'],
                searchBase=f"CN=Password Settings Container,CN=System,{base_dn}"
            )
            
            for item in policy_results:
                policy = {}
                
                for attr in item['attributes']:
                    if attr['type'] == 'maxPwdAge':
                        # Convert large integer to days
                        max_pwd_age = int(attr['vals'][0])
                        max_days = abs(max_pwd_age) / (10**7 * 86400)
                        policy['max_password_age'] = int(max_days)
                        
                        if max_days == 0 or max_days > 90:
                            ad_data['risky_settings'].append({
                                'type': 'Weak Password Policy',
                                'setting': 'Maximum Password Age',
                                'value': f"{int(max_days)} days" if max_days > 0 else "Never expires",
                                'risk': 'HIGH',
                                'recommendation': 'Set maximum password age to 60-90 days'
                            })
                    elif attr['type'] == 'minPwdLength':
                        min_length = int(attr['vals'][0])
                        policy['min_password_length'] = min_length
                        
                        if min_length < 12:
                            ad_data['risky_settings'].append({
                                'type': 'Weak Password Policy',
                                'setting': 'Minimum Password Length',
                                'value': f"{min_length} characters",
                                'risk': 'HIGH' if min_length < 8 else 'MEDIUM',
                                'recommendation': 'Set minimum password length to at least 12 characters'
                            })
                    elif attr['type'] == 'lockoutThreshold':
                        lockout = int(attr['vals'][0])
                        policy['lockout_threshold'] = lockout
                        
                        if lockout == 0:
                            ad_data['risky_settings'].append({
                                'type': 'Weak Password Policy',
                                'setting': 'Account Lockout Threshold',
                                'value': "Disabled",
                                'risk': 'HIGH',
                                'recommendation': 'Enable account lockout with threshold of 5-10 attempts'
                            })
                
                ad_data['password_policy'] = policy
        except Exception as e:
            logger.warning(f"[AD] Error checking password policy: {e}")
        
        # Save results to database
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ad_enumeration (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    domain TEXT, 
                    data TEXT)''')
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO ad_enumeration (timestamp, domain, data) VALUES (?, ?, ?)",
                 (timestamp, domain, json.dumps(ad_data)))
        conn.commit()
        conn.close()
        
        logger.info(f"[+] AD enumeration complete. Found {len(ad_data['users'])} users, " +
                    f"{len(ad_data['groups'])} groups, {len(ad_data['vulnerable_accounts'])} vulnerable accounts, " +
                    f"{len(ad_data['risky_settings'])} risky settings.")
        
    except Exception as e:
        logger.error(f"AD enumeration failed: {str(e)}")
    
    return ad_data

def add_password_policy_assessment(target, domain, username="", password="", db_path="smb_enum.db"):
    """
    Assess password policy settings and identify weaknesses.
    """
    policy_results = {}
    
    try:
        # Check password policy via net accounts
        if not username:
            # Try anonymous connection
            cmd = ["net", "rpc", "info", "-S", target, "-U", "%"]
        else:
            cmd = ["net", "rpc", "info", "-S", target, "-U", f"{domain}/{username}%{password}"]
        
        net_info = subprocess.run(cmd, capture_output=True, text=True)
        
        # Query password policy
        if not username:
            cmd = ["net", "rpc", "password", "policy", "list", "-S", target, "-U", "%"]
        else:
            cmd = ["net", "rpc", "password", "policy", "list", "-S", target, 
                   "-U", f"{domain}/{username}%{password}"]
            
        policy_output = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse policy information
        policy_data = {}
        for line in policy_output.stdout.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                policy_data[key.strip()] = value.strip()
        
        # Analyze policy strength
        if 'Minimum password length' in policy_data:
            min_len = int(policy_data['Minimum password length'])
            if min_len < 8:
                policy_results['weak_password_length'] = {
                    'severity': 'HIGH',
                    'finding': f"Weak minimum password length ({min_len})",
                    'recommendation': 'Increase minimum password length to at least 12 characters'
                }
        
        if 'Maximum password age' in policy_data:
            max_age = int(policy_data['Maximum password age'].split()[0])
            if max_age > 90 or max_age == 0:
                policy_results['weak_password_expiration'] = {
                    'severity': 'MEDIUM',
                    'finding': f"Weak password expiration policy ({max_age} days)",
                    'recommendation': 'Set maximum password age to 60-90 days'
                }
        
        # Save results to database
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS password_policy (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    target TEXT,
                    policy TEXT,
                    findings TEXT)''')
        
        c.execute("INSERT INTO password_policy (timestamp, target, policy, findings) VALUES (?, ?, ?, ?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                  target,
                  json.dumps(policy_data),
                  json.dumps(policy_results)))
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Password policy assessment failed: {str(e)}")
    
    return policy_results

# ================== 11) EXPORT OPTIONS ==================

def add_export_functionality(db_path="smb_enum.db"):
    """
    Add support for exporting results to multiple formats.
    """
    import pandas as pd
    import json
    import csv
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    import os
    
    # Create exports directory
    os.makedirs("exports", exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    
    # Export vulnerability scores
    vuln_df = pd.read_sql_query("SELECT * FROM vulnerability_scores", conn)
    
    # CSV Export
    vuln_df.to_csv("exports/vulnerability_scores.csv", index=False)
    
    # JSON Export
    vuln_df.to_json("exports/vulnerability_scores.json", orient="records")
    
    # XML Export
    root = ET.Element("vulnerability_assessment")
    for _, row in vuln_df.iterrows():
        host_elem = ET.SubElement(root, "host")
        for col in vuln_df.columns:
            child = ET.SubElement(host_elem, col)
            child.text = str(row[col])
    
    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
    with open("exports/vulnerability_scores.xml", "w") as f:
        f.write(xmlstr)
    
    # Export other tables
    tables = ["logs", "nmap_scans", "metasploit_runs", "remediation_recommendations"]
    for table in tables:
        try:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
            df.to_csv(f"exports/{table}.csv", index=False)
            df.to_json(f"exports/{table}.json", orient="records")
        except Exception as e:
            logger.warning(f"Could not export table {table}: {e}")
    
    # Try to export AD data if it exists
    try:
        ad_df = pd.read_sql_query("SELECT * FROM ad_enumeration", conn)
        if len(ad_df) > 0:
            ad_df.to_csv("exports/ad_enumeration.csv", index=False)
            
            # For JSON, we need to parse the data column which is JSON serialized
            ad_records = []
            for _, row in ad_df.iterrows():
                record = {
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'domain': row['domain']
                }
                try:
                    # Parse JSON-serialized data
                    data = json.loads(row['data'])
                    record['data'] = data
                except:
                    record['data'] = row['data']
                ad_records.append(record)
            
            with open("exports/ad_enumeration.json", "w") as f:
                json.dump(ad_records, f, indent=4)
    except Exception as e:
        logger.warning(f"Could not export AD data: {e}")
    
    # Create consolidated export
    try:
        # Create a full data export in JSON
        export_data = {
            'meta': {
                'generated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'tool': "SMB-Scor3 Enhanced",
                'version': "2.0"
            },
            'hosts': {}
        }
        
        # Get all hosts from vulnerability_scores
        for _, row in vuln_df.iterrows():
            host = row['host']
            export_data['hosts'][host] = {
                'score': row['final_score'],
                'risk_category': row['risk_category'],
                'open_ports': row['open_ports'],
                'vulnerabilities': row['vulnerabilities'],
                'high_risk_ports': row['high_risk_ports'],
                'plaintext_creds': row['plaintext_creds'],
                'missing_patches': row['missing_patches'],
                'cvss_score': row['cvss_score']
            }
        
        # Add recommendations for each host
        try:
            rec_df = pd.read_sql_query("SELECT * FROM remediation_recommendations", conn)
            for _, row in rec_df.iterrows():
                host = row['host']
                if host in export_data['hosts']:
                    if 'recommendations' not in export_data['hosts'][host]:
                        export_data['hosts'][host]['recommendations'] = []
                    
                    export_data['hosts'][host]['recommendations'].append({
                        'severity': row['severity'],
                        'finding': row['finding'],
                        'remediation': row['remediation'],
                        'reference': row['reference']
                    })
        except Exception as e:
            logger.warning(f"Could not export recommendations: {e}")
        
        # Write consolidated export
        with open("exports/full_assessment.json", "w") as f:
            json.dump(export_data, f, indent=4)
    except Exception as e:
        logger.warning(f"Could not create consolidated export: {e}")
    
    conn.close()
    
    logger.info(f"[EXPORT] Exported data to CSV, JSON, and XML formats in the 'exports' directory")
    
    return {
        "csv": "exports/vulnerability_scores.csv",
        "json": "exports/vulnerability_scores.json",
        "xml": "exports/vulnerability_scores.xml",
        "full": "exports/full_assessment.json"
    }

# ================== 12) SCHEDULED SCANNING ==================

def add_scheduled_scanning():
    """
    Add support for scheduled scans.
    """
    import argparse
    import schedule
    import time
    
    parser = argparse.ArgumentParser(description='SMB-Scor3 Enhanced - Scheduled Scanning')
    parser.add_argument('--schedule', choices=['daily', 'weekly'], help='Schedule periodic scans')
    parser.add_argument('--time', help='Time to run scheduled scan (HH:MM)')
    parser.add_argument('--network', help='Network CIDR to scan')
    parser.add_argument('--db', default='smb_enum.db', help='Database file path')
    args = parser.parse_args()
    
    if args.schedule:
        # Define the job to run
        def scheduled_scan_job():
            logger.info(f"[SCHEDULED] Starting scheduled scan of {args.network}")
            
            # Set up database connection for this run
            db_path = args.db
            
            # Discover hosts
            discovered_hosts = discover_smb_hosts(args.network)
            
            # Gather host data
            host_data = enumerate_lan_hosts(discovered_hosts)
            
            # Run Nmap scans
            for host in discovered_hosts:
                host_data[host] = run_nmap_scan(host, "vuln", db_path, host_data[host])
            
            # Calculate vulnerability scores
            run_vulnerability_scoring_workflow(db_path, host_data)
            
            # Export results
            add_export_functionality(db_path)
            
            # Generate report
            generate_reports(db_path)
            
            logger.info(f"[SCHEDULED] Completed scheduled scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Set up the schedule
        if not args.time:
            args.time = "03:00"  # Default to 3 AM
            
        logger.info(f"[SCHEDULER] Setting up {args.schedule} scan at {args.time}")
        
        if args.schedule == 'daily':
            schedule.every().day.at(args.time).do(scheduled_scan_job)
        elif args.schedule == 'weekly':
            schedule.every().monday.at(args.time).do(scheduled_scan_job)
            
        logger.info(f"[SCHEDULER] Scheduled scan activated. Will run {args.schedule} at {args.time}")
        logger.info(f"[SCHEDULER] Press Ctrl+C to stop the scheduler")
            
        # Keep the scheduler running
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("[SCHEDULER] Scheduler stopped by user")
    else:
        logger.error("[SCHEDULER] No schedule specified. Use --schedule daily|weekly --time HH:MM --network CIDR")

# ================== 13) MAIN SCRIPT ==================

def add_ad_enumeration(domain, username, password, target_dc=None, db_path="smb_enum.db"):
    """
    Perform Active Directory enumeration using impacket tools.
    """
    logger.info(f"[AD] Starting Active Directory enumeration for domain {domain}")
    
    ad_data = {
        "users": [],
        "groups": [],
        "vulnerable_accounts": [],
        "risky_settings": [],
        "domain": domain
    }
    
    try:
        from impacket.ldap import ldap
        from impacket.ldap import ldapasn1
        from impacket.smbconnection import SMBConnection
        
        # Connect to LDAP
        if not target_dc:
            # Try to find DC
            smb = SMBConnection('*SMBSERVER', '')
            smb.login('', '')
            primary_dc = smb.getServerDNSDomainName()
            target_dc = primary_dc
            logger.info(f"[AD] Detected domain controller: {target_dc}")
        
        logger.info(f"[AD] Connecting to LDAP on {target_dc}")
        
        ldap_conn = ldap.LDAPConnection(f'ldap://{target_dc}', domain, username, password)
        base_dn = ','.join(f"DC={part}" for part in domain.split('.'))
        
        # Get domain users
        logger.info("[AD] Enumerating domain users")
        user_search_filter = ldapasn1.SubstringFilter()
        user_search_filter['type'] = 'samAccountName'
        user_search_filter['any'] = '*'
        
        ldap_filter = ldapasn1.Filter()
        ldap_filter['present'] = 'objectClass'
        
        user_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                       attributes=['sAMAccountName', 'userAccountControl', 
                                                  'pwdLastSet', 'memberOf'],
                                       searchBase=f"CN=Users,{base_dn}")
        
        for item in user_results:
            user = {}
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    user['username'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'userAccountControl':
                    uac = int(attr['vals'][0])
                    # Check for password never expires
                    if uac & 0x10000:
                        user['password_never_expires'] = True
                    # Check for password not required
                    if uac & 0x0020:
                        user['password_not_required'] = True
                    # Check for account not required to pre-authenticate
                    if uac & 0x400000:
                        user['no_preauth_required'] = True
                    # Check if account is disabled
                    if uac & 0x0002:
                        user['account_disabled'] = True
                elif attr['type'] == 'pwdLastSet':
                    pwd_last_set = int(attr['vals'][0])
                    if pwd_last_set == 0:
                        user['password_change_required'] = True
                    else:
                        # Convert Windows filetime to datetime
                        delta = datetime(1601, 1, 1)
                        seconds = pwd_last_set / 10**7
                        pwd_date = delta + timedelta(seconds=seconds)
                        user['password_last_set'] = pwd_date.strftime("%Y-%m-%d")
                        
                        # Check if password is old (>90 days)
                        if (datetime.now() - pwd_date).days > 90:
                            user['password_age_issue'] = True
                elif attr['type'] == 'memberOf':
                    user['groups'] = [g.decode('utf-8') for g in attr['vals']]
            
            if 'username' in user:
                ad_data['users'].append(user)
                
                # Check for weak account settings
                if any(k for k in user if k.startswith('password_') or k == 'no_preauth_required'):
                    ad_data['vulnerable_accounts'].append(user)
                    logger.warning(f"[AD] Vulnerable account settings for {user['username']}")
        
        # Get domain groups
        logger.info("[AD] Enumerating domain groups")
        group_search_filter = ldapasn1.SubstringFilter()
        group_search_filter['type'] = 'objectClass'
        group_search_filter['any'] = 'group'
        
        group_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                        attributes=['sAMAccountName', 'member'],
                                        searchBase=f"CN=Users,{base_dn}")
        
        for item in group_results:
            group = {}
            members = []
            
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    group['name'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'member':
                    members = [m.decode('utf-8') for m in attr['vals']]
            
            if 'name' in group:
                group['members'] = members
                ad_data['groups'].append(group)
                
                # Check if this is a privileged group
                privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators']
                if any(pg.lower() in group['name'].lower() for pg in privileged_groups):
                    group['privilege#!/usr/bin/env python3

import os
import re
import sys
import json
import socket
import sqlite3
import logging
import argparse
import subprocess
import shutil
import pandas as pd
import schedule
import time
import requests
from enum import Enum
from datetime import datetime
import concurrent.futures
import matplotlib
matplotlib.use("Agg")  # Headless environment
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET
from xml.dom import minidom

"""
Enhanced SMB-Scor3: A comprehensive tool for:
  1) Logging to SQLite
  2) SMB/Network enumeration
  3) Impacket-based intensity enumeration
  4) Parallel Nmap scanning
  5) Metasploit usage via msfconsole
  6) Vulnerability scoring with additional criteria
  7) Charting final scores with a Matplotlib line plot
  8) Web-based dashboard for reporting
  9) Scheduled scanning and trend analysis
  10) Enhanced vulnerability correlation with CVE lookup
  11) Remediation guidance
  12) Improved reporting with template system
  13) Active Directory integration
  14) Password policy assessment
  15) Multi-format export options
"""


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

def check_dependencies():
    """Check and install required Python libraries and external tools."""
    try:
        import impacket
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import wkst, srvs
    except ImportError:
        if logger:
            logger.info("[*] Installing impacket library...")
        subprocess.run(["pip", "install", "impacket"], check=True)
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import wkst, srvs

    # Check for other Python dependencies
    python_deps = ["pandas", "matplotlib", "jinja2", "flask", "requests"]
    for dep in python_deps:
        try:
            __import__(dep)
        except ImportError:
            if logger:
                logger.info(f"[*] Installing {dep} library...")
            subprocess.run(["pip", "install", dep], check=True)

    # Check for external tools
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
    host_data = {}
    
    for ip in hosts:
        logger.info(f"[*] Enumerating {ip} (LAN-wide logic)...")
        host_data[ip] = {
            "vulnerabilities": [],
            "open_ports": [],
            "plaintext_creds": 0,
            "missing_patches": 0,
            "host": ip
        }

        # a) Basic info (CME)
        try:
            cme = subprocess.run(["crackmapexec", "smb", ip],
                                 capture_output=True, text=True, check=True)
            logger.info("[crackmapexec info]\n" + cme.stdout.strip())
            
            # Extract data from CME output
            cme_out = cme.stdout.strip()
            host_data[ip]["cme_output"] = cme_out
            
            # Check for SMBv1
            if "SMBv1:True" in cme_out:
                host_data[ip]["vulnerabilities"].append("SMBv1 Enabled")
            
            # Add ports
            host_data[ip]["open_ports"].append(445)  # If CME works, 445 is open
            
        except Exception:
            logger.warning("[!] crackmapexec failed or not installed for host %s.", ip)

        # b) List shares (anonymous) with Impacket
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(ip, ip)
            conn.login('', '')  # Attempt anonymous
            shares = conn.listShares()
            msg = "[Shares (anonymous) via Impacket]:\n"
            
            host_data[ip]["shares"] = []
            for share in shares:
                share_name = share['shi1_netname'].rstrip('\x00')
                msg += f"  {share_name}\n"
                host_data[ip]["shares"].append(share_name)
                
                # Check for non-default shares that allow anonymous access
                if share_name not in ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"]:
                    try:
                        conn.listPath(share_name, '*')
                        host_data[ip]["vulnerabilities"].append(f"Anonymous Access to {share_name}")
                    except:
                        pass
                        
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
            
            # Extract user data
            host_data[ip]["users"] = []
            for line in sid_result.stdout.strip().splitlines():
                if "User:" in line:
                    user = line.split("User:")[1].strip()
                    host_data[ip]["users"].append(user)
                    
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
                    host_data[ip]["vulnerabilities"].append("Accessible NTLM Hashes")

        except Exception:
            # fallback
            rpc = subprocess.run(["rpcclient", "-U", "", "-N", ip, "-c", "lsaquery"],
                                 capture_output=True, text=True)
            logger.info("[rpcclient lsaquery output]:\n" + rpc.stdout.strip())
    
    return host_data


# ================== 4) INTENSITY-BASED IMPACKET ENUM ==================

class IntensityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

def enumerate_with_intensity(target, username, password, domain, intensity, host_data=None):
    """
    Uses Impacket-based enumeration for a single target based on intensity.
    Now updates host_data dictionary with findings.
    """
    logger.info(f"[+] Starting {intensity.name} enumeration for {target}")
    
    if host_data is None:
        host_data = {
            "vulnerabilities": [],
            "open_ports": [445],  # If we're doing SMB enumeration, 445 is open
            "plaintext_creds": 0,
            "missing_patches": 0,
            "host": target
        }
    
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import wkst, srvs
        
        conn = SMBConnection(target, target)
        conn.login(username, password, domain)
        
        # If we succeed with credentials, add to plaintext credentials count
        if username and password and username != '' and password != '':
            host_data["plaintext_creds"] += 1
            logger.info(f"[!] Valid credentials found: {domain}\\{username}:{password}")

        if intensity == IntensityLevel.LOW:
            logger.info("[LOW] Listing SMB shares...")
            shares = conn.listShares()
            host_data["shares"] = []
            for share in shares:
                share_name = share['shi1_netname']
                logger.info(f"    Share found: {share_name}")
                host_data["shares"].append(share_name)
                
                # Check for non-default shares
                if share_name not in ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"]:
                    try:
                        conn.listPath(share_name, '*')
                        host_data["vulnerabilities"].append(f"Access to {share_name} share")
                    except:
                        pass

        elif intensity == IntensityLevel.MEDIUM:
            logger.info("[MEDIUM] Enumerating logged-on users...")
            dce = conn.getDCE()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            request = wkst.NetrWkstaUserEnum()
            response = dce.request(request)
            
            host_data["logged_on_users"] = []
            for user in response['UserInfo']['WkstaUserInfo']:
                username = user['wkui1_username']
                logger.info(f"    Logged-on User: {username}")
                host_data["logged_on_users"].append(username)
            
            # Check for SMBv1 protocol
            server_os = conn.getServerOS()
            if "Windows 7" in server_os or "Windows Server 2008" in server_os:
                host_data["vulnerabilities"].append("Potential SMBv1 System (EOL OS)")
            
            # Check for MS17-010
            try:
                ms17_010_cmd = ["crackmapexec", "smb", target, "-u", username, "-p", password, "-M", "ms17-010"]
                ms17_output = subprocess.run(ms17_010_cmd, capture_output=True, text=True)
                if "MS17-010" in ms17_output.stdout and "VULNERABLE" in ms17_output.stdout:
                    host_data["vulnerabilities"].append("MS17-010 (EternalBlue)")
                    logger.warning(f"[!] {target} is VULNERABLE to MS17-010!")
            except:
                logger.warning(f"Could not check MS17-010 on {target}")

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
                
                host_data["active_sessions"] = []
                if response['SessionInfo']['Level'] == 10:
                    for session in response['SessionInfo']['SessionInfo10']:
                        session_user = session['sesi10_username']
                        session_client = session['sesi10_cname']
                        logger.info(
                            f"    Session => User: {session_user}, "
                            f"Client: {session_client}, Time: {session['sesi10_time']}"
                        )
                        host_data["active_sessions"].append({
                            "user": session_user,
                            "client": session_client,
                            "time": session['sesi10_time']
                        })
                else:
                    logger.info("    No active sessions found.")
            except Exception as e:
                logger.warning(f"Error enumerating sessions on {target}: {e}")

            # 2) Check for writable/exploitable shares
            logger.info("Checking for writable shares...")
            try:
                shares = conn.listShares()
                host_data["writable_shares"] = []
                for share in shares:
                    share_name = share['shi1_netname']
                    if not share_name.endswith('$'):
                        try:
                            conn.listPath(share_name, '*')
                            logger.info(f"    Share '{share_name}' is accessible/writable.")
                            host_data["writable_shares"].append(share_name)
                            
                            # Try to write a test file
                            test_file = "smb_write_test.txt"
                            try:
                                conn.putFile(share_name, test_file, b"SMB write test")
                                logger.warning(f"[!] Share '{share_name}' allows file writes!")
                                host_data["vulnerabilities"].append(f"Writable Share: {share_name}")
                                # Clean up test file
                                conn.deleteFile(share_name, test_file)
                            except:
                                pass
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
                host_data["server_name"] = server_info
                
                # Check for additional protocols
                server_os = conn.getServerOS()
                host_data["server_os"] = server_os
                logger.info(f"    Server OS: {server_os}")
                
                # Check for potentially vulnerable configurations
                if "Windows XP" in server_os or "Windows Server 2003" in server_os:
                    host_data["vulnerabilities"].append("End-of-Life OS")
                    host_data["missing_patches"] += 5  # Heavily penalize EOL systems
                elif "Windows 7" in server_os or "Windows Server 2008" in server_os:
                    host_data["vulnerabilities"].append("End-of-Support OS")
                    host_data["missing_patches"] += 3
                
                # Run OS-specific vulnerability checks
                try:
                    vuln_checks = [
                        {"name": "MS17-010", "cmd": ["crackmapexec", "smb", target, "-u", username, "-p", password, "-M", "ms17-010"]},
                        {"name": "SMB Signing", "cmd": ["crackmapexec", "smb", target, "-u", username, "-p", password, "--gen-relay-list", "/dev/null"]}
                    ]
                    
                    for check in vuln_checks:
                        check_output = subprocess.run(check["cmd"], capture_output=True, text=True)
                        if check["name"] == "MS17-010" and "VULNERABLE" in check_output.stdout:
                            host_data["vulnerabilities"].append("MS17-010 (EternalBlue)")
                        elif check["name"] == "SMB Signing" and "SMB signing is disabled" in check_output.stdout:
                            host_data["vulnerabilities"].append("SMB Signing Disabled")
                except Exception as e:
                    logger.warning(f"Error during vulnerability checks on {target}: {e}")
                    
            except Exception as e:
                logger.warning(f"Error enumerating services on {target}: {e}")

            # 4) Try to obtain patch level
            try:
                wmi_cmd = ["wmic", "-U", f"{domain}/{username}%{password}", f"//{target}", "qfe", "list", "brief"]
                wmi_output = subprocess.run(wmi_cmd, capture_output=True, text=True)
                
                if wmi_output.returncode == 0:
                    logger.info("Patch information retrieved")
                    
                    # Look for recent security patches
                    if "KB5022282" not in wmi_output.stdout:  # Example recent security patch
                        host_data["missing_patches"] += 1
                else:
                    logger.warning(f"Could not retrieve patch information from {target}")
            except Exception as e:
                logger.warning(f"Error checking patches on {target}: {e}")

        conn.close()

    except Exception as e:
        logger.error(f"Error during Impacket enumeration of {target}: {e}")
    
    return host_data


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

def run_nmap_scan(target, script_category=None, db_path="smb_enum.db", host_data=None):
    """
    Run an nmap scan on one target, with optional script categories.
    Save XML output, insert record into DB.
    Now updates host_data dictionary with findings.
    """
    if host_data is None:
        host_data = {
            "vulnerabilities": [],
            "open_ports": [],
            "plaintext_creds": 0, 
            "missing_patches": 0,
            "host": target
        }
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_filename = f"nmap_results_{timestamp_str}_{target.replace('/', '_')}.xml"
    cmd = ["nmap", "-sV", "-p", "21,22,23,25,53,80,139,445,1433,3306,3389,5900,8080,8443", "-oX", xml_filename]

    if script_category:
        cmd += ["--script", script_category]
    cmd += [target]

    logger.info(f"[Nmap] Scanning {target} with script category: {script_category or 'None'}")
    logger.info(f"[Nmap] Command: {' '.join(cmd)}")

    try:
        run_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(f"[Nmap Output for {target}]\n{run_result.stdout}")
        
        # Parse XML output to get open ports and vulnerabilities
        try:
            tree = ET.parse(xml_filename)
            root = tree.getroot()
            
            # Get open ports
            for port in root.findall(".//port[@state='open']"):
                port_num = int(port.get('portid'))
                host_data["open_ports"].append(port_num)
                
                # Check for services with default credentials
                service = port.find("service")
                if service is not None:
                    service_name = service.get('name', '')
                    
                    # Check for potentially vulnerable services
                    if service_name == "ms-sql-s":
                        host_data["vulnerabilities"].append("MS SQL Server Exposed")
                    elif service_name == "mysql":
                        host_data["vulnerabilities"].append("MySQL Exposed")
                    elif service_name == "telnet":
                        host_data["vulnerabilities"].append("Telnet (Cleartext) Exposed")
                    elif service_name == "ftp":
                        host_data["vulnerabilities"].append("FTP Service Exposed")
            
            # Get script results for vulnerabilities
            for script in root.findall(".//script"):
                script_id = script.get('id', '')
                script_output = script.get('output', '')
                
                # Check for vulnerability scripts
                if script_id.startswith("vuln-") or "vuln" in script_id:
                    if "VULNERABLE" in script_output:
                        vuln_name = script_id.replace("vuln-", "").upper()
                        host_data["vulnerabilities"].append(vuln_name)
                        logger.warning(f"[!] Vulnerability found: {vuln_name}")
                
                # Check for default credentials
                if "default credential" in script_output.lower() or "default password" in script_output.lower():
                    host_data["plaintext_creds"] += 1
                    host_data["vulnerabilities"].append("Default Credentials")
                    
        except Exception as e:
            logger.warning(f"Error parsing Nmap XML output: {e}")
        
    except subprocess.CalledProcessError as e:
        logger.warning(f"Nmap scan failed for {target}: {e}\n{e.output}")

    # Log to DB
    full_cmd_str = " ".join(cmd)
    log_nmap_scan_to_db(db_path, target, full_cmd_str, os.path.abspath(xml_filename))
    
    return host_data

def advanced_nmap_menu(db_path="smb_enum.db", host_data=None):
    """
    Allows user to specify multiple targets for parallel scanning,
    choose an NSE script category, and run them concurrently.
    Now updates host_data dictionary with findings.
    """
    if host_data is None:
        host_data = {}
        
    logger.info("\n=== ADVANCED NMAP PARALLEL SCANS ===")
    targets_input = input("Enter targets (comma-separated, e.g. '192.168.1.10,192.168.1.20/24'): ").strip()
    if not targets_input:
        logger.warning("No targets provided. Returning.")
        return host_data

    targets = [t.strip() for t in targets_input.split(",") if t.strip()]

    logger.info("Common NSE categories: 'discovery', 'safe', 'default', 'vuln'")
    script_category = input("Enter an NSE script category or leave blank for none: ").strip()

    max_workers = 5
    logger.info(f"Starting parallel Nmap scans on {len(targets)} target(s) with up to {max_workers} workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for target in targets:
            if target not in host_data:
                host_data[target] = {
                    "vulnerabilities": [],
                    "open_ports": [],
                    "plaintext_creds": 0,
                    "missing_patches": 0,
                    "host": target
                }
            future = executor.submit(run_nmap_scan, target, script_category, db_path, host_data[target])
            futures[future] = target

        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                target_data = future.result()
                host_data[target] = target_data
            except Exception as e:
                logger.error(f"Error in Nmap scan for {target}: {e}")
    
    logger.info("Parallel Nmap scans completed.")
    return host_data


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

def run_metasploit_module(target, module_name, options=None, db_path="smb_enum.db", host_data=None):
    """
    Launch msfconsole non-interactively with a specific module, set RHOSTS, run, exit.
    Now updates host_data dictionary with findings.
    """
    if host_data is None:
        host_data = {
            "vulnerabilities": [],
            "open_ports": [],
            "plaintext_creds": 0,
            "missing_patches": 0,
            "host": target
        }
        
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
        
        # Check output for vulnerability indicators
        if module_name == "auxiliary/scanner/smb/smb_ms17_010":
            if "MS17-010" in output and "VULNERABLE" in output:
                host_data["vulnerabilities"].append("MS17-010 (EternalBlue)")
                logger.warning(f"[!] {target} is VULNERABLE to MS17-010 (EternalBlue)!")
        
        elif module_name == "auxiliary/scanner/smb/smb_version":
            # Extract SMB version info
            if "SMBv1" in output:
                host_data["vulnerabilities"].append("SMBv1 Enabled")
            
            # Look for EOL OS versions
            for eol_os in ["Windows XP", "Windows 2003", "Windows 2000"]:
                if eol_os in output:
                    host_data["vulnerabilities"].append(f"EOL OS: {eol_os}")
                    host_data["missing_patches"] += 5
        
        elif module_name == "auxiliary/scanner/ftp/anonymous":
            if "Anonymous READ" in output:
                host_data["vulnerabilities"].append("Anonymous FTP Access")
                host_data["plaintext_creds"] += 1
                logger.warning(f"[!] {target} allows anonymous FTP access!")
                
        # Add more module-specific checks here as needed
        
    except subprocess.CalledProcessError as e:
        output = f"Metasploit run failed: {e}\n{e.output}"
        logger.warning(output)

    # Log result
    log_metasploit_run_to_db(db_path, target, module_name, output)
    
    return host_data

def metasploit_menu(db_path="smb_enum.db", host_data=None):
    """
    Enhanced Metasploit menu with more modules and host_data tracking.
    """
    if host_data is None:
        host_data = {}
        
    while True:
        logger.info("\n=== METASPLOIT MENU ===")
        logger.info("1) SMB Version (auxiliary/scanner/smb/smb_version)")
        logger.info("2) MS17-010 (auxiliary/scanner/smb/smb_ms17_010)")
        logger.info("3) FTP Anonymous (auxiliary/scanner/ftp/anonymous)")
        logger.info("4) SMB Login (auxiliary/scanner/smb/smb_login)")
        logger.info("5) SSH Login (auxiliary/scanner/ssh/ssh_login)")
        logger.info("6) MySQL Login (auxiliary/scanner/mysql/mysql_login)")
        logger.info("7) Web Vulnerabilities (auxiliary/scanner/http/dir_scanner)")
        logger.info("0) Return to main menu")

        choice = input("Select a Metasploit module (0 to exit): ").strip()
        if choice == '0':
            break

        target = input("Enter target IP or range (RHOSTS): ").strip()
        if not target:
            logger.warning("No target specified.")
            continue
            
        # Initialize host_data for this target if it doesn't exist
        if target not in host_data:
            host_data[target] = {
                "vulnerabilities": [],
                "open_ports": [],
                "plaintext_creds": 0,
                "missing_patches": 0,
                "host": target
            }

        if choice == '1':
            run_metasploit_module(target, "auxiliary/scanner/smb/smb_version", db_path=db_path, host_data=host_data[target])
        elif choice == '2':
            run_metasploit_module(target, "auxiliary/scanner/smb/smb_ms17_010", db_path=db_path, host_data=host_data[target])
        elif choice == '3':
            run_metasploit_module(target, "auxiliary/scanner/ftp/anonymous", db_path=db_path, host_data=host_data[target])
        elif choice == '4':
            username = input("Enter username (or 'file:/path/to/userlist'): ")
            password = input("Enter password (or 'file:/path/to/passlist'): ")
            options = {"SMBUser": username, "SMBPass": password}
            run_metasploit_module(target, "auxiliary/scanner/smb/smb_login", options, db_path, host_data[target])
        elif choice == '5':
            username = input("Enter username (or 'file:/path/to/userlist'): ")
            password = input("Enter password (or 'file:/path/to/passlist'): ")
            options = {"USERNAME": username, "PASSWORD": password}
            run_metasploit_module(target, "auxiliary/scanner/ssh/ssh_login", options, db_path, host_data[target])
        elif choice == '6':
            username = input("Enter username (or 'file:/path/to/userlist'): ")
            password = input("Enter password (or 'file:/path/to/passlist'): ")
            options = {"USERNAME": username, "PASSWORD": password}
            run_metasploit_module(target, "auxiliary/scanner/mysql/mysql_login", options, db_path, host_data[target])
        elif choice == '7':
            run_metasploit_module(target, "auxiliary/scanner/http/dir_scanner", db_path=db_path, host_data=host_data[target])
        else:
            logger.info("Invalid choice. Please pick 0-7.")
    
    return host_data


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
            cvss_score REAL,
            critical_vulns INT,
            final_score INT,
            risk_category TEXT
        )
    ''')
    conn.commit()
    conn.close()

def enhance_vulnerability_scoring(host_data):
    """
    Enhancement: Add CVE lookup and scoring based on CVSS.
    """
    vulnerabilities = host_data.get("vulnerabilities", [])
    total_cvss_score = 0
    critical_vulns = 0
    
    # Define known vulnerabilities with CVSS scores
    vuln_cvss_map = {
        "MS17-010": 9.8,  # EternalBlue
        "SMBv1 Enabled": 7.5,
        "EOL OS": 8.0,
        "Anonymous FTP Access": 5.0,
        "Default Credentials": 7.0,
        "SMB Signing Disabled": 5.8,
        "Writable Share": 6.0,
    }
    
    for vuln in vulnerabilities:
        # Check if we have a predefined CVSS score
        base_vuln_name = next((k for k in vuln_cvss_map.keys() if k in vuln), None)
        if base_vuln_name:
            cvss_score = vuln_cvss_map[base_vuln_name]
            total_cvss_score += cvss_score
            
            if cvss_score >= 9.0:
                critical_vulns += 1
            
            logger.info(f"CVSS score for {vuln}: {cvss_score}")
        else:
            # For unknown vulnerabilities, try to look up CVE if present
            cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', vuln)
            if cve_match:
                cve_id = cve_match.group(1)
                try:
                    logger.info(f"Looking up CVSS score for {cve_id}")
                    response = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if 'result' in data and 'CVE_Items' in data['result'] and len(data['result']['CVE_Items']) > 0:
                            if 'impact' in data['result']['CVE_Items'][0] and 'baseMetricV3' in data['result']['CVE_Items'][0]['impact']:
                                cvss_score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                                total_cvss_score += float(cvss_score)
                                
                                if float(cvss_score) >= 9.0:
                                    critical_vulns += 1
                                    
                                logger.info(f"CVSS score for {cve_id}: {cvss_score}")
                            else:
                                # Fallback to baseMetricV2 if V3 not available
                                if 'baseMetricV2' in data['result']['CVE_Items'][0]['impact']:
                                    cvss_score = data['result']['CVE_Items'][0]['impact']['baseMetricV2']['cvssV2']['baseScore']
                                    total_cvss_score += float(cvss_score)
                                    logger.info(f"CVSS V2 score for {cve_id}: {cvss_score}")
                                else:
                                    logger.warning(f"No CVSS score found for {cve_id}")
                                    total_cvss_score += 5  # Default medium score
                        else:
                            logger.warning(f"No CVE data found for {cve_id}")
                            total_cvss_score += 5  # Default medium score
                except Exception as e:
                    logger.warning(f"Error looking up CVE {cve_id}: {e}")
                    total_cvss_score += 5  # Default medium score
            else:
                # Generic vulnerability with no CVE ID
                total_cvss_score += 5  # Default medium score
    
    # Update host_data with CVSS information
    host_data['cvss_score'] = total_cvss_score
    host_data['critical_vulns'] = critical_vulns
    
    return host_data

def calculate_vulnerability_score(host_data: dict):
    """
    Enhanced scoring algorithm including CVSS scores and critical vulnerabilities.
    
    Scoring weights:
      - Base score: 100 points
      - Each vulnerability: -15 points
      - Each open port: -5 points
      - Each plaintext credential: -10 points
      - Each missing patch: -5 points
      - Each high-risk port: -3 additional points
      - Critical vulnerabilities: -20 points each
      - CVSS score adjustment: -1 point per CVSS point
      
    Returns:
      (final_score, vuln_count, open_port_count, high_risk_count, plaintext_creds, 
       missing_patches, cvss_score, critical_vulns, category)
    """
    score = 100

    # Allow configuration of scoring weights
    VULN_PENALTY = 15
    PORT_PENALTY = 5
    CREDS_PENALTY = 10
    PATCH_PENALTY = 5
    HIGH_RISK_PENALTY = 3
    CRITICAL_VULN_PENALTY = 20
    CVSS_PENALTY_FACTOR = 1

    vulnerabilities = host_data.get("vulnerabilities", [])
    open_ports = host_data.get("open_ports", [])
    plaintext_creds = host_data.get("plaintext_creds", 0)
    missing_patches = host_data.get("missing_patches", 0)
    cvss_score = host_data.get("cvss_score", 0)
    critical_vulns = host_data.get("critical_vulns", 0)

    vuln_count = len(vulnerabilities)
    open_port_count = len(open_ports)

    # Subtract for each vulnerability
    score -= (vuln_count * VULN_PENALTY)
    # Subtract for each open port
    score -= (open_port_count * PORT_PENALTY)
    # Subtract for discovered plaintext creds
    score -= (plaintext_creds * CREDS_PENALTY)
    # Subtract for missing patches
    score -= (missing_patches * PATCH_PENALTY)
    # Subtract for critical vulnerabilities (additional penalty)
    score -= (critical_vulns * CRITICAL_VULN_PENALTY)
    # Subtract based on CVSS score
    score -= (cvss_score * CVSS_PENALTY_FACTOR)

    # Additional penalty for high-risk ports
    high_risk_list = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
    high_risk_count = sum(1 for p in open_ports if p in high_risk_list)
    score -= (high_risk_count * HIGH_RISK_PENALTY)

    final_score = max(score, 0)

    # Risk category thresholds
    LOW_THRESHOLD = 80
    MEDIUM_THRESHOLD = 50
    HIGH_THRESHOLD = 20

    # Risk category
    if final_score >= LOW_THRESHOLD:
        category = "Low"
    elif final_score >= MEDIUM_THRESHOLD:
        category = "Medium"
    elif final_score >= HIGH_THRESHOLD:
        category = "High"
    else:
        category = "Critical"

    return (final_score, vuln_count, open_port_count, high_risk_count, plaintext_creds, 
            missing_patches, cvss_score, critical_vulns, category)

def log_vulnerability_score(db_path: str,
                            host: str,
                            open_ports: int,
                            vulnerabilities: int,
                            high_risk_ports: int,
                            plaintext_creds: int,
                            missing_patches: int,
                            cvss_score: float,
                            critical_vulns: int,
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
            cvss_score, critical_vulns, final_score, risk_category
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, host, open_ports, vulnerabilities,
          high_risk_ports, plaintext_creds, missing_patches,
          cvss_score, critical_vulns, final_score, category))
    conn.commit()
    conn.close()

def add_remediation_recommendations(host_data: dict, db_path="smb_enum.db"):
    """
    Generate specific remediation steps based on findings.
    """
    if "host" not in host_data:
        logger.warning("Host data missing 'host' field, cannot generate recommendations")
        return []
    
    host = host_data["host"]
    recommendations = []
    
    # Remediation mappings for common vulnerabilities
    remediation_map = {
        "SMBv1 Enabled": {
            "severity": "HIGH",
            "finding": "SMBv1 Protocol Enabled",
            "remediation": "Disable SMBv1 protocol using Group Policy or registry settings.",
            "reference": "https://support.microsoft.com/en-us/topic/how-to-enable-and-disable-smbv1-19be6424-5dd5-4797-8385-75488a9c54c5"
        },
        "MS17-010": {
            "severity": "CRITICAL",
            "finding": "MS17-010 (EternalBlue) Vulnerability",
            "remediation": "Apply Microsoft security patch MS17-010 immediately.",
            "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
        },
        "SMB Signing Disabled": {
            "severity": "MEDIUM",
            "finding": "SMB Signing Disabled",
            "remediation": "Enable SMB signing via Group Policy.",
            "reference": "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-client-digitally-sign-communications-always"
        },
        "Anonymous FTP Access": {
            "severity": "HIGH",
            "finding": "Anonymous FTP Access",
            "remediation": "Disable anonymous FTP access or restrict permissions.",
            "reference": "https://www.stigviewer.com/stig/ftp_server/2015-06-01/finding/V-1"
        },
        "Default Credentials": {
            "severity": "CRITICAL",
            "finding": "Default Credentials in Use",
            "remediation": "Change all default passwords and implement a strong password policy.",
            "reference": "https://www.cisa.gov/sites/default/files/publications/Eliminating_Obsolete_Connections.pdf"
        },
        "EOL OS": {
            "severity": "CRITICAL",
            "finding": "End-of-Life Operating System",
            "remediation": "Upgrade to a supported operating system version immediately.",
            "reference": "https://www.cisa.gov/sites/default/files/publications/Assess_Your_Cyber_Infrastructure.pdf"
        },
        "Writable Share": {
            "severity": "HIGH",
            "finding": "Insecure File Share Permissions",
            "remediation": "Review and restrict share permissions to authorized users only.",
            "reference": "https://docs.microsoft.com/en-us/windows-server/storage/file-server/configure-security-permissions-file-share"
        }
    }
    
    # Check vulnerabilities against remediation map
    for vuln in host_data.get("vulnerabilities", []):
        for vuln_key, remedy in remediation_map.items():
            if vuln_key in vuln:  # Partial match to catch variants
                recommendations.append({
                    "severity": remedy["severity"],
                    "finding": remedy["finding"],
                    "remediation": remedy["remediation"],
                    "reference": remedy["reference"]
                })
                break
    
    # Check for high-risk ports
    high_risk_ports = []
    for port in host_data.get("open_ports", []):
        if port in [21, 23, 139, 445, 3389]:
            high_risk_ports.append(port)
    
    if high_risk_ports:
        port_list = ", ".join(str(p) for p in high_risk_ports)
        recommendations.append({
            "severity": "MEDIUM",
            "finding": f"High-risk ports exposed: {port_list}",
            "remediation": "Filter or close unnecessary high-risk ports at the firewall.",
            "reference": "https://www.cisa.gov/sites/default/files/publications/Securing_Network_Infrastructure_Devices.pdf"
        })
    
    # Check if plaintext credentials were found
    if host_data.get("plaintext_creds", 0) > 0:
        recommendations.append({
            "severity": "HIGH",
            "finding": "Plaintext Credentials Discovered",
            "remediation": "Implement secure authentication and encrypt all credential storage.",
            "reference": "https://csrc.nist.gov/publications/detail/sp/800-63/3/final"
        })
    
    # Check missing patches
    if host_data.get("missing_patches", 0) > 0:
        recommendations.append({
            "severity": "HIGH",
            "finding": "Missing Security Patches",
            "remediation": "Implement a regular patching schedule and verify patch installation.",
            "reference": "https://www.cisa.gov/sites/default/files/publications/Patch_Management.pdf"
        })
    
    # Log recommendations to database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS remediation_recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT,
                timestamp TEXT,
                severity TEXT,
                finding TEXT,
                remediation TEXT,
                reference TEXT)''')
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for rec in recommendations:
        c.execute('''INSERT INTO remediation_recommendations 
                    (host, timestamp, severity, finding, remediation, reference) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (host, timestamp, 
                  rec['severity'], rec['finding'], 
                  rec['remediation'], rec['reference']))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Generated {len(recommendations)} remediation recommendations for {host}")
    return recommendations

def run_vulnerability_scoring_workflow(db_path: str, discovered_data: dict):
    """
    Enhanced vulnerability scoring workflow with remediation guidance.
    """
    setup_vulnerability_scores_table(db_path)

    host_scores = {}
    remediation_results = {}

    for host, data in discovered_data.items():
        # Enhance scoring with CVSS data
        data = enhance_vulnerability_scoring(data)
        
        # Calculate score
        (final_score, vuln_count, open_count, high_risk_count,
         plain_creds, missing_patches, cvss_score, critical_vulns, category) = calculate_vulnerability_score(data)

        logger.info(f"[Score] {host}: final_score={final_score}, category={category}, CVSS={cvss_score}")
        
        # Generate remediation recommendations
        remediation_results[host] = add_remediation_recommendations(data, db_path)
        
        # Insert into DB
        log_vulnerability_score(db_path,
                                host,
                                open_count,
                                vuln_count,
                                high_risk_count,
                                plain_creds,
                                missing_patches,
                                cvss_score,
                                critical_vulns,
                                final_score,
                                category)
        host_scores[host] = final_score

    # Create line plot of final scores
    create_line_plot_of_scores(host_scores)
    
    # Generate comprehensive report
    generate_reports(db_path, host_scores, remediation_results)
    
    return host_scores, remediation_results, schedule_time):
                logger.error("Invalid time format. Must be HH:MM.")
                continue
                
            network = input("Network CIDR to scan: ").strip()
            if not network:
                logger.error("Network CIDR is required.")
                continue
                
            db_path = input("Database path (default: smb_enum.db): ").strip()
            if not db_path:
                db_path = "smb_enum.db"
                
            print(f"\nSchedule setup: {schedule_type} scan at {schedule_time} of {network}")
            confirm = input("Confirm? (y/n): ").strip().lower()
            
            if confirm == 'y':
                logger.info(f"Setting up {schedule_type} scan at {schedule_time} of {network}")
                # Create a launcher script for scheduled task
                with open("scheduled_scan.py", "w") as f:
                    f.write(f"""#!/usr/bin/env python3
# Auto-generated scheduled scan script
import sys
import os
import time

# Add current directory to path to find modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from smb_score import setup_logger, discover_smb_hosts, enumerate_lan_hosts, run_nmap_scan
from smb_score import run_vulnerability_scoring_workflow, add_export_functionality, generate_reports

def scheduled_scan_job():
    logger = setup_logger("{db_path}")
    logger.info("[SCHEDULED] Starting scheduled scan of {network}")
    
    # Discover hosts
    discovered_hosts = discover_smb_hosts("{network}")
    
    # Gather host data
    host_data = enumerate_lan_hosts(discovered_hosts)
    
    # Run Nmap scans
    for host in discovered_hosts:
        host_data[host] = run_nmap_scan(host, "vuln", "{db_path}", host_data[host])
    
    # Calculate vulnerability scores
    run_vulnerability_scoring_workflow("{db_path}", host_data)
    
    # Export results
    add_export_functionality("{db_path}")
    
    # Generate report
    generate_reports("{db_path}")
    
    logger.info("[SCHEDULED] Completed scheduled scan")

if __name__ == "__main__":
    scheduled_scan_job()
""")
                
                # Set up the scheduling based on OS
                if os.name == 'nt':  # Windows
                    # Create a Windows Task Scheduler task
                    schedule_cmd = f'schtasks /create /tn "SMB-Scor3 Scan" /tr "python {os.path.abspath("scheduled_scan.py")}" /sc {schedule_type.upper()} /st {schedule_time}'
                    if schedule_type == 'weekly':
                        schedule_cmd += ' /d MON'  # Run on Mondays
                    
                    try:
                        subprocess.run(schedule_cmd, shell=True, check=True)
                        logger.info("Scheduled task created successfully in Windows Task Scheduler")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to create scheduled task: {e}")
                        
                else:  # Linux/Unix/macOS
                    # Set up crontab entry
                    hour, minute = schedule_time.split(':')
                    day_of_week = '1' if schedule_type == 'weekly' else '*'  # 1 = Monday in crontab
                    
                    cron_cmd = f"{minute} {hour} * * {day_of_week} python3 {os.path.abspath('scheduled_scan.py')}"
                    
                    try:
                        # Get existing crontab
                        crontab = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                        if crontab.returncode != 0:
                            # No crontab exists yet
                            crontab_content = ""
                        else:
                            crontab_content = crontab.stdout
                            
                        # Add our entry
                        crontab_content += f"\n# SMB-Scor3 Scheduled Scan\n{cron_cmd}\n"
                        
                        # Write to temp file and load it
                        with open("temp_crontab", "w") as f:
                            f.write(crontab_content)
                            
                        subprocess.run(['crontab', 'temp_crontab'], check=True)
                        os.remove("temp_crontab")
                        
                        logger.info("Scheduled task created successfully in crontab")
                    except Exception as e:
                        logger.error(f"Failed to create crontab entry: {e}")
            else:
                logger.info("Scheduled scan setup cancelled.")
                
        else:
            logger.warning("Invalid choice. Please select a valid option (0-10).")
    
    logger.info("Thank you for using SMB-Scor3 Enhanced!")


if __name__ == "__main__":
    main()
_score": 9.8,
                            "critical_vulns": 1
                        },
                        "192.168.1.11": {
                            "vulnerabilities": [],
                            "open_ports": [80, 443],
                            "plaintext_creds": 0,
                            "missing_patches": 0,
                            "host": "192.168.1.11",
                            "cvss# ================== 10) ACTIVE DIRECTORY INTEGRATION ==================

def add_ad_enumeration(domain, username, password, target_dc=None, db_path="smb_enum.db"):
    """
    Perform Active Directory enumeration using impacket tools.
    """
    logger.info(f"[AD] Starting Active Directory enumeration for domain {domain}")
    
    ad_data = {
        "users": [],
        "groups": [],
        "vulnerable_accounts": [],
        "risky_settings": [],
        "domain": domain
    }
    
    try:
        from impacket.ldap import ldap
        from impacket.ldap import ldapasn1
        from impacket.smbconnection import SMBConnection
        
        # Connect to LDAP
        if not target_dc:
            # Try to find DC
            smb = SMBConnection('*SMBSERVER', '')
            smb.login('', '')
            primary_dc = smb.getServerDNSDomainName()
            target_dc = primary_dc
            logger.info(f"[AD] Detected domain controller: {target_dc}")
        
        logger.info(f"[AD] Connecting to LDAP on {target_dc}")
        
        ldap_conn = ldap.LDAPConnection(f'ldap://{target_dc}', domain, username, password)
        base_dn = ','.join(f"DC={part}" for part in domain.split('.'))
        
        # Get domain users
        logger.info("[AD] Enumerating domain users")
        user_search_filter = ldapasn1.SubstringFilter()
        user_search_filter['type'] = 'samAccountName'
        user_search_filter['any'] = '*'
        
        ldap_filter = ldapasn1.Filter()
        ldap_filter['present'] = 'objectClass'
        
        user_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                       attributes=['sAMAccountName', 'userAccountControl', 
                                                  'pwdLastSet', 'memberOf'],
                                       searchBase=f"CN=Users,{base_dn}")
        
        for item in user_results:
            user = {}
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    user['username'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'userAccountControl':
                    uac = int(attr['vals'][0])
                    # Check for password never expires
                    if uac & 0x10000:
                        user['password_never_expires'] = True
                    # Check for password not required
                    if uac & 0x0020:
                        user['password_not_required'] = True
                    # Check for account not required to pre-authenticate
                    if uac & 0x400000:
                        user['no_preauth_required'] = True
                    # Check if account is disabled
                    if uac & 0x0002:
                        user['account_disabled'] = True
                elif attr['type'] == 'pwdLastSet':
                    pwd_last_set = int(attr['vals'][0])
                    if pwd_last_set == 0:
                        user['password_change_required'] = True
                    else:
                        # Convert Windows filetime to datetime
                        delta = datetime(1601, 1, 1)
                        seconds = pwd_last_set / 10**7
                        pwd_date = delta + timedelta(seconds=seconds)
                        user['password_last_set'] = pwd_date.strftime("%Y-%m-%d")
                        
                        # Check if password is old (>90 days)
                        if (datetime.now() - pwd_date).days > 90:
                            user['password_age_issue'] = True
                elif attr['type'] == 'memberOf':
                    user['groups'] = [g.decode('utf-8') for g in attr['vals']]
            
            if 'username' in user:
                ad_data['users'].append(user)
                
                # Check for weak account settings
                if any(k for k in user if k.startswith('password_') or k == 'no_preauth_required'):
                    ad_data['vulnerable_accounts'].append(user)
                    logger.warning(f"[AD] Vulnerable account settings for {user['username']}")
        
        # Get domain groups
        logger.info("[AD] Enumerating domain groups")
        group_search_filter = ldapasn1.SubstringFilter()
        group_search_filter['type'] = 'objectClass'
        group_search_filter['any'] = 'group'
        
        group_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                        attributes=['sAMAccountName', 'member'],
                                        searchBase=f"CN=Users,{base_dn}")
        
        for item in group_results:
            group = {}
            members = []
            
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    group['name'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'member':
                    members = [m.decode('utf-8') for m in attr['vals']]
            
            if 'name' in group:
                group['members'] = members
                ad_data['groups'].append(group)
                
                # Check if this is a privileged group
                privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators']
                if any(pg.lower() in group['name'].lower() for pg in privileged_groups):
                    group['privileged'] = True
                    ad_data['risky_settings'].append({
                        'type': 'Privileged Group',
                        'name': group['name'],
                        'members_count': len(members),
                        'risk': 'HIGH' if len(members) > 5 else 'MEDIUM',
                        'recommendation': 'Review privileged group membership and minimize number of accounts'
                    })
                    logger.warning(f"[AD] Privileged group {group['name']} has {len(members)} members")
        
        # Check for Kerberoasting vulnerabilities
        logger.info("[AD] Checking for Kerberoastable service accounts")
        service_filter = ldapasn1.Filter()
        service_filter['present'] = 'servicePrincipalName'
        
        service_results = ldap_conn.search(
            searchFilter=str(service_filter),
            attributes=['sAMAccountName', 'servicePrincipalName', 'userAccountControl'],
            searchBase=base_dn
        )
        
        kerberoastable_accounts = []
        for item in service_results:
            service_account = {'spns': []}
            
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    service_account['username'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'servicePrincipalName':
                    service_account['spns'] = [spn.decode('utf-8') for spn in attr['vals']]
                elif attr['type'] == 'userAccountControl':
                    uac = int(attr['vals'][0])
                    service_account['uac'] = uac
                    # Check if account doesn't require Kerberos pre-authentication
                    if uac & 0x400000:
                        service_account['asreproastable'] = True
            
            if 'username' in service_account and service_account['spns']:
                kerberoastable_accounts.append(service_account)
                ad_data['risky_settings'].append({
                    'type': 'Kerberoastable Account',
                    'name': service_account['username'],
                    'spn_count': len(service_account['spns']),
                    'risk': 'HIGH',
                    'recommendation': 'Use strong password for service accounts with SPNs and rotate regularly'
                })
                logger.warning(f"[AD] Kerberoastable account: {service_account['username']} with {len(service_account['spns'])} SPNs")
                
                if service_account.get('asreproastable'):
                    ad_data['risky_settings'].append({
                        'type': 'ASREPRoastable Account',
                        'name': service_account['username'],
                        'risk': 'CRITICAL',
                        'recommendation': 'Enable Kerberos pre-authentication for this account immediately'
                    })
                    logger.warning(f"[AD] CRITICAL: {service_account['username']} doesn't require Kerberos pre-authentication!")
        
        # Check domain password policy
        logger.info("[AD] Checking domain password policy")
        try:
            policy_filter = ldapasn1.Filter()
            policy_filter['present'] = 'objectClass'
            
            policy_results = ldap_conn.search(
                searchFilter=str(policy_filter),
                attributes=['maxPwdAge', 'minPwdLength', 'lockoutThreshold'],
                searchBase=f"CN=Password Settings Container,CN=System,{base_dn}"
            )
            
            for item in policy_results:
                policy = {}
                
                for attr in item['attributes']:
                    if attr['type'] == 'maxPwdAge':
                        # Convert large integer to days
                        max_pwd_age = int(attr['vals'][0])
                        max_days = abs(max_pwd_age) / (10**7 * 86400)
                        policy['max_password_age'] = int(max_days)
                        
                        if max_days == 0 or max_days > 90:
                            ad_data['risky_settings'].append({
                                'type': 'Weak Password Policy',
                                'setting': 'Maximum Password Age',
                                'value': f"{int(max_days)} days" if max_days > 0 else "Never expires",
                                'risk': 'HIGH',
                                'recommendation': 'Set maximum password age to 60-90 days'
                            })
                    elif attr['type'] == 'minPwdLength':
                        min_length = int(attr['vals'][0])
                        policy['min_password_length'] = min_length
                        
                        if min_length < 12:
                            ad_data['risky_settings'].append({
                                'type': 'Weak Password Policy',
                                'setting': 'Minimum Password Length',
                                'value': f"{min_length} characters",
                                'risk': 'HIGH' if min_length < 8 else 'MEDIUM',
                                'recommendation': 'Set minimum password length to at least 12 characters'
                            })
                    elif attr['type'] == 'lockoutThreshold':
                        lockout = int(attr['vals'][0])
                        policy['lockout_threshold'] = lockout
                        
                        if lockout == 0:
                            ad_data['risky_settings'].append({
                                'type': 'Weak Password Policy',
                                'setting': 'Account Lockout Threshold',
                                'value': "Disabled",
                                'risk': 'HIGH',
                                'recommendation': 'Enable account lockout with threshold of 5-10 attempts'
                            })
                
                ad_data['password_policy'] = policy
        except Exception as e:
            logger.warning(f"[AD] Error checking password policy: {e}")
        
        # Save results to database
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ad_enumeration (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    domain TEXT, 
                    data TEXT)''')
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO ad_enumeration (timestamp, domain, data) VALUES (?, ?, ?)",
                 (timestamp, domain, json.dumps(ad_data)))
        conn.commit()
        conn.close()
        
        logger.info(f"[+] AD enumeration complete. Found {len(ad_data['users'])} users, " +
                    f"{len(ad_data['groups'])} groups, {len(ad_data['vulnerable_accounts'])} vulnerable accounts, " +
                    f"{len(ad_data['risky_settings'])} risky settings.")
        
    except Exception as e:
        logger.error(f"AD enumeration failed: {str(e)}")
    
    return ad_data

def add_password_policy_assessment(target, domain, username="", password="", db_path="smb_enum.db"):
    """
    Assess password policy settings and identify weaknesses.
    """
    policy_results = {}
    
    try:
        # Check password policy via net accounts
        if not username:
            # Try anonymous connection
            cmd = ["net", "rpc", "info", "-S", target, "-U", "%"]
        else:
            cmd = ["net", "rpc", "info", "-S", target, "-U", f"{domain}/{username}%{password}"]
        
        net_info = subprocess.run(cmd, capture_output=True, text=True)
        
        # Query password policy
        if not username:
            cmd = ["net", "rpc", "password", "policy", "list", "-S", target, "-U", "%"]
        else:
            cmd = ["net", "rpc", "password", "policy", "list", "-S", target, 
                   "-U", f"{domain}/{username}%{password}"]
            
        policy_output = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse policy information
        policy_data = {}
        for line in policy_output.stdout.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                policy_data[key.strip()] = value.strip()
        
        # Analyze policy strength
        if 'Minimum password length' in policy_data:
            min_len = int(policy_data['Minimum password length'])
            if min_len < 8:
                policy_results['weak_password_length'] = {
                    'severity': 'HIGH',
                    'finding': f"Weak minimum password length ({min_len})",
                    'recommendation': 'Increase minimum password length to at least 12 characters'
                }
        
        if 'Maximum password age' in policy_data:
            max_age = int(policy_data['Maximum password age'].split()[0])
            if max_age > 90 or max_age == 0:
                policy_results['weak_password_expiration'] = {
                    'severity': 'MEDIUM',
                    'finding': f"Weak password expiration policy ({max_age} days)",
                    'recommendation': 'Set maximum password age to 60-90 days'
                }
        
        # Save results to database
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS password_policy (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    target TEXT,
                    policy TEXT,
                    findings TEXT)''')
        
        c.execute("INSERT INTO password_policy (timestamp, target, policy, findings) VALUES (?, ?, ?, ?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                  target,
                  json.dumps(policy_data),
                  json.dumps(policy_results)))
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Password policy assessment failed: {str(e)}")
    
    return policy_results

# ================== 11) EXPORT OPTIONS ==================

def add_export_functionality(db_path="smb_enum.db"):
    """
    Add support for exporting results to multiple formats.
    """
    import pandas as pd
    import json
    import csv
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    import os
    
    # Create exports directory
    os.makedirs("exports", exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    
    # Export vulnerability scores
    vuln_df = pd.read_sql_query("SELECT * FROM vulnerability_scores", conn)
    
    # CSV Export
    vuln_df.to_csv("exports/vulnerability_scores.csv", index=False)
    
    # JSON Export
    vuln_df.to_json("exports/vulnerability_scores.json", orient="records")
    
    # XML Export
    root = ET.Element("vulnerability_assessment")
    for _, row in vuln_df.iterrows():
        host_elem = ET.SubElement(root, "host")
        for col in vuln_df.columns:
            child = ET.SubElement(host_elem, col)
            child.text = str(row[col])
    
    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
    with open("exports/vulnerability_scores.xml", "w") as f:
        f.write(xmlstr)
    
    # Export other tables
    tables = ["logs", "nmap_scans", "metasploit_runs", "remediation_recommendations"]
    for table in tables:
        try:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
            df.to_csv(f"exports/{table}.csv", index=False)
            df.to_json(f"exports/{table}.json", orient="records")
        except Exception as e:
            logger.warning(f"Could not export table {table}: {e}")
    
    # Try to export AD data if it exists
    try:
        ad_df = pd.read_sql_query("SELECT * FROM ad_enumeration", conn)
        if len(ad_df) > 0:
            ad_df.to_csv("exports/ad_enumeration.csv", index=False)
            
            # For JSON, we need to parse the data column which is JSON serialized
            ad_records = []
            for _, row in ad_df.iterrows():
                record = {
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'domain': row['domain']
                }
                try:
                    # Parse JSON-serialized data
                    data = json.loads(row['data'])
                    record['data'] = data
                except:
                    record['data'] = row['data']
                ad_records.append(record)
            
            with open("exports/ad_enumeration.json", "w") as f:
                json.dump(ad_records, f, indent=4)
    except Exception as e:
        logger.warning(f"Could not export AD data: {e}")
    
    # Create consolidated export
    try:
        # Create a full data export in JSON
        export_data = {
            'meta': {
                'generated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'tool': "SMB-Scor3 Enhanced",
                'version': "2.0"
            },
            'hosts': {}
        }
        
        # Get all hosts from vulnerability_scores
        for _, row in vuln_df.iterrows():
            host = row['host']
            export_data['hosts'][host] = {
                'score': row['final_score'],
                'risk_category': row['risk_category'],
                'open_ports': row['open_ports'],
                'vulnerabilities': row['vulnerabilities'],
                'high_risk_ports': row['high_risk_ports'],
                'plaintext_creds': row['plaintext_creds'],
                'missing_patches': row['missing_patches'],
                'cvss_score': row['cvss_score']
            }
        
        # Add recommendations for each host
        try:
            rec_df = pd.read_sql_query("SELECT * FROM remediation_recommendations", conn)
            for _, row in rec_df.iterrows():
                host = row['host']
                if host in export_data['hosts']:
                    if 'recommendations' not in export_data['hosts'][host]:
                        export_data['hosts'][host]['recommendations'] = []
                    
                    export_data['hosts'][host]['recommendations'].append({
                        'severity': row['severity'],
                        'finding': row['finding'],
                        'remediation': row['remediation'],
                        'reference': row['reference']
                    })
        except Exception as e:
            logger.warning(f"Could not export recommendations: {e}")
        
        # Write consolidated export
        with open("exports/full_assessment.json", "w") as f:
            json.dump(export_data, f, indent=4)
    except Exception as e:
        logger.warning(f"Could not create consolidated export: {e}")
    
    conn.close()
    
    logger.info(f"[EXPORT] Exported data to CSV, JSON, and XML formats in the 'exports' directory")
    
    return {
        "csv": "exports/vulnerability_scores.csv",
        "json": "exports/vulnerability_scores.json",
        "xml": "exports/vulnerability_scores.xml",
        "full": "exports/full_assessment.json"
    }

# ================== 12) SCHEDULED SCANNING ==================

def add_scheduled_scanning():
    """
    Add support for scheduled scans.
    """
    import argparse
    import schedule
    import time
    
    parser = argparse.ArgumentParser(description='SMB-Scor3 Enhanced - Scheduled Scanning')
    parser.add_argument('--schedule', choices=['daily', 'weekly'], help='Schedule periodic scans')
    parser.add_argument('--time', help='Time to run scheduled scan (HH:MM)')
    parser.add_argument('--network', help='Network CIDR to scan')
    parser.add_argument('--db', default='smb_enum.db', help='Database file path')
    args = parser.parse_args()
    
    if args.schedule:
        # Define the job to run
        def scheduled_scan_job():
            logger.info(f"[SCHEDULED] Starting scheduled scan of {args.network}")
            
            # Set up database connection for this run
            db_path = args.db
            
            # Discover hosts
            discovered_hosts = discover_smb_hosts(args.network)
            
            # Gather host data
            host_data = enumerate_lan_hosts(discovered_hosts)
            
            # Run Nmap scans
            for host in discovered_hosts:
                host_data[host] = run_nmap_scan(host, "vuln", db_path, host_data[host])
            
            # Calculate vulnerability scores
            run_vulnerability_scoring_workflow(db_path, host_data)
            
            # Export results
            add_export_functionality(db_path)
            
            # Generate report
            generate_reports(db_path)
            
            logger.info(f"[SCHEDULED] Completed scheduled scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Set up the schedule
        if not args.time:
            args.time = "03:00"  # Default to 3 AM
            
        logger.info(f"[SCHEDULER] Setting up {args.schedule} scan at {args.time}")
        
        if args.schedule == 'daily':
            schedule.every().day.at(args.time).do(scheduled_scan_job)
        elif args.schedule == 'weekly':
            schedule.every().monday.at(args.time).do(scheduled_scan_job)
            
        logger.info(f"[SCHEDULER] Scheduled scan activated. Will run {args.schedule} at {args.time}")
        logger.info(f"[SCHEDULER] Press Ctrl+C to stop the scheduler")
            
        # Keep the scheduler running
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("[SCHEDULER] Scheduler stopped by user")
    else:
        logger.error("[SCHEDULER] No schedule specified. Use --schedule daily|weekly --time HH:MM --network CIDR")

# ================== 13) MAIN SCRIPT ==================

def add_ad_enumeration(domain, username, password, target_dc=None, db_path="smb_enum.db"):
    """
    Perform Active Directory enumeration using impacket tools.
    """
    logger.info(f"[AD] Starting Active Directory enumeration for domain {domain}")
    
    ad_data = {
        "users": [],
        "groups": [],
        "vulnerable_accounts": [],
        "risky_settings": [],
        "domain": domain
    }
    
    try:
        from impacket.ldap import ldap
        from impacket.ldap import ldapasn1
        from impacket.smbconnection import SMBConnection
        
        # Connect to LDAP
        if not target_dc:
            # Try to find DC
            smb = SMBConnection('*SMBSERVER', '')
            smb.login('', '')
            primary_dc = smb.getServerDNSDomainName()
            target_dc = primary_dc
            logger.info(f"[AD] Detected domain controller: {target_dc}")
        
        logger.info(f"[AD] Connecting to LDAP on {target_dc}")
        
        ldap_conn = ldap.LDAPConnection(f'ldap://{target_dc}', domain, username, password)
        base_dn = ','.join(f"DC={part}" for part in domain.split('.'))
        
        # Get domain users
        logger.info("[AD] Enumerating domain users")
        user_search_filter = ldapasn1.SubstringFilter()
        user_search_filter['type'] = 'samAccountName'
        user_search_filter['any'] = '*'
        
        ldap_filter = ldapasn1.Filter()
        ldap_filter['present'] = 'objectClass'
        
        user_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                       attributes=['sAMAccountName', 'userAccountControl', 
                                                  'pwdLastSet', 'memberOf'],
                                       searchBase=f"CN=Users,{base_dn}")
        
        for item in user_results:
            user = {}
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    user['username'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'userAccountControl':
                    uac = int(attr['vals'][0])
                    # Check for password never expires
                    if uac & 0x10000:
                        user['password_never_expires'] = True
                    # Check for password not required
                    if uac & 0x0020:
                        user['password_not_required'] = True
                    # Check for account not required to pre-authenticate
                    if uac & 0x400000:
                        user['no_preauth_required'] = True
                    # Check if account is disabled
                    if uac & 0x0002:
                        user['account_disabled'] = True
                elif attr['type'] == 'pwdLastSet':
                    pwd_last_set = int(attr['vals'][0])
                    if pwd_last_set == 0:
                        user['password_change_required'] = True
                    else:
                        # Convert Windows filetime to datetime
                        delta = datetime(1601, 1, 1)
                        seconds = pwd_last_set / 10**7
                        pwd_date = delta + timedelta(seconds=seconds)
                        user['password_last_set'] = pwd_date.strftime("%Y-%m-%d")
                        
                        # Check if password is old (>90 days)
                        if (datetime.now() - pwd_date).days > 90:
                            user['password_age_issue'] = True
                elif attr['type'] == 'memberOf':
                    user['groups'] = [g.decode('utf-8') for g in attr['vals']]
            
            if 'username' in user:
                ad_data['users'].append(user)
                
                # Check for weak account settings
                if any(k for k in user if k.startswith('password_') or k == 'no_preauth_required'):
                    ad_data['vulnerable_accounts'].append(user)
                    logger.warning(f"[AD] Vulnerable account settings for {user['username']}")
        
        # Get domain groups
        logger.info("[AD] Enumerating domain groups")
        group_search_filter = ldapasn1.SubstringFilter()
        group_search_filter['type'] = 'objectClass'
        group_search_filter['any'] = 'group'
        
        group_results = ldap_conn.search(searchFilter=str(ldap_filter), 
                                        attributes=['sAMAccountName', 'member'],
                                        searchBase=f"CN=Users,{base_dn}")
        
        for item in group_results:
            group = {}
            members = []
            
            for attr in item['attributes']:
                if attr['type'] == 'sAMAccountName':
                    group['name'] = attr['vals'][0].decode('utf-8')
                elif attr['type'] == 'member':
                    members = [m.decode('utf-8') for m in attr['vals']]
            
            if 'name' in group:
                group['members'] = members
                ad_data['groups'].append(group)
                
                # Check if this is a privileged group
                privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators']
                if any(pg.lower() in group['name'].lower() for pg in privileged_groups):
                    group['privilege#!/usr/bin/env python3

import os
import re
import sys
import json
import socket
import sqlite3
import logging
import argparse
import subprocess
import shutil
import pandas as pd
import schedule
import time
import requests
from enum import Enum
from datetime import datetime
import concurrent.futures
import matplotlib
matplotlib.use("Agg")  # Headless environment
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET
from xml.dom import minidom

"""
Enhanced SMB-Scor3: A comprehensive tool for:
1) Logging to SQLite
2) SMB/Network enumeration
3) Impacket-based intensity enumeration
4) Parallel Nmap scanning
5) Metasploit usage via msfconsole
6) Vulnerability scoring with additional criteria
7) Charting final scores with a Matplotlib line plot
8) Web-based dashboard for reporting
9) Scheduled scanning and trend analysis
10) Enhanced vulnerability correlation with CVE lookup
11) Remediation guidance
12) Improved reporting with template system
13) Active Directory integration
14) Password policy assessment
15) Multi-format export options
"""


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

def check_dependencies():
"""Check and install required Python libraries and external tools."""
try:
    import impacket
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import wkst, srvs
except ImportError:
    if logger:
        logger.info("[*] Installing impacket library...")
    subprocess.run(["pip", "install", "impacket"], check=True)
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import wkst, srvs

# Check for other Python dependencies
python_deps = ["pandas", "matplotlib", "jinja2", "flask", "requests"]
for dep in python_deps:
    try:
        __import__(dep)
    except ImportError:
        if logger:
            logger.info(f"[*] Installing {dep} library...")
        subprocess.run(["pip", "install", dep], check=True)

# Check for external tools
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
host_data = {}

for ip in hosts:
    logger.info(f"[*] Enumerating {ip} (LAN-wide logic)...")
    host_data[ip] = {
        "vulnerabilities": [],
        "open_ports": [],
        "plaintext_creds": 0,
        "missing_patches": 0,
        "host": ip
    }

    # a) Basic info (CME)
    try:
        cme = subprocess.run(["crackmapexec", "smb", ip],
                             capture_output=True, text=True, check=True)
        logger.info("[crackmapexec info]\n" + cme.stdout.strip())
        
        # Extract data from CME output
        cme_out = cme.stdout.strip()
        host_data[ip]["cme_output"] = cme_out
        
        # Check for SMBv1
        if "SMBv1:True" in cme_out:
            host_data[ip]["vulnerabilities"].append("SMBv1 Enabled")
        
        # Add ports
        host_data[ip]["open_ports"].append(445)  # If CME works, 445 is open
        
    except Exception:
        logger.warning("[!] crackmapexec failed or not installed for host %s.", ip)

    # b) List shares (anonymous) with Impacket
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(ip, ip)
        conn.login('', '')  # Attempt anonymous
        shares = conn.listShares()
        msg = "[Shares (anonymous) via Impacket]:\n"
        
        host_data[ip]["shares"] = []
        for share in shares:
            share_name = share['shi1_netname'].rstrip('\x00')
            msg += f"  {share_name}\n"
            host_data[ip]["shares"].append(share_name)
            
            # Check for non-default shares that allow anonymous access
            if share_name not in ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"]:
                try:
                    conn.listPath(share_name, '*')
                    host_data[ip]["vulnerabilities"].append(f"Anonymous Access to {share_name}")
                except:
                    pass
                    
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
        
        # Extract user data
        host_data[ip]["users"] = []
        for line in sid_result.stdout.strip().splitlines():
            if "User:" in line:
                user = line.split("User:")[1].strip()
                host_data[ip]["users"].append(user)
                
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
                host_data[ip]["vulnerabilities"].append("Accessible NTLM Hashes")

    except Exception:
        # fallback
        rpc = subprocess.run(["rpcclient", "-U", "", "-N", ip, "-c", "lsaquery"],
                             capture_output=True, text=True)
        logger.info("[rpcclient lsaquery output]:\n" + rpc.stdout.strip())

return host_data


# ================== 4) INTENSITY-BASED IMPACKET ENUM ==================

class IntensityLevel(Enum):
LOW = 1
MEDIUM = 2
HIGH = 3

def enumerate_with_intensity(target, username, password, domain, intensity, host_data=None):
"""
Uses Impacket-based enumeration for a single target based on intensity.
Now updates host_data dictionary with findings.
"""
logger.info(f"[+] Starting {intensity.name} enumeration for {target}")

if host_data is None:
    host_data = {
        "vulnerabilities": [],
        "open_ports": [445],  # If we're doing SMB enumeration, 445 is open
        "plaintext_creds": 0,
        "missing_patches": 0,
        "host": target
    }

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import wkst, srvs
    
    conn = SMBConnection(target, target)
    conn.login(username, password, domain)
    
    # If we succeed with credentials, add to plaintext credentials count
    if username and password and username != '' and password != '':
        host_data["plaintext_creds"] += 1
        logger.info(f"[!] Valid credentials found: {domain}\\{username}:{password}")

    if intensity == IntensityLevel.LOW:
        logger.info("[LOW] Listing SMB shares...")
        shares = conn.listShares()
        host_data["shares"] = []
        for share in shares:
            share_name = share['shi1_netname']
            logger.info(f"    Share found: {share_name}")
            host_data["shares"].append(share_name)
            
            # Check for non-default shares
            if share_name not in ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"]:
                try:
                    conn.listPath(share_name, '*')
                    host_data["vulnerabilities"].append(f"Access to {share_name} share")
                except:
                    pass

    elif intensity == IntensityLevel.MEDIUM:
        logger.info("[MEDIUM] Enumerating logged-on users...")
        dce = conn.getDCE()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)
        request = wkst.NetrWkstaUserEnum()
        response = dce.request(request)
        
        host_data["logged_on_users"] = []
        for user in response['UserInfo']['WkstaUserInfo']:
            username = user['wkui1_username']
            logger.info(f"    Logged-on User: {username}")
            host_data["logged_on_users"].append(username)
        
        # Check for SMBv1 protocol
        server_os = conn.getServerOS()
        if "Windows 7" in server_os or "Windows Server 2008" in server_os:
            host_data["vulnerabilities"].append("Potential SMBv1 System (EOL OS)")
        
        # Check for MS17-010
        try:
            ms17_010_cmd = ["crackmapexec", "smb", target, "-u", username, "-p", password, "-M", "ms17-010"]
            ms17_output = subprocess.run(ms17_010_cmd, capture_output=True, text=True)
            if "MS17-010" in ms17_output.stdout and "VULNERABLE" in ms17_output.stdout:
                host_data["vulnerabilities"].append("MS17-010 (EternalBlue)")
                logger.warning(f"[!] {target} is VULNERABLE to MS17-010!")
        except:
            logger.warning(f"Could not check MS17-010 on {target}")

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
            
            host_data["active_sessions"] = []
            if response['SessionInfo']['Level'] == 10:
                for session in response['SessionInfo']['SessionInfo10']:
                    session_user = session['sesi10_username']
                    session_client = session['sesi10_cname']
                    logger.info(
                        f"    Session => User: {session_user}, "
                        f"Client: {session_client}, Time: {session['sesi10_time']}"
                    )
                    host_data["active_sessions"].append({
                        "user": session_user,
                        "client": session_client,
                        "time": session['sesi10_time']
                    })
            else:
                logger.info("    No active sessions found.")
        except Exception as e:
            logger.warning(f"Error enumerating sessions on {target}: {e}")

        # 2) Check for writable/exploitable shares
        logger.info("Checking for writable shares...")
        try:
            shares = conn.listShares()
            host_data["writable_shares"] = []
            for share in shares:
                share_name = share['shi1_netname']
                if not share_name.endswith('$'):
                    try:
                        conn.listPath(share_name, '*')
                        logger.info(f"    Share '{share_name}' is accessible/writable.")
                        host_data["writable_shares"].append(share_name)
                        
                        # Try to write a test file
                        test_file = "smb_write_test.txt"
                        try:
                            conn.putFile(share_name, test_file, b"SMB write test")
                            logger.warning(f"[!] Share '{share_name}' allows file writes!")
                            host_data["vulnerabilities"].append(f"Writable Share: {share_name}")
                            # Clean up test file
                            conn.deleteFile(share_name, test_file)
                        except:
                            pass
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
            host_data["server_name"] = server_info
            
            # Check for additional protocols
            server_os = conn.getServerOS()
            host_data["server_os"] = server_os
            logger.info(f"    Server OS: {server_os}")
            
            # Check for potentially vulnerable configurations
            if "Windows XP" in server_os or "Windows Server 2003" in server_os:
                host_data["vulnerabilities"].append("End-of-Life OS")
                host_data["missing_patches"] += 5  # Heavily penalize EOL systems
            elif "Windows 7" in server_os or "Windows Server 2008" in server_os:
                host_data["vulnerabilities"].append("End-of-Support OS")
                host_data["missing_patches"] += 3
            
            # Run OS-specific vulnerability checks
            try:
                vuln_checks = [
                    {"name": "MS17-010", "cmd": ["crackmapexec", "smb", target, "-u", username, "-p", password, "-M", "ms17-010"]},
                    {"name": "SMB Signing", "cmd": ["crackmapexec", "smb", target, "-u", username, "-p", password, "--gen-relay-list", "/dev/null"]}
                ]
                
                for check in vuln_checks:
                    check_output = subprocess.run(check["cmd"], capture_output=True, text=True)
                    if check["name"] == "MS17-010" and "VULNERABLE" in check_output.stdout:
                        host_data["vulnerabilities"].append("MS17-010 (EternalBlue)")
                    elif check["name"] == "SMB Signing" and "SMB signing is disabled" in check_output.stdout:
                        host_data["vulnerabilities"].append("SMB Signing Disabled")
            except Exception as e:
                logger.warning(f"Error during vulnerability checks on {target}: {e}")
                
        except Exception as e:
            logger.warning(f"Error enumerating services on {target}: {e}")

        # 4) Try to obtain patch level
        try:
            wmi_cmd = ["wmic", "-U", f"{domain}/{username}%{password}", f"//{target}", "qfe", "list", "brief"]
            wmi_output = subprocess.run(wmi_cmd, capture_output=True, text=True)
            
            if wmi_output.returncode == 0:
                logger.info("Patch information retrieved")
                
                # Look for recent security patches
                if "KB5022282" not in wmi_output.stdout:  # Example recent security patch
                    host_data["missing_patches"] += 1
            else:
                logger.warning(f"Could not retrieve patch information from {target}")
        except Exception as e:
            logger.warning(f"Error checking patches on {target}: {e}")

    conn.close()

except Exception as e:
    logger.error(f"Error during Impacket enumeration of {target}: {e}")

return host_data


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

def run_nmap_scan(target, script_category=None, db_path="smb_enum.db", host_data=None):
"""
Run an nmap scan on one target, with optional script categories.
Save XML output, insert record into DB.
Now updates host_data dictionary with findings.
"""
if host_data is None:
    host_data = {
        "vulnerabilities": [],
        "open_ports": [],
        "plaintext_creds": 0, 
        "missing_patches": 0,
        "host": target
    }

timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
xml_filename = f"nmap_results_{timestamp_str}_{target.replace('/', '_')}.xml"
cmd = ["nmap", "-sV", "-p", "21,22,23,25,53,80,139,445,1433,3306,3389,5900,8080,8443", "-oX", xml_filename]

if script_category:
    cmd += ["--script", script_category]
cmd += [target]

logger.info(f"[Nmap] Scanning {target} with script category: {script_category or 'None'}")
logger.info(f"[Nmap] Command: {' '.join(cmd)}")

try:
    run_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    logger.info(f"[Nmap Output for {target}]\n{run_result.stdout}")
    
    # Parse XML output to get open ports and vulnerabilities
    try:
        tree = ET.parse(xml_filename)
        root = tree.getroot()
        
        # Get open ports
        for port in root.findall(".//port[@state='open']"):
            port_num = int(port.get('portid'))
            host_data["open_ports"].append(port_num)
            
            # Check for services with default credentials
            service = port.find("service")
            if service is not None:
                service_name = service.get('name', '')
                
                # Check for potentially vulnerable services
                if service_name == "ms-sql-s":
                    host_data["vulnerabilities"].append("MS SQL Server Exposed")
                elif service_name == "mysql":
                    host_data["vulnerabilities"].append("MySQL Exposed")
                elif service_name == "telnet":
                    host_data["vulnerabilities"].append("Telnet (Cleartext) Exposed")
                elif service_name == "ftp":
                    host_data["vulnerabilities"].append("FTP Service Exposed")
        
        # Get script results for vulnerabilities
        for script in root.findall(".//script"):
            script_id = script.get('id', '')
            script_output = script.get('output', '')
            
            # Check for vulnerability scripts
            if script_id.startswith("vuln-") or "vuln" in script_id:
                if "VULNERABLE" in script_output:
                    vuln_name = script_id.replace("vuln-", "").upper()
                    host_data["vulnerabilities"].append(vuln_name)
                    logger.warning(f"[!] Vulnerability found: {vuln_name}")
            
            # Check for default credentials
            if "default credential" in script_output.lower() or "default password" in script_output.lower():
                host_data["plaintext_creds"] += 1
                host_data["vulnerabilities"].append("Default Credentials")
                
    except Exception as e:
        logger.warning(f"Error parsing Nmap XML output: {e}")
    
except subprocess.CalledProcessError as e:
    logger.warning(f"Nmap scan failed for {target}: {e}\n{e.output}")

# Log to DB
full_cmd_str = " ".join(cmd)
log_nmap_scan_to_db(db_path, target, full_cmd_str, os.path.abspath(xml_filename))

return host_data

def advanced_nmap_menu(db_path="smb_enum.db", host_data=None):
"""
Allows user to specify multiple targets for parallel scanning,
choose an NSE script category, and run them concurrently.
Now updates host_data dictionary with findings.
"""
if host_data is None:
    host_data = {}
    
logger.info("\n=== ADVANCED NMAP PARALLEL SCANS ===")
targets_input = input("Enter targets (comma-separated, e.g. '192.168.1.10,192.168.1.20/24'): ").strip()
if not targets_input:
    logger.warning("No targets provided. Returning.")
    return host_data

targets = [t.strip() for t in targets_input.split(",") if t.strip()]

logger.info("Common NSE categories: 'discovery', 'safe', 'default', 'vuln'")
script_category = input("Enter an NSE script category or leave blank for none: ").strip()

max_workers = 5
logger.info(f"Starting parallel Nmap scans on {len(targets)} target(s) with up to {max_workers} workers...")

with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = {}
    for target in targets:
        if target not in host_data:
            host_data[target] = {
                "vulnerabilities": [],
                "open_ports": [],
                "plaintext_creds": 0,
                "missing_patches": 0,
                "host": target
            }
        future = executor.submit(run_nmap_scan, target, script_category, db_path, host_data[target])
        futures[future] = target

    for future in concurrent.futures.as_completed(futures):
        target = futures[future]
        try:
            target_data = future.result()
            host_data[target] = target_data
        except Exception as e:
            logger.error(f"Error in Nmap scan for {target}: {e}")

logger.info("Parallel Nmap scans completed.")
return host_data


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

def run_metasploit_module(target, module_name, options=None, db_path="smb_enum.db", host_data=None):
"""
Launch msfconsole non-interactively with a specific module, set RHOSTS, run, exit.
Now updates host_data dictionary with findings.
"""
if host_data is None:
    host_data = {
        "vulnerabilities": [],
        "open_ports": [],
        "plaintext_creds": 0,
        "missing_patches": 0,
        "host": target
    }
    
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
    
    # Check output for vulnerability indicators
    if module_name == "auxiliary/scanner/smb/smb_ms17_010":
        if "MS17-010" in output and "VULNERABLE" in output:
            host_data["vulnerabilities"].append("MS17-010 (EternalBlue)")
            logger.warning(f"[!] {target} is VULNERABLE to MS17-010 (EternalBlue)!")
    
    elif module_name == "auxiliary/scanner/smb/smb_version":
        # Extract SMB version info
        if "SMBv1" in output:
            host_data["vulnerabilities"].append("SMBv1 Enabled")
        
        # Look for EOL OS versions
        for eol_os in ["Windows XP", "Windows 2003", "Windows 2000"]:
            if eol_os in output:
                host_data["vulnerabilities"].append(f"EOL OS: {eol_os}")
                host_data["missing_patches"] += 5
    
    elif module_name == "auxiliary/scanner/ftp/anonymous":
        if "Anonymous READ" in output:
            host_data["vulnerabilities"].append("Anonymous FTP Access")
            host_data["plaintext_creds"] += 1
            logger.warning(f"[!] {target} allows anonymous FTP access!")
            
    # Add more module-specific checks here as needed
    
except subprocess.CalledProcessError as e:
    output = f"Metasploit run failed: {e}\n{e.output}"
    logger.warning(output)

# Log result
log_metasploit_run_to_db(db_path, target, module_name, output)

return host_data

def metasploit_menu(db_path="smb_enum.db", host_data=None):
"""
Enhanced Metasploit menu with more modules and host_data tracking.
"""
if host_data is None:
    host_data = {}
    
while True:
    logger.info("\n=== METASPLOIT MENU ===")
    logger.info("1) SMB Version (auxiliary/scanner/smb/smb_version)")
    logger.info("2) MS17-010 (auxiliary/scanner/smb/smb_ms17_010)")
    logger.info("3) FTP Anonymous (auxiliary/scanner/ftp/anonymous)")
    logger.info("4) SMB Login (auxiliary/scanner/smb/smb_login)")
    logger.info("5) SSH Login (auxiliary/scanner/ssh/ssh_login)")
    logger.info("6) MySQL Login (auxiliary/scanner/mysql/mysql_login)")
    logger.info("7) Web Vulnerabilities (auxiliary/scanner/http/dir_scanner)")
    logger.info("0) Return to main menu")

    choice = input("Select a Metasploit module (0 to exit): ").strip()
    if choice == '0':
        break

    target = input("Enter target IP or range (RHOSTS): ").strip()
    if not target:
        logger.warning("No target specified.")
        continue
        
    # Initialize host_data for this target if it doesn't exist
    if target not in host_data:
        host_data[target] = {
            "vulnerabilities": [],
            "open_ports": [],
            "plaintext_creds": 0,
            "missing_patches": 0,
            "host": target
        }

    if choice == '1':
        run_metasploit_module(target, "auxiliary/scanner/smb/smb_version", db_path=db_path, host_data=host_data[target])
    elif choice == '2':
        run_metasploit_module(target, "auxiliary/scanner/smb/smb_ms17_010", db_path=db_path, host_data=host_data[target])
    elif choice == '3':
        run_metasploit_module(target, "auxiliary/scanner/ftp/anonymous", db_path=db_path, host_data=host_data[target])
    elif choice == '4':
        username = input("Enter username (or 'file:/path/to/userlist'): ")
        password = input("Enter password (or 'file:/path/to/passlist'): ")
        options = {"SMBUser": username, "SMBPass": password}
        run_metasploit_module(target, "auxiliary/scanner/smb/smb_login", options, db_path, host_data[target])
    elif choice == '5':
        username = input("Enter username (or 'file:/path/to/userlist'): ")
        password = input("Enter password (or 'file:/path/to/passlist'): ")
        options = {"USERNAME": username, "PASSWORD": password}
        run_metasploit_module(target, "auxiliary/scanner/ssh/ssh_login", options, db_path, host_data[target])
    elif choice == '6':
        username = input("Enter username (or 'file:/path/to/userlist'): ")
        password = input("Enter password (or 'file:/path/to/passlist'): ")
        options = {"USERNAME": username, "PASSWORD": password}
        run_metasploit_module(target, "auxiliary/scanner/mysql/mysql_login", options, db_path, host_data[target])
    elif choice == '7':
        run_metasploit_module(target, "auxiliary/scanner/http/dir_scanner", db_path=db_path, host_data=host_data[target])
    else:
        logger.info("Invalid choice. Please pick 0-7.")

return host_data


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
        cvss_score REAL,
        critical_vulns INT,
        final_score INT,
        risk_category TEXT
    )
''')
conn.commit()
conn.close()

def enhance_vulnerability_scoring(host_data):
"""
Enhancement: Add CVE lookup and scoring based on CVSS.
"""
vulnerabilities = host_data.get("vulnerabilities", [])
total_cvss_score = 0
critical_vulns = 0

# Define known vulnerabilities with CVSS scores
vuln_cvss_map = {
    "MS17-010": 9.8,  # EternalBlue
    "SMBv1 Enabled": 7.5,
    "EOL OS": 8.0,
    "Anonymous FTP Access": 5.0,
    "Default Credentials": 7.0,
    "SMB Signing Disabled": 5.8,
    "Writable Share": 6.0,
}

for vuln in vulnerabilities:
    # Check if we have a predefined CVSS score
    base_vuln_name = next((k for k in vuln_cvss_map.keys() if k in vuln), None)
    if base_vuln_name:
        cvss_score = vuln_cvss_map[base_vuln_name]
        total_cvss_score += cvss_score
        
        if cvss_score >= 9.0:
            critical_vulns += 1
        
        logger.info(f"CVSS score for {vuln}: {cvss_score}")
    else:
        # For unknown vulnerabilities, try to look up CVE if present
        cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', vuln)
        if cve_match:
            cve_id = cve_match.group(1)
            try:
                logger.info(f"Looking up CVSS score for {cve_id}")
                response = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if 'result' in data and 'CVE_Items' in data['result'] and len(data['result']['CVE_Items']) > 0:
                        if 'impact' in data['result']['CVE_Items'][0] and 'baseMetricV3' in data['result']['CVE_Items'][0]['impact']:
                            cvss_score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                            total_cvss_score += float(cvss_score)
                            
                            if float(cvss_score) >= 9.0:
                                critical_vulns += 1
                                
                            logger.info(f"CVSS score for {cve_id}: {cvss_score}")
                        else:
                            # Fallback to baseMetricV2 if V3 not available
                            if 'baseMetricV2' in data['result']['CVE_Items'][0]['impact']:
                                cvss_score = data['result']['CVE_Items'][0]['impact']['baseMetricV2']['cvssV2']['baseScore']
                                total_cvss_score += float(cvss_score)
                                logger.info(f"CVSS V2 score for {cve_id}: {cvss_score}")
                            else:
                                logger.warning(f"No CVSS score found for {cve_id}")
                                total_cvss_score += 5  # Default medium score
                    else:
                        logger.warning(f"No CVE data found for {cve_id}")
                        total_cvss_score += 5  # Default medium score
            except Exception as e:
                logger.warning(f"Error looking up CVE {cve_id}: {e}")
                total_cvss_score += 5  # Default medium score
        else:
            # Generic vulnerability with no CVE ID
            total_cvss_score += 5  # Default medium score

# Update host_data with CVSS information
host_data['cvss_score'] = total_cvss_score
host_data['critical_vulns'] = critical_vulns

return host_data

def calculate_vulnerability_score(host_data: dict):
"""
Enhanced scoring algorithm including CVSS scores and critical vulnerabilities.

Scoring weights:
  - Base score: 100 points
  - Each vulnerability: -15 points
  - Each open port: -5 points
  - Each plaintext credential: -10 points
  - Each missing patch: -5 points
  - Each high-risk port: -3 additional points
  - Critical vulnerabilities: -20 points each
  - CVSS score adjustment: -1 point per CVSS point
  
Returns:
  (final_score, vuln_count, open_port_count, high_risk_count, plaintext_creds, 
   missing_patches, cvss_score, critical_vulns, category)
"""
score = 100

# Allow configuration of scoring weights
VULN_PENALTY = 15
PORT_PENALTY = 5
CREDS_PENALTY = 10
PATCH_PENALTY = 5
HIGH_RISK_PENALTY = 3
CRITICAL_VULN_PENALTY = 20
CVSS_PENALTY_FACTOR = 1

vulnerabilities = host_data.get("vulnerabilities", [])
open_ports = host_data.get("open_ports", [])
plaintext_creds = host_data.get("plaintext_creds", 0)
missing_patches = host_data.get("missing_patches", 0)
cvss_score = host_data.get("cvss_score", 0)
critical_vulns = host_data.get("critical_vulns", 0)

vuln_count = len(vulnerabilities)
open_port_count = len(open_ports)

# Subtract for each vulnerability
score -= (vuln_count * VULN_PENALTY)
# Subtract for each open port
score -= (open_port_count * PORT_PENALTY)
# Subtract for discovered plaintext creds
score -= (plaintext_creds * CREDS_PENALTY)
# Subtract for missing patches
score -= (missing_patches * PATCH_PENALTY)
# Subtract for critical vulnerabilities (additional penalty)
score -= (critical_vulns * CRITICAL_VULN_PENALTY)
# Subtract based on CVSS score
score -= (cvss_score * CVSS_PENALTY_FACTOR)

# Additional penalty for high-risk ports
high_risk_list = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
high_risk_count = sum(1 for p in open_ports if p in high_risk_list)
score -= (high_risk_count * HIGH_RISK_PENALTY)

final_score = max(score, 0)

# Risk category thresholds
LOW_THRESHOLD = 80
MEDIUM_THRESHOLD = 50
HIGH_THRESHOLD = 20

# Risk category
if final_score >= LOW_THRESHOLD:
    category = "Low"
elif final_score >= MEDIUM_THRESHOLD:
    category = "Medium"
elif final_score >= HIGH_THRESHOLD:
    category = "High"
else:
    category = "Critical"

return (final_score, vuln_count, open_port_count, high_risk_count, plaintext_creds, 
        missing_patches, cvss_score, critical_vulns, category)

def log_vulnerability_score(db_path: str,
                        host: str,
                        open_ports: int,
                        vulnerabilities: int,
                        high_risk_ports: int,
                        plaintext_creds: int,
                        missing_patches: int,
                        cvss_score: float,
                        critical_vulns: int,
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
        cvss_score, critical_vulns, final_score, risk_category
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', (timestamp, host, open_ports, vulnerabilities,
      high_risk_ports, plaintext_creds, missing_patches,
      cvss_score, critical_vulns, final_score, category))
conn.commit()
conn.close()

def add_remediation_recommendations(host_data: dict, db_path="smb_enum.db"):
"""
Generate specific remediation steps based on findings.
"""
if "host" not in host_data:
    logger.warning("Host data missing 'host' field, cannot generate recommendations")
    return []

host = host_data["host"]
recommendations = []

# Remediation mappings for common vulnerabilities
remediation_map = {
    "SMBv1 Enabled": {
        "severity": "HIGH",
        "finding": "SMBv1 Protocol Enabled",
        "remediation": "Disable SMBv1 protocol using Group Policy or registry settings.",
        "reference": "https://support.microsoft.com/en-us/topic/how-to-enable-and-disable-smbv1-19be6424-5dd5-4797-8385-75488a9c54c5"
    },
    "MS17-010": {
        "severity": "CRITICAL",
        "finding": "MS17-010 (EternalBlue) Vulnerability",
        "remediation": "Apply Microsoft security patch MS17-010 immediately.",
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
    },
    "SMB Signing Disabled": {
        "severity": "MEDIUM",
        "finding": "SMB Signing Disabled",
        "remediation": "Enable SMB signing via Group Policy.",
        "reference": "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-client-digitally-sign-communications-always"
    },
    "Anonymous FTP Access": {
        "severity": "HIGH",
        "finding": "Anonymous FTP Access",
        "remediation": "Disable anonymous FTP access or restrict permissions.",
        "reference": "https://www.stigviewer.com/stig/ftp_server/2015-06-01/finding/V-1"
    },
    "Default Credentials": {
        "severity": "CRITICAL",
        "finding": "Default Credentials in Use",
        "remediation": "Change all default passwords and implement a strong password policy.",
        "reference": "https://www.cisa.gov/sites/default/files/publications/Eliminating_Obsolete_Connections.pdf"
    },
    "EOL OS": {
        "severity": "CRITICAL",
        "finding": "End-of-Life Operating System",
        "remediation": "Upgrade to a supported operating system version immediately.",
        "reference": "https://www.cisa.gov/sites/default/files/publications/Assess_Your_Cyber_Infrastructure.pdf"
    },
    "Writable Share": {
        "severity": "HIGH",
        "finding": "Insecure File Share Permissions",
        "remediation": "Review and restrict share permissions to authorized users only.",
        "reference": "https://docs.microsoft.com/en-us/windows-server/storage/file-server/configure-security-permissions-file-share"
    }
}

# Check vulnerabilities against remediation map
for vuln in host_data.get("vulnerabilities", []):
    for vuln_key, remedy in remediation_map.items():
        if vuln_key in vuln:  # Partial match to catch variants
            recommendations.append({
                "severity": remedy["severity"],
                "finding": remedy["finding"],
                "remediation": remedy["remediation"],
                "reference": remedy["reference"]
            })
            break

# Check for high-risk ports
high_risk_ports = []
for port in host_data.get("open_ports", []):
    if port in [21, 23, 139, 445, 3389]:
        high_risk_ports.append(port)

if high_risk_ports:
    port_list = ", ".join(str(p) for p in high_risk_ports)
    recommendations.append({
        "severity": "MEDIUM",
        "finding": f"High-risk ports exposed: {port_list}",
        "remediation": "Filter or close unnecessary high-risk ports at the firewall.",
        "reference": "https://www.cisa.gov/sites/default/files/publications/Securing_Network_Infrastructure_Devices.pdf"
    })

# Check if plaintext credentials were found
if host_data.get("plaintext_creds", 0) > 0:
    recommendations.append({
        "severity": "HIGH",
        "finding": "Plaintext Credentials Discovered",
        "remediation": "Implement secure authentication and encrypt all credential storage.",
        "reference": "https://csrc.nist.gov/publications/detail/sp/800-63/3/final"
    })

# Check missing patches
if host_data.get("missing_patches", 0) > 0:
    recommendations.append({
        "severity": "HIGH",
        "finding": "Missing Security Patches",
        "remediation": "Implement a regular patching schedule and verify patch installation.",
        "reference": "https://www.cisa.gov/sites/default/files/publications/Patch_Management.pdf"
    })

# Log recommendations to database
conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS remediation_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            timestamp TEXT,
            severity TEXT,
            finding TEXT,
            remediation TEXT,
            reference TEXT)''')

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
for rec in recommendations:
    c.execute('''INSERT INTO remediation_recommendations 
                (host, timestamp, severity, finding, remediation, reference) 
                VALUES (?, ?, ?, ?, ?, ?)''',
             (host, timestamp, 
              rec['severity'], rec['finding'], 
              rec['remediation'], rec['reference']))

conn.commit()
conn.close()

logger.info(f"Generated {len(recommendations)} remediation recommendations for {host}")
return recommendations

def run_vulnerability_scoring_workflow(db_path: str, discovered_data: dict):
"""
Enhanced vulnerability scoring workflow with remediation guidance.
"""
setup_vulnerability_scores_table(db_path)

host_scores = {}
remediation_results = {}

for host, data in discovered_data.items():
    # Enhance scoring with CVSS data
    data = enhance_vulnerability_scoring(data)
    
    # Calculate score
    (final_score, vuln_count, open_count, high_risk_count,
     plain_creds, missing_patches, cvss_score, critical_vulns, category) = calculate_vulnerability_score(data)

    logger.info(f"[Score] {host}: final_score={final_score}, category={category}, CVSS={cvss_score}")
    
    # Generate remediation recommendations
    remediation_results[host] = add_remediation_recommendations(data, db_path)
    
    # Insert into DB
    log_vulnerability_score(db_path,
                            host,
                            open_count,
                            vuln_count,
                            high_risk_count,
                            plain_creds,
                            missing_patches,
                            cvss_score,
                            critical_vulns,
                            final_score,
                            category)
    host_scores[host] = final_score

# Create line plot of final scores
create_line_plot_of_scores(host_scores)

# Generate comprehensive report
generate_reports(db_path, host_scores, remediation_results)

return host_scores, remediation_results
