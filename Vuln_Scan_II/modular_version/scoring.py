# scoring.py

import sqlite3
import logging
from datetime import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

class VulnerabilityScorer:
    """
    Calculates vulnerability scores based on:
      - vulnerabilities
      - open_ports
      - plaintext_creds
      - missing_patches
      - high-risk ports
    Then stores them + categories in 'vulnerability_scores' table,
    and can produce a line plot of final scores.
    """

    def __init__(self, logger: logging.Logger, db_path="smb_enum.db"):
        self.logger = logger
        self.db_path = db_path
        self._initialize_table()

    def _initialize_table(self):
        conn = sqlite3.connect(self.db_path)
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

    def score_and_store(self, discovered_data: dict):
        """
        discovered_data might look like:
          {
            "192.168.1.10": {
                "vulnerabilities": ["MS17-010", "Weak SMB Signing"],
                "open_ports": [139,445],
                "plaintext_creds": 1,
                "missing_patches": 2
            },
            ...
          }
        """
        host_scores = {}
        for host, data in discovered_data.items():
            final_score, risk_cat, details = self._calculate_score(data)
            self.logger.info(f"[Score] Host={host}, Score={final_score}, Category={risk_cat}")
            self._insert_into_db(host, details, final_score, risk_cat)
            host_scores[host] = final_score

        # After scoring all, create a line plot
        self._create_line_plot(host_scores)
        return host_scores

    def _calculate_score(self, host_data: dict):
        """
        Return (final_score, risk_category, details_dict)
        details_dict includes open_ports, vulnerabilities, etc.
        """
        score = 100

        vulnerabilities = host_data.get("vulnerabilities", [])
        open_ports = host_data.get("open_ports", [])
        plaintext_creds = host_data.get("plaintext_creds", 0)
        missing_patches = host_data.get("missing_patches", 0)

        vuln_count = len(vulnerabilities)
        open_port_count = len(open_ports)
        # -15 per vuln
        score -= (vuln_count * 15)
        # -5 per open port
        score -= (open_port_count * 5)
        # -10 per plaintext cred
        score -= (plaintext_creds * 10)
        # -5 per missing patch
        score -= (missing_patches * 5)

        # High-risk ports
        high_risk_list = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
        high_risk_count = sum(1 for p in open_ports if p in high_risk_list)
        score -= (high_risk_count * 3)

        final_score = max(score, 0)

        # Category
        if final_score >= 80:
            cat = "Low"
        elif final_score >= 50:
            cat = "Medium"
        elif final_score >= 20:
            cat = "High"
        else:
            cat = "Critical"

        details = {
            'vuln_count': vuln_count,
            'open_port_count': open_port_count,
            'plaintext_creds': plaintext_creds,
            'missing_patches': missing_patches,
            'high_risk_count': high_risk_count
        }
        return final_score, cat, details

    def _insert_into_db(self, host, details, final_score, risk_cat):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute('''
            INSERT INTO vulnerability_scores (
                timestamp, host, open_ports, vulnerabilities,
                high_risk_ports, plaintext_creds, missing_patches,
                final_score, risk_category
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            host,
            details['open_port_count'],
            details['vuln_count'],
            details['high_risk_count'],
            details['plaintext_creds'],
            details['missing_patches'],
            final_score,
            risk_cat
        ))
        conn.commit()
        conn.close()

    def _create_line_plot(self, host_scores: dict, output_file="vulnerability_scores_line.png"):
        """
        Create a line plot of final scores, sorted descending.
        """
        if not host_scores:
            self.logger.warning("No host scores to plot. Skipping plot.")
            return

        sorted_hosts = sorted(host_scores.keys(), key=lambda h: host_scores[h], reverse=True)
        scores = [host_scores[h] for h in sorted_hosts]

        plt.figure(figsize=(8, 4))
        plt.plot(range(len(scores)), scores, marker='o')
        plt.xticks(range(len(scores)), sorted_hosts, rotation=45, ha='right')
        plt.xlabel("Host")
        plt.ylabel("Score")
        plt.title("Vulnerability Scores (Line Plot)")
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        self.logger.info(f"[LINE PLOT] Saved: {output_file}")