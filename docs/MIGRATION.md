# Migration notes (v1.x scripts → v2.0 package)

The project was audited at commit `ffa8ff809512911986e63b669d5c1ee09d023342` (branch `main_pi`).
At that commit:

* The root `main.py` (4,070 lines) **did not compile** (`SyntaxError` at line 198). It held two or more
  pasted copies of the script (24 functions/classes were defined more than once, plus a literal spliced at
  line 207). It also imported a module `smb_score` and called `start_web_dashboard` / `generate_reports`,
  none of which exist in the repository.
* `Vuln_Scan_II/modular_version` and `Vuln_Scan_II/single_liner` compiled, but they called `shell=True` with
  target input, ran `pip install` / `apt-get install` at runtime, and logged credentials and hashes.
* The README pointed to a `requirements.txt` and `config.yaml` that did not exist, a `--target` option
  that was never implemented, and placeholder images.

All of that code is still available in git history. v2.0 merges it into `src/vulnr_scannr/`.

## Feature mapping

| Legacy feature | v2.0 |
|---|---|
| Menu 1 / `--discover-cidr` SMB discovery + LAN enumeration | `discover NETWORK --enumerate`, part of `scan` |
| Menu 2 / `--intensity 1-3 --intensity-target` | `smb-intensity TARGET --level 1-3` |
| Menu 3 / `--run-nmap` advanced parallel nmap | `nmap TARGETS --scripts ... --workers N` |
| Menu 4 / `--metasploit` menu | `list-modules`, `metasploit TARGET --module KEY` (allowlist) |
| Menu 7 / `--score-json` scoring (modular & enhanced CVSS) | `score FILE` (enhanced by default, `--no-cvss` = modular) |
| Remediation recommendations | written automatically by `score` / `scan` |
| Menu 8 export CSV/JSON/XML (pandas) | `export` (stdlib, no pandas) |
| Line plot of scores | `report --plot` (bar chart, `[plot]` extra) |
| Menu 10 / `--schedule daily|weekly --time --network` | `schedule NETWORK --frequency ... --time ...` (stdlib) |
| `check_dependencies()` auto-installer | `check-deps` (reports only, never installs) |
| Interactive main menu | `menu` |
| CVE lookup via NVD API 1.0 (retired) | `score --nvd` via NVD API 2.0 (opt-in) |
| CrackMapExec | NetExec (`nxc`), falling back to `crackmapexec` if that is all that is installed |

## Removed or disabled on purpose

| Legacy behaviour | Why |
|---|---|
| `crackmapexec smb IP --sam` hash dump and "NTLM Hash Found" logging | Credential harvesting. Not needed to grade exposure |
| Metasploit login modules (SMB/SSH/DB login with password lists) and arbitrary `set` options | Brute force, plus msfconsole command injection through user-supplied options |
| Logging `Valid credentials found: domain\user:password` | Leaked secrets to the console and SQLite. Logs are now redacted |
| `net rpc ... -U user%password` / `wmic -U` / `crackmapexec -p` | Exposed passwords on the process command line |
| Runtime `pip install` / `apt-get install` | Unexpected system changes. Use `pip install .[all]` and your OS package manager |
| Socket sweep fallback when nmap fails | Ignored the CIDR (always swept `x.y.z.1-254`). nmap is now required for discovery |
| Web dashboard (menu 9) | Its implementation (`start_web_dashboard`) never existed in the repo. Replaced by a static HTML report |
| Active Directory LDAP enumeration and password-policy assessment (root `main.py` only) | Not ported. They existed only in the file that would not compile, needed credentials on the command line, and used unencrypted `ldap://`. Deferred until they can be redone safely (LDAPS, no argv secrets) and tested in a lab |
| `Vuln_Scan_II/modular_version/{enumeration,logging_db,scoring}.py` | Merged into the package. The `main.py` launchers remain |

## Database

The table names and columns used before are kept. Opening an old `smb_enum.db` adds `cvss_score` and
`critical_vulns` columns to `vulnerability_scores` and creates the new tables `remediation_recommendations` and `host_findings`
if they are missing.
