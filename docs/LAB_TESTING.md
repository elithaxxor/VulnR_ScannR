# Isolated-lab validation guide

This guide covers validating VulnR_ScannR's tool integrations against real software. **None of this has been run
against a real lab by the project yet.** Everything in the repository is either an offline contract test or a
*synthetic* fixture (see `tests/fixtures/README.md` for provenance).

> Only use machines you own, on a network with no route to anything you are not authorized to test.
> `capture` accepts a **single private/loopback/link-local IP** and requires `--authorized`. It never scans ranges.

## What is checked offline today (CI)

| Integration | Offline check | Still needs a real lab |
|---|---|---|
| NetExec SMB banner | Parser tests against hand-built lines that follow `print_host_info` in NetExec `841d7fe` (`nxc/protocols/smb.py` L319–326), with and without ANSI colour | The real prefix/columns, and whether colour codes appear when output is piped |
| enum4linux / enum4linux-ng | `-U` checked against the enum4linux-ng README at `288826f`; `lab_validate.py flags` re-checks the installed `-h` | Real output, RPC permissions on a Samba/Windows target |
| smbclient / rpcclient | `-L -N -g` and `-U -N -c` checked against the Samba man pages; grepable share parser tested | Real share listing |
| impacket RPC | `hNetrWkstaUserEnum`, `hNetrSessionEnum`, `SMBTransport` signatures and response field paths checked against **installed impacket 0.13.1** (and locally against 0.12.0, the declared minimum); session parsing fed a real impacket NDR response object | Live DCE/RPC against a host, access-denied behaviour |
| Metasploit | All allowlisted module paths confirmed to exist in metasploit-framework `6962ae6`; `-q`, `-n`, `-x` confirmed in its option parser. (This found that the legacy `ftp/anonymous` path no longer exists, so it is now `ftp/ftp_anonymous`.) | An actual `msfconsole` run and its output |

## 1. Build an isolated lab (example)

Any host-only or internal-only virtual network works. For example:

* **VirtualBox/VMware/libvirt host-only network** such as `192.168.56.0/24`, with no NAT adapter on the target VMs.
* **Target A – Samba:** a Linux VM (or container on an `--internal` Docker network) running Samba with one
  anonymous read-only share.
* **Target B – Windows evaluation VM** (optional), for signing/SMBv1/RPC behaviour.
* **Scanner VM:** Linux with `nmap`, `smbclient`/`rpcclient` (Samba client), `nxc` (NetExec), `enum4linux-ng`,
  `pip install "vulnr-scannr[all]"`, and Metasploit if you want to check the module runs.

Make sure the scanner has no route out of the lab during capture (for example `ip route` shows only the host-only
network).

## 2. Check flags (offline, no network)

```bash
python scripts/lab_validate.py flags
```

This runs each installed tool's local help and confirms that every flag VulnR_ScannR passes to it is still listed.
Tools that are not installed are reported as `SKIP`. Exit code 1 means a flag has disappeared.

## 3. Capture real output from ONE lab host

```bash
python scripts/lab_validate.py capture 192.168.56.10 --authorized --out tests/fixtures/lab_captured
python scripts/lab_validate.py capture 192.168.56.10 --authorized --with-msf   # also smb_version
```

This runs the same read-only commands the scanner uses (`nxc smb`, `smbclient -L -N -g`, `impacket-lookupsid -no-pass`,
`enum4linux(-ng) -U`, `rpcclient -c lsaquery`, and `nmap -sV --script default,safe` on the common ports). It writes:

* `<stamp>_<ip>.nxc.txt`, `.smbclient.txt`, `.xml` and other output files, with ANSI codes stripped and secrets redacted
* `<stamp>_<ip>.meta.json` with commands, exit codes, the version, and `"provenance": "real lab capture (redacted)"`

Public IPs, hostnames, CIDRs and multicast/unspecified addresses are refused.

## 4. Replay and lock in expectations (offline)

```bash
python scripts/lab_validate.py replay tests/fixtures/lab_captured
```

Check the parsed result by hand. If it is correct, save it as `<file>.expected.json` next to the capture. Replay (and
the unit tests) will then flag any future parser change that breaks it. Run `replay tests/fixtures` to re-check the
synthetic fixtures.

## 5. impacket intensity levels (manual)

```bash
vulnr-scannr --authorized smb-intensity 192.168.56.10 --level 3
vulnr-scannr --authorized smb-intensity 192.168.56.10 --level 2 --username labuser --domain LAB   # password prompted
```

Record which RPC calls succeed anonymously and which need credentials. Logged-on users and sessions usually need
privileges, and the tool logs a warning instead of failing.

## Before committing captures

* Use lab-only names and addresses. Review files for hostnames, usernames or anything sensitive. Redaction covers
  password-like patterns and NTLM hashes, not everything.
* Do not commit captures from networks you are not authorized to test.
