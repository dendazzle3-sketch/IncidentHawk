# 🦅 IncidentHawk — Linux Incident Response Automation Tool

IncidentHawk automates the first hour of incident response on a Linux host.
It collects a read-only forensic snapshot — system info, users, processes,
network state, persistence mechanisms, and log artifacts — flags anomalies
using built-in heuristics, and packages everything into a timestamped,
SHA-256-hashed evidence bundle you can hand off for deeper analysis.

**IncidentHawk never modifies, kills, blocks, or deletes anything.** It only
reads and reports — safe to run on a live, potentially compromised system.

---

## 1. Requirements

- Linux (tested on Ubuntu/Debian/Kali; works on most distros with standard coreutils)
- Python 3.6+ (standard library only — no pip installs required)
- Run as **root** (`sudo`) for complete results — some data (other users'
  crontabs, `/var/log/auth.log`, other users' SSH keys) is only readable by root.

Check your Python version:
```bash
python3 --version
```

---

## 2. Installation

### Option A — Run directly
```bash
sudo python3 incidenthawk.py --output ./evidence
```

### Option B — Install system-wide as an `incidenthawk` command (recommended)
```bash
chmod +x incidenthawk.py
sudo cp incidenthawk.py /usr/local/bin/incidenthawk
incidenthawk --version
```

Now you can run `sudo incidenthawk` from anywhere.

---

## 3. Quick Start

```bash
# Full triage, evidence saved under ./cases
sudo incidenthawk --output ./cases

# Faster triage (skips filesystem-wide SUID/hidden-file scan)
sudo incidenthawk --output ./cases --quick

# Generate an HTML report you can open in a browser, alongside the evidence bundle
sudo incidenthawk --output ./cases --format html
```

Each run creates a new timestamped case folder, e.g.:
```
./cases/incidenthawk_20260712_101530/
./cases/incidenthawk_20260712_101530.tar.gz
```

---

## 4. Full Command Reference

| Flag | Description | Default |
|---|---|---|
| `--output DIR`, `-o DIR` | **(required)** Directory to write the evidence bundle into. A timestamped case subfolder is created inside it. | — |
| `--quick` | Skip the slower filesystem-wide SUID/hidden-file scan for a faster triage pass. | off |
| `--since HOURS` | Look-back window (in hours) for the "recently modified files" scan. | `48` |
| `--no-hash` | Skip SHA-256 hashing of collected evidence (faster, but weaker chain-of-custody). | off |
| `--no-archive` | Do not compress the evidence folder into a `.tar.gz` bundle. | off |
| `--format {console,json,html,all}` | Additional report format written alongside the evidence bundle. | `console` |
| `--no-color` | Disable ANSI colors (useful when piping to a file). | off |
| `--version` | Show version and exit. | — |
| `-h`, `--help` | Show help. | — |

---

## 5. Usage Examples

### 5.1 Standard full triage
```bash
sudo incidenthawk --output /root/ir_cases
```

### 5.2 Quick triage during an active incident (speed over depth)
```bash
sudo incidenthawk --output /root/ir_cases --quick
```

### 5.3 Widen the "recently modified files" window to 7 days
```bash
sudo incidenthawk --output /root/ir_cases --since 168
```

### 5.4 Generate all report formats (console + JSON + HTML) alongside the evidence bundle
```bash
sudo incidenthawk --output /root/ir_cases --format all
```

### 5.5 Skip hashing and archiving for the fastest possible run
```bash
sudo incidenthawk --output /root/ir_cases --quick --no-hash --no-archive
```

### 5.6 Pipe console output to a log file (no ANSI colors)
```bash
sudo incidenthawk --output /root/ir_cases --no-color > triage_$(date +%F).log
```

### 5.7 Run on a suspected-compromised host as part of a response runbook
```bash
# 1. Take the evidence snapshot immediately, before anyone touches the box
sudo incidenthawk --output /root/ir_cases --format all

# 2. Copy the resulting .tar.gz off the host to a secure analysis workstation
scp /root/ir_cases/incidenthawk_*.tar.gz analyst@secure-host:/evidence/

# 3. Verify the archive's evidence against sha256_manifest.json after transfer
tar -xzf incidenthawk_*.tar.gz
sha256sum -c <(python3 -c "import json;[print(v,'',k) for k,v in json.load(open('incidenthawk_*/sha256_manifest.json')).items()]")
```

---

## 6. What Gets Collected

| Category | Artifacts Collected |
|---|---|
| **System Info** | Hostname, kernel version, OS release, uptime, collection timestamp |
| **Users** | Currently logged-in users, last 30 logins, `/etc/passwd`, sudoers config, UID-0 account check |
| **Processes** | Full `ps auxww` listing, process tree |
| **Network** | Listening ports, established connections, ARP/neighbor cache |
| **Persistence** | System crontab, `/etc/cron.d/`, all users' crontabs, enabled systemd services, `/etc/rc.local`, `/etc/ld.so.preload`, all users' SSH `authorized_keys` |
| **Filesystem** *(skipped with `--quick`)* | Recently modified files, SUID/SGID binaries, hidden files in temp directories, world-writable directories |
| **Logs** | Last 200 lines of auth log and syslog, last 50 lines of each user's bash history |

---

## 7. Built-In Threat Heuristics

IncidentHawk automatically flags:

- 🔴 **CRITICAL** — Non-root account with UID 0 (classic backdoor technique)
- 🔴 **CRITICAL** — Populated `/etc/ld.so.preload` (rootkit/library-hijack persistence)
- 🔴 **CRITICAL** — Listener on a known backdoor/shell port (4444, 1337, 31337, etc.)
- 🟠 **HIGH** — Process running from `/tmp`, `/dev/shm`, or `/var/tmp`
- 🟠 **HIGH** — Cron entry containing download/reverse-shell indicators (`curl`, `wget`, `/dev/tcp`, `bash -i`, etc.)
- 🟡 **MEDIUM** — Hidden files in temp directories
- 🔵 **LOW** — SUID/SGID binaries outside the common system allow-list

---

## 8. Evidence Bundle Structure

```
incidenthawk_20260712_101530/
├── system_info/          # hostname, kernel, os_release, uptime...
├── users/                # logged_in_now, last_logins, passwd_file, sudoers...
├── processes/            # process_list, process_tree
├── network/              # listening_ports, established_connections, arp_cache
├── persistence/          # crontabs, systemd services, rc.local, authorized_keys...
├── filesystem/           # recently_modified, suid_sgid_binaries, hidden_files...
├── logs/                 # auth_log_tail, syslog_tail, bash_histories
├── findings.json         # all flagged anomalies with severity
└── sha256_manifest.json  # SHA-256 hash of every evidence file (chain of custody)
```

---

## 9. Notes & Limitations

- Run as **root** for a complete collection — without it, other users' crontabs, SSH keys, and protected logs will be silently unreadable.
- IncidentHawk is a **triage and evidence-collection** tool, not a full forensic imaging suite — for deep-dive analysis, follow up with disk imaging and memory forensics tools as needed.
- Heuristic findings are a starting point for investigation, not a definitive compromise verdict — always review the raw evidence.
- Run collection **before** taking any remediation action on a suspected-compromised host, so volatile evidence (running processes, network connections) isn't lost.

---

## 10. Uninstall

```bash
sudo rm /usr/local/bin/incidenthawk
```
