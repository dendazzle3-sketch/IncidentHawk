#!/usr/bin/env python3
"""
IncidentHawk - Linux Incident Response Automation Tool
=========================================================
Automates first-response triage and evidence collection on a Linux host:
system/user/process/network snapshots, persistence-mechanism checks,
suspicious file discovery, and log artifact collection - packaged into
a timestamped, hash-verified evidence bundle plus a human-readable report.

Read-only by design: IncidentHawk never modifies, kills, blocks, or deletes
anything on the host. It only collects and reports.

Author : Afsa Taj
License: MIT
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from collections import defaultdict
from datetime import datetime, timedelta

VERSION = "1.0.0"

BANNER = r"""
   ___                  __        __  __  __
  /_ _|_ __   ___(_) __| | ___ _ __ | |_ | || | __ ___      __
   | || '_ \ / __| |/ _` |/ _ \ '_ \| __|| || |/ _` \ \ /\ / /
   | || | | | (__| | (_| |  __/ | | | |_ | || | (_| |\ V  V /
  |___|_| |_|\___|_|\__,_|\___|_| |_|\__||_||_|\__,_| \_/\_/
        Linux Incident Response Automation  v{ver}
"""

class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"

SEVERITY_COLOR = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.GREEN}


def colorize(text, color, use_color=True):
    return f"{color}{text}{C.END}" if use_color else text


def run(cmd, timeout=15):
    """Run a shell command safely and return its stdout, or an error note."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() or (result.stderr.strip() or "(no output)")
    except FileNotFoundError:
        return "(command not found)"
    except subprocess.TimeoutExpired:
        return "(command timed out)"
    except Exception as e:
        return f"(error: {e})"


class Finding:
    def __init__(self, severity, category, message, evidence=""):
        self.severity = severity
        self.category = category
        self.message = message
        self.evidence = evidence

    def to_dict(self):
        return {"severity": self.severity, "category": self.category,
                "message": self.message, "evidence": self.evidence}


class IncidentHawk:
    def __init__(self, since_hours=48, hash_files=True, quick=False):
        self.since_hours = since_hours
        self.hash_files = hash_files
        self.quick = quick
        self.findings = []
        self.evidence = {}
        self.timestamp = datetime.now()

    # ---------------- COLLECTORS ----------------

    def collect_system_info(self):
        data = {
            "hostname": run("hostname"),
            "kernel": run("uname -a"),
            "os_release": run("cat /etc/os-release 2>/dev/null"),
            "uptime": run("uptime"),
            "date_collected": self.timestamp.isoformat(),
            "collector_user": run("whoami"),
        }
        self.evidence["system_info"] = data

    def collect_users(self):
        data = {
            "logged_in_now": run("who"),
            "last_logins": run("last -n 30"),
            "passwd_file": run("cat /etc/passwd"),
            "sudoers": run("cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null"),
            "recent_uid0_accounts": run(
                "awk -F: '($3 == 0) {print}' /etc/passwd"
            ),
        }
        self.evidence["users"] = data

        # Flag any non-root account with UID 0 (classic backdoor technique)
        for line in data["recent_uid0_accounts"].splitlines():
            if line and not line.startswith("root:"):
                self.findings.append(Finding(
                    "CRITICAL", "Backdoor Account",
                    f"Non-root account with UID 0 detected: {line.split(':')[0]}",
                    line
                ))

    def collect_processes(self):
        data = {
            "process_list": run("ps auxww"),
            "process_tree": run("ps -eo pid,ppid,user,cmd --forest"),
        }
        self.evidence["processes"] = data

        # Heuristic: processes running from suspicious paths
        suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"]
        for line in data["process_list"].splitlines()[1:]:
            for p in suspicious_paths:
                if p in line:
                    self.findings.append(Finding(
                        "HIGH", "Suspicious Process Path",
                        f"Process executing from {p.strip('/')}: {line[:140]}",
                        line
                    ))
                    break

    def collect_network(self):
        data = {
            "listening_ports": run("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"),
            "established_connections": run("ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null"),
            "arp_cache": run("ip neigh 2>/dev/null || arp -a 2>/dev/null"),
        }
        self.evidence["network"] = data

        # Flag listening on all interfaces on uncommon high ports
        for line in data["listening_ports"].splitlines():
            if ("0.0.0.0:" in line or "*:" in line) and any(
                f":{p}" in line for p in ("4444", "1337", "31337", "6666", "12345")
            ):
                self.findings.append(Finding(
                    "CRITICAL", "Known Backdoor Port",
                    "Listener found on a commonly-abused backdoor/shell port",
                    line.strip()
                ))

    def collect_persistence(self):
        data = {
            "system_crontab": run("cat /etc/crontab 2>/dev/null"),
            "cron_d": run("for f in /etc/cron.d/*; do echo \"--$f--\"; cat \"$f\" 2>/dev/null; done"),
            "user_crontabs": run(
                "for u in $(cut -f1 -d: /etc/passwd); do "
                "c=$(crontab -u $u -l 2>/dev/null); "
                "if [ -n \"$c\" ]; then echo \"--user:$u--\"; echo \"$c\"; fi; done"
            ),
            "systemd_services_enabled": run("systemctl list-unit-files --state=enabled --type=service 2>/dev/null"),
            "rc_local": run("cat /etc/rc.local 2>/dev/null"),
            "ld_preload": run("cat /etc/ld.so.preload 2>/dev/null"),
            "authorized_keys": run(
                "for h in /root /home/*; do "
                "f=\"$h/.ssh/authorized_keys\"; "
                "if [ -f \"$f\" ]; then echo \"--$f--\"; cat \"$f\"; fi; done"
            ),
        }
        self.evidence["persistence"] = data

        if data["ld_preload"] and data["ld_preload"] != "(no output)":
            self.findings.append(Finding(
                "CRITICAL", "LD_PRELOAD Hijack",
                "/etc/ld.so.preload is populated - possible rootkit/library hijack persistence",
                data["ld_preload"]
            ))

        for line in data["user_crontabs"].splitlines():
            lower = line.lower()
            if any(k in lower for k in ("curl", "wget", "nc ", "netcat", "/dev/tcp", "base64 -d", "bash -i")):
                self.findings.append(Finding(
                    "HIGH", "Suspicious Cron Entry",
                    f"Cron entry contains download/reverse-shell indicators: {line.strip()[:140]}",
                    line
                ))

    def collect_filesystem_artifacts(self):
        since = f"-{self.since_hours}"
        data = {
            "recently_modified": run(
                f"find /etc /bin /sbin /usr/bin /usr/sbin /home /root /tmp /var/tmp /dev/shm "
                f"-type f -mmin {since}0 2>/dev/null | head -300"
            ),
            "suid_sgid_binaries": run(
                "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"
            ),
            "hidden_files_tmp": run(
                "find /tmp /var/tmp /dev/shm -name '.*' -type f 2>/dev/null"
            ),
            "world_writable_dirs": run(
                "find /etc /bin /sbin /usr -xdev -perm -0002 -type d 2>/dev/null"
            ),
        }
        self.evidence["filesystem"] = data

        hidden = [l for l in data["hidden_files_tmp"].splitlines() if l.strip()]
        if hidden:
            self.findings.append(Finding(
                "MEDIUM", "Hidden Files in Temp Directory",
                f"{len(hidden)} hidden file(s) found under /tmp, /var/tmp, or /dev/shm",
                "\n".join(hidden[:10])
            ))

        suid_list = [l for l in data["suid_sgid_binaries"].splitlines() if l.strip()]
        known_common = {
            "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount",
            "/usr/bin/umount", "/usr/bin/ping", "/usr/bin/newgrp", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/lib/openssh/ssh-keysign",
        }
        unusual_suid = [l for l in suid_list if l.strip() and l.strip() not in known_common]
        if len(unusual_suid) > 0:
            self.findings.append(Finding(
                "LOW", "SUID/SGID Binaries Present",
                f"{len(unusual_suid)} SUID/SGID binaries outside the common allow-list - review recommended",
                "\n".join(unusual_suid[:15])
            ))

    def collect_logs(self):
        data = {
            "auth_log_tail": run("tail -n 200 /var/log/auth.log 2>/dev/null || tail -n 200 /var/log/secure 2>/dev/null"),
            "syslog_tail": run("tail -n 200 /var/log/syslog 2>/dev/null || tail -n 200 /var/log/messages 2>/dev/null"),
            "bash_histories": run(
                "for h in /root /home/*; do "
                "f=\"$h/.bash_history\"; "
                "if [ -f \"$f\" ]; then echo \"--$f--\"; tail -n 50 \"$f\"; fi; done"
            ),
        }
        self.evidence["logs"] = data

    # ---------------- ORCHESTRATION ----------------

    def run_full_triage(self):
        steps = [
            ("System Information", self.collect_system_info),
            ("User & Account Data", self.collect_users),
            ("Process Snapshot", self.collect_processes),
            ("Network Snapshot", self.collect_network),
            ("Persistence Mechanisms", self.collect_persistence),
            ("Log Artifacts", self.collect_logs),
        ]
        if not self.quick:
            steps.insert(5, ("Filesystem Artifacts", self.collect_filesystem_artifacts))

        for label, fn in steps:
            print(colorize(f"[*] Collecting: {label}...", C.CYAN))
            fn()

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda f: order.get(f.severity, 9))

    # ---------------- EVIDENCE BUNDLE ----------------

    def write_evidence_bundle(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        manifest = {}

        for section, content in self.evidence.items():
            section_dir = os.path.join(out_dir, section)
            os.makedirs(section_dir, exist_ok=True)
            for key, text in content.items():
                fname = os.path.join(section_dir, f"{key}.txt")
                with open(fname, "w") as f:
                    f.write(str(text))
                if self.hash_files:
                    manifest[os.path.relpath(fname, out_dir)] = hashlib.sha256(
                        str(text).encode(errors="ignore")
                    ).hexdigest()

        findings_path = os.path.join(out_dir, "findings.json")
        with open(findings_path, "w") as f:
            json.dump([fnd.to_dict() for fnd in self.findings], f, indent=2)
        if self.hash_files:
            with open(findings_path, "rb") as f:
                manifest["findings.json"] = hashlib.sha256(f.read()).hexdigest()

        if self.hash_files:
            manifest_path = os.path.join(out_dir, "sha256_manifest.json")
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)

        return out_dir

    def package_bundle(self, out_dir):
        archive_path = f"{out_dir}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(out_dir, arcname=os.path.basename(out_dir))
        return archive_path

    # ---------------- OUTPUT ----------------

    def print_console(self, use_color=True):
        print(colorize(BANNER.format(ver=VERSION), C.CYAN, use_color))
        print(colorize(f"Collection time: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", C.BOLD, use_color))
        print(colorize(f"Host: {self.evidence.get('system_info', {}).get('hostname', 'unknown')}", C.BOLD, use_color))
        print()

        if not self.findings:
            print(colorize("No high-risk indicators detected during triage.", C.GREEN, use_color))
            return

        print(colorize(f"=== TRIAGE FINDINGS ({len(self.findings)}) ===", C.BOLD, use_color))
        for fnd in self.findings:
            color = SEVERITY_COLOR.get(fnd.severity, C.END)
            print(f"[{colorize(fnd.severity, color, use_color):<18}] {fnd.category}: {fnd.message}")

    def to_json(self):
        return json.dumps({
            "generated_at": self.timestamp.isoformat(),
            "version": VERSION,
            "hostname": self.evidence.get("system_info", {}).get("hostname"),
            "findings": [f.to_dict() for f in self.findings],
        }, indent=2)

    def to_html(self):
        rows = "\n".join(
            f"<tr class='sev-{f.severity.lower()}'><td>{f.severity}</td><td>{f.category}</td>"
            f"<td>{f.message}</td></tr>"
            for f in self.findings
        )
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IncidentHawk Triage Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:32px; }}
h1 {{ color:#f6ad55; }}
h2 {{ color:#9ae6b4; border-bottom:1px solid #333; padding-bottom:6px; margin-top:36px;}}
table {{ border-collapse: collapse; width:100%; margin-top:12px; }}
th, td {{ border:1px solid #2d2d3a; padding:8px 12px; text-align:left; font-size:14px;}}
th {{ background:#1a1d29; }}
.sev-critical {{ background:#4a1414; }}
.sev-high {{ background:#4a2c14; }}
.sev-medium {{ background:#4a4414; }}
.sev-low {{ background:#14304a; }}
.meta {{ color:#999; font-size:13px; }}
</style></head>
<body>
<h1>🦅 IncidentHawk Triage Report</h1>
<p class="meta">Host: {self.evidence.get('system_info', {}).get('hostname', 'unknown')} |
Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | Version {VERSION}</p>

<h2>Findings ({len(self.findings)})</h2>
<table><tr><th>Severity</th><th>Category</th><th>Message</th></tr>
{rows if rows else "<tr><td colspan='3'>No high-risk indicators detected.</td></tr>"}
</table>
</body></html>"""


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="incidenthawk",
        description="IncidentHawk - Linux Incident Response Automation Tool. "
                    "Collects a read-only forensic triage snapshot and packages it into a hash-verified evidence bundle.",
    )
    p.add_argument("--output", "-o", metavar="DIR", required=True,
                   help="Directory to write the evidence bundle to (a timestamp subfolder is created inside it)")
    p.add_argument("--quick", action="store_true",
                   help="Skip the slower filesystem-wide SUID/hidden-file scan for a faster triage")
    p.add_argument("--since", type=int, default=48, metavar="HOURS",
                   help="Look-back window in hours for 'recently modified files' (default: 48)")
    p.add_argument("--no-hash", action="store_true", help="Skip SHA-256 hashing of collected evidence (faster, less chain-of-custody rigor)")
    p.add_argument("--no-archive", action="store_true", help="Do not compress the evidence folder into a .tar.gz bundle")
    p.add_argument("--format", default="console", choices=["console", "json", "html", "all"],
                   help="Report output format in addition to the evidence bundle (default: console)")
    p.add_argument("--no-color", action="store_true", help="Disable colored console output")
    p.add_argument("--version", action="version", version=f"IncidentHawk {VERSION}")
    return p


def main():
    args = build_arg_parser().parse_args()

    if os.geteuid() != 0:
        print(colorize("[!] Not running as root - some data (other users' crontabs, protected logs, SSH keys) may be inaccessible.", C.YELLOW))

    hawk = IncidentHawk(since_hours=args.since, hash_files=not args.no_hash, quick=args.quick)
    hawk.run_full_triage()

    use_color = not args.no_color
    print()
    hawk.print_console(use_color=use_color)

    case_name = f"incidenthawk_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    case_dir = os.path.join(args.output, case_name)
    hawk.write_evidence_bundle(case_dir)
    print()
    print(colorize(f"[+] Evidence bundle written: {case_dir}/", C.GREEN, use_color))

    if not args.no_archive:
        archive = hawk.package_bundle(case_dir)
        print(colorize(f"[+] Compressed archive created: {archive}", C.GREEN, use_color))

    if args.format in ("json", "all"):
        path = os.path.join(args.output, f"{case_name}_report.json")
        with open(path, "w") as f:
            f.write(hawk.to_json())
        print(colorize(f"[+] JSON report saved: {path}", C.GREEN, use_color))

    if args.format in ("html", "all"):
        path = os.path.join(args.output, f"{case_name}_report.html")
        with open(path, "w") as f:
            f.write(hawk.to_html())
        print(colorize(f"[+] HTML report saved: {path}", C.GREEN, use_color))


if __name__ == "__main__":
    main()
