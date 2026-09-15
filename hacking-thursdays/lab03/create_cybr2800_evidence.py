#!/usr/bin/env python3

"""
CYBR 2800 Digital Forensics
Instructor Evidence Image Generator

Creates:
    CYBR2800_Lab2_Evidence.dd
    CYBR2800_Lab2_Evidence.dd.sha256
    CYBR2800_Lab2_Evidence_manifest.txt

Scenario for this build:
    After the Lab 1 investigation concluded, investigators located a second
    device connected to the same incident: an external backup drive used by
    "backupadmin", the service account responsible for backing up Alex's
    workstation to the internal backup server (backup01, 10.10.20.25). That
    drive has been imaged and merged into this evidence file, alongside the
    original workstation data, so students have substantially more material
    to examine than in Lab 1 -- including ~200 days of daily backup job logs,
    backupadmin's own home directory, and two additional deleted files.

The resulting image contains:
    - User documents (Alex's workstation)
    - Bash history (Alex and backupadmin)
    - Browser history
    - SSH configuration
    - Authentication logs (expanded, multi-week)
    - System logs (syslog, cron, dpkg)
    - Network activity (expanded, multi-week)
    - Remote-access activity
    - Suspicious script
    - Investigation notes
    - A second, unrelated user account (noise/red herring)
    - A recovered backup-drive source (mnt/recovered_backup) with ~200 daily
      backup job logs and backupadmin's own artifacts
    - Deleted files for recovery (5 total, across both sources)
    - Timestamps and filesystem metadata

IMPORTANT:
This script is intended for the instructor to create a controlled
forensic evidence image for CYBR 2800.

Students should receive a copy of the resulting .dd image.
"""

import os
import shutil
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

IMAGE_NAME = "CYBR2800_Lab2_Evidence.dd"
IMAGE_SIZE_MB = 256
PARTITION_START = "1MiB"
FS_LABEL = "CYBR2800L2"

MOUNT_POINT = Path("/mnt/cybr2800_lab2_evidence")
BUILD_DIR = Path("/tmp/cybr2800_lab2_evidence_build")
EVIDENCE_ROOT = BUILD_DIR / "root"

SCRIPT_DIR = Path.cwd()

IMAGE_PATH = SCRIPT_DIR / IMAGE_NAME
HASH_PATH = SCRIPT_DIR / f"{IMAGE_NAME}.sha256"
MANIFEST_PATH = SCRIPT_DIR / "CYBR2800_Lab2_Evidence_manifest.txt"

# Daily backup job logs on the recovered backup drive span this range,
# ending on the day of the incident.
BACKUP_LOG_START = date(2026, 2, 1)
BACKUP_LOG_END = date(2026, 8, 20)

# Tracks the loop device currently attached to IMAGE_PATH, if any,
# so it can be detached during cleanup or on error.
CURRENT_LOOP_DEV = None


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def run(command, check=True):
    """Run a system command and display it."""

    print()
    print("[+] " + " ".join(str(x) for x in command))

    result = subprocess.run(
        command,
        check=check,
        text=True
    )

    return result


def run_output(command):
    """Run a system command and capture its output."""

    print()
    print("[+] " + " ".join(str(x) for x in command))

    return subprocess.check_output(
        command,
        text=True
    ).strip()


def write_file(path, content):
    """Create a text file."""

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        content,
        encoding="utf-8"
    )


def require_root():
    """Require root privileges."""

    if os.geteuid() != 0:
        print()
        print("[-] This script must be run as root.")
        print()
        print("Run:")
        print()
        print("    sudo python3 create_cybr2800_evidence.py")
        print()
        sys.exit(1)


def check_tools():
    """Check required Linux tools."""

    required_tools = [
        "dd",
        "parted",
        "losetup",
        "mkfs.ext4",
        "mount",
        "umount",
        "mountpoint",
        "sha256sum",
        "cp",
        "rm",
        "sync",
        "chmod"
    ]

    missing = []

    for tool in required_tools:
        if shutil.which(tool) is None:
            missing.append(tool)

    if missing:
        print()
        print("[-] Missing required tools:")
        for tool in missing:
            print(f"    {tool}")

        print()
        print("Install the required packages before running the script.")
        sys.exit(1)


def detach_loop_device():
    """Detach the loop device attached to the image, if any."""

    global CURRENT_LOOP_DEV

    if CURRENT_LOOP_DEV:
        print(f"[+] Detaching loop device: {CURRENT_LOOP_DEV}")
        subprocess.run(
            ["losetup", "-d", CURRENT_LOOP_DEV],
            check=False
        )
        CURRENT_LOOP_DEV = None


def detach_stray_loop_devices():
    """Detach any loop devices left over from a previous, interrupted run."""

    if not IMAGE_PATH.exists():
        return

    result = subprocess.run(
        ["losetup", "-j", str(IMAGE_PATH)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False
    )

    for line in result.stdout.splitlines():
        loop_dev = line.split(":")[0].strip()

        if loop_dev:
            print(f"[+] Detaching stray loop device: {loop_dev}")
            subprocess.run(
                ["losetup", "-d", loop_dev],
                check=False
            )


def cleanup_mount():
    """Unmount the evidence image and detach its loop device, if active."""

    result = subprocess.run(
        ["mountpoint", "-q", str(MOUNT_POINT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode == 0:
        print("[+] Unmounting existing mount...")
        subprocess.run(
            ["umount", str(MOUNT_POINT)],
            check=False
        )

    detach_loop_device()


def cleanup():
    """Clean temporary resources."""

    cleanup_mount()
    detach_stray_loop_devices()

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)

    MOUNT_POINT.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# BULK CONTENT GENERATORS
# ============================================================
#
# These functions build the "hundreds of entries" content: multi-week logs
# and ~200 daily backup job logs. Every function that touches a required
# filename/keyword (see module docstring) preserves the original lines
# verbatim inside a larger body of realistic filler, so existing handout
# instructions (lab03.html, lab04.html) keep working unchanged.

def build_auth_log():
    """Build an expanded, multi-week auth.log around the incident day."""

    lines = []
    pid = 1000

    # Routine logins for ~19 days before the incident.
    for day in range(1, 20):
        pid += 3
        lines.append(
            f"Aug {day:02d} 08:0{day % 6}:11 workstation sshd[{pid}]: "
            f"Accepted password for alex from 10.10.20.10"
        )
        pid += 1
        lines.append(
            f"Aug {day:02d} 09:1{day % 6}:04 workstation sudo: "
            f"alex : COMMAND=/usr/bin/ls"
        )
        pid += 1
        lines.append(
            f"Aug {day:02d} 17:4{day % 6}:22 workstation sshd[{pid}]: "
            f"session closed for user alex"
        )
        pid += 1
        lines.append(
            f"Aug {day:02d} 02:00:0{day % 6} workstation sshd[{pid}]: "
            f"Accepted publickey for backupadmin from 10.10.20.25"
        )

    # Incident-day activity, preserved exactly from the original evidence set.
    lines += [
        "Aug 20 08:01:11 workstation sshd[1201]: Accepted password for alex from 10.10.20.10",
        "Aug 20 08:02:43 workstation sshd[1210]: Failed password for root from 10.10.20.55",
        "Aug 20 08:02:47 workstation sshd[1211]: Failed password for root from 10.10.20.55",
        "Aug 20 08:03:02 workstation sshd[1212]: Failed password for admin from 10.10.20.55",
        "Aug 20 09:15:31 workstation sudo: alex : COMMAND=/usr/bin/ls",
        "Aug 20 10:21:43 workstation sshd[1401]: Accepted password for alex from 10.10.20.15",
        "Aug 20 14:20:10 workstation sshd[1901]: Accepted password for backupadmin from 10.10.20.25",
        "Aug 20 14:22:17 workstation sshd[1902]: session opened for user backupadmin",
        "Aug 20 14:31:44 workstation sshd[1902]: session closed for user backupadmin",
        "Aug 20 15:42:03 workstation sshd[2010]: Failed password for root from 10.10.20.55",
        "Aug 20 15:42:06 workstation sshd[2011]: Failed password for root from 10.10.20.55",
    ]

    # A few routine days after, before the drive was imaged.
    for day in range(21, 24):
        pid += 5
        lines.append(
            f"Aug {day:02d} 08:0{day % 6}:11 workstation sshd[{pid}]: "
            f"Accepted password for alex from 10.10.20.10"
        )
        lines.append(
            f"Aug {day:02d} 17:4{day % 6}:00 workstation sshd[{pid + 1}]: "
            f"session closed for user alex"
        )

    return "\n".join(lines) + "\n"


def build_syslog():
    """Build an expanded, multi-week syslog around the incident day."""

    lines = []

    for day in range(1, 20):
        lines.append(
            f"Aug {day:02d} 06:00:0{day % 6} workstation systemd[1]: "
            f"Starting Daily apt download activities..."
        )
        lines.append(
            f"Aug {day:02d} 08:0{day % 6}:00 workstation systemd[1]: "
            f"Started User Manager for UID 1000."
        )
        lines.append(
            f"Aug {day:02d} 02:00:0{day % 6} workstation cron[{2000 + day}]: "
            f"(backupadmin) CMD (/usr/local/bin/backup_rotate.sh)"
        )

    lines += [
        "Aug 20 08:00:00 workstation systemd[1]: Started Network Service.",
        "Aug 20 08:05:13 workstation systemd[1]: Started User Manager for UID 1000.",
        "Aug 20 09:12:55 workstation kernel: eth0: link becomes ready",
        "Aug 20 10:22:10 workstation systemd[1]: Started OpenSSH server.",
        "Aug 20 14:19:57 workstation systemd[1]: Accepted SSH connection.",
        "Aug 20 14:20:01 workstation systemd[1]: New session created.",
        "Aug 20 14:32:01 workstation systemd[1]: Session closed.",
    ]

    for day in range(21, 24):
        lines.append(
            f"Aug {day:02d} 08:0{day % 6}:00 workstation systemd[1]: "
            f"Started User Manager for UID 1000."
        )

    return "\n".join(lines) + "\n"


def build_network_log():
    """Build an expanded, multi-week network_connections.log."""

    lines = ["TIME                 SOURCE          DESTINATION       PORT"]

    for day in range(1, 20):
        lines.append(
            f"2026-08-{day:02d} 02:00:0{day % 6}   10.10.20.25     10.10.20.30       5432"
        )
        lines.append(
            f"2026-08-{day:02d} 08:0{day % 6}:14   10.10.20.10     10.10.20.15       22"
        )

    lines += [
        "2026-08-20 10:22:14   10.10.20.10     10.10.20.15       22",
        "2026-08-20 11:03:21   10.10.20.10     8.8.8.8           53",
        "2026-08-20 14:20:03   10.10.20.25     10.10.20.10       22",
        "2026-08-20 14:21:17   10.10.20.10     10.10.20.25       443",
        "2026-08-20 14:22:11   10.10.20.10     10.10.20.25       22",
    ]

    for day in range(21, 24):
        lines.append(
            f"2026-08-{day:02d} 08:0{day % 6}:14   10.10.20.10     10.10.20.15       22"
        )

    return "\n".join(lines) + "\n"


def build_alex_bash_history():
    """Build an expanded .bash_history for alex with the original lines intact."""

    lines = [
        "pwd", "ls -la", "cd Documents", "cat notes.txt", "cat project.txt",
        "cd ..", "ls -la", "cd Documents", "less passwords_backup.txt",
        "cd ../Downloads", "ls -la", "cat suspicious_commands.txt",
        "cd ../Documents", "nano notes.txt", "cat notes.txt", "cd ~",
        "df -h", "free -m", "uptime", "whoami", "id", "cat /etc/hostname",
        "ls -la Documents", "ls -la Downloads", "cat investigation.txt",
    ]

    # Original suspicious commands, preserved exactly.
    lines += [
        "ssh alex@10.10.20.15",
        "ssh backupadmin@10.10.20.25",
        "curl http://10.10.20.15/status",
        "wget http://10.10.20.25/backup.zip",
        "ls -la",
        "history",
    ]

    lines += [
        "cd Documents", "cat maintenance.sh", "chmod +x maintenance.sh",
        "./maintenance.sh", "cat maintenance.sh", "cd ~", "ls -la",
        "history | tail -20",
    ]

    return "\n".join(lines) + "\n"


def build_cron_log():
    """Build a var/log/cron.log with routine and backup-related cron activity."""

    lines = []

    for day in range(1, 24):
        lines.append(
            f"Aug {day:02d} 02:00:00 workstation CRON[{3000 + day}]: "
            f"(backupadmin) CMD (/usr/local/bin/backup_rotate.sh)"
        )
        lines.append(
            f"Aug {day:02d} 03:00:00 workstation CRON[{3100 + day}]: "
            f"(root) CMD (/usr/local/bin/sync_to_offsite.sh)"
        )

    return "\n".join(lines) + "\n"


def build_dpkg_log():
    """Build a var/log/dpkg.log with routine package activity."""

    packages = [
        "openssh-server", "curl", "wget", "rsync", "cron", "vim", "git",
        "python3", "ca-certificates", "sudo",
    ]

    lines = []

    for index, package in enumerate(packages):
        day = 1 + (index * 2) % 20
        lines.append(
            f"2026-08-{day:02d} 06:0{index % 6}:00 upgrade {package} "
            f"1.0.{index} 1.0.{index + 1}"
        )

    return "\n".join(lines) + "\n"


def build_daily_backup_logs():
    """
    Generate one dated backup job log per day, simulating the routine job
    history recovered from the backup drive. Returns a dict mapping a path
    relative to mnt/recovered_backup/ to that file's content.

    This is the primary source of "hundreds of files" in the expanded image:
    ~200 days of daily job logs (2026-02-01 through 2026-08-20).
    """

    logs = {}
    current = BACKUP_LOG_START
    job_id = 40000

    while current <= BACKUP_LOG_END:
        job_id += 1
        relative_path = f"archives/backup_log_{current.isoformat()}.txt"

        files_backed_up = 120 + (current.toordinal() % 40)
        size_mb = 512 + (current.toordinal() % 200)
        status = "SUCCESS"
        note = ""

        if current == date(2026, 8, 20):
            note = (
                "\nNOTE: Job started outside the normal maintenance window "
                "(14:00 instead of 02:00). Authenticated as backupadmin "
                "from 10.10.20.10.\n"
            )
        elif current == date(2026, 8, 19):
            status = "FAILED"
            note = (
                "\nNOTE: Job failed - authentication error for backupadmin. "
                "Retried manually the next day.\n"
            )

        content = (
            "Backup Job Log\n"
            f"Date: {current.isoformat()}\n"
            f"Job ID: {job_id}\n"
            "Host: backup01\n"
            "Account: backupadmin\n"
            f"Files backed up: {files_backed_up}\n"
            f"Total size: {size_mb} MB\n"
            f"Status: {status}\n"
            f"{note}"
        )

        logs[relative_path] = content
        current += timedelta(days=1)

    return logs


# ============================================================
# CREATE EVIDENCE DATA
# ============================================================

def create_evidence_files():

    print()
    print("=" * 70)
    print("CREATING CONTROLLED FORENSIC EVIDENCE")
    print("=" * 70)

    # --------------------------------------------------------
    # README
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "README.txt",
        """CYBR 2800 FORENSIC EVIDENCE IMAGE

This image was created for educational digital-forensics analysis.

Investigation areas include:

1. User activity
2. Authentication activity
3. Network activity
4. SSH activity
5. Suspicious scripts
6. Deleted files
7. File metadata
8. Evidence recovery
9. Timeline analysis
10. Backup-server activity (recovered second device)

Students should treat this image as forensic evidence.

DO NOT MODIFY THE ORIGINAL EVIDENCE IMAGE.
"""
    )

    # --------------------------------------------------------
    # User documents (Alex's workstation)
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/Documents/notes.txt",
        """CYBR 2800 Investigation Notes

Meeting notes:

- Review server logs
- Check authentication activity
- Verify unusual network connections
- Follow up with IT regarding the backup server

TODO:

- Review VPN logs
- Verify administrator accounts
- Review backup server activity
"""
    )

    write_file(
        EVIDENCE_ROOT / "home/alex/Documents/project.txt",
        """Project: Network Security Assessment

Systems:

web01
db01
backup01

Security controls:

Firewall
IDS
Endpoint monitoring
Centralized logging
"""
    )

    write_file(
        EVIDENCE_ROOT / "home/alex/Documents/passwords_backup.txt",
        """OLD PASSWORD NOTES

Email:
old-password-123

VPN:
VPN-Backup-2025

NOTE:
These passwords should no longer be used.
"""
    )

    # --------------------------------------------------------
    # Investigation document
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/Documents/investigation.txt",
        """Security Investigation

Potentially suspicious activity:

10.10.20.55
Repeated SSH authentication failures.

10.10.20.25
Backup server accessed outside normal maintenance window.

Files requiring review:

maintenance.sh
backup.zip
temporary_credentials.txt

Investigation questions:

Who accessed the backup server?
When did the activity occur?
Was the activity authorized?
Were credentials exposed?
"""
    )

    # --------------------------------------------------------
    # Suspicious script
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/Documents/maintenance.sh",
        """#!/bin/bash

echo "Starting maintenance..."

SERVER="10.10.20.25"

curl http://$SERVER/update.sh -o /tmp/update.sh

chmod +x /tmp/update.sh

echo "Maintenance complete."
"""
    )

    # --------------------------------------------------------
    # Bash history (expanded, original lines preserved)
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/.bash_history",
        build_alex_bash_history()
    )

    # --------------------------------------------------------
    # Browser history simulation
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/.browser_history.txt",
        """2026-08-20 08:32 https://www.google.com
2026-08-20 08:35 https://www.uvu.edu/
2026-08-20 09:10 https://github.com/
2026-08-20 10:25 https://stackoverflow.com/
2026-08-20 11:42 https://example.com/security
2026-08-20 14:03 https://internal.example.local/login
2026-08-20 14:15 https://paste.example.local/
2026-08-20 14:21 https://files.example.local/
"""
    )

    # --------------------------------------------------------
    # SSH configuration
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/.ssh/config",
        """Host internal-server
    HostName 10.10.20.15
    User alex

Host backup-server
    HostName 10.10.20.25
    User backupadmin
"""
    )

    # --------------------------------------------------------
    # Authentication / system / network logs (expanded)
    # --------------------------------------------------------

    write_file(EVIDENCE_ROOT / "var/log/auth.log", build_auth_log())
    write_file(EVIDENCE_ROOT / "var/log/syslog", build_syslog())
    write_file(EVIDENCE_ROOT / "var/log/network_connections.log", build_network_log())
    write_file(EVIDENCE_ROOT / "var/log/cron.log", build_cron_log())
    write_file(EVIDENCE_ROOT / "var/log/dpkg.log", build_dpkg_log())

    write_file(
        EVIDENCE_ROOT / "var/log/remote_access.log",
        """2026-08-20 10:21:40 SUCCESS alex 10.10.20.15 SSH
2026-08-20 14:20:08 SUCCESS backupadmin 10.10.20.25 SSH
2026-08-20 14:31:44 CLOSED backupadmin 10.10.20.25 SSH
"""
    )

    # --------------------------------------------------------
    # Application configuration
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "etc/application.conf",
        """APPLICATION_NAME=InternalPortal
ENVIRONMENT=production
DATABASE_HOST=10.10.20.30
DATABASE_PORT=5432
DEBUG=false
LOG_LEVEL=INFO
"""
    )

    # --------------------------------------------------------
    # Downloads (three original deleted files)
    # --------------------------------------------------------

    downloads = EVIDENCE_ROOT / "home/alex/Downloads"

    write_file(
        downloads / "temporary_credentials.txt",
        """TEMPORARY CREDENTIALS

username: backupadmin
password: Backup-Temp-2026!

Server: 10.10.20.25

These credentials were created for temporary maintenance.
"""
    )

    write_file(
        downloads / "backup_notes.txt",
        """Backup Server Notes

Backup server:
10.10.20.25

Maintenance window:
14:00 - 15:00

Account:
backupadmin
"""
    )

    write_file(
        downloads / "suspicious_commands.txt",
        """Commands observed during investigation:

wget http://10.10.20.25/backup.zip
curl http://10.10.20.25/update.sh
ssh backupadmin@10.10.20.25
"""
    )

    # --------------------------------------------------------
    # Second, unrelated user account (noise / red herring)
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/jordan/Documents/todo.txt",
        """Personal TODO

- Renew gym membership
- Pick up dry cleaning
- Submit expense report
- Schedule dentist appointment
"""
    )

    write_file(
        EVIDENCE_ROOT / "home/jordan/.bash_history",
        """pwd
ls
cd Documents
cat todo.txt
firefox &
exit
"""
    )

    write_file(
        EVIDENCE_ROOT / "home/jordan/.browser_history.txt",
        """2026-08-18 09:15 https://mail.example.com
2026-08-18 12:03 https://news.example.com
2026-08-18 17:41 https://shopping.example.com
"""
    )

    # --------------------------------------------------------
    # Recovered backup drive (second device discovered after Lab 1)
    # --------------------------------------------------------

    backup_root = EVIDENCE_ROOT / "mnt/recovered_backup"

    write_file(
        backup_root / "README_BACKUP_SOURCE.txt",
        """EVIDENCE SOURCE NOTE

This directory (mnt/recovered_backup) represents a secondary evidence
source: an external backup drive used by the "backupadmin" service
account for backup01 (10.10.20.25).

The drive was located and seized after the Lab 1 investigation concluded.
It has been imaged and merged into this evidence file so investigators
can examine both the original workstation data and the backup server's
activity together.

Do not assume every item here is new. Some information may confirm or
expand on what was already identified from the workstation image.
"""
    )

    write_file(
        backup_root / "backup_manifest.txt",
        f"""BACKUP DEVICE MANIFEST

Device: External USB backup drive
Associated host: backup01 (10.10.20.25)
Associated account: backupadmin

Contents:
- Daily backup job logs (archives/)
- backupadmin home directory
- Maintenance records
- Internal notes

Job log range: {BACKUP_LOG_START.isoformat()} to {BACKUP_LOG_END.isoformat()}
"""
    )

    write_file(
        backup_root / "home/backupadmin/.bash_history",
        """pwd
ls -la
cd Documents
cat server_inventory.txt
ssh backupadmin@10.10.20.25
cat maintenance_log.txt
sudo systemctl status backup.timer
tail /var/log/auth.log
cd ../scripts
cat backup_rotate.sh
cat sync_to_offsite.sh
cd ../Documents
nano credentials_rotation.txt
rm credentials_rotation.txt
history
"""
    )

    write_file(
        backup_root / "home/backupadmin/Documents/server_inventory.txt",
        """Backup Server Inventory

Host: backup01 (10.10.20.25)
Role: Nightly backups for the workstation and internal file shares
Account: backupadmin (service account)
Scheduled jobs: 02:00 daily via cron
Retention: 200 days of job logs kept under archives/
"""
    )

    write_file(
        backup_root / "home/backupadmin/Documents/maintenance_log.txt",
        """Maintenance Log - backup01

2026-07-02  Rotated backupadmin SSH key
2026-07-15  Patched OpenSSH to latest version
2026-08-01  Reviewed firewall rules for 10.10.20.0/24
2026-08-20  Unscheduled maintenance window - see maintenance.sh on workstation
"""
    )

    write_file(
        backup_root / "home/backupadmin/Documents/credentials_rotation.txt",
        """CREDENTIAL ROTATION NOTES

Old backupadmin password: Backup-Temp-2026!
New backupadmin password: (see password manager)

Reason for rotation: temporary credentials were created for a
maintenance window on 2026-08-20 and should not remain valid afterward.
"""
    )

    write_file(
        backup_root / "home/backupadmin/Documents/incident_draft.txt",
        """DRAFT - Incident Notes (backupadmin)

Noticed a login to backup01 outside the normal maintenance window on
2026-08-20. Also noticed the scheduled backup job for 2026-08-19 failed
with an authentication error, which is unusual. Flagging for the
investigation team.

- backupadmin
"""
    )

    write_file(
        backup_root / "home/backupadmin/scripts/backup_rotate.sh",
        """#!/bin/bash
# Rotates backup archives older than 200 days
find /mnt/recovered_backup/archives -name "backup_log_*.txt" -mtime +200 -delete
"""
    )

    write_file(
        backup_root / "home/backupadmin/scripts/sync_to_offsite.sh",
        """#!/bin/bash
# Syncs nightly backups to the offsite server
rsync -az /var/backups/ offsite:/backups/workstation/
"""
    )

    # ~200 daily backup job logs -- the main source of "hundreds of files".
    print("[+] Generating daily backup job logs (this adds ~200 files)...")

    for relative_path, content in build_daily_backup_logs().items():
        write_file(backup_root / relative_path, content)

    print("[+] Evidence files created.")


# ============================================================
# BUILD IMAGE
# ============================================================

def create_image():

    global CURRENT_LOOP_DEV

    print()
    print("=" * 70)
    print("CREATING FORENSIC DISK IMAGE")
    print("=" * 70)

    # --------------------------------------------------------
    # Create blank image
    # --------------------------------------------------------

    run([
        "dd",
        "if=/dev/zero",
        f"of={IMAGE_PATH}",
        "bs=1M",
        f"count={IMAGE_SIZE_MB}",
        "status=progress"
    ])

    # --------------------------------------------------------
    # Create an MBR partition table with a single primary partition.
    #
    # The lab requires students to run `mmls` to identify a real
    # partition scheme/start sector, then pass that offset to
    # `fsstat`/`fls`/`istat`/`icat`/`tsk_recover` with `-o`. A raw
    # image formatted directly with mkfs (no partition table) has
    # none of that, so mmls would fail to find a valid partition.
    # --------------------------------------------------------

    run([
        "parted",
        "--script",
        str(IMAGE_PATH),
        "mklabel",
        "msdos"
    ])

    run([
        "parted",
        "--script",
        str(IMAGE_PATH),
        "mkpart",
        "primary",
        "ext4",
        PARTITION_START,
        "100%"
    ])

    # --------------------------------------------------------
    # Attach the image as a loop device with partition scanning so
    # the partition appears as its own device node.
    # --------------------------------------------------------

    loop_dev = run_output([
        "losetup",
        "--find",
        "--show",
        "-P",
        str(IMAGE_PATH)
    ])

    CURRENT_LOOP_DEV = loop_dev
    partition_dev = f"{loop_dev}p1"

    # --------------------------------------------------------
    # Create ext4 filesystem on the partition
    # --------------------------------------------------------

    run([
        "mkfs.ext4",
        "-F",
        "-L",
        FS_LABEL,
        partition_dev
    ])

    # --------------------------------------------------------
    # Mount the partition
    # --------------------------------------------------------

    MOUNT_POINT.mkdir(
        parents=True,
        exist_ok=True
    )

    run([
        "mount",
        partition_dev,
        str(MOUNT_POINT)
    ])

    try:

        # ----------------------------------------------------
        # Copy evidence
        # ----------------------------------------------------

        print()
        print("[+] Copying evidence into filesystem...")

        run([
            "cp",
            "-a",
            str(EVIDENCE_ROOT) + "/.",
            str(MOUNT_POINT)
        ])

        run(["sync"])

        # ----------------------------------------------------
        # Set realistic permissions
        # ----------------------------------------------------

        print("[+] Setting file permissions...")

        run([
            "chmod",
            "700",
            str(MOUNT_POINT / "home/alex")
        ])

        run([
            "chmod",
            "600",
            str(MOUNT_POINT / "home/alex/.bash_history")
        ])

        run([
            "chmod",
            "600",
            str(MOUNT_POINT / "home/alex/.ssh/config")
        ])

        run([
            "chmod",
            "755",
            str(MOUNT_POINT / "home/alex/Documents/maintenance.sh")
        ])

        run([
            "chmod",
            "700",
            str(MOUNT_POINT / "mnt/recovered_backup/home/backupadmin")
        ])

        run([
            "chmod",
            "600",
            str(MOUNT_POINT / "mnt/recovered_backup/home/backupadmin/.bash_history")
        ])

        # ----------------------------------------------------
        # Force filesystem activity before deletion
        # ----------------------------------------------------

        run(["sync"])

        # ----------------------------------------------------
        # Delete selected files
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print("CREATING DELETED-FILE EVIDENCE")
        print("=" * 70)

        deleted_files = [
            MOUNT_POINT / "home/alex/Downloads/temporary_credentials.txt",
            MOUNT_POINT / "home/alex/Downloads/backup_notes.txt",
            MOUNT_POINT / "home/alex/Downloads/suspicious_commands.txt",
            MOUNT_POINT / "mnt/recovered_backup/home/backupadmin/Documents/credentials_rotation.txt",
            MOUNT_POINT / "mnt/recovered_backup/archives/backup_log_2026-08-19.txt",
        ]

        for file_path in deleted_files:

            print(
                f"[+] Deleting evidence file: "
                f"{file_path.relative_to(MOUNT_POINT)}"
            )

            if file_path.exists():
                file_path.unlink()

        run(["sync"])

    finally:

        # ----------------------------------------------------
        # Unmount and detach the loop device
        # ----------------------------------------------------

        print()
        print("[+] Unmounting evidence image...")

        cleanup_mount()


# ============================================================
# HASH IMAGE
# ============================================================

def calculate_hash():

    print()
    print("=" * 70)
    print("CALCULATING EVIDENCE HASH")
    print("=" * 70)

    result = subprocess.check_output(
        ["sha256sum", str(IMAGE_PATH)],
        text=True
    ).strip()

    HASH_PATH.write_text(
        result + "\n",
        encoding="utf-8"
    )

    print()
    print(f"[+] SHA-256:")
    print(f"    {result}")

    return result


# ============================================================
# CREATE MANIFEST
# ============================================================

def create_manifest(image_hash):

    print()
    print("=" * 70)
    print("CREATING EVIDENCE MANIFEST")
    print("=" * 70)

    manifest = f"""CYBR 2800 DIGITAL FORENSICS
FORENSIC EVIDENCE MANIFEST
========================================

Evidence Image:
{IMAGE_NAME}

Image Size:
{IMAGE_SIZE_MB} MB

Filesystem:
ext4

Evidence Image SHA-256:
{image_hash}

Purpose:
Educational digital-forensics investigation.

Scenario:
After Lab 1 concluded, a second device (an external backup drive used
by the "backupadmin" service account for backup01) was discovered and
imaged. Its contents were merged into this evidence file alongside the
original workstation data.

Evidence Categories:
- User documents (Alex's workstation)
- Bash history (Alex and backupadmin)
- Browser history
- SSH configuration
- Authentication logs (expanded, multi-week)
- System logs (syslog, cron, dpkg)
- Network activity (expanded, multi-week)
- Remote-access activity
- Suspicious shell script
- A second, unrelated user account (noise)
- ~200 daily backup job logs recovered from the backup drive
- Deleted files
- Credential-related artifacts
- File metadata

Deleted Evidence:
- home/alex/Downloads/temporary_credentials.txt
- home/alex/Downloads/backup_notes.txt
- home/alex/Downloads/suspicious_commands.txt
- mnt/recovered_backup/home/backupadmin/Documents/credentials_rotation.txt
- mnt/recovered_backup/archives/backup_log_2026-08-19.txt

Important Investigation Indicators:
- 10.10.20.55
- 10.10.20.25
- 10.10.20.15
- backupadmin
- maintenance.sh
- backup_log_2026-08-19.txt (failed job, later deleted)
- backup_log_2026-08-20.txt (job outside maintenance window)

FORENSIC HANDLING:
The original image generated by this script should be preserved
as the instructor master copy.

Students should receive a duplicate copy and verify its SHA-256
hash before beginning analysis.

Students should not modify their original evidence copy.

========================================
"""

    MANIFEST_PATH.write_text(
        manifest,
        encoding="utf-8"
    )

    print(f"[+] Manifest created: {MANIFEST_PATH}")


# ============================================================
# FINAL VERIFICATION
# ============================================================

def verify_image():

    print()
    print("=" * 70)
    print("FINAL VERIFICATION")
    print("=" * 70)

    if not IMAGE_PATH.exists():
        print("[-] Evidence image was not created.")
        sys.exit(1)

    if not HASH_PATH.exists():
        print("[-] Hash file was not created.")
        sys.exit(1)

    if IMAGE_PATH.stat().st_size == 0:
        print("[-] Evidence image is empty.")
        sys.exit(1)

    print()
    print("[+] Evidence image exists.")
    print(
        f"[+] Size: "
        f"{IMAGE_PATH.stat().st_size:,} bytes"
    )

    print(f"[+] SHA-256 file: {HASH_PATH}")
    print(f"[+] Manifest: {MANIFEST_PATH}")

    print()
    print("Files created:")
    print()
    print(f"  {IMAGE_PATH}")
    print(f"  {HASH_PATH}")
    print(f"  {MANIFEST_PATH}")


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("CYBR 2800 FORENSIC EVIDENCE GENERATOR")
    print("=" * 70)

    require_root()
    check_tools()

    cleanup()

    create_evidence_files()
    create_image()

    image_hash = calculate_hash()

    create_manifest(image_hash)

    verify_image()

    cleanup_mount()

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)

    print()
    print("=" * 70)
    print("FORENSIC EVIDENCE IMAGE COMPLETE")
    print("=" * 70)

    print()
    print("IMPORTANT:")
    print("Preserve the generated .dd file as your instructor master.")
    print("Do not modify the master evidence image.")
    print()
    print("Students should verify the SHA-256 hash before analysis.")
    print()


if __name__ == "__main__":
    main()
