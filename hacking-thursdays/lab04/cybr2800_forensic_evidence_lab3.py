#!/usr/bin/env python3

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone

IMAGE_NAME = "CYBR2800_Lab3_Evidence.dd"
IMAGE_SIZE_MB = 256
MOUNT_DIR = Path("/mnt/cybr2800_lab3_evidence")
WORK_DIR = Path.cwd() / "lab3_build"

REQUIRED_COMMANDS = [
    "dd",
    "mkfs.ext4",
    "mount",
    "umount",
    "sha256sum",
    "cp",
    "rm",
    "sync",
]


def run(command, check=True):
    print(f"[+] Running: {' '.join(command)}")
    return subprocess.run(command, check=check)


def require_root():
    if os.geteuid() != 0:
        raise SystemExit(
            "ERROR: This script must be run as root.\n"
            "Run it with: sudo ./cybr2800_forensic_evidence_lab3.py"
        )


def check_commands():
    missing = []

    for command in REQUIRED_COMMANDS:
        if shutil.which(command) is None:
            missing.append(command)

    if missing:
        raise SystemExit(
            "ERROR: Missing required commands:\n"
            + "\n".join(f"  - {cmd}" for cmd in missing)
        )


def write_file(path, content, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    if mode is not None:
        os.chmod(path, mode)


def create_image():
    image_path = Path.cwd() / IMAGE_NAME

    if image_path.exists():
        raise SystemExit(
            f"ERROR: {image_path} already exists.\n"
            "Remove or rename the existing image before running this script."
        )

    print(f"[+] Creating {IMAGE_SIZE_MB} MB forensic image...")

    run([
        "dd",
        "if=/dev/zero",
        f"of={image_path}",
        "bs=1M",
        f"count={IMAGE_SIZE_MB}",
        "status=progress",
    ])

    print("[+] Creating ext4 filesystem...")
    run([
        "mkfs.ext4",
        "-F",
        "-L",
        "CYBR2800-LAB3",
        str(image_path),
    ])

    return image_path


def mount_image(image_path):
    MOUNT_DIR.mkdir(parents=True, exist_ok=True)

    print("[+] Mounting forensic image...")
    run([
        "mount",
        "-o",
        "loop",
        str(image_path),
        str(MOUNT_DIR),
    ])


def populate_evidence():
    print("[+] Populating controlled forensic evidence...")

    # ---------------------------------------------------------
    # Directory structure
    # ---------------------------------------------------------

    directories = [
        "home/alex/Documents",
        "home/alex/Downloads",
        "home/alex/.ssh",
        "home/alex/.config",
        "var/log",
        "var/tmp",
        "opt/tools",
        "etc",
    ]

    for directory in directories:
        (MOUNT_DIR / directory).mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # README
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "README.txt",
        """CYBR2800 Digital Forensics Lab 3
=================================

This filesystem is an instructor-created forensic training image.

Students are expected to examine the evidence using forensic tools.

Important:
- Do not modify the original evidence image.
- Verify the SHA-256 hash before analysis.
- Treat all timestamps as evidence requiring interpretation.
- Correlate multiple artifacts before making conclusions.

This image contains intentionally constructed forensic artifacts.
Not every artifact necessarily represents malicious activity.
""",
    )

    # ---------------------------------------------------------
    # User Documents
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/Documents/project.txt",
        """CYBR2800 Project Notes

Project status:
- Application migration
- Backup verification
- Security review

Next steps:
- Verify service accounts
- Review SSH access
- Remove temporary credentials
""",
    )

    write_file(
        MOUNT_DIR / "home/alex/Documents/notes.txt",
        """Meeting Notes

The maintenance window is scheduled for Friday.

Tasks:
1. Verify application configuration
2. Test remote administration
3. Confirm backup
4. Remove temporary access
""",
    )

    write_file(
        MOUNT_DIR / "home/alex/Documents/investigation.txt",
        """Security Investigation Notes

Several unexpected login attempts were observed.

Questions:
- Was remote access authorized?
- Which account was used?
- Were temporary credentials exposed?
- Were files removed after the activity?

Additional review is required.
""",
    )

    # ---------------------------------------------------------
    # Credential-related artifact
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/Documents/passwords_backup.txt",
        """Temporary Account Information

Account: svc_backup
Temporary access enabled during maintenance.

NOTE:
This file should not remain on the system after maintenance.
""",
        mode=0o600,
    )

    # ---------------------------------------------------------
    # SSH configuration
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/.ssh/config",
        """Host backup-server
    HostName 10.10.20.15
    User svc_backup
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
""",
        mode=0o600,
    )

    # ---------------------------------------------------------
    # Bash history
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/.bash_history",
        """cd ~/Documents
ls -la
cat passwords_backup.txt
ssh svc_backup@10.10.20.15
./maintenance.sh
cat /etc/application.conf
sudo systemctl restart application
grep -i credential /var/log/application.log
rm ~/Downloads/temporary_credentials.txt
rm ~/Downloads/backup_notes.txt
history
""",
        mode=0o600,
    )

    # ---------------------------------------------------------
    # Browser history
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/.browser_history.txt",
        """CYBR2800 Training Browser History

2026-08-28 18:42:11 https://intranet.example.local/login
2026-08-28 18:45:02 https://backup.example.local/
2026-08-28 18:47:31 https://intranet.example.local/admin
2026-08-28 18:51:19 https://backup.example.local/files
""",
        mode=0o600,
    )

    # ---------------------------------------------------------
    # Maintenance script
    # ---------------------------------------------------------

    maintenance_script = """#!/bin/bash

# CYBR2800 Lab 3 - Maintenance Script

echo "[+] Starting maintenance"

DATE=$(date)

echo "Maintenance started: $DATE" >> /var/log/maintenance.log

# Verify application
systemctl status application

# Test backup connection
ssh svc_backup@10.10.20.15 "ls -la /backup"

# Copy application configuration
cp /etc/application.conf /var/tmp/application.conf.backup

# Cleanup temporary files
rm -f /var/tmp/temporary_export.txt

echo "[+] Maintenance completed"
"""

    write_file(
        MOUNT_DIR / "home/alex/Documents/maintenance.sh",
        maintenance_script,
        mode=0o750,
    )

    # ---------------------------------------------------------
    # Suspicious command artifact
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/Downloads/suspicious_commands.txt",
        """Command Review

Potentially important commands observed:

ssh svc_backup@10.10.20.15
sudo systemctl restart application
cp /etc/application.conf /var/tmp/application.conf.backup
rm ~/Downloads/temporary_credentials.txt
rm ~/Downloads/backup_notes.txt

Investigator note:
Determine whether these commands were part of authorized maintenance.
""",
    )

    # ---------------------------------------------------------
    # Temporary credentials
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/Downloads/temporary_credentials.txt",
        """Temporary Maintenance Credentials

Username: svc_backup
Purpose: backup maintenance

Temporary password:
TRAINING-ONLY-REMOVE-ME

This file was created for temporary maintenance use.
It should be deleted after the maintenance window.
""",
        mode=0o600,
    )

    # ---------------------------------------------------------
    # Backup notes
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "home/alex/Downloads/backup_notes.txt",
        """Backup Maintenance Notes

Backup server:
10.10.20.15

Account:
svc_backup

Maintenance task:
Verify application backup.

Reminder:
Remove temporary credentials after maintenance.
""",
    )

    # ---------------------------------------------------------
    # Application configuration
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "etc/application.conf",
        """application.name=cybr-training-app
application.environment=production
application.port=8443
backup.server=10.10.20.15
backup.user=svc_backup
logging.enabled=true
""",
    )

    # ---------------------------------------------------------
    # Authentication log
    # ---------------------------------------------------------

    auth_log = """Aug 28 18:39:51 cybr-lab sshd[2140]: Failed password for invalid user admin from 10.10.20.44 port 49821 ssh2
Aug 28 18:40:02 cybr-lab sshd[2142]: Failed password for invalid user test from 10.10.20.44 port 49822 ssh2
Aug 28 18:42:17 cybr-lab sshd[2150]: Accepted publickey for alex from 10.10.20.44 port 49825 ssh2
Aug 28 18:42:18 cybr-lab sshd[2150]: pam_unix(sshd:session): session opened for user alex
Aug 28 18:44:03 cybr-lab sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/systemctl status application
Aug 28 18:45:10 cybr-lab sudo: alex : TTY=pts/0 ; PWD=/home/alex/Documents ; USER=root ; COMMAND=/usr/bin/systemctl restart application
Aug 28 18:52:41 cybr-lab sshd[2150]: pam_unix(sshd:session): session closed for user alex
"""

    write_file(
        MOUNT_DIR / "var/log/auth.log",
        auth_log,
    )

    # ---------------------------------------------------------
    # Remote access log
    # ---------------------------------------------------------

    remote_access = """2026-08-28 18:42:17 REMOTE_LOGIN user=alex source=10.10.20.44 destination=cybr-lab method=publickey result=SUCCESS
2026-08-28 18:45:10 PRIVILEGE_ESCALATION user=alex source=10.10.20.44 command="systemctl restart application" result=SUCCESS
2026-08-28 18:47:32 OUTBOUND_SSH user=alex source=cybr-lab destination=10.10.20.15 user=svc_backup result=SUCCESS
2026-08-28 18:49:12 OUTBOUND_CONNECTION source=cybr-lab destination=10.10.20.15 port=22 protocol=TCP result=ESTABLISHED
"""

    write_file(
        MOUNT_DIR / "var/log/remote_access.log",
        remote_access,
    )

    # ---------------------------------------------------------
    # Network connections
    # ---------------------------------------------------------

    network_log = """2026-08-28 18:42:17 TCP 10.10.20.44:49825 -> 10.10.20.10:22 ESTABLISHED
2026-08-28 18:47:32 TCP 10.10.20.10:40211 -> 10.10.20.15:22 ESTABLISHED
2026-08-28 18:47:34 TCP 10.10.20.10:40211 -> 10.10.20.15:22 DATA_TRANSFER
2026-08-28 18:49:12 TCP 10.10.20.10:40215 -> 10.10.20.15:443 ESTABLISHED
2026-08-28 18:50:04 TCP 10.10.20.10:40215 -> 10.10.20.15:443 CLOSED
"""

    write_file(
        MOUNT_DIR / "var/log/network_connections.log",
        network_log,
    )

    # ---------------------------------------------------------
    # System log
    # ---------------------------------------------------------

    syslog = """Aug 28 18:42:18 cybr-lab systemd[1]: Started User Manager for UID 1000.
Aug 28 18:44:03 cybr-lab sudo[2201]: alex : TTY=pts/0 ; COMMAND=/usr/bin/systemctl status application
Aug 28 18:45:10 cybr-lab sudo[2208]: alex : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart application
Aug 28 18:45:12 cybr-lab systemd[1]: Started cybr-training-app.service
Aug 28 18:47:35 cybr-lab systemd[1]: ssh.service: session activity detected
Aug 28 18:52:41 cybr-lab systemd[1]: Stopped User Manager for UID 1000.
"""

    write_file(
        MOUNT_DIR / "var/log/syslog",
        syslog,
    )

    # ---------------------------------------------------------
    # Application log
    # ---------------------------------------------------------

    application_log = """2026-08-28 18:43:12 INFO User alex authenticated
2026-08-28 18:44:52 INFO Configuration review initiated
2026-08-28 18:45:11 INFO Application restart requested by alex
2026-08-28 18:45:13 INFO Application restart completed
2026-08-28 18:47:34 INFO Backup connection initiated
2026-08-28 18:48:02 INFO Backup directory accessed
2026-08-28 18:50:22 INFO Configuration backup created
"""

    write_file(
        MOUNT_DIR / "var/log/application.log",
        application_log,
    )

    # ---------------------------------------------------------
    # Maintenance log
    # ---------------------------------------------------------

    maintenance_log = """2026-08-28 18:46:59 Maintenance started
2026-08-28 18:47:31 Testing backup connection
2026-08-28 18:48:02 Backup directory verified
2026-08-28 18:49:51 Application configuration copied
2026-08-28 18:50:07 Temporary file cleanup completed
2026-08-28 18:50:15 Maintenance completed
"""

    write_file(
        MOUNT_DIR / "var/log/maintenance.log",
        maintenance_log,
    )

    # ---------------------------------------------------------
    # Temporary export
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "var/tmp/temporary_export.txt",
        """Temporary Application Export

Application:
cybr-training-app

Environment:
production

Backup target:
10.10.20.15

This file is intended to be removed after maintenance.
""",
    )

    # ---------------------------------------------------------
    # Application configuration backup
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "var/tmp/application.conf.backup",
        """application.name=cybr-training-app
application.environment=production
application.port=8443
backup.server=10.10.20.15
backup.user=svc_backup
logging.enabled=true
""",
    )

    # ---------------------------------------------------------
    # Additional operational artifact
    # ---------------------------------------------------------

    write_file(
        MOUNT_DIR / "opt/tools/backup_check.sh",
        """#!/bin/bash

echo "Checking backup server"
ssh svc_backup@10.10.20.15 "ls -la /backup"
""",
        mode=0o750,
    )

    # ---------------------------------------------------------
    # Delete selected artifacts
    # ---------------------------------------------------------

    deleted_files = [
        MOUNT_DIR / "home/alex/Downloads/temporary_credentials.txt",
        MOUNT_DIR / "home/alex/Downloads/backup_notes.txt",
        MOUNT_DIR / "home/alex/Downloads/suspicious_commands.txt",
        MOUNT_DIR / "var/tmp/temporary_export.txt",
    ]

    print("[+] Creating deleted-file evidence...")

    for path in deleted_files:
        if path.exists():
            path.unlink()

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------

    try:
        os.chown(
            MOUNT_DIR / "home/alex",
            1000,
            1000,
        )
    except PermissionError:
        pass

    # ---------------------------------------------------------
    # Force filesystem updates
    # ---------------------------------------------------------

    run(["sync"])


def unmount_image():
    print("[+] Unmounting evidence image...")
    run(["umount", str(MOUNT_DIR)])


def calculate_hash(image_path):
    hash_file = Path(str(image_path) + ".sha256")

    print("[+] Calculating SHA-256 hash...")

    result = subprocess.run(
        ["sha256sum", str(image_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    hash_value = result.stdout.strip()

    hash_file.write_text(
        hash_value + "\n",
        encoding="utf-8",
    )

    return hash_value


def create_manifest(image_path, hash_value):
    manifest_path = Path.cwd() / "CYBR2800_Lab3_Evidence_manifest.txt"

    manifest = f"""CYBR2800 Digital Forensics Lab 3
=======================================

Evidence Image:
{image_path.name}

SHA-256:
{hash_value}

Filesystem:
ext4

Image Size:
{IMAGE_SIZE_MB} MB

Evidence Type:
Instructor-created controlled forensic training image

Scenario:
The image contains artifacts representing a controlled system
investigation involving user activity, authentication, remote access,
network communication, application activity, temporary credentials,
maintenance activity, and deleted files.

Important Evidence Categories:
- User shell history
- Authentication logs
- Remote access logs
- Network connection logs
- Application logs
- Maintenance logs
- SSH configuration
- Application configuration
- Deleted files
- File timestamps
- Maintenance scripts

Intentionally Deleted Evidence:
- /home/alex/Downloads/temporary_credentials.txt
- /home/alex/Downloads/backup_notes.txt
- /home/alex/Downloads/suspicious_commands.txt
- /var/tmp/temporary_export.txt

Important Investigation Goals:
1. Verify evidence integrity.
2. Identify filesystem structure.
3. Generate a filesystem timeline.
4. Analyze user activity.
5. Analyze authentication events.
6. Analyze remote access.
7. Analyze network activity.
8. Recover deleted evidence.
9. Correlate independent evidence sources.
10. Construct an incident timeline.
11. Determine what can and cannot be concluded.
12. Produce a professional forensic report.

Forensic Handling:
- Treat the original image as evidence.
- Do not modify the original image.
- Work from a verified copy.
- Record SHA-256 hashes.
- Document all analysis steps.
- Distinguish confirmed facts from assumptions.
"""

    manifest_path.write_text(
        manifest,
        encoding="utf-8",
    )

    return manifest_path


def main():
    require_root()
    check_commands()

    image_path = create_image()

    try:
        mount_image(image_path)
        populate_evidence()
    finally:
        if MOUNT_DIR.is_mount():
            unmount_image()

    print("[+] Evidence image created successfully.")

    hash_value = calculate_hash(image_path)
    manifest_path = create_manifest(image_path, hash_value)

    print()
    print("=" * 70)
    print("CYBR2800 LAB 3 FORENSIC EVIDENCE CREATED")
    print("=" * 70)
    print(f"Evidence Image : {image_path}")
    print(f"SHA-256        : {hash_value}")
    print(f"Hash File      : {image_path}.sha256")
    print(f"Manifest       : {manifest_path}")
    print()
    print("IMPORTANT:")
    print("Keep the original evidence image unchanged.")
    print("Students should receive a copy of the image and the SHA-256 hash.")
    print("=" * 70)


if __name__ == "__main__":
    main()