#!/usr/bin/env python3

"""
CYBR 2800 Digital Forensics
Instructor Evidence Image Generator

Creates:
    CYBR2800_Lab2_Evidence.dd
    CYBR2800_Lab2_Evidence.dd.sha256
    CYBR2800_Lab2_Evidence_manifest.txt

The resulting image contains:
    - User documents
    - Bash history
    - Browser history
    - SSH configuration
    - Authentication logs
    - System logs
    - Network activity
    - Suspicious script
    - Investigation notes
    - Deleted files for recovery
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
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

IMAGE_NAME = "CYBR2800_Lab2_Evidence.dd"
IMAGE_SIZE_MB = 256

MOUNT_POINT = Path("/mnt/cybr2800_lab2_evidence")
BUILD_DIR = Path("/tmp/cybr2800_lab2_evidence_build")
EVIDENCE_ROOT = BUILD_DIR / "root"

SCRIPT_DIR = Path.cwd()

IMAGE_PATH = SCRIPT_DIR / IMAGE_NAME
HASH_PATH = SCRIPT_DIR / f"{IMAGE_NAME}.sha256"
MANIFEST_PATH = SCRIPT_DIR / "CYBR2800_Lab2_Evidence_manifest.txt"


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
        "mkfs.ext4",
        "mount",
        "umount",
        "sha256sum",
        "cp",
        "rm",
        "sync"
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


def cleanup_mount():
    """Unmount the evidence image if mounted."""

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


def cleanup():
    """Clean temporary resources."""

    cleanup_mount()

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)

    MOUNT_POINT.mkdir(
        parents=True,
        exist_ok=True
    )


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

Students should treat this image as forensic evidence.

DO NOT MODIFY THE ORIGINAL EVIDENCE IMAGE.
"""
    )

    # --------------------------------------------------------
    # User documents
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
    # Bash history
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "home/alex/.bash_history",
        """pwd
ls -la
cd Documents
cat notes.txt
ssh alex@10.10.20.15
ssh backupadmin@10.10.20.25
curl http://10.10.20.15/status
wget http://10.10.20.25/backup.zip
ls -la
history
"""
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
    # Authentication log
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "var/log/auth.log",
        """Aug 20 08:01:11 workstation sshd[1201]: Accepted password for alex from 10.10.20.10
Aug 20 08:02:43 workstation sshd[1210]: Failed password for root from 10.10.20.55
Aug 20 08:02:47 workstation sshd[1211]: Failed password for root from 10.10.20.55
Aug 20 08:03:02 workstation sshd[1212]: Failed password for admin from 10.10.20.55
Aug 20 09:15:31 workstation sudo: alex : COMMAND=/usr/bin/ls
Aug 20 10:21:43 workstation sshd[1401]: Accepted password for alex from 10.10.20.15
Aug 20 14:20:10 workstation sshd[1901]: Accepted password for backupadmin from 10.10.20.25
Aug 20 14:22:17 workstation sshd[1902]: session opened for user backupadmin
Aug 20 14:31:44 workstation sshd[1902]: session closed for user backupadmin
Aug 20 15:42:03 workstation sshd[2010]: Failed password for root from 10.10.20.55
Aug 20 15:42:06 workstation sshd[2011]: Failed password for root from 10.10.20.55
"""
    )

    # --------------------------------------------------------
    # System log
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "var/log/syslog",
        """Aug 20 08:00:00 workstation systemd[1]: Started Network Service.
Aug 20 08:05:13 workstation systemd[1]: Started User Manager for UID 1000.
Aug 20 09:12:55 workstation kernel: eth0: link becomes ready
Aug 20 10:22:10 workstation systemd[1]: Started OpenSSH server.
Aug 20 14:19:57 workstation systemd[1]: Accepted SSH connection.
Aug 20 14:20:01 workstation systemd[1]: New session created.
Aug 20 14:32:01 workstation systemd[1]: Session closed.
"""
    )

    # --------------------------------------------------------
    # Network log
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "var/log/network_connections.log",
        """TIME                 SOURCE          DESTINATION       PORT
2026-08-20 10:22:14   10.10.20.10     10.10.20.15       22
2026-08-20 11:03:21   10.10.20.10     8.8.8.8           53
2026-08-20 14:20:03   10.10.20.25     10.10.20.10       22
2026-08-20 14:21:17   10.10.20.10     10.10.20.25       443
2026-08-20 14:22:11   10.10.20.10     10.10.20.25       22
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
    # Downloads
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
    # Additional evidence
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "var/log/remote_access.log",
        """2026-08-20 10:21:40 SUCCESS alex 10.10.20.15 SSH
2026-08-20 14:20:08 SUCCESS backupadmin 10.10.20.25 SSH
2026-08-20 14:31:44 CLOSED backupadmin 10.10.20.25 SSH
"""
    )

    print("[+] Evidence files created.")


# ============================================================
# BUILD IMAGE
# ============================================================

def create_image():

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
    # Create ext4 filesystem
    # --------------------------------------------------------

    run([
        "mkfs.ext4",
        "-F",
        "-L",
        "CYBR2800L2",
        str(IMAGE_PATH)
    ])

    # --------------------------------------------------------
    # Mount image
    # --------------------------------------------------------

    MOUNT_POINT.mkdir(
        parents=True,
        exist_ok=True
    )

    run([
        "mount",
        "-o",
        "loop",
        str(IMAGE_PATH),
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
            MOUNT_POINT / "home/alex/Downloads/suspicious_commands.txt"
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
        # Unmount
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

Evidence Categories:
- User documents
- Bash history
- Browser history
- SSH configuration
- Authentication logs
- System logs
- Network activity
- Remote-access activity
- Suspicious shell script
- Deleted files
- Credential-related artifacts
- File metadata

Deleted Evidence:
- home/alex/Downloads/temporary_credentials.txt
- home/alex/Downloads/backup_notes.txt
- home/alex/Downloads/suspicious_commands.txt

Important Investigation Indicators:
- 10.10.20.55
- 10.10.20.25
- 10.10.20.15
- backupadmin
- maintenance.sh

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