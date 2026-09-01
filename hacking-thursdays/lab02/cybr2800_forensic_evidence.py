#!/usr/bin/env python3

import os
import subprocess
import shutil
import tempfile
from pathlib import Path
from datetime import datetime

IMAGE_NAME = "CYBR2800_Lab1_Evidence.dd"
IMAGE_SIZE_MB = 256
MOUNT_POINT = "/mnt/cybr2800_lab1_evidence"

BASE_DIR = Path("/tmp/cybr2800_lab1_evidence_build")
EVIDENCE_DIR = BASE_DIR / "evidence"

def run(command):
    print(f"\n[+] Running: {' '.join(command)}")
    subprocess.run(command, check=True)

def write_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

def main():

    if os.geteuid() != 0:
        print("[-] Please run this script with sudo.")
        print("    Example: sudo python3 cybr2800_forensic_evidence.py")
        return

    print("=" * 70)
    print(" CYBR 2800 - FORENSIC EVIDENCE IMAGE CREATOR")
    print("=" * 70)

    # ------------------------------------------------------------
    # 1. Check required tools
    # ------------------------------------------------------------

    required = ["dd", "mkfs.ext4", "mount", "umount", "sha256sum"]

    for tool in required:
        if shutil.which(tool) is None:
            print(f"[-] Required tool not found: {tool}")
            return

    # ------------------------------------------------------------
    # 2. Clean previous build
    # ------------------------------------------------------------

    if BASE_DIR.exists():
        print("[+] Removing previous build directory...")
        shutil.rmtree(BASE_DIR)

    BASE_DIR.mkdir(parents=True)
    EVIDENCE_DIR.mkdir()

    image_path = Path.cwd() / IMAGE_NAME

    if image_path.exists():
        print(f"[!] Removing previous image: {image_path}")
        image_path.unlink()

    # ------------------------------------------------------------
    # 3. Create realistic evidence files
    # ------------------------------------------------------------

    print("[+] Creating evidence files...")

    # User profile
    write_file(
        EVIDENCE_DIR / "home/alex/Documents/notes.txt",
        """CYBR 2800 Investigation Notes

Meeting notes:
- Review server logs
- Check authentication activity
- Verify unusual network connections
- Follow up with IT regarding the backup server

TODO:
- Review VPN logs
- Verify administrator accounts
"""
    )

    write_file(
        EVIDENCE_DIR / "home/alex/Documents/project.txt",
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

    # Personal-looking document
    write_file(
        EVIDENCE_DIR / "home/alex/Documents/passwords_backup.txt",
        """OLD PASSWORD NOTES

Email:
old-password-123

VPN:
VPN-Backup-2025

NOTE:
These passwords should no longer be used.
"""
    )

    # Browser history simulation
    write_file(
        EVIDENCE_DIR / "home/alex/.browser_history.txt",
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

    # SSH configuration
    write_file(
        EVIDENCE_DIR / "home/alex/.ssh/config",
        """Host internal-server
    HostName 10.10.20.15
    User alex

Host backup-server
    HostName 10.10.20.25
    User backupadmin
"""
    )

    # Bash history
    write_file(
        EVIDENCE_DIR / "home/alex/.bash_history",
        """pwd
ls -la
cd Documents
cat notes.txt
ssh alex@10.10.20.15
ssh backupadmin@10.10.20.25
curl http://10.10.20.15/status
wget http://10.10.20.25/backup.zip
history
"""
    )

    # Authentication logs
    write_file(
        EVIDENCE_DIR / "var/log/auth.log",
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

    # System log
    write_file(
        EVIDENCE_DIR / "var/log/syslog",
        """Aug 20 08:00:00 workstation systemd[1]: Started Network Service.
Aug 20 08:05:13 workstation systemd[1]: Started User Manager for UID 1000.
Aug 20 09:12:55 workstation kernel: eth0: link becomes ready
Aug 20 10:22:10 workstation systemd[1]: Started OpenSSH server.
Aug 20 14:19:57 workstation systemd[1]: Accepted SSH connection.
Aug 20 14:20:01 workstation systemd[1]: New session created.
Aug 20 14:32:01 workstation systemd[1]: Session closed.
"""
    )

    # Network connections
    write_file(
        EVIDENCE_DIR / "var/log/network_connections.log",
        """TIME                 SOURCE          DESTINATION       PORT
2026-08-20 10:22:14   10.10.20.10     10.10.20.15       22
2026-08-20 11:03:21   10.10.20.10     8.8.8.8           53
2026-08-20 14:20:03   10.10.20.25     10.10.20.10       22
2026-08-20 14:21:17   10.10.20.10     10.10.20.25       443
2026-08-20 14:22:11   10.10.20.10     10.10.20.25       22
"""
    )

    # Suspicious script
    write_file(
        EVIDENCE_DIR / "home/alex/Documents/maintenance.sh",
        """#!/bin/bash

echo "Starting maintenance..."

SERVER="10.10.20.25"

curl http://$SERVER/update.sh -o /tmp/update.sh
chmod +x /tmp/update.sh

echo "Maintenance complete."
"""
    )

    # Suspicious IP notes
    write_file(
        EVIDENCE_DIR / "home/alex/Documents/investigation.txt",
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
"""
    )

    # Fake configuration
    write_file(
        EVIDENCE_DIR / "etc/application.conf",
        """APPLICATION_NAME=InternalPortal
ENVIRONMENT=production
DATABASE_HOST=10.10.20.30
DATABASE_PORT=5432
DEBUG=false
LOG_LEVEL=INFO
"""
    )

    # README
    write_file(
        EVIDENCE_DIR / "README.txt",
        """CYBR 2800 FORENSIC EVIDENCE

This disk image was created for educational forensic analysis.

Students should investigate:

1. User activity
2. Authentication attempts
3. Network activity
4. Suspicious files
5. Deleted files
6. File metadata
7. Possible timeline of events

DO NOT MODIFY THE ORIGINAL EVIDENCE IMAGE.
"""
    )

    # ------------------------------------------------------------
    # 4. Create files that will intentionally be deleted
    # ------------------------------------------------------------

    deleted_dir = EVIDENCE_DIR / "home/alex/Downloads"

    deleted_dir.mkdir(parents=True, exist_ok=True)

    write_file(
        deleted_dir / "temporary_credentials.txt",
        """TEMPORARY CREDENTIALS

username: backupadmin
password: Backup-Temp-2026!

Server: 10.10.20.25

These credentials were created for temporary maintenance.
"""
    )

    write_file(
        deleted_dir / "backup_notes.txt",
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
        deleted_dir / "suspicious_commands.txt",
        """Commands observed during investigation:

wget http://10.10.20.25/backup.zip
curl http://10.10.20.25/update.sh
ssh backupadmin@10.10.20.25
"""
    )

    # ------------------------------------------------------------
    # 5. Create a 256 MB raw image
    # ------------------------------------------------------------

    print("[+] Creating raw disk image...")

    run([
        "dd",
        "if=/dev/zero",
        f"of={image_path}",
        "bs=1M",
        f"count={IMAGE_SIZE_MB}",
        "status=progress"
    ])

    # ------------------------------------------------------------
    # 6. Format image as ext4
    # ------------------------------------------------------------

    print("[+] Creating ext4 filesystem...")

    run([
        "mkfs.ext4",
        "-F",
        "-L",
        "CYBR2800L1",
        str(image_path)
    ])

    # ------------------------------------------------------------
    # 7. Mount image
    # ------------------------------------------------------------

    Path(MOUNT_POINT).mkdir(exist_ok=True)

    print("[+] Mounting evidence image...")

    run([
        "mount",
        "-o",
        "loop",
        str(image_path),
        MOUNT_POINT
    ])

    # ------------------------------------------------------------
    # 8. Copy evidence into mounted filesystem
    # ------------------------------------------------------------

    print("[+] Copying evidence into image...")

    run([
        "cp",
        "-a",
        str(EVIDENCE_DIR) + "/.",
        MOUNT_POINT
    ])

    # ------------------------------------------------------------
    # 9. Sync changes
    # ------------------------------------------------------------

    print("[+] Syncing filesystem...")

    run(["sync"])

    # ------------------------------------------------------------
    # 10. Remove selected files so students can recover them
    # ------------------------------------------------------------

    print("[+] Creating deleted-file evidence...")

    deleted_files = [
        f"{MOUNT_POINT}/home/alex/Downloads/temporary_credentials.txt",
        f"{MOUNT_POINT}/home/alex/Downloads/backup_notes.txt",
        f"{MOUNT_POINT}/home/alex/Downloads/suspicious_commands.txt"
    ]

    for file in deleted_files:
        if os.path.exists(file):
            os.remove(file)

    run(["sync"])

    # ------------------------------------------------------------
    # 11. Unmount image
    # ------------------------------------------------------------

    print("[+] Unmounting evidence image...")

    run([
        "umount",
        MOUNT_POINT
    ])

    # ------------------------------------------------------------
    # 12. Calculate SHA-256 hash
    # ------------------------------------------------------------

    print("[+] Calculating SHA-256 hash...")

    hash_result = subprocess.check_output(
        ["sha256sum", str(image_path)],
        text=True
    ).strip()

    hash_file = Path.cwd() / f"{IMAGE_NAME}.sha256"

    hash_file.write_text(hash_result + "\n")

    # ------------------------------------------------------------
    # 13. Clean temporary files
    # ------------------------------------------------------------

    print("[+] Cleaning temporary build files...")

    shutil.rmtree(BASE_DIR)

    # ------------------------------------------------------------
    # 14. Final output
    # ------------------------------------------------------------

    print("\n" + "=" * 70)
    print(" FORENSIC EVIDENCE IMAGE CREATED")
    print("=" * 70)

    print(f"\nEvidence image:")
    print(f"  {image_path}")

    print("\nSHA-256:")
    print(f"  {hash_result}")

    print("\nHash file:")
    print(f"  {hash_file}")

    print("\nThe image contains:")
    print("  - User documents")
    print("  - Bash history")
    print("  - Browser history")
    print("  - SSH configuration")
    print("  - Authentication logs")
    print("  - System logs")
    print("  - Network activity")
    print("  - Suspicious script")
    print("  - Investigation notes")
    print("  - Deleted files")
    print("  - Metadata/timestamps")

    print("\nIMPORTANT:")
    print("  Preserve this original image.")
    print("  Students should work from a verified copy.")
    print("  Do not modify the original evidence image.")

if __name__ == "__main__":
    main()