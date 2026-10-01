# Lab 04 — Timeline Analysis, Incident Reconstruction & Forensic Reporting

Case **CYBR-2026-0042 — "The Tobor Transfer."** The capstone of the three-lab sequence,
and the lab where the ambiguity Lab 2 deliberately left open gets resolved.

## Files

- `lab04.html` — the student lab handout (HTML fragment, ready to paste into Canvas).
- `cybr2800_forensic_evidence_lab4.py` — instructor script that generates the evidence image.

> **Numbering:** this folder is `lab04` (course week), but the handout inside is titled
> **Lab 3 of 3** and its evidence image is `CYBR2800_Lab3_Evidence.dd`. See the root
> `INSTRUCTOR_GUIDE.md` for the full folder-to-lab mapping.

---

## The scenario

> **Spoiler — instructor only.** Do not paste this section into Canvas.

Over roughly six months, `alex` enumerated an internal finance reporting API, found a
never-rotated service token in a world-readable scheduler config, used it to bulk-pull
bank reconciliations and a wire-transfer ledger, staged them in a hidden directory, and
rsynced them to `tobor.rm` — an unmanaged personal laptop attached to the corporate VLAN.
Messaging history shows coordination with an unidentified outside contact. Afterwards the
staging directory, the chat export, a rotated API log, the crontab, and the shell history
were all destroyed.

**The payoff that makes this feel like a sequel:** the DHCP log proves `10.10.20.55` — the
unattributed SSH brute-force source students saw in Lab 2 and could not explain — and
`10.10.20.77`, the exfiltration destination, are two leases issued to the same MAC address
(`b4:2e:99:0c:17:aa`, hostname `TOBOR-RM`). The lease flips at 13:12:48 on the incident
day, after the morning brute force and before the afternoon transfer. No single artifact
says so; students have to correlate `var/log/dhcpd.log`, `home/alex/.ssh/known_hosts` (same
host key recorded for both addresses), and `etc/hosts` (a manual entry for a host absent
from `etc/asset_inventory.csv`).

Everything from Lab 2 still holds — `alex`, `backupadmin`, `jordan`, `backup01`
(`10.10.20.25`), `app01` (`10.10.20.15`), the 2026-08-19 failed backup job and the
2026-08-20 out-of-window one. The Lab 2 backup drive is reproduced at
`mnt/recovered_backup/` so students can re-examine their earlier findings.

### Deliberate traps

1. **The USB red herring.** A SanDisk drive really was attached on the incident day, but
   only **800 bytes** were written to it. Students who name USB as the exfiltration channel
   have not quantified anything. The handout rubric docks this explicitly.
2. **The control group.** `priya` is a finance analyst who legitimately touched financial
   data every working day. Access to financial data is not itself incriminating; the
   distinguishing features are the service-token reuse, the `python-requests` agent, the
   403-then-200 progression, and the destination.
3. **The timestomp.** `home/alex/.local/bin/tobor_sync.sh` has an mtime of 2025-01-05,
   predating the system it talks to. mtime and ctime disagree. This is the concrete example
   for the handout's timestamp-reliability section.
4. **"Kestrel" is never identified.** The correct answer to "who received the data" is that
   the evidence does not establish it. Full marks for saying so.

---

## `cybr2800_forensic_evidence_lab4.py`

Builds a **512 MB ext2** forensic image with an MBR partition table (single primary
partition, start sector 2048), containing roughly 400 files.

**Contents:** Alex's workstation (documents, live *and rotated* shell history, browser
history, SSH config and `known_hosts`, the sync script and its run log, WhatsApp/Telegram/
Signal artifacts); `priya` and `jordan` home directories; a classified finance share with
monthly `.xlsx` reports and ~96 per-client statement CSVs; the Lab 2 backup drive with its
~200 daily job logs; and fifteen logs under `var/log` including `dhcpd.log`, `vpn.log`,
`dlp_alerts.log`, `usb_events.log`, `audit/file_access.log`, and the finance API access and
error logs.

**Real spreadsheets.** The script writes valid OOXML `.xlsx` packages by hand using only
`zipfile` from the standard library — no `openpyxl`, no pip dependencies. Each workbook
holds thousands of generated transaction rows with bank partners, masked account numbers,
dollar amounts, and a computed `GRAND TOTAL` row. Because the packages are
DEFLATE-compressed, `grep` and `strings` find nothing in them, which is exactly the point
of the handout's Part 13.

**Eleven deleted files across five directories**, plus the deleted `.cache_sync` directory
itself, spanning text, CSV, compressed spreadsheets, and a `.tar.gz` — so `fls -r -d` is a
real search and `strings` alone is not enough. Expect two extra `^` entries (inode 2049,
0 bytes) under `bank_statements/` and `archives/`: directory-slack artifacts, not deleted
files. The handout tells students to rule them out rather than count them.

### Two design decisions worth knowing about

**1. Evidence is deleted offline with `debugfs`, not through the mount.**

This resolves the problem flagged in `INSTRUCTOR_GUIDE.md` §3.3, and it corrects a wrong
assumption an earlier revision of this lab made. Deleting a file through a *mounted* Linux
filesystem zeroes the inode's size and block pointers and overwrites mtime/ctime — on ext2
exactly as on ext4. `fls -r -d` still lists the filename, so students think they have found
something, but `icat` returns zero bytes and every recovery point in the lab is unearnable.

The generator therefore unmounts the image and runs `debugfs -w` (`rm` and `rmdir`), which
frees the inode and blocks but leaves the size, block pointers, and scenario mtime intact.
This was validated on Ubuntu 24.04: all 11 files recover with real bytes, the recovered
workbook sums to the dollar figure in the recovered manifest, and the deleted directory is
traversable. ext2 is used for simplicity (no journal); the method also works on ext4.

**Do not change `delete_evidence_offline()` back to `Path.unlink()`. It silently breaks
Parts 11–14.**

**2. Filesystem timestamps are set to match the scenario.**

This resolves `INSTRUCTOR_GUIDE.md` §3.5. A timeline lab whose MAC times all read "the day
the instructor built the image" teaches nothing. After the tree is populated, an `os.utime`
pass rewrites atime and mtime to the narrative dates, so `fls -m` piped into `mactime`
produces a timeline that matches the logs.

ctime and the deletion time (dtime) are not settable from userspace and still reflect build
time, and ext2 records no creation time at all. That is deliberate — the handout asks
students to notice it and disclose it as a limitation, which is itself the lesson about
never trusting a single timestamp.

**Outputs** (written to the current working directory):

- `CYBR2800_Lab3_Evidence.dd`
- `CYBR2800_Lab3_Evidence.dd.sha256`
- `CYBR2800_Lab3_Evidence_manifest.txt` — **effectively an answer key.** It lists every
  deleted path, the full indicator set, the exact dollar totals, and all four traps. Move it
  out of the distribution folder as soon as the build finishes.

---

## How to Run

> **Run this inside your Ubuntu VM — not on your local macOS machine.**
> The script uses `parted`, `losetup`, `mkfs.ext2`, and loop mounting, none of which exist
> on macOS. It requires root and writes to `/mnt`, `/tmp`, and the current working directory.

Run it from the directory where you want the image written:

```bash
sudo apt update
sudo apt install e2fsprogs coreutils parted util-linux sleuthkit

sudo python3 cybr2800_forensic_evidence_lab4.py
```

Build **once per semester**. Every run produces a new filesystem UUID, so every build has a
different SHA-256. Rebuilding after you publish a hash will fail integrity verification for
every student who already downloaded the image.

---

## Validate before class

The fast way is the automated validator in `dist/`, which runs 40 read-only checks and exits
0 only if the image is ready to publish:

```bash
sudo apt install sleuthkit unzip file python3
./dist/validate_lab4_image.sh CYBR2800_Lab3_Evidence.dd
```

See `dist/BUILD_AND_DISTRIBUTE.md` for the full build, publish, and answer-key runbook, and
`dist/make_instructor_kit.sh` to package the generator for a TA.

The manual equivalent follows. The generator prints these steps when it finishes. Do not
skip the third one.

```bash
# 1. Freeze the master
chmod 444 CYBR2800_Lab3_Evidence.dd

# 2. Partition table is readable (the handout requires an mmls screenshot)
mmls CYBR2800_Lab3_Evidence.dd

# 3. CRITICAL — deleted-file recovery actually returns data
fls -r -d -o 2048 CYBR2800_Lab3_Evidence.dd
icat -o 2048 CYBR2800_Lab3_Evidence.dd <INODE> | wc -c
```

A zero byte count in step 3 means Parts 11–14 are broken and roughly 22 rubric points are
unearnable. Test at least one deleted `.xlsx` and one deleted text file.

Also confirm the recovered workbook actually opens:

```bash
icat -o 2048 CYBR2800_Lab3_Evidence.dd <INODE> > /tmp/recovered.xlsx
file /tmp/recovered.xlsx          # expect: Microsoft Excel 2007+ / Zip archive
unzip -l /tmp/recovered.xlsx      # expect: xl/worksheets/sheet1.xml
```

And confirm the attribution pivot survived:

```bash
fls -r -o 2048 CYBR2800_Lab3_Evidence.dd | grep dhcpd
icat -o 2048 CYBR2800_Lab3_Evidence.dd <INODE> | grep -c "b4:2e:99:0c:17:aa"
```

---

## What to distribute

1. The `.dd` image, gzipped. Tell students to hash **after** decompressing.
2. The SHA-256 string, published in the Canvas assignment text — **not** inside the archive.
3. `lab04.html`, pasted into the Canvas rich-content editor.

Withhold the manifest, this README's scenario section, the generator script, and
`ANSWER_KEY.md`.
