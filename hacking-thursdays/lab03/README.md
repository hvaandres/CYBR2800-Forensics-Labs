# Lab 03 — Evidence Examination, Recovery, and Artifact Analysis

## Files

- `lab03.html` — the student lab handout (HTML fragment, ready to paste into Canvas).
- `create_cybr2800_evidence.py` — instructor script that generates the evidence image.

## `create_cybr2800_evidence.py`

**Description:** Enhanced version of the Lab 02 generator. Builds the same 256 MB ext4
forensic image (user documents, bash and browser history, SSH config, auth/system/network
logs, suspicious script, deleted files), and additionally performs pre-flight tool checks,
safe mount/unmount cleanup, realistic file permissions, an extra remote-access log, and
writes an evidence manifest. Like the Lab 02 image, the disk image has a real MBR
partition table with a single ext4 partition (not just a raw ext4 filesystem), so
`mmls` in Part 5 of the lab finds a real partition and start-sector offset for students
to use with `-o` in later Sleuth Kit commands.

**Objective:** Produce the verified evidence image students examine in Lab 2 — including
the hash and manifest they use to prove the evidence was not altered.

**Outputs** (written to the current working directory):

- `CYBR2800_Lab2_Evidence.dd`
- `CYBR2800_Lab2_Evidence.dd.sha256`
- `CYBR2800_Lab2_Evidence_manifest.txt`

## How to Run

> **Run this inside your Ubuntu VM — not on your local macOS machine.**
> The script uses `mkfs.ext4` and loop mounting, which do not exist on macOS. It also
> requires root and writes to `/mnt` and `/tmp`. Running it outside a VM will fail or
> touch system paths you don't want modified.

Run the script from the directory where you want the image written, since it outputs to
the current working directory:

```bash
sudo apt update
sudo apt install e2fsprogs coreutils parted util-linux

sudo python3 create_cybr2800_evidence.py
```

The script performs a pre-flight check (`check_tools()`) and will tell you exactly
which command-line tool is missing if one of these packages isn't installed, rather
than installing anything on your behalf.

The generated `.dd` file is the **master copy**. Keep it unmodified and give students a
duplicate along with the SHA-256 value from the manifest.
