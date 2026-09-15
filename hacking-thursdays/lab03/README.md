# Lab 03 — Evidence Examination, Recovery, and Artifact Analysis

## Files

- `lab03.html` — the student lab handout (HTML fragment, ready to paste into Canvas).
- `create_cybr2800_evidence.py` — instructor script that generates the evidence image.

> **Numbering:** this folder is `lab03` (course week), but the handout inside is titled
> **Lab 2 of 3** and its evidence image is `CYBR2800_Lab2_Evidence.dd`. See the root
> `INSTRUCTOR_GUIDE.md` for the full folder-to-lab mapping.

## `create_cybr2800_evidence.py`

**Description:** Enhanced version of the Lab 02 generator. Builds the same 256 MB ext4
forensic image (user documents, bash and browser history, SSH config, auth/system/network
logs, suspicious script, deleted files), and additionally performs pre-flight tool checks,
safe mount/unmount cleanup, realistic file permissions, an extra remote-access log, and
writes an evidence manifest. Like the Lab 02 image, the disk image has a real MBR
partition table with a single ext4 partition (not just a raw ext4 filesystem), so
`mmls` in Part 5 of the lab finds a real partition and start-sector offset for students
to use with `-o` in later Sleuth Kit commands.

**Scenario / continuity with Lab 1:** this build adds a "second device discovered"
narrative on top of the original scenario. After Lab 1 concludes, a backup drive used by
the `backupadmin` service account is located and imaged. Its contents are merged into
this evidence file under `mnt/recovered_backup/`, alongside the original workstation data
under `home/alex/`. This is what `lab03.html`'s Lab Purpose/Scenario sections now
reference, and it is the reason this image is substantially larger than Lab 1's:

- `mnt/recovered_backup/` contains `backupadmin`'s own home directory, notes, scripts, and
  **~200 daily backup job logs** (`archives/backup_log_YYYY-MM-DD.txt`, 2026-02-01 through
  2026-08-20) — the main source of the extra file volume.
- `home/alex/` logs (`auth.log`, `syslog`, `network_connections.log`) and `.bash_history`
  are all expanded to multiple weeks of routine activity, with the original Lab 2
  indicators preserved verbatim inside the larger body of filler.
- A second, unrelated user (`home/jordan/`) is included as noise/red herring.
- 5 deleted files total (up from 3): the original three under `home/alex/Downloads/`,
  plus `mnt/recovered_backup/home/backupadmin/Documents/credentials_rotation.txt` and
  `mnt/recovered_backup/archives/backup_log_2026-08-19.txt` (a failed job log that ties
  into `backupadmin`'s own recovered `.bash_history`).

All filenames, paths, and keywords referenced by `lab03.html` and by `lab04.html` (the
Lab 3 timeline lab) are preserved unchanged, so both handouts still work against this
expanded image without modification beyond what's already in `lab03.html`.

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

> **If you already built a master image with an earlier version of this script**, rebuild
> it. This update changed the evidence content materially (not just a routine re-run), so
> an old image will not match `lab03.html`'s current scenario text or the larger file/log
> volume it describes. Publish the new SHA-256 and discard the old one.
