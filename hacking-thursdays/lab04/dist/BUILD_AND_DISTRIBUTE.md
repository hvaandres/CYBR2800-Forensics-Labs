# Lab 3 of 3 ("The Tobor Transfer") — Build & Distribute Runbook

Case CYBR-2026-0042. This folder is `hacking-thursdays/lab04/dist/`. The folder is numbered
by course week; the student-facing material is titled **Lab 3** and uses `CYBR2800_Lab3_*`
filenames throughout.

| File | Audience | Purpose |
| --- | --- | --- |
| `lab04.html` | **Students** | The handout. Paste into the Canvas rich-content editor. |
| `validate_lab4_image.sh` | **Instructor / TA only** | 40 automated pre-class checks against the built image. |
| `BUILD_AND_DISTRIBUTE.md` | **Instructor / TA only** | This runbook. |

The generator itself (`../cybr2800_forensic_evidence_lab4.py`) is **instructor-only** and is
not in this folder. It contains the entire evidence set as literal strings. See
*Instructor kit* below if a TA needs to build the image.

> **Everything below runs on an Ubuntu VM.** The generator needs root and Linux-only tools
> (`parted`, `losetup`, `mkfs.ext2`, `debugfs`, loop mounts). Tested on Ubuntu 24.04.

## 0. Keep the handout copy in sync

`lab04.html` here is a copy of `../lab04.html`. If you edit one, copy it to the other:

```bash
cp ../lab04.html lab04.html
```

## 1. Build the master image

```bash
sudo apt update
sudo apt install e2fsprogs coreutils parted util-linux sleuthkit unzip file python3

mkdir -p ~/masters/lab04 && cd ~/masters/lab04
sudo python3 /path/to/hacking-thursdays/lab04/cybr2800_forensic_evidence_lab4.py
```

Produces, in the current directory:

- `CYBR2800_Lab3_Evidence.dd` — 512 MB, MBR partition table, ext2
- `CYBR2800_Lab3_Evidence.dd.sha256`
- `CYBR2800_Lab3_Evidence_manifest.txt` — **the answer key**

Build **once per semester.** Every build gets a new filesystem UUID and new inode timestamps,
so every build has a different SHA-256. Rebuilding after you publish a hash breaks the
integrity step for every student who already downloaded the image.

If the build fails partway, re-run it. The script detaches stale loop devices on startup.

## 2. Validate before publishing — do not skip

```bash
./validate_lab4_image.sh ~/masters/lab04/CYBR2800_Lab3_Evidence.dd
```

Expect `40 passed, 0 failed` and an exit code of 0. The script is read-only. It checks, among
other things:

- **Partition and tree:** `mmls` finds a Linux partition at sector 2048; `home/`, `mnt/`,
  `var/log/finance_api/` and the rest all appear.
- **Deleted-file recovery — the critical one.** All 11 deleted files list under `fls -r -d`
  *and* `icat` returns real bytes for each, including the multi-block `.xlsx` and `.tar.gz`
  files. If any returns 0 bytes, Parts 11–14 (about 22 rubric points) are unearnable.
- **Genuine binary evidence:** the recovered workbook is a valid ZIP, `grep` finds nothing in
  it, and its row sum matches the recovered manifest to the cent.
- **The attribution pivot:** one MAC holds both `10.10.20.55` and `10.10.20.77`, `known_hosts`
  records one key for both, and the laptop is absent from the asset inventory.
- **Traps and continuity:** the 800-byte USB red herring, the unreviewed DLP alerts, the
  timestomped script, the Lab 2 brute-force and backup lines, and incident-day transfer volume
  agreeing across two independent logs.
- **Scenario mtimes survive deletion** (proves files were deleted offline, not through the mount).

A non-zero exit means **do not publish**. The most likely cause is someone changing
`delete_evidence_offline()` back to `Path.unlink()`. Deleting through a mounted filesystem zeroes
the inode's size and block pointers on ext2 and ext4 alike. See `INSTRUCTOR_GUIDE.md` §3.3.

## 3. Freeze the master

```bash
chmod 444 CYBR2800_Lab3_Evidence.dd
sha256sum CYBR2800_Lab3_Evidence.dd
```

Keep this copy untouched for the whole semester. Everything you distribute is a duplicate.

## 4. What to distribute

Hand students exactly three things:

1. **The compressed image**, as a file download:
   ```bash
   gzip -9 -c CYBR2800_Lab3_Evidence.dd > CYBR2800_Lab3_Evidence.dd.gz
   ```
   Tell students to **decompress first, then hash** — the `.gz` hash will not match.
2. **The SHA-256 string**, pasted into the Canvas assignment text. Do **not** put it in the
   same archive as the image; that makes integrity verification circular.
3. **`lab04.html`**, pasted into the Canvas rich-content editor.

Name the Canvas assignment **"Forensics Lab 3"** (the sequence number), not "Lab 4".

### Do NOT distribute

- `CYBR2800_Lab3_Evidence_manifest.txt` — every deleted path, every indicator, the exact dollar
  totals, and the traps.
- `cybr2800_forensic_evidence_lab4.py` — the whole evidence set as literal strings.
- `validate_lab4_image.sh` — its checks spell out the answers.
- This runbook, the `lab04/README.md` scenario section, and any `ANSWER_KEY.md`.

## 5. After building: write the answer key

Create `hacking-thursdays/lab04/ANSWER_KEY.md` (gitignored). The validator prints most of what
you need; record at least:

- The partition start sector (expected `2048`) and the master's SHA-256.
- The inode number of each of the **11** deleted files, plus the deleted `.cache_sync`
  directory. Inode numbers are specific to your build.
- The grand totals from the manifest: 17,830 rows and the dollar figure, plus the per-file rows
  and totals students must reproduce.
- The incident-day transfer volume: 4 runs, 346 files, 1,000,452,077 bytes.
- The attribution evidence: `dhcpd.log`, `known_hosts`, `etc/hosts`, and the MAC
  `b4:2e:99:0c:17:aa`.
- The traps: USB (800 bytes), `priya` as the legitimate control, the timestomped
  `tobor_sync.sh`, and the unidentified "Kestrel."
- The two phantom `^` entries (inode 2049) that are slack artifacts, not deleted files.

Grading guidance is in `INSTRUCTOR_GUIDE.md` §6. For this lab specifically: **full marks for
correctly marking something Unsupported.** The handout requires at least one row of the case
status board to be Unsupported (who "Kestrel" is, whether money changed hands). A student who
says the evidence does not establish the other party's identity is right.

## 6. Instructor kit (optional, for a TA)

To hand a TA everything needed to rebuild and validate, without the student material:

```bash
./make_instructor_kit.sh
```

This writes `cybr2800_lab4_instructor_kit.tar.gz` and its `.sha256` next to the script. It
contains the generator, the validator, and this runbook. It is gitignored and **must not be
shared with students.**

## Troubleshooting the build

- **`The file /dev/loopNp1 does not exist`** — fixed in the current script (it waits for the
  partition node). If you see it on an old copy, update the script.
- **`debugfs reported problems deleting evidence`** — a path in `DELETED_FILES` does not exist
  in the tree. The script fails loudly rather than shipping an image missing a deleted file.
- **Stale loop devices after a crash** — `sudo losetup -a`, then `sudo losetup -d /dev/loopN`.
  The script also does this itself on the next run.
- **Validator reports `offset is N, docs say 2048`** — the partition layout changed; update the
  answer key and the docs.
