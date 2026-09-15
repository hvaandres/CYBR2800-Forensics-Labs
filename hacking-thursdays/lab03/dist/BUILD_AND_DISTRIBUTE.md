# Lab 2 — Build & Distribute Runbook

This folder (`dist/`) holds the one artifact that's already safe to hand to
students as-is: `lab03.html`. Everything else — the evidence image — must be
built on an **Ubuntu VM**, not this Mac. `create_cybr2800_evidence.py` requires
root and Linux-only tools (`mkfs.ext4`, `parted`, `losetup`, loop mounting)
that don't exist on macOS, so it cannot be run or packaged from here.

Run the steps below on your Ubuntu VM, then bring the two resulting files
(image + hash) back to wherever you publish course material from.

## 1. Build the master image

```bash
sudo apt update
sudo apt install e2fsprogs coreutils parted util-linux sleuthkit

mkdir -p ~/masters/lab03 && cd ~/masters/lab03
sudo python3 /path/to/hacking-thursdays/lab03/create_cybr2800_evidence.py
```

This produces `CYBR2800_Lab2_Evidence.dd`, `CYBR2800_Lab2_Evidence.dd.sha256`,
and `CYBR2800_Lab2_Evidence_manifest.txt` in the current directory. The build
now writes ~230 files (vs. ~15 previously) because of the "second device
discovered" backup-drive content, so expect the `cp -a` step to take a little
longer — it's still a 256 MB image.

## 2. Freeze the master

```bash
chmod 444 CYBR2800_Lab2_Evidence.dd
sha256sum CYBR2800_Lab2_Evidence.dd
```

Keep this copy untouched for the whole semester — every rebuild produces a new
UUID/timestamps and therefore a new hash, which breaks Part 2 for any student
who already downloaded the old one.

## 3. Validate before publishing — do not skip

Run each check from `INSTRUCTOR_GUIDE.md` §3 against the master:

- **§3.1** `mmls` finds a DOS partition table with a non-zero start sector.
- **§3.2** `fsstat -o <offset>` and `fls -r -o <offset>` show the full tree —
  confirm `home/`, `mnt/recovered_backup/`, and `var/` all appear.
- **§3.3 — critical** `icat | wc -c` on a deleted-file inode from **both**
  `home/alex/Downloads/` and `mnt/recovered_backup/`. If either returns `0`,
  this build still has the known ext4-zeroing issue (see §3.3 for fixes) —
  Part 10 will not work for students until it's addressed.
- **§3.5** `istat` timestamps will reflect your build date, not the log
  narrative dates — expected, unless you've applied the `touch -d` fix.

## 4. What to actually distribute

Per `INSTRUCTOR_GUIDE.md` §4, hand students exactly three things:

1. **The compressed image**, published as a file download (not inside the
   same place as the hash):
   ```bash
   gzip -9 -c CYBR2800_Lab2_Evidence.dd > CYBR2800_Lab2_Evidence.dd.gz
   ```
   Tell students to decompress, then hash — the `.gz` hash won't match.
2. **The SHA-256 string**, pasted into the Canvas assignment text.
3. **`lab03.html`** (this folder), pasted into the Canvas rich-content editor.

### Do NOT distribute

- `CYBR2800_Lab2_Evidence_manifest.txt` — lists every deleted filename and
  indicator; it's the answer key.
- `create_cybr2800_evidence.py` — contains the entire evidence set as literal
  strings.
- Any `ANSWER_KEY.md` you create per §7 of the instructor guide.

## 5. After building: write the answer key

Per `INSTRUCTOR_GUIDE.md` §7, create `hacking-thursdays/lab03/ANSWER_KEY.md`
(gitignored) once you have a real image, recording inode numbers for all
**5** deleted files, the partition offset, and which daily backup log under
`archives/` carries each anomaly (2026-08-19 failed job, 2026-08-20 job
outside the maintenance window).
