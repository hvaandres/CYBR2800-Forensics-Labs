# Instructor Guide — CYBR 2800 Digital Forensics Labs

Operational guide for running the "Hacking Thursdays" forensics lab series: how to build
the evidence images, what to hand students, how to pace class time, and what to validate
before students arrive.

**This file is safe to share with TAs and co-instructors.** It intentionally does not list
the deleted filenames, inode numbers, or the full indicator set. Those live in
`ANSWER_KEY.md` (gitignored — see *Answer keys* below).

---

## 1. Folder-to-lab mapping

The folders are numbered by **course week**. The handouts inside are numbered by
**position in the 3-lab sequence**. These do not match, and that is intentional — but it
confuses students who see both.

- `hacking-thursdays/lab02/` → handout **"Lab 1 of 3"** → builds `CYBR2800_Lab1_Evidence.dd`
- `hacking-thursdays/lab03/` → handout **"Lab 2 of 3"** → builds `CYBR2800_Lab2_Evidence.dd`
- `hacking-thursdays/lab04/` → handout **"Lab 3 of 3"** → builds `CYBR2800_Lab3_Evidence.dd`

Everything students touch (handout title, evidence filename, working directory) uses the
**sequence** number consistently. The week number never appears in student-facing material.

**Name your Canvas assignments with the sequence number** ("Forensics Lab 2"), not the
folder number, or students will file the wrong submission.

---

## 2. Build the master image

Build **once per semester, per lab**. Do not rebuild mid-semester.

Every run produces a new filesystem UUID and new file timestamps, so **every build has a
different SHA-256**. If you rebuild after publishing a hash, every student who already
downloaded the image will fail Part 2 integrity verification, and you will spend the lab
session debugging your own artifact.

### Requirements

Linux only, as root. The scripts use `mkfs.ext4`, `parted`, `losetup`, and loop mounting,
none of which exist on macOS. Run them **inside the Ubuntu VM**, never on your Mac.

```bash
sudo apt update
sudo apt install e2fsprogs coreutils parted util-linux sleuthkit
```

### Build

Each script writes to the current working directory, so `cd` to where you want the output.

```bash
mkdir -p ~/masters/lab03 && cd ~/masters/lab03
sudo python3 /path/to/hacking-thursdays/lab03/create_cybr2800_evidence.py
```

### Freeze the master immediately

```bash
chmod 444 CYBR2800_Lab2_Evidence.dd
sha256sum CYBR2800_Lab2_Evidence.dd | tee CYBR2800_Lab2_Evidence.dd.sha256
```

Keep this copy untouched for the whole semester. Everything you distribute is a duplicate.

---

## 3. Validate before class

**Do not skip this.** Each check below corresponds to a handout section that will fail
silently in front of students if the image is wrong — and by then you cannot fix it without
reissuing the image and invalidating the published hash.

Run every check against the master, in the VM, with The Sleuth Kit installed.

### 3.1 The partition table exists

```bash
mmls CYBR2800_Lab2_Evidence.dd
```

Expect a `DOS Partition Table` with one Linux partition and a non-zero start sector
(typically `2048`). If `mmls` errors or finds nothing, the `parted` step failed and Parts
5–15 of the handout are unusable, because every later command depends on that `-o` offset.

### 3.2 The filesystem is readable at that offset

```bash
fsstat -o 2048 CYBR2800_Lab2_Evidence.dd
fls -r -o 2048 CYBR2800_Lab2_Evidence.dd
```

You should see the full populated tree. Substitute your actual offset.

### 3.3 Deleted-file recovery actually returns data — CRITICAL

This is the check that matters most, and the one most likely to fail.

```bash
fls -r -d -o 2048 CYBR2800_Lab2_Evidence.dd
# note an inode number from the output, then:
icat -o 2048 CYBR2800_Lab2_Evidence.dd <INODE> | wc -c
```

**If that byte count is `0`, Part 10 is broken** and its 15 rubric points are
unearnable.

Why this happens: on **ext4**, deleting a file zeroes the extent tree stored in the inode.
The directory entry survives — so `fls -r -d` still shows the filename and students think
they have found something — but the pointers to the data blocks are gone, so `istat`
reports size 0 with no blocks and `icat` returns nothing. This is normal ext4 behavior, not
a bug in the script.

Three ways to resolve it, in order of effort:

1. **Format the partition ext2 instead of ext4.** Change `mkfs.ext4` to `mkfs.ext2` in the
   generator. ext2 does not zero block pointers on unlink, so `icat` recovery works cleanly.
   This is the classic teaching filesystem and the lowest-effort fix. Update the handout and
   manifest, which currently say ext4.
2. **Keep ext4 and rewrite Parts 8–10 as a carving exercise** using `blkls` to extract
   unallocated space, then `strings` / `foremost` / `photorec` against it. More realistic and
   more instructive, but a larger handout rewrite and harder for a first-time student.
3. **Do both** — ext2 for the guaranteed recovery win, carving as a stretch/bonus section.

Whichever you choose, re-run this check after changing the generator.

### 3.4 `tsk_recover` scope

Part 11 runs `tsk_recover` with no `-e` flag, which recovers **allocated files only**. That
is fine as written — Parts 12–14 grep the allocated tree. But if you want students to see
deleted files in that output too, the handout needs `tsk_recover -e`.

### 3.5 Timestamp consistency

```bash
istat -o 2048 CYBR2800_Lab2_Evidence.dd <INODE>
```

The log *contents* describe August 2026 activity, but the actual MAC times will be your
build date. Any student running `istat` or `mactime` sees the contradiction, and Lab 3 is
explicitly a timeline lab built on these timestamps.

Fix by adding a `touch -d` pass over the mounted tree before unmount, so filesystem
metadata matches the narrative in the logs. Until then, warn students that filesystem
timestamps reflect image creation, not the scenario.

---

## 4. What to distribute

Hand students exactly three things.

1. **The evidence image**, compressed. The image is 256 MB but mostly zeros, so it
   compresses to a few MB:
   ```bash
   gzip -9 -c CYBR2800_Lab2_Evidence.dd > CYBR2800_Lab2_Evidence.dd.gz
   ```
   Tell students to hash **after** decompressing — the `.gz` hash will not match.
2. **The SHA-256 string**, published in the Canvas assignment text — **not** bundled in the
   same archive as the image. If the hash ships inside the download, "verify integrity"
   is circular and teaches nothing about chain of custody.
3. **The handout** (`labNN.html`), pasted into Canvas. These are HTML fragments (a bare
   `<div>`), designed to drop straight into the Canvas rich-content editor.

### What NOT to distribute

- **`CYBR2800_*_manifest.txt`.** The generator writes this next to the image and it is
  effectively the answer key — it lists every deleted filename and every indicator IP and
  account. Handing it over converts "determine what happened" into a transcription task.
  Move it out of the distribution folder as soon as the build finishes.
- **`ANSWER_KEY.md`**, obviously.
- **The generator scripts.** They contain the entire evidence set as literal strings. Keep
  this repository private, or distribute handouts through Canvas only.
- Consider also removing the **`README.txt` written inside the image**, which telegraphs
  the nine investigation areas before students have looked at anything.

---

## 5. Pacing class time

The handouts are 20-part reference documents. They are good to read from and bad to run a
clock against. Group them into four checkpoints and gate on each one.

### Checkpoint 1 — Setup and integrity (~20 min) · Parts 1–3

Tools installed, hash verified, working copy created.

**Gate hard here.** Confirm every student produces the same SHA-256 before anyone
continues. A mismatch means a truncated or corrupted download, and you want that surfaced
at minute 20, not minute 90 when a student cannot explain why `mmls` fails.

### Checkpoint 2 — Image and filesystem structure (~40 min) · Parts 4–7

`img_stat` → `mmls` → record offset → `fsstat` → `fls -r`.

The `-o` offset is the single biggest stumbling block in the whole series. Have students
state their offset out loud or drop it in chat. Every subsequent command fails silently or
confusingly without it, and students rarely connect the failure back to the offset.

### Checkpoint 3 — Deleted files and recovery (~60 min) · Parts 8–11

`fls -r -d`, `istat`, `icat`, `tsk_recover`.

This is where §3.3 either pays off or bites you.

### Checkpoint 4 — Analysis and reporting (remainder / homework) · Parts 12–20

Artifact analysis, indicator searching, evidence table, screenshots, written findings.

This is the part worth the most points and the part students rush. Budget real time for it,
or assign it as homework with the lab session used for Checkpoints 1–3.

---

## 6. Grading guidance

### Withhold the conclusion

The scenario is deliberately ambiguous. Alex may be the analyst investigating an incident,
or the person who caused it — the evidence supports either reading. Do not resolve it.

Part 19 question 9 asks whether students can determine the activity was malicious.
**"No, not from this evidence alone" is a correct answer** and should score full marks when
the reasoning is sound. Grade the reasoning, not the verdict. The ambiguity is the lesson;
Lab 3's timeline work is where it resolves.

### Where students lose points

- Screenshots pasted with no caption or explanation. The handout requires written findings
  in text; the accessibility requirement is not decorative, and a screenshot-only report
  should not pass the documentation rubric item.
- Stating conclusions as fact ("Alex hacked the backup server") rather than as
  evidence-supported inference. The handout gives them the correct phrasing pattern —
  hold them to it.
- Evidence tables with fewer than five items, or items with no hash.
- Copying another student's `-o` offset. It happens to be identical across students since
  everyone gets the same image, so you cannot detect this from the value alone — but you
  can detect it when their `mmls` screenshot is missing or does not match their claim.

---

## 7. Answer keys

Per-lab answer keys are **not** committed. The root `.gitignore` excludes `ANSWER_KEY.md`
at any depth.

Create one per lab after your first build, since inode numbers are only knowable from the
actual image:

```bash
# in the lab folder, after building
nano hacking-thursdays/lab03/ANSWER_KEY.md
```

Record at minimum:

- The `mmls` partition start sector for this build
- The SHA-256 of the master
- The inode number of each deleted file, and the expected `fls -r -d` output
- The expected `icat` byte count per deleted file (your §3.3 result)
- The five-plus evidence items you will accept for the evidence table
- The indicator set (IPs, accounts, script names) with the file each one appears in

The generated `CYBR2800_*_manifest.txt` covers part of this and is a reasonable starting
point — but it has no inode numbers, no offset, and no grading thresholds, so it is not
sufficient on its own. Keep the manifest out of the student distribution regardless.

---

## 8. Troubleshooting during the lab

Symptoms you will actually see, and what they mean.

### Student's hash does not match

Almost always a bad transfer, not tampering. Have them check the byte size first:
`ls -l` against the size you published. A truncated download is the common case. If they
downloaded the `.gz`, confirm they hashed the **decompressed** `.dd`, not the archive.

If the size is right and the hash is still wrong, they opened or mounted the image
read-write at some point. Reissue a fresh copy.

### `mmls` says "Cannot determine partition type"

Either the image is truncated (see above) or they are pointing at the wrong file. Note
that a hash mismatch and this error usually appear together — fix the hash first.

### Every Sleuth Kit command returns nothing or errors

The `-o` offset is missing or wrong. This is the most common failure in the series by a
wide margin. Without `-o`, the tools read the partition table region as if it were a
filesystem and find nothing coherent. Have the student re-run `mmls` and read the Start
column for the Linux partition.

### `icat` produces an empty file

Expected on ext4 — see §3.3. If you have not applied one of the fixes there, this will
happen to every student simultaneously in Checkpoint 3. Have a fallback ready: either
pivot the class to `strings` against unallocated space, or accept the `fls -r -d` listing
plus `istat` metadata as the deliverable for that section and adjust the rubric.

### `tsk_recover` output tree looks incomplete

Without `-e` it recovers allocated files only, which is the documented behavior of the
handout as written. Not a bug. See §3.4.

### Student mounted the evidence image directly

They have modified it, and their working-copy hash no longer matches. This is a teachable
moment rather than a failure — have them document what happened, reissue a clean copy, and
credit the chain-of-custody reasoning. It is exactly the mistake the lab is designed to
prevent.

### Permission denied reading files in the recovered tree

The generator sets `700` on `home/alex` and `600` on `.bash_history` and `.ssh/config`.
After `tsk_recover`, those modes are preserved and the files are owned by whoever ran the
recovery. If a student ran it under `sudo`, they will need `sudo` to read the results too.

---

## 9. Repository hygiene

- `.gitignore` at the root excludes Python bytecode, generated `.dd` images and their
  hashes and manifests, generator scratch directories, and answer keys.
- **Never commit a `.dd`.** They are large, binary, and non-reproducible.
- Each lab folder's `README.md` documents that lab's generator and its outputs.
- Generator scripts must be run from the Ubuntu VM. Running them on macOS fails at
  `mkfs.ext4` at best; at worst a partially-written script touches `/mnt` and `/tmp` paths
  you did not intend to modify.
