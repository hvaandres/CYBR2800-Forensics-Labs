# Lab 02 — Evidence Acquisition and Preservation

## Files

- `lab02.html` — the student lab handout (HTML fragment, ready to paste into Canvas).
- `cybr2800_forensic_evidence.py` — instructor script that generates the evidence image.

> **Numbering:** this folder is `lab02` (course week), but the handout inside is titled
> **Lab 1 of 3** and its evidence image is `CYBR2800_Lab1_Evidence.dd`. See the root
> `INSTRUCTOR_GUIDE.md` for the full folder-to-lab mapping.

## `cybr2800_forensic_evidence.py`

**Description:** Builds a 256 MB forensic disk image containing a simulated Linux
workstation — user documents, bash history, browser history, SSH config, auth/system/network
logs, and a suspicious maintenance script. Three files in `home/alex/Downloads/` are deleted
after being written so students can practice deleted-file recovery.

The image now has a real **MBR (msdos) partition table with a single primary ext4
partition**, instead of an ext4 filesystem written directly to the raw image with no
partition table. This was a required fix: the handout's Part 8 has students run `mmls`
and record a partition scheme/start sector, then pass that offset to `fsstat`/`fls`/`icat`
via `-o`. Without a real partition table, `mmls` had nothing to find and that whole section
of the lab (and its 10-point rubric item) couldn't be completed.

**Objective:** Produce the controlled, repeatable master evidence disk (plus its SHA-256
hash) that the instructor stages as the approved evidence source for Lab 1. Students image
this source themselves during the handout's acquisition steps (Parts 4–5), then analyze the
transferred copy for the rest of the lab.

**Outputs** (written to the current working directory):

- `CYBR2800_Lab1_Evidence.dd` — now contains a partition table + ext4 partition (previously
  a bare ext4 filesystem with no partition table).
- `CYBR2800_Lab1_Evidence.dd.sha256`

### What changed and why

- **Partitioning added.** The script now runs `parted` to create an `msdos` label and a
  single primary partition starting at `1MiB`, then attaches the image with
  `losetup -P` so the partition appears as its own device node (`<loop>p1`). `mkfs.ext4`
  and the evidence copy now target that partition device, not the raw image file.
  This makes `mmls` report a real partition scheme/offset and makes the handout's
  `-o YOUR_OFFSET` instructions meaningful.
- **Mount/unmount and loop-device cleanup are now wrapped in `try`/`finally`** so the
  partition is unmounted and the loop device is detached even if a step in between fails.
- **New `--write-to-device DEVICE` option** clones the finished master image onto a real
  block device (e.g. a USB drive), so it can be handed to a student as a physical evidence
  source for the macOS `diskutil`/`dc3dd` acquisition steps in Part 4–5. Previously the
  script only produced a loose `.dd` file with no defined hand-off mechanism to a real
  device. This step:
  - Refuses to run unless the target path is an actual block device.
  - Checks the target device is large enough to hold the master image.
  - Prompts for a typed `YES` confirmation before writing (skip with `--yes`), since it
    erases the entire target device.
  - Unmounts any partitions already mounted from that device before writing.
- **New required tools:** `parted` and `losetup` are now required always; `blockdev` and
  `lsblk` are required only when `--write-to-device` is used.

## How to Run

> **Run this inside your Ubuntu VM — not on your local macOS machine.**
> The script uses `parted`, `losetup`, `mkfs.ext4`, and mounting, none of which exist on
> macOS. It also requires root and writes to `/mnt` and `/tmp`. Running it outside a VM
> will fail or touch system paths you don't want modified.

Run the script from the directory where you want the image written, since it outputs to
the current working directory:

```bash
sudo apt update
sudo apt install e2fsprogs coreutils parted util-linux

sudo python3 cybr2800_forensic_evidence.py
```

The generated `.dd` file is the **master copy**. Keep it unmodified and give students a
duplicate along with the SHA-256 value.

To clone the master image directly onto a USB drive for a student (identify the correct
device first with `lsblk`; this **erases** the target device):

```bash
sudo python3 cybr2800_forensic_evidence.py --write-to-device /dev/sdX
```

Add `--yes` to skip the interactive confirmation prompt (e.g. for scripted, repeated runs
when preparing multiple USB drives).
