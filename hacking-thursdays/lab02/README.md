# Lab 02 — Evidence Acquisition and Preservation

## Files

- `lab02.html` — the student lab handout (HTML fragment, ready to paste into Canvas).
- `cybr2800_forensic_evidence.py` — instructor script that generates the evidence image.

## `cybr2800_forensic_evidence.py`

**Description:** Builds a 256 MB ext4 forensic disk image containing a simulated Linux
workstation — user documents, bash history, browser history, SSH config, auth/system/network
logs, and a suspicious maintenance script. Three files in `home/alex/Downloads/` are deleted
after being written so students can practice deleted-file recovery.

**Objective:** Produce the controlled, repeatable master evidence disk (plus its SHA-256
hash) that the instructor stages as the approved evidence source for Lab 1. Students image
this source themselves during the handout's acquisition steps (Parts 4–5), then analyze the
transferred copy for the rest of the lab.

**Outputs** (written to the current working directory):

- `CYBR2800_Lab1_Evidence.dd`
- `CYBR2800_Lab1_Evidence.dd.sha256`

## How to Run

> **Run this inside your Ubuntu VM — not on your local macOS machine.**
> The script uses `mkfs.ext4` and loop mounting, which do not exist on macOS. It also
> requires root and writes to `/mnt` and `/tmp`. Running it outside a VM will fail or
> touch system paths you don't want modified.

Run the script from the directory where you want the image written, since it outputs to
the current working directory:

```bash
sudo apt update
sudo apt install e2fsprogs coreutils

sudo python3 cybr2800_forensic_evidence.py
```

The generated `.dd` file is the **master copy**. Keep it unmodified and give students a
duplicate along with the SHA-256 value.
