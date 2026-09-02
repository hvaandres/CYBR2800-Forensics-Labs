# Lab 04 — Timeline Analysis, Incident Reconstruction & Forensic Reporting

## Files

- `lab04.html` — the student lab handout (HTML fragment, ready to paste into Canvas).
- `cybr2800_forensic_evidence_lab3.py` — instructor script that generates the evidence image.

## `cybr2800_forensic_evidence_lab3.py`

**Description:** Builds the 256 MB ext4 forensic image used in Lab 3 — user documents,
bash and browser history, SSH config, auth/system/network/remote-access/application/
maintenance logs, a maintenance script, and several deleted files for recovery.
The script performs pre-flight tool checks, safe mount/unmount handling, realistic
file permissions, and writes an evidence manifest documenting the scenario and
intentionally deleted files.

**Objective:** Produce the verified evidence image students examine in Lab 3 —
including the hash and manifest they use to prove the evidence was not altered
before building a timeline and reconstructing the incident.

**Outputs** (written to the current working directory):

- `CYBR2800_Lab3_Evidence.dd`
- `CYBR2800_Lab3_Evidence.dd.sha256`
- `CYBR2800_Lab3_Evidence_manifest.txt`

## How to Run

> **Run this inside your Ubuntu VM — not on your local macOS machine.**
> The script uses `mkfs.ext4` and loop mounting, which do not exist on macOS. It also
> requires root and writes to `/mnt` and the current working directory. Running it
> outside a VM will fail or touch system paths you don't want modified.

Run the script from the directory where you want the image written, since it outputs to
the current working directory:

```bash
sudo apt update
sudo apt install e2fsprogs coreutils

sudo python3 cybr2800_forensic_evidence_lab3.py
```

The generated `.dd` file is the **master copy**. Keep it unmodified and give students a
duplicate along with the SHA-256 value from the manifest.
