# CYBR 2800 – Digital Forensics Labs

Course materials for the "Hacking Thursdays" digital forensics lab series. Each lab
combines an HTML lab handout (the student instructions) with a Python generator script
that the instructor runs to build the forensic disk image students analyze.

All labs use free, open-source, command-line tools (mainly **The Sleuth Kit**) on an
Ubuntu analysis VM. Nothing here attacks real systems — the evidence is synthetic and
built locally.

> **Running this course?** Read **[`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md)** first. It
> covers building and freezing the master images, the pre-class validation checks, what to
> distribute versus withhold, class pacing, grading guidance, and troubleshooting.

## Repository Layout

```
CYBR2800-Forensics-Labs/
├── README.md
├── INSTRUCTOR_GUIDE.md
└── hacking-thursdays/
    ├── lab02/
    │   ├── README.md
    │   ├── lab02.html
    │   └── cybr2800_forensic_evidence.py
    ├── lab03/
    │   ├── README.md
    │   ├── lab03.html
    │   └── create_cybr2800_evidence.py
    └── lab04/
        ├── README.md
        ├── lab04.html
        └── cybr2800_forensic_evidence_lab4.py
```

Each lab folder has its own `README.md` explaining what that lab's Python script does and
how to run it.

> **Note on numbering:** the folders are numbered by course week, but the handouts inside
> are numbered by position in the 3-lab sequence:
>
> - `lab02/` → handout **Lab 1 of 3** → `CYBR2800_Lab1_Evidence.dd`
> - `lab03/` → handout **Lab 2 of 3** → `CYBR2800_Lab2_Evidence.dd`
> - `lab04/` → handout **Lab 3 of 3** → `CYBR2800_Lab3_Evidence.dd`
>
> Student-facing material uses the sequence number consistently; the week number never
> appears in it.

---

## `hacking-thursdays/lab02` — Evidence Acquisition and Preservation

**What students do:** act as a junior forensic analyst who must acquire a disk image,
prove it was not altered, and perform a first pass of analysis. Roughly 3–5 hours, 100 points.

Covered in 20 parts: building an Ubuntu forensic workstation, installing and version-logging
the tools, hashing with SHA-256, acquiring the image with `dc3dd`, transferring it and
re-verifying the hash, then examining it with `img_stat`, `mmls`, `fsstat`, `fls`, `istat`,
`icat`, `tsk_recover`, and `mactime`. Ends with deleted-file recovery, a file timeline,
keyword searching, a chain-of-custody record, investigation questions, and a written
forensic report.

**Files**

- `lab02.html` — the student handout. It is an HTML fragment (a `<div>`, not a full page),
  styled inline so it can be pasted directly into an LMS such as Canvas. Contains the
  scenario, safety/evidence rules, tool tables, step-by-step commands, required screenshots,
  submission structure, and grading breakdown.
- `cybr2800_forensic_evidence.py` — instructor script that builds the master evidence disk
  staged for Lab 1's acquisition steps. Requires Linux + root, run inside the Ubuntu VM. It
  creates a 256 MB raw `.dd` file, formats it ext4, mounts it, populates a fake user system
  (documents, `.bash_history`, browser history, SSH config, `auth.log`, `syslog`, network
  logs, a suspicious `maintenance.sh`), then deletes three files from `home/alex/Downloads/`
  so students have something to recover. Outputs `CYBR2800_Lab1_Evidence.dd`. See
  `hacking-thursdays/lab02/README.md` for run instructions.

---

## `hacking-thursdays/lab03` — Evidence Examination, Recovery, and Artifact Analysis

**What students do:** continue the same investigation, working only from a verified working
copy of the image. Roughly 3–5 hours, 100 points.

Covered in 20 parts: verifying the instructor's hash, cloning the image to a working copy,
mapping partitions and the file system, listing deleted entries with `fls -r -d`, inspecting
metadata with `istat`, recovering a single file with `icat` and everything with `tsk_recover`,
analyzing user artifacts (bash history, browser history, SSH config, auth logs), reviewing
the suspicious script, grepping for indicators (IPs, `backupadmin`, credentials), and
producing investigation notes, an evidence table, screenshots, and preliminary findings.

**Files**

- `lab03.html` — the student handout, same fragment-style HTML as Lab 1 but without inline
  styling. Includes the scenario around the user "Alex", the tool table, all command steps,
  the required submission structure, a checklist, and the grading rubric.
- `create_cybr2800_evidence.py` — a more complete rewrite of the Lab 02 generator. Same
  requirements (Linux, root, run inside the Ubuntu VM) and the same 256 MB ext4 approach,
  but it adds pre-flight tool checks, safe unmount/cleanup handling, realistic file
  permissions, an extra `remote_access.log`, and a written evidence manifest. Outputs
  `CYBR2800_Lab2_Evidence.dd`. See `hacking-thursdays/lab03/README.md` for run instructions.

---

## `hacking-thursdays/lab04` — Timeline Analysis, Incident Reconstruction & Reporting

**What students do:** stop hunting individual files and reconstruct the incident — what
happened, when, how, and what evidence supports it. Roughly 4–6 hours, 100 points.

Builds a forensic timeline from filesystem metadata, correlates it against system and
application logs, identifies suspicious user activity, reconstructs the sequence of events,
and produces a professional forensic report. This is where the ambiguity deliberately left
open in Lab 2 gets resolved through correlation rather than assumption.

**Files**

- `lab04.html` — the student handout, fragment-style HTML with inline styling. Includes the
  timeline methodology, correlation steps, reporting structure, and grading rubric.
- `cybr2800_forensic_evidence_lab4.py` — instructor script that builds the Lab 3 evidence
  image. Same requirements (Linux, root, run inside the Ubuntu VM). Adds
  remote-access, application, and maintenance logs on top of the Lab 2 artifact set, plus
  several deleted files and an evidence manifest. Outputs `CYBR2800_Lab3_Evidence.dd`. See
  `hacking-thursdays/lab04/README.md` for run instructions.

---

## Using the Generator Scripts

**All three scripts must run inside the Ubuntu VM, not on macOS.** They are Linux-only (they
use `mkfs.ext4` and loop mounts), require root, and write to `/mnt` and `/tmp`. Each writes
its `.dd` image to the current working directory, so run it from the folder where you want
the image to land.

```bash
sudo apt update
sudo apt install e2fsprogs coreutils

# from the lab folder you want to build
sudo python3 <generator_script>.py
```

The generated `.dd` file is the **master copy**. Distribute a duplicate to students along
with the SHA-256 value, and keep the master unmodified.

## The Scenario in the Evidence

> **Spoiler — instructor reference only.** Do not paste this section into Canvas or share
> it with students; it gives away the indicators they are meant to discover.

Every image tells the same story so the labs build on each other:

- User `alex` on a workstation at `10.10.20.10`.
- Repeated failed SSH logins for `root`/`admin` from `10.10.20.55`.
- A `backupadmin` session to the backup server `10.10.20.25`, outside the maintenance window.
- A `maintenance.sh` script that downloads and chmods a remote `update.sh`.
- Three deleted files in `home/alex/Downloads/` (temporary credentials, backup notes,
  suspicious commands) that students must recover.
