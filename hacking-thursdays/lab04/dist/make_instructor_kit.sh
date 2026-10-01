#!/usr/bin/env bash
#
# make_instructor_kit.sh -- package the Lab 3 generator for instructors / TAs.
#
# Produces, next to this script:
#     cybr2800_lab4_instructor_kit.tar.gz
#     cybr2800_lab4_instructor_kit.tar.gz.sha256
#
# The kit contains the evidence generator (which holds the entire answer set
# as literal strings), the validator, and the runbook. INSTRUCTOR ONLY -- never
# give it to students. Runs on Linux or macOS; building the *image* needs Ubuntu.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(dirname "$HERE")"
KIT="cybr2800_lab4_instructor_kit"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

GENERATOR="$LAB/cybr2800_forensic_evidence_lab4.py"

for f in "$GENERATOR" "$HERE/validate_lab4_image.sh" "$HERE/BUILD_AND_DISTRIBUTE.md"; do
    if [ ! -f "$f" ]; then
        echo "missing: $f" >&2
        exit 1
    fi
done

# Refuse to package a generator that does not even compile.
python3 -m py_compile "$GENERATOR" || { echo "generator does not compile" >&2; exit 1; }
bash -n "$HERE/validate_lab4_image.sh" || { echo "validator has a syntax error" >&2; exit 1; }

mkdir -p "$STAGE/$KIT"
cp "$GENERATOR"                         "$STAGE/$KIT/"
cp "$HERE/validate_lab4_image.sh"       "$STAGE/$KIT/"
cp "$HERE/BUILD_AND_DISTRIBUTE.md"      "$STAGE/$KIT/"
chmod 755 "$STAGE/$KIT/validate_lab4_image.sh"

cat > "$STAGE/$KIT/README.txt" <<'EOF'
CYBR 2800 -- Lab 3 of 3 ("The Tobor Transfer") -- INSTRUCTOR KIT
==================================================================

INSTRUCTOR / TA ONLY. Do not give this to students: the generator contains the
entire evidence set and the answer key as literal strings.

Contents
  cybr2800_forensic_evidence_lab4.py   builds the evidence image (Ubuntu, root)
  validate_lab4_image.sh               40 pre-class checks (Ubuntu + sleuthkit)
  BUILD_AND_DISTRIBUTE.md              the full runbook -- read this first

Quick start (Ubuntu 24.04 VM)
  sudo apt update
  sudo apt install e2fsprogs coreutils parted util-linux sleuthkit unzip file python3
  mkdir -p ~/masters/lab04 && cd ~/masters/lab04
  sudo python3 /path/to/cybr2800_forensic_evidence_lab4.py
  /path/to/validate_lab4_image.sh CYBR2800_Lab3_Evidence.dd     # expect 40 passed
  chmod 444 CYBR2800_Lab3_Evidence.dd

Build once per semester: every build has a different SHA-256.
The student handout (lab04.html) is distributed separately through Canvas.
EOF

# Build the archive with Python's tarfile rather than tar(1). bsdtar on macOS embeds
# Apple xattrs (com.apple.provenance), which make GNU tar on Ubuntu print "Ignoring
# unknown extended header keyword" warnings. tarfile never writes them, and it lets us
# normalize ownership so the kit does not carry the packager's uid/username.
python3 - "$STAGE" "$KIT" "$HERE/$KIT.tar.gz" <<'PY'
import sys, tarfile

stage, kit, out = sys.argv[1:4]

def normalize(info):
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = int(info.mtime)
    return info

with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as archive:
    archive.add(f"{stage}/{kit}", arcname=kit, filter=normalize)
PY

( cd "$HERE" && {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$KIT.tar.gz" > "$KIT.tar.gz.sha256"
    else
        shasum -a 256 "$KIT.tar.gz" > "$KIT.tar.gz.sha256"
    fi
} )

echo "Wrote:"
ls -l "$HERE/$KIT.tar.gz" "$HERE/$KIT.tar.gz.sha256"
echo
cat "$HERE/$KIT.tar.gz.sha256"
echo
echo "Contents:"
tar -tzf "$HERE/$KIT.tar.gz"
echo
echo "INSTRUCTOR ONLY -- do not share with students."
