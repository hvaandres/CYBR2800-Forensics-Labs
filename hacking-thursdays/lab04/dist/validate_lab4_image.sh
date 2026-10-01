#!/usr/bin/env bash
#
# validate_lab4_image.sh -- pre-class validation for CYBR2800_Lab3_Evidence.dd
#
# Run on Ubuntu with The Sleuth Kit installed:
#
#     sudo apt install sleuthkit unzip file python3
#     ./validate_lab4_image.sh /path/to/CYBR2800_Lab3_Evidence.dd
#
# Read-only: it never mounts or modifies the image. Exits 0 only if every
# check passes. Run it against the MASTER before publishing the hash; a
# failure here is a failure students would hit in class.
#
# INSTRUCTOR ONLY -- the checks below spell out the answers.

set -u

IMG="${1:-}"

if [ -z "$IMG" ] || [ ! -f "$IMG" ]; then
    echo "usage: $0 /path/to/CYBR2800_Lab3_Evidence.dd" >&2
    exit 2
fi

for tool in mmls fsstat fls istat icat file unzip python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing tool: $tool  (sudo apt install sleuthkit unzip file python3)" >&2
        exit 2
    }
done

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ok()   { printf '  [ ok ] %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
head_() { printf '\n== %s\n' "$1"; }

check() {
    # check "description" <command...>   -- passes if the command succeeds
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

# ---------------------------------------------------------------- 3.1
head_ "3.1  Partition table (handout Part 3 requires mmls)"

mmls "$IMG" > "$WORK/mmls.txt" 2>&1
OFFSET="$(awk '/Linux/ {print $3 + 0; exit}' "$WORK/mmls.txt")"

if [ -n "$OFFSET" ] && [ "$OFFSET" -gt 0 ]; then
    ok "mmls found a Linux partition, start sector $OFFSET"
else
    bad "mmls did not find a Linux partition (image has no partition table?)"
    echo; echo "Cannot continue without an offset."; exit 1
fi

[ "$OFFSET" = "2048" ] && ok "offset is the documented 2048" \
                       || bad "offset is $OFFSET, docs say 2048 -- update the answer key"

# ---------------------------------------------------------------- 3.2
head_ "3.2  Filesystem and tree"

fsstat -o "$OFFSET" "$IMG" > "$WORK/fsstat.txt" 2>&1
grep -q "File System Type: Ext" "$WORK/fsstat.txt" \
    && ok "filesystem readable: $(grep -m1 'File System Type' "$WORK/fsstat.txt")" \
    || bad "fsstat could not read the filesystem at offset $OFFSET"

fls -r -p -o "$OFFSET" "$IMG" > "$WORK/alloc.txt" 2>&1
COUNT="$(wc -l < "$WORK/alloc.txt" | tr -d ' ')"
[ "$COUNT" -ge 350 ] && ok "allocated listing has $COUNT entries (expected ~390)" \
                     || bad "allocated listing has only $COUNT entries (expected ~390)"

for area in "home/alex/" "home/priya/" "home/jordan/" "mnt/finance_share/" \
            "mnt/recovered_backup/" "var/log/finance_api/" "etc/report-scheduler/"; do
    grep -q "$area" "$WORK/alloc.txt" && ok "present: $area" || bad "missing: $area"
done

# Helper: inode of an exact path in a listing file (allocated or deleted).
inode_of() {
    awk -F'\t' -v p="$2" '$2 == p { n = split($1, a, " "); i = a[n]; sub(":", "", i); print i; exit }' "$1"
}

# ---------------------------------------------------------------- 3.3
head_ "3.3  Deleted-file recovery  (CRITICAL -- 22 rubric points depend on this)"

fls -r -p -d -o "$OFFSET" "$IMG" > "$WORK/deleted.txt" 2>&1

DELETED=(
    "home/alex/Downloads/.cache_sync/Q1_2026_Bank_Reconciliation.xlsx"
    "home/alex/Downloads/.cache_sync/Q2_2026_Bank_Reconciliation.xlsx"
    "home/alex/Downloads/.cache_sync/Wire_Transfer_Ledger_2026.xlsx"
    "home/alex/Downloads/.cache_sync/Payroll_Disbursements_2026.xlsx"
    "home/alex/Downloads/.cache_sync/Client_Bank_Accounts_Master.csv"
    "home/alex/Downloads/.cache_sync/finance_packet_2026-08-20.tar.gz"
    "home/alex/Downloads/.cache_sync/transfer_manifest.txt"
    "home/alex/.local/share/WhatsApp/chat_export_Kestrel.txt"
    "home/alex/.config/Signal/logs/conversation_notes.txt"
    "home/alex/Downloads/temporary_credentials.txt"
    "var/log/finance_api/access.log.1"
)

for path in "${DELETED[@]}"; do
    ino="$(inode_of "$WORK/deleted.txt" "$path")"
    if [ -z "$ino" ]; then
        bad "not listed by fls -r -d: $path"
        continue
    fi
    size="$(icat -o "$OFFSET" "$IMG" "$ino" 2>/dev/null | wc -c | tr -d ' ')"
    if [ "$size" -gt 0 ]; then
        ok "recovers $size bytes  (inode $ino)  $(basename "$path")"
    else
        bad "icat returned 0 bytes (inode $ino): $path"
    fi
done

grep -q "home/alex/Downloads/.cache_sync$" "$WORK/deleted.txt" \
    && ok "deleted directory .cache_sync is listed" \
    || bad "deleted directory .cache_sync not listed"

PHANTOM="$(grep -c '\^$' "$WORK/deleted.txt" | tr -d ' ')"
echo "  [info] $PHANTOM phantom '^' slack entries (expected 2; the handout tells students to rule them out)"

# ---------------------------------------------------------------- binary evidence
head_ "Recovered binary evidence is genuine (handout Parts 13-14)"

Q1="$(inode_of "$WORK/deleted.txt" "${DELETED[0]}")"
MAN="$(inode_of "$WORK/deleted.txt" "${DELETED[6]}")"
TGZ="$(inode_of "$WORK/deleted.txt" "${DELETED[5]}")"

icat -o "$OFFSET" "$IMG" "$Q1"  > "$WORK/Q1.xlsx"
icat -o "$OFFSET" "$IMG" "$MAN" > "$WORK/manifest.txt"
icat -o "$OFFSET" "$IMG" "$TGZ" > "$WORK/packet.tar.gz"

file "$WORK/Q1.xlsx" | grep -qiE "Excel|Zip" && ok "Q1 workbook identifies as an Excel/ZIP file" \
                                              || bad "Q1 workbook is not a valid ZIP/Excel file"
unzip -l "$WORK/Q1.xlsx" 2>/dev/null | grep -q "xl/worksheets/sheet1.xml" \
    && ok "workbook contains xl/worksheets/sheet1.xml" || bad "workbook missing sheet1.xml"

[ "$(grep -a -c 'GRAND TOTAL' "$WORK/Q1.xlsx")" = "0" ] \
    && ok "grep finds nothing in the raw .xlsx (compressed, as the handout teaches)" \
    || bad "raw .xlsx is greppable -- the Part 13 lesson would not land"

tar -tzf "$WORK/packet.tar.gz" 2>/dev/null | grep -q "Q1_2026_Bank_Reconciliation.xlsx" \
    && ok "tar.gz extracts and lists the staged workbooks" || bad "tar.gz is corrupt"

python3 - "$WORK/Q1.xlsx" "$WORK/manifest.txt" <<'PY' && ok "Q1 row sum matches the recovered manifest to the cent" || bad "Q1 row sum does NOT match the manifest"
import re, sys, zipfile
import xml.etree.ElementTree as ET

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
book = zipfile.ZipFile(sys.argv[1])
sheet = ET.fromstring(book.read("xl/worksheets/sheet1.xml"))
rows = sheet.findall(f"{NS}sheetData/{NS}row")

total = 0.0
for row in rows[1:-1]:
    for cell in row.findall(f"{NS}c"):
        if cell.get("r", "").startswith("I"):
            total += float(cell.find(f"{NS}v").text)

manifest = open(sys.argv[2], encoding="utf-8").read()
match = re.search(r"Q1_2026_Bank_Reconciliation\.xlsx\s+([\d,]+)\s+([\d,\.]+)", manifest)
want_rows, want_total = int(match.group(1).replace(",", "")), float(match.group(2).replace(",", ""))

print(f"      rows {len(rows) - 2} (manifest {want_rows}), sum {total:,.2f} (manifest {want_total:,.2f})")
sys.exit(0 if len(rows) - 2 == want_rows and abs(total - want_total) < 0.01 else 1)
PY

# ---------------------------------------------------------------- attribution pivot
head_ "The attribution pivot (Lab 2 -> Lab 3 payoff)"

DHCP="$(inode_of "$WORK/alloc.txt" "var/log/dhcpd.log")"
KH="$(inode_of "$WORK/alloc.txt" "home/alex/.ssh/known_hosts")"
HOSTS="$(inode_of "$WORK/alloc.txt" "etc/hosts")"
INV="$(inode_of "$WORK/alloc.txt" "etc/asset_inventory.csv")"

icat -o "$OFFSET" "$IMG" "$DHCP"  > "$WORK/dhcpd.log"
icat -o "$OFFSET" "$IMG" "$KH"    > "$WORK/known_hosts"
icat -o "$OFFSET" "$IMG" "$HOSTS" > "$WORK/hosts"
icat -o "$OFFSET" "$IMG" "$INV"   > "$WORK/inventory.csv"

MAC="b4:2e:99:0c:17:aa"

grep -q "DHCPACK on 10.10.20.55 to $MAC" "$WORK/dhcpd.log" && ok "dhcpd.log: $MAC held 10.10.20.55" \
                                                           || bad "dhcpd.log: old lease missing"
grep -q "DHCPACK on 10.10.20.77 to $MAC" "$WORK/dhcpd.log" && ok "dhcpd.log: same MAC then held 10.10.20.77" \
                                                           || bad "dhcpd.log: new lease missing"

KEY55="$(awk '$1=="10.10.20.55"{print $3}' "$WORK/known_hosts")"
KEY77="$(awk '$1=="10.10.20.77"{print $3}' "$WORK/known_hosts")"
[ -n "$KEY55" ] && [ "$KEY55" = "$KEY77" ] && ok "known_hosts: identical host key for both addresses" \
                                           || bad "known_hosts: keys differ or missing"

grep -q "tobor" "$WORK/hosts" && ok "etc/hosts: manual tobor entry present" || bad "etc/hosts: tobor entry missing"
grep -qi "tobor\|$MAC" "$WORK/inventory.csv" && bad "asset inventory lists the laptop (it must NOT)" \
                                             || ok "asset inventory does not list the laptop"

# ---------------------------------------------------------------- scenario logic
head_ "Scenario integrity"

check_log() {   # check_log "description" <path> <pattern>
    local ino
    ino="$(inode_of "$WORK/alloc.txt" "$2")"
    if [ -n "$ino" ] && icat -o "$OFFSET" "$IMG" "$ino" 2>/dev/null | grep -qE "$3"; then
        ok "$1"
    else
        bad "$1"
    fi
}

check_log "Lab 2 continuity: brute force from 10.10.20.55 in auth.log" \
    "var/log/auth.log" "Failed password for root from 10.10.20.55"
check_log "Lab 2 continuity: backupadmin out-of-window login" \
    "var/log/auth.log" "Accepted password for backupadmin from 10.10.20.25"
check_log "USB red herring: exactly 800 bytes written" \
    "var/log/usb_events.log" "total_bytes_written=800"
check_log "DLP alerts present and unreviewed" \
    "var/log/dlp_alerts.log" "reviewed=NO"

# Transfer volume must agree between two independent logs.
RA="$(icat -o "$OFFSET" "$IMG" "$(inode_of "$WORK/alloc.txt" var/log/remote_access.log)" \
      | grep -oE 'bytes=[0-9]+' | cut -d= -f2 | paste -sd+ - | python3 -c 'import sys; print(eval(sys.stdin.read()))')"
SL="$(icat -o "$OFFSET" "$IMG" "$(inode_of "$WORK/alloc.txt" home/alex/.local/state/tobor_sync.log)" \
      | grep '^2026-08-20 15:' | awk -F'|' '{gsub(/ /,"",$3); s+=$3} END {print s}')"
[ -n "$RA" ] && [ "$RA" = "$SL" ] && ok "incident-day transfer volume agrees across two logs ($RA bytes)" \
                                  || bad "transfer volume disagrees: remote_access=$RA sync_log=$SL"

# Timestomp: mtime must predate ctime by a wide margin on tobor_sync.sh.
TS="$(inode_of "$WORK/alloc.txt" "home/alex/.local/bin/tobor_sync.sh")"
istat -o "$OFFSET" "$IMG" "$TS" > "$WORK/istat_ts.txt" 2>&1
MT="$(awk -F'\t' '/File Modified/ {print $2}' "$WORK/istat_ts.txt" | cut -c1-4)"
CT="$(awk -F'\t' '/Inode Modified/ {print $2}' "$WORK/istat_ts.txt" | cut -c1-4)"
[ "$MT" = "2025" ] && [ -n "$CT" ] && [ "$CT" -ge 2026 ] \
    && ok "timestomp visible: mtime year $MT vs ctime year $CT" \
    || bad "timestomp not visible (mtime '$MT', ctime '$CT')"

# Scenario mtime must survive deletion (offline debugfs delete, not unlink).
istat -o "$OFFSET" "$IMG" "$Q1" 2>/dev/null | grep -q "File Modified:.*2026-08-20 12:40:08" \
    && ok "deleted file kept its scenario mtime (2026-08-20 12:40:08)" \
    || bad "deleted file's mtime was overwritten -- was it deleted through the mount?"

# ---------------------------------------------------------------- summary
head_ "Result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"

if [ "$FAIL" -eq 0 ]; then
    echo "  READY. Freeze the master, then publish its SHA-256:"
    sha256sum "$IMG" | sed 's/^/    /'
    exit 0
fi

echo "  NOT READY -- do not publish this image."
exit 1
