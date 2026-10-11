#!/usr/bin/env bash
# Does the default list set do its job? Downloads the app's default lists and reports:
#   - coverage of known ad/tracker domains (d3ward's adblock test, by category);
#   - critical TV domains blocked by mistake (scripts/data/critical-domains.txt);
#   - top-1000 sites (Tranco) that the lists block, to review for false positives.
# Usage: scripts/validate-lists.sh   (needs curl, python3, cargo)
set -euo pipefail
cd "$(dirname "$0")/.."
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Same sources and defaults as ListRepository.ALL_LISTS.
LISTS=(
    https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt
    https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt
)
files=(app/src/main/assets/video-ads.txt)
for i in "${!LISTS[@]}"; do
    curl -sSfL -o "$WORK/list$i.txt" "${LISTS[$i]}"
    files+=("$WORK/list$i.txt")
done
curl -sSfL -o "$WORK/adblock_data.json" https://raw.githubusercontent.com/d3ward/toolz/master/src/data/adblock_data.json
curl -sSfL -o "$WORK/tranco.zip" https://tranco-list.eu/top-1m.csv.zip

python3 - "$WORK" > "$WORK/labelled.txt" <<'PY'
import json, sys, zipfile
work = sys.argv[1]
for category, groups in json.load(open(f"{work}/adblock_data.json")).items():
    for domains in groups.values():
        for domain in domains:
            print(f"{category}\t{domain}")
for line in open("scripts/data/critical-domains.txt"):
    line = line.strip()
    if line and not line.startswith("#"):
        print(f"allow:critical\t{line}")
with zipfile.ZipFile(f"{work}/tranco.zip") as z:
    rows = z.read(z.namelist()[0]).decode().splitlines()[:1000]
for row in rows:
    print(f"allow:tranco-top1000\t{row.split(',')[1]}")
PY

(cd native/nfdns-core && cargo build -q --release --example coverage)
native/nfdns-core/target/release/examples/coverage "$WORK/labelled.txt" "${files[@]}"
