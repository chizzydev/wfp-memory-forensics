#!/usr/bin/env python3
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "src/windows/wfpfilters.py": "BD5703A884D55F652328F3326DDDD30F59AD1D6038D03DDAA88E401C74128B7C",
    "src/windows/wfpcheck.py": "7E1683A9A5F02DAD8C63034018F18850A39F7A6A458E95648BACA61AE875CF30",
    "src/windows/wfpcallouts.py": "F71FC85972D0849A849080818504A7C171CA12351500EB0E16D7EC16D8BAA691",
}

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()

ok = True
for rel, expected in EXPECTED.items():
    path = ROOT / rel
    actual = sha256(path) if path.is_file() else "MISSING"
    status = "PASS" if actual == expected else "FAIL"
    print(f"{status}  {actual}  {rel}")
    ok &= actual == expected

raise SystemExit(0 if ok else 1)
