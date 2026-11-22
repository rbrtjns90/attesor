#!/usr/bin/env python3
"""Summarize the Darwin bridge against the Linux v6.1 x86-64 syscall table."""

import argparse
from collections import Counter
from pathlib import Path
import re


BRIDGE = Path(__file__).resolve().parents[1]
TABLE = BRIDGE / "tools/linux-x86_64-v6.1.tsv"
CASE = re.compile(r"\bcase (OAH_X86_NR_[A-Z_]+|\d+)\s*:")
DEFINE = re.compile(r"^#define (OAH_X86_NR_[A-Z_]+)\s+(\d+)", re.MULTILINE)
# These explicitly dispatched calls have no working behavior yet.
STUBS = {40}
# Only audited operations with an integration test and no known gap in scope.
SUPPORTED = {39}


def inventory():
    numbers = dict(DEFINE.findall((BRIDGE / "include/oah/syscall_bridge.h").read_text()))
    dispatcher = (BRIDGE / "src/syscall_darwin.c").read_text().split(
        "oah_sys_status oah_guest_syscall(", 1
    )[1]
    dispatched = {int(numbers.get(case, case)) for case in CASE.findall(dispatcher)}
    for row in TABLE.read_text().splitlines():
        number, name = row.split("\t")
        number = int(number)
        if number not in dispatched or number in STUBS:
            status = "unsupported"
        else:
            status = "supported" if number in SUPPORTED else "partial"
        yield number, name, status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    rows = list(inventory())
    if args.summary:
        counts = Counter(row[2] for row in rows)
        for status in ("supported", "partial", "unsupported"):
            print(f"{status:11} {counts[status]}")
        print(f"{'total':11} {len(rows)}")
    else:
        print("number\tsyscall\tstatus")
        for number, name, status in rows:
            print(f"{number}\t{name}\t{status}")


if __name__ == "__main__":
    main()
