#!/usr/bin/env python3
"""cairn - tamper-evident activity records for Windows.

Each entry stores the fingerprint (SHA-256) of the one before it. Change any
entry and every entry after it stops matching. That does not make the file
impossible to alter - it makes alteration visible.

    cairn record --category process --message "notepad.exe started"
    cairn timeline 20
    cairn verify
    cairn export --out bundle.cairn
    cairn verify bundle.cairn          <- anyone can run this, on any machine
    cairn selftest

THREAT MODEL - read this before trusting it
    Detects:    accidental corruption, naive edits, deleted entries,
                reordering, and any change made without rebuilding the chain.
    Does not:   stop an administrator who rewrites the whole file and rebuilds
                the chain. Preventing that needs an append-only medium or a
                remote anchor, neither of which this has.
    Never claim this tool is tamper-proof. It is tamper-EVIDENT.

FORMAT
    One JSON object per line. Fields are sorted and separators fixed, so the
    same entry always hashes to the same value on any machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

VERSION = "0.1.0"
GENESIS = "0" * 64
HOME = os.path.expanduser("~")
DEFAULT_LOG = os.path.join(HOME, "Documents", "Cairn", "cairn.jsonl")


# ---------------------------------------------------------------- primitives
def canonical(entry: dict) -> bytes:
    """Stable byte representation. sort_keys + fixed separators means the same
    entry hashes identically regardless of Python version or platform."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


def digest(entry: dict) -> str:
    return hashlib.sha256(canonical(entry)).hexdigest()


def read_log(path: str) -> list:
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                entries.append({"__corrupt__": line[:120], "__line__": lineno})
    return entries


def append(path: str, category: str, message: str, severity: str = "info",
           source: str = "manual", evidence: str = "", when: str = "") -> dict:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    entries = read_log(path)
    prev = entries[-1].get("hash", GENESIS) if entries else GENESIS
    now = datetime.now(timezone.utc)
    entry = {
        "v": 1,
        "seq": len(entries) + 1,
        "ts": when or now.isoformat(timespec="seconds"),
        "recorded": now.isoformat(timespec="seconds"),
        "category": category,
        "severity": severity,
        "message": message,
        "source": source,
        "evidence": evidence,
        "prev": prev,
    }
    entry["hash"] = digest(entry)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


def check(entries: list) -> list:
    """Return a list of problems. Empty list means the chain is intact."""
    problems = []
    prev = GENESIS
    # A bundle ends with a manifest line. It is not part of the chain, so it is
    # skipped here and validated separately - otherwise every exported bundle
    # fails its own verification.
    entries = [e for e in entries if "__manifest__" not in e]
    for i, e in enumerate(entries, 1):
        if "__corrupt__" in e:
            problems.append(f"line {e.get('__line__', i)}: unreadable record")
            continue
        if e.get("seq") != i:
            problems.append(f"seq {e.get('seq')} appears at position {i} (entry removed or reordered)")
        body = {k: v for k, v in e.items() if k != "hash"}
        if digest(body) != e.get("hash"):
            problems.append(f"seq {e.get('seq')}: content does not match its hash (edited)")
        if e.get("prev") != prev:
            problems.append(f"seq {e.get('seq')}: does not link to the previous entry (chain broken)")
        prev = e.get("hash")
    return problems


# ---------------------------------------------------------------- commands
def cmd_record(a) -> None:
    e = append(a.log, a.category, a.message, a.severity, a.source, a.evidence or "")
    print(f"  recorded seq {e['seq']}  hash {e['hash'][:16]}...")


def cmd_timeline(a) -> None:
    entries = read_log(a.log)[-a.count:]
    if not entries:
        print("  no entries yet")
        return
    for e in entries:
        print(f"  {e.get('ts','?')[:19]}  [{e.get('severity','?'):<8}] {e.get('category','?'):<10} "
              f"{e.get('message','')[:80]}")


def cmd_verify(a) -> int:
    entries = read_log(a.file)
    if not entries:
        print(f"  {a.file}: no entries")
        return 1
    manifest = None
    for e in entries:
        if "__manifest__" in e:
            manifest = e["__manifest__"]
    problems = check(entries)
    chain = [e for e in entries if "__manifest__" not in e]
    print(f"  {a.file}")
    if chain:
        print(f"  {len(chain)} entries, head {chain[-1].get('hash','?')[:32]}...")
    if manifest:
        if manifest.get("entries") != len(chain):
            problems.append("manifest entry count does not match the chain")
        elif manifest.get("head") != chain[-1].get("hash"):
            problems.append("manifest head does not match the last entry")
        else:
            print(f"  manifest ok: {manifest.get('entries')} entries, head matches")
    if problems:
        print(f"  FAILED - {len(problems)} problem(s):")
        for p in problems[:12]:
            print(f"    {p}")
        return 2
    print("  OK - chain intact")
    return 0


def cmd_export(a) -> None:
    """A bundle is the plain log plus a small manifest. Deliberately not
    encrypted or compressed: the recipient must be able to read it without us."""
    entries = read_log(a.log)
    if not entries:
        print("  nothing to export")
        return
    manifest = {
        "format": "cairn-bundle/1",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entries": len(entries),
        "head": entries[-1].get("hash"),
        "generator": f"cairn {VERSION}",
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")
        fh.write(json.dumps({"__manifest__": manifest}) + "\n")
    print(f"  exported {len(entries)} entries -> {a.out}")
    print(f"  head {manifest['head']}")
    print("  anyone can check it with:  cairn verify " + a.out)


def cmd_watch(a) -> None:
    """Pull real Sysmon events into the chain.

    Reading the Sysmon log needs administrator rights. Unelevated this reports
    that honestly instead of recording nothing and looking successful.
    """
    ps = ("$e = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
          "-MaxEvents " + str(a.count) + " -ErrorAction SilentlyContinue; "
          "if ($e) { foreach ($x in $e) { Write-Output ($x.RecordId.ToString() + '|' + "
          "$x.Id.ToString() + '|' + $x.TimeCreated.ToString('o')) } } else { 'NONE' }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=120)
        raw = (out.stdout or "").strip()
    except Exception as exc:
        print("  collector failed: " + str(exc))
        return
    if not raw or "NONE" in raw:
        print("  no Sysmon events readable - run this in an administrator terminal")
        return

    seen = {e.get("evidence") for e in read_log(a.log)}
    kinds = {"1": "process", "3": "network", "11": "file", "13": "persistence", "22": "network"}
    added = 0
    for line in raw.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        rid, eid, ts = parts
        key = "sysmon:" + rid
        if key in seen:
            continue
        append(a.log, kinds.get(eid, "event"), "Sysmon event " + eid,
               "info", "sysmon", key, when=ts)
        added += 1
    print("  " + str(added) + " new Sysmon event(s) recorded")


def selftest() -> int:
    import tempfile
    fails = []

    def ck(name, cond, detail=""):
        print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  {detail}"))
        if not cond:
            fails.append(name)

    tmp = tempfile.mkdtemp(prefix="cairn-")
    log = os.path.join(tmp, "t.jsonl")
    try:
        e1 = append(log, "process", "first")
        e2 = append(log, "process", "second")
        ck("first entry links to genesis", e1["prev"] == GENESIS)
        ck("second links to first", e2["prev"] == e1["hash"])
        ck("clean chain verifies", check(read_log(log)) == [])

        # edit detection
        lines = open(log, encoding="utf-8").read().splitlines()
        obj = json.loads(lines[0]); obj["message"] = "edited"
        lines[0] = json.dumps(obj)
        open(log, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        ck("edit is detected", len(check(read_log(log))) > 0)

        # deletion detection
        os.remove(log)
        append(log, "a", "one"); append(log, "a", "two"); append(log, "a", "three")
        lines = open(log, encoding="utf-8").read().splitlines()
        open(log, "w", encoding="utf-8").write("\n".join([lines[0], lines[2]]) + "\n")
        ck("deletion is detected", len(check(read_log(log))) > 0)

        # determinism: same body hashes the same regardless of key order
        ck("hash is order-independent",
           digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1}))

        # export round trip
        os.remove(log)
        append(log, "x", "one"); append(log, "x", "two")
        out = os.path.join(tmp, "bundle.cairn")
        class A: pass
        a = A(); a.log = log; a.out = out
        cmd_export(a)
        ck("bundle is readable", os.path.exists(out))
        ck("bundle contains manifest",
           any("__manifest__" in ln for ln in open(out, encoding="utf-8")))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print(f"  {len(fails)} failed" if fails else "  all tests passed")
    return 1 if fails else 0


def main() -> None:
    p = argparse.ArgumentParser(prog="cairn", description="tamper-evident activity records")
    p.add_argument("--log", default=DEFAULT_LOG, help="log file path")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("record"); r.add_argument("--category", default="event")
    r.add_argument("--message", required=True); r.add_argument("--severity", default="info")
    r.add_argument("--source", default="manual"); r.add_argument("--evidence", default="")

    t = sub.add_parser("timeline"); t.add_argument("count", nargs="?", type=int, default=20)

    v = sub.add_parser("verify"); v.add_argument("file", nargs="?", default=None)

    e = sub.add_parser("export"); e.add_argument("--out", required=True)

    w = sub.add_parser("watch"); w.add_argument("count", nargs="?", type=int, default=50)

    sub.add_parser("selftest")

    a = p.parse_args()
    if not a.cmd:
        p.print_help(); return

    if a.cmd == "record":   cmd_record(a)
    elif a.cmd == "timeline": cmd_timeline(a)
    elif a.cmd == "verify":
        a.file = a.file or a.log
        sys.exit(cmd_verify(a))
    elif a.cmd == "export": cmd_export(a)
    elif a.cmd == "watch": cmd_watch(a)
    elif a.cmd == "selftest": sys.exit(selftest())


if __name__ == "__main__":
    main()
