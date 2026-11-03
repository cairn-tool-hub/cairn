# cairn

Tamper-evident activity records for Windows.

cairn records what happened on a machine into a hash-chained log, so that
anyone can later check whether the record was altered. It is small enough to
run on hardware that cannot host a SIEM.

## Commands


    cairn watch                    pull Sysmon events into the chain (admin)
    cairn record --message "..."   add your own note
    cairn timeline 20              recent entries
    cairn verify                   check the chain
    cairn export --out bundle.cairn
    cairn verify bundle.cairn      anyone can run this, on any machine

## Why

Sysmon is a great sensor and a terrible archive. It writes raw XML into the
Windows event log with no history, no portability and no integrity check.
Wazuh solves that, but needs a multi-gigabyte server.

cairn is the small version: one file, one chain, one command to verify.

## What it proves, and what it does not

**Detects:** accidental corruption, naive edits, deleted entries, reordering,
and any change made without rebuilding the entire chain.

**Does not prevent:** an administrator rewriting the whole file and rebuilding
the chain. That needs an append-only medium or a remote anchor, neither of
which this has.

cairn is tamper-**evident**, not tamper-**proof**. Any security tool claiming
otherwise is lying to you.

## How the chain works

Each entry stores the SHA-256 fingerprint of the entry before it:

    {"seq":1, "ts":"...", "message":"first",  "prev":"000...0", "hash":"a1b2..."}
    {"seq":2, "ts":"...", "message":"second", "prev":"a1b2...", "hash":"c3d4..."}

Edit entry 1 and entry 2 no longer links to it. Delete entry 1 and the
sequence numbers no longer line up. Both are detected.

Hashing uses sorted keys and fixed separators, so the same entry produces the
same fingerprint on any machine, in any language, forever.

## Requirements

- Python 3.8+
- Windows (Sysmon feed). `record`, `verify` and `export` work on any OS.
- Administrator only for `cairn watch`, because reading the Sysmon log needs it.

## Limitations - read these

- **The log lives on the same disk it monitors.** A wiped machine takes the
  evidence with it. Run `cairn export` and move the bundle somewhere else.
- No tamper *prevention*, only detection.
- No event search or filtering yet.
- Sysmon must already be installed.
- Single user. No multi-host aggregation.

## Status

Working and tested: chain, export, verify, tamper detection, Sysmon ingest.
8 self-tests. Not published yet.

MIT License

Copyright (c) 2026 cairn-tool-hub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
