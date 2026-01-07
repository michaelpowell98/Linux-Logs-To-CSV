#!/usr/bin/env python3
"""
auth_log_processor.py

Purpose
-------
Parse Linux auth.log / secure-style syslog files and produce an enriched CSV
that is easy to ingest into SIEM / Splunk-like tools.

Key design goals
----------------
• Preserve the original log message
• Promote useful fields (USER, COMMAND, SRC_IP, etc.) into first-class columns
• Work even when log lines are not uniform
• Be readable and maintainable by humans

Usage
-----
python3 auth_log_processor.py /path/to/auth.log

Output
------
<auth.log>.parsed.csv
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from typing import Dict, Optional, Tuple


# =============================================================================
# 1. SYSLOG HEADER PARSING
# =============================================================================
# Standard syslog format:
#   Jan  2 11:43:04 hostname program[pid]: message
#
# We do NOT attempt to infer year or timezone.
# The raw "Mon Day HH:MM:SS" string is preserved as TIMESTAMP.
# =============================================================================

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[^\s\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)


# =============================================================================
# 2. GENERIC KEY=VALUE EXTRACTION
# =============================================================================
# Many auth.log lines contain key=value pairs:
#   user=root rhost=1.2.3.4 tty=ssh
#
# We scrape these generically so:
#   • new record types still retain useful data
#   • we don't lose information if patterns change
#
# Promoted fields get real columns; everything else lands in EXTRA_JSON.
# =============================================================================

KV_RE = re.compile(
    r"(?<![\w/.-])"
    r"(?P<k>[A-Za-z_][A-Za-z0-9_.-]*)="
    r"(?P<v>\"[^\"]*\"|[^ \t;]+)"
)

def _clean(v: str) -> str:
    """Normalize extracted values by removing quotes and punctuation."""
    v = v.strip()
    if v.startswith('"') and v.endswith('"') and len(v) >= 2:
        v = v[1:-1]
    return v.strip().strip(",;.)]").strip()

def extract_kv(text: str) -> Dict[str, str]:
    """Return all key=value pairs found in text."""
    return {m.group("k"): _clean(m.group("v")) for m in KV_RE.finditer(text)}


# =============================================================================
# 3. SUDO MESSAGE PARSING
# =============================================================================
# Example sudo message:
#   ubuntu : TTY=tty1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/nano /etc/hosts
#
# Design notes:
# • The "actor" is the username before the first colon
# • COMMAND may contain spaces → we preserve everything after COMMAND=
# =============================================================================

def parse_sudo_message(msg: str) -> Tuple[str, Dict[str, str]]:
    """
    Parse sudo message into:
      - actor: user who ran sudo
      - kv: dict of sudo fields (TTY, PWD, USER, COMMAND)
    """
    actor = ""
    rest = msg

    # Extract the actor before the first colon
    if ":" in msg:
        left, right = msg.split(":", 1)
        candidate = left.strip()
        if candidate and " " not in candidate:
            actor = candidate
            rest = right.strip()

    kv: Dict[str, str] = {}
    for part in (p.strip() for p in rest.split(";")):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        kv[k.strip()] = _clean(v)

    return actor, kv


# =============================================================================
# 4. SSHD MESSAGE PATTERNS
# =============================================================================
# sshd logs do NOT use key=value consistently, so regex is required.
# =============================================================================

SSHD_CONN_RE   = re.compile(r"^Connection from (?P<src_ip>\S+) port (?P<src_port>\d+) on (?P<dst_ip>\S+) port (?P<dst_port>\d+)")
SSHD_ACCEPT_RE = re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)")
SSHD_FAIL_RE   = re.compile(r"^Failed \S+ for (?:(?:invalid user)\s+)?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)")


# =============================================================================
# 5. PAM (pam_unix) MESSAGE PARSING
# =============================================================================
# pam_unix lines wrap authentication and session events across multiple services.
# =============================================================================

PAM_UNIX_RE = re.compile(
    r"^pam_unix\((?P<service>[^:]+):(?P<phase>[^)]+)\):\s+(?P<detail>.*)$"
)

PAM_SESSION_RE = re.compile(
    r"^session (?P<action>opened|closed) for user (?P<target_user>\S+)(?: by (?P<actor>.+))?$"
)


# =============================================================================
# 6. OUTPUT CSV SCHEMA
# =============================================================================
# Fixed schema → easy aggregation, stats, dashboards.
# EXTRA_JSON preserves everything else without schema churn.
# =============================================================================

FIELDNAMES = [
    "TIMESTAMP", "HOST", "PROGRAM", "PID",
    "EVENT_TYPE", "ACTION",
    "ACTOR",
    "USER",
    "TARGET_USER",
    "COMMAND",
    "TTY", "PWD",
    "SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT",
    "PAM_SERVICE", "PAM_PHASE",
    "MESSAGE",
    "EXTRA_JSON",
]


# =============================================================================
# 7. LINE PARSER (CORE LOGIC)
# =============================================================================

def parse_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single log line into a normalized event dict."""

    line = line.rstrip("\n")
    if not line.strip():
        return None

    # --- Parse syslog header
    m = SYSLOG_RE.match(line)
    if not m:
        # Preserve unparseable lines
        return {
            **{k: "" for k in FIELDNAMES},
            "EVENT_TYPE": "UNPARSED",
            "MESSAGE": line,
            "EXTRA_JSON": json.dumps({"note": "no syslog header"}, sort_keys=True),
        }

    ts = f"{m.group('mon')} {m.group('day')} {m.group('time')}"
    program = m.group("program")
    msg = m.group("msg")

    row = {k: "" for k in FIELDNAMES}
    row.update({
        "TIMESTAMP": ts,
        "HOST": m.group("host"),
        "PROGRAM": program,
        "PID": m.group("pid") or "",
        "MESSAGE": msg,
        "EVENT_TYPE": "GENERIC",
    })

    extra = extract_kv(msg)
    prog = program.lower()

    # --- sudo
    if prog == "sudo":
        row["EVENT_TYPE"] = "SUDO"
        actor, kv = parse_sudo_message(msg)
        row["ACTOR"] = actor
        row["TTY"] = kv.get("TTY", "")
        row["PWD"] = kv.get("PWD", "")
        row["TARGET_USER"] = kv.get("USER", "")
        row["COMMAND"] = kv.get("COMMAND", "")
        row["ACTION"] = "RUN_COMMAND" if row["COMMAND"] else ""

    # --- sshd
    elif prog == "sshd":
        row["EVENT_TYPE"] = "SSHD"

        if m2 := SSHD_CONN_RE.match(msg):
            row["ACTION"] = "CONNECT"
            row.update(m2.groupdict())
        elif m2 := SSHD_ACCEPT_RE.match(msg):
            row["ACTION"] = "AUTH_SUCCESS"
            row["USER"] = m2.group("user")
            row["SRC_IP"] = m2.group("src_ip")
            row["SRC_PORT"] = m2.group("src_port")
        elif m2 := SSHD_FAIL_RE.match(msg):
            row["ACTION"] = "AUTH_FAILURE"
            row["USER"] = m2.group("user")
            row["SRC_IP"] = m2.group("src_ip")
            row["SRC_PORT"] = m2.group("src_port")

    # --- PAM
    if pam := PAM_UNIX_RE.match(msg):
        row["EVENT_TYPE"] = "PAM_UNIX"
        row["PAM_SERVICE"] = pam.group("service")
        row["PAM_PHASE"] = pam.group("phase")

        detail = pam.group("detail")
        extra.update(extract_kv(detail))

        if ses := PAM_SESSION_RE.match(detail):
            row["ACTION"] = f"SESSION_{ses.group('action').upper()}"
            row["TARGET_USER"] = ses.group("target_user")

    row["EXTRA_JSON"] = json.dumps(extra, ensure_ascii=False, sort_keys=True)
    return row


# =============================================================================
# 8. CLI ENTRYPOINT
# =============================================================================

def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} /path/to/auth.log", file=sys.stderr)
        return 2

    in_path = sys.argv[1]
    out_path = f"{in_path}.parsed.csv"

    with open(in_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(out_path, "w", newline="", encoding="utf-8") as fout:

        writer = csv.DictWriter(fout, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()

        for line in fin:
            row = parse_line(line)
            if row:
                writer.writerow(row)

    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
