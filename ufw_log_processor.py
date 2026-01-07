#!/usr/bin/env python3
"""
Generic, structured syslog parser for SIEM/Splunk ingestion.

Goals:
- Stream input (no full-file reads)
- Preserve original message verbatim (MESSAGE column)
- Promote meaningful fields into first-class columns
- Put everything else into EXTRA_JSON (a JSON object)
- Handle unknown/future record types gracefully

Input example:
Jan  2 10:47:21 ubuntu-ad kernel: [ 1572.110651] [UFW BLOCK] IN=ens37 OUT= MAC=... SRC=... DST=... PROTO=... SPT=... DPT=...

Output:
<input>.parsed.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from typing import Dict, Tuple, Optional, List


# -----------------------------
# 1) Header parsing (syslog-ish)
# -----------------------------
# Do NOT guess year or timezone; keep timestamp exactly as present in the log.
SYSLOG_RE = re.compile(
    r"^(?P<TS>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<HOST>\S+)\s+"
    r"(?P<PROGRAM>[A-Za-z0-9_.-]+)(?:\[(?P<PID>\d+)\])?:\s*"
    r"(?P<REST>.*)$"
)

# -----------------------------
# 2) Known deterministic formats
# -----------------------------
# Linux kernel prefix: "[ 1572.110651] ..." optionally present
KERNEL_UPTIME_RE = re.compile(r"^\[\s*(?P<UPTIME_SEC>\d+(?:\.\d+)?)\]\s*(?P<AFTER>.*)$")

# UFW tag: "[UFW ALLOW]" / "[UFW BLOCK]" / "[UFW AUDIT]" etc.
UFW_TAG_RE = re.compile(r"^\[(?P<UFW_TAG>UFW\s+[A-Z]+)\]\s*(?P<AFTER>.*)$")


# -------------------------------------------------
# 3) Generic key=value scraping + bare flag scraping
# -------------------------------------------------
# Key=Value pairs where value is a non-space token (typical in these logs)
KV_RE = re.compile(r"(?P<K>[A-Za-z0-9_.-]+)=(?P<V>\S*)")

# Bare flags sometimes appear without '=' (e.g., DF, SYN, ACK, PSH)
# We only treat ALL-CAPS/0-9/_ tokens as flags to avoid grabbing random words.
FLAG_TOKEN_RE = re.compile(r"\b[A-Z0-9_]{2,}\b")


def scrape_kv_and_flags(text: str) -> Tuple[Dict[str, str], List[str], str]:
    """
    Scrape key=value pairs deterministically and also detect uppercase bare flags.

    Returns:
      kv: dict of key->value (last one wins if repeated)
      flags: list of bare flags detected (order preserved, de-duped)
      remaining_text: original text with key=value removed (useful if you later add more parsers)
    """
    kv: Dict[str, str] = {}
    flags: List[str] = []

    # Extract kv pairs
    for m in KV_RE.finditer(text):
        k = m.group("K")
        v = m.group("V")
        kv[k] = v

    # Remove kv pairs for flag scanning to reduce false positives
    remaining_text = KV_RE.sub(" ", text)

    # Extract bare flags (de-dupe but keep order)
    seen = set()
    for m in FLAG_TOKEN_RE.finditer(remaining_text):
        tok = m.group(0)
        # Skip obvious non-flags that are part of UFW tag (already parsed) or common words
        # Keep this minimal to avoid fragile assumptions.
        if tok in seen:
            continue
        seen.add(tok)
        flags.append(tok)

    # Tidy remaining text
    remaining_text = " ".join(remaining_text.split())
    return kv, flags, remaining_text


def normalize_action_event_type(program: str, ufw_tag: Optional[str], kv: Dict[str, str], flags: List[str]) -> Tuple[str, str]:
    """
    Derive EVENT_TYPE and ACTION from deterministic indicators.
    Avoid guessing; if unknown, leave blank.
    """
    event_type = ""
    action = ""

    if ufw_tag:
        event_type = "FIREWALL"
        # UFW tags are like "UFW ALLOW", "UFW BLOCK", "UFW AUDIT"
        parts = ufw_tag.split()
        if len(parts) >= 2:
            action = parts[1]  # ALLOW/BLOCK/AUDIT

    # Kernel messages could be other types too; we keep it conservative.
    if not event_type and program.lower() == "kernel":
        event_type = "KERNEL"

    return event_type, action


def promote_fields(host: str, program: str, pid: str, ts: str, message_rest: str) -> Dict[str, str]:
    """
    Promote common SIEM-ish fields into first-class columns.
    Everything else goes to EXTRA_JSON.
    """
    original_message = f"{ts} {host} {program}{'['+pid+']' if pid else ''}: {message_rest}"

    row: Dict[str, str] = {
        # Common SIEM columns (uppercase)
        "TIMESTAMP": ts,          # no year/tz guessing
        "HOST": host,
        "PROGRAM": program,
        "PID": pid or "",
        "EVENT_TYPE": "",
        "ACTION": "",
        "USER": "",
        "SRC_IP": "",
        "DST_IP": "",
        "SRC_PORT": "",
        "DST_PORT": "",
        "PROTOCOL": "",
        "INTERFACE_IN": "",
        "INTERFACE_OUT": "",
        "MAC": "",
        "MESSAGE": original_message,  # preserve verbatim
        "EXTRA_JSON": "",             # filled later
    }

    extra: Dict[str, object] = {}

    # Kernel uptime prefix (deterministic)
    after = message_rest
    m_up = KERNEL_UPTIME_RE.match(after)
    if m_up:
        extra["KERNEL_UPTIME_SEC"] = m_up.group("UPTIME_SEC")
        after = m_up.group("AFTER")

    # UFW tag (deterministic)
    ufw_tag = None
    m_ufw = UFW_TAG_RE.match(after)
    if m_ufw:
        ufw_tag = m_ufw.group("UFW_TAG")
        extra["UFW_TAG"] = ufw_tag
        after = m_ufw.group("AFTER")

    # Generic scrape of KV and flags from the remainder
    kv, flags, remaining_text = scrape_kv_and_flags(after)

    # Promote well-known network fields when present (do not invent)
    # Typical UFW keys: IN, OUT, SRC, DST, PROTO, SPT, DPT, MAC, LEN, TOS, PREC, TTL, ID, WINDOW, RES, URGP, etc.
    # Promote common ones; keep the rest in EXTRA_JSON.
    if "SRC" in kv:
        row["SRC_IP"] = kv.get("SRC", "")
    if "DST" in kv:
        row["DST_IP"] = kv.get("DST", "")
    if "SPT" in kv:
        row["SRC_PORT"] = kv.get("SPT", "")
    if "DPT" in kv:
        row["DST_PORT"] = kv.get("DPT", "")
    if "PROTO" in kv:
        row["PROTOCOL"] = kv.get("PROTO", "")
    if "IN" in kv:
        row["INTERFACE_IN"] = kv.get("IN", "")
    if "OUT" in kv:
        row["INTERFACE_OUT"] = kv.get("OUT", "")
    if "MAC" in kv:
        row["MAC"] = kv.get("MAC", "")

    # Derive EVENT_TYPE and ACTION conservatively
    event_type, action = normalize_action_event_type(program, ufw_tag, kv, flags)
    row["EVENT_TYPE"] = event_type
    row["ACTION"] = action

    # Put everything not promoted into EXTRA_JSON
    promoted_keys = {"SRC", "DST", "SPT", "DPT", "PROTO", "IN", "OUT", "MAC"}
    for k, v in kv.items():
        if k not in promoted_keys:
            extra[k] = v

    if flags:
        extra["FLAGS"] = flags
    if remaining_text:
        # Keep any leftover text that wasn't kv/flags (future-proofing)
        extra["REMAINDER_TEXT"] = remaining_text

    row["EXTRA_JSON"] = json.dumps(extra, ensure_ascii=False, separators=(",", ":")) if extra else "{}"
    return row


def parse_line(line: str) -> Dict[str, str]:
    """
    Parse a single log line into a normalized row.
    Unknown formats are handled gracefully:
    - If syslog header doesn't match, treat the whole line as MESSAGE and put minimal fields.
    """
    line = line.rstrip("\n")

    m = SYSLOG_RE.match(line)
    if not m:
        # Unknown/unsupported header: preserve verbatim and avoid guessing fields.
        return {
            "TIMESTAMP": "",
            "HOST": "",
            "PROGRAM": "",
            "PID": "",
            "EVENT_TYPE": "",
            "ACTION": "",
            "USER": "",
            "SRC_IP": "",
            "DST_IP": "",
            "SRC_PORT": "",
            "DST_PORT": "",
            "PROTOCOL": "",
            "INTERFACE_IN": "",
            "INTERFACE_OUT": "",
            "MAC": "",
            "MESSAGE": line,
            "EXTRA_JSON": json.dumps({"UNPARSED": True}, separators=(",", ":")),
        }

    ts = m.group("TS")
    host = m.group("HOST")
    program = m.group("PROGRAM")
    pid = m.group("PID") or ""
    rest = m.group("REST")

    return promote_fields(host, program, pid, ts, rest)


def main() -> int:
    ap = argparse.ArgumentParser(description="Stream-parse syslog-like logs to normalized CSV for SIEM ingestion.")
    ap.add_argument("logfile", help="Path to input log file")
    args = ap.parse_args()

    in_path = args.logfile
    out_path = in_path + ".parsed.csv"

    # Fixed schema (stable for SIEM ingestion)
    fieldnames = [
        "TIMESTAMP",
        "HOST",
        "PROGRAM",
        "PID",
        "EVENT_TYPE",
        "ACTION",
        "USER",
        "SRC_IP",
        "DST_IP",
        "SRC_PORT",
        "DST_PORT",
        "PROTOCOL",
        "INTERFACE_IN",
        "INTERFACE_OUT",
        "MAC",
        "MESSAGE",
        "EXTRA_JSON",
    ]

    with open(in_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(out_path, "w", encoding="utf-8", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for line in fin:  # streaming
            if not line.strip():
                continue
            row = parse_line(line)
            writer.writerow(row)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
