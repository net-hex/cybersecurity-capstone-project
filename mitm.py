from mitmproxy import http
import re
import csv
import os
from datetime import datetime

# --- Simple PHI patterns ---
PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),   # SSN
    re.compile(r"\bpatient\b", re.I),
    re.compile(r"\bdiagnosis\b", re.I),
    re.compile(r"\bprescription\b", re.I),
    re.compile(r"\bmedical record\b", re.I),
]
# Change to whatever the output file name is
CSV_FILE = "dlp_log.csv"

# --- Ensure CSV has headers once ---
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "type", "url", "pattern", "sample"])

# Covers for edge cases
def safe_text(message):
    try:
        if not message:
            return ""
        return message.get_text(strict=False) or ""
    except Exception:
        return ""

# Match patterns for PHI filter
def match_pattern(text):
    for p in PATTERNS:
        try:
            if p.search(text):
                return p.pattern
        except Exception:
            continue
    return None


# Writes to the csv file
def write_csv(row):
    try:
        with open(CSV_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)
    except Exception:
        # Never crash proxy due to logging
        pass


def request(flow: http.HTTPFlow):
    try:
        text = safe_text(flow.request)
        if not text:
            return

        pattern = match_pattern(text)
        if pattern:
            row = [
                datetime.utcnow().isoformat(),
                "request",
                flow.request.pretty_url,
                pattern,
                text[:200]
            ]

            print("\n🚨 DLP REQUEST DETECTED")
            print(flow.request.pretty_url)

            write_csv(row)

    except Exception:
        return


def response(flow: http.HTTPFlow):
    try:
        if not flow.response:
            return

        text = safe_text(flow.response)
        if not text:
            return

        pattern = match_pattern(text)
        if pattern:
            row = [
                datetime.utcnow().isoformat(),
                "response",
                flow.request.pretty_url,
                pattern,
                text[:200]
            ]

            print("\n⚠️ DLP RESPONSE DETECTED")
            print(flow.request.pretty_url)

            write_csv(row)

    except Exception:
        return
