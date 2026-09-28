"""
Access Log Analyzer
-------------------
Analyses a login/access log and reports:
  1. the number of access attempts per device (IP address)
  2. the total number of successful and failed attempts
  3. the number of attempts on a chosen day
  4. all failed attempts, saved to a separate file
  5. suspicious IPs with many failed attempts (possible brute-force attack)

Log line format:
    YYYY-MM-DD - HH:MM:SS - <ip address> - success|fail

Usage:
    python log_analyzer.py
    python log_analyzer.py path/to/log.txt --date 2026-09-01 --threshold 5
"""

import argparse
import ipaddress
from pathlib import Path

BASE_DIR = Path(__file__).parent
DEFAULT_LOG = BASE_DIR / "data" / "access_log.txt"
OUTPUT_DIR = BASE_DIR / "output"
FAILED_FILE = OUTPUT_DIR / "failed_attempts.txt"


# ---------------------------------------------------------
# Reading and parsing
# ---------------------------------------------------------
def parse_line(line):
    """Turn one log line into a dict. Raises ValueError if the line is malformed."""
    parts = [part.strip() for part in line.split(" - ")]
    if len(parts) != 4:
        raise ValueError("expected 4 fields separated by ' - '")

    date, time, ip, status = parts
    status = status.lower()

    try:
        ipaddress.ip_address(ip)          # validates both IPv4 and IPv6
    except ValueError:
        raise ValueError(f"'{ip}' is not a valid IP address")

    if status not in ("success", "fail"):
        raise ValueError(f"unknown status '{status}'")

    return {"date": date, "time": time, "ip": ip, "status": status, "raw": line}


def load_log(path):
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(parse_line(line))
            except ValueError as error:
                print(f"Line {line_number} skipped: {error}")
    return entries


# ---------------------------------------------------------
# 1) Count the number of access attempts from each device
# ---------------------------------------------------------
def count_access_per_device(entries):
    device_count = {}
    for entry in entries:
        device_count[entry["ip"]] = device_count.get(entry["ip"], 0) + 1
    return device_count


# ---------------------------------------------------------
# 2) Count number of successes & failures
# ---------------------------------------------------------
def count_success_fail(entries):
    status_count = {"success": 0, "fail": 0}
    for entry in entries:
        status_count[entry["status"]] += 1
    return status_count


# ---------------------------------------------------------
# 3) Number of attempts on a chosen day
# ---------------------------------------------------------
def count_attempts_on_day(entries, target_date):
    return sum(1 for entry in entries if entry["date"] == target_date)


# ---------------------------------------------------------
# 4) Save all failed attempts into a separate file
# ---------------------------------------------------------
def save_failed_attempts(entries, output_path):
    failed_lines = [entry["raw"] for entry in entries if entry["status"] == "fail"]

    output_path.parent.mkdir(exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(failed_lines) + "\n")

    return len(failed_lines)


# ---------------------------------------------------------
# 5) Detect suspicious IPs (possible brute force)
# ---------------------------------------------------------
def find_suspicious_ips(entries, threshold):
    """Return {ip: number_of_failures} for IPs with at least `threshold` failures."""
    failures = {}
    for entry in entries:
        if entry["status"] == "fail":
            failures[entry["ip"]] = failures.get(entry["ip"], 0) + 1
    return {ip: count for ip, count in failures.items() if count >= threshold}


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Analyse an access log file.")
    parser.add_argument("log_file", nargs="?", default=DEFAULT_LOG, type=Path,
                        help="path to the log file (default: data/access_log.txt)")
    parser.add_argument("--date", help="day to count attempts for, e.g. 2026-09-01")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed attempts before an IP is flagged (default: 5)")
    args = parser.parse_args()

    try:
        entries = load_log(args.log_file)
    except FileNotFoundError:
        print(f"File not found: {args.log_file}")
        return

    if not entries:
        print("No valid log entries found.")
        return

    print(f"\nLoaded {len(entries)} valid log entries.")

    print("\n--- Access count per device ---")
    device_access = count_access_per_device(entries)
    for ip, count in sorted(device_access.items(), key=lambda item: item[1], reverse=True):
        print(f"{ip:<16} {count}")

    status_summary = count_success_fail(entries)
    print("\n--- Success/Fail summary ---")
    print(f"Success: {status_summary['success']}")
    print(f"Fail:    {status_summary['fail']}")

    target_date = args.date or input("\nEnter a date to check attempts (e.g. 2026-09-01): ").strip()
    print(f"Attempts on {target_date}: {count_attempts_on_day(entries, target_date)}")

    failed_count = save_failed_attempts(entries, FAILED_FILE)
    print(f"\nSaved {failed_count} failed attempts to output/{FAILED_FILE.name}")

    suspicious = find_suspicious_ips(entries, args.threshold)
    print(f"\n--- Suspicious IPs ({args.threshold}+ failed attempts) ---")
    if suspicious:
        for ip, count in sorted(suspicious.items(), key=lambda item: item[1], reverse=True):
            print(f"[!] {ip:<16} {count} failed attempts")
    else:
        print("None found.")


if __name__ == "__main__":
    main()
