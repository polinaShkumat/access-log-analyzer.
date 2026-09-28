# Access Log Analyzer

A small security-oriented Python tool that analyses a login/access log: it counts attempts per device, summarises successes and failures, exports failed attempts and flags IP addresses that look like a **brute-force attack**.

## Features

- Parses and validates every log line, including a real IP check with Python's `ipaddress` module (IPv4 and IPv6); malformed lines are reported and skipped
- Access attempts per IP address, sorted from most to least active
- Total successful vs. failed attempts
- Number of attempts on a chosen day
- Exports all failed attempts to `output/failed_attempts.txt`
- **Brute-force detection**: flags every IP with at least N failed attempts (default 5)

## How to run

Requires Python 3.8+ and no external libraries.

```bash
python log_analyzer.py                                   # sample log, asks for a date
python log_analyzer.py --date 2026-09-02                 # no prompt
python log_analyzer.py my_log.txt --threshold 3          # own log, stricter detection
```

## Log format

```
2026-09-01 - 09:01:03 - 10.0.0.23 - fail
2026-09-01 - 09:01:41 - 10.0.0.23 - success
```

## Example output

```
Line 21 skipped: '999.168.1.1' is not a valid IP address
Line 26 skipped: expected 4 fields separated by ' - '

Loaded 24 valid log entries.

--- Access count per device ---
203.0.113.77     7
10.0.0.23        6
192.168.1.5      4

--- Success/Fail summary ---
Success: 10
Fail:    14
Attempts on 2026-09-02: 10

Saved 14 failed attempts to output/failed_attempts.txt

--- Suspicious IPs (5+ failed attempts) ---
[!] 203.0.113.77     7 failed attempts
[!] 10.0.0.23        5 failed attempts
```

Note that `10.0.0.23` had five failures followed by a success, which is exactly the pattern of a password that was eventually guessed and worth investigating.

## Possible improvements

- Detect failures within a short time window (e.g. 5 fails in 1 minute) instead of a total count
- Read real log formats such as Linux `auth.log`
- Export the report as CSV or JSON

## What I practised

Parsing semi-structured text, input validation, dictionaries for counting, command-line arguments with `argparse`, and a first step into log analysis, one of the core tasks in a Security Operations Center.
