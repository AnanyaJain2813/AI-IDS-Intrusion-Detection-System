"""
Log parser — reads authentication logs in two formats:
  1. Linux auth.log lines (e.g. "sshd[1234]: Failed password for root from 1.2.3.4 port 22")
  2. CSV files with columns: timestamp, ip_address, username, status, port

Both are normalized into the same dict shape so the rest of the pipeline
never has to care which source a record came from.
"""
import csv
import re
from datetime import datetime

AUTH_LOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?"
    r"(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

REQUIRED_CSV_FIELDS = {"timestamp", "ip_address", "username", "status", "port"}


def parse_auth_log(path, year=None):
    """Parse a Linux-style auth.log file into a list of normalized records."""
    year = year or datetime.now().year
    records = []
    with open(path) as f:
        for line in f:
            m = AUTH_LOG_PATTERN.search(line)
            if not m:
                continue
            gd = m.groupdict()
            try:
                ts = datetime.strptime(
                    f"{year} {gd['month']} {gd['day']} {gd['time']}", "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                continue
            records.append({
                "timestamp": ts.isoformat(),
                "ip_address": gd["ip"],
                "username": gd["username"],
                "status": "Success" if gd["status"] == "Accepted" else "Failed",
                "port": int(gd["port"]),
            })
    return records


def parse_csv_log(path):
    """Parse a CSV log file into a list of normalized records."""
    records = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED_CSV_FIELDS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {sorted(missing)}")
        for row in reader:
            records.append({
                "timestamp": row["timestamp"],
                "ip_address": row["ip_address"],
                "username": row["username"],
                "status": row["status"],
                "port": int(row["port"]),
            })
    return records


def parse_log_file(path):
    if path.endswith(".csv"):
        return parse_csv_log(path)
    return parse_auth_log(path)
