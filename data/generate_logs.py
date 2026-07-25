"""
Generates a synthetic dataset of authentication log entries: mostly
normal logins, plus injected attack patterns (brute force, off-hours,
root targeting, SSH scanning) so the model has something realistic to
learn from and the dashboard has something to show.

Usage:
    python data/generate_logs.py --out data/sample_logs.csv --n 1000
"""
import argparse
import csv
import random
from datetime import datetime, timedelta

NORMAL_USERNAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
ATTACK_USERNAMES = ["root", "admin", "administrator", "test", "oracle", "postgres"]
COMMON_PORTS = [22, 443, 3389, 3306, 5432]

random.seed(42)


def random_ip(subnet_pool):
    return random.choice(subnet_pool)


def make_normal_event(base_time, benign_ips):
    ts = base_time + timedelta(seconds=random.randint(0, 86400 * 7))
    hour = 8 + (ts.hour % 10)  # bias toward working hours
    ts = ts.replace(hour=hour % 24)
    return {
        "timestamp": ts.isoformat(),
        "ip_address": random_ip(benign_ips),
        "username": random.choice(NORMAL_USERNAMES),
        "status": "Success" if random.random() > 0.05 else "Failed",
        "port": 22,
    }


def make_brute_force_burst(base_time, attacker_ip):
    events = []
    start = base_time + timedelta(seconds=random.randint(0, 86400 * 7))
    for i in range(random.randint(15, 40)):
        ts = start + timedelta(seconds=i * random.randint(1, 4))
        events.append({
            "timestamp": ts.isoformat(),
            "ip_address": attacker_ip,
            "username": random.choice(ATTACK_USERNAMES),
            "status": "Failed",
            "port": 22,
        })
    return events


def make_off_hours_event(base_time, ip_pool):
    ts = base_time + timedelta(seconds=random.randint(0, 86400 * 7))
    ts = ts.replace(hour=random.choice([0, 1, 2, 3, 4]))
    return {
        "timestamp": ts.isoformat(),
        "ip_address": random_ip(ip_pool),
        "username": random.choice(NORMAL_USERNAMES + ATTACK_USERNAMES),
        "status": "Failed" if random.random() > 0.3 else "Success",
        "port": 22,
    }


def make_port_scan_burst(base_time, attacker_ip):
    events = []
    start = base_time + timedelta(seconds=random.randint(0, 86400 * 7))
    for i, port in enumerate(random.sample(range(1, 65535), random.randint(10, 25))):
        ts = start + timedelta(seconds=i)
        events.append({
            "timestamp": ts.isoformat(),
            "ip_address": attacker_ip,
            "username": "unknown",
            "status": "Failed",
            "port": port,
        })
    return events


def generate(n_total, out_path):
    base_time = datetime.now() - timedelta(days=7)
    benign_ips = [f"192.168.1.{i}" for i in range(2, 30)]
    attacker_ips = [f"45.33.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(8)]

    records = []
    n_normal = int(n_total * 0.75)
    for _ in range(n_normal):
        records.append(make_normal_event(base_time, benign_ips))

    remaining = n_total - n_normal
    while len(records) < n_total:
        kind = random.random()
        if kind < 0.4:
            records.extend(make_brute_force_burst(base_time, random.choice(attacker_ips)))
        elif kind < 0.7:
            records.append(make_off_hours_event(base_time, benign_ips + attacker_ips))
        else:
            records.extend(make_port_scan_burst(base_time, random.choice(attacker_ips)))

    records.sort(key=lambda r: r["timestamp"])
    records = records[:n_total] if len(records) > n_total else records

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "ip_address", "username", "status", "port"])
        writer.writeheader()
        writer.writerows(records)

    print(f"Generated {len(records)} log entries -> {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="data/sample_logs.csv")
    parser.add_argument("--n", type=int, default=1000)
    args = parser.parse_args()
    generate(args.n, args.out)
