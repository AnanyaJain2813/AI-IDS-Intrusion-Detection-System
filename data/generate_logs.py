import csv
import random
import uuid
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# Configuration
NUM_ENTITIES_MIN = 200
NUM_ENTITIES_MAX = 500
WEEKS = random.randint(2, 4)  # number of weeks of data
START_DATE = datetime.now() - timedelta(weeks=WEEKS)
END_DATE = datetime.now()

ENTITY_TYPES = ["user", "service_account", "edge_device"]
RESOURCE_POOL = [
    "/api/v1/login",
    "/api/v1/logout",
    "/api/v1/get_user",
    "/api/v1/update_profile",
    "/api/v1/upload_file",
    "/api/v1/download_file",
    "/api/v1/delete_account",
    "/api/v1/list_devices",
    "/api/v1/trigger_backup",
    "/api/v1/health_check",
]
AUTH_METHODS = ["password", "token", "certificate", "biometric"]
OS_FIRMWARE = [
    "Windows 10/2023-01",
    "Ubuntu 22.04/2023-06",
    "macOS 13.2/2023-03",
    "Raspbian 11/2022-12",
]
COMMANDS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
PATTERNS = [
    "brute_force",
    "impossible_travel",
    "credential_stuffing",
    "lateral_movement",
    "device_spoofing",
    "low_and_slow_exfiltration",
    "insider_drift",
    "normal",
]

def random_timestamp(base_start, base_end, hour_range=(8, 18)):
    """Generate a timestamp within working hours (default 8am‑6pm)."""
    total_seconds = int((base_end - base_start).total_seconds())
    rand_seconds = random.randint(0, total_seconds)
    dt = base_start + timedelta(seconds=rand_seconds)
    hour = random.randint(*hour_range)
    dt = dt.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
    return dt.isoformat()

# Pre‑generate entities with stable geo location and device fingerprint
entities = []
for _ in range(random.randint(NUM_ENTITIES_MIN, NUM_ENTITIES_MAX)):
    entity_id = str(uuid.uuid4())
    entity_type = random.choice(ENTITY_TYPES)
    geo_location = f"{fake.city()}, {fake.country()}"
    device_fingerprint = f"{random.choice(OS_FIRMWARE)} / {fake.mac_address()}"
    entities.append({
        "entity_id": entity_id,
        "entity_type": entity_type,
        "geo_location": geo_location,
        "device_fingerprint": device_fingerprint,
    })

sessions = []
session_id = 0
for entity in entities:
    days = (END_DATE - START_DATE).days
    # Approx 5‑15 sessions per day per entity
    num_sessions = random.randint(days * 5, days * 15)
    for _ in range(num_sessions):
        session_id += 1
        timestamp = random_timestamp(START_DATE, END_DATE)
        source_ip = fake.ipv4()
        resource_accessed = random.choice(RESOURCE_POOL)
        auth_method = random.choice(AUTH_METHODS)
        session_duration = round(random.expovariate(1 / 300), 2)  # avg 5 min
        cmd_seq_len = random.randint(1, 5)
        command_sequence = ";".join(random.choices(COMMANDS, k=cmd_seq_len))
        label = "normal"
        sessions.append({
            "session_id": session_id,
            "entity_id": entity["entity_id"],
            "entity_type": entity["entity_type"],
            "timestamp": timestamp,
            "source_ip": source_ip,
            "geo_location": entity["geo_location"],
            "resource_accessed": resource_accessed,
            "auth_method": auth_method,
            "session_duration": session_duration,
            "command_sequence": command_sequence,
            "device_fingerprint": entity["device_fingerprint"],
            "label": label,
        })

# Inject anomalous patterns (0.5‑3 % of sessions)
total_sessions = len(sessions)
num_anomalies = int(total_sessions * random.uniform(0.005, 0.03))
anomaly_indices = random.sample(range(total_sessions), num_anomalies)
for idx in anomaly_indices:
    session = sessions[idx]
    pattern = random.choice(PATTERNS[:-1])  # exclude "normal"
    session["label"] = pattern
    if pattern == "brute_force":
        session["auth_method"] = "password"
        session["source_ip"] = fake.ipv4(public=True)
        session["session_duration"] = round(random.uniform(1, 5), 2)
    elif pattern == "impossible_travel":
        session["geo_location"] = f"{fake.city()}, {fake.country()}"
    elif pattern == "credential_stuffing":
        session["auth_method"] = "token"
        session["resource_accessed"] = "/api/v1/login"
    elif pattern == "lateral_movement":
        session["resource_accessed"] = "/api/v1/list_devices"
        session["command_sequence"] = "GET;POST;GET"
    elif pattern == "device_spoofing":
        session["device_fingerprint"] = f"{random.choice(OS_FIRMWARE)} / {fake.mac_address()}"
    elif pattern == "low_and_slow_exfiltration":
        session["resource_accessed"] = "/api/v1/download_file"
        session["session_duration"] = round(random.uniform(600, 3600), 2)
    elif pattern == "insider_drift":
        session["resource_accessed"] = random.choice(["/api/v1/update_profile", "/api/v1/delete_account"])
        session["auth_method"] = random.choice(["password", "biometric"])

# Write CSV files
sample_logs_path = "data/sample_logs.csv"
labels_path = "data/labels.csv"

import os
os.makedirs(os.path.dirname(sample_logs_path), exist_ok=True)

with open(sample_logs_path, "w", newline="") as f:
    writer = csv.writer(f)
    header = [
        "session_id",
        "entity_id",
        "entity_type",
        "timestamp",
        "source_ip",
        "geo_location",
        "resource_accessed",
        "auth_method",
        "session_duration",
        "command_sequence",
        "device_fingerprint",
    ]
    writer.writerow(header)
    for s in sessions:
        writer.writerow([
            s["session_id"],
            s["entity_id"],
            s["entity_type"],
            s["timestamp"],
            s["source_ip"],
            s["geo_location"],
            s["resource_accessed"],
            s["auth_method"],
            s["session_duration"],
            s["command_sequence"],
            s["device_fingerprint"],
        ])

with open(labels_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["session_id", "label"])
    for s in sessions:
        writer.writerow([s["session_id"], s["label"]])

if __name__ == "__main__":
    print(f"Generated {total_sessions} sessions for {len(entities)} entities.")
    print(f"Sample logs -> {sample_logs_path}")
    print(f"Labels      -> {labels_path}")
