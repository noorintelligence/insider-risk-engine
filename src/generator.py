import json
import uuid
import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

START_TIME = datetime(2026, 8, 1, 8, 0, 0, tzinfo=timezone.utc)
DAYS_SPAN = 5

DEPARTMENTS = ["Engineering", "Finance", "Sales", "HR", "IT_Support", "Legal"]
USERS = [
    {
        "user_id": f"usr_{100 + i}",
        "username": f"user{i}",
        "email": f"user{i}@corp.internal",
        "dept": random.choice(DEPARTMENTS)
    }
    for i in range(40)
]

INSIDER = {
    "user_id": "usr_999",
    "username": "m_jenkins",
    "email": "mjenkins@corp.internal",
    "dept": "Engineering"
}
USERS.append(INSIDER)

STORAGE_BUCKETS = [
    "prod-analytics-raw",
    "customer-invoices-2026",
    "corp-backups-archive",
    "internal-rnd-vault"
]

SENSITIVE_FILES = [
    "customer_db_dump.tar.gz",
    "pci_cardholder_export.parquet",
    "q3_merger_term_sheets.docx",
    "master_privkey.pem"
]


def get_random_working_time() -> datetime:
    """Generates random standard business hours (8:00 AM - 6:00 PM UTC)."""
    day_offset = random.randint(0, DAYS_SPAN - 1)
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return START_TIME + timedelta(days=day_offset, hours=hour - 8, minutes=minute, seconds=second)


def generate_baseline_idp(dt: datetime, user: Dict[str, str]) -> Dict[str, Any]:
    return {
        "source": "Identity_IdP",
        "timestamp": dt.isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": random.choice(["SSO_LOGIN", "MFA_CHALLENGE", "API_TOKEN_ISSUE"]),
        "actor": {
            "user_id": user["user_id"],
            "email": user["email"],
            "ip_address": f"192.168.10.{random.randint(2, 250)}",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "department": user["dept"]
        },
        "auth_details": {
            "method": random.choice(["SAML", "OIDC", "PASSKEY"]),
            "mfa_type": random.choice(["TOTP", "PUSH_NOTIFICATION", "HARDWARE_TOKEN"]),
            "target_role": "StandardEmployeeRole"
        },
        "status": "SUCCESS" if random.random() > 0.05 else "FAILURE"
    }


def generate_baseline_edr(dt: datetime, user: Dict[str, str]) -> Dict[str, Any]:
    return {
        "source": "Endpoint_EDR",
        "timestamp": dt.isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": random.choice(["PROCESS_SPAWN", "FILE_WRITE"]),
        "host": {
            "hostname": f"wkst-{user['username']}-corp",
            "os": "macOS 15.1" if user["dept"] in ["Engineering", "HR"] else "Windows 11 Enterprise",
            "internal_ip": f"192.168.20.{random.randint(2, 250)}"
        },
        "user": {
            "username": user["username"],
            "domain": "CORP",
            "is_privileged": False
        },
        "process": {
            "process_id": random.randint(1000, 65000),
            "name": random.choice(["slack", "chrome", "code", "zoom", "git"]),
            "path": "/usr/local/bin/app",
            "command_line": f"app --worker-process={random.randint(1, 4)}",
            "parent_process_id": random.randint(500, 999)
        }
    }


def generate_baseline_cloud(dt: datetime, user: Dict[str, str]) -> Dict[str, Any]:
    return {
        "source": "Cloud_Storage",
        "timestamp": dt.isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": random.choice(["GetObject", "PutObject", "ListBucket"]),
        "bucket_name": random.choice(STORAGE_BUCKETS),
        "object_key": f"daily_logs/{uuid.uuid4().hex[:8]}.log",
        "bytes_sent": random.randint(1024, 5242880),
        "principal": {
            "arn": f"arn:aws:iam::123456789012:user/{user['username']}",
            "account_id": "123456789012"
        },
        "client_ip": f"192.168.10.{random.randint(2, 250)}",
        "status_code": 200
    }


def generate_threat_scenarios() -> List[Dict[str, Any]]:
    """Injects a 3-stage insider threat sequence for m_jenkins."""
    threat_events = []

    # Stage 1: Off-Hours Scripted Login & Privilege Escalation
    t1 = START_TIME + timedelta(days=2, hours=15, minutes=15)  # 23:15 UTC
    threat_events.append({
        "source": "Identity_IdP",
        "timestamp": t1.isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": "SSO_LOGIN",
        "actor": {
            "user_id": INSIDER["user_id"],
            "email": INSIDER["email"],
            "ip_address": "198.51.100.24",
            "user_agent": "python-requests/2.31.0",
            "department": INSIDER["dept"]
        },
        "auth_details": {"method": "SAML", "mfa_type": "PUSH_NOTIFICATION", "target_role": "StandardEmployeeRole"},
        "status": "SUCCESS"
    })
    threat_events.append({
        "source": "Identity_IdP",
        "timestamp": (t1 + timedelta(seconds=12)).isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": "ROLE_ASSIGNMENT",
        "actor": {
            "user_id": INSIDER["user_id"],
            "email": INSIDER["email"],
            "ip_address": "198.51.100.24",
            "user_agent": "python-requests/2.31.0",
            "department": INSIDER["dept"]
        },
        "auth_details": {"method": "OIDC", "mfa_type": "NONE", "target_role": "GlobalStorageAdmin"},
        "status": "SUCCESS"
    })

    # Stage 2: Mass Off-Hours Cloud Exfiltration
    t2 = t1 + timedelta(minutes=10)
    for idx, file_key in enumerate(SENSITIVE_FILES):
        file_time = t2 + timedelta(minutes=idx * 4, seconds=random.randint(5, 30))
        threat_events.append({
            "source": "Cloud_Storage",
            "timestamp": file_time.isoformat(),
            "event_id": str(uuid.uuid4()),
            "event_type": "GetObject",
            "bucket_name": "internal-rnd-vault",
            "object_key": f"confidential/prod/{file_key}",
            "bytes_sent": random.randint(500000000, 3500000000),  # 500MB - 3.5GB
            "principal": {
                "arn": "arn:aws:iam::123456789012:role/GlobalStorageAdmin",
                "account_id": "123456789012"
            },
            "client_ip": "198.51.100.24",
            "status_code": 200
        })

    # Stage 3: USB Mount & CLI Staging
    t3 = START_TIME + timedelta(days=3, hours=-6, minutes=45)  # 01:15 UTC next day
    threat_events.append({
        "source": "Endpoint_EDR",
        "timestamp": t3.isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": "USB_CONNECT",
        "host": {"hostname": f"wkst-{INSIDER['username']}-corp", "os": "macOS 15.1", "internal_ip": "192.168.20.99"},
        "user": {"username": INSIDER["username"], "domain": "CORP", "is_privileged": True},
        "process": {"process_id": 412, "name": "kernel_task", "path": "/System/Library/Kernels/kernel", "command_line": "", "parent_process_id": 0},
        "device_details": {
            "device_vendor": "SanDisk Extreme SSD",
            "serial_number": "SD-99823-EXP-001",
            "mount_point": "/Volumes/EXT_STORAGE",
            "bytes_transferred": 0
        }
    })
    threat_events.append({
        "source": "Endpoint_EDR",
        "timestamp": (t3 + timedelta(minutes=2, seconds=10)).isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": "SHELL_EXEC",
        "host": {"hostname": f"wkst-{INSIDER['username']}-corp", "os": "macOS 15.1", "internal_ip": "192.168.20.99"},
        "user": {"username": INSIDER["username"], "domain": "CORP", "is_privileged": True},
        "process": {
            "process_id": 8920,
            "name": "bash",
            "path": "/bin/bash",
            "command_line": "tar -czvf /Volumes/EXT_STORAGE/staged_exports.tar.gz ~/Downloads/confidential/*",
            "parent_process_id": 8919
        }
    })
    threat_events.append({
        "source": "Endpoint_EDR",
        "timestamp": (t3 + timedelta(minutes=4, seconds=45)).isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": "FILE_WRITE",
        "host": {"hostname": f"wkst-{INSIDER['username']}-corp", "os": "macOS 15.1", "internal_ip": "192.168.20.99"},
        "user": {"username": INSIDER["username"], "domain": "CORP", "is_privileged": True},
        "process": {"process_id": 8920, "name": "tar", "path": "/usr/bin/tar", "command_line": "tar", "parent_process_id": 8919},
        "device_details": {
            "device_vendor": "SanDisk Extreme SSD",
            "serial_number": "SD-99823-EXP-001",
            "mount_point": "/Volumes/EXT_STORAGE",
            "bytes_transferred": 7820491024
        }
    })

    return threat_events


def generate_telemetry(count: int = 10000, out_file: str = "telemetry.jsonl") -> None:
    """Generates synthetic baseline logs + threat patterns and writes to JSONL."""
    events = []
    generators = [generate_baseline_idp, generate_baseline_edr, generate_baseline_cloud]

    for _ in range(count):
        ts = get_random_working_time()
        user = random.choice(USERS)
        gen = random.choice(generators)
        events.append(gen(ts, user))

    threat_events = generate_threat_scenarios()
    events.extend(threat_events)

    events.sort(key=lambda x: x["timestamp"])

    with open(out_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
