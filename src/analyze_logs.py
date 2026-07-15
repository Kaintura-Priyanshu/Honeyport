#!/usr/bin/env python3
"""
Quick summary report over honeypot_events.jsonl:
  - top source IPs
  - top attempted username/password pairs
  - events per service

Usage:
    python3 src/analyze_logs.py [path/to/honeypot_events.jsonl]
"""

import json
import sys
from collections import Counter


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/honeypot_events.jsonl"

    ip_counter = Counter()
    service_counter = Counter()
    creds_counter = Counter()
    total = 0

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total += 1
                ip_counter[event.get("src_ip", "unknown")] += 1
                service_counter[event.get("service", "unknown")] += 1

                details = event.get("details", {})
                if "username" in details and "password" in details:
                    creds_counter[(details["username"], details["password"])] += 1
    except FileNotFoundError:
        print(f"No log file found at {path}. Run the honeypot first.")
        return

    print(f"Total events: {total}\n")

    print("Top source IPs:")
    for ip, count in ip_counter.most_common(10):
        print(f"  {ip:<20} {count}")

    print("\nEvents by service:")
    for service, count in service_counter.most_common():
        print(f"  {service:<10} {count}")

    print("\nTop attempted username/password pairs:")
    for (user, pw), count in creds_counter.most_common(10):
        print(f"  {user!r:<20} {pw!r:<20} {count}")


if __name__ == "__main__":
    main()
