"""
backup_dns_config.py - DNS server configuration backup
Backs up DNS1 and DNS2 configuration to DNS-Backup/Server-1 and Server-2 (record-config.txt).
"""

import os
import re

from network_monitor import load_devices, now, run, ssh_connect

BACKUP_DIR = "DNS-Backup"
DNS_SERVERS = [("DNS1", "Server-1"), ("DNS2", "Server-2")]
DEFAULT_ZONES = ["db.local", "db.127", "db.0", "db.255", "db.empty"]


def backup_server(device, folder):
    name, ip = device["Device Name"], device["Device Address"]
    print(f"Connecting to {name} ({ip})...")
    client = ssh_connect(ip, device["Username"], device["Password"])
    sudo = f"echo {device['Password']} | sudo -S "

    # BIND configuration and service status
    _, config = run(client, sudo + "named-checkconf -p")
    sections = [("BIND configuration (named-checkconf -p)", config)]

    _, status = run(client, "systemctl is-active named; named -v")
    sections.append(("DNS service status and BIND version", status))

    # DNS record (zone) files listed in the configuration
    zone_files = re.findall(r'file\s+"([^"]+)"', config)
    for path in zone_files:
        if os.path.basename(path) in DEFAULT_ZONES:
            continue
        if not path.startswith("/"):
            path = "/var/cache/bind/" + path
        _, records = run(client, sudo + f"cat {path}")
        sections.append((f"DNS records - {path}", records))
    client.close()

    os.makedirs(os.path.join(BACKUP_DIR, folder), exist_ok=True)
    backup_file = os.path.join(BACKUP_DIR, folder, "record-config.txt")
    with open(backup_file, "w") as f:
        f.write(f"DNS configuration backup for {name} ({ip})\n")
        f.write(f"Backup taken: {now()}\n\n")
        for title, text in sections:
            f.write(f"===== {title} =====\n{text}\n\n")

    print(f"  Saved {len(sections)} section(s) to {os.path.abspath(backup_file)}\n")


def main():
    print(f"===== B: DNS configuration backup ({now()}) =====")
    devices = {d["Device Name"]: d for d in load_devices()}
    for name, folder in DNS_SERVERS:
        backup_server(devices[name], folder)

    print(f"Backup location: {os.path.abspath(BACKUP_DIR)}")
    for root, _, files in sorted(os.walk(BACKUP_DIR)):
        depth = root.count(os.sep)
        print("    " * depth + os.path.basename(root) + "/")
        for file in files:
            size = os.path.getsize(os.path.join(root, file))
            print("    " * (depth + 1) + f"{file} ({size} bytes)")


if __name__ == "__main__":
    main()
