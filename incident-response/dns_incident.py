"""
dns_incident.py - Incident response - Program 1
Runs these parts in order:
  B1  Load the device list from the CSV file
  B2  Find the DHCP IPs, ping each device, and check its DNS settings
  C1  Email an incident alert listing the compromised devices
  C2  Create a helpdesk ticket for each compromised device
  D4  Fix the DNS settings on each compromised device
  E   Email a resolution notice listing the fixed devices
Parts D1-D3 (the DNS service itself) are in dns_service.py.
"""

import csv
import os
import logging
import re
import smtplib
from datetime import datetime
from email.message import EmailMessage

import paramiko
import requests

logging.getLogger("paramiko").setLevel(logging.CRITICAL)  # hide paramiko's internal error dumps

CSV_FILE = "network_devices.csv"
GOOD_DNS = ["10.10.10.10", "10.10.10.20"]                  # DNS1 and DNS2
EXCLUDED = ["SMTP", "SW1", "SW2", "SW3", "SW4", "ROUTER1"]  # not analyzed, per the lab notes
SSH_PORT = 22
SMTP_SERVER = "10.10.10.100"  # smtp.d522.wgu.internal
SMTP_PORT = 1025
API_URL = "http://10.10.10.200:5000"  # api.d522.wgu.internal
API_TOKEN = os.environ.get("HELPDESK_API_TOKEN", "")  # set this in your environment


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def pause(message):
    """Wait for Enter so there's time to take a screenshot."""
    input(f"\n>>> {message} - take your screenshot, then press Enter to continue...\n")


def load_devices():
    """Read the CSV file and return a list of devices (one dictionary per row)."""
    with open(CSV_FILE, newline="") as f:
        return [{k.strip(): v.strip() for k, v in row.items()} for row in csv.DictReader(f)]


def ssh_connect(ip, username, password, sock=None):
    """Open an SSH connection to a device."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=SSH_PORT, username=username, password=password, sock=sock,
                   timeout=10, look_for_keys=False, allow_agent=False)
    return client


def run(client, command):
    """Run a command over SSH. Returns (exit_code, output)."""
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode().strip()
    return stdout.channel.recv_exit_status(), output


def connect_device(device, ip, router):
    """SSH to a device. If the firewall blocks a direct connection, go through ROUTER1."""
    try:
        return ssh_connect(ip, device["Username"], device["Password"])
    except Exception:
        tunnel = router.get_transport().open_channel("direct-tcpip", (ip, SSH_PORT), ("127.0.0.1", 0))
        return ssh_connect(ip, device["Username"], device["Password"], sock=tunnel)


def get_dhcp_leases(router, device_names):
    """Ask ROUTER1 which IP it leased to each DHCP device. Returns e.g. {"PC1": "192.168.10.50"}."""
    _, output = run(router, "/opt/vyatta/bin/vyatta-op-cmd-wrapper show dhcp server leases")
    leases = {}
    for line in output.splitlines():
        words = line.split()
        if words and re.match(r"^\d+\.\d+\.\d+\.\d+$", words[0]):  # lines that start with an IP
            for word in words:
                hostname = word.split(".")[0].upper()
                if hostname in device_names:                        # the hostname column
                    leases[hostname] = words[0]
    return leases


def uses_stub_resolver(client):
    """True if /etc/resolv.conf points at 127.0.0.53 (systemd-resolved's stub resolver)."""
    _, output = run(client, "cat /etc/resolv.conf")
    return "nameserver 127.0.0.53" in output


def get_dns_servers(client):
    """
    Return the DNS servers the device really uses.
    127.0.0.53 is only the local stub resolver, so in that case the real
    servers are looked up with 'resolvectl dns'.
    """
    if uses_stub_resolver(client):
        _, output = run(client, "resolvectl dns")
        servers = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", output)
    else:
        _, output = run(client, "cat /etc/resolv.conf")
        servers = [line.split()[1] for line in output.splitlines() if line.startswith("nameserver")]
    return list(dict.fromkeys(servers))  # remove duplicates, keep the order


def send_email(subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "network-monitor@d522.wgu.internal"
    msg["To"] = "stakeholders@d522.wgu.internal"
    msg.set_content(body)
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.send_message(msg)


# ---------------------------------------------------------------------------
# B1 - Load the device list
# ---------------------------------------------------------------------------
def b1_load_devices():
    print(f"===== B1: Network device list ({now()}) =====")
    devices = load_devices()
    for device in devices:
        print(f"  {device['Device Name']}")
    print(f"Total devices: {len(devices)}")
    return devices


# ---------------------------------------------------------------------------
# B2 - Ping each device and check its DNS settings
# ---------------------------------------------------------------------------
def b2_check_devices(devices, router):
    print(f"===== B2: Device status and DNS check ({now()}) =====")
    names = [d["Device Name"] for d in devices]
    leases = get_dhcp_leases(router, names)  # current IPs of the DHCP devices

    print(f"{'Device':<9}{'IP Address':<17}{'Ping':<7}{'DNS Servers':<28}DNS Check")
    print("-" * 72)
    compromised = []
    for device in devices:
        name = device["Device Name"]
        if name in EXCLUDED:
            continue

        ip = leases.get(name) if device["Device Address"] == "DHCP" else device["Device Address"]
        if not ip:
            print(f"{name:<9}{'no lease':<17}{'DOWN':<7}{'-':<28}UNKNOWN")
            continue

        # Ping from ROUTER1, which can reach every network segment
        exit_code, _ = run(router, f"ping -c 2 {ip}")
        status = "UP" if exit_code == 0 else "DOWN"

        dns_servers = []
        dns_check = "UNKNOWN"
        # DNS1 and DNS2 run the DNS service themselves, so 127.0.0.1 (their own service) is internal too
        allowed = GOOD_DNS + ["127.0.0.1"] if name in ["DNS1", "DNS2"] else GOOD_DNS
        try:
            client = connect_device(device, ip, router)
            dns_servers = get_dns_servers(client)
            client.close()
            dns_check = "OK" if all(s in allowed for s in dns_servers) and dns_servers else "ROGUE"
        except Exception as e:
            print(f"   could not connect to {name} over SSH ({type(e).__name__})")

        print(f"{name:<9}{ip:<17}{status:<7}{', '.join(dns_servers) or '-':<28}{dns_check}")
        if dns_check == "ROGUE":
            bad = ", ".join(s for s in dns_servers if s not in allowed) or "none set"
            print(f"   WARNING: {name} is misconfigured to use non-internal DNS server {bad}")
            compromised.append({"device": device, "name": name, "ip": ip, "status": status,
                                "dns_servers": dns_servers, "checked": now()})

    print(f"\nCompromised devices: {', '.join(d['name'] for d in compromised) or 'none'}")
    return compromised


# ---------------------------------------------------------------------------
# C1 - Incident alert email
# ---------------------------------------------------------------------------
def c1_send_alert(compromised):
    print(f"===== C1: Incident alert email ({now()}) =====")
    device_text = ""
    for d in compromised:
        device_text += (f"Device Name: {d['name']}\n"
                        f"IP Address: {d['ip']}\n"
                        f"Service: DNS\n"
                        f"Last Checked: {d['checked']}\n\n")

    body = ("Dear Stakeholders,\n\n"
            "This is an automated alert to inform you that the following device(s) have been "
            "identified as compromised during the recent network scan:\n\n"
            f"{device_text}"
            "Immediate investigation and remediation are recommended to prevent further impact.\n\n"
            "If you have any questions or require additional information, please contact the IT "
            "support team.\n\n"
            "Best regards,\n"
            "Network Monitoring System\n")

    send_email("URGENT: Device Compromise Detected—Immediate Attention Required", body)
    print(f"Alert email sent to stakeholders at {now()}")
    print("View it in MailHog: http://mail.d522.wgu.internal:8025/")


# ---------------------------------------------------------------------------
# C2 - One helpdesk ticket per compromised device
# ---------------------------------------------------------------------------
def c2_create_tickets(compromised):
    print(f"===== C2: Helpdesk tickets ({now()}) =====")
    headers = {"Authorization": f"Bearer {API_TOKEN}"}

    response = requests.get(f"{API_URL}/api/health", timeout=10)
    print(f"Connected to {API_URL} - health check: {response.status_code} {response.text}\n")

    for d in compromised:
        bad = ", ".join(s for s in d["dns_servers"] if s not in GOOD_DNS)
        ticket = {
            "title": f"Rogue DNS configuration - {d['name']}",
            "description": f"Issue type: Rogue DNS configuration. "
                           f"Target device: {d['name']} ({d['ip']}). "
                           f"Device status: {d['status']}. "
                           f"Using non-internal DNS server: {bad}.",
            "priority": "high",
        }
        response = requests.post(f"{API_URL}/api/tickets", json=ticket, headers=headers, timeout=10)
        print(f"{d['name']}: {response.status_code} {response.text}\n")


# ---------------------------------------------------------------------------
# D4 - Fix DNS on each compromised device
# ---------------------------------------------------------------------------
def fix_dns(client, password):
    """Point the device's DNS at DNS1 and DNS2."""
    sudo = f"echo {password} | sudo -S "
    good = " ".join(GOOD_DNS)

    if uses_stub_resolver(client):
        # systemd-resolved: set the global DNS servers, then each network link's servers
        run(client, sudo + "sed -i '/^#*DNS=/d' /etc/systemd/resolved.conf")
        run(client, sudo + f"sed -i '/^\\[Resolve\\]/a DNS={good}' /etc/systemd/resolved.conf")
        run(client, sudo + "systemctl restart systemd-resolved")
        _, output = run(client, "resolvectl dns")
        for link in re.findall(r"Link \d+ \(([^)]+)\): *\S", output):
            run(client, sudo + f"resolvectl dns {link} {good}")
    else:
        # plain /etc/resolv.conf: rewrite the nameserver lines
        lines = "".join(f"nameserver {ip}\\n" for ip in GOOD_DNS)
        run(client, sudo + f"sh -c \"printf '{lines}' > /etc/resolv.conf\"")


def d4_fix_devices(compromised, router):
    print(f"===== D4: Fix DNS settings ({now()}) =====")
    fixed = []
    for d in compromised:
        print(f"\n--- {d['name']} ({d['ip']}) - {now()} ---")
        client = connect_device(d["device"], d["ip"], router)
        print(f"DNS before: {', '.join(get_dns_servers(client))}")
        fix_dns(client, d["device"]["Password"])
        after = get_dns_servers(client)
        client.close()
        print(f"DNS after:  {', '.join(after)}")

        if after and all(s in GOOD_DNS for s in after):
            print(f"DNS settings successfully updated on {d['name']}")
            fixed.append(d)
        else:
            print(f"DNS update FAILED on {d['name']}")
        pause(f"D4 screenshot for {d['name']}")
    return fixed


# ---------------------------------------------------------------------------
# E - Resolution email
# ---------------------------------------------------------------------------
def e_send_resolution(fixed):
    print(f"===== E: Resolution email ({now()}) =====")
    device_list = "\n".join(f"- Hostname: {d['name']}, IP Address: {d['ip']}" for d in fixed)

    body = ("Dear Stakeholders,\n\n"
            "This is an automated notification to inform you that the DNS service issue and all "
            "related device compromises have been successfully resolved. The following devices "
            "were affected and have now been remediated:\n\n"
            f"{device_list}\n\n"
            "No further action is required at this time. If you have any questions or concerns, "
            "please contact the IT support team.\n\n"
            "Thank you for your attention.\n\n"
            "Best regards,\n"
            "Network Monitoring System\n")

    send_email("RESOLVED: DNS Service Issue and Device Compromise—All Issues Remediated", body)
    print(f"Resolution email sent to stakeholders at {now()}")
    print(device_list)
    print("View it in MailHog: http://mail.d522.wgu.internal:8025/")


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------
def main():
    devices = b1_load_devices()
    pause("B1 complete")

    router_info = next(d for d in devices if d["Device Name"] == "ROUTER1")
    router = ssh_connect(router_info["Device Address"], router_info["Username"], router_info["Password"])

    compromised = b2_check_devices(devices, router)
    pause("B2 complete")
    if not compromised:
        print("No compromised devices found - nothing more to do.")
        router.close()
        return

    c1_send_alert(compromised)
    pause("C1 complete - screenshot the email in MailHog too")

    c2_create_tickets(compromised)
    pause("C2 complete")

    fixed = d4_fix_devices(compromised, router)
    router.close()

    e_send_resolution(fixed)
    print("\nDone. Screenshot the resolution email in MailHog.")


if __name__ == "__main__":
    main()
