"""
network_monitor.py - continuous DNS and availability monitoring
Continuously monitors device availability and DNS settings until Ctrl+C.
"""

import csv
import os
import logging
import re
import smtplib
import time
from datetime import datetime
from email.message import EmailMessage

import paramiko
import requests

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

CSV_FILE = "network_devices.csv"
LOG_FILE = "dns_monitor.log"
CHECK_INTERVAL = 30
GOOD_DNS = ["10.10.10.10", "10.10.10.20"]
EXCLUDED = ["SMTP", "SW1", "SW2", "SW3", "SW4", "ROUTER1"]
SSH_PORT = 22
SMTP_SERVER = "10.10.10.100"
SMTP_PORT = 1025
EMAIL_FROM = "network-monitor@d522.wgu.internal"
EMAIL_TO = "network-admin@d522.wgu.internal, stakeholders@d522.wgu.internal"
API_URL = "http://10.10.10.200:5000"
API_TOKEN = os.environ.get("HELPDESK_API_TOKEN", "")  # set this in your environment
API_HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}


# ----- Helper functions -----
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_devices():
    with open(CSV_FILE, newline="") as f:
        return [{k.strip(): v.strip() for k, v in row.items()} for row in csv.DictReader(f)]


def ssh_connect(ip, username, password, sock=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=SSH_PORT, username=username, password=password, sock=sock,
                   timeout=10, look_for_keys=False, allow_agent=False)
    return client


def run(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode(errors="replace").strip()
    return stdout.channel.recv_exit_status(), output


def connect_router(devices):
    router = next(d for d in devices if d["Device Name"] == "ROUTER1")
    return ssh_connect(router["Device Address"], router["Username"], router["Password"])


def connect_device(device, ip, router):
    try:
        return ssh_connect(ip, device["Username"], device["Password"])
    except Exception:
        tunnel = router.get_transport().open_channel("direct-tcpip", (ip, SSH_PORT), ("127.0.0.1", 0))
        return ssh_connect(ip, device["Username"], device["Password"], sock=tunnel)


def get_dhcp_leases(router, device_names):
    _, output = run(router, "/opt/vyatta/bin/vyatta-op-cmd-wrapper show dhcp server leases")
    leases = {}
    for line in output.splitlines():
        words = line.split()
        if words and re.match(r"^\d+\.\d+\.\d+\.\d+$", words[0]):
            for word in words:
                hostname = word.split(".")[0].upper()
                if hostname in device_names:
                    leases[hostname] = words[0]
    return leases


def uses_stub_resolver(client):
    _, output = run(client, "cat /etc/resolv.conf")
    return "nameserver 127.0.0.53" in output


def get_dns_servers(client):
    if uses_stub_resolver(client):
        _, output = run(client, "resolvectl dns")
        servers = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", output)
    else:
        _, output = run(client, "cat /etc/resolv.conf")
        servers = [line.split()[1] for line in output.splitlines() if line.startswith("nameserver")]
    return list(dict.fromkeys(servers))


def fix_dns(client, password):
    sudo = f"echo {password} | sudo -S "
    good = " ".join(GOOD_DNS)
    if uses_stub_resolver(client):
        run(client, sudo + "sed -i '/^#*DNS=/d' /etc/systemd/resolved.conf")
        run(client, sudo + f"sed -i '/^\\[Resolve\\]/a DNS={good}' /etc/systemd/resolved.conf")
        run(client, sudo + "systemctl restart systemd-resolved")
        _, output = run(client, "resolvectl dns")
        for link in re.findall(r"Link \d+ \(([^)]+)\): *\S", output):
            run(client, sudo + f"resolvectl dns {link} {good}")
    else:
        lines = "".join(f"nameserver {ip}\\n" for ip in GOOD_DNS)
        run(client, sudo + f"sh -c \"printf '{lines}' > /etc/resolv.conf\"")


def send_email(subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.set_content(body)
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.send_message(msg)


def create_ticket(title, description, priority):
    response = requests.post(f"{API_URL}/api/tickets", headers=API_HEADERS, timeout=10,
                             json={"title": title, "description": description, "priority": priority})
    print(f"    API response (create ticket): {response.status_code} {response.text}")
    return response.json().get("id") if response.ok else None


def update_ticket(ticket_id, note):
    for status in ["resolved", "closed"]:
        response = requests.patch(f"{API_URL}/api/tickets/{ticket_id}", headers=API_HEADERS,
                                  timeout=10, json={"status": status, "description": note})
        if response.ok:
            break
    print(f"    API response (update ticket): {response.status_code} {response.text}")


def write_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{now()} | {message}\n")


# ----- C2 + C3 - Device unavailable -----
def handle_unavailable(name, ip):
    checked = now()
    print(f"[{checked}] ALERT: {name} ({ip}) is UNAVAILABLE")

    body = ("Dear Network Administrator,\n\n"
            "This is an automated notification that the following network device is currently "
            "unavailable:\n\n"
            f"Device Name: {name}\n"
            f"IP Address: {ip}\n"
            f"Last Checked: {checked}\n\n"
            "Please investigate this issue at your earliest convenience.\n\n"
            "Best regards,\n"
            "Network Monitoring System\n")
    send_email(f"Network Device Unavailable: {name} ({ip})", body)
    print(f"    C2: 'Device Unavailable' email sent for {name}")

    print(f"    C3: creating helpdesk ticket for {name}")
    create_ticket(f"Device unavailable - {name}",
                  f"Issue type: Device unavailable. Device: {name} ({ip}). "
                  f"The device stopped responding to ping at {checked}.",
                  "high")


# ----- C4 - DNS setting altered -----
def handle_altered_dns(device, name, ip, dns_servers, client):
    detected = now()
    current = ", ".join(dns_servers) or "none"
    expected = ", ".join(GOOD_DNS)
    print(f"[{detected}] ALERT: DNS setting on {name} ({ip}) has been ALTERED: {current}")

    body = ("Dear Network Administrator,\n\n"
            "This is an automated alert that the DNS configuration for the following device has "
            "been altered from the expected settings:\n\n"
            f"Device Name: {name}\n"
            f"IP Address: {ip}\n"
            f"Detected DNS Setting: {current}\n"
            f"Expected DNS Setting: {expected}\n"
            f"Time Detected: {detected}\n\n"
            "The system will attempt to automatically correct this configuration.\n\n"
            "Best regards,\n"
            "Network Monitoring System\n")
    send_email(f"DNS Configuration Alert: {name} ({ip})", body)
    print(f"    C4: 'DNS Setting Altered' email sent for {name}")

    print(f"    C4: creating helpdesk ticket for {name}")
    ticket_id = create_ticket(f"DNS setting altered - {name}",
                              f"Issue type: DNS setting altered. Device: {name} ({ip}). "
                              f"Detected DNS: {current}. Expected DNS: {expected}.",
                              "high")

    print(f"    C4: correcting DNS on {name}...")
    fix_dns(client, device["Password"])
    after = get_dns_servers(client)
    print(f"    C4: corrected DNS configuration on {name}: {', '.join(after)}")
    if not (after and all(s in GOOD_DNS for s in after)):
        print(f"    C4: DNS correction FAILED on {name} - ticket left open")
        return

    if ticket_id:
        print(f"    C4: updating ticket {ticket_id} to resolved")
        update_ticket(ticket_id, f"RESOLVED at {now()}: DNS on {name} ({ip}) was automatically "
                                 f"corrected from {current} to {expected}.")

    body = ("Dear Network Administrator,\n\n"
            "The DNS configuration issue previously detected on the following device has been "
            "automatically corrected:\n\n"
            f"Device Name: {name}\n"
            f"IP Address: {ip}\n"
            f"Corrected DNS Setting: {expected}\n"
            f"Time Corrected: {now()}\n\n"
            "No further action is required at this time.\n\n"
            "Best regards,\n"
            "Network Monitoring System\n")
    send_email(f"DNS Configuration Corrected: {name} ({ip})", body)
    print(f"    C4: 'DNS Setting Corrected' email sent for {name}")


# ----- C4 - DNS service stopped on DNS1 or DNS2 -----
def handle_dns_service_down(device, name, ip, client):
    detected = now()
    print(f"[{detected}] ALERT: DNS service (named) on {name} ({ip}) is NOT RUNNING")

    body = ("Dear Network Administrator,\n\n"
            "This is an automated alert that the DNS configuration for the following device has "
            "been altered from the expected settings:\n\n"
            f"Device Name: {name}\n"
            f"IP Address: {ip}\n"
            f"Detected DNS Setting: DNS service (named) stopped\n"
            f"Expected DNS Setting: DNS service (named) running\n"
            f"Time Detected: {detected}\n\n"
            "The system will attempt to automatically correct this configuration.\n\n"
            "Best regards,\n"
            "Network Monitoring System\n")
    send_email(f"DNS Configuration Alert: {name} ({ip})", body)
    print(f"    C4: 'DNS Setting Altered' email sent for {name}")

    print(f"    C4: creating helpdesk ticket for {name}")
    ticket_id = create_ticket(f"DNS service stopped - {name}",
                              f"Issue type: DNS service stopped. Device: {name} ({ip}). "
                              f"The named service was found not running at {detected}.",
                              "high")

    print(f"    C4: restarting the DNS service on {name}...")
    run(client, f"echo {device['Password']} | sudo -S sh -c "
                "'systemctl restart named || service named restart || service bind9 restart'")
    time.sleep(3)
    code, _ = run(client, "pgrep -x named")
    if code != 0:
        print(f"    C4: DNS service on {name} is STILL DOWN - ticket left open")
        return
    print(f"    C4: DNS service (named) on {name} is RUNNING again")

    if ticket_id:
        print(f"    C4: updating ticket {ticket_id} to resolved")
        update_ticket(ticket_id, f"RESOLVED at {now()}: the DNS service (named) on {name} ({ip}) "
                                 f"was automatically restarted and is running.")


# ----- One full check of every monitored device -----
def check_all(devices, unavailable):
    summary = {"DNS OK": 0, "unavailable": 0, "DNS fixed": 0}
    router = connect_router(devices)

    # DHCP IPs are looked up from ROUTER1 at the start of every cycle (not hardcoded)
    leases = get_dhcp_leases(router, [d["Device Name"] for d in devices])
    print(f"[{now()}] Current DHCP leases from ROUTER1 (looked up this cycle):")
    for d in devices:
        if d["Device Address"] == "DHCP":
            print(f"    {d['Device Name']}: {leases.get(d['Device Name'], 'no active lease')}")

    for device in devices:
        name = device["Device Name"]
        if name in EXCLUDED:
            continue
        ip = leases.get(name) if device["Device Address"] == "DHCP" else device["Device Address"]

        # Availability path (C2, C3)
        exit_code, _ = run(router, f"ping -c 2 {ip}") if ip else (1, "")
        if exit_code != 0:
            if name not in unavailable:
                handle_unavailable(name, ip or "no DHCP lease")
                unavailable.add(name)
            else:
                print(f"[{now()}] {name}: still unavailable")
            summary["unavailable"] += 1
            continue
        if name in unavailable:
            print(f"[{now()}] {name} ({ip}) is back ONLINE")
            unavailable.discard(name)

        # DNS path (C4, C5)
        try:
            client = connect_device(device, ip, router)
        except Exception as e:
            print(f"[{now()}] {name}: could not connect over SSH ({type(e).__name__})")
            continue
        if name in ["DNS1", "DNS2"]:
            service_running, _ = run(client, "pgrep -x named")
            if service_running != 0:
                handle_dns_service_down(device, name, ip, client)

        dns_servers = get_dns_servers(client)
        # DNS1/DNS2 use themselves (127.0.0.1) as a resolver, which is valid
        allowed = GOOD_DNS + ["127.0.0.1"] if name in ["DNS1", "DNS2"] else GOOD_DNS
        if dns_servers and all(s in allowed for s in dns_servers):
            note = " | DNS service (named) running" if name in ["DNS1", "DNS2"] else ""
            write_log(f"{name} ({ip}) | DNS OK - not altered | DNS servers: {', '.join(dns_servers)}{note}")
            summary["DNS OK"] += 1
            print(f"[{now()}] {name} ({ip}): UP, DNS OK - logged")
        else:
            handle_altered_dns(device, name, ip, dns_servers, client)
            summary["DNS fixed"] += 1
        client.close()

    router.close()
    print(f"Summary: {summary['DNS OK']} device(s) UP with correct DNS, "
          f"{summary['unavailable']} unavailable, {summary['DNS fixed']} DNS issue(s) fixed this check")


def c1_print_inventory(devices):
    print(f"===== C1: Network device inventory ({now()}) =====")
    print(f"{'Device':<10}{'Address':<17}{'Location':<10}OS")
    print("-" * 48)
    for d in devices:
        print(f"{d['Device Name']:<10}{d['Device Address']:<17}{d['Location']:<10}{d['OS']}")
    print(f"Total devices: {len(devices)}\n")


def main():
    devices = load_devices()
    c1_print_inventory(devices)
    input(">>> C1 complete - take your screenshot, then press Enter to start monitoring...\n")

    unavailable = set()
    print(f"Network monitor started at {now()} - checking every {CHECK_INTERVAL} seconds.")
    print(f"Log file: {LOG_FILE}. Press Ctrl+C to stop.\n")
    try:
        while True:
            print(f"===== Check started {now()} =====")
            try:
                check_all(devices, unavailable)
            except Exception as e:
                print(f"[{now()}] Check failed: {e}")
            print(f"===== Check finished {now()} - next check in {CHECK_INTERVAL} seconds =====\n")
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print(f"\nNetwork monitor stopped at {now()}.")


if __name__ == "__main__":
    main()
