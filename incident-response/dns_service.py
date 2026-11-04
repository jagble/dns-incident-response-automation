"""
dns_service.py - Incident response - Program 2
Runs these parts in order:
  D1  Connect to each internal DNS server and check the DNS service status
  D2  Restart the DNS service on any server where it is down, then check again
  D3  The output of D1 and D2 together shows the full process:
      service down -> restart -> service running
"""

import time

from dns_incident import load_devices, now, pause, run, ssh_connect

DNS_SERVERS = ["DNS1", "DNS2"]
SERVICE = "named"  # BIND9's DNS service


def service_is_running(client):
    exit_code, _ = run(client, f"pgrep -x {SERVICE}")
    return exit_code == 0


def main():
    devices = {d["Device Name"]: d for d in load_devices()}

    # D1 - check each DNS server
    print(f"===== D1: DNS service status ({now()}) =====")
    down = []
    for name in DNS_SERVERS:
        server = devices[name]
        print(f"Connecting to {name} ({server['Device Address']})...")
        client = ssh_connect(server["Device Address"], server["Username"], server["Password"])
        if service_is_running(client):
            print(f"[{now()}] DNS service ({SERVICE}) on {name}: RUNNING\n")
        else:
            print(f"[{now()}] DNS service ({SERVICE}) on {name}: DOWN\n")
            down.append(name)
        client.close()

    if not down:
        print("All DNS services are running - nothing to restart.")
        return
    pause("D1 complete")

    # D2 - restart the service where it is down, then verify
    print(f"===== D2: Restart DNS service ({now()}) =====")
    for name in down:
        server = devices[name]
        client = ssh_connect(server["Device Address"], server["Username"], server["Password"])

        print(f"[{now()}] Restarting the DNS service ({SERVICE}) on {name}...")
        run(client, f"echo {server['Password']} | sudo -S sh -c "
                    f"'systemctl restart {SERVICE} || service {SERVICE} restart || service bind9 restart'")
        time.sleep(3)  # give the service a moment to start

        if service_is_running(client):
            print(f"[{now()}] DNS service ({SERVICE}) on {name}: RUNNING - restart successful\n")
        else:
            print(f"[{now()}] DNS service ({SERVICE}) on {name}: STILL DOWN - restart failed\n")
        client.close()


if __name__ == "__main__":
    main()
