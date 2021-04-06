# /usr/bin/env python3
import yaml
import scp
import glob
import paramiko
import time


with open("config.yml") as config:
    config_parsed = yaml.load(config, Loader=yaml.FullLoader)

connections = []
pending_configures = []

for router_name, router in config_parsed["routers"].items():
    hostname = router.get("hostname")
    if not hostname:
        continue

    print(f"Connecting to {router_name} - {hostname}")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy)
    ssh_client.connect(hostname, username=router["ssh_user"], compress=True)

    connections.append((router_name, ssh_client))

for router_name, ssh_client in connections:
    print(f"Uploading config to {router_name}")

    scp_client = scp.SCPClient(ssh_client.get_transport())
    scp_client.put(glob.glob(f"./out/{router_name}/*"), recursive=True, remote_path="/opt/bird-conf/")

    print(f"Applying config to {router_name}")
    ssh_client.exec_command("birdc configure timeout 60")
    pending_configures.append((time.monotonic(), ssh_client, router_name))

while len(pending_configures):
    to_remove = []
    for client in pending_configures:
        if time.monotonic() - client[0] > 30:
            to_remove.append(client)
            print(f"Confirming config on {client[2]}")
            client[1].exec_command("birdc configure confirm")

    for r in to_remove:
        pending_configures.remove(r)

    time.sleep(5)
