import requests
import socket
import platform
import os
import sys
import uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

from agent.cis.ubuntu_20 import run_all_checks

SERVER_URL = "http://13.62.224.104:8000"


def get_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return socket.gethostbyname(socket.gethostname())


def get_system_info():
    hostname = socket.gethostname()
    ip_address = get_ip()
    os_type = platform.system()

    # 🔥 MACHINE UNIQUE ID (KEY FIX)
    machine_id = str(uuid.getnode())

    return hostname, ip_address, os_type, machine_id


def register_or_get_system(hostname, ip_address, os_type, machine_id):
    response = requests.post(
        f"{SERVER_URL}/systems/",
        json={
            "hostname": hostname,
            "ip_address": ip_address,
            "os_type": os_type,
            "machine_id": machine_id
        }
    )

    if response.status_code != 200:
        print("Registration failed:", response.text)
        exit()

    return response.json()["id"]


def run_audit():
    return run_all_checks()


def upload_results(system_id, results):
    response = requests.post(
        f"{SERVER_URL}/audit/upload",
        json={
            "system_id": system_id,
            "results": results
        }
    )

    if response.status_code != 200:
        print("Upload failed:", response.text)
        return None

    return response.json()


def main():
    print("[+] TRACE Linux Agent Starting")

    hostname, ip_address, os_type, machine_id = get_system_info()

    system_id = register_or_get_system(
        hostname, ip_address, os_type, machine_id
    )

    print(f"[+] System ID: {system_id}")

    results = run_audit()
    print(f"[+] Running audit... {len(results)} checks")

    response = upload_results(system_id, results)

    print("[+] Audit Uploaded")
    print("[+] Security Score:")
    print(response)


if __name__ == "__main__":
    main()
