import requests 
import socket
import platform
import os
import json
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
sys.path.append(PROJECT_ROOT)

from agent.cis.ubuntu_20 import run_all_checks

SERVER_URL = "http://13.62.224.104:8000"
SYSTEM_ID_FILE = "system_id.txt"


def get_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return socket.gethostbyname(socket.gethostname())


def get_system_info():
    hostname = socket.gethostname()
    ip_address = get_ip()
    os_type = platform.system()
    return hostname, ip_address, os_type


def register_system(hostname, ip_address, os_type):
    response = requests.post(
        f"{SERVER_URL}/systems/",
        json={
            "hostname": hostname,
            "ip_address": ip_address,
            "os_type": os_type
        }
    )

    if response.status_code != 200:
        print("Registration failed:", response.text)
        exit()

    data = response.json()
    system_id = data["id"]

    with open(SYSTEM_ID_FILE, "w") as f:
        f.write(str(system_id))

    return system_id


def get_or_register_system():
    if os.path.exists(SYSTEM_ID_FILE):
        with open(SYSTEM_ID_FILE, "r") as f:
            return int(f.read().strip())

    hostname, ip_address, os_type = get_system_info()
    return register_system(hostname, ip_address, os_type)


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

    system_id = get_or_register_system()
    print(f"[+] System ID: {system_id}")

    results = run_audit()
    print(f"[+] Running audit... {len(results)} checks")

    response = upload_results(system_id, results)

    print("[+] Audit Uploaded")
    print("[+] Security Score:")
    print(response)


if __name__ == "__main__":
    main()
