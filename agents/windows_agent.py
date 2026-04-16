import subprocess
import requests
import json
import platform
import os
import socket
import uuid

SERVER_URL = "http://13.62.224.104:8000"

if platform.system() != "Windows":
    print("This agent runs only on Windows.")
    exit()

def login():
    username = input("Username: ")
    password = input("Password: ")

    res = requests.post(
        f"{SERVER_URL}/login",
        data={"username": username, "password": password}
    )

    if res.status_code != 200:
        print("Login failed")
        exit()

    return res.json()["access_token"]

# 🔥 GET REAL IP
def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"


# 🔥 REGISTER OR GET SYSTEM (USING machine_id)
def register_or_get_system():
    machine_id = str(uuid.getnode())

    payload = {
        "hostname": platform.node(),
        "ip_address": get_ip(),
        "os_type": "windows",
        "machine_id": machine_id
    }

    r = requests.post(f"{SERVER_URL}/systems/", json=payload)

    if r.status_code != 200:
        print("System registration failed:", r.text)
        exit()

    return r.json()["id"]


print("[+] Running Windows CIS Scanner...")

# 🔥 RUN SCAN
subprocess.run(["python", os.path.join("agents", "windows_scan.py")])


# 🔥 LOAD RESULTS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(BASE_DIR, "..", "output", "scan.json")

if not os.path.exists(json_path):
    print("scan.json not found!")
    exit()

with open(json_path, "r") as f:
    scan_data = json.load(f)


# 🔥 PARSE RESULTS
parsed_results = []

for rule in scan_data.get("checks", []):
    parsed_results.append({
        "rule_id": str(rule.get("id")),
        "rule_name": rule.get("title"),
        "framework": "CIS Windows 11",
        "severity": rule.get("severity", "MEDIUM").upper(),
        "status": True if rule.get("status") == "PASS" else False,
        "remediation": rule.get("remediation", "N/A")
    })


# 🔥 GET SYSTEM ID (NO FILE STORAGE)
system_id = register_or_get_system()


# 🔥 UPLOAD
payload = {
    "system_id": system_id,
    "results": parsed_results
}

print("[+] Uploading results...")

response = requests.post(
    f"{SERVER_URL}/audit/upload",
    json=payload
)

print("Server response:", response.status_code)
print(response.text)
print(f"👉 Dashboard: http://13.62.224.104/system/{system_id}")
