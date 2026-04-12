import subprocess
import requests
import json
import platform
import os
import socket

SERVER_URL = "http://13.62.224.104:8000"
SYSTEM_ID_FILE = "system_id.txt"

if platform.system() != "Windows":
    print("This agent runs only on Windows.")
    exit()


# ✅ REAL IP DETECTION
def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"


def register_system():
    payload = {
        "hostname": platform.node(),
        "ip_address": get_ip(),   # 🔥 FIXED
        "os_type": "windows"
    }

    r = requests.post(f"{SERVER_URL}/systems/", json=payload)

    if r.status_code != 200:
        print("System registration failed:", r.text)
        exit()

    return r.json()["id"]


# ✅ REUSE SYSTEM (IMPORTANT)
if os.path.exists(SYSTEM_ID_FILE):
    with open(SYSTEM_ID_FILE, "r") as f:
        system_id = int(f.read())
else:
    system_id = register_system()
    with open(SYSTEM_ID_FILE, "w") as f:
        f.write(str(system_id))


print("[+] Running Windows CIS Scanner...")

# ✅ safer path
subprocess.run(["python", os.path.join("agents", "windows_scan.py")])


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(BASE_DIR, "..", "output", "scan.json")

if not os.path.exists(json_path):
    print("scan.json not found!")
    exit()

with open(json_path, "r") as f:
    scan_data = json.load(f)

parsed_results = []

for rule in scan_data.get("checks", []):
    parsed_results.append({
        "rule_id": str(rule.get("id")),
        "rule_name": rule.get("title"),
        "framework": "CIS Windows 11",
        "severity": rule.get("severity", "MEDIUM").upper(),
        "status": rule.get("status") == "PASS",
        "remediation": rule.get("remediation", "N/A")
    })


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
