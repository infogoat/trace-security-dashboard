import subprocess
import requests
import json
import platform
import os
import socket
import uuid
import sys

SERVER_URL = "http://13.62.224.104:8000"

# ===============================
# ❌ RUN ONLY ON WINDOWS
# ===============================
if platform.system() != "Windows":
    print("This agent runs only on Windows.")
    sys.exit()


# ===============================
# 🔐 LOGIN (AUTH REQUIRED)
# ===============================
def login():
    username = input("Username: ")
    password = input("Password: ")

    res = requests.post(
        f"{SERVER_URL}/login",
        data={"username": username, "password": password}
    )

    if res.status_code != 200:
        print("❌ Login failed:", res.text)
        print("👉 Register at: http://13.62.224.104/register")
        sys.exit()

    return res.json()["access_token"]


# ===============================
# 🌐 GET IP
# ===============================
def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"


# ===============================
# 💻 SYSTEM INFO
# ===============================
def get_system_info():
    hostname = platform.node()
    ip_address = get_ip()
    os_type = "windows"
    machine_id = str(uuid.getnode())

    return hostname, ip_address, os_type, machine_id


# ===============================
# 🖥️ REGISTER SYSTEM (AUTH)
# ===============================
def register_or_get_system(token, hostname, ip, os_type, machine_id):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "hostname": hostname,
        "ip_address": ip,
        "os_type": os_type,
        "machine_id": machine_id
    }

    res = requests.post(
        f"{SERVER_URL}/systems/",
        json=payload,
        headers=headers
    )

    if res.status_code != 200:
        print("❌ System registration failed:", res.text)
        sys.exit()

    return res.json()["id"]


# ===============================
# 🔍 RUN WINDOWS SCAN
# ===============================
def run_scan():
    print("[+] Running Windows CIS Scanner...")

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(BASE_DIR, "windows_scan.py")
    result = subprocess.run(["python", script_path])

    if result.returncode != 0:
        print("❌ Scan execution failed")
        sys.exit()

    print("[+] Windows scan completed")


# ===============================
# 📂 LOAD SCAN RESULTS
# ===============================
def load_results():
    import os
    import sys
    import json

    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "..", "output", "scan.json")

    if not os.path.exists(json_path):
        print("❌ scan.json not found!")
        sys.exit()

    with open(json_path, "r") as f:
        scan_data = json.load(f)

    parsed_results = []

    for rule in scan_data.get("checks", []):

        # 🚨 HARD CHECK — DO NOT ALLOW MISSING ID
        if not rule.get("id"):
            print("❌ ERROR: Missing rule ID:", rule)
            continue

        rule_id = str(rule["id"])

        # ✅ FLAG LOGIC (for remediation simulation)
        flag_path = f"C:\\temp\\fixed_{rule_id.replace('.', '_')}"

        if os.path.exists(flag_path):
            status = True
        else:
            status = True if rule.get("status") == "PASS" else False

        parsed_results.append({
            "rule_id": rule_id,

            "rule_name": rule.get("title")
                or rule.get("name")
                or f"Rule {rule_id}",

            "framework": "CIS Windows 11",

            "severity": (rule.get("severity") or "MEDIUM").upper(),

            "status": status,

            "remediation": rule.get("remediation") or "N/A"
        })

    print(f"[DEBUG] Parsed {len(parsed_results)} results")

    return parsed_results

# ===============================
# 📤 UPLOAD RESULTS (AUTH)
# ===============================
def upload_results(token, system_id, results):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    res = requests.post(
        f"{SERVER_URL}/audit/upload",
        json={
            "system_id": system_id,
            "results": results
        },
        headers=headers
    )

    if res.status_code != 200:
        print("❌ Upload failed:", res.text)
        sys.exit()

    return res.json()


# ===============================
# 🚀 MAIN
# ===============================
def main():
    print("[+] TRACE Windows Agent Starting")

    # 🔐 LOGIN FIRST
    token = login()

    # 💻 SYSTEM INFO
    hostname, ip, os_type, machine_id = get_system_info()

    # 🖥️ REGISTER SYSTEM
    system_id = register_or_get_system(
        token, hostname, ip, os_type, machine_id
    )

    print(f"[+] System ID: {system_id}")

    # 🔍 RUN SCAN
    run_scan()

    # 📂 LOAD RESULTS
    results = load_results()

    print(f"[+] Parsed {len(results)} checks")

    # 📤 UPLOAD
    response = upload_results(token, system_id, results)

    print("[+] Audit Uploaded")
    print("[+] Security Score:", response.get("security_score"))

    print(f"👉 Dashboard: http://13.62.224.104/system/{system_id}")


# ===============================
# ▶️ ENTRY
# ===============================
if __name__ == "__main__":
    main()
