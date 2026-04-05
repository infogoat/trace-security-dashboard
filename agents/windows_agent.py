import subprocess
import requests
import json
import platform
import os

if platform.system() != "Windows":
    print("This agent runs only on Windows.")
    exit()

system_id = 5
EC2_IP = "13.49.245.123"

print("Running Windows CIS Scanner...")
subprocess.run(["python", "main.py"])

json_path = os.path.join("output", "scan.json")

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
        "severity": "medium",
        "status": True if rule.get("status") == "PASS" else False,
        "remediation": rule.get("remediation", "N/A")
    })

payload = {
    "system_id": system_id,
    "results": parsed_results
}

print("Uploading results to backend...")

response = requests.post(
    f"http://{EC2_IP}:8000/audit/upload",
    json=payload
)

print("Server response:", response.status_code)
print(response.text)
