import sys
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

sys.path.append(PROJECT_ROOT)

from agent.cis.windows.runner import run_all_windows_checks


def run_scan():
    print("[+] Running Windows CIS checks...")

    try:
        checks = run_all_windows_checks()
    except Exception as e:
        print("❌ Error running checks:", str(e))
        sys.exit(1)

    # 🚨 VALIDATION LAYER (CRITICAL)
    valid_checks = []

    for idx, check in enumerate(checks):

        if not isinstance(check, dict):
            print(f"❌ Invalid check format at index {idx}: {check}")
            continue

        if not check.get("id"):
            print(f"❌ Missing ID in check {idx}: {check}")
            continue

        # ✅ Normalize structure
        valid_checks.append({
            "id": str(check["id"]),
            "title": check.get("title") or check.get("name") or f"Rule {check['id']}",
            "status": check.get("status", "FAIL"),
            "severity": (check.get("severity") or "MEDIUM").upper(),
            "remediation": check.get("remediation") or "N/A"
        })

    print(f"[DEBUG] Total checks: {len(checks)}")
    print(f"[DEBUG] Valid checks: {len(valid_checks)}")

    if len(valid_checks) == 0:
        print("❌ No valid checks found — scan is useless")
        sys.exit(1)

    output_dir = os.path.join(BASE_DIR, "..", "output")
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, "scan.json")

    with open(output_path, "w") as f:
        json.dump({"checks": valid_checks}, f, indent=4)

    print("[+] Windows scan completed")
    print(f"[+] Output saved to: {output_path}")


if __name__ == "__main__":
    run_scan()
