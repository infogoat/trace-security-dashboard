import sys
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

sys.path.append(PROJECT_ROOT)

from agent.cis.windows.runner import run_all_windows_checks


def run_scan():
    checks = run_all_windows_checks()

    output_dir = os.path.join(BASE_DIR, "..", "output")
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, "scan.json")

    with open(output_path, "w") as f:
        json.dump({"checks": checks}, f, indent=4)

    print("[+] Windows scan completed")


if __name__ == "__main__":
    run_scan()
