import subprocess

FRAMEWORK = "CIS Ubuntu 20.04 Level 1"


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip()


def check_auditd_enabled():
    code, output = run_command("systemctl is-enabled auditd")
    status = (code == 0 and output == "enabled")

    return {
        "rule_id": "4.1.1",
        "framework": FRAMEWORK,
        "rule_name": "Auditd enabled",
        "severity": "High",
        "status": status,
        "remediation": "Enable auditd service"
    }


def run_logging_checks():
    return [
        check_auditd_enabled(),
    ]
