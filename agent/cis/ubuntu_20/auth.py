import subprocess

FRAMEWORK = "CIS Ubuntu 20.04 Level 1"


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip()


def check_ssh_root_disabled():
    code, output = run_command("grep '^PermitRootLogin' /etc/ssh/sshd_config")
    status = ("no" in output.lower())

    return {
        "rule_id": "5.2.8",
        "framework": FRAMEWORK,
        "rule_name": "SSH root login disabled",
        "severity": "Critical",
        "status": status,
        "remediation": "Set PermitRootLogin no in sshd_config"
    }


def check_password_min_length():
    code, output = run_command("grep '^minlen' /etc/security/pwquality.conf")
    status = False
    if code == 0:
        try:
            value = int(output.split("=")[1])
            status = value >= 8
        except:
            pass

    return {
        "rule_id": "5.5.1",
        "framework": FRAMEWORK,
        "rule_name": "Password minimum length >= 8",
        "severity": "High",
        "status": status,
        "remediation": "Set minlen = 8 in pwquality.conf"
    }


def run_auth_checks():
    return [
        check_ssh_root_disabled(),
        check_password_min_length(),
    ]
