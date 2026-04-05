import subprocess

FRAMEWORK = "CIS Ubuntu 20.04 Level 1"


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip()


def check_telnet_removed():
    code, _ = run_command("dpkg -l | grep telnet")
    status = (code != 0)

    return {
        "rule_id": "2.2.1",
        "framework": FRAMEWORK,
        "rule_name": "Telnet not installed",
        "severity": "High",
        "status": status,
        "remediation": "Remove telnet package"
    }


def check_rsh_removed():
    code, _ = run_command("dpkg -l | grep rsh-client")
    status = (code != 0)

    return {
        "rule_id": "2.2.2",
        "framework": FRAMEWORK,
        "rule_name": "RSH client not installed",
        "severity": "High",
        "status": status,
        "remediation": "Remove rsh-client package"
    }


def run_service_checks():
    return [
        check_telnet_removed(),
        check_rsh_removed(),
    ]
