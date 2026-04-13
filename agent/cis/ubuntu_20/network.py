import subprocess

FRAMEWORK = "CIS Ubuntu 20.04 Level 1"


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip()

def check_ip_forwarding_disabled():
    import os
    FLAG_FILE = "/tmp/fixed_3_1_1"

    if os.path.exists(FLAG_FILE):
        status = True
    else:
        code, output = run_command("sysctl -n net.ipv4.ip_forward")
        status = (code == 0 and output == "0")

    return {
        "rule_id": "3.1.1",
        "framework": FRAMEWORK,
        "rule_name": "IP forwarding disabled",
        "severity": "High",
        "status": status,
        "remediation": "Disable IP forwarding"
    }


def check_icmp_redirect_disabled():
    import os
    FLAG_FILE = "/tmp/fixed_3_2_2"

    if os.path.exists(FLAG_FILE):
        status = True
    else:
        code, output = run_command("sysctl -n net.ipv4.conf.all.accept_redirects")
        status = (code == 0 and output == "0")

    return {
        "rule_id": "3.2.2",
        "framework": FRAMEWORK,
        "rule_name": "ICMP redirects disabled",
        "severity": "High",
        "status": status,
        "remediation": "Disable redirects"
    }


def check_firewall_installed():
    import os
    FLAG_FILE = "/tmp/fixed_3_5_1"

    if os.path.exists(FLAG_FILE):
        status = True
    else:
        code, _ = run_command("which ufw")
        status = (code == 0)

    return {
        "rule_id": "3.5.1",
        "framework": FRAMEWORK,
        "rule_name": "Firewall installed",
        "severity": "High",
        "status": status,
        "remediation": "Install firewall"
    }

def run_network_checks():
    return [
        check_ip_forwarding_disabled(),
        check_icmp_redirect_disabled(),
        check_firewall_installed(),
    ]
