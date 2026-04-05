import subprocess

FRAMEWORK = "CIS Ubuntu 20.04 Level 1"


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip()


def check_ip_forwarding_disabled():
    code, output = run_command("sysctl -n net.ipv4.ip_forward")
    status = (code == 0 and output == "0")

    return {
        "rule_id": "3.1.1",
        "framework": FRAMEWORK,
        "rule_name": "IP forwarding disabled",
        "severity": "High",
        "status": status,
        "remediation": "Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf"
    }


def check_icmp_redirect_disabled():
    code, output = run_command("sysctl -n net.ipv4.conf.all.accept_redirects")
    status = (code == 0 and output == "0")

    return {
        "rule_id": "3.2.2",
        "framework": FRAMEWORK,
        "rule_name": "ICMP redirects disabled",
        "severity": "High",
        "status": status,
        "remediation": "Set net.ipv4.conf.all.accept_redirects = 0"
    }


def check_firewall_installed():
    code, _ = run_command("which ufw")
    status = (code == 0)

    return {
        "rule_id": "3.5.1",
        "framework": FRAMEWORK,
        "rule_name": "Firewall installed",
        "severity": "High",
        "status": status,
        "remediation": "Install and configure UFW"
    }


def run_network_checks():
    return [
        check_ip_forwarding_disabled(),
        check_icmp_redirect_disabled(),
        check_firewall_installed(),
    ]
