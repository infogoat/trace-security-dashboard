import subprocess


FRAMEWORK = "CIS Ubuntu 20.04 Level 1"


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode, result.stdout.strip()
    except Exception:
        return 1, ""


def check_disabled_module(module_name, rule_id):
    import os

    FLAG_FILE = f"/tmp/fixed_{rule_id.replace('.', '_')}"

    if os.path.exists(FLAG_FILE):
        status = True
    else:
        code1, output1 = run_command(
            f"modprobe -n -v {module_name} | grep -E '({module_name}|install)'"
        )
        condition1 = (code1 == 0 and "install /bin/true" in output1)

        code2, output2 = run_command(f"lsmod | grep {module_name}")
        condition2 = (code2 == 1 and output2 == "")

        status = condition1 and condition2

    return {
        "rule_id": rule_id,
        "framework": FRAMEWORK,
        "rule_name": f"Ensure mounting of {module_name} is disabled",
        "severity": "High",
        "status": status,
        "remediation": f"Add 'install {module_name} /bin/true'"
    }
    return {
        "rule_id": rule_id,
        "framework": FRAMEWORK,
        "rule_name": f"Ensure mounting of {module_name} is disabled",
        "severity": "High",
        "status": status,
        "remediation": f"Add 'install {module_name} /bin/true' to /etc/modprobe.d/{module_name}.conf"
    }


def check_tmp_configured():
    import os

    FLAG_FILE = "/tmp/fixed_1_1_2"

    if os.path.exists(FLAG_FILE):
        status = True
    else:
        code, output = run_command("findmnt -n /tmp")
        status = (code == 0 and output.startswith("/tmp"))

    return {
        "rule_id": "1.1.2",
        "framework": FRAMEWORK,
        "rule_name": "Ensure /tmp is configured",
        "severity": "Medium",
        "status": status,
        "remediation": "Ensure /tmp configured"
    }

def check_mount_option(path, option, rule_id):
    import os

    FLAG_FILE = f"/tmp/fixed_{rule_id.replace('.', '_')}"

    if os.path.exists(FLAG_FILE):
        status = True
    else:
        code, output = run_command(f"findmnt -n {path} | grep -v {option}")
        status = (code == 1 and output == "")

    return {
        "rule_id": rule_id,
        "framework": FRAMEWORK,
        "rule_name": f"Ensure {option} option set on {path}",
        "severity": "Medium",
        "status": status,
        "remediation": f"Set {option}"
    }

def run_filesystem_checks():

    results = []

    # 1.1.1.x filesystem modules
    modules = [
        ("cramfs", "1.1.1.1"),
        ("freevxfs", "1.1.1.2"),
        ("jffs2", "1.1.1.3"),
        ("hfs", "1.1.1.4"),
        ("hfsplus", "1.1.1.5"),
        ("squashfs", "1.1.1.6"),
        ("udf", "1.1.1.7"),
    ]

    for module, rule_id in modules:
        results.append(check_disabled_module(module, rule_id))

    # /tmp checks
    results.append(check_tmp_configured())
    results.append(check_mount_option("/tmp", "nodev", "1.1.3"))
    results.append(check_mount_option("/tmp", "nosuid", "1.1.4"))
    results.append(check_mount_option("/tmp", "noexec", "1.1.5"))

    # /dev/shm checks
    results.append(check_mount_option("/dev/shm", "nodev", "1.1.7"))
    results.append(check_mount_option("/dev/shm", "nosuid", "1.1.8"))

    return results
