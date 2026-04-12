import winreg

FRAMEWORK = "CIS Windows Server 2016"

def get_reg_value(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except:
        return None


def check_inactivity_timeout():
    value = get_reg_value(
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "InactivityTimeoutSecs"
    )

    status = value is not None and value != 0 and value <= 900

    return {
        "rule_id": "2.3.7.3",
        "framework": FRAMEWORK,
        "rule_name": "Inactivity timeout <= 900",
        "severity": "Medium",
        "status": status,
        "remediation": "Set InactivityTimeoutSecs <= 900 and not 0"
    }


def run_system_checks():
    return [
        check_inactivity_timeout(),
    ]
