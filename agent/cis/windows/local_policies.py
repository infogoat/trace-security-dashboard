import winreg

FRAMEWORK = "CIS Windows Server 2016"

def get_reg_value(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except:
        return None


def check_ctrl_alt_del_required():
    value = get_reg_value(
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD"
    )

    status = value == 0

    return {
        "rule_id": "2.3.7.2",
        "framework": FRAMEWORK,
        "rule_name": "CTRL+ALT+DEL required",
        "severity": "High",
        "status": status,
        "remediation": "Set DisableCAD = 0"
    }


def run_local_policy_checks():
    return [
        check_ctrl_alt_del_required(),
    ]
