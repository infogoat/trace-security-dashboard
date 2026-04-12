import winreg

FRAMEWORK = "CIS Windows Server 2016"

def get_reg_value(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except:
        return None


def check_max_password_age():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "MaximumPasswordAge"
    )

    status = value is not None and value != 0 and value <= 60

    return {
        "rule_id": "1.1.2",
        "framework": FRAMEWORK,
        "rule_name": "Maximum password age <= 60 and not 0",
        "severity": "High",
        "status": status,
        "remediation": "Set MaximumPasswordAge to <= 60 and not 0"
    }


def check_block_microsoft_accounts():
    value = get_reg_value(
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "NoConnectedUser"
    )

    status = value == 3

    return {
        "rule_id": "2.3.1.2",
        "framework": FRAMEWORK,
        "rule_name": "Block Microsoft accounts",
        "severity": "Medium",
        "status": status,
        "remediation": "Set NoConnectedUser = 3"
    }


def run_account_checks():
    return [
        check_max_password_age(),
        check_block_microsoft_accounts(),
    ]
