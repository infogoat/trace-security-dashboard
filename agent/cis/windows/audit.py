import winreg

FRAMEWORK = "CIS Windows Server 2016"

def get_reg_value(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except:
        return None


def check_secure_channel_signing():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "RequireSignOrSeal"
    )

    status = value == 1

    return {
        "rule_id": "2.3.6.1",
        "framework": FRAMEWORK,
        "rule_name": "Secure channel signing enabled",
        "severity": "High",
        "status": status,
        "remediation": "Set RequireSignOrSeal = 1"
    }


def check_secure_channel_encryption():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "SealSecureChannel"
    )

    status = value == 1

    return {
        "rule_id": "2.3.6.2",
        "framework": FRAMEWORK,
        "rule_name": "Secure channel encryption enabled",
        "severity": "High",
        "status": status,
        "remediation": "Set SealSecureChannel = 1"
    }


def run_audit_checks():
    return [
        check_secure_channel_signing(),
        check_secure_channel_encryption(),
    ]
