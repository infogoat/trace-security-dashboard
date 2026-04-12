import winreg

FRAMEWORK = "CIS Windows Server 2016"

def get_reg_value(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except:
        return None


def check_smb_signing_required():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "RequireSecuritySignature"
    )

    status = value == 1

    return {
        "rule_id": "2.3.8.1",
        "framework": FRAMEWORK,
        "rule_name": "SMB signing required",
        "severity": "High",
        "status": status,
        "remediation": "Set RequireSecuritySignature = 1"
    }


def run_network_checks():
    return [
        check_smb_signing_required(),
    ]
