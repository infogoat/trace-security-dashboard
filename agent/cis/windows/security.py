import winreg

FRAMEWORK = "CIS Windows Server 2016"

def get_reg_value(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except:
        return None


def check_blank_password_limit():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "LimitBlankPasswordUse"
    )

    status = value == 1

    return {
        "rule_id": "2.3.1.4",
        "framework": FRAMEWORK,
        "rule_name": "Limit blank password use",
        "severity": "High",
        "status": status,
        "remediation": "Set LimitBlankPasswordUse = 1"
    }


def check_audit_policy_override():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "SCENoApplyLegacyAuditPolicy"
    )

    status = value == 1

    return {
        "rule_id": "2.3.2.1",
        "framework": FRAMEWORK,
        "rule_name": "Audit policy override enabled",
        "severity": "Medium",
        "status": status,
        "remediation": "Set SCENoApplyLegacyAuditPolicy = 1"
    }


def check_crash_on_audit_fail():
    value = get_reg_value(
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "CrashOnAuditFail"
    )

    status = value == 0

    return {
        "rule_id": "2.3.2.2",
        "framework": FRAMEWORK,
        "rule_name": "Crash on audit fail disabled",
        "severity": "High",
        "status": status,
        "remediation": "Set CrashOnAuditFail = 0"
    }


def run_security_checks():
    return [
        check_blank_password_limit(),
        check_audit_policy_override(),
        check_crash_on_audit_fail(),
    ]
