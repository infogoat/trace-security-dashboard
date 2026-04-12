def run_all_windows_checks():
    from .account import run_account_checks
    from .security import run_security_checks
    from .audit import run_audit_checks
    from .local_policies import run_local_policy_checks
    from .network import run_network_checks
    from .system import run_system_checks

    return (
        run_account_checks() +
        run_security_checks() +
        run_audit_checks() +
        run_local_policy_checks() +
        run_network_checks() +
        run_system_checks()
    )
