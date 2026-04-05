from .filesystem import run_filesystem_checks
from .network import run_network_checks
from .services import run_service_checks
from .auth import run_auth_checks
from .logging import run_logging_checks


def run_all_checks():
    results = []
    results.extend(run_filesystem_checks())
    results.extend(run_network_checks())
    results.extend(run_service_checks())
    results.extend(run_auth_checks())
    results.extend(run_logging_checks())
    return results

