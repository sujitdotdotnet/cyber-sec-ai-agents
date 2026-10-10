from .incident_response import run_incident_response
from .log_monitor import run_log_monitor
from .policy_checker import run_policy_checker
from .threat_intel import run_threat_intel
from .vuln_scanner import run_vuln_scanner

AGENTS = {
    "log_monitor": run_log_monitor,
    "vuln_scanner": run_vuln_scanner,
    "threat_intel": run_threat_intel,
    "incident_response": run_incident_response,
    "policy_checker": run_policy_checker,
}

__all__ = ["AGENTS"]
