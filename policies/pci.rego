package pci

default decision := {
    "status": "MANUAL_REVIEW",
    "severity": "MEDIUM",
    "reason": "Manual evidence review is required"
}

decision := {
    "status": "PASS",
    "severity": "NONE",
    "reason": "Evidence passed the control"
} if input.result == "PASS"

decision := {
    "status": "FAIL",
    "severity": input.severity_if_failed,
    "reason": input.reason
} if input.result == "FAIL"