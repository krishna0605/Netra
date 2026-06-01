"""Human-readable anomaly explanation helpers."""


def explain_score(reason: str) -> str:
    return reason


def recommended_action(behaviour: str, hypothesis: str) -> str:
    behaviour_l = behaviour.lower()
    hypothesis_l = hypothesis.lower()
    if "dns" in behaviour_l:
        return "Review resolver logs, queried domains, and the endpoint process that generated the DNS traffic."
    if "service access" in behaviour_l or "brute" in hypothesis_l:
        return "Correlate with authentication logs and isolate the source if the attempts are unauthorized."
    if "fan-out" in behaviour_l or "scan" in hypothesis_l:
        return "Check whether the source is approved for scanning; otherwise contain it and inspect contacted services."
    if "transfer" in behaviour_l or "exfiltration" in hypothesis_l:
        return "Identify the destination owner, transferred service, and whether sensitive data left the network."
    if "beacon" in behaviour_l or "c2" in hypothesis_l:
        return "Correlate destination reputation with threat intelligence and preserve endpoint logs."
    if "service" in behaviour_l:
        return "Review server logs and patch or isolate the exposed service if the activity is unauthorized."
    return "Review the linked packets, sessions, alerts, and Zeek logs before closing this anomaly."
