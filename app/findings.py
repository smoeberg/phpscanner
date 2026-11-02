"""Conservative, traceable interpretations of raw HTTP observations."""
import re


PHP_VERSION_RE = re.compile(r"(?i)\\bPHP\\s*/?\\s*(\\d+\\.\\d+(?:\\.\\d+)?)")


def derive_findings(observations: list[dict]) -> list[dict]:
    """Return one qualified PHP disclosure assessment for a scan.

    A disclosed product/version is an observation, not proof of a vulnerability.
    Absence of a signature is never treated as proof that PHP is absent.
    """
    by_type = {item["observation_type"]: item for item in observations}
    powered = by_type.get("x_powered_by")
    server = by_type.get("server_header")
    status = by_type.get("http_status")

    version = None
    if powered:
        match = PHP_VERSION_RE.search(powered["observed_value"])
        if match:
            version = match.group(1)

    evidence_items = [item for item in (status, server, powered) if item]
    evidence = [
        {
            "observation_id": item["id"],
            "observation_type": item["observation_type"],
            "value": item["observed_value"],
            "source": item["source"],
        }
        for item in evidence_items
    ]

    powered_value = powered["observed_value"] if powered else ""
    server_value = server["observed_value"] if server else ""
    if re.search(r"(?i)\\bPHP\\b", powered_value):
        assessment = "disclosed"
        confidence = "high"
        rationale = (
            "X-Powered-By explicitly discloses PHP"
            + (f" version {version}" if version else "")
            + ". This confirms technology disclosure only; it does not establish an outdated or vulnerable runtime."
        )
    elif re.search(r"(?i)\\bPHP\\b", server_value):
        assessment = "possible"
        confidence = "low"
        rationale = (
            "The Server header contains a PHP indicator, but this header alone does not reliably identify the application runtime."
        )
    else:
        assessment = "undetermined"
        confidence = "undetermined"
        if status and status["observed_value"] in {"403", "429"}:
            rationale = (
                f"HTTP {status['observed_value']} limited the observation, and no explicit PHP disclosure was present. "
                "PHP presence cannot be determined from the available headers."
            )
        else:
            rationale = (
                "No explicit PHP disclosure was present in the collected headers. "
                "This is not evidence that PHP is absent."
            )

    return [{
        "finding_type": "php_runtime_disclosure",
        "assessment": assessment,
        "confidence": confidence,
        "version_observed": version,
        "rationale": rationale,
        "evidence": evidence,
    }]
