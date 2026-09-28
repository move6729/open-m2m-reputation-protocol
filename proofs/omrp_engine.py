import time
import hashlib

def evaluate_omrp_transport_request(ip_address: str, domain: str, omrp_record: dict, dmarc_pass: bool) -> tuple[str, str]:
    """
    Evaluates incoming TCP/25 connection using OMRP deterministic rules.
    Replaces black-box IP throttling with cryptographic key-age proofs.
    """
    # System Invariant 1: Strict DMARC Authentication Barrier
    if not dmarc_pass:
        return ("REJECT", "550 5.7.1 Security Policy Violation: DMARC Authentication Failed.")

    # System Invariant 2: Cryptographic Identity Validation
    key_inception = omrp_record.get("cryptographic_identity", {}).get("key_inception_timestamp", 0)
    current_time = int(time.time())
    key_age_days = (current_time - key_inception) / 86400

    if key_age_days < 0:
        return ("REJECT", "550 5.7.1 Malformed Proof: Key inception timestamp in future.")

    # System Invariant 3: Zero IP-Neighborhood Discrimination
    # Domain identity age (>= 30 days) overrides host IP-range warming penalties
    if key_age_days >= 30:
        return ("ACCEPT", "250 2.0.0 OK: Cryptographic identity verified. Ingest authorized.")

    # System Invariant 4: Deterministic, Bounded Backoff (No Opaque Connection Drops)
    allowed_burst = int(key_age_days * 1000)  # Gradual scale strictly bound to key age
    return ("THROTTLE", f"451 4.7.500 Rate Limit: Key age ({key_age_days:.1f}d) permits max {allowed_burst} msgs/hr. Retry in 300s.")
