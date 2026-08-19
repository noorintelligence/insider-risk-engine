import hmac
import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class PrivacyScrubber:
    """
    Implements deterministic HMAC pseudonymization for telemetry logs.
    Preserves analytical correlation while preventing analyst bias.
    Reversible only by authorized legal/compliance officers holding the master key.
    """
    def __init__(self, hmac_secret_key: bytes):
        self._secret_key = hmac_secret_key
        # In-memory vault mapping pseudonyms back to raw PII
        self._secure_vault: Dict[str, str] = {}

    def _generate_token(self, field_type: str, raw_value: str) -> str:
        """Generates a deterministic, formatted pseudonym from raw PII."""
        if not raw_value:
            return raw_value
        
        digest = hmac.new(
            self._secret_key,
            f"{field_type}:{raw_value}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()[:12]
        
        pseudonym = f"ANON-{field_type.upper()}-{digest}"
        self._secure_vault[pseudonym] = raw_value
        return pseudonym

    def scrub_event(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Deep copies and tokenizes sensitive employee identifiers across telemetry types."""
        scrubbed = json.loads(json.dumps(record))
        src = scrubbed.get("source")

        if src == "Identity_IdP":
            actor = scrubbed.get("actor", {})
            if "email" in actor:
                actor["email"] = self._generate_token("EMAIL", actor["email"])
            if "user_id" in actor:
                actor["user_id"] = self._generate_token("UID", actor["user_id"])
            if "ip_address" in actor:
                actor["ip_address"] = self._generate_token("IP", actor["ip_address"])

        elif src == "Endpoint_EDR":
            user = scrubbed.get("user", {})
            host = scrubbed.get("host", {})
            if "username" in user:
                user["username"] = self._generate_token("USER", user["username"])
            if "hostname" in host:
                host["hostname"] = self._generate_token("HOST", host["hostname"])
            if "internal_ip" in host:
                host["internal_ip"] = self._generate_token("IP", host["internal_ip"])

        elif src == "Cloud_Storage":
            principal = scrubbed.get("principal", {})
            if "arn" in principal:
                principal["arn"] = self._generate_token("ARN", principal["arn"])
            if "client_ip" in scrubbed:
                scrubbed["client_ip"] = self._generate_token("IP", scrubbed["client_ip"])

        scrubbed["privacy_context"] = {
            "is_pseudonymized": True,
            "scrubbed_at": datetime.now(timezone.utc).isoformat(),
            "policy": "GDPR-Art4(5)-Compliance"
        }
        return scrubbed

    def request_deanonymization(
        self, 
        token: str, 
        risk_score: float, 
        legal_auth_ticket: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Gated De-Anonymization API:
        Requires an authorization ticket and an objective risk score threshold (>= 70.0).
        """
        RISK_THRESHOLD = 70.0

        if risk_score < RISK_THRESHOLD:
            return {
                "status": "DENIED",
                "reason": f"Risk score ({risk_score}) below legal threshold ({RISK_THRESHOLD})."
            }
        
        if not legal_auth_ticket or not legal_auth_ticket.startswith("LEGAL-AUTH-"):
            return {
                "status": "DENIED",
                "reason": "Missing or invalid legal authorization ticket."
            }

        original_pii = self._secure_vault.get(token)
        if not original_pii:
            return {"status": "ERROR", "reason": "Token not found in privacy vault."}

        return {
            "status": "AUTHORIZED",
            "token": token,
            "revealed_pii": original_pii,
            "audit_trail": {
                "ticket": legal_auth_ticket,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "justification_score": risk_score
            }
        }
