class GatewaySecurityEngine:
    def evaluate(self, telemetry: dict | None = None) -> dict:
        if not telemetry:
            return {"visibility_status": "unavailable", "gateway_security_coverage": "limited", "score": 0.0}
        return {"visibility_status": "telemetry_observed", "gateway_security_coverage": "metadata", "score": 0.0}
