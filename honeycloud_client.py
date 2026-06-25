"""
HoneyCloud Client Library
========================
Handles communication with the HoneyCloud security monitoring platform.
Updated for HoneyCloud Multi-Tenant API.
"""

import requests
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

class HoneyCloudClient:
    """
    Client for HoneyCloud security monitoring platform.
    """

    def __init__(self, api_key: str, base_url: str = "http://localhost:8000"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.events_endpoint = f"{self.base_url}/api/ingest"
        self.verify_endpoint = f"{self.base_url}/health"
        self.timeout = 5  # seconds
        
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

        logger.info(f"✅ HoneyCloud client initialized: {self.base_url}")

    def _get_severity_score(self, severity: str) -> float:
        """Map severity string to 0-100 score"""
        severity_map = {
            "CRITICAL": 95.0,
            "HIGH": 80.0,
            "MEDIUM": 60.0,
            "LOW": 30.0,
            "INFO": 10.0
        }
        return severity_map.get(severity.upper(), 50.0)

    def send_event(
        self,
        service: str,
        source_ip: str,
        endpoint: str,
        method: str,
        severity: str,
        description: str = "",
        additional_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Send a security event to HoneyCloud.
        """
        
        # For local demonstration, map loopback/private IPs to random public IPs so they geolocate globally if configured
        import os
        randomize_ips = os.environ.get("HONEYCLOUD_RANDOMIZE_IPS", "false").lower() in ("true", "1", "yes")
        if randomize_ips and (source_ip in ("127.0.0.1", "localhost", "::1") or source_ip.startswith(("192.168.", "10.", "172.16."))):
            import random
            test_ips = [
                "198.51.100.42",   # US
                "95.163.220.12",   # RU
                "220.181.38.148",  # CN
                "46.165.2.14",     # DE
                "200.221.2.45",    # BR
                "82.197.200.4",    # NL
                "101.100.180.2",   # SG
                "103.241.136.1",   # IN (Delhi)
                "43.242.144.1",    # IN (Mumbai)
                "210.140.10.10",   # JP (Tokyo)
                "109.228.0.1",     # GB (London)
                "198.41.0.4"       # CA (Toronto)
            ]
            source_ip = random.choice(test_ips)

        score = self._get_severity_score(severity)
        
        # Build payload matching HoneyCloud /api/ingest schema
        payload = {
            "service": service,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "method": method,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": f"{method} {endpoint}",
            "payload": description,
            "metadata": additional_data or {}
        }

        try:
            response = requests.post(
                self.events_endpoint,
                json=payload,
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code in (200, 201):
                res_data = response.json()
                logger.info(f"✅ Event sent")
                return res_data
            elif response.status_code == 429:
                 logger.warning("⚠️  Rate limited/Quota exceeded")
                 return {"status": "error", "message": "Rate limited"}
            else:
                logger.error(f"❌ HoneyCloud error: {response.status_code} - {response.text}")
                return {"status": "error", "message": "API Error"}

        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            return {"status": "error", "message": str(e)}

    def health_check(self) -> bool:
        """Check connection via health check endpoint"""
        try:
            response = requests.get(
                self.verify_endpoint,
                headers=self.headers,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception:
            return False

    def send_failed_login(
        self,
        source_ip: str,
        username: str,
        attempt_count: int = 1,
        user_agent: str = "",
        referer: str = "",
        username_exists: bool = False
    ) -> Dict[str, Any]:
        """
        Send a failed login attempt to HoneyCloud.
        This is one of the most realistic security signals a protected app can generate.
        """
        metadata = {
            "event_type": "FAILED_LOGIN",
            "attempt_count": attempt_count,
        }
        if user_agent:
            metadata["user_agent"] = user_agent
        if referer:
            metadata["referer"] = referer

        if username_exists:
            calculated_severity = "MEDIUM" if attempt_count < 3 else "HIGH" if attempt_count < 10 else "CRITICAL"
        else:
            calculated_severity = "LOW" if attempt_count < 3 else "MEDIUM" if attempt_count < 10 else "HIGH"

        return self.send_event(
            service="DEMO_ECOMMERCE",
            source_ip=source_ip,
            endpoint="/login",
            method="POST",
            severity=calculated_severity,
            description=f"Failed login attempt for user '{username}' (attempt #{attempt_count})",
            additional_data=metadata
        )

    def send_successful_login(
        self,
        source_ip: str,
        username: str,
        user_agent: str = ""
    ) -> Dict[str, Any]:
        """
        Send a successful login event for audit trail.
        """
        metadata = {
            "event_type": "SUCCESSFUL_LOGIN",
        }
        if user_agent:
            metadata["user_agent"] = user_agent

        return self.send_event(
            service="DEMO_ECOMMERCE",
            source_ip=source_ip,
            endpoint="/login",
            method="POST",
            severity="INFO",
            description=f"Successful login for user '{username}'",
            additional_data=metadata
        )

    def send_account_enumeration(
        self,
        source_ip: str,
        username: str,
        user_agent: str = ""
    ) -> Dict[str, Any]:
        """
        Send account enumeration attempt — probing for valid usernames.
        """
        metadata = {
            "event_type": "ACCOUNT_ENUMERATION",
        }
        if user_agent:
            metadata["user_agent"] = user_agent

        return self.send_event(
            service="DEMO_ECOMMERCE",
            source_ip=source_ip,
            endpoint="/login",
            method="POST",
            severity="HIGH",
            description=f"Account enumeration probe for username '{username}'",
            additional_data=metadata
        )

    def send_honeypot_hit(
        self,
        endpoint: str,
        source_ip: str,
        method: str = "GET",
        severity: str = "HIGH",
        user_agent: str = "",
        referer: str = ""
    ) -> Dict[str, Any]:
        """
        Convenience method for sending honeypot hits.
        """
        metadata = {}
        if user_agent:
            metadata["user_agent"] = user_agent
        if referer:
            metadata["referer"] = referer

        return self.send_event(
            service="DEMO_ECOMMERCE",
            source_ip=source_ip,
            endpoint=endpoint,
            method=method,
            severity=severity,
            description=f"Honeypot hit: {endpoint}",
            additional_data=metadata
        )
