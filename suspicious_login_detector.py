#!/usr/bin/env python3
"""
Incident Response Automation: Suspicious Login Detector
Detects and responds to logins from blacklisted IPs, foreign countries, or threat intel matches.
"""

import json
import sys
import logging
import os
import time
import requests
from typing import Dict, List, Set, Optional
from datetime import datetime, UTC, timedelta
from ipaddress import ip_address, IPv4Address, IPv6Address
import geoip2.database
from geoip2.errors import AddressNotFoundError

# ======================
# CONFIGURATION
# ======================

# Trusted countries (ISO 3166-1 alpha-2)
TRUSTED_COUNTRIES: Set[str] = {"US", "CA", "GB", }

# Paths
BLACKLIST_FILE = "blacklist.txt"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
AUDIT_LOG_FILE = "incident_response_audit.log"

# AbuseIPDB
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY)

# Safety & Control
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
TRUSTED_IPS: Set[str] = set(ip.strip() for ip in os.getenv("TRUSTED_IPS", "").split(",") if ip.strip())
EXEMPT_USERS: Set[str] = set(u.strip() for u in os.getenv("EXEMPT_USERS", "").split(",") if u.strip())

# Rate limiting: max disables per hour
MAX_DISABLES_PER_HOUR = 10
_disable_timestamps: List[datetime] = []

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(AUDIT_LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SuspiciousLoginDetector")


# ======================
# UTILITY FUNCTIONS
# ======================

def normalize_ip(raw_ip: str) -> Optional[str]:
    """Normalize IP: handle X-Forwarded-For, clean, validate."""
    if not raw_ip:
        return None
    # Handle X-Forwarded-For: take first IP (client)
    ip = raw_ip.split(',')[0].strip()
    try:
        # Validate and return canonical form
        addr = ip_address(ip)
        return str(addr)
    except ValueError:
        logger.warning(f"Invalid IP address: {raw_ip}")
        return None


def load_blacklist(path: str) -> Set[str]:
    """Load internal blacklist of IPs from file."""
    if not os.path.exists(path):
        logger.info(f"Blacklist file {path} not found. Starting with empty blacklist.")
        return set()
    with open(path, "r") as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def get_geoip_country(ip: str) -> Optional[str]:
    """Get country code using MaxMind GeoIP2."""
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.iso_code
    except AddressNotFoundError:
        logger.debug(f"IP {ip} not found in GeoIP database.")
        return None
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip}: {e}")
        return None  # Fallback: assume unknown


def check_abuseipdb(ip: str, max_age_in_days: int = 90) -> bool:
    """Check if IP is reported in AbuseIPDB."""
    if not ABUSEIPDB_ENABLED:
        return False
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": max_age_in_days}
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("abuseConfidenceScore", 0) > 0
        else:
            logger.warning(f"AbuseIPDB API error: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"AbuseIPDB check failed for {ip}: {e}")
    return False


def is_rate_limit_exceeded() -> bool:
    """Check if we've exceeded max disables per hour."""
    now = datetime.now(UTC)
    one_hour_ago = now - timedelta(hours=1)
    # Remove timestamps older than 1 hour
    global _disable_timestamps
    _disable_timestamps = [ts for ts in _disable_timestamps if ts > one_hour_ago]
    if len(_disable_timestamps) >= MAX_DISABLES_PER_HOUR:
        logger.warning("Rate limit exceeded: max disables per hour reached.")
        return True
    return False


def is_exempt_user(user_id: str) -> bool:
    """Check if user is exempt from auto-disable."""
    return user_id in EXEMPT_USERS


def is_trusted_ip(ip: str) -> bool:
    """Check if IP is in trusted allowlist."""
    return ip in TRUSTED_IPS


# ======================
# RESPONSE ACTIONS (STUBS - CUSTOMIZE PER ENV)
# ======================

def revoke_sessions(user_id: str):
    """Revoke active sessions (stub)."""
    action = f"[DRY-RUN] Would revoke sessions for {user_id}" if DRY_RUN else f"Revoked sessions for {user_id}"
    logger.info(action)
    # TODO: Integrate with Okta, AWS, or custom session store
    # Example Okta: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/revokeUserSessions
    # Example AWS: iam.update_access_key(UserName=user_id, Status='Inactive')


def disable_user(user_id: str):
    """Disable user account (stub)."""
    if is_rate_limit_exceeded():
        logger.error(f"Skipping disable for {user_id} due to rate limit.")
        return
    action = f"[DRY-RUN] Would disable user {user_id}" if DRY_RUN else f"Disabled user {user_id}"
    logger.info(action)
    if not DRY_RUN:
        _disable_timestamps.append(datetime.now(UTC))
    # TODO: Implement actual disable logic per identity provider


def notify_secops(alert: Dict):
    """Send alert to SecOps (Slack/email/PagerDuty stub)."""
    message = (
        f"[ALERT] *Suspicious Login Detected*\n"
        f"*User:* {alert['user_id']}\n"
        f"*IP:* {alert['ip']} ({alert['country'] or 'Unknown'})\n"
        f"*Reasons:* {', '.join(alert['reasons'])}\n"
        f"*Action:* {'Sessions revoked, user disabled' if not DRY_RUN else 'DRY-RUN: No action taken'}\n"
        f"*Timestamp:* {alert['timestamp']}"
    )
    logger.info(f"SecOps Alert: {message}")
    # TODO: Send to Slack webhook, email, or PagerDuty
    # Example Slack:
    # requests.post(SLACK_WEBHOOK, json={"text": message})


def log_to_siem(alert: Dict):
    """Send to SIEM (e.g., Splunk, ELK)."""
    logger.info(f"SIEM Alert: {json.dumps(alert)}")
    # TODO: Forward to syslog, HTTP endpoint, etc.


# ======================
# MAIN LOGIC
# ======================

def main(log_event: Dict):
    user_id = log_event.get("user_id")
    raw_ip = log_event.get("ip_address")

    if not user_id or not raw_ip:
        logger.error("Missing user_id or ip_address in event")
        return

    ip = normalize_ip(raw_ip)
    if not ip:
        return

    # Safety: Skip trusted IPs
    if is_trusted_ip(ip):
        logger.info(f"Trusted IP {ip} for user {user_id} – skipping analysis.")
        return

    # Enrichment
    country = get_geoip_country(ip)
    reasons = []

    internal_blacklist = load_blacklist(BLACKLIST_FILE)
    if ip in internal_blacklist:
        reasons.append("Internal blacklist")

    if country not in TRUSTED_COUNTRIES:
        reasons.append(f"Foreign GeoIP: {country}")

    if ABUSEIPDB_ENABLED and check_abuseipdb(ip):
        reasons.append("Threat intel match (AbuseIPDB)")

    # Decision
    if not reasons:
        logger.debug(f"Login from {ip} ({country}) for {user_id} appears normal.")
        return

    alert = {
        "user_id": user_id,
        "ip": ip,
        "country": country,
        "reasons": reasons,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "event": log_event
    }

    log_to_siem(alert)

    if is_exempt_user(user_id):
        logger.warning(f"Exempt user {user_id} triggered alert but auto-response skipped.")
        notify_secops(alert)
        return

    # Automated Response
    revoke_sessions(user_id)
    disable_user(user_id)
    notify_secops(alert)

    logger.info(f"Incident handled for user {user_id} from IP {ip}")


# ======================
# ENTRY POINT
# ======================

if __name__ == "__main__":
    try:
        # Read JSON event from stdin
        if not sys.stdin.isatty():
            event = json.load(sys.stdin)
        else:
            # For testing: read from first CLI arg as file
            if len(sys.argv) < 2:
                print("Usage: python suspicious_login_detector.py <event.json>", file=sys.stderr)
                sys.exit(1)
            with open(sys.argv[1], "r") as f:
                event = json.load(f)
        main(event)
    except Exception as e:
        logger.exception(f"Critical error in main: {e}")
        sys.exit(1)