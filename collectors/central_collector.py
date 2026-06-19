# collectors/central_collector.py
"""
Aruba Central data collector — new GreenLake-integrated API.
API reference: https://developer.arubanetworks.com/new-central/reference

New API namespaces (all on {CENTRAL_BASE_URL}):
  network-monitoring/v1/       — APs, radios, clients, switches
  network-troubleshooting/v1/  — events (requires context params)
  network-notifications/v1/    — alerts
"""
import os
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class CentralCollector:
    """
    Collects AP health, wireless client stats, RF radio metrics,
    network alerts, and events from Aruba Central (GreenLake-integrated).
    """

    # Default token endpoint — works for both Central-native and GLP credentials
    DEFAULT_TOKEN_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2"

    def __init__(self, lookback_minutes: int = 30):
        self.base_url = os.getenv(
            "CENTRAL_BASE_URL",
            "https://in1.api.central.arubanetworks.com"
        ).rstrip("/")
        self.client_id = os.getenv("CENTRAL_CLIENT_ID")
        self.client_secret = os.getenv("CENTRAL_CLIENT_SECRET")
        self.workspace_id = os.getenv("CENTRAL_WORKSPACE_ID")
        self.customer_id = os.getenv("CENTRAL_CUSTOMER_ID")
        self.token_url = os.getenv("CENTRAL_TOKEN_URL", self.DEFAULT_TOKEN_URL)
        self.lookback_minutes = lookback_minutes

        for var, val in [
            ("CENTRAL_CLIENT_ID", self.client_id),
            ("CENTRAL_CLIENT_SECRET", self.client_secret),
        ]:
            if not val:
                raise EnvironmentError(f"{var} is not set.")

        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=int(os.getenv("COLLECTOR_RETRIES", 3)),
            backoff_factor=float(os.getenv("COLLECTOR_BACKOFF", 2)),
            status_forcelist=[429, 500, 502, 503, 504],
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        return session

    def _get_token(self) -> str:
        """OAuth2 client-credentials token, cached and auto-refreshed.

        Tries CENTRAL_TOKEN_URL (default: SSO endpoint).
        Falls back to GLP workspace endpoint if CENTRAL_WORKSPACE_ID is set
        and the primary endpoint fails.
        """
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        resp = self.session.post(self.token_url, data=payload, timeout=15)

        # If SSO endpoint fails and workspace_id is set, try GLP workspace endpoint
        if not resp.ok and self.workspace_id and self.token_url == self.DEFAULT_TOKEN_URL:
            glp_url = (
                f"https://global.api.greenlake.hpe.com"
                f"/authorization/v2/oauth2/{self.workspace_id}/token"
            )
            logger.warning(
                f"SSO token endpoint returned {resp.status_code}, "
                f"retrying with GLP workspace endpoint."
            )
            resp = self.session.post(glp_url, data=payload, timeout=15)

        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 7200)
        logger.info(f"Central: token acquired (expires_in={data.get('expires_in')}s).")
        return self._access_token

    def _get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        token = self._get_token()
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        resp = self.session.get(
            url, headers=headers, params=params,
            timeout=int(os.getenv("COLLECTOR_TIMEOUT", 15))
        )
        resp.raise_for_status()
        return resp.json()

    def _ts_from(self) -> str:
        """RFC 3339 UTC timestamp for start of lookback window."""
        return (
            datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _ts_now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Access Points ─────────────────────────────────────────────────────

    def get_ap_health(self) -> dict:
        """Returns AP status summary: up/down counts and details for problem APs."""
        data = self._get("network-monitoring/v1/aps", params={"limit": 1000})
        aps = data.get("items", [])
        summary = {
            "total": data.get("total", len(aps)),
            "up": 0, "down": 0, "restarting": 0,
            "down_aps": [], "high_noise_aps": [],
        }
        for ap in aps:
            status = (ap.get("status") or ap.get("deviceStatus") or "").lower()
            if status in ("up", "online"):
                summary["up"] += 1
            elif status in ("down", "offline"):
                summary["down"] += 1
                summary["down_aps"].append({
                    "name": ap.get("name") or ap.get("deviceName"),
                    "serial": ap.get("serial") or ap.get("serialNumber"),
                    "ip": ap.get("ipAddress") or ap.get("ip_address"),
                    "site": ap.get("siteName") or ap.get("site"),
                    "last_seen": ap.get("lastSeen") or ap.get("last_modified"),
                })
            elif "restart" in status:
                summary["restarting"] += 1
        return summary

    # ── RF Radio Metrics ──────────────────────────────────────────────────

    def get_ap_rf_metrics(self) -> list[dict]:
        """RF health: channel utilization, noise, client count per radio."""
        data = self._get("network-monitoring/v1/radios", params={"limit": 1000})
        radios = data.get("items", [])
        rf_data = []
        for radio in radios:
            rf_data.append({
                "ap_name": radio.get("apName") or radio.get("name"),
                "serial": radio.get("apSerial") or radio.get("serial"),
                "band": radio.get("band") or radio.get("radioType"),
                "channel": radio.get("channel"),
                "channel_utilization_pct": radio.get("utilization") or radio.get("channelUtilization"),
                "client_count": radio.get("clientCount") or radio.get("numClients"),
                "tx_power_dbm": radio.get("txPower") or radio.get("txPowerDbm"),
                "noise_dbm": radio.get("noise") or radio.get("noiseFloor"),
                "snr_db": radio.get("snr"),
            })
        logger.info(f"Central: retrieved {len(rf_data)} radio metrics")
        return rf_data

    # ── Wireless Clients ──────────────────────────────────────────────────

    def get_client_health(self) -> dict:
        """Client connection statistics: SNR distribution by SSID."""
        data = self._get("network-monitoring/v1/clients", params={"limit": 500})
        clients = data.get("items", [])
        min_snr = int(os.getenv("MIN_SNR_DB", 20))
        summary = {
            "total_clients": data.get("total", len(clients)),
            "poor_snr_clients": [],
            "by_ssid": {},
        }
        for c in clients:
            snr = c.get("snr") or c.get("snrDb")
            ssid = c.get("ssid") or c.get("networkName") or c.get("network") or "unknown"
            summary["by_ssid"].setdefault(ssid, {"count": 0, "poor_snr": 0})
            summary["by_ssid"][ssid]["count"] += 1
            if snr is not None and snr < min_snr:
                summary["poor_snr_clients"].append({
                    "mac": c.get("macAddress") or c.get("macaddr"),
                    "ssid": ssid,
                    "ap": c.get("associatedDevice") or c.get("apName"),
                    "snr_db": snr,
                    "channel": c.get("channel"),
                })
                summary["by_ssid"][ssid]["poor_snr"] += 1
        return summary

    # ── Events ────────────────────────────────────────────────────────────

    def get_network_events(self) -> list[dict]:
        """Fetch recent network events via network-troubleshooting API.

        The events endpoint requires a context-type and context-identifier.
        Falls back to empty list if no events are accessible.
        """
        since = self._ts_from()
        now = self._ts_now()
        events: list[dict] = []

        # The API requires context-type + context-identifier; try SITE scope first
        # For broader coverage, iterate over context types that don't need a specific ID
        for ctx_type in ["ACCESS_POINT", "SWITCH", "GATEWAY"]:
            try:
                data = self._get("network-troubleshooting/v1/events", params={
                    "context-type": ctx_type,
                    "start-at": since,
                    "end-at": now,
                    "limit": 100,
                })
                batch = data.get("items", [])
                events.extend(batch)
                if batch:
                    logger.info(
                        f"Central: {len(batch)} events for context-type={ctx_type}"
                    )
            except Exception as e:
                logger.debug(f"Central events [{ctx_type}] skipped: {e}")

        logger.info(f"Central: {len(events)} total network events retrieved")
        return events[:200]

    # ── Alerts ────────────────────────────────────────────────────────────

    def get_alerts(self) -> list[dict]:
        """Fetch active and recently resolved alerts."""
        data = self._get("network-notifications/v1/alerts", params={"limit": 100})
        alerts = data.get("items", [])
        logger.info(f"Central: retrieved {len(alerts)} alerts")
        return alerts

    # ── Consolidated Snapshot ─────────────────────────────────────────────

    def collect_all(self) -> dict:
        logger.info("Central: starting full data collection...")
        return {
            "source": "aruba_central",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "lookback_minutes": self.lookback_minutes,
            "ap_health": self.get_ap_health(),
            "rf_metrics": self.get_ap_rf_metrics(),
            "client_health": self.get_client_health(),
            "network_events": self.get_network_events(),
            "alerts": self.get_alerts(),
        }
