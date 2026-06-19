# collectors/uxi_collector.py
"""
Aruba UXI (User Experience Insight) data collector.
API reference: https://developer.arubanetworks.com/uxi/

NOTE: The networking-uxi/v1alpha1 API is a configuration/inventory API.
Test result telemetry is not available via REST pull — UXI pushes alerts
via webhook. This collector returns sensor inventory, configured tests,
and wireless network definitions for RCA context.
"""
import os
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class UXICollector:
    """Collects sensor inventory, service test definitions, and network config from UXI."""

    BASE_URL = os.getenv("UXI_BASE_URL", "https://api.capenetworks.com")
    API_VERSION = "networking-uxi/v1alpha1"

    def __init__(self, lookback_minutes: int = 30):
        self.token = os.getenv("UXI_API_TOKEN")
        if not self.token:
            raise EnvironmentError("UXI_API_TOKEN is not set in environment.")
        self.lookback_minutes = lookback_minutes
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=int(os.getenv("COLLECTOR_RETRIES", 3)),
            backoff_factor=float(os.getenv("COLLECTOR_BACKOFF", 2)),
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        return session

    def _get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        url = f"{self.BASE_URL}/{self.API_VERSION}/{endpoint}"
        try:
            resp = self.session.get(
                url, params=params,
                timeout=int(os.getenv("COLLECTOR_TIMEOUT", 15))
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            logger.error(f"UXI API error [{endpoint}]: {e.response.status_code} {e.response.text}")
            raise
        except requests.RequestException as e:
            logger.error(f"UXI request failed [{endpoint}]: {e}")
            raise

    def _get_all_pages(self, endpoint: str, params: Optional[dict] = None) -> list[dict]:
        """Fetch all pages from a paginated endpoint."""
        items = []
        p = dict(params or {})
        while True:
            data = self._get(endpoint, p)
            items.extend(data.get("items", []))
            if not data.get("next"):
                break
            # next is a URL — extract cursor/offset if needed; simplest is re-GET the next URL
            next_url = data["next"]
            resp = self.session.get(next_url, timeout=int(os.getenv("COLLECTOR_TIMEOUT", 15)))
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("items", []))
            if not data.get("next"):
                break
        return items

    # ── Sensors ──────────────────────────────────────────────────────────

    def get_sensors(self) -> list[dict]:
        """List all UXI sensors (inventory — no live health state in this API)."""
        data = self._get("sensors")
        sensors = data.get("items", [])
        logger.info(f"UXI: retrieved {len(sensors)} sensors")
        return sensors

    def get_sensor_inventory(self) -> dict:
        """Return sensor inventory summary with model and group breakdown."""
        sensors = self.get_sensors()
        by_group: dict[str, int] = {}
        by_model: dict[str, int] = {}
        for s in sensors:
            grp = s.get("groupName") or "Ungrouped"
            mdl = s.get("modelNumber") or "Unknown"
            by_group[grp] = by_group.get(grp, 0) + 1
            by_model[mdl] = by_model.get(mdl, 0) + 1
        return {
            "total": len(sensors),
            "by_group": by_group,
            "by_model": by_model,
            "sensors": [
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "serial": s.get("serial"),
                    "model": s.get("modelNumber"),
                    "group": s.get("groupName"),
                    "group_path": s.get("groupPath"),
                    "wifi_mac": s.get("wifiMacAddress"),
                }
                for s in sensors
            ],
        }

    # ── Service Tests ─────────────────────────────────────────────────────

    def get_service_tests(self) -> list[dict]:
        """
        List all configured UXI service test definitions.
        Types include: network_connectivity, perform, dns, dhcp, http, etc.
        Note: test RESULTS are not available via REST — UXI pushes results via webhook.
        """
        data = self._get("service-tests")
        tests = data.get("items", [])
        logger.info(f"UXI: retrieved {len(tests)} service test definitions")
        return tests

    def get_service_test_summary(self) -> dict:
        """Summarise configured service tests by type and enabled state."""
        tests = self.get_service_tests()
        by_type: dict[str, dict] = {}
        for t in tests:
            t_type = t.get("type") or t.get("category") or "unknown"
            entry = by_type.setdefault(t_type, {"total": 0, "enabled": 0, "tests": []})
            entry["total"] += 1
            if t.get("isEnabled"):
                entry["enabled"] += 1
            entry["tests"].append({
                "id": t.get("id"),
                "name": t.get("name"),
                "target": t.get("target"),
                "enabled": t.get("isEnabled"),
            })
        return {
            "total_tests": len(tests),
            "by_type": by_type,
            "note": (
                "Test result telemetry is not available via UXI REST API. "
                "Configure UXI webhooks to receive real-time alert events."
            ),
        }

    # ── Wireless Networks ─────────────────────────────────────────────────

    def get_wireless_networks(self) -> list[dict]:
        """Return all configured UXI wireless network (SSID) definitions."""
        data = self._get("wireless-networks")
        networks = data.get("items", [])
        logger.info(f"UXI: retrieved {len(networks)} wireless networks")
        return [
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "ssid": n.get("ssid"),
                "security": n.get("security"),
                "band_locking": n.get("bandLocking"),
                "external_connectivity": n.get("externalConnectivity"),
                "dns_lookup_domain": n.get("dnsLookupDomain"),
            }
            for n in networks
        ]

    # ── Groups ────────────────────────────────────────────────────────────

    def get_groups(self) -> list[dict]:
        """Return sensor group hierarchy."""
        data = self._get("groups")
        return data.get("items", [])

    # ── Consolidated Snapshot ─────────────────────────────────────────────

    def collect_all(self) -> dict:
        """
        Return a unified UXI snapshot for the RCA engine.
        Includes sensor inventory, configured tests, and wireless network definitions.
        Real-time test results must be received via UXI webhook push.
        """
        logger.info("UXI: starting data collection (config/inventory API)...")
        return {
            "source": "uxi",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "lookback_minutes": self.lookback_minutes,
            "api_note": (
                "UXI REST API provides configuration and inventory only. "
                "Test result telemetry arrives via webhook push (see triggers/webhook_server.py)."
            ),
            "sensor_inventory": self.get_sensor_inventory(),
            "service_tests": self.get_service_test_summary(),
            "wireless_networks": self.get_wireless_networks(),
        }
