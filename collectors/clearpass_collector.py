# collectors/clearpass_collector.py
"""
ClearPass Policy Manager (CPPM) data collector — v6.x REST API.
API reference: https://developer.arubanetworks.com/cppm/docs/introduction-and-overview

Known API constraints (ClearPass 6.12.x):
  - /api/session?filter={"state":"active"} → 500 (CPPM DB bug with state filter)
  - /api/audit-records                     → 404 (requires different license/version)
  - /api/insight/*                         → 404 (requires Insight module)
  Active-session detection: acctstoptime == "0" or "" = still active
"""
import os
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class ClearPassCollector:
    """
    Collects RADIUS accounting sessions, endpoint compliance data,
    and session-derived auth statistics from ClearPass.
    """

    def __init__(self, lookback_minutes: int = 30):
        self.base_url = os.getenv("CPPM_HOST", "").rstrip("/")
        self.client_id = os.getenv("CPPM_CLIENT_ID")
        self.client_secret = os.getenv("CPPM_CLIENT_SECRET")
        self.lookback_minutes = lookback_minutes

        for var, val in [
            ("CPPM_HOST", self.base_url),
            ("CPPM_CLIENT_ID", self.client_id),
            ("CPPM_CLIENT_SECRET", self.client_secret),
        ]:
            if not val:
                raise EnvironmentError(f"{var} is not set.")

        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        # Exclude 500 from auto-retry — CPPM returns 500 for unsupported filter
        # expressions (DB bug), and retrying only adds latency.
        retry = Retry(
            total=int(os.getenv("COLLECTOR_RETRIES", 3)),
            backoff_factor=float(os.getenv("COLLECTOR_BACKOFF", 2)),
            status_forcelist=[429, 502, 503, 504],
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.verify = os.getenv("CPPM_VERIFY_SSL", "false").lower() != "false"
        if not session.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return session

    def _get_token(self) -> str:
        """OAuth2 Client Credentials grant for CPPM API."""
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token

        resp = self.session.post(
            f"{self.base_url}/api/oauth",
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 28800)
        logger.info("ClearPass: OAuth2 token acquired.")
        return self._access_token

    def _get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        token = self._get_token()
        url = f"{self.base_url}/api/{endpoint}"
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

    def _since_epoch(self) -> int:
        """Unix epoch for start of lookback window."""
        return int(
            (datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)).timestamp()
        )

    # ── Sessions ──────────────────────────────────────────────────────────

    def get_active_sessions(self) -> dict:
        """
        Retrieve RADIUS accounting sessions.

        Note: filtering by state="active" triggers a CPPM DB error (v6.x bug).
        We fetch recent sessions without a state filter and classify locally:
          active  = acctstoptime is "0" or missing
          closed  = acctstoptime is a non-zero timestamp
        """
        data = self._get("session", params={
            "limit": 1000,
            "sort": "-acctstarttime",
            "calculate_count": "true",
        })
        all_sessions = data.get("_embedded", {}).get("items", [])
        total_db = data.get("count", len(all_sessions))

        since_ts = self._since_epoch()
        active: list[dict] = []
        recent_closed: list[dict] = []
        by_auth_type: dict[str, int] = {}
        termination_causes: dict[str, int] = {}

        for s in all_sessions:
            start_ts = int(s.get("acctstarttime") or 0)
            stop_ts = int(s.get("acctstoptime") or 0)
            is_active = stop_ts == 0
            in_lookback = start_ts >= since_ts

            auth_type = s.get("servicetype") or s.get("nasporttype") or "unknown"
            by_auth_type[auth_type] = by_auth_type.get(auth_type, 0) + 1

            cause = s.get("acctterminatecause") or ("active" if is_active else "unknown")
            termination_causes[cause] = termination_causes.get(cause, 0) + 1

            session_row = {
                "username": s.get("username"),
                "mac": s.get("callingstationid") or s.get("mac_address"),
                "ssid": s.get("ssid"),
                "ap": s.get("ap_name"),
                "nas_ip": s.get("nasipaddress"),
                "role": s.get("arubauserrole"),
                "state": "active" if is_active else "closed",
                "started": datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat() if start_ts else None,
                "duration_s": s.get("acctsessiontime"),
                "terminate_cause": s.get("acctterminatecause"),
            }
            if is_active:
                active.append(session_row)
            elif in_lookback:
                recent_closed.append(session_row)

        return {
            "total_sessions_in_db": total_db,
            "active_count": len(active),
            "closed_in_lookback": len(recent_closed),
            "by_auth_type": by_auth_type,
            "termination_causes": termination_causes,
            "active_sessions": active[:20],
            "recent_closed_sessions": recent_closed[:20],
        }

    # ── Auth Logs ─────────────────────────────────────────────────────────

    def get_auth_logs(self) -> dict:
        """
        RADIUS authentication event analysis.

        ClearPass Insight module provides detailed accept/reject logs via
        /api/insight/* — these endpoints return 404 if Insight is not licensed.
        Falls back to session-based analysis when Insight is unavailable.
        """
        insight_available = False
        summary = {
            "total_events": 0,
            "accepted": 0,
            "rejected": 0,
            "failure_rate_pct": 0.0,
            "top_failure_reasons": {},
            "failed_details": [],
            "data_source": None,
            "data_gap": None,
        }

        # Try Insight endpoint first
        try:
            since = (
                datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)
            ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            data = self._get("insight/endpoint/summary/all", params={
                "filter": f'{{"timestamp":{{"$gte":"{since}"}}}}',
                "limit": 1000,
            })
            records = data.get("_embedded", {}).get("items", [])
            insight_available = True
            summary["data_source"] = "clearpass_insight"

            for rec in records:
                auth_status = (rec.get("auth_status") or "").upper()
                if auth_status in ("ACCEPT", "ALLOW"):
                    summary["accepted"] += 1
                elif auth_status in ("REJECT", "DENY", "FAIL"):
                    summary["rejected"] += 1
                    reason = rec.get("error_message") or rec.get("description") or "Unknown"
                    summary["top_failure_reasons"][reason] = (
                        summary["top_failure_reasons"].get(reason, 0) + 1
                    )
                    if len(summary["failed_details"]) < 10:
                        summary["failed_details"].append({
                            "timestamp": rec.get("timestamp"),
                            "mac": rec.get("mac_address"),
                            "ssid": rec.get("ssid"),
                            "nas_ip": rec.get("nas_ip_address"),
                            "reason": reason,
                            "user": rec.get("username"),
                        })

            summary["total_events"] = summary["accepted"] + summary["rejected"]
            total = summary["total_events"]
            if total > 0:
                summary["failure_rate_pct"] = round(summary["rejected"] / total * 100, 1)
            summary["top_failure_reasons"] = dict(
                sorted(summary["top_failure_reasons"].items(),
                       key=lambda x: x[1], reverse=True)[:10]
            )
        except Exception as e:
            logger.warning(f"ClearPass Insight not available: {e}")

        if not insight_available:
            # Insight unavailable — derive what we can from the session table
            summary["data_source"] = "session_accounting_only"
            summary["data_gap"] = (
                "ClearPass Insight module is not available on this instance. "
                "RADIUS Access-Accept / Access-Reject counts require the Insight module "
                "(/api/insight/*). Session accounting data only shows successfully "
                "authenticated sessions (no auth rejections visible)."
            )
            try:
                sess_data = self._get("session", params={
                    "limit": 500, "sort": "-acctstarttime", "calculate_count": "true"
                })
                sessions = sess_data.get("_embedded", {}).get("items", [])
                # Sessions in accounting = successful authentications
                summary["total_events"] = len(sessions)
                summary["accepted"] = len(sessions)  # all accounting sessions = accepted
                summary["note"] = (
                    f"{len(sessions)} RADIUS accounting sessions retrieved "
                    "(these represent successful auths only; rejections not captured)."
                )
                # Highlight problem termination causes
                problem_causes = {}
                for s in sessions:
                    cause = s.get("acctterminatecause") or "active"
                    if cause not in ("User-Request", "Admin-Reset", "active"):
                        problem_causes[cause] = problem_causes.get(cause, 0) + 1
                if problem_causes:
                    summary["abnormal_termination_causes"] = problem_causes
            except Exception as e:
                logger.warning(f"ClearPass session fallback also failed: {e}")

        max_failure_rate = float(os.getenv("MAX_AUTH_FAILURE_RATE_PCT", 10))
        summary["alert"] = summary["failure_rate_pct"] > max_failure_rate
        return summary

    # ── Endpoint Compliance ───────────────────────────────────────────────

    def get_endpoint_compliance(self) -> dict:
        """Count endpoints by status: Known, Unknown, Disabled."""
        result = {"total": 0, "known": 0, "unknown": 0, "disabled": 0, "sample_unknown": []}
        try:
            for status in ("Known", "Unknown", "Disabled"):
                r = self._get("endpoint", params={
                    "filter": f'{{"status":"{status}"}}',
                    "limit": 1,
                    "calculate_count": "true",
                })
                count = r.get("count", 0)
                result[status.lower()] = count
                result["total"] += count
        except Exception as e:
            logger.warning(f"ClearPass endpoint compliance query failed: {e}")
            result["error"] = str(e)

        # Grab sample of unknown endpoints for RCA context
        try:
            r = self._get("endpoint", params={
                "filter": '{"status":"Unknown"}', "limit": 10
            })
            result["sample_unknown"] = [
                {"mac": ep.get("mac_address"), "added": ep.get("added_at")}
                for ep in r.get("_embedded", {}).get("items", [])
            ]
        except Exception:
            pass

        return result

    # ── Consolidated Snapshot ─────────────────────────────────────────────

    def collect_all(self) -> dict:
        logger.info("ClearPass: starting full data collection...")
        return {
            "source": "clearpass",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "lookback_minutes": self.lookback_minutes,
            "active_sessions": self.get_active_sessions(),
            "auth_logs": self.get_auth_logs(),
            "endpoint_compliance": self.get_endpoint_compliance(),
        }
