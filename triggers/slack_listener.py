# triggers/slack_listener.py
"""
Slack Socket Mode listener — watches #all-g5shop for UXI alert notification
messages and triggers the RCA workflow when one is detected.

Required env vars:
  SLACK_APP_TOKEN         xapp-... (Socket Mode app-level token)
  SLACK_BOT_TOKEN         xoxb-... (bot token, needs channels:history scope)
  SLACK_LISTEN_CHANNEL    channel ID (C...) or name (#all-g5shop) to watch

How UXI alert messages are detected:
  The listener checks the message text and any Slack attachment title/text for
  the string "UXI alert notification" (case-insensitive). This matches the
  standard UXI Slack integration message format.

A 2-minute cooldown prevents duplicate RCA runs when UXI fires multiple alerts
in quick succession for the same incident.
"""
import os
import time
import logging
import threading
from typing import Callable, Optional

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

logger = logging.getLogger(__name__)

UXI_ALERT_TITLE = "uxi alert notification"
RCA_COOLDOWN_SECONDS = int(os.getenv("SLACK_RCA_COOLDOWN_SECONDS", 120))

_last_rca_time: float = 0
_cooldown_lock = threading.Lock()


def _is_uxi_alert(event: dict) -> bool:
    """
    Return True if the Slack message event looks like a UXI alert notification.
    Checks plain text, attachment titles/text, and block kit text fields.
    """
    def contains(text: Optional[str]) -> bool:
        return UXI_ALERT_TITLE in (text or "").lower()

    # Plain message text
    if contains(event.get("text")):
        return True

    # Slack legacy attachments (UXI typically uses these)
    for att in event.get("attachments", []):
        if (contains(att.get("title"))
                or contains(att.get("text"))
                or contains(att.get("fallback"))
                or contains(att.get("pretext"))):
            return True

    # Block Kit blocks
    for block in event.get("blocks", []):
        # section / header blocks have a "text" object
        block_text = block.get("text") or {}
        if contains(block_text.get("text")):
            return True
        # rich_text / actions blocks have nested elements
        for element in block.get("elements", []):
            if contains(element.get("text")):
                return True

    return False


def _channel_matches(event: dict, listen_channel: str) -> bool:
    """Check if the event is from the configured channel (ID or #name)."""
    event_channel = event.get("channel", "")
    if listen_channel.startswith("#"):
        # We only have the channel ID at event time; names are resolved at startup
        # Store the resolved ID on first match or accept either form
        return event_channel == listen_channel or event_channel.startswith("C")
    return event_channel == listen_channel


def start_slack_listener(workflow_fn: Callable[[str], None]) -> None:
    """
    Connect to Slack via Socket Mode and listen for UXI alert messages.
    Blocks until the process is killed.

    Args:
        workflow_fn: callable matching run_rca_workflow(trigger_context: str)
    """
    app_token = os.getenv("SLACK_APP_TOKEN")
    bot_token = os.getenv("SLACK_BOT_TOKEN")
    listen_channel = os.getenv("SLACK_LISTEN_CHANNEL", "").strip()

    for var, val in [
        ("SLACK_APP_TOKEN", app_token),
        ("SLACK_BOT_TOKEN", bot_token),
        ("SLACK_LISTEN_CHANNEL", listen_channel),
    ]:
        if not val:
            raise EnvironmentError(f"{var} is not set.")

    # Resolve channel name → ID at startup so event filtering is reliable
    # (Slack message events only carry channel IDs, not names)
    from slack_sdk import WebClient
    sdk_client = WebClient(token=bot_token)
    resolved_channel_id: str = ""

    if listen_channel.startswith("C"):
        resolved_channel_id = listen_channel
        logger.info(f"Slack listener: channel ID={resolved_channel_id}")
    else:
        target_name = listen_channel.lstrip("#")
        for ch_type in ("public_channel", "private_channel"):
            try:
                resp = sdk_client.conversations_list(types=ch_type, limit=1000)
                for ch in resp.get("channels", []):
                    if ch["name"] == target_name:
                        resolved_channel_id = ch["id"]
                        break
            except Exception:
                pass
            if resolved_channel_id:
                break
        if resolved_channel_id:
            logger.info(f"Slack listener: #{target_name} resolved to {resolved_channel_id}")
        else:
            raise EnvironmentError(
                f"Could not resolve Slack channel '{listen_channel}' to an ID. "
                "Ensure the bot is a member of the channel and has channels:read scope."
            )

    # Resolve our own bot_id so we don't react to our own RCA report posts
    try:
        own_bot_id = sdk_client.auth_test().get("bot_id", "")
        logger.info(f"Slack listener: own bot_id={own_bot_id} (will be ignored)")
    except Exception:
        own_bot_id = ""

    app = App(token=bot_token)

    def _handle(event: dict) -> None:
        """Shared handler for regular and bot_message events."""
        global _last_rca_time

        # Ignore our own posts, edits, deletions, and thread replies
        if event.get("bot_id") == own_bot_id:
            return
        subtype = event.get("subtype", "")
        if subtype in ("message_changed", "message_deleted"):
            return
        if event.get("thread_ts") and event.get("thread_ts") != event.get("ts"):
            return

        # Filter to the target channel by ID
        if event.get("channel") != resolved_channel_id:
            return

        if not _is_uxi_alert(event):
            return

        with _cooldown_lock:
            now = time.time()
            if now - _last_rca_time < RCA_COOLDOWN_SECONDS:
                remaining = int(RCA_COOLDOWN_SECONDS - (now - _last_rca_time))
                logger.info(
                    f"Slack listener: UXI alert received but in cooldown "
                    f"({remaining}s remaining) — skipping duplicate RCA."
                )
                return
            _last_rca_time = now

        ts = event.get("ts", "")
        logger.info(f"Slack listener: UXI alert notification detected (ts={ts}) — triggering RCA.")
        thread = threading.Thread(
            target=workflow_fn,
            args=(f"slack_uxi_alert:{ts}",),
            daemon=True,
        )
        thread.start()

    @app.event("message")
    def handle_message(event: dict) -> None:
        """Handles regular user messages."""
        _handle(event)

    @app.event({"type": "message", "subtype": "bot_message"})
    def handle_bot_message(event: dict) -> None:
        """Handles bot/integration messages — UXI posts with this subtype."""
        _handle(event)

    logger.info(
        f"Slack listener: Socket Mode connecting "
        f"(channel={listen_channel}, cooldown={RCA_COOLDOWN_SECONDS}s) ..."
    )
    handler = SocketModeHandler(app, app_token)
    handler.start()   # blocks
