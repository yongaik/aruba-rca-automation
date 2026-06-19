# triggers/webhook_server.py
"""
Lightweight Flask server that accepts POST webhooks from:
- Aruba UXI alert webhooks
- Aruba Central alert webhooks

When a webhook arrives with a matching secret, an RCA run is triggered immediately.
"""
import os
import hmac
import hashlib
import logging
import threading
from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)
app = Flask(__name__)

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change_me")
WEBHOOK_PORT = int(os.getenv("WEBHOOK_PORT", 5001))

_workflow_fn = None  # set at startup


@app.route("/webhook/aruba", methods=["POST"])
def aruba_webhook():
    """
    Accepts webhook payloads from Aruba Central or UXI.
    Validates the HMAC-SHA256 signature if present.
    """
    # Optional signature validation
    sig_header = request.headers.get("X-Aruba-Signature") or \
                 request.headers.get("X-Hub-Signature-256")
    if sig_header and WEBHOOK_SECRET:
        body = request.get_data()
        expected = "sha256=" + hmac.new(
            WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            logger.warning("Webhook: invalid signature — rejected.")
            return jsonify({"error": "Invalid signature"}), 401

    payload = request.json or {}
    alert_type = payload.get("alert_type") or payload.get("type") or "unknown"
    logger.info(f"Webhook received: type={alert_type}")

    # Trigger RCA asynchronously so webhook responds immediately
    if _workflow_fn:
        trigger_context = f"webhook:{alert_type}"
        thread = threading.Thread(
            target=_workflow_fn, args=(trigger_context,), daemon=True
        )
        thread.start()

    return jsonify({"status": "accepted", "trigger": f"webhook:{alert_type}"}), 202


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


def start_webhook_server(workflow_fn=None):
    global _workflow_fn
    _workflow_fn = workflow_fn
    logger.info(f"Webhook server listening on port {WEBHOOK_PORT}")
    app.run(host="0.0.0.0", port=WEBHOOK_PORT, debug=False, use_reloader=False)
