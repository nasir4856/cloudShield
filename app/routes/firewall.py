import logging

from flask import Blueprint, jsonify, redirect, request, url_for

from app.proxy.forwarder import forward_request
from app.security.threat_engine import (
    ThreatAction,
    apply_temporary_block,
    evaluate_request,
    is_temporarily_blocked,
    record_response,
    temporary_block_remaining,
)
from app.services.application_registry import find_matching_application
from app.services.email_service import send_email
from app.services.runtime import get_blocklist, get_rate_limiter


firewall_bp = Blueprint("firewall", __name__)
security_logger = logging.getLogger("cloudshield.security")


@firewall_bp.route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@firewall_bp.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def firewall(path: str | None = None):
    ip_address = request.remote_addr or "unknown"
    blocklist = get_blocklist()
    rate_limiter = get_rate_limiter()

    if blocklist.contains(ip_address):
        security_logger.info("Blocked request from %s.", ip_address)
        return redirect(url_for("captcha.captcha_verification"))

    if is_temporarily_blocked(ip_address):
        return (
            jsonify(
                {
                    "error": "Temporarily blocked due to critical threat score",
                    "retry_after_seconds": temporary_block_remaining(ip_address),
                }
            ),
            403,
        )

    application_match = find_matching_application(path)
    if application_match is None:
        record_response(ip_address, 404)
        return jsonify({"error": "No matching protected application"}), 404

    application = application_match.application
    if not application.enabled:
        return jsonify({"error": "Protected application is disabled"}), 503

    threat_result = evaluate_request(request, application, ip_address)
    if threat_result.action == ThreatAction.CAPTCHA and application.captcha_enabled:
        return redirect(url_for("captcha.captcha_verification"))

    if threat_result.action == ThreatAction.PERMANENT_BLOCK:
        blocklist.add(ip_address)
        if application.email_alerts:
            send_email(
                "Critical Threat Detected - IP Permanently Blocked",
                (
                    f"IP {ip_address} was permanently blocked for "
                    f"{application.name}. Threat score: {threat_result.score}."
                ),
            )
        return jsonify({"error": "Blocked due to critical threat score"}), 403

    if threat_result.action == ThreatAction.TEMPORARY_BLOCK:
        apply_temporary_block(ip_address)
        if application.email_alerts:
            send_email(
                "Critical Threat Detected - IP Temporarily Blocked",
                (
                    f"IP {ip_address} was temporarily blocked for "
                    f"{application.name}. Threat score: {threat_result.score}."
                ),
            )
        return jsonify({"error": "Temporarily blocked due to critical threat score"}), 403

    if rate_limiter.is_over_limit(ip_address):
        blocklist.add(ip_address)
        security_logger.warning("Blocked IP %s due to DDoS suspicion.", ip_address)
        send_email(
            "DDoS Suspicion - IP Blocked",
            f"IP {ip_address} has been blocked due to suspected DDoS activity.",
        )
        return jsonify({"error": "Blocked due to suspected DDoS"}), 403

    response = forward_request(application, application_match.upstream_path)
    status_code = _response_status_code(response)
    if status_code is not None:
        record_response(ip_address, status_code)
    return response


def _response_status_code(response) -> int | None:
    if hasattr(response, "status_code"):
        return response.status_code
    if isinstance(response, tuple) and len(response) >= 2:
        return response[1]
    return None
