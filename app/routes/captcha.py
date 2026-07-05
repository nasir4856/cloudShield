import logging

from flask import Blueprint, Response, redirect, render_template, request, send_file, session, url_for

from app.security.captcha import generate_captcha
from app.services.redis_service import get_runtime_store
from app.services.runtime import get_blocklist


captcha_bp = Blueprint("captcha", __name__)
security_logger = logging.getLogger("cloudshield.security")


@captcha_bp.route("/captcha", methods=["GET"])
def captcha_verification():
    generate_captcha()
    return render_template("captcha.html", captcha_image="captcha.png")


@captcha_bp.route("/captcha_image", methods=["GET"])
def captcha_image() -> Response:
    image_io = generate_captcha()
    return send_file(image_io, mimetype="image/png")


@captcha_bp.route("/verify_captcha", methods=["POST"])
def verify_captcha():
    user_input = request.form.get("captcha_input", "")
    expected = session.get("captcha", "")

    security_logger.info("CAPTCHA verification attempt from %s.", request.remote_addr)
    if user_input.upper() == expected:
        ip_address = request.remote_addr or "unknown"
        get_blocklist().discard(ip_address)
        get_runtime_store().delete(_captcha_attempt_key(ip_address))
        security_logger.info("IP %s passed CAPTCHA verification.", ip_address)
        return redirect(url_for("firewall.firewall"))

    ip_address = request.remote_addr or "unknown"
    attempt_count = get_runtime_store().incr(_captcha_attempt_key(ip_address), ttl=3600)
    security_logger.info(
        "CAPTCHA verification failed from %s attempt_count=%s.",
        ip_address,
        attempt_count,
    )
    return render_template("captcha.html", error="Incorrect CAPTCHA, please try again.")


def _captcha_attempt_key(ip_address: str) -> str:
    return f"cloudshield:runtime:captcha:attempts:{ip_address}"
