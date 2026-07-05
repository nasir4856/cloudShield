from flask import Blueprint, jsonify

from app.services.health_service import health_report, liveness_report, readiness_report


health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health():
    payload, status_code = health_report()
    return jsonify(payload), status_code


@health_bp.route("/ready", methods=["GET"])
def ready():
    payload, status_code = readiness_report()
    return jsonify(payload), status_code


@health_bp.route("/live", methods=["GET"])
def live():
    payload, status_code = liveness_report()
    return jsonify(payload), status_code

