from flask import Blueprint, jsonify, request

from app.security.jwt_service import (
    issue_token_pair,
    refresh_access_token,
    revoke_refresh_token,
)
from app.services.iam_service import authenticate_user, create_audit_log


auth_api_bp = Blueprint("auth_api", __name__, url_prefix="/api/auth")


@auth_api_bp.route("/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    user, error = authenticate_user(payload.get("username", ""), payload.get("password", ""))
    if user is None:
        create_audit_log("API Login", "JWT", "failure", error)
        return jsonify({"error": error or "Invalid credentials"}), 401

    access_token, refresh_token = issue_token_pair(user)
    create_audit_log("API Login", "JWT", "success", user=user)
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


@auth_api_bp.route("/refresh", methods=["POST"])
def api_refresh():
    payload = request.get_json(silent=True) or {}
    access_token, refresh_token = refresh_access_token(payload.get("refresh_token", ""))
    if not access_token or not refresh_token:
        return jsonify({"error": "Invalid refresh token"}), 401
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


@auth_api_bp.route("/logout", methods=["POST"])
def api_logout():
    payload = request.get_json(silent=True) or {}
    revoked = revoke_refresh_token(payload.get("refresh_token", ""))
    create_audit_log("API Logout", "JWT", "success" if revoked else "failure")
    return jsonify({"revoked": revoked})

