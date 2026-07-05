from __future__ import annotations

from flask import current_app
from sqlalchemy import text

from app.services.redis_service import get_runtime_store
from extensions import db


def health_report() -> tuple[dict, int]:
    database = database_health()
    redis = redis_health()
    configuration = configuration_health()
    application = application_health()

    components = {
        "application": application,
        "redis": redis,
        "database": database,
        "configuration": configuration,
    }
    overall = "healthy"
    status_code = 200

    if database["status"] != "healthy":
        overall = "unhealthy"
        status_code = 503
    elif configuration["status"] == "degraded" or redis["status"] == "fallback":
        overall = "degraded"

    return {"status": overall, "components": components}, status_code


def readiness_report() -> tuple[dict, int]:
    database = database_health()
    configuration = configuration_health()
    redis = redis_health()
    ready = database["status"] == "healthy" and configuration["ready"]
    return (
        {
            "status": "ready" if ready else "not_ready",
            "components": {
                "database": database,
                "configuration": configuration,
                "redis": redis,
            },
        },
        200 if ready else 503,
    )


def liveness_report() -> tuple[dict, int]:
    return {"status": "alive", "application": current_app.config["APP_NAME"]}, 200


def application_health() -> dict:
    return {
        "status": "healthy",
        "name": current_app.config["APP_NAME"],
    }


def redis_health() -> dict:
    return get_runtime_store().health()


def database_health() -> dict:
    try:
        db.session.execute(text("SELECT 1"))
    except Exception as exc:
        current_app.logger.exception("Database health check failed.")
        return {"status": "unhealthy", "connected": False, "error": str(exc)}
    return {"status": "healthy", "connected": True}


def configuration_health() -> dict:
    warnings: list[str] = []
    if current_app.config["SECRET_KEY"] == "change-this-secret-key":
        warnings.append("SECRET_KEY uses the development default.")
    if not current_app.config["ADMIN_PASSWORD_HASH"]:
        warnings.append("ADMIN_PASSWORD_HASH is not configured; admin login is disabled.")
    if not current_app.config["SQLALCHEMY_DATABASE_URI"]:
        warnings.append("DATABASE_URL is not configured.")

    return {
        "status": "degraded" if warnings else "healthy",
        "ready": bool(current_app.config["SQLALCHEMY_DATABASE_URI"]),
        "warnings": warnings,
    }

