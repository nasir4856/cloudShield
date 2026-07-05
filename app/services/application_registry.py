from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

import requests
from flask import current_app
from sqlalchemy import func

from app.models import ProtectedApplication
from extensions import db


class ApplicationStatus(str, Enum):
    HEALTHY = "Healthy"
    OFFLINE = "Offline"
    TIMEOUT = "Timeout"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class ApplicationMatch:
    application: ProtectedApplication
    upstream_path: str


def normalize_public_path(public_path: str) -> str:
    cleaned = public_path.strip()
    if not cleaned:
        cleaned = "/"
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    if len(cleaned) > 1:
        cleaned = cleaned.rstrip("/")
    return cleaned


def validate_upstream_url(upstream_url: str) -> bool:
    parsed = urlparse(upstream_url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_application_form(
    public_path: str,
    upstream_url: str,
    application_id: int | None = None,
) -> list[str]:
    errors: list[str] = []
    normalized_path = normalize_public_path(public_path)

    existing = ProtectedApplication.query.filter_by(public_path=normalized_path).first()
    if existing and existing.id != application_id:
        errors.append("Public path already exists.")

    if not validate_upstream_url(upstream_url):
        errors.append("Upstream URL must be a valid http:// or https:// URL.")

    return errors


def _positive_int(value: str | None, default: int) -> int:
    try:
        parsed = int(value or default)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def create_application(form_data) -> ProtectedApplication:
    application = ProtectedApplication(
        name=form_data.get("name", "").strip(),
        description=form_data.get("description", "").strip(),
        public_path=normalize_public_path(form_data.get("public_path", "")),
        upstream_url=form_data.get("upstream_url", "").strip().rstrip("/"),
        enabled=form_data.get("enabled") == "on",
        rate_limit_per_minute=_positive_int(form_data.get("rate_limit_per_minute"), 3000),
        burst_limit=_positive_int(form_data.get("burst_limit"), 50),
        captcha_enabled=form_data.get("captcha_enabled") == "on",
        email_alerts=form_data.get("email_alerts") == "on",
    )
    db.session.add(application)
    db.session.commit()
    return application


def update_application(application: ProtectedApplication, form_data) -> ProtectedApplication:
    application.name = form_data.get("name", "").strip()
    application.description = form_data.get("description", "").strip()
    application.public_path = normalize_public_path(form_data.get("public_path", ""))
    application.upstream_url = form_data.get("upstream_url", "").strip().rstrip("/")
    application.enabled = form_data.get("enabled") == "on"
    application.rate_limit_per_minute = _positive_int(
        form_data.get("rate_limit_per_minute"),
        3000,
    )
    application.burst_limit = _positive_int(form_data.get("burst_limit"), 50)
    application.captcha_enabled = form_data.get("captcha_enabled") == "on"
    application.email_alerts = form_data.get("email_alerts") == "on"
    db.session.commit()
    return application


def find_matching_application(request_path: str | None) -> ApplicationMatch | None:
    incoming_path = f"/{request_path.strip('/')}" if request_path else "/"
    applications = (
        ProtectedApplication.query.order_by(func.length(ProtectedApplication.public_path).desc())
        .all()
    )

    for application in applications:
        public_path = normalize_public_path(application.public_path)
        if incoming_path == public_path or incoming_path.startswith(f"{public_path}/"):
            upstream_path = incoming_path[len(public_path) :]
            return ApplicationMatch(
                application=application,
                upstream_path=upstream_path.lstrip("/"),
            )
        if public_path == "/":
            return ApplicationMatch(
                application=application,
                upstream_path=incoming_path.lstrip("/"),
            )
    return None


def check_application_health(application: ProtectedApplication) -> ApplicationStatus:
    if not application.upstream_url:
        return ApplicationStatus.UNKNOWN

    try:
        response = requests.get(
            application.upstream_url,
            timeout=min(current_app.config["UPSTREAM_TIMEOUT"], 5),
        )
    except requests.Timeout:
        return ApplicationStatus.TIMEOUT
    except requests.ConnectionError:
        return ApplicationStatus.OFFLINE
    except requests.RequestException:
        return ApplicationStatus.UNKNOWN

    if response.status_code < 500:
        return ApplicationStatus.HEALTHY
    return ApplicationStatus.OFFLINE
