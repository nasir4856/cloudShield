from __future__ import annotations

import secrets
from datetime import datetime

from app.models import ApiKey
from app.services.iam_service import hash_secret
from extensions import db


def create_api_key(form_data, created_by_id: int | None) -> tuple[ApiKey, str]:
    plaintext = f"cs_{secrets.token_urlsafe(32)}"
    api_key = ApiKey(
        key_name=form_data.get("key_name", "").strip(),
        key_prefix=plaintext[:12],
        hashed_key=hash_secret(plaintext),
        created_by_id=created_by_id,
        expires_at=_parse_date(form_data.get("expires_at", "")),
        status=form_data.get("status", "active"),
        purpose=form_data.get("purpose", "").strip(),
    )
    db.session.add(api_key)
    db.session.commit()
    return api_key, plaintext


def revoke_api_key(api_key: ApiKey) -> None:
    api_key.status = "revoked"
    db.session.commit()


def verify_api_key(plaintext: str) -> ApiKey | None:
    api_key = ApiKey.query.filter_by(hashed_key=hash_secret(plaintext)).first()
    if api_key is None or api_key.status != "active":
        return None
    if api_key.expires_at and api_key.expires_at <= datetime.utcnow():
        api_key.status = "expired"
        db.session.commit()
        return None
    return api_key


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None

