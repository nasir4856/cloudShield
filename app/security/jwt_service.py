from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import jwt
from flask import current_app, request

from app.models import AdminUser, RefreshToken
from app.services.iam_service import hash_secret, user_permissions, user_roles
from extensions import db


def issue_token_pair(user: AdminUser) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    access_jti = secrets.token_hex(16)
    refresh_jti = secrets.token_hex(16)

    access_token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "roles": [role.name for role in user_roles(user)],
            "permissions": sorted(user_permissions(user)),
            "type": "access",
            "jti": access_jti,
            "iat": int(now.timestamp()),
            "exp": int(
                (now + timedelta(seconds=current_app.config["JWT_ACCESS_TOKEN_SECONDS"])).timestamp()
            ),
        },
        current_app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    refresh_token = secrets.token_urlsafe(48)
    refresh_record = RefreshToken(
        user_id=user.id,
        jti=refresh_jti,
        token_hash=hash_secret(refresh_token),
        expires_at=datetime.utcnow()
        + timedelta(seconds=current_app.config["JWT_REFRESH_TOKEN_SECONDS"]),
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:255],
    )
    db.session.add(refresh_record)
    db.session.commit()
    return access_token, refresh_token


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "access":
        return None
    return payload


def refresh_access_token(refresh_token: str) -> tuple[str | None, str | None]:
    token_hash = hash_secret(refresh_token)
    record = RefreshToken.query.filter_by(token_hash=token_hash).first()
    if (
        record is None
        or record.revoked_at is not None
        or record.expires_at <= datetime.utcnow()
    ):
        return None, None

    user = AdminUser.query.get(record.user_id)
    if user is None or not user.is_active:
        return None, None

    record.revoked_at = datetime.utcnow()
    db.session.commit()
    return issue_token_pair(user)


def revoke_refresh_token(refresh_token: str) -> bool:
    record = RefreshToken.query.filter_by(token_hash=hash_secret(refresh_token)).first()
    if record is None:
        return False
    record.revoked_at = datetime.utcnow()
    db.session.commit()
    return True

