from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta

from flask import current_app, request, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import AdminUser, AuditLog, Permission, Role, UserRole
from app.services.redis_service import get_runtime_store
from extensions import db


PERMISSIONS: dict[str, str] = {
    "manage_users": "Manage Users",
    "manage_applications": "Manage Applications",
    "manage_rules": "Manage Rules",
    "view_dashboard": "View Dashboard",
    "view_threats": "View Threats",
    "export_reports": "Export Reports",
    "manage_settings": "Manage Settings",
    "view_audit_logs": "View Audit Logs",
    "manage_api_keys": "Manage API Keys",
}

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "Super Admin": list(PERMISSIONS.keys()),
    "Security Analyst": [
        "view_dashboard",
        "view_threats",
        "manage_rules",
        "export_reports",
        "view_audit_logs",
    ],
    "Operator": ["view_dashboard", "manage_applications", "view_threats"],
    "Auditor": ["view_dashboard", "view_threats", "export_reports", "view_audit_logs"],
    "Viewer": ["view_dashboard"],
}

def seed_iam_defaults() -> None:
    permission_by_code: dict[str, Permission] = {}
    for code, name in PERMISSIONS.items():
        permission = Permission.query.filter_by(code=code).first()
        if permission is None:
            permission = Permission(code=code, name=name)
            db.session.add(permission)
        permission_by_code[code] = permission

    for role_name, permission_codes in ROLE_PERMISSIONS.items():
        role = Role.query.filter_by(name=role_name).first()
        if role is None:
            role = Role(name=role_name, is_system=True)
            db.session.add(role)
        role.permissions = [permission_by_code[code] for code in permission_codes]

    db.session.flush()
    _seed_initial_super_admin()
    db.session.commit()


def _seed_initial_super_admin() -> None:
    username = current_app.config["ADMIN_USERNAME"]
    password_hash = current_app.config["ADMIN_PASSWORD_HASH"]
    if not password_hash:
        return

    user = AdminUser.query.filter_by(username=username).first()
    if user is None:
        user = AdminUser(
            username=username,
            email=current_app.config["ADMIN_EMAIL"],
            password_hash=password_hash,
        )
        db.session.add(user)
        db.session.flush()

    super_admin = Role.query.filter_by(name="Super Admin").first()
    if super_admin and not UserRole.query.filter_by(
        user_id=user.id,
        role_id=super_admin.id,
    ).first():
        db.session.add(UserRole(user_id=user.id, role_id=super_admin.id))


def user_permissions(user: AdminUser) -> set[str]:
    roles = (
        Role.query.join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user.id)
        .all()
    )
    return {permission.code for role in roles for permission in role.permissions}


def user_roles(user: AdminUser) -> list[Role]:
    return (
        Role.query.join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user.id)
        .order_by(Role.name.asc())
        .all()
    )


def has_permission(user: AdminUser | None, permission_code: str) -> bool:
    if user is None or not user.is_active:
        return False
    return permission_code in user_permissions(user)


def current_user() -> AdminUser | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return AdminUser.query.get(user_id)


def authenticate_user(username: str, password: str) -> tuple[AdminUser | None, str | None]:
    if _login_rate_limited(username):
        return None, "Too many login attempts. Please wait before trying again."

    user = AdminUser.query.filter_by(username=username).first()
    if user is None or not user.is_active:
        _track_login_attempt(username)
        return None, "Invalid username or password."

    if user.locked_until and user.locked_until > datetime.utcnow():
        return None, "Account is temporarily locked."

    if not check_password_hash(user.password_hash, password):
        user.failed_login_attempts += 1
        _track_login_attempt(username)
        if user.failed_login_attempts >= current_app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"]:
            user.locked_until = datetime.utcnow() + timedelta(
                minutes=current_app.config["ACCOUNT_LOCKOUT_MINUTES"]
            )
        db.session.commit()
        return None, "Invalid username or password."

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    return user, None


def login_user_session(user: AdminUser) -> None:
    session.clear()
    session.permanent = True
    session["admin_authenticated"] = True
    session["user_id"] = user.id
    session["admin_username"] = user.username
    session["last_activity"] = int(time.time())


def validate_password_policy(password: str) -> list[str]:
    errors: list[str] = []
    if len(password) < current_app.config["PASSWORD_MIN_LENGTH"]:
        errors.append(
            f"Password must be at least {current_app.config['PASSWORD_MIN_LENGTH']} characters."
        )
    if not any(char.isupper() for char in password):
        errors.append("Password must include an uppercase letter.")
    if not any(char.islower() for char in password):
        errors.append("Password must include a lowercase letter.")
    if not any(char.isdigit() for char in password):
        errors.append("Password must include a number.")
    if not any(not char.isalnum() for char in password):
        errors.append("Password must include a symbol.")
    return errors


def set_user_password(user: AdminUser, password: str) -> None:
    user.password_hash = generate_password_hash(password)
    user.password_changed_at = datetime.utcnow()
    db.session.commit()


def create_user(form_data, assigned_by_id: int | None = None) -> tuple[AdminUser | None, list[str]]:
    errors = validate_password_policy(form_data.get("password", ""))
    username = form_data.get("username", "").strip()
    email = form_data.get("email", "").strip() or None
    if not username:
        errors.append("Username is required.")
    if AdminUser.query.filter_by(username=username).first():
        errors.append("Username already exists.")
    if email and AdminUser.query.filter_by(email=email).first():
        errors.append("Email already exists.")
    if errors:
        return None, errors

    user = AdminUser(
        username=username,
        email=email,
        password_hash=generate_password_hash(form_data.get("password", "")),
        is_active=form_data.get("is_active") == "on",
    )
    db.session.add(user)
    db.session.flush()

    for role_id in form_data.getlist("role_ids"):
        db.session.add(
            UserRole(
                user_id=user.id,
                role_id=int(role_id),
                assigned_by_id=assigned_by_id,
            )
        )
    db.session.commit()
    return user, []


def update_user(user: AdminUser, form_data, assigned_by_id: int | None = None) -> list[str]:
    username = form_data.get("username", "").strip()
    email = form_data.get("email", "").strip() or None
    errors: list[str] = []
    existing = AdminUser.query.filter_by(username=username).first()
    if existing and existing.id != user.id:
        errors.append("Username already exists.")
    if email:
        existing_email = AdminUser.query.filter_by(email=email).first()
        if existing_email and existing_email.id != user.id:
            errors.append("Email already exists.")
    if errors:
        return errors

    user.username = username
    user.email = email
    user.is_active = form_data.get("is_active") == "on"
    UserRole.query.filter_by(user_id=user.id).delete()
    for role_id in form_data.getlist("role_ids"):
        db.session.add(
            UserRole(
                user_id=user.id,
                role_id=int(role_id),
                assigned_by_id=assigned_by_id,
            )
        )
    db.session.commit()
    return []


def create_audit_log(
    action: str,
    resource: str | None,
    status: str,
    message: str | None = None,
    user: AdminUser | None = None,
) -> None:
    actor = user or current_user()
    log = AuditLog(
        user_id=actor.id if actor else None,
        username=actor.username if actor else None,
        action=action,
        resource=resource,
        ip_address=request.remote_addr if request else None,
        status=status,
        message=message,
    )
    db.session.add(log)
    db.session.commit()


def password_reset_token(user: AdminUser) -> str:
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps({"user_id": user.id}, salt="cloudshield-password-reset")


def verify_password_reset_token(token: str, max_age_seconds: int = 3600) -> AdminUser | None:
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        data = serializer.loads(
            token,
            salt="cloudshield-password-reset",
            max_age=max_age_seconds,
        )
    except (BadSignature, SignatureExpired):
        return None
    return AdminUser.query.get(data.get("user_id"))


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _track_login_attempt(username: str) -> None:
    get_runtime_store().incr(
        _login_attempt_key(username),
        current_app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"],
    )


def _login_rate_limited(username: str) -> bool:
    return (
        get_runtime_store().get_int(_login_attempt_key(username))
        >= current_app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"]
    )


def _login_attempt_key(username: str) -> str:
    normalized = username.strip().lower() or "unknown"
    return f"cloudshield:runtime:iam:login_attempts:{normalized}"
