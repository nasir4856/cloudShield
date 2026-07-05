from datetime import datetime

from extensions import db


role_permissions = db.Table(
    "role_permissions",
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id"), primary_key=True),
    db.Column(
        "permission_id",
        db.Integer,
        db.ForeignKey("permissions.id"),
        primary_key=True,
    ),
)


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    is_system = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    permissions = db.relationship(
        "Permission",
        secondary=role_permissions,
        back_populates="roles",
    )


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    roles = db.relationship(
        "Role",
        secondary=role_permissions,
        back_populates="permissions",
    )


class UserRole(db.Model):
    __tablename__ = "user_roles"

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("admin_users.id"),
        primary_key=True,
    )
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), primary_key=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("admin_users.id"), nullable=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("admin_users.id"), nullable=True)
    username = db.Column(db.String(120), nullable=True, index=True)
    action = db.Column(db.String(120), nullable=False, index=True)
    resource = db.Column(db.String(255), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    status = db.Column(db.String(40), nullable=False, index=True)
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(160), nullable=False)
    key_prefix = db.Column(db.String(16), nullable=False, index=True)
    hashed_key = db.Column(db.String(128), unique=True, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("admin_users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(40), default="active", nullable=False, index=True)
    purpose = db.Column(db.Text, nullable=True)


class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("admin_users.id"), nullable=False)
    jti = db.Column(db.String(64), unique=True, nullable=False, index=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    message = db.Column(db.Text, nullable=False)
    application_id = db.Column(
        db.Integer,
        db.ForeignKey("protected_applications.id"),
        nullable=True,
    )
    application_name = db.Column(db.String(160), nullable=True, index=True)
    threat_score = db.Column(db.Integer, nullable=True, index=True)
    matched_rule = db.Column(db.String(120), nullable=True, index=True)
    risk_level = db.Column(db.String(40), nullable=True, index=True)
    action_taken = db.Column(db.String(40), nullable=True, index=True)
    request_path = db.Column(db.String(2048), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SecurityRule(db.Model):
    __tablename__ = "security_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    rule_type = db.Column(db.String(80), nullable=False, index=True)
    pattern = db.Column(db.Text, nullable=True)
    condition = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(40), nullable=False, default="Medium", index=True)
    threat_score = db.Column(db.Integer, nullable=False, default=10)
    action = db.Column(db.String(40), nullable=False, default="Log", index=True)
    priority = db.Column(db.Integer, nullable=False, default=100, index=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    application_id = db.Column(
        db.Integer,
        db.ForeignKey("protected_applications.id"),
        nullable=True,
        index=True,
    )
    created_by = db.Column(db.Integer, db.ForeignKey("admin_users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AppSetting(db.Model):
    __tablename__ = "app_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class ProtectedApplication(db.Model):
    __tablename__ = "protected_applications"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=True)
    public_path = db.Column(db.String(255), unique=True, nullable=False, index=True)
    upstream_url = db.Column(db.String(2048), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    rate_limit_per_minute = db.Column(db.Integer, default=3000, nullable=False)
    burst_limit = db.Column(db.Integer, default=50, nullable=False)
    captcha_enabled = db.Column(db.Boolean, default=True, nullable=False)
    email_alerts = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
