from flask import Blueprint, redirect, render_template, request, url_for
from sqlalchemy import or_

from app.models import (
    AdminUser,
    ApiKey,
    AuditLog,
    Permission,
    ProtectedApplication,
    RefreshToken,
    Role,
    SecurityRule,
    SecurityEvent,
    UserRole,
)
from app.security.auth import login_admin, logout_admin, permission_required
from app.security.ip_validation import is_valid_ip
from app.services.application_registry import (
    check_application_health,
    create_application,
    update_application,
    validate_application_form,
)
from app.services.api_key_service import create_api_key, revoke_api_key
from app.services.iam_service import (
    create_audit_log,
    create_user,
    current_user,
    set_user_password,
    update_user,
    user_roles,
    validate_password_policy,
)
from app.services.runtime import get_blocklist, get_rate_limiter
from app.services.rule_service import (
    ACTIONS,
    RULE_TYPES,
    SEVERITIES,
    clone_rule,
    create_rule,
    form_to_rule_request,
    match_rules,
    recommended_action,
    update_rule,
)
from app.services.threat_summary_service import (
    recent_threats,
    risk_level_counts,
    threat_distribution,
    top_triggered_rules,
)
from extensions import db


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/login", methods=["GET", "POST"])
def login():
    return login_admin()


@admin_bp.route("/admin/logout", methods=["GET", "POST"])
def logout():
    return logout_admin()


@admin_bp.route("/admin", methods=["GET", "POST"])
@permission_required("view_dashboard")
def admin_panel():
    blocklist = get_blocklist()
    rate_limiter = get_rate_limiter()

    if request.method == "POST":
        ip_to_block = request.form.get("ip_to_block")
        ip_to_unblock = request.form.get("ip_to_unblock")

        if ip_to_block and is_valid_ip(ip_to_block):
            blocklist.add(ip_to_block)
            create_audit_log("Block IP", ip_to_block, "success")

        if ip_to_unblock and is_valid_ip(ip_to_unblock):
            blocklist.discard(ip_to_unblock)
            create_audit_log("Unblock IP", ip_to_unblock, "success")

        return redirect(url_for("admin.admin_panel"))

    return render_template(
        "admin.html",
        ip_stats=rate_limiter.stats(),
        recent_logs=rate_limiter.recent_logs(),
        blocked_ips=blocklist.all(),
        recent_threats=recent_threats(),
        top_rules=top_triggered_rules(),
        threat_distribution=threat_distribution(),
        risk_counts=risk_level_counts(),
    )


@admin_bp.route("/admin/applications", methods=["GET", "POST"])
@permission_required("manage_applications")
def applications():
    errors: list[str] = []

    if request.method == "POST":
        errors = validate_application_form(
            request.form.get("public_path", ""),
            request.form.get("upstream_url", ""),
        )
        if not request.form.get("name", "").strip():
            errors.append("Application name is required.")

        if not errors:
            application = create_application(request.form)
            create_audit_log("Create Protected App", application.name, "success")
            return redirect(url_for("admin.applications"))

    protected_applications = ProtectedApplication.query.order_by(
        ProtectedApplication.public_path.asc()
    ).all()
    statuses = {
        application.id: check_application_health(application).value
        for application in protected_applications
    }
    return render_template(
        "applications.html",
        applications=protected_applications,
        statuses=statuses,
        errors=errors,
        tested=request.args.get("tested"),
        tested_status=request.args.get("status"),
    )


@admin_bp.route("/admin/applications/<int:application_id>/edit", methods=["GET", "POST"])
@permission_required("manage_applications")
def edit_application(application_id: int):
    application = ProtectedApplication.query.get_or_404(application_id)
    errors: list[str] = []

    if request.method == "POST":
        errors = validate_application_form(
            request.form.get("public_path", ""),
            request.form.get("upstream_url", ""),
            application_id=application.id,
        )
        if not request.form.get("name", "").strip():
            errors.append("Application name is required.")

        if not errors:
            update_application(application, request.form)
            create_audit_log("Edit Protected App", application.name, "success")
            return redirect(url_for("admin.applications"))

    return render_template(
        "application_form.html",
        application=application,
        errors=errors,
    )


@admin_bp.route("/admin/applications/<int:application_id>/delete", methods=["POST"])
@permission_required("manage_applications")
def delete_application(application_id: int):
    application = ProtectedApplication.query.get_or_404(application_id)
    application_name = application.name
    db.session.delete(application)
    db.session.commit()
    create_audit_log("Delete Protected App", application_name, "success")
    return redirect(url_for("admin.applications"))


@admin_bp.route("/admin/applications/<int:application_id>/toggle", methods=["POST"])
@permission_required("manage_applications")
def toggle_application(application_id: int):
    application = ProtectedApplication.query.get_or_404(application_id)
    application.enabled = not application.enabled
    db.session.commit()
    create_audit_log("Toggle Protected App", application.name, "success")
    return redirect(url_for("admin.applications"))


@admin_bp.route("/admin/applications/<int:application_id>/test", methods=["POST"])
@permission_required("manage_applications")
def test_application(application_id: int):
    application = ProtectedApplication.query.get_or_404(application_id)
    status = check_application_health(application).value
    create_audit_log("Test Protected App", application.name, "success", status)
    return redirect(url_for("admin.applications", tested=application.id, status=status))


@admin_bp.route("/admin/users", methods=["GET", "POST"])
@permission_required("manage_users")
def users():
    errors: list[str] = []
    if request.method == "POST":
        user, errors = create_user(request.form, assigned_by_id=current_user().id)
        if user:
            create_audit_log("Create User", user.username, "success")
            return redirect(url_for("admin.users"))

    all_users = AdminUser.query.order_by(AdminUser.username.asc()).all()
    roles = Role.query.order_by(Role.name.asc()).all()
    return render_template(
        "users.html",
        users=all_users,
        roles=roles,
        user_roles=user_roles,
        errors=errors,
    )


@admin_bp.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@permission_required("manage_users")
def edit_user(user_id: int):
    user = AdminUser.query.get_or_404(user_id)
    errors: list[str] = []
    if request.method == "POST":
        errors = update_user(user, request.form, assigned_by_id=current_user().id)
        if not errors:
            create_audit_log("Edit User", user.username, "success")
            return redirect(url_for("admin.users"))

    roles = Role.query.order_by(Role.name.asc()).all()
    assigned_role_ids = {role.id for role in user_roles(user)}
    return render_template(
        "user_form.html",
        managed_user=user,
        roles=roles,
        assigned_role_ids=assigned_role_ids,
        errors=errors,
    )


@admin_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@permission_required("manage_users")
def delete_user(user_id: int):
    user = AdminUser.query.get_or_404(user_id)
    if current_user() and current_user().id == user.id:
        create_audit_log("Delete User", user.username, "failure", "Self-delete denied.")
        return redirect(url_for("admin.users"))
    username = user.username
    UserRole.query.filter_by(user_id=user.id).delete()
    RefreshToken.query.filter_by(user_id=user.id).delete()
    ApiKey.query.filter_by(created_by_id=user.id).update({"created_by_id": None})
    db.session.delete(user)
    db.session.commit()
    create_audit_log("Delete User", username, "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/admin/roles", methods=["GET", "POST"])
@permission_required("manage_users")
def roles():
    if request.method == "POST":
        role = Role.query.get_or_404(int(request.form.get("role_id", "0")))
        permission_ids = [int(value) for value in request.form.getlist("permission_ids")]
        role.permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
        db.session.commit()
        create_audit_log("Change Role Permissions", role.name, "success")
        return redirect(url_for("admin.roles"))

    roles_list = Role.query.order_by(Role.name.asc()).all()
    permissions = Permission.query.order_by(Permission.name.asc()).all()
    return render_template("roles.html", roles=roles_list, permissions=permissions)


@admin_bp.route("/admin/password", methods=["GET", "POST"])
@permission_required("view_dashboard")
def change_password():
    errors: list[str] = []
    if request.method == "POST":
        password = request.form.get("password", "")
        errors = validate_password_policy(password)
        if not errors and current_user():
            set_user_password(current_user(), password)
            create_audit_log("Password Change", current_user().username, "success")
            return redirect(url_for("admin.admin_panel"))
    return render_template("change_password.html", errors=errors)


@admin_bp.route("/admin/api-keys", methods=["GET", "POST"])
@permission_required("manage_api_keys")
def api_keys():
    plaintext_key = None
    if request.method == "POST":
        api_key, plaintext_key = create_api_key(request.form, current_user().id)
        create_audit_log("Generate API Key", api_key.key_name, "success")
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template("api_keys.html", api_keys=keys, plaintext_key=plaintext_key)


@admin_bp.route("/admin/api-keys/<int:key_id>/revoke", methods=["POST"])
@permission_required("manage_api_keys")
def revoke_key(key_id: int):
    api_key = ApiKey.query.get_or_404(key_id)
    revoke_api_key(api_key)
    create_audit_log("Revoke API Key", api_key.key_name, "success")
    return redirect(url_for("admin.api_keys"))


@admin_bp.route("/admin/audit-logs", methods=["GET"])
@permission_required("view_audit_logs")
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("audit_logs.html", audit_logs=logs)


@admin_bp.route("/admin/threats", methods=["GET"])
@permission_required("view_threats")
def threat_explorer():
    query = SecurityEvent.query
    search = request.args.get("search", "").strip()
    risk_level = request.args.get("risk_level", "").strip()
    application = request.args.get("application", "").strip()
    action = request.args.get("action", "").strip()

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                SecurityEvent.ip_address.ilike(pattern),
                SecurityEvent.application_name.ilike(pattern),
                SecurityEvent.matched_rule.ilike(pattern),
                SecurityEvent.request_path.ilike(pattern),
                SecurityEvent.message.ilike(pattern),
            )
        )
    if risk_level:
        query = query.filter(SecurityEvent.risk_level == risk_level)
    if application:
        query = query.filter(SecurityEvent.application_name == application)
    if action:
        query = query.filter(SecurityEvent.action_taken == action)

    events = query.order_by(SecurityEvent.created_at.desc()).limit(200).all()
    all_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(200).all()
    applications = sorted(
        {event.application_name for event in all_events if event.application_name}
    )
    actions = sorted({event.action_taken for event in all_events if event.action_taken})
    risk_levels = ["Critical", "High Risk", "Suspicious", "Normal"]
    return render_template(
        "threat_explorer.html",
        events=events,
        applications=applications,
        actions=actions,
        risk_levels=risk_levels,
        filters={
            "search": search,
            "risk_level": risk_level,
            "application": application,
            "action": action,
        },
    )


@admin_bp.route("/admin/security-events", methods=["GET"])
@permission_required("view_threats")
def security_events():
    query = SecurityEvent.query
    search = request.args.get("search", "").strip()
    risk_level = request.args.get("risk_level", "").strip()
    action = request.args.get("action", "").strip()

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                SecurityEvent.event_type.ilike(pattern),
                SecurityEvent.ip_address.ilike(pattern),
                SecurityEvent.application_name.ilike(pattern),
                SecurityEvent.matched_rule.ilike(pattern),
                SecurityEvent.request_path.ilike(pattern),
                SecurityEvent.message.ilike(pattern),
            )
        )
    if risk_level:
        query = query.filter(SecurityEvent.risk_level == risk_level)
    if action:
        query = query.filter(SecurityEvent.action_taken == action)

    events = query.order_by(SecurityEvent.created_at.desc()).limit(300).all()
    all_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(300).all()
    actions = sorted({event.action_taken for event in all_events if event.action_taken})
    risk_levels = ["Critical", "High Risk", "Suspicious", "Normal"]
    return render_template(
        "security_events.html",
        events=events,
        actions=actions,
        risk_levels=risk_levels,
        filters={
            "search": search,
            "risk_level": risk_level,
            "action": action,
        },
    )


@admin_bp.route("/admin/reports", methods=["GET"])
@permission_required("export_reports")
def reports():
    return render_template(
        "placeholder_page.html",
        page_title="Reports",
        active_page="reports",
    )


@admin_bp.route("/admin/monitoring", methods=["GET"])
@permission_required("view_dashboard")
def monitoring():
    return render_template(
        "placeholder_page.html",
        page_title="Monitoring",
        active_page="monitoring",
    )


@admin_bp.route("/admin/settings", methods=["GET"])
@permission_required("manage_settings")
def settings():
    return render_template(
        "placeholder_page.html",
        page_title="Settings",
        active_page="settings",
    )


@admin_bp.route("/admin/rules", methods=["GET", "POST"])
@permission_required("manage_rules")
def rules():
    errors: list[str] = []
    if request.method == "POST":
        if not request.form.get("name", "").strip():
            errors.append("Rule name is required.")
        if not errors:
            rule = create_rule(request.form, created_by=current_user().id)
            create_audit_log("Create Rule", rule.name, "success")
            return redirect(url_for("admin.rules"))

    query = SecurityRule.query
    search = request.args.get("search", "").strip()
    rule_type = request.args.get("rule_type", "").strip()
    enabled = request.args.get("enabled", "").strip()
    if search:
        query = query.filter(SecurityRule.name.ilike(f"%{search}%"))
    if rule_type:
        query = query.filter_by(rule_type=rule_type)
    if enabled in {"true", "false"}:
        query = query.filter_by(enabled=enabled == "true")
    rules_list = query.order_by(SecurityRule.priority.asc(), SecurityRule.id.asc()).all()
    applications = ProtectedApplication.query.order_by(ProtectedApplication.name.asc()).all()
    return render_template(
        "rules.html",
        rules=rules_list,
        applications=applications,
        rule_types=RULE_TYPES,
        actions=ACTIONS,
        severities=SEVERITIES,
        errors=errors,
        search=search,
        selected_type=rule_type,
        selected_enabled=enabled,
    )


@admin_bp.route("/admin/rules/<int:rule_id>/edit", methods=["GET", "POST"])
@permission_required("manage_rules")
def edit_rule(rule_id: int):
    rule = SecurityRule.query.get_or_404(rule_id)
    errors: list[str] = []
    if request.method == "POST":
        if not request.form.get("name", "").strip():
            errors.append("Rule name is required.")
        if not errors:
            update_rule(rule, request.form)
            create_audit_log("Edit Rule", rule.name, "success")
            return redirect(url_for("admin.rules"))
    applications = ProtectedApplication.query.order_by(ProtectedApplication.name.asc()).all()
    return render_template(
        "rule_form.html",
        rule=rule,
        applications=applications,
        rule_types=RULE_TYPES,
        actions=ACTIONS,
        severities=SEVERITIES,
        errors=errors,
    )


@admin_bp.route("/admin/rules/<int:rule_id>/toggle", methods=["POST"])
@permission_required("manage_rules")
def toggle_rule(rule_id: int):
    rule = SecurityRule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    create_audit_log("Toggle Rule", rule.name, "success")
    return redirect(url_for("admin.rules"))


@admin_bp.route("/admin/rules/<int:rule_id>/clone", methods=["POST"])
@permission_required("manage_rules")
def clone_security_rule(rule_id: int):
    rule = SecurityRule.query.get_or_404(rule_id)
    cloned = clone_rule(rule, created_by=current_user().id)
    create_audit_log("Clone Rule", cloned.name, "success")
    return redirect(url_for("admin.rules"))


@admin_bp.route("/admin/rules/<int:rule_id>/delete", methods=["POST"])
@permission_required("manage_rules")
def delete_rule(rule_id: int):
    rule = SecurityRule.query.get_or_404(rule_id)
    name = rule.name
    db.session.delete(rule)
    db.session.commit()
    create_audit_log("Delete Rule", name, "success")
    return redirect(url_for("admin.rules"))


@admin_bp.route("/admin/rules/test", methods=["GET", "POST"])
@permission_required("manage_rules")
def test_rule():
    results = None
    if request.method == "POST":
        rule_request = form_to_rule_request(request.form)
        matches = match_rules(rule_request)
        results = {
            "matches": matches,
            "score": sum(match.rule.threat_score for match in matches),
            "action": recommended_action([match.rule.action for match in matches]),
        }
        create_audit_log("Test Rule", "Rule Tester", "success")
    return render_template("rule_tester.html", results=results)
