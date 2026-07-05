from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

from flask import (
    Response,
    current_app,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash

from app.models import AdminUser
from app.services.iam_service import (
    authenticate_user,
    create_audit_log,
    current_user,
    has_permission,
    login_user_session,
)


LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudShield Admin Login</title>
  <style>
    body { font-family: Arial, sans-serif; background: #111; color: #fff; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    form { background: #1f1f1f; padding: 24px; border-radius: 8px; width: 320px; }
    input { width: 100%; padding: 10px; margin: 8px 0 14px; box-sizing: border-box; }
    button { width: 100%; padding: 10px; background: #3498db; color: #fff; border: 0; cursor: pointer; }
    .error { color: #e74c3c; }
  </style>
</head>
<body>
  <form method="POST">
    <h1>CloudShield Admin</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <label>Username</label>
    <input name="username" required>
    <label>Password</label>
    <input name="password" type="password" required>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
"""


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def verify_admin_credentials(username: str, password: str) -> bool:
    user, _error = authenticate_user(username, password)
    if user is None:
        return False
    login_user_session(user)
    return True


def login_admin() -> Response | str:
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user, auth_error = authenticate_user(username, password)
        if user:
            login_user_session(user)
            create_audit_log("Login", "Admin UI", "success", user=user)
            return redirect(url_for("admin.admin_panel"))
        create_audit_log("Login", "Admin UI", "failure", auth_error)
        error = auth_error or "Invalid username or password."

    return render_template_string(LOGIN_TEMPLATE, error=error)


def logout_admin() -> Response:
    create_audit_log("Logout", "Admin UI", "success")
    session.clear()
    return redirect(url_for("admin.login"))


def admin_required(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin.login"))

        now = _now()
        last_activity = int(session.get("last_activity", 0))
        if now - last_activity > current_app.config["SESSION_TIMEOUT"]:
            session.clear()
            return redirect(url_for("admin.login"))

        session["last_activity"] = now
        return func(*args, **kwargs)

    return wrapper


def permission_required(permission_code: str) -> Callable[..., Any]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_response = _ensure_authenticated()
            if auth_response is not None:
                return auth_response

            user = current_user()
            if not has_permission(user, permission_code):
                create_audit_log(
                    "Authorization Denied",
                    permission_code,
                    "failure",
                    user=user,
                )
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Forbidden"}), 403
                return render_template_string(
                    "<h1>Forbidden</h1><p>You do not have permission to access this page.</p>"
                ), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator


def _ensure_authenticated() -> Response | None:
    if not session.get("admin_authenticated"):
        return redirect(url_for("admin.login"))

    now = _now()
    last_activity = int(session.get("last_activity", 0))
    if now - last_activity > current_app.config["SESSION_TIMEOUT"]:
        session.clear()
        return redirect(url_for("admin.login"))

    user = current_user()
    if user is None or not user.is_active:
        session.clear()
        return redirect(url_for("admin.login"))

    session["last_activity"] = now
    return None


def user_has_permission(user: AdminUser | None, permission_code: str) -> bool:
    return has_permission(user, permission_code)


def make_password_hash(password: str) -> str:
    return generate_password_hash(password)
