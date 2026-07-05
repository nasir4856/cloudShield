import secrets

from flask import Flask, abort, request, session


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_field() -> str:
    return f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'


def init_csrf(app: Flask) -> None:
    @app.context_processor
    def inject_csrf_helpers():
        return {"csrf_token": csrf_token, "csrf_field": csrf_field}

    @app.before_request
    def protect_admin_forms():
        if not app.config["WTF_CSRF_ENABLED"]:
            return None
        if request.method != "POST":
            return None
        if not request.path.startswith("/admin"):
            return None
        if request.path == "/admin/login":
            return None
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token")
        if not expected or not supplied or supplied != expected:
            abort(400)
        return None
