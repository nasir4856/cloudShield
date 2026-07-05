from flask import Flask

from config import Config
from extensions import db

from app.routes.admin import admin_bp
from app.routes.auth_api import auth_api_bp
from app.routes.captcha import captcha_bp
from app.routes.firewall import firewall_bp
from app.routes.health import health_bp
from app.security.csrf import init_csrf
from app.services.iam_service import seed_iam_defaults
from app.services.redis_service import init_redis
from app.services.rule_service import seed_default_rules
from app.services.runtime import init_runtime_services
from app.utils.errors import register_error_handlers
from app.utils.logging import configure_logging


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_class)

    configure_logging(app)
    init_csrf(app)
    init_redis(app)
    db.init_app(app)
    init_runtime_services(app)

    with app.app_context():
        db.create_all()
        app.logger.info("Database initialized.")
        seed_iam_defaults()
        seed_default_rules()

    app.register_blueprint(health_bp)
    app.logger.info("Health service ready.")
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_api_bp)
    app.register_blueprint(captcha_bp)
    app.register_blueprint(firewall_bp)
    register_error_handlers(app)
    app.logger.info("Application started.")

    return app
