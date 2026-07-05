import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Config:
    """Application configuration loaded from environment variables."""

    APP_NAME = "CloudShield"
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'cloudshield.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@cloudshield.local")

    EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
    EMAIL_PORT = _int_env("EMAIL_PORT", 587)
    EMAIL_USER = os.getenv("EMAIL_USER", "")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
    EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT", "")

    UPSTREAM_TIMEOUT = _int_env("UPSTREAM_TIMEOUT", 30)
    DEFAULT_RATE_LIMIT = _int_env("DEFAULT_RATE_LIMIT", 50)
    THREAT_WINDOW_SECONDS = _int_env("THREAT_WINDOW_SECONDS", 60)
    THREAT_BURST_WINDOW_SECONDS = _int_env("THREAT_BURST_WINDOW_SECONDS", 5)
    THREAT_TEMP_BLOCK_SECONDS = _int_env("THREAT_TEMP_BLOCK_SECONDS", 600)
    THREAT_LONG_URL_LENGTH = _int_env("THREAT_LONG_URL_LENGTH", 2000)
    THREAT_404_LIMIT = _int_env("THREAT_404_LIMIT", 5)
    THREAT_ADMIN_PATH_LIMIT = _int_env("THREAT_ADMIN_PATH_LIMIT", 3)
    THREAT_SUSPICIOUS_USER_AGENTS = os.getenv(
        "THREAT_SUSPICIOUS_USER_AGENTS",
        "sqlmap,nikto,nmap,masscan,acunetix,nessus,dirbuster,hydra",
    )

    BLOCKED_IPS_FILE = os.getenv("BLOCKED_IPS_FILE", str(BASE_DIR / "blocked_ips.txt"))
    SESSION_TIMEOUT = _int_env("SESSION_TIMEOUT", 1800)
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=SESSION_TIMEOUT)
    JWT_ACCESS_TOKEN_SECONDS = _int_env("JWT_ACCESS_TOKEN_SECONDS", 900)
    JWT_REFRESH_TOKEN_SECONDS = _int_env("JWT_REFRESH_TOKEN_SECONDS", 604800)
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = _int_env("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300)
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS = _int_env("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5)
    ACCOUNT_LOCKOUT_MINUTES = _int_env("ACCOUNT_LOCKOUT_MINUTES", 15)
    PASSWORD_MIN_LENGTH = _int_env("PASSWORD_MIN_LENGTH", 12)
    REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT = _int_env("REDIS_PORT", 6379)
    REDIS_DB = _int_env("REDIS_DB", 0)
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
    REDIS_SSL = os.getenv("REDIS_SSL", "false").lower() == "true"
    REDIS_SOCKET_TIMEOUT = _int_env("REDIS_SOCKET_TIMEOUT", 2)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

    WTF_CSRF_ENABLED = os.getenv("WTF_CSRF_ENABLED", "false").lower() == "true"

    LOG_DIR = BASE_DIR / "logs"
    APP_LOG_FILE = LOG_DIR / "application.log"
    SECURITY_LOG_FILE = LOG_DIR / "security.log"
    ERROR_LOG_FILE = LOG_DIR / "errors.log"
