from flask import Flask

from app.services.blocklist_service import BlocklistService
from app.services.rate_limiter import InMemoryRateLimiter


blocklist: BlocklistService | None = None
rate_limiter: InMemoryRateLimiter | None = None


def init_runtime_services(app: Flask) -> None:
    global blocklist, rate_limiter
    blocklist = BlocklistService(app.config["BLOCKED_IPS_FILE"])
    rate_limiter = InMemoryRateLimiter(app.config["DEFAULT_RATE_LIMIT"])


def get_blocklist() -> BlocklistService:
    if blocklist is None:
        raise RuntimeError("Blocklist service has not been initialized.")
    return blocklist


def get_rate_limiter() -> InMemoryRateLimiter:
    if rate_limiter is None:
        raise RuntimeError("Rate limiter service has not been initialized.")
    return rate_limiter

