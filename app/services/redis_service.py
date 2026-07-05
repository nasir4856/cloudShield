from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import RLock
from typing import Any

from flask import Flask


try:
    import redis
except ImportError:  # pragma: no cover - exercised only when dependency missing.
    redis = None


logger = logging.getLogger(__name__)


class RuntimeStore:
    """Redis-backed runtime store with transparent in-memory fallback."""

    def __init__(self) -> None:
        self._redis: Any = None
        self._fallback_enabled = True
        self._lock = RLock()
        self._values: dict[str, tuple[str, float | None]] = {}
        self._counters: dict[str, tuple[int, float | None]] = {}
        self._zsets: dict[str, dict[str, float]] = defaultdict(dict)

    @property
    def using_redis(self) -> bool:
        return self._redis is not None

    @property
    def fallback_enabled(self) -> bool:
        return self._redis is None and self._fallback_enabled

    def init_app(self, app: Flask) -> None:
        if redis is None:
            logger.warning("Redis package unavailable. Runtime fallback enabled.")
            return

        try:
            self._redis = redis.Redis(
                host=app.config["REDIS_HOST"],
                port=app.config["REDIS_PORT"],
                db=app.config["REDIS_DB"],
                password=app.config["REDIS_PASSWORD"] or None,
                ssl=app.config["REDIS_SSL"],
                socket_timeout=app.config["REDIS_SOCKET_TIMEOUT"],
                decode_responses=True,
            )
            self._redis.ping()
            logger.info("Redis connected for CloudShield runtime state.")
        except Exception as exc:
            self._redis = None
            self._fallback_enabled = True
            logger.warning(
                "Redis unavailable. Runtime fallback enabled. error=%s",
                exc,
            )

    def health(self) -> dict[str, Any]:
        if self._redis is None:
            return {
                "status": "fallback",
                "connected": False,
                "fallback_enabled": True,
            }
        try:
            self._redis.ping()
        except Exception as exc:
            self._handle_cache_error(exc)
            return {
                "status": "fallback",
                "connected": False,
                "fallback_enabled": True,
                "error": "Redis ping failed; fallback enabled.",
            }
        return {
            "status": "healthy",
            "connected": True,
            "fallback_enabled": False,
        }

    def zadd(self, key: str, score: float, member: str, ttl: int | None = None) -> None:
        if self._redis is not None:
            try:
                self._redis.zadd(key, {member: score})
                if ttl:
                    self._redis.expire(key, ttl)
                return
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._zsets[key][member] = score

    def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> None:
        if self._redis is not None:
            try:
                self._redis.zremrangebyscore(key, min_score, max_score)
                return
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            for member, score in list(self._zsets[key].items()):
                if min_score <= score <= max_score:
                    self._zsets[key].pop(member, None)

    def zcard(self, key: str) -> int:
        if self._redis is not None:
            try:
                return int(self._redis.zcard(key))
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            return len(self._zsets[key])

    def zcount(self, key: str, min_score: float, max_score: float) -> int:
        if self._redis is not None:
            try:
                return int(self._redis.zcount(key, min_score, max_score))
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            return sum(1 for score in self._zsets[key].values() if min_score <= score <= max_score)

    def zrangebyscore(self, key: str, min_score: float, max_score: float) -> list[str]:
        if self._redis is not None:
            try:
                return list(self._redis.zrangebyscore(key, min_score, max_score))
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            return [
                member
                for member, score in sorted(self._zsets[key].items(), key=lambda item: item[1])
                if min_score <= score <= max_score
            ]

    def incr(self, key: str, ttl: int | None = None) -> int:
        if self._redis is not None:
            try:
                value = int(self._redis.incr(key))
                if ttl and value == 1:
                    self._redis.expire(key, ttl)
                return value
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._prune_key(key)
            value, expires_at = self._counters.get(key, (0, None))
            value += 1
            if ttl and expires_at is None:
                expires_at = time.time() + ttl
            self._counters[key] = (value, expires_at)
            return value

    def get_int(self, key: str) -> int:
        if self._redis is not None:
            try:
                value = self._redis.get(key)
                return int(value or 0)
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._prune_key(key)
            return self._counters.get(key, (0, None))[0]

    def setex(self, key: str, ttl: int, value: str) -> None:
        if self._redis is not None:
            try:
                self._redis.setex(key, ttl, value)
                return
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._values[key] = (value, time.time() + ttl)

    def exists(self, key: str) -> bool:
        if self._redis is not None:
            try:
                return bool(self._redis.exists(key))
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._prune_key(key)
            return key in self._values

    def ttl(self, key: str) -> int:
        if self._redis is not None:
            try:
                return int(self._redis.ttl(key))
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._prune_key(key)
            if key not in self._values:
                return -2
            expires_at = self._values[key][1]
            if expires_at is None:
                return -1
            return max(0, int(expires_at - time.time()))

    def delete(self, key: str) -> None:
        if self._redis is not None:
            try:
                self._redis.delete(key)
                return
            except Exception as exc:
                self._handle_cache_error(exc)
        with self._lock:
            self._values.pop(key, None)
            self._counters.pop(key, None)
            self._zsets.pop(key, None)

    def _handle_cache_error(self, exc: Exception) -> None:
        logger.warning("Redis cache error. Fallback enabled. error=%s", exc)
        self._redis = None
        self._fallback_enabled = True

    def _prune_key(self, key: str) -> None:
        now = time.time()
        if key in self._values:
            expires_at = self._values[key][1]
            if expires_at is not None and expires_at <= now:
                self._values.pop(key, None)
        if key in self._counters:
            expires_at = self._counters[key][1]
            if expires_at is not None and expires_at <= now:
                self._counters.pop(key, None)


runtime_store = RuntimeStore()


def init_redis(app: Flask) -> None:
    runtime_store.init_app(app)


def get_runtime_store() -> RuntimeStore:
    return runtime_store
