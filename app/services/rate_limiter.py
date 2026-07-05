from datetime import datetime
import time
import uuid

from app.services.redis_service import get_runtime_store


class InMemoryRateLimiter:
    """Original one-second per-IP request threshold, isolated as a service."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self._events_key = "cloudshield:runtime:rate:events"

    def record(self, ip_address: str) -> int:
        now = time.time()
        store = get_runtime_store()
        member = f"{now}|{ip_address}|{uuid.uuid4().hex}"
        store.zadd(self._events_key, now, member, ttl=60)
        store.zremrangebyscore(self._events_key, 0, now - 1)
        return sum(1 for event in self._recent_events(now) if self._event_ip(event) == ip_address)

    def is_over_limit(self, ip_address: str) -> bool:
        return self.record(ip_address) > self.threshold

    def stats(self) -> dict[str, int]:
        now = time.time()
        stats: dict[str, int] = {}
        for event in self._recent_events(now):
            ip_address = self._event_ip(event)
            if ip_address:
                stats[ip_address] = stats.get(ip_address, 0) + 1
        return stats

    def recent_logs(self, limit: int = 10) -> list[str]:
        now = time.time()
        events = self._recent_events(now)[-limit:]
        return [self._format_event(event) for event in events if self._format_event(event)]

    def _recent_events(self, now: float) -> list[str]:
        return get_runtime_store().zrangebyscore(self._events_key, now - 1, now)

    def _event_ip(self, event: str) -> str:
        parts = event.split("|", 2)
        return parts[1] if len(parts) >= 2 else ""

    def _format_event(self, event: str) -> str:
        parts = event.split("|", 2)
        if len(parts) < 2:
            return ""
        timestamp = datetime.fromtimestamp(float(parts[0]))
        return f"{parts[1]} at {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
