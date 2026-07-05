from sqlalchemy import func

from app.models import SecurityEvent


def recent_threats(limit: int = 10) -> list[SecurityEvent]:
    return (
        SecurityEvent.query.filter(SecurityEvent.matched_rule.isnot(None))
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
        .all()
    )


def top_triggered_rules(limit: int = 5) -> list[tuple[str, int]]:
    return (
        SecurityEvent.query.with_entities(
            SecurityEvent.matched_rule,
            func.count(SecurityEvent.id),
        )
        .filter(SecurityEvent.matched_rule.isnot(None))
        .group_by(SecurityEvent.matched_rule)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(limit)
        .all()
    )


def threat_distribution() -> list[tuple[str, int]]:
    return (
        SecurityEvent.query.with_entities(
            SecurityEvent.risk_level,
            func.count(SecurityEvent.id),
        )
        .filter(SecurityEvent.risk_level.isnot(None))
        .group_by(SecurityEvent.risk_level)
        .all()
    )


def risk_level_counts() -> dict[str, int]:
    counts = {level: 0 for level in ["Normal", "Suspicious", "High Risk", "Critical"]}
    for risk_level, count in threat_distribution():
        counts[risk_level] = count
    return counts

