from sqlalchemy import func

from app.models import ProtectedApplication, SecurityEvent


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


def application_activity_summary(limit: int = 5) -> list[tuple[str, int]]:
    return (
        SecurityEvent.query.with_entities(
            SecurityEvent.application_name,
            func.count(SecurityEvent.id),
        )
        .filter(SecurityEvent.application_name.isnot(None))
        .group_by(SecurityEvent.application_name)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(limit)
        .all()
    )


def summarize_application_metrics(applications: list[ProtectedApplication]) -> dict[int, dict[str, int]]:
    metrics: dict[int, dict[str, int]] = {}
    for application in applications:
        events = SecurityEvent.query.filter_by(application_id=application.id).all()
        metrics[application.id] = {
            "request_volume": len(events),
            "threat_count": sum(1 for event in events if event.matched_rule is not None),
        }
    return metrics

