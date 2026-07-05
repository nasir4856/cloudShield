from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from enum import Enum
import uuid

from flask import Request, current_app

from app.models import ProtectedApplication, SecurityEvent
from app.services.rule_service import (
    RuleMatchResult,
    match_rules,
    recommended_action,
    request_to_rule_request,
)
from app.services.redis_service import get_runtime_store
from extensions import db


security_logger = logging.getLogger("cloudshield.security")


class RiskLevel(str, Enum):
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CRITICAL = "Critical"


class ThreatAction(str, Enum):
    ALLOW = "Allow"
    LOG = "Log"
    CAPTCHA = "CAPTCHA"
    TEMPORARY_BLOCK = "Temporary Block"
    PERMANENT_BLOCK = "Permanent Block"


@dataclass(frozen=True)
class RuleMatch:
    name: str
    score: int
    message: str


@dataclass(frozen=True)
class ThreatResult:
    score: int
    risk_level: RiskLevel
    action: ThreatAction
    matches: list[RuleMatch]


def is_temporarily_blocked(ip_address: str) -> bool:
    return get_runtime_store().exists(_temporary_block_key(ip_address))


def temporary_block_remaining(ip_address: str) -> int:
    return max(0, get_runtime_store().ttl(_temporary_block_key(ip_address)))


def apply_temporary_block(ip_address: str) -> None:
    get_runtime_store().setex(
        _temporary_block_key(ip_address),
        current_app.config["THREAT_TEMP_BLOCK_SECONDS"],
        "1",
    )


def record_response(ip_address: str, status_code: int) -> None:
    if status_code == 404:
        get_runtime_store().incr(_not_found_key(ip_address))


def check_rate(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del request_obj
    now = time.time()
    window = current_app.config["THREAT_WINDOW_SECONDS"]
    key = _request_times_key(ip_address)
    store = get_runtime_store()
    store.zadd(key, now, f"{now}|{uuid.uuid4().hex}", ttl=window * 2)
    store.zremrangebyscore(key, 0, now - window)

    request_count = store.zcard(key)
    if request_count > application.rate_limit_per_minute:
        return RuleMatch(
            "Rate Threshold",
            30,
            f"{request_count} requests within {window} seconds.",
        )
    return None


def check_repeated_requests(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del request_obj
    now = time.time()
    burst_window = current_app.config["THREAT_BURST_WINDOW_SECONDS"]
    burst_count = get_runtime_store().zcount(
        _request_times_key(ip_address),
        now - burst_window,
        now,
    )

    if burst_count > application.burst_limit:
        return RuleMatch(
            "Repeated requests within short interval",
            20,
            f"{burst_count} requests within {burst_window} seconds.",
        )
    return None


def check_user_agent(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application, ip_address
    user_agent = request_obj.headers.get("User-Agent", "")
    if not user_agent:
        return RuleMatch("Missing User-Agent", 10, "Request has no User-Agent header.")

    suspicious_agents = [
        item.strip().lower()
        for item in current_app.config["THREAT_SUSPICIOUS_USER_AGENTS"].split(",")
        if item.strip()
    ]
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        return RuleMatch(
            "Suspicious User-Agent",
            20,
            f"User-Agent matched suspicious signature: {user_agent[:120]}",
        )
    return None


def check_too_many_404(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del request_obj, application
    count = get_runtime_store().get_int(_not_found_key(ip_address))
    if count > current_app.config["THREAT_404_LIMIT"]:
        return RuleMatch("Too many 404 responses", 15, f"{count} prior 404 responses.")
    return None


def check_admin_paths(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application
    path = request_obj.path.lower()
    if "/admin" not in path:
        return None

    count = get_runtime_store().incr(_admin_path_key(ip_address))
    if count > current_app.config["THREAT_ADMIN_PATH_LIMIT"]:
        return RuleMatch(
            "Repeated access to admin paths",
            25,
            f"{count} admin-path requests observed.",
        )
    return None


def check_attack_paths(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application, ip_address
    path = request_obj.path.lower()
    attack_paths = ["/admin", "/phpmyadmin", "/.env", "/.git", "/config", "/wp-admin"]
    if any(marker in path for marker in attack_paths):
        return RuleMatch("Access to common attack paths", 35, f"Path matched: {path}")
    return None


def check_long_url(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application, ip_address
    url_length = len(request_obj.full_path)
    if url_length > current_app.config["THREAT_LONG_URL_LENGTH"]:
        return RuleMatch("Very long URL", 15, f"URL length was {url_length}.")
    return None


def check_sqli(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application, ip_address
    payload = _request_payload(request_obj)
    patterns = [r"union\s+select", r"'\s*or\s+1\s*=\s*1", r"drop\s+table"]
    if any(re.search(pattern, payload, re.IGNORECASE) for pattern in patterns):
        return RuleMatch("SQL Injection patterns", 40, "SQL injection signature detected.")
    return None


def check_xss(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application, ip_address
    payload = _request_payload(request_obj).lower()
    patterns = ["<script", "javascript:", "onerror="]
    if any(pattern in payload for pattern in patterns):
        return RuleMatch("Cross Site Scripting patterns", 40, "XSS signature detected.")
    return None


def check_path_traversal(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> RuleMatch | None:
    del application, ip_address
    payload = _request_payload(request_obj)
    if "../" in payload or "..\\" in payload:
        return RuleMatch("Path Traversal", 40, "Path traversal signature detected.")
    return None


def evaluate_request(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
) -> ThreatResult:
    rule_request = request_to_rule_request(request_obj)
    db_matches = match_rules(rule_request, application)
    matches = [
        RuleMatch(match.rule.name, match.rule.threat_score, match.message)
        for match in db_matches
    ]
    # Stateful behavioral checks remain outside simple pattern matching but map to
    # seeded rule names and preserve the previous protection behavior.
    for check in [check_rate, check_repeated_requests, check_too_many_404, check_admin_paths]:
        match = check(request_obj, application, ip_address)
        if match:
            matches.append(match)
    score = sum(match.score for match in matches)
    risk_level = _risk_level(score)
    db_actions = [match.rule.action for match in db_matches]
    action = _action_for_name(recommended_action(db_actions)) or _action_for_risk(risk_level)
    if ACTION_RANK.get(action.value, 0) < ACTION_RANK.get(_action_for_risk(risk_level).value, 0):
        action = _action_for_risk(risk_level)

    for match in matches:
        security_logger.warning(
            "Threat rule triggered ip=%s app=%s rule=%s score=%s",
            ip_address,
            application.name,
            match.name,
            match.score,
        )

    security_logger.info(
        "Threat evaluation ip=%s app=%s threat_score=%s risk=%s action=%s",
        ip_address,
        application.name,
        score,
        risk_level.value,
        action.value,
    )

    result = ThreatResult(score, risk_level, action, matches)
    persist_security_events(request_obj, application, ip_address, result)
    return result


def persist_security_events(
    request_obj: Request,
    application: ProtectedApplication,
    ip_address: str,
    result: ThreatResult,
) -> None:
    if not result.matches:
        return

    for match in result.matches:
        event = SecurityEvent(
            event_type="threat_rule_triggered",
            ip_address=ip_address,
            message=match.message,
            application_id=application.id,
            application_name=application.name,
            threat_score=result.score,
            matched_rule=match.name,
            risk_level=result.risk_level.value,
            action_taken=result.action.value,
            request_path=request_obj.full_path.rstrip("?"),
        )
        db.session.add(event)
    db.session.commit()


def _risk_level(score: int) -> RiskLevel:
    if score <= 20:
        return RiskLevel.NORMAL
    if score <= 40:
        return RiskLevel.SUSPICIOUS
    if score <= 70:
        return RiskLevel.HIGH_RISK
    return RiskLevel.CRITICAL


def _action_for_risk(risk_level: RiskLevel) -> ThreatAction:
    if risk_level == RiskLevel.NORMAL:
        return ThreatAction.ALLOW
    if risk_level == RiskLevel.SUSPICIOUS:
        return ThreatAction.LOG
    if risk_level == RiskLevel.HIGH_RISK:
        return ThreatAction.CAPTCHA
    return ThreatAction.TEMPORARY_BLOCK


ACTION_RANK = {
    "Allow": 0,
    "Log": 1,
    "Rate Limit": 2,
    "CAPTCHA": 3,
    "Temporary Block": 4,
    "Permanent Block": 5,
}


def _action_for_name(action: str) -> ThreatAction | None:
    if action == "Allow":
        return ThreatAction.ALLOW
    if action in {"Log", "Rate Limit"}:
        return ThreatAction.LOG
    if action == "CAPTCHA":
        return ThreatAction.CAPTCHA
    if action == "Temporary Block":
        return ThreatAction.TEMPORARY_BLOCK
    if action == "Permanent Block":
        return ThreatAction.PERMANENT_BLOCK
    return None


def _request_payload(request_obj: Request) -> str:
    body = request_obj.get_data(cache=True, as_text=True) or ""
    query = request_obj.query_string.decode("utf-8", errors="ignore")
    return f"{request_obj.path} {query} {body}"


def _request_times_key(ip_address: str) -> str:
    return f"cloudshield:runtime:threat:req:{ip_address}"


def _temporary_block_key(ip_address: str) -> str:
    return f"cloudshield:runtime:threat:temp_block:{ip_address}"


def _not_found_key(ip_address: str) -> str:
    return f"cloudshield:runtime:threat:404:{ip_address}"


def _admin_path_key(ip_address: str) -> str:
    return f"cloudshield:runtime:threat:admin_path:{ip_address}"
