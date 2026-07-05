from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping

from flask import Request

from app.models import ProtectedApplication, SecurityRule
from extensions import db


RULE_TYPES = [
    "URL Pattern",
    "Regex",
    "Header Match",
    "User-Agent Match",
    "HTTP Method",
    "Request Size",
    "Query String Pattern",
]

ACTIONS = ["Allow", "Log", "CAPTCHA", "Rate Limit", "Temporary Block", "Permanent Block"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
ACTION_RANK = {
    "Allow": 0,
    "Log": 1,
    "Rate Limit": 2,
    "CAPTCHA": 3,
    "Temporary Block": 4,
    "Permanent Block": 5,
}


@dataclass(frozen=True)
class RuleRequest:
    path: str
    method: str
    headers: Mapping[str, str]
    query_string: str
    body: str = ""

    @property
    def full_payload(self) -> str:
        return f"{self.path} {self.query_string} {self.body}"


@dataclass(frozen=True)
class RuleMatchResult:
    rule: SecurityRule
    message: str


def seed_default_rules() -> None:
    defaults = [
        ("SQL Injection", "Regex", r"union\s+select|'\s*or\s+1\s*=\s*1|drop\s+table", "Critical", 40, "CAPTCHA", 10),
        ("XSS", "Regex", r"<script|javascript:|onerror=", "Critical", 40, "CAPTCHA", 20),
        ("Path Traversal", "Regex", r"\.\./|\.\.\\", "Critical", 40, "CAPTCHA", 30),
        ("Sensitive Files", "URL Pattern", "/.env,/.git,/config,/phpmyadmin,/wp-admin", "High", 35, "CAPTCHA", 40),
        ("Admin Scanning", "URL Pattern", "/admin", "High", 35, "CAPTCHA", 50),
        ("Suspicious User-Agent", "User-Agent Match", "sqlmap,nikto,nmap,masscan,acunetix,nessus,dirbuster,hydra", "Medium", 20, "Log", 60),
        ("Long URL", "Request Size", "", "Medium", 15, "Log", 70, {"max_url_length": 2000}),
        ("Missing User-Agent", "Header Match", "User-Agent", "Low", 10, "Log", 80, {"missing": True}),
        ("Rate Threshold", "Regex", "", "High", 30, "Rate Limit", 90, {"rate_rule": True}),
    ]
    for item in defaults:
        name, rule_type, pattern, severity, score, action, priority, *extra = item
        if SecurityRule.query.filter_by(name=name, application_id=None).first():
            continue
        db.session.add(
            SecurityRule(
                name=name,
                description=f"Default CloudShield rule: {name}",
                rule_type=rule_type,
                pattern=pattern,
                condition=json.dumps(extra[0] if extra else {}),
                severity=severity,
                threat_score=score,
                action=action,
                priority=priority,
                enabled=True,
            )
        )
    db.session.commit()


def enabled_rules(application: ProtectedApplication | None = None) -> list[SecurityRule]:
    query = SecurityRule.query.filter_by(enabled=True)
    if application is not None:
        query = query.filter(
            (SecurityRule.application_id.is_(None))
            | (SecurityRule.application_id == application.id)
        )
    return query.order_by(SecurityRule.priority.asc(), SecurityRule.id.asc()).all()


def match_rules(rule_request: RuleRequest, application: ProtectedApplication | None = None) -> list[RuleMatchResult]:
    matches: list[RuleMatchResult] = []
    for rule in enabled_rules(application):
        message = _match_rule(rule, rule_request)
        if message:
            matches.append(RuleMatchResult(rule, message))
    return matches


def request_to_rule_request(request_obj: Request) -> RuleRequest:
    return RuleRequest(
        path=request_obj.path,
        method=request_obj.method,
        headers=dict(request_obj.headers),
        query_string=request_obj.query_string.decode("utf-8", errors="ignore"),
        body=request_obj.get_data(cache=True, as_text=True) or "",
    )


def form_to_rule_request(form_data) -> RuleRequest:
    headers = {}
    for line in (form_data.get("headers", "") or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return RuleRequest(
        path=form_data.get("url", "/") or "/",
        method=(form_data.get("method", "GET") or "GET").upper(),
        headers=headers,
        query_string=form_data.get("query_string", "") or "",
    )


def create_rule(form_data, created_by: int | None = None) -> SecurityRule:
    rule = SecurityRule(created_by=created_by)
    return update_rule(rule, form_data, commit_new=True)


def update_rule(rule: SecurityRule, form_data, commit_new: bool = False) -> SecurityRule:
    rule.name = form_data.get("name", "").strip()
    rule.description = form_data.get("description", "").strip()
    rule.rule_type = form_data.get("rule_type", "Regex")
    rule.pattern = form_data.get("pattern", "")
    rule.condition = form_data.get("condition", "{}") or "{}"
    rule.severity = form_data.get("severity", "Medium")
    rule.threat_score = _int(form_data.get("threat_score"), 10)
    rule.action = form_data.get("action", "Log")
    rule.priority = _int(form_data.get("priority"), 100)
    rule.enabled = form_data.get("enabled") == "on"
    app_id = form_data.get("application_id")
    rule.application_id = int(app_id) if app_id else None
    if commit_new:
        db.session.add(rule)
    db.session.commit()
    return rule


def clone_rule(rule: SecurityRule, created_by: int | None = None) -> SecurityRule:
    clone = SecurityRule(
        name=f"{rule.name} Copy",
        description=rule.description,
        rule_type=rule.rule_type,
        pattern=rule.pattern,
        condition=rule.condition,
        severity=rule.severity,
        threat_score=rule.threat_score,
        action=rule.action,
        priority=rule.priority + 1,
        enabled=False,
        application_id=rule.application_id,
        created_by=created_by,
    )
    db.session.add(clone)
    db.session.commit()
    return clone


def recommended_action(actions: list[str]) -> str:
    if not actions:
        return "Allow"
    return max(actions, key=lambda action: ACTION_RANK.get(action, 0))


def _match_rule(rule: SecurityRule, rule_request: RuleRequest) -> str | None:
    condition = _condition(rule)
    pattern = rule.pattern or ""
    if condition.get("rate_rule"):
        return None
    if rule.rule_type == "URL Pattern":
        patterns = _csv(pattern)
        if any(item.lower() in rule_request.path.lower() for item in patterns):
            return f"URL path matched {pattern}"
    elif rule.rule_type == "Regex":
        if pattern and re.search(pattern, rule_request.full_payload, re.IGNORECASE):
            return f"Regex matched {rule.name}"
    elif rule.rule_type == "Header Match":
        header_name = pattern
        value = rule_request.headers.get(header_name, "")
        if condition.get("missing") and not value:
            return f"Missing header {header_name}"
        expected = condition.get("value")
        if expected and expected.lower() in value.lower():
            return f"Header {header_name} matched"
    elif rule.rule_type == "User-Agent Match":
        user_agent = rule_request.headers.get("User-Agent", "")
        if any(item.lower() in user_agent.lower() for item in _csv(pattern)):
            return "User-Agent matched suspicious signature"
    elif rule.rule_type == "HTTP Method":
        if rule_request.method.upper() in [item.upper() for item in _csv(pattern)]:
            return f"HTTP method matched {rule_request.method}"
    elif rule.rule_type == "Request Size":
        max_url_length = int(condition.get("max_url_length", 0) or 0)
        if max_url_length and len(rule_request.path) + len(rule_request.query_string) > max_url_length:
            return "URL length exceeded threshold"
        max_body_size = int(condition.get("max_body_size", 0) or 0)
        if max_body_size and len(rule_request.body) > max_body_size:
            return "Request body size exceeded threshold"
    elif rule.rule_type == "Query String Pattern":
        if pattern and re.search(pattern, rule_request.query_string, re.IGNORECASE):
            return "Query string pattern matched"
    return None


def _condition(rule: SecurityRule) -> dict:
    try:
        return json.loads(rule.condition or "{}")
    except json.JSONDecodeError:
        return {}


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

