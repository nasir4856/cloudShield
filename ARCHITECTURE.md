# CloudShield Architecture

## Vision

CloudShield is an enterprise Web Application Firewall and reverse-proxy security gateway designed to protect any HTTP application without requiring changes to the protected application itself.

The platform sits between users and backend services, evaluates every request, applies tenant-aware routing, enforces configurable security rules, records security and audit events, and gives administrators a foundation for operating a security platform.

CloudShield is being built as a practical enterprise cybersecurity product, not a single-purpose script.

## Project Goals

- Protect any HTTP application through reverse proxying.
- Support multiple protected applications from a central gateway.
- Score requests before they reach upstream backends.
- Make security rules configurable and auditable.
- Provide enterprise identity and access management.
- Maintain clear separation between routing, security, IAM, models, services, and UI.
- Preserve explainability: every security decision should be traceable.
- Build toward production readiness with tests, migrations, observability, and deployment automation.

## High-Level Architecture

```text
Client
  |
  v
CloudShield Flask Gateway
  |
  +--> IAM / Session / JWT / API Key Layer
  |
  +--> Application Registry
  |
  +--> Threat Engine
  |
  +--> Configurable Rule Engine
  |
  +--> Blocklist / CAPTCHA / Actions
  |
  +--> Redis Runtime Store / In-Memory Fallback
  |
  +--> Reverse Proxy Forwarder
  |
  v
Protected HTTP Application
```

CloudShield is framework-agnostic. Protected applications may be Flask, Django, Node.js, Laravel, Spring Boot, ASP.NET, Go, PHP, or any service reachable over HTTP.

## Request Lifecycle

1. A client sends a request to CloudShield.
2. CloudShield checks whether the source IP is permanently or temporarily blocked.
3. CloudShield resolves the target `ProtectedApplication` by matching the incoming URL against registered `public_path` values.
4. If no application matches, CloudShield returns `404`.
5. If the application is disabled, CloudShield returns `503`.
6. The Threat Engine evaluates the request.
7. The Rule Engine loads and evaluates enabled rules by priority.
8. Matched rules contribute to the final threat score.
9. CloudShield chooses an action: allow, log, CAPTCHA, rate limit, temporary block, or permanent block.
10. If allowed, the proxy forwards the request to the upstream backend.
11. Response metadata is logged and returned to the client.
12. Security events and audit logs are persisted as needed.

## Security Pipeline

```text
Incoming Request
  |
  v
Blocklist Check
  |
  v
Application Match
  |
  v
Threat Engine
  |
  v
Rule Engine
  |
  v
Risk Level + Action Decision
  |
  +--> Allow -> Proxy Forward
  +--> Log -> Proxy Forward + Event
  +--> CAPTCHA -> Challenge
  +--> Temporary Block -> Deny
  +--> Permanent Block -> Add to Blocklist + Deny
```

Runtime security state is stored through `app/services/redis_service.py`. Redis is preferred when available. If Redis is unavailable, CloudShield logs a warning and continues with an in-memory fallback so local development does not fail.

Runtime key structure:

```text
cloudshield:runtime:rate:events
cloudshield:runtime:threat:req:<ip>
cloudshield:runtime:threat:temp_block:<ip>
cloudshield:runtime:threat:404:<ip>
cloudshield:runtime:threat:admin_path:<ip>
cloudshield:runtime:captcha:attempts:<ip>
cloudshield:runtime:iam:login_attempts:<username>
```

Risk levels:

```text
0-20   Normal
21-40  Suspicious
41-70  High Risk
71+    Critical
```

## Module Breakdown

### `app/routes/`

Flask blueprints. Routes should be thin and delegate business logic to services.

Responsibilities:

- Admin UI routes.
- Auth API routes.
- CAPTCHA routes.
- Firewall entrypoint routes.
- Health monitoring routes.

### `app/services/`

Business logic and reusable application services.

Responsibilities:

- Application registry.
- IAM service.
- API key service.
- Rule service.
- Email service.
- Blocklist service.
- Rate limiter.
- Redis-backed runtime state with in-memory fallback.
- Health service.
- Threat summary queries.

### `app/security/`

Security-specific logic.

Responsibilities:

- Authentication decorators.
- JWT handling.
- CSRF helpers.
- CAPTCHA generation.
- Threat engine.
- IP validation.

### `app/proxy/`

Reverse proxy forwarding logic.

Responsibilities:

- Build upstream URL.
- Forward method, headers, query string, body, cookies, and content type.
- Return upstream response transparently.
- Log target, response status, and response time.

### `app/models/`

SQLAlchemy database models.

Responsibilities:

- Data schema definitions.
- Relationships and persistence structures.

### `app/templates/`

Server-rendered admin UI templates.

Responsibilities:

- Dashboard.
- Application management.
- Rule management.
- IAM pages.
- Audit logs.

### `app/utils/`

Cross-cutting utilities.

Responsibilities:

- Logging setup.
- Error handlers.

## Folder Structure

```text
cloudshield/
    app/
        __init__.py
        routes/
        services/
        security/
        proxy/
        models/
        templates/
        static/
        utils/
    config.py
    extensions.py
    run.py
    app.py
    requirements.txt
    README.md
    ARCHITECTURE.md
    ROADMAP.md
    CONTRIBUTING.md
```

## Database Overview

Core models:

```text
AdminUser
Role
Permission
UserRole
AuditLog
ApiKey
RefreshToken
ProtectedApplication
SecurityRule
SecurityEvent
BlockedIP
AppSetting
```

Important principles:

- Passwords are stored only as hashes.
- API keys are stored only as hashes and prefixes.
- Refresh tokens are stored only as hashes.
- Security decisions should create `SecurityEvent` records.
- Administrative changes should create `AuditLog` records.
- Future schema changes should use Alembic migrations.

## Authentication Flow

Admin UI:

1. User submits username and password.
2. Login rate limits and account lockout are checked.
3. Password hash is verified.
4. Flask session is created.
5. Session expiration is enforced.
6. Route permissions are checked through RBAC.
7. Login success or failure is audited.

API:

1. Client posts credentials to `/api/auth/login`.
2. CloudShield returns a short-lived JWT access token and an opaque refresh token.
3. Refresh tokens are stored hashed.
4. Refresh rotates the token pair.
5. Logout revokes the refresh token.

## Threat Engine Flow

1. Request enters firewall route.
2. Matching protected application is resolved.
3. Threat Engine receives request, application, and IP.
4. Rule Engine evaluates database-backed rules.
5. Stateful behavior checks are evaluated where required.
6. Final score is calculated.
7. Risk level is derived from score.
8. Recommended action is selected.
9. Triggered rules create `SecurityEvent` records.
10. Firewall enforces action.

## Rule Engine Flow

1. Load enabled global rules and application-specific rules.
2. Sort by `priority`, then `id`.
3. Evaluate each rule by `rule_type`.
4. If a rule matches, add its `threat_score`.
5. Collect matched actions.
6. Choose strongest action.
7. Return matches, score, and action recommendation.

Supported rule types:

```text
URL Pattern
Regex
Header Match
User-Agent Match
HTTP Method
Request Size
Query String Pattern
```

Supported actions:

```text
Allow
Log
CAPTCHA
Rate Limit
Temporary Block
Permanent Block
```

## Coding Standards

- Keep routes thin.
- Put reusable logic in services.
- Put security-specific logic in `app/security/`.
- Prefer explicit names over abbreviations.
- Use type hints for new Python code.
- Keep functions small and focused.
- Avoid hidden side effects.
- Avoid hardcoded secrets, credentials, URLs, thresholds, or policy values.

## Naming Conventions

Python:

```text
modules: snake_case.py
functions: snake_case
variables: snake_case
classes: PascalCase
constants: UPPER_SNAKE_CASE
```

Database:

```text
tables: snake_case plural
columns: snake_case
foreign keys: <model>_id
```

Permissions:

```text
manage_users
manage_applications
manage_rules
view_dashboard
view_threats
export_reports
manage_settings
view_audit_logs
manage_api_keys
```

## Logging Standards

CloudShield maintains separate logs:

```text
application.log
security.log
errors.log
```

Use application logs for normal operational events.

Use security logs for:

- Rule matches.
- Threat scores.
- Blocks.
- CAPTCHA decisions.
- Authentication events.
- Authorization failures.

Use error logs for exceptions and failed integrations.

Never log:

- Plaintext passwords.
- Plaintext API keys.
- Refresh tokens.
- Full sensitive request bodies.
- Secret configuration values.

## Error Handling Strategy

- Return friendly JSON errors from firewall/proxy paths.
- Avoid exposing stack traces to users.
- Log full exception details server-side.
- Use HTTP status codes consistently:

```text
400 Bad request
401 Unauthenticated
403 Forbidden or blocked
404 No matching application/resource
502 Upstream unavailable
503 Application disabled
500 Internal server error
```

## Health Monitoring

CloudShield exposes three operational endpoints:

```text
GET /live   - process liveness
GET /ready  - readiness for serving traffic
GET /health - aggregate component health
```

Health reports include:

- Application status.
- Redis status or fallback status.
- Database connectivity.
- Configuration warnings.

Redis fallback is considered degraded but acceptable for development. Database failure makes readiness fail.

## Security Principles

- Deny by default for unauthorized admin access.
- Store secrets only as hashes where possible.
- Never store plaintext API keys or refresh tokens.
- Audit administrative actions.
- Keep security decisions explainable.
- Prefer configuration and database-backed policy over hardcoded logic.
- Validate user input.
- Avoid leaking upstream internals.
- Keep protected application logic separate from CloudShield logic.
- Design for least privilege through RBAC.

## Future Architecture Notes

Planned future architecture improvements:

- Alembic migrations.
- GitHub Actions CI.
- Unit and integration tests.
- SOC module with incidents, analytics, and reports.
- Prometheus metrics endpoint.
- Grafana dashboard templates.
- SIEM export pipeline.
- GeoIP enrichment.
- Threat intelligence feeds.
- Machine learning anomaly detection.
