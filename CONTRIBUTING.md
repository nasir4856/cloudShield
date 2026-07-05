# Contributing to CloudShield

## Purpose

This document defines development rules for CloudShield. Every future implementation should follow these guidelines to keep the project secure, maintainable, and enterprise-ready.

## Folder Responsibilities

### `app/routes/`

Routes and blueprints only.

Rules:

- Keep route functions thin.
- Do not put business logic in routes.
- Validate request shape, then delegate to services.
- Apply authentication and permission decorators here.

### `app/services/`

Business logic.

Rules:

- Put reusable workflows here.
- Keep services framework-aware only when necessary.
- Avoid direct template or UI concerns.
- Use clear function names.

### `app/security/`

Security-specific logic.

Rules:

- Auth, JWT, CSRF, CAPTCHA, threat evaluation, and validation belong here.
- Do not mix security logic into templates or proxy code.
- Security decisions must be explainable and auditable.

### `app/proxy/`

Reverse proxy forwarding.

Rules:

- Forward request details carefully.
- Preserve upstream response behavior where safe.
- Log target, status code, and response time.
- Do not add threat logic here.

### `app/models/`

SQLAlchemy models.

Rules:

- Keep schema definitions clear.
- Do not put complex business logic in models.
- Add migrations for schema changes once Alembic is introduced.

### `app/templates/`

Server-rendered admin UI.

Rules:

- Keep design language consistent.
- Do not embed business decisions in templates.
- Include CSRF fields in admin forms.

### `app/utils/`

Shared utilities.

Rules:

- Use for logging, error handling, and small cross-cutting helpers.
- Avoid dumping unrelated helpers here.

## Code Style

- Follow PEP 8.
- Use type hints for new functions.
- Prefer explicit names over abbreviations.
- Keep functions small.
- Avoid unnecessary abstractions.
- Avoid broad exception handling unless logging and fallback behavior are clear.
- Do not hardcode secrets, credentials, URLs, or policy thresholds.

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
foreign keys: <resource>_id
```

Routes:

```text
/admin/<resource>
/api/<domain>/<action>
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

## Logging Requirements

Use Python logging, not `print()`.

Log:

- Authentication success/failure.
- Authorization denial.
- Rule changes.
- Protected application changes.
- API key creation or revocation.
- Threat rule matches.
- Proxy upstream failures.
- Unexpected exceptions.

Do not log:

- Plaintext passwords.
- Plaintext API keys.
- Refresh tokens.
- JWTs.
- Secret keys.
- Sensitive request bodies.

## Error Handling

- Return friendly errors to users and clients.
- Log detailed errors server-side.
- Do not expose stack traces.
- Use appropriate HTTP status codes.
- Keep error handling close to the boundary where the error can be understood.

Common codes:

```text
400 Invalid request
401 Authentication required
403 Forbidden or blocked
404 Not found
502 Upstream unavailable
503 Protected application disabled
500 Unexpected server error
```

## Database Migration Rules

Until Alembic is introduced:

- Document every schema change in README migration notes.
- Keep new columns nullable when possible for compatibility.
- Avoid destructive schema changes.

After Alembic is introduced:

- Every model change must include a migration.
- Migrations must be reversible where practical.
- Never edit an applied migration unless explicitly approved.
- Seed data should be idempotent.

## Security Requirements

- Passwords must be hashed.
- API keys must be stored only as hashes.
- Refresh tokens must be stored only as hashes.
- Admin actions must create `AuditLog` entries.
- Security detections must create `SecurityEvent` entries.
- New admin routes must use permission decorators.
- New forms must support CSRF protection.
- New configuration must be environment-driven.
- Never commit `.env` files or real secrets.
- Validate all user-controllable inputs.

## Testing Expectations

New work should include appropriate tests once the test suite is introduced.

Minimum expectations:

- Model creation tests for new models.
- Service tests for business logic.
- Route tests for authentication and permissions.
- Security tests for blocked and allowed behavior.
- Regression tests for existing firewall behavior.

For manual verification before tests are formalized:

- Run Python compile checks.
- Smoke test admin login.
- Smoke test protected app routing.
- Smoke test rule evaluation.
- Smoke test audit logging.
- Smoke test JWT login/refresh/logout when IAM is touched.

## Documentation Requirements

Update documentation when changing:

- Architecture.
- Database schema.
- Environment variables.
- Security behavior.
- Routes.
- IAM permissions.
- Rule engine behavior.
- Deployment steps.

Relevant docs:

```text
README.md
ARCHITECTURE.md
ROADMAP.md
CONTRIBUTING.md
```

## Git Commit Conventions

Use concise conventional commits:

```text
feat: add configurable security rule model
fix: preserve query string in proxy forwarding
docs: add SOC product specification
refactor: split IAM token logic
test: add rule engine service tests
chore: update requirements
```

Recommended types:

```text
feat
fix
docs
refactor
test
chore
security
```

## Pull Request Checklist

Before opening a pull request:

- Code compiles.
- Existing behavior is preserved.
- New behavior is documented.
- No secrets are committed.
- Logs do not expose sensitive values.
- Permissions are enforced.
- Audit logs are added for admin actions.
- Database changes include migration notes or migrations.
- Relevant smoke tests are described.
- UI follows existing design language.
- README/ARCHITECTURE/ROADMAP/CONTRIBUTING are updated if needed.

