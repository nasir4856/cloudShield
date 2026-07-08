from flask import render_template

from app import create_app
from app.models import ProtectedApplication, SecurityEvent
from config import Config
from extensions import db


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


def test_application_metrics_count_matching_security_events():
    app = create_app(config_class=TestConfig)

    with app.app_context():
        db.drop_all()
        db.create_all()

        application = ProtectedApplication(
            name="Example",
            public_path="/example",
            upstream_url="http://127.0.0.1:8000",
        )
        db.session.add(application)
        db.session.flush()

        db.session.add(
            SecurityEvent(
                event_type="request",
                application_id=application.id,
                application_name=application.name,
                message="request",
                threat_score=20,
                matched_rule="Rate Limit",
                risk_level="High Risk",
            )
        )
        db.session.add(
            SecurityEvent(
                event_type="request",
                application_id=application.id,
                application_name=application.name,
                message="another request",
                threat_score=5,
            )
        )
        db.session.commit()

        from app.services.threat_summary_service import summarize_application_metrics

        metrics = summarize_application_metrics([application])
        assert metrics[application.id]["request_volume"] == 2
        assert metrics[application.id]["threat_count"] == 1


def test_admin_dashboard_shows_protected_applications_count():
    app = create_app(config_class=TestConfig)

    with app.test_request_context():
        html = render_template(
            "admin.html",
            ip_stats={},
            recent_logs=[],
            blocked_ips=[],
            recent_threats=[],
            top_rules=[],
            threat_distribution=[],
            risk_counts={},
            healthy_apps=1,
            degraded_apps=0,
            offline_apps=0,
            protected_applications=[ProtectedApplication(name="Example", public_path="/example", upstream_url="http://127.0.0.1:8000")],
        )

        assert ">1<" in html


def test_reports_and_monitoring_templates_include_live_cards():
    app = create_app(config_class=TestConfig)

    with app.test_request_context():
        reports_html = render_template(
            "reports.html",
            page_title="Reports",
            active_page="reports",
            events=[],
            recent_threats=[],
            risk_counts={},
            top_rules=[],
            protected_applications=[ProtectedApplication(name="Example", public_path="/example", upstream_url="http://127.0.0.1:8000", enabled=True)],
            application_activity=[("Example", 2)],
        )
        monitoring_html = render_template(
            "monitoring.html",
            page_title="Monitoring",
            active_page="monitoring",
            protected_applications=[ProtectedApplication(name="Example", public_path="/example", upstream_url="http://127.0.0.1:8000", enabled=True)],
            healthy_apps=1,
            degraded_apps=0,
            offline_apps=0,
            status_map={1: "Healthy"},
            recent_threats=[],
            top_rules=[],
        )

        assert "Threat Posture" in reports_html
        assert "Application Activity" in reports_html
        assert "Protection Coverage" in monitoring_html
        assert "Operations Snapshot" in monitoring_html
