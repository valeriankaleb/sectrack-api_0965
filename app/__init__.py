import os
import sqlite3
from flask import Flask
from sqlalchemy import event
from sqlalchemy.engine import Engine
from app.models import db, User, Asset, Vulnerability, Incident, AuditLog
from app.routes.api_routes import api_bp
from app.utils import success_response, error_response


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _seed_demo_data():
    u1 = User(username="valerian_soc", email="valerian@amikom.ac.id", role="SOC_ANALYST")
    u2 = User(username="redteam_pentest", email="pentest@amikom.ac.id", role="PENTESTER")
    u3 = User(username="sysadmin_sec", email="admin@amikom.ac.id", role="ADMIN")
    db.session.add_all([u1, u2, u3])
    db.session.flush()

    a1 = Asset(
        asset_name="Game Auth API Server",
        asset_type="AUTH_SERVICE",
        ip_or_url="https://auth.simulasi.local/api/v1",
        criticality="CRITICAL"
    )
    a2 = Asset(
        asset_name="Player Session Redis DB",
        asset_type="DATABASE",
        ip_or_url="10.20.1.15:6379",
        criticality="HIGH"
    )
    a3 = Asset(
        asset_name="Internal Admin Portal API",
        asset_type="API_SERVER",
        ip_or_url="https://portal-internal.simulasi.local/api",
        criticality="MEDIUM"
    )
    db.session.add_all([a1, a2, a3])
    db.session.flush()

    v1 = Vulnerability(
        asset_id=a1.id,
        cve_code="CWE-307",
        title="Improper Restriction of Excessive Authentication Attempts",
        cvss_score=9.1,
        severity="CRITICAL",
        status="OPEN"
    )
    v2 = Vulnerability(
        asset_id=a1.id,
        cve_code="CWE-613",
        title="Insufficient Session Expiration on Refresh Token",
        cvss_score=7.5,
        severity="HIGH",
        status="MITIGATED"
    )
    v3 = Vulnerability(
        asset_id=a3.id,
        cve_code="CWE-89",
        title="Legacy Search Parameter Susceptible to SQL Injection",
        cvss_score=8.6,
        severity="HIGH",
        status="PATCHED"
    )
    db.session.add_all([v1, v2, v3])
    db.session.flush()

    inc1 = Incident(
        asset_id=a1.id,
        vulnerability_id=v1.id,
        reporter_id=u1.id,
        title="Indikasi Credential Stuffing pada Endpoint Login",
        incident_type="ACCOUNT_TAKEOVER",
        severity="CRITICAL",
        status="INVESTIGATING",
        description="Terdeteksi 4.200 percobaan login gagal beruntun dari subnet IP simulasi dalam 3 menit."
    )
    inc2 = Incident(
        asset_id=a1.id,
        vulnerability_id=v2.id,
        reporter_id=u1.id,
        title="Penggunaan Ulang Refresh Token Kedaluwarsa",
        incident_type="BROKEN_AUTH",
        severity="HIGH",
        status="RESOLVED",
        description="Sesi lama masih diterima setelah reset password pada simulasi pengujian token."
    )
    inc3 = Incident(
        asset_id=a2.id,
        vulnerability_id=None,
        reporter_id=u3.id,
        title="Lonjakan Koneksi Anomali ke Port Database Sesi",
        incident_type="BRUTE_FORCE",
        severity="MEDIUM",
        status="OPEN",
        description="Ditemukan percobaan autentikasi Redis berulang dari host internal tidak dikenal."
    )
    inc4 = Incident(
        asset_id=a3.id,
        vulnerability_id=v3.id,
        reporter_id=u2.id,
        title="Deteksi Payload SQL Injection pada Query Pencarian",
        incident_type="SQL_INJECTION",
        severity="CRITICAL",
        status="CLOSED",
        description="Payload boolean-based terdeteksi di log simulasi dan telah ditambal melalui ORM."
    )
    db.session.add_all([inc1, inc2, inc3, inc4])
    db.session.flush()

    logs = [
        AuditLog(
            user_id=u2.id,
            action="CREATE_VULN",
            target_type="Vulnerability",
            target_id=v1.id,
            ip_address="127.0.0.1",
            details="Added vulnerability: CWE-307 on Game Auth API Server"
        ),
        AuditLog(
            user_id=u1.id,
            action="CREATE_INCIDENT",
            target_type="Incident",
            target_id=inc1.id,
            ip_address="127.0.0.1",
            details="Reported: Indikasi Credential Stuffing pada Endpoint Login"
        )
    ]
    db.session.add_all(logs)
    db.session.commit()


def create_app(test_config=None):
    is_vercel = bool(os.environ.get("VERCEL"))

    if is_vercel:
        app = Flask(__name__, instance_path="/tmp")
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/sectrack.db"
    else:
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sectrack.db"

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # Batas payload 1 MB

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    app.register_blueprint(api_bp)

    @app.route("/", methods=["GET"])
    def health_check():
        return success_response(
            data={
                "service": "SecTrack API",
                "version": "1.0.0",
                "base_url": "/api/v1",
                "endpoints": [
                    "/api/v1/users",
                    "/api/v1/assets",
                    "/api/v1/vulnerabilities",
                    "/api/v1/incidents",
                    "/api/v1/audit-logs"
                ]
            },
            message="SecTrack Cybersecurity REST API is running"
        )

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    @app.errorhandler(404)
    def handle_404(e):
        return error_response("Endpoint or resource not found", 404)

    @app.errorhandler(405)
    def handle_405(e):
        return error_response("HTTP method not allowed", 405)

    @app.errorhandler(413)
    def handle_413(e):
        return error_response("Payload too large. Maximum allowed size is 1 MB", 413)

    @app.errorhandler(500)
    def handle_500(e):
        return error_response("Internal server error", 500)

    with app.app_context():
        db.create_all()
        if is_vercel and not app.config.get("TESTING") and User.query.count() == 0:
            _seed_demo_data()

    return app