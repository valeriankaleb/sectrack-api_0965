import sqlite3
from flask import Flask
from sqlalchemy import event
from sqlalchemy.engine import Engine
from app.models import db
from app.routes.api_routes import api_bp
from app.utils import success_response, error_response


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def create_app(test_config=None):
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

    return app