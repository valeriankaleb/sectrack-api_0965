from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utc_now():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(30), nullable=False, default="SOC_ANALYST")
    created_at = db.Column(db.DateTime, default=utc_now)

    incidents = db.relationship("Incident", backref="reporter", lazy=True)
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(100), nullable=False)
    asset_type = db.Column(db.String(50), nullable=False)
    ip_or_url = db.Column(db.String(150), nullable=False)
    criticality = db.Column(db.String(20), nullable=False, default="HIGH")
    created_at = db.Column(db.DateTime, default=utc_now)

    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan"
    )
    incidents = db.relationship("Incident", backref="asset", lazy=True)

    def to_dict(self, include_relations=False):
        data = {
            "id": self.id,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type,
            "ip_or_url": self.ip_or_url,
            "criticality": self.criticality,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
        if include_relations:
            data["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        return data


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    cve_code = db.Column(db.String(40), nullable=True)
    title = db.Column(db.String(150), nullable=False)
    cvss_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="OPEN")
    discovered_at = db.Column(db.DateTime, default=utc_now)

    incidents = db.relationship("Incident", backref="vulnerability", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "cve_code": self.cve_code,
            "title": self.title,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "status": self.status,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None
        }


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id"), nullable=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    incident_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="OPEN")
    description = db.Column(db.Text, nullable=False)
    occurred_at = db.Column(db.DateTime, default=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "vulnerability_id": self.vulnerability_id,
            "reporter_id": self.reporter_id,
            "title": self.title,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    target_type = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    details = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "ip_address": self.ip_address,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }