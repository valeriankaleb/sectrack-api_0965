from flask import request
from sqlalchemy import asc, desc
from app.models import db, User, Asset, Vulnerability, Incident, AuditLog
from app.utils import (
    success_response, error_response, sanitize_string,
    VALID_SEVERITIES, VALID_INCIDENT_STATUS, VALID_VULN_STATUS, VALID_ROLES
)

ALLOWED_INCIDENT_SORT_FIELDS = {"id", "occurred_at", "severity", "status", "title"}


def record_audit(user_id, action, target_type, target_id, details):
    ip_addr = request.remote_addr or "127.0.0.1"
    log = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=ip_addr,
        details=sanitize_string(details, 255)
    )
    db.session.add(log)


# --- USER CONTROLLER ---
def create_user(data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    username = sanitize_string(data.get("username", ""), 50)
    email = sanitize_string(data.get("email", ""), 120)
    role = sanitize_string(data.get("role", "SOC_ANALYST"), 30).upper()

    if not username or not email:
        return error_response("username and email are required", 400)
    if "@" not in email or "." not in email.split("@")[-1]:
        return error_response("Invalid email format", 422)
    if role not in VALID_ROLES:
        return error_response(f"Invalid role. Allowed: {sorted(VALID_ROLES)}", 422)
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return error_response("Username or email already exists", 409)

    user = User(username=username, email=email, role=role)
    db.session.add(user)
    db.session.commit()
    return success_response(user.to_dict(), "User created", 201)


def get_users():
    users = User.query.order_by(asc(User.id)).all()
    return success_response([u.to_dict() for u in users])


# --- ASSET CONTROLLER ---
def create_asset(data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    name = sanitize_string(data.get("asset_name", ""), 100)
    atype = sanitize_string(data.get("asset_type", ""), 50).upper()
    ip_url = sanitize_string(data.get("ip_or_url", ""), 150)
    crit = sanitize_string(data.get("criticality", "HIGH"), 20).upper()

    if not name or not atype or not ip_url:
        return error_response("asset_name, asset_type, and ip_or_url are required", 400)
    if crit not in VALID_SEVERITIES:
        return error_response(f"Invalid criticality. Allowed: {sorted(VALID_SEVERITIES)}", 422)

    asset = Asset(asset_name=name, asset_type=atype, ip_or_url=ip_url, criticality=crit)
    db.session.add(asset)
    db.session.commit()
    return success_response(asset.to_dict(), "Asset created", 201)


def get_assets():
    assets = Asset.query.order_by(asc(Asset.id)).all()
    return success_response([a.to_dict() for a in assets])


def get_asset_detail(asset_id):
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return error_response("Asset not found", 404)
    return success_response(asset.to_dict(include_relations=True))


def update_asset(asset_id, data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    asset = db.session.get(Asset, asset_id)
    if not asset:
        return error_response("Asset not found", 404)

    if "asset_name" in data:
        name = sanitize_string(data["asset_name"], 100)
        if not name:
            return error_response("asset_name cannot be empty", 400)
        asset.asset_name = name
    if "asset_type" in data:
        atype = sanitize_string(data["asset_type"], 50).upper()
        if not atype:
            return error_response("asset_type cannot be empty", 400)
        asset.asset_type = atype
    if "ip_or_url" in data:
        ip_url = sanitize_string(data["ip_or_url"], 150)
        if not ip_url:
            return error_response("ip_or_url cannot be empty", 400)
        asset.ip_or_url = ip_url
    if "criticality" in data:
        crit = sanitize_string(data["criticality"], 20).upper()
        if crit not in VALID_SEVERITIES:
            return error_response(f"Invalid criticality. Allowed: {sorted(VALID_SEVERITIES)}", 422)
        asset.criticality = crit

    db.session.commit()
    return success_response(asset.to_dict(), "Asset updated")


def delete_asset(asset_id):
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return error_response("Asset not found", 404)
    if asset.incidents:
        return error_response("Cannot delete asset with linked security incidents", 409)

    db.session.delete(asset)
    db.session.commit()
    return success_response(message="Asset deleted")


# --- VULNERABILITY CONTROLLER ---
def create_vulnerability(data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    asset_id = data.get("asset_id")
    title = sanitize_string(data.get("title", ""), 150)
    cvss = data.get("cvss_score")
    severity = sanitize_string(data.get("severity", ""), 20).upper()
    cve_code = sanitize_string(data.get("cve_code", ""), 40) or None
    user_id = data.get("user_id")

    if not asset_id or not title or cvss is None or not severity:
        return error_response("asset_id, title, cvss_score, and severity are required", 400)
    if not isinstance(asset_id, int) or not db.session.get(Asset, asset_id):
        return error_response("Referenced asset_id does not exist", 404)
    if user_id is not None and (not isinstance(user_id, int) or not db.session.get(User, user_id)):
        return error_response("Referenced user_id does not exist", 404)

    try:
        cvss_val = float(cvss)
        if not (0.0 <= cvss_val <= 10.0):
            return error_response("cvss_score must be between 0.0 and 10.0", 422)
    except (ValueError, TypeError):
        return error_response("cvss_score must be a number", 422)

    if severity not in VALID_SEVERITIES:
        return error_response(f"Invalid severity. Allowed: {sorted(VALID_SEVERITIES)}", 422)

    vuln = Vulnerability(
        asset_id=asset_id,
        cve_code=cve_code,
        title=title,
        cvss_score=cvss_val,
        severity=severity,
        status="OPEN"
    )
    db.session.add(vuln)
    db.session.flush()
    record_audit(user_id, "CREATE_VULN", "Vulnerability", vuln.id, f"Added vulnerability: {title}")
    db.session.commit()
    return success_response(vuln.to_dict(), "Vulnerability logged", 201)


def get_vulnerabilities(args):
    query = Vulnerability.query
    status = args.get("status")
    min_cvss = args.get("min_cvss")

    if status:
        query = query.filter(Vulnerability.status == status.upper())
    if min_cvss:
        try:
            query = query.filter(Vulnerability.cvss_score >= float(min_cvss))
        except ValueError:
            return error_response("min_cvss must be a valid number", 400)

    vulns = query.order_by(desc(Vulnerability.cvss_score)).all()
    return success_response([v.to_dict() for v in vulns])


def update_vulnerability_status(vuln_id, data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    vuln = db.session.get(Vulnerability, vuln_id)
    if not vuln:
        return error_response("Vulnerability not found", 404)

    new_status = sanitize_string(data.get("status", ""), 20).upper()
    user_id = data.get("user_id")

    if not new_status:
        return error_response("status is required", 400)
    if new_status not in VALID_VULN_STATUS:
        return error_response(f"Invalid status. Allowed: {sorted(VALID_VULN_STATUS)}", 422)
    if user_id is not None and (not isinstance(user_id, int) or not db.session.get(User, user_id)):
        return error_response("Referenced user_id does not exist", 404)

    vuln.status = new_status
    record_audit(user_id, "UPDATE_VULN_STATUS", "Vulnerability", vuln.id, f"Status updated to {new_status}")
    db.session.commit()
    return success_response(vuln.to_dict(), "Vulnerability status updated")


# --- INCIDENT CONTROLLER (CRUD + SEARCH, FILTER, SORT, PAGINATION) ---
def create_incident(data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    asset_id = data.get("asset_id")
    vuln_id = data.get("vulnerability_id")
    reporter_id = data.get("reporter_id")
    title = sanitize_string(data.get("title", ""), 150)
    inc_type = sanitize_string(data.get("incident_type", ""), 50).upper()
    severity = sanitize_string(data.get("severity", ""), 20).upper()
    status = sanitize_string(data.get("status", "OPEN"), 20).upper()
    desc_text = sanitize_string(data.get("description", ""), 2000)

    if not all([asset_id, reporter_id, title, inc_type, severity, desc_text]):
        return error_response(
            "asset_id, reporter_id, title, incident_type, severity, and description are required",
            400
        )
    if not isinstance(asset_id, int) or not db.session.get(Asset, asset_id):
        return error_response("Referenced asset_id not found", 404)
    if not isinstance(reporter_id, int) or not db.session.get(User, reporter_id):
        return error_response("Referenced reporter_id not found", 404)
    if vuln_id is not None and (not isinstance(vuln_id, int) or not db.session.get(Vulnerability, vuln_id)):
        return error_response("Referenced vulnerability_id not found", 404)
    if severity not in VALID_SEVERITIES:
        return error_response(f"Invalid severity. Allowed: {sorted(VALID_SEVERITIES)}", 422)
    if status not in VALID_INCIDENT_STATUS:
        return error_response(f"Invalid status. Allowed: {sorted(VALID_INCIDENT_STATUS)}", 422)

    incident = Incident(
        asset_id=asset_id,
        vulnerability_id=vuln_id,
        reporter_id=reporter_id,
        title=title,
        incident_type=inc_type,
        severity=severity,
        status=status,
        description=desc_text
    )
    db.session.add(incident)
    db.session.flush()
    record_audit(reporter_id, "CREATE_INCIDENT", "Incident", incident.id, f"Reported: {title}")
    db.session.commit()
    return success_response(incident.to_dict(), "Incident created successfully", 201)


def get_incidents(args):
    query = Incident.query

    # 1. Search (title atau description)
    search = args.get("search")
    if search:
        pattern = f"%{sanitize_string(search, 100)}%"
        query = query.filter(
            (Incident.title.ilike(pattern)) | (Incident.description.ilike(pattern))
        )

    # 2. Filter
    if args.get("severity"):
        query = query.filter(Incident.severity == args.get("severity").upper())
    if args.get("status"):
        query = query.filter(Incident.status == args.get("status").upper())
    if args.get("incident_type"):
        query = query.filter(Incident.incident_type == args.get("incident_type").upper())
    if args.get("asset_id"):
        try:
            query = query.filter(Incident.asset_id == int(args.get("asset_id")))
        except ValueError:
            return error_response("asset_id filter must be an integer", 400)

    # 3. Sorting (whitelisted columns)
    sort_by = args.get("sort_by", "occurred_at")
    if sort_by not in ALLOWED_INCIDENT_SORT_FIELDS:
        sort_by = "occurred_at"
    order = args.get("order", "desc").lower()
    sort_column = getattr(Incident, sort_by)
    query = query.order_by(asc(sort_column) if order == "asc" else desc(sort_column))

    # 4. Pagination (maksimal 50 per halaman)
    try:
        page = max(1, int(args.get("page", 1)))
        per_page = min(50, max(1, int(args.get("per_page", 10))))
    except ValueError:
        return error_response("page and per_page must be integers", 400)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)
    meta = {
        "page": page,
        "per_page": per_page,
        "total_items": paginated.total,
        "total_pages": paginated.pages
    }
    return success_response([i.to_dict() for i in paginated.items], meta=meta)


def get_incident_detail(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        return error_response("Incident not found", 404)
    return success_response(incident.to_dict())


def update_incident(incident_id, data):
    if not data:
        return error_response("Request body must be valid JSON", 400)

    incident = db.session.get(Incident, incident_id)
    if not incident:
        return error_response("Incident not found", 404)

    if "status" in data:
        st = sanitize_string(data["status"], 20).upper()
        if st not in VALID_INCIDENT_STATUS:
            return error_response(f"Invalid status. Allowed: {sorted(VALID_INCIDENT_STATUS)}", 422)
        incident.status = st
    if "severity" in data:
        sev = sanitize_string(data["severity"], 20).upper()
        if sev not in VALID_SEVERITIES:
            return error_response(f"Invalid severity. Allowed: {sorted(VALID_SEVERITIES)}", 422)
        incident.severity = sev
    if "description" in data:
        desc_text = sanitize_string(data["description"], 2000)
        if not desc_text:
            return error_response("description cannot be empty", 400)
        incident.description = desc_text

    actor_id = data.get("user_id", incident.reporter_id)
    if actor_id is not None and not db.session.get(User, actor_id):
        return error_response("Referenced user_id not found", 404)

    record_audit(actor_id, "UPDATE_INCIDENT", "Incident", incident.id, f"Updated status to {incident.status}")
    db.session.commit()
    return success_response(incident.to_dict(), "Incident updated")


def delete_incident(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        return error_response("Incident not found", 404)

    record_audit(incident.reporter_id, "DELETE_INCIDENT", "Incident", incident.id, f"Deleted incident #{incident.id}")
    db.session.delete(incident)
    db.session.commit()
    return success_response(message="Incident deleted")


# --- AUDIT LOG CONTROLLER ---
def get_audit_logs():
    logs = AuditLog.query.order_by(desc(AuditLog.timestamp)).limit(100).all()
    return success_response([l.to_dict() for l in logs])