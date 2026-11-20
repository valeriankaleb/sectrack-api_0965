from flask import jsonify

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_INCIDENT_STATUS = {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}
VALID_VULN_STATUS = {"OPEN", "MITIGATED", "PATCHED"}
VALID_ROLES = {"SOC_ANALYST", "PENTESTER", "ADMIN"}


def success_response(data=None, message="Success", status_code=200, meta=None):
    payload = {
        "status": "success",
        "message": message
    }
    if data is not None:
        payload["data"] = data
    if meta is not None:
        payload["meta"] = meta
    return jsonify(payload), status_code


def error_response(message, status_code=400, errors=None):
    payload = {
        "status": "error",
        "code": status_code,
        "message": message
    }
    if errors:
        payload["errors"] = errors
    return jsonify(payload), status_code


def sanitize_string(value, max_length=255):
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]