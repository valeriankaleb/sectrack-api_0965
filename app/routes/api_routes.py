from flask import Blueprint, request
from app.controllers import api_controller

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@api_bp.route("/users", methods=["POST"])
def add_user():
    return api_controller.create_user(request.get_json(silent=True))


@api_bp.route("/users", methods=["GET"])
def list_users():
    return api_controller.get_users()


@api_bp.route("/assets", methods=["POST"])
def add_asset():
    return api_controller.create_asset(request.get_json(silent=True))


@api_bp.route("/assets", methods=["GET"])
def list_assets():
    return api_controller.get_assets()


@api_bp.route("/assets/<int:asset_id>", methods=["GET"])
def detail_asset(asset_id):
    return api_controller.get_asset_detail(asset_id)


@api_bp.route("/assets/<int:asset_id>", methods=["PUT"])
def edit_asset(asset_id):
    return api_controller.update_asset(asset_id, request.get_json(silent=True))


@api_bp.route("/assets/<int:asset_id>", methods=["DELETE"])
def remove_asset(asset_id):
    return api_controller.delete_asset(asset_id)


@api_bp.route("/vulnerabilities", methods=["POST"])
def add_vuln():
    return api_controller.create_vulnerability(request.get_json(silent=True))


@api_bp.route("/vulnerabilities", methods=["GET"])
def list_vulns():
    return api_controller.get_vulnerabilities(request.args)


@api_bp.route("/vulnerabilities/<int:vuln_id>", methods=["PATCH"])
def patch_vuln(vuln_id):
    return api_controller.update_vulnerability_status(vuln_id, request.get_json(silent=True))


@api_bp.route("/incidents", methods=["POST"])
def add_incident():
    return api_controller.create_incident(request.get_json(silent=True))


@api_bp.route("/incidents", methods=["GET"])
def list_incidents():
    return api_controller.get_incidents(request.args)


@api_bp.route("/incidents/<int:incident_id>", methods=["GET"])
def detail_incident(incident_id):
    return api_controller.get_incident_detail(incident_id)


@api_bp.route("/incidents/<int:incident_id>", methods=["PUT"])
def edit_incident(incident_id):
    return api_controller.update_incident(incident_id, request.get_json(silent=True))


@api_bp.route("/incidents/<int:incident_id>", methods=["DELETE"])
def remove_incident(incident_id):
    return api_controller.delete_incident(incident_id)


@api_bp.route("/audit-logs", methods=["GET"])
def list_logs():
    return api_controller.get_audit_logs()