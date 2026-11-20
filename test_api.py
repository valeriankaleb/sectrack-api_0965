import pytest
from app import create_app
from app.models import db


@pytest.fixture
def client():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.session.remove()
            db.drop_all()


def test_health_check_and_security_headers(client):
    """Skenario Berhasil: Memastikan root endpoint aktif dan HTTP security headers terpasang."""
    res = client.get("/")
    assert res.status_code == 200
    assert res.get_json()["status"] == "success"
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Content-Security-Policy") == "default-src 'none'"


def test_full_crud_search_filter_pagination_and_audit_log(client):
    """Skenario Berhasil: Alur penuh User -> Asset -> Vulnerability -> Incident + Search/Filter/Pagination + Audit Log."""
    # 1. Create User
    res_user = client.post("/api/v1/users", json={
        "username": "valerian_soc",
        "email": "valerian@amikom.ac.id",
        "role": "SOC_ANALYST"
    })
    assert res_user.status_code == 201
    user_id = res_user.get_json()["data"]["id"]

    # 2. Create Asset
    res_asset = client.post("/api/v1/assets", json={
        "asset_name": "Game Auth API Server",
        "asset_type": "AUTH_SERVICE",
        "ip_or_url": "https://auth.simulasi.local/api",
        "criticality": "CRITICAL"
    })
    assert res_asset.status_code == 201
    asset_id = res_asset.get_json()["data"]["id"]

    # 3. Create Vulnerability + Patch Status
    res_vuln = client.post("/api/v1/vulnerabilities", json={
        "asset_id": asset_id,
        "cve_code": "CWE-307",
        "title": "Excessive Authentication Attempts",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "user_id": user_id
    })
    assert res_vuln.status_code == 201
    vuln_id = res_vuln.get_json()["data"]["id"]

    res_patch = client.patch(f"/api/v1/vulnerabilities/{vuln_id}", json={
        "status": "MITIGATED",
        "user_id": user_id
    })
    assert res_patch.status_code == 200
    assert res_patch.get_json()["data"]["status"] == "MITIGATED"

    # 4. Create 2 Incidents
    res_inc1 = client.post("/api/v1/incidents", json={
        "asset_id": asset_id,
        "vulnerability_id": vuln_id,
        "reporter_id": user_id,
        "title": "Indikasi Credential Stuffing Login",
        "incident_type": "ACCOUNT_TAKEOVER",
        "severity": "CRITICAL",
        "status": "INVESTIGATING",
        "description": "Lonjakan percobaan login gagal beruntun."
    })
    assert res_inc1.status_code == 201
    inc1_id = res_inc1.get_json()["data"]["id"]

    res_inc2 = client.post("/api/v1/incidents", json={
        "asset_id": asset_id,
        "reporter_id": user_id,
        "title": "Brute Force Port Internal",
        "incident_type": "BRUTE_FORCE",
        "severity": "LOW",
        "status": "OPEN",
        "description": "Percobaan koneksi berulang."
    })
    assert res_inc2.status_code == 201

    # 5. Test Search, Filter, Sorting, dan Pagination
    res_list = client.get(
        "/api/v1/incidents?search=Credential&severity=CRITICAL&sort_by=occurred_at&order=desc&page=1&per_page=5"
    )
    assert res_list.status_code == 200
    body = res_list.get_json()
    assert len(body["data"]) == 1
    assert body["data"][0]["id"] == inc1_id
    assert body["meta"]["total_items"] == 1
    assert body["meta"]["page"] == 1

    # 6. Update Incident
    res_upd = client.put(f"/api/v1/incidents/{inc1_id}", json={
        "status": "RESOLVED",
        "user_id": user_id
    })
    assert res_upd.status_code == 200
    assert res_upd.get_json()["data"]["status"] == "RESOLVED"

    # 7. Verify Automatic Audit Logs recorded
    res_logs = client.get("/api/v1/audit-logs")
    assert res_logs.status_code == 200
    assert len(res_logs.get_json()["data"]) >= 5


def test_validation_and_integrity_error_scenarios(client):
    """Skenario Error & Validasi: 400 (input kurang), 404 (FK tidak ada), 409 (duplikat & deletion guard), 422 (CVSS/enum invalid)."""
    # 1. Error 400: Field wajib asset tidak lengkap
    res_400 = client.post("/api/v1/assets", json={"asset_name": "Incomplete Server"})
    assert res_400.status_code == 400
    assert res_400.get_json()["status"] == "error"

    # 2. Error 422: Format email tidak valid
    res_email = client.post("/api/v1/users", json={
        "username": "bad_user",
        "email": "bukan-email-valid",
        "role": "SOC_ANALYST"
    })
    assert res_email.status_code == 422

    # 3. Error 409: Duplikat username/email
    client.post("/api/v1/users", json={
        "username": "dup_user",
        "email": "dup@amikom.ac.id",
        "role": "ADMIN"
    })
    res_dup = client.post("/api/v1/users", json={
        "username": "dup_user",
        "email": "dup@amikom.ac.id",
        "role": "ADMIN"
    })
    assert res_dup.status_code == 409

    # 4. Error 404: Foreign key tidak ditemukan saat buat insiden
    res_404 = client.post("/api/v1/incidents", json={
        "asset_id": 999,
        "reporter_id": 999,
        "title": "Ghost Incident",
        "incident_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "description": "Referensi tidak valid"
    })
    assert res_404.status_code == 404

    # 5. Error 422: CVSS Score di luar rentang 0.0 - 10.0
    res_asset = client.post("/api/v1/assets", json={
        "asset_name": "Protected Asset",
        "asset_type": "API_SERVER",
        "ip_or_url": "10.0.0.10",
        "criticality": "HIGH"
    })
    asset_id = res_asset.get_json()["data"]["id"]

    res_cvss = client.post("/api/v1/vulnerabilities", json={
        "asset_id": asset_id,
        "title": "Invalid Score Bug",
        "cvss_score": 15.5,
        "severity": "HIGH"
    })
    assert res_cvss.status_code == 422
    assert res_cvss.get_json()["code"] == 422

    # 6. Error 409: Deletion Guard (gagal hapus aset yang masih punya insiden)
    user_id = client.get("/api/v1/users").get_json()["data"][0]["id"]
    client.post("/api/v1/incidents", json={
        "asset_id": asset_id,
        "reporter_id": user_id,
        "title": "Linked Incident",
        "incident_type": "DDOS",
        "severity": "HIGH",
        "description": "Masih terhubung ke aset."
    })
    res_del = client.delete(f"/api/v1/assets/{asset_id}")
    assert res_del.status_code == 409