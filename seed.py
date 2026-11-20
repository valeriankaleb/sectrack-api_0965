from app import create_app
from app.models import db, User, Asset, Vulnerability, Incident, AuditLog

app = create_app()


def run_seed():
    with app.app_context():
        db.drop_all()
        db.create_all()

        # 1. Seed Users (Aktor Internal)
        u1 = User(username="valerian_soc", email="valerian@amikom.ac.id", role="SOC_ANALYST")
        u2 = User(username="redteam_pentest", email="pentest@amikom.ac.id", role="PENTESTER")
        u3 = User(username="sysadmin_sec", email="admin@amikom.ac.id", role="ADMIN")
        db.session.add_all([u1, u2, u3])
        db.session.flush()

        # 2. Seed Assets (Aset Simulasi Lokal)
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

        # 3. Seed Vulnerabilities
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

        # 4. Seed Incidents (Beragam severity & status untuk demo search/filter/pagination)
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

        # 5. Seed Audit Logs
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

        print("Database initialized and seeded successfully!")
        print(f"Users: {User.query.count()} | Assets: {Asset.query.count()} | "
              f"Vulnerabilities: {Vulnerability.query.count()} | "
              f"Incidents: {Incident.query.count()} | Audit Logs: {AuditLog.query.count()}")


if __name__ == "__main__":
    run_seed()