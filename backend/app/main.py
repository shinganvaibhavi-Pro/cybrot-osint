import re
import re
import json
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.modules.scan_workflow import run_scan

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.database import Base, engine, SessionLocal, check_database
from app.models import Scan
from app.modules.domain_intelligence import lookup_domain
from app.modules.dns_analysis import analyze_dns
from app.modules.ssl_analysis import analyze_ssl
from app.modules.security_headers import analyze_headers
from app.modules.email_security import analyze_email_security
from app.modules.technology_stack import analyze_technology
from app.modules.subdomain_discovery import discover_subdomains
from app.modules.infrastructure import analyze_infrastructure
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi.responses import StreamingResponse

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

Base.metadata.create_all(bind=engine)
app = FastAPI(
    title="CYBROT OSINT API",
    description="Local Website Intelligence and OSINT Engine",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

class ScanRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    authorized: bool

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value):
        value = value.strip().lower()
        pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
        if not re.fullmatch(pattern, value):
            raise ValueError("Enter a valid domain name")
        return value

@app.get("/")
def root():
    return {"message": "Welcome to CYBROT OSINT API", "status": "running"}

@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "application": "CYBROT OSINT",
        "engine": "online",
        "version": "0.1.0"
    }

@app.get("/api/v1/database/status")
def database_status():
    check_database()
    return {"database": "connected", "type": "SQLite", "status": "healthy"}

@app.get("/api/v1/modules")
def modules():
    return {
        "modules": [
            "Domain Intelligence",
            "DNS Analysis",
            "Subdomain Discovery",
            "SSL / TLS",
            "Technology Stack",
            "Infrastructure",
            "Security Headers",
            "Email Security",
            "Threat Intelligence"
        ]
    }

@app.get("/api/v1/domain/{domain}")
def domain_intelligence(domain: str):
    try:
        return lookup_domain(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))

@app.post("/api/v1/scans")
def create_scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Authorization is required")

    db = SessionLocal()
    try:
        scan = Scan(domain=request.domain, status="queued")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        return {
            "scan_id": scan.id,
            "domain": scan.domain,
            "status": scan.status,
            "message": "Scan request saved. Collection engine is pending."
        }
    finally:
        db.close()

@app.get("/api/v1/scans")
def get_scans():
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.id.desc()).all()
        return {
            "total": len(scans),
            "scans": [
                {
                    "scan_id": scan.id,
                    "domain": scan.domain,
                    "status": scan.status,
                    "created_at": scan.created_at.isoformat()
                }
                for scan in scans
            ]
        }
    finally:
        db.close()

@app.get("/api/v1/dns/{domain}")
def dns_analysis(domain: str):
    try:
        return analyze_dns(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@app.get("/api/v1/ssl/{domain}")
def ssl_analysis(domain: str):
    try:
        return analyze_ssl(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))

@app.get("/api/v1/security-headers/{domain}")
def security_headers(domain: str):
    try:
        return analyze_headers(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))

@app.get("/api/v1/email-security/{domain}")
def email_security(domain: str):
    try:
        return analyze_email_security(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@app.get("/api/v1/technology/{domain}")
def technology_stack(domain: str):
    try:
        return analyze_technology(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))

@app.get("/api/v1/subdomains/{domain}")
def subdomain_discovery(domain: str):
    try:
        return discover_subdomains(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))

@app.get("/api/v1/infrastructure/{domain}")
def infrastructure_analysis(domain: str):
    try:
        return analyze_infrastructure(domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))


@app.post("/api/v1/scans/{scan_id}/run")
def run_existing_scan(scan_id: int):
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(
            Scan.id == scan_id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan not found"
            )

        scan.status = "running"
        db.commit()

        results = run_scan(scan.domain)

        scan.results = json.dumps(results)
        scan.status = results["status"]
        db.commit()

        return {
            "scan_id": scan.id,
            "domain": scan.domain,
            "status": scan.status,
            "results": results
        }

    except HTTPException:
        raise
    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )
    finally:
        db.close()


@app.get("/api/v1/scans/{scan_id}/results")
def get_scan_results(scan_id: int):
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(
            Scan.id == scan_id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan not found"
            )

        return {
            "scan_id": scan.id,
            "domain": scan.domain,
            "status": scan.status,
            "results": json.loads(scan.results)
            if scan.results else None
        }
    finally:
        db.close()


@app.get("/api/v1/scans/{scan_id}/report")
def generate_scan_report(scan_id: int):
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan not found"
            )

        if not scan.results:
            raise HTTPException(
                status_code=404,
                detail="No scan results available for this scan"
            )

        try:
            report_data = json.loads(scan.results)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=500,
                detail="Stored scan results are invalid"
            )

        buffer = BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#079FC0"),
            alignment=TA_CENTER,
            fontSize=22,
            spaceAfter=12
        )

        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#087F9B"),
            spaceBefore=12,
            spaceAfter=7
        )

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            spaceAfter=5,
            wordWrap="CJK"
        )

        story = []

        story.append(Paragraph("CYBROT OSINT", title_style))
        story.append(
            Paragraph("Website Intelligence & OSINT Report", styles["Heading2"])
        )
        story.append(Spacer(1, 10))

        story.append(Paragraph("1. Scan Information", heading_style))

        scan_info = [
            ["Scan ID", str(scan.id)],
            ["Domain", escape(scan.domain)],
            ["Status", escape(scan.status.upper())],
            ["Created At", escape(scan.created_at.isoformat())],
        ]

        info_table = Table(scan_info, colWidths=[40 * mm, 125 * mm])

        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F4F8")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        story.append(info_table)
        story.append(Spacer(1, 12))

        summary = report_data.get("results", {})
        total_modules = report_data.get("total_modules", len(summary))
        successful = report_data.get("successful_modules", 0)

        story.append(Paragraph("2. Executive Summary", heading_style))
        story.append(Paragraph(
            f"Total modules: {total_modules}<br/>"
            f"Successful modules: {successful}<br/>"
            f"Overall status: {escape(str(report_data.get('status', scan.status)).upper())}",
            body_style
        ))

        story.append(Paragraph("3. Module Analysis", heading_style))

        for module_name, result in summary.items():
            module_status = result.get("status", "unknown")
            story.append(
                Paragraph(
                    escape(module_name.replace("_", " ").title())
                    + " - "
                    + escape(str(module_status).upper()),
                    styles["Heading3"]
                )
            )

            if result.get("error"):
                details = "Error: " + str(result["error"])
            elif "data" in result:
                details = json.dumps(
                    result["data"],
                    indent=2,
                    ensure_ascii=True,
                    default=str
                )
            else:
                details = "No additional details available."

            details = details[:8000]

            story.append(
                Paragraph(
                    escape(details).replace("\n", "<br/>"),
                    body_style
                )
            )

            story.append(Spacer(1, 6))

        story.append(Spacer(1, 10))
        story.append(Paragraph("4. Report Notes", heading_style))
        story.append(Paragraph(
            "This report contains results collected by the CYBROT OSINT "
            "passive intelligence modules. Results may be incomplete when "
            "external sources are unavailable. Findings should be manually "
            "validated before making security decisions.",
            body_style
        ))

        document.build(story)

        buffer.seek(0)

        filename = f"cybrot_scan_{scan.id}.pdf"

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )

    finally:
        db.close()

