import re
import json
import traceback
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator
from reportlab.lib.utils import ImageReader
from app.modules.scan_workflow import run_scan


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
from dotenv import load_dotenv
load_dotenv()

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
    db = SessionLocal()

    try:
        scan = Scan(
            domain=request.domain,
            status="queued"
        )

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
def generate_scan_report(scan_id: int, format: str = "clean"):
    db = SessionLocal()

    try:
        # Validate report format
        if format not in ("clean", "json"):
            raise HTTPException(
                status_code=400,
                detail="Format must be clean or json"
            )

        # Retrieve scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if not scan.results:
            raise HTTPException(
                status_code=404,
                detail="No scan results available"
            )

        try:
            report_data = json.loads(scan.results)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=500,
                detail="Stored scan results are invalid"
            )

        if not isinstance(report_data, dict):
            raise HTTPException(
                status_code=500,
                detail="Invalid scan result structure"
            )

        # --------------------------------------------------
        # CREATE PDF DOCUMENT
        # --------------------------------------------------
        buffer = BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=25 * mm,
            title=f"CYBROT OSINT Report - {scan.domain}",
            author="CYBROT TECHNOLOGIES"
        )

        # --------------------------------------------------
        # WATERMARK - EVERY PAGE
        # --------------------------------------------------
        app_dir = Path(__file__).resolve().parent

        watermark_path = (
            app_dir / "assets" / "cybrot_watermark.png"
        )

        print("CYBROT watermark path:", watermark_path)
        print("CYBROT watermark exists:", watermark_path.is_file())


        def draw_watermark(canvas, doc):
            # Keep the watermark drawing isolated so a missing logo never
            # prevents the PDF report itself from being generated.
            canvas.saveState()
            try:
                if not watermark_path.is_file():
                    print("CYBROT watermark image not found:", watermark_path)
                    return

                image = ImageReader(str(watermark_path))
                image_width, image_height = image.getSize()

                if image_width <= 0 or image_height <= 0:
                    print("CYBROT watermark image has invalid dimensions.")
                    return

                # Smaller watermark, aligned to the bottom-right corner.
                watermark_width = 35 * mm
                watermark_height = watermark_width * image_height / image_width
                right_margin = 18 * mm
                x_position = A4[0] - right_margin - watermark_width

                canvas.drawImage(
                    image,
                    x_position,
                    7 * mm,
                    width=watermark_width,
                    height=watermark_height,
                    preserveAspectRatio=True,
                    mask="auto"
                )
                print("CYBROT watermark drawn successfully.")

            except Exception as watermark_error:
                print("Watermark drawing error:", repr(watermark_error))
            finally:
                canvas.restoreState()


        # --------------------------------------------------
        # PDF STYLES
        # --------------------------------------------------
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CybrotTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#079FC0"),
            alignment=TA_CENTER,
            fontSize=22,
            leading=27,
            spaceAfter=8
        )

        subtitle_style = ParagraphStyle(
            "CybrotSubtitle",
            parent=styles["Normal"],
            textColor=colors.HexColor("#526579"),
            alignment=TA_CENTER,
            fontSize=10,
            spaceAfter=18
        )

        heading_style = ParagraphStyle(
            "CybrotHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#087F9B"),
            fontSize=14,
            spaceBefore=14,
            spaceAfter=8
        )

        module_heading_style = ParagraphStyle(
            "CybrotModuleHeading",
            parent=styles["Heading3"],
            textColor=colors.HexColor("#075E75"),
            fontSize=10,
            spaceBefore=10,
            spaceAfter=5
        )

        body_style = ParagraphStyle(
            "CybrotBody",
            parent=styles["BodyText"],
            fontSize=8,
            leading=12,
            spaceAfter=5,
            wordWrap="CJK"
        )

        small_style = ParagraphStyle(
            "CybrotSmall",
            parent=body_style,
            fontSize=7,
            leading=10
        )

        label_style = ParagraphStyle(
            "CybrotLabel",
            parent=body_style,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#173B50")
        )

        story = []

        # --------------------------------------------------
        # NORMALIZE SCAN DATA
        # --------------------------------------------------
        module_results = report_data.get("results", {})

        if (
            isinstance(module_results, dict)
            and isinstance(module_results.get("results"), dict)
        ):
            module_results = module_results["results"]

        if not isinstance(module_results, dict):
            module_results = {}

        summary_source = report_data.get("results", {})

        if not isinstance(summary_source, dict):
            summary_source = {}

        total_modules = report_data.get(
            "total_modules",
            summary_source.get("total_modules", len(module_results))
        )

        successful_modules = report_data.get(
            "successful_modules",
            summary_source.get("successful_modules")
        )

        if successful_modules is None:
            successful_modules = sum(
                1 for result in module_results.values()
                if isinstance(result, dict)
                and result.get("status") == "success"
            )

        overall_status = report_data.get(
            "status",
            scan.status or "unknown"
        )

        # --------------------------------------------------
        # SECURITY FINDINGS
        # --------------------------------------------------
        findings_data = report_data.get("findings")

        if not isinstance(findings_data, dict):
            nested_results = report_data.get("results", {})

            if isinstance(nested_results, dict):
                findings_data = nested_results.get("findings", {})

        if not isinstance(findings_data, dict):
            findings_data = {}

        findings_list = findings_data.get("findings", [])

        if not isinstance(findings_list, list):
            findings_list = []

        severity_summary = findings_data.get("severity_summary", {})

        if not isinstance(severity_summary, dict):
            severity_summary = {}

        # --------------------------------------------------
        # HELPER FUNCTIONS
        # --------------------------------------------------
        def readable_value(value):
            if value is None:
                return "Not available"

            if isinstance(value, bool):
                return "Yes" if value else "No"

            if isinstance(value, (dict, list)):
                return json.dumps(
                    value,
                    indent=2,
                    ensure_ascii=False,
                    default=str
                )

            return str(value)

        def flatten_data(data, prefix=""):
            rows = []

            if isinstance(data, dict):
                if not data:
                    rows.append((prefix or "Result", "No data returned"))

                for key, value in data.items():
                    label = str(key).replace("_", " ").title()

                    full_label = (
                        f"{prefix} / {label}" if prefix else label
                    )

                    if isinstance(value, dict):
                        rows.extend(flatten_data(value, full_label))

                    elif isinstance(value, list):
                        if not value:
                            rows.append((full_label, "No entries"))

                        elif all(
                            not isinstance(item, (dict, list))
                            for item in value
                        ):
                            rows.append((
                                full_label,
                                ", ".join(
                                    readable_value(item) for item in value
                                )
                            ))

                        else:
                            for index, item in enumerate(value, start=1):
                                rows.extend(
                                    flatten_data(
                                        item,
                                        f"{full_label} #{index}"
                                    )
                                )

                    else:
                        rows.append((
                            full_label,
                            readable_value(value)
                        ))

            elif isinstance(data, list):
                for index, item in enumerate(data, start=1):
                    rows.extend(
                        flatten_data(item, f"{prefix} #{index}")
                    )

            else:
                rows.append((
                    prefix or "Result",
                    readable_value(data)
                ))

            return rows

        # --------------------------------------------------
        # JSON PDF
        # --------------------------------------------------
        if format == "json":

            story.append(
                Paragraph("CYBROT OSINT", title_style)
            )

            story.append(
                Paragraph(
                    "Website Intelligence & OSINT Assessment - JSON Report",
                    subtitle_style
                )
            )

            story.append(
                Paragraph("Scan Information", heading_style)
            )

            info_rows = [
                ["Field", "Value"],
                ["Scan ID", str(scan.id)],
                ["Domain", str(scan.domain)],
                ["Status", str(scan.status).upper()],
                ["Created At", str(scan.created_at)]
            ]

            info_table = Table(
                [
                    [
                        Paragraph(escape(str(cell)), body_style)
                        for cell in row
                    ]
                    for row in info_rows
                ],
                colWidths=[40 * mm, 125 * mm],
                repeatRows=1
            )

            info_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#087F9B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#E8F4F8")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8CBD5")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))

            story.append(info_table)
            story.append(Spacer(1, 15))

            story.append(
                Paragraph("Complete JSON Data", heading_style)
            )

            raw_json = json.dumps(
                report_data,
                indent=2,
                ensure_ascii=False,
                default=str
            )

            for start in range(0, len(raw_json), 1000):
                chunk = raw_json[start:start + 1000]

                story.append(
                    Paragraph(
                        escape(chunk).replace("\n", "<br/>"),
                        small_style
                    )
                )

                story.append(Spacer(1, 4))

        # --------------------------------------------------
        # CLEAN PDF
        # --------------------------------------------------
        else:

            story.append(
                Paragraph("CYBROT OSINT", title_style)
            )

            story.append(
                Paragraph(
                    "Website Intelligence & OSINT Assessment Report",
                    subtitle_style
                )
            )

            # 1. Scan Information
            story.append(
                Paragraph("1. Scan Information", heading_style)
            )

            scan_info = [
                ["Scan ID", str(scan.id)],
                ["Domain", str(scan.domain)],
                ["Scan Status", str(scan.status).upper()],
                ["Created At", str(scan.created_at)]
            ]

            info_data = [
                [
                    Paragraph(escape(str(row[0])), label_style),
                    Paragraph(escape(str(row[1])), body_style)
                ]
                for row in scan_info
            ]

            info_table = Table(
                info_data,
                colWidths=[40 * mm, 125 * mm]
            )

            info_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F4F8")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8CBD5")),
                ("PADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))

            story.append(info_table)
            story.append(Spacer(1, 12))

            # 2. Executive Summary
            story.append(
                Paragraph("2. Executive Summary", heading_style)
            )

            summary_rows = [
                ["Metric", "Result"],
                ["Total Modules", str(total_modules)],
                ["Successful Modules", str(successful_modules)],
                ["Overall Status", str(overall_status).upper()]
            ]

            summary_table = Table(
                [
                    [
                        Paragraph(escape(str(cell)), body_style)
                        for cell in row
                    ]
                    for row in summary_rows
                ],
                colWidths=[75 * mm, 90 * mm],
                repeatRows=1
            )

            summary_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#087F9B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8CBD5")),
                ("PADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))

            story.append(summary_table)
            story.append(Spacer(1, 10))

            # 3. Module Analysis
            story.append(
                Paragraph("3. Module Analysis", heading_style)
            )

            for module_name, result in module_results.items():

                if not isinstance(result, dict):
                    result = {"data": result}

                module_title = str(module_name).replace("_", " ").title()

                module_status = str(
                    result.get("status", "unknown")
                ).upper()

                story.append(
                    Paragraph(
                        f"{escape(module_title)} - {escape(module_status)}",
                        module_heading_style
                    )
                )

                if result.get("error"):
                    story.append(
                        Paragraph(
                            "<b>Module Error:</b> "
                            + escape(str(result["error"])),
                            body_style
                        )
                    )

                module_data = result.get("data", {
                    key: value
                    for key, value in result.items()
                    if key not in ("status", "error")
                })

                data_rows = flatten_data(module_data)

                if data_rows:
                    table_data = [[
                        Paragraph("Field", body_style),
                        Paragraph("Collected Result", body_style)
                    ]]

                    for field, value in data_rows:
                        table_data.append([
                            Paragraph(escape(str(field)), small_style),
                            Paragraph(
                                escape(str(value)).replace("\n", "<br/>"),
                                small_style
                            )
                        ])

                    result_table = Table(
                        table_data,
                        colWidths=[48 * mm, 117 * mm],
                        repeatRows=1,
                        splitByRow=1
                    )

                    result_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E1F1F5")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#075E75")),
                        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C7D5DD")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("PADDING", (0, 0), (-1, -1), 5)
                    ]))

                    story.append(result_table)

                else:
                    story.append(
                        Paragraph(
                            "No additional details were returned by this module.",
                            body_style
                        )
                    )

                story.append(Spacer(1, 8))

            # 4. Security Findings
            story.append(
                Paragraph("4. Security Findings", heading_style)
            )

            severity_rows = [
                ["Severity", "Count"],
                ["Critical", str(severity_summary.get("Critical", 0))],
                ["High", str(severity_summary.get("High", 0))],
                ["Medium", str(severity_summary.get("Medium", 0))],
                ["Low", str(severity_summary.get("Low", 0))],
                ["Informational", str(severity_summary.get("Informational", 0))]
            ]

            severity_table = Table(
                [
                    [
                        Paragraph(escape(str(cell)), body_style)
                        for cell in row
                    ]
                    for row in severity_rows
                ],
                colWidths=[85 * mm, 80 * mm],
                repeatRows=1
            )

            severity_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#087F9B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8CBD5")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))

            story.append(severity_table)
            story.append(Spacer(1, 10))

            story.append(
                Paragraph(
                    f"<b>Total Findings:</b> {len(findings_list)}",
                    body_style
                )
            )

            if findings_list:

                for index, finding in enumerate(findings_list, start=1):

                    if not isinstance(finding, dict):
                        continue

                    story.append(
                        Paragraph(
                            f"Finding {index}: "
                            + escape(str(finding.get("title", "Untitled"))),
                            module_heading_style
                        )
                    )

                    details = [
                        ("Severity", finding.get("severity", "Unknown")),
                        ("Category", finding.get("category", "Unknown")),
                        ("Description", finding.get("description", "Not available")),
                        (
                            "Evidence",
                            json.dumps(
                                finding.get("evidence", {}),
                                indent=2,
                                ensure_ascii=False,
                                default=str
                            )
                        ),
                        (
                            "Recommendation",
                            finding.get("recommendation", "No recommendation available")
                        )
                    ]

                    for label, value in details:
                        story.append(
                            Paragraph(
                                f"<b>{escape(str(label))}:</b> "
                                + escape(str(value)).replace("\n", "<br/>"),
                                small_style
                            )
                        )

                        story.append(Spacer(1, 4))

                    story.append(Spacer(1, 8))

            else:
                story.append(
                    Paragraph(
                        "No findings were generated by the automated analysis.",
                        body_style
                    )
                )

            # 5. Report Notes
            story.append(
                Paragraph("5. Report Notes", heading_style)
            )

            story.append(
                Paragraph(
                    "This report contains information collected by the "
                    "CYBROT OSINT modules. Results may be incomplete when "
                    "external sources are unavailable. A module marked "
                    "NOT_CONFIGURED or NOT_CHECKED should not be interpreted "
                    "as a confirmed security vulnerability. Collected "
                    "observations should be manually validated before "
                    "making security decisions.",
                    body_style
                )
            )

            story.append(Spacer(1, 8))

            story.append(
                Paragraph(
                    "Report generated by CYBROT TECHNOLOGIES. "
                    "For authorized security assessment and defensive "
                    "intelligence purposes.",
                    small_style
                )
            )

        # --------------------------------------------------
        # BUILD PDF WITH WATERMARK ON EVERY PAGE
        # --------------------------------------------------
        document.build(
            story,
            onFirstPage=draw_watermark,
            onLaterPages=draw_watermark
        )

        buffer.seek(0)
        pdf_bytes = buffer.getvalue()

        if not pdf_bytes.startswith(b"%PDF"):
            raise RuntimeError("Generated PDF is invalid")

        filename = f"cybrot_scan_{scan.id}_{format}.pdf"

        return StreamingResponse(
            BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
                "Cache-Control": "no-store"
            }
        )

    except HTTPException:
        raise

    except Exception as error:
        print("PDF GENERATION ERROR:", repr(error))

        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {str(error)}"
        )

    finally:
        db.close()
