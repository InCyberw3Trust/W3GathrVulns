from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List
from app.database import get_db
from app.models import Finding, Project, SeverityEnum, StatusEnum, SourceEnum
import csv
import io
from datetime import datetime

router = APIRouter(prefix="/export", tags=["export"])


def get_filtered_findings(
    db: Session,
    project_id: Optional[str] = None,
    severity: Optional[List[str]] = None,
    status: Optional[List[str]] = None,
    source: Optional[List[str]] = None,
    search: Optional[str] = None,
    filters: Optional[str] = None,
) -> List[Finding]:
    import json
    from sqlalchemy import or_, func, cast
    from sqlalchemy import Text as SAText
    q = db.query(Finding).join(Project, Finding.project_id == Project.id)
    if project_id:
        q = q.filter(Finding.project_id == project_id)
    if severity:
        q = q.filter(Finding.severity.in_(severity))
    if status:
        q = q.filter(Finding.status.in_(status))
    if source:
        q = q.filter(Finding.source.in_(source))
    if search:
        q = q.filter(or_(
            Finding.title.ilike(f"%{search}%"),
            Finding.cve.ilike(f"%{search}%"),
            Finding.vuln_id.ilike(f"%{search}%"),
            Finding.component.ilike(f"%{search}%"),
            Finding.file_path.ilike(f"%{search}%"),
        ))
    if filters:
        try:
            ENUM_COLS = {"source": Finding.source, "severity": Finding.severity, "status": Finding.status}
            TEXT_COLS = {"title": Finding.title, "file_path": Finding.file_path, "component": Finding.component,
                         "vuln_id": Finding.vuln_id, "cve": Finding.cve, "description": Finding.description, "project": Project.name}
            for flt in json.loads(filters):
                field, op, val = flt.get("field"), flt.get("op"), flt.get("value", "")
                if field in ENUM_COLS:
                    raw = ENUM_COLS[field]
                    text = cast(raw, SAText)
                    if op == "equals":       q = q.filter(raw == val.upper())
                    elif op == "not_equals": q = q.filter(raw != val.upper())
                    elif op == "in":         q = q.filter(raw.in_([v.strip().upper() for v in val.split(",")]))
                    elif op == "contains":   q = q.filter(text.ilike(f"%{val}%"))
                    elif op == "not_contains": q = q.filter(~text.ilike(f"%{val}%"))
                elif field in TEXT_COLS:
                    col = TEXT_COLS[field]
                    if op == "equals":         q = q.filter(func.lower(col) == val.lower())
                    elif op == "not_equals":   q = q.filter(func.lower(col) != val.lower())
                    elif op == "contains":     q = q.filter(col.ilike(f"%{val}%"))
                    elif op == "not_contains": q = q.filter(~col.ilike(f"%{val}%"))
                    elif op == "starts_with":  q = q.filter(col.ilike(f"{val}%"))
                    elif op == "ends_with":    q = q.filter(col.ilike(f"%{val}"))
        except Exception:
            pass
    return q.order_by(Finding.severity, Finding.first_seen.desc()).all()


@router.get("/csv")
def export_csv(
    project_id: Optional[str] = Query(None),
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    source: Optional[List[str]] = Query(None),
    search: Optional[str] = Query(None),
    filters: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    findings = get_filtered_findings(db, project_id, severity, status, source, search, filters)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Severity", "Status", "Source", "Project",
        "CVE", "CVSS", "Component", "Component Version", "Fixed Version",
        "File Path", "Line", "URL", "First Seen", "Last Seen", "Tags"
    ])

    for f in findings:
        writer.writerow([
            f.id, f.title, f.severity.value, f.status.value, f.source.value,
            f.project.name if f.project else "",
            f.cve or "", f.cvss_score or "",
            f.component or "", f.component_version or "", f.fixed_version or "",
            f.file_path or "", f.line_start or "",
            f.url or "",
            f.first_seen.isoformat() if f.first_seen else "",
            f.last_seen.isoformat() if f.last_seen else "",
            ",".join(f.tags or []),
        ])

    output.seek(0)
    filename = f"w3gathrvulns-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/pdf")
def export_pdf(
    project_id: Optional[str] = Query(None),
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    source: Optional[List[str]] = Query(None),
    search: Optional[str] = Query(None),
    filters: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import cm

    findings = get_filtered_findings(db, project_id, severity, status, source, search, filters)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=1.5*cm, rightMargin=1.5*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=18,
                                  textColor=colors.HexColor("#0f172a"), spaceAfter=6)
    elements.append(Paragraph("W3GathrVulns — Security Findings Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Total findings: {len(findings)}",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 0.5*cm))

    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#dc2626"),
        "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#ca8a04"),
        "LOW": colors.HexColor("#16a34a"),
        "INFO": colors.HexColor("#2563eb"),
        "UNKNOWN": colors.HexColor("#6b7280"),
    }

    data = [["Severity", "Title", "Source", "Project", "CVE", "First Seen"]]
    row_colors = []

    for i, f in enumerate(findings[:500], 1):  # Cap at 500
        data.append([
            f.severity.value,
            (f.title[:60] + "...") if len(f.title) > 60 else f.title,
            f.source.value,
            f.project.name[:20] if f.project else "",
            f.cve or f.vuln_id or "",
            f.first_seen.strftime("%Y-%m-%d") if f.first_seen else "",
        ])
        row_colors.append(SEV_COLORS.get(f.severity.value, colors.gray))

    col_widths = [2.2*cm, 8*cm, 2.8*cm, 3*cm, 2.5*cm, 2.5*cm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])
    for i, color in enumerate(row_colors, 1):
        style.add("TEXTCOLOR", (0, i), (0, i), color)
        style.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
    table.setStyle(style)
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    filename = f"w3gathrvulns-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    return StreamingResponse(
        iter([buffer.read()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
