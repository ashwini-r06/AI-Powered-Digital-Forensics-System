"""Generate PDF investigation reports for CyberSentry AI."""

from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _safe(value: Any) -> str:
    """Convert values to safe text for ReportLab."""
    if value is None:
        return "N/A"
    try:
        missing = pd.isna(value)
        if bool(missing):
            return "N/A"
    except (TypeError, ValueError):
        pass
    return escape(str(value))


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_safe(value), style)


def _add_section_title(story: list, title: str, styles: Any) -> None:
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(_safe(title), styles["Heading2"]))
    story.append(Spacer(1, 2 * mm))


def _to_records(data: Any) -> list[dict]:
    """Convert DataFrames, dictionaries, and lists into report records."""
    if data is None:
        return []
    if isinstance(data, pd.DataFrame):
        # Convert to object dtype first so missing values can become None.
        return data.astype(object).where(pd.notna(data), None).to_dict(orient="records")
    if isinstance(data, dict):
        return [data]
    if isinstance(data, (list, tuple)):
        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(item)
            elif hasattr(item, "_mapping"):
                result.append(dict(item._mapping))
            else:
                result.append({"value": item})
        return result
    return [{"value": data}]


def _add_table(
    story: list,
    records: list[dict],
    columns: list[str],
    styles: Any,
    page_width: float,
) -> None:
    """Add a wrapping table with a repeated header row."""
    if not records:
        story.append(Paragraph("No records available.", styles["BodyText"]))
        return

    if not columns:
        columns = list(records[0].keys())[:6]
    if not columns:
        story.append(Paragraph("No records available.", styles["BodyText"]))
        return

    header_style = ParagraphStyle(
        "CyberSentryTableHeader",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=9,
        textColor=colors.white,
    )
    cell_style = ParagraphStyle(
        "CyberSentryTableCell",
        parent=styles["BodyText"],
        fontSize=6.8,
        leading=8.5,
        wordWrap="LTR",
    )

    table_data = [
        [_paragraph(column.replace("_", " ").title(), header_style) for column in columns]
    ]
    for record in records:
        table_data.append([_paragraph(record.get(column), cell_style) for column in columns])

    available_width = page_width - 30 * mm
    col_width = available_width / len(columns)
    table = Table(
        table_data,
        colWidths=[col_width] * len(columns),
        repeatRows=1,
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D0D9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F2F5F8")]),
        ])
    )
    story.append(table)


def _draw_footer(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#536273"))
    canvas.drawString(15 * mm, 10 * mm, "CyberSentry AI — Investigation Report")
    canvas.drawRightString(doc.pagesize[0] - 15 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_investigation_pdf(
    case_details: dict,
    evidence: Any = None,
    findings: Any = None,
    timeline: Any = None,
    audit_entries: Any = None,
) -> bytes:
    """Generate a PDF report and return the PDF content as bytes.

    case_details may be the dictionary returned by get_case_details().
    """
    if not isinstance(case_details, dict):
        raise TypeError("case_details must be a dictionary.")

    case = case_details.get("case") or {}
    if not isinstance(case, dict):
        case = {}

    evidence_records = _to_records(
        evidence if evidence is not None else case_details.get("evidence", [])
    )
    finding_records = _to_records(
        findings if findings is not None else case_details.get("findings", [])
    )
    timeline_records = _to_records(timeline)
    audit_records = _to_records(
        audit_entries if audit_entries is not None else case_details.get("audit_entries", [])
    )

    output = BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title="CyberSentry AI Investigation Report",
        author="CyberSentry AI",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CyberSentryReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=25,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D"),
        spaceAfter=6 * mm,
    ))

    story = [
        Paragraph("CyberSentry AI", styles["CyberSentryReportTitle"]),
        Paragraph("Digital Forensics & Incident Response Report", styles["Heading2"]),
        Spacer(1, 2 * mm),
        Paragraph(
            f"<b>Generated (UTC):</b> {_safe(datetime.now(timezone.utc).isoformat())}",
            styles["BodyText"],
        ),
        Spacer(1, 5 * mm),
    ]

    _add_section_title(story, "1. Investigation Case", styles)
    case_records = [{
        "field": label,
        "value": value,
    } for label, value in [
        ("Case Number", case.get("case_number", case.get("id"))),
        ("Title", case.get("title")),
        ("Description", case.get("description")),
        ("Status", case.get("status")),
        ("Priority", case.get("priority")),
        ("Created At", case.get("created_at")),
        ("Updated At", case.get("updated_at")),
    ]]
    _add_table(story, case_records, ["field", "value"], styles, doc.width + 30 * mm)

    story.append(PageBreak())
    _add_section_title(story, "2. Evidence Registry", styles)
    evidence_columns = [
        "id", "filename", "sha256", "file_size", "evidence_status", "recorded_at"
    ]
    _add_table(story, evidence_records, evidence_columns, styles, doc.width + 30 * mm)

    story.append(PageBreak())
    _add_section_title(story, "3. Security Findings", styles)
    finding_columns = [
        "id", "rule_id", "title", "severity", "category", "description",
        "source_ip", "username", "event_count", "status",
    ]
    _add_table(story, finding_records, finding_columns, styles, doc.width + 30 * mm)

    if timeline_records:
        story.append(PageBreak())
        _add_section_title(story, "4. Forensic Timeline", styles)
        timeline_columns = [
            "timeline_time_utc", "timestamp", "event_type", "host", "username",
            "source_ip", "destination_ip", "message",
        ]
        _add_table(story, timeline_records, timeline_columns, styles, doc.width + 30 * mm)

    story.append(PageBreak())
    _add_section_title(story, "5. Audit Trail", styles)
    audit_columns = ["id", "action", "actor", "details", "created_at"]
    _add_table(story, audit_records, audit_columns, styles, doc.width + 30 * mm)

    story.extend([
        Spacer(1, 8 * mm),
        Paragraph(
            "<b>Important:</b> Automated detection results are investigative leads and "
            "require analyst validation. This report does not independently establish "
            "that an attack occurred or that evidence is authentic.",
            styles["BodyText"],
        ),
    ])

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return output.getvalue()
