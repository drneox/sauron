"""
PDF Report Generator for Sauron
Generates a professional, styled PDF with all scan results.
"""
from __future__ import annotations

import html as _html
import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    FrameBreak,
    HRFlowable,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Frame,
    KeepTogether,
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as pdfcanvas

# ─── Color Palette ────────────────────────────────────────────────────────────
C_BG_COVER   = colors.HexColor("#0f172a")   # cover background
C_BG_BAND    = colors.HexColor("#1e293b")   # section header band
C_BG_ROW_ALT = colors.HexColor("#f8fafc")   # alternating row
C_BG_ROW_2   = colors.HexColor("#ffffff")
C_CYBER      = colors.HexColor("#10b981")   # brand green
C_CYBER_DIM  = colors.HexColor("#064e3b")
C_TEXT       = colors.HexColor("#1e293b")
C_TEXT_MUTED = colors.HexColor("#64748b")
C_BORDER     = colors.HexColor("#e2e8f0")

C_CRITICAL   = colors.HexColor("#ef4444")
C_HIGH       = colors.HexColor("#f97316")
C_MEDIUM     = colors.HexColor("#eab308")
C_LOW        = colors.HexColor("#22c55e")
C_INFO       = colors.HexColor("#3b82f6")

C_CRITICAL_BG = colors.HexColor("#fef2f2")
C_HIGH_BG     = colors.HexColor("#fff7ed")
C_MEDIUM_BG   = colors.HexColor("#fefce8")
C_LOW_BG      = colors.HexColor("#f0fdf4")

RISK_COLOR = {
    "critical": C_CRITICAL,
    "high":     C_HIGH,
    "medium":   C_MEDIUM,
    "low":      C_LOW,
    "info":     C_INFO,
}
RISK_BG = {
    "critical": C_CRITICAL_BG,
    "high":     C_HIGH_BG,
    "medium":   C_MEDIUM_BG,
    "low":      C_LOW_BG,
    "info":     colors.HexColor("#eff6ff"),
}

PAGE_W, PAGE_H = A4
MARGIN_L = 1.8 * cm
MARGIN_R = 1.8 * cm
MARGIN_T = 1.8 * cm
MARGIN_B = 1.8 * cm
COL_W = PAGE_W - MARGIN_L - MARGIN_R


# ─── Custom Flowables ─────────────────────────────────────────────────────────

class RiskBadge(Flowable):
    """Small inline colored risk badge pill."""
    def __init__(self, risk: str, width=1.8*cm, height=0.45*cm):
        super().__init__()
        self.risk  = risk.lower()
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        col  = RISK_COLOR.get(self.risk, C_INFO)
        bg   = RISK_BG.get(self.risk, colors.white)
        c.setFillColor(bg)
        c.setStrokeColor(col)
        c.setLineWidth(0.5)
        r = self.height / 2
        c.roundRect(0, 0, self.width, self.height, r, stroke=1, fill=1)
        c.setFillColor(col)
        c.setFont("Helvetica-Bold", 6)
        label = self.risk.upper()
        c.drawCentredString(self.width / 2, self.height / 2 - 2.5, label)


class ScoreCircle(Flowable):
    """Big donut-style score indicator for the cover page."""
    def __init__(self, score: int, grade: str, risk: str, size=4*cm):
        super().__init__()
        self.score = score
        self.grade = grade
        self.risk  = risk
        self.width = self.height = size

    def draw(self):
        c    = self.canv
        cx   = self.width / 2
        cy   = self.height / 2
        r    = self.width / 2 - 4
        col  = RISK_COLOR.get(self.risk, C_INFO)

        # Background ring
        c.setStrokeColor(colors.HexColor("#e2e8f0"))
        c.setLineWidth(6)
        c.circle(cx, cy, r, stroke=1, fill=0)

        # Score arc using path
        from math import pi, cos, sin, radians
        sweep = (self.score / 100) * 360
        start_rad = radians(90)
        end_rad   = radians(90 - sweep)

        c.setStrokeColor(col)
        c.setLineWidth(6)
        # Draw the arc as a series of small line segments for compatibility
        steps = max(int(sweep), 1)
        p = c.beginPath()
        angle0 = radians(90)
        p.moveTo(cx + r * cos(angle0), cy + r * sin(angle0))
        for i in range(1, steps + 1):
            angle = radians(90 - (sweep * i / steps))
            p.lineTo(cx + r * cos(angle), cy + r * sin(angle))
        c.drawPath(p, stroke=1, fill=0)

        # Grade
        c.setFillColor(col)
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(cx, cy + 3, self.grade)

        # Score number
        c.setFillColor(C_TEXT_MUTED)
        c.setFont("Helvetica", 8)
        c.drawCentredString(cx, cy - 10, f"{self.score}/100")


# ─── Style Sheet ──────────────────────────────────────────────────────────────

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title", fontName="Helvetica-Bold", fontSize=28,
            textColor=colors.white, alignment=TA_CENTER, leading=34,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", fontName="Helvetica", fontSize=11,
            textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER, leading=16,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", fontName="Helvetica", fontSize=9,
            textColor=colors.HexColor("#64748b"), alignment=TA_CENTER, leading=14,
        ),
        "section_title": ParagraphStyle(
            "section_title", fontName="Helvetica-Bold", fontSize=11,
            textColor=colors.white, leftIndent=4, leading=16,
        ),
        "h2": ParagraphStyle(
            "h2", fontName="Helvetica-Bold", fontSize=10,
            textColor=C_TEXT, spaceBefore=8, spaceAfter=4, leading=14,
        ),
        "body": ParagraphStyle(
            "body", fontName="Helvetica", fontSize=8,
            textColor=C_TEXT, leading=11,
        ),
        "body_bold": ParagraphStyle(
            "body_bold", fontName="Helvetica-Bold", fontSize=8,
            textColor=C_TEXT, leading=11,
        ),
        "small": ParagraphStyle(
            "small", fontName="Helvetica", fontSize=7,
            textColor=C_TEXT_MUTED, leading=10,
        ),
        "small_mono": ParagraphStyle(
            "small_mono", fontName="Courier", fontSize=7,
            textColor=C_TEXT, leading=10,
        ),
        "mono": ParagraphStyle(
            "mono", fontName="Courier", fontSize=7.5,
            textColor=C_TEXT, leading=10,
        ),
        "finding": ParagraphStyle(
            "finding", fontName="Helvetica", fontSize=7.5,
            textColor=C_TEXT, leading=11, leftIndent=6,
        ),
        "label": ParagraphStyle(
            "label", fontName="Helvetica-Bold", fontSize=7,
            textColor=C_TEXT_MUTED, leading=10,
        ),
        "value": ParagraphStyle(
            "value", fontName="Helvetica", fontSize=8,
            textColor=C_TEXT, leading=10,
        ),
    }


# ─── Page Decorators ──────────────────────────────────────────────────────────

def _cover_page_bg(c: pdfcanvas.Canvas, doc):
    """Draws the dark cover page background and footer."""
    c.saveState()
    c.setFillColor(C_BG_COVER)
    c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    # Green accent bar at top
    c.setFillColor(C_CYBER)
    c.rect(0, PAGE_H - 6, PAGE_W, 6, stroke=0, fill=1)

    # Green accent bar at bottom
    c.rect(0, 0, PAGE_W, 4, stroke=0, fill=1)

    # Footer text
    c.setFillColor(colors.HexColor("#475569"))
    c.setFont("Helvetica", 7)
    c.drawCentredString(PAGE_W / 2, 12, "SAURON — Automated Security Assessment · by Carlos Ganoza")
    c.restoreState()


def _content_page_bg(c: pdfcanvas.Canvas, doc):
    """Draws header/footer for content pages."""
    c.saveState()

    # Top bar
    c.setFillColor(C_BG_BAND)
    c.rect(0, PAGE_H - 30, PAGE_W, 30, stroke=0, fill=1)

    c.setFillColor(C_CYBER)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(MARGIN_L, PAGE_H - 18, "SAURON")

    c.setFillColor(colors.white)
    c.setFont("Helvetica", 8)
    domain = getattr(doc, "_report_domain", "")
    c.drawRightString(PAGE_W - MARGIN_R, PAGE_H - 18, domain)

    # Bottom bar
    c.setFillColor(C_BG_BAND)
    c.rect(0, 0, PAGE_W, 22, stroke=0, fill=1)

    c.setFillColor(colors.HexColor("#64748b"))
    c.setFont("Helvetica", 7)
    c.drawString(MARGIN_L, 7, "CONFIDENTIAL — Security Assessment Report")
    c.drawRightString(PAGE_W - MARGIN_R, 7, f"Page {doc.page}")

    c.restoreState()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _e(text: Any) -> str:
    """Escape a value for safe use inside a ReportLab Paragraph (XML parser)."""
    return _html.escape(str(text) if text is not None else "—")


def _section_header(title: str, icon: str = "") -> Table:
    """Creates a colored section header band."""
    label = f"{icon}  {title}" if icon else title
    t = Table([[Paragraph(label, ParagraphStyle(
        "sh", fontName="Helvetica-Bold", fontSize=9.5,
        textColor=colors.white, leading=14,
    ))]], colWidths=[COL_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_BG_BAND),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("ROUNDEDCORNERS", [4]),
    ]))
    return t


def _kv_table(rows: list[tuple[str, str]], col_w: tuple = None) -> Table:
    """Key-value two-column table."""
    styles = _build_styles()
    if col_w is None:
        col_w = (3.5 * cm, COL_W - 3.5 * cm)
    data = [
        [
            Paragraph(_e(k), styles["label"]),
            Paragraph(_e(v), styles["value"]),
        ]
        for k, v in rows
    ]
    t = Table(data, colWidths=list(col_w))
    t.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG_ROW_2, C_BG_ROW_ALT]),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
    ]))
    return t


def _findings_table(findings: list[dict], styles: dict) -> Table | None:
    if not findings:
        return None
    rows = [
        [Paragraph("Risk", styles["label"]),
         Paragraph("Category", styles["label"]),
         Paragraph("Module", styles["label"]),
         Paragraph("Finding", styles["label"])],
    ]
    for f in findings:
        risk = f.get("risk", "low")
        col  = RISK_COLOR.get(risk, C_INFO)
        rows.append([
            Paragraph(f'<font color="{col.hexval()}">{risk.upper()}</font>', styles["body_bold"]),
            Paragraph(_e(f.get("category", "") or ""), styles["small"]),
            Paragraph(_e(f.get("module", "")), styles["small"]),
            Paragraph(_e(f.get("finding", "")), styles["finding"]),
        ])
    t = Table(rows, colWidths=[1.4*cm, 2.2*cm, 2.2*cm, COL_W - 5.8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  C_BG_BAND),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _check(ok: bool) -> str:
    return "✓" if ok else "✗"


def _risk_label(risk: str, styles: dict) -> Paragraph:
    col = RISK_COLOR.get(risk.lower(), C_INFO)
    return Paragraph(
        f'<font color="{col.hexval()}"><b>{risk.upper()}</b></font>',
        styles["body"],
    )


def _spacer(h: float = 0.3) -> Spacer:
    return Spacer(1, h * cm)


def _hr() -> HRFlowable:
    return HRFlowable(width=COL_W, thickness=0.3, color=C_BORDER, spaceAfter=4)


# ─── Section Builders ─────────────────────────────────────────────────────────

def _build_cover(domain: str, report: dict, styles: dict) -> list:
    """Cover page flowables."""
    sc = report.get("scorecard", {})
    score = sc.get("score", 0)
    grade = sc.get("grade", "?")
    risk  = sc.get("overall_risk", "low")
    scanned_at = report.get("scanned_at", "")
    try:
        dt = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        date_str = dt.strftime("%B %d, %Y  %H:%M UTC")
    except Exception:
        date_str = scanned_at

    elems: list = []
    elems.append(Spacer(1, 5 * cm))

    # Brand label
    elems.append(Paragraph(
        '<font color="#10b981">SAURON</font>',
        ParagraphStyle("brand", fontName="Helvetica-Bold", fontSize=13,
                       textColor=C_CYBER, alignment=TA_CENTER, leading=18,
                       letterSpacing=4),
    ))
    elems.append(_spacer(0.5))

    # Title
    elems.append(Paragraph("Security Assessment Report", styles["cover_title"]))
    elems.append(_spacer(0.6))

    # Domain
    elems.append(Paragraph(
        f'<font color="#10b981">{_e(domain)}</font>',
        ParagraphStyle("domain", fontName="Helvetica-Bold", fontSize=18,
                       textColor=C_CYBER, alignment=TA_CENTER, leading=24),
    ))
    elems.append(_spacer(1.5))

    # Score circle — center it in a 1-cell table
    circle = ScoreCircle(score, grade, risk, size=4.5 * cm)
    t = Table([[circle]], colWidths=[COL_W])
    t.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    elems.append(t)
    elems.append(_spacer(0.4))

    risk_col = RISK_COLOR.get(risk, C_INFO)
    elems.append(Paragraph(
        f'<font color="{risk_col.hexval()}"><b>Overall Risk: {risk.upper()}</b></font>',
        ParagraphStyle("or", fontName="Helvetica-Bold", fontSize=11,
                       textColor=risk_col, alignment=TA_CENTER, leading=16),
    ))
    elems.append(_spacer(2))

    # Meta table
    num_findings = len(report.get("findings", []))
    mods = report.get("modules", {})
    meta_rows = [
        ["Scanned on", date_str],
        ["Total Findings", str(num_findings)],
        ["Modules", str(len([k for k, v in mods.items() if v and v.get("status") != "error"]))],
        ["Subdomains Found", str((mods.get("subdomains") or {}).get("count", 0))],
        ["Open Ports", str((mods.get("ports") or {}).get("total_open", 0))],
    ]
    data = [[
        Paragraph(_e(k), ParagraphStyle("mk", fontName="Helvetica-Bold", fontSize=8,
                                    textColor=colors.HexColor("#94a3b8"), alignment=TA_RIGHT)),
        Paragraph(_e(v), ParagraphStyle("mv", fontName="Helvetica", fontSize=8,
                                    textColor=colors.white)),
    ] for k, v in meta_rows]
    mt = Table(data, colWidths=[4.5 * cm, 6 * cm], hAlign="CENTER")
    mt.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.3, colors.HexColor("#1e293b")),
    ]))
    elems.append(mt)
    elems.append(PageBreak())
    return elems


def _build_executive_summary(report: dict, styles: dict) -> list:
    elems: list = []
    elems.append(_section_header("EXECUTIVE SUMMARY", "📋"))
    elems.append(_spacer(0.3))

    sc  = report.get("scorecard", {})
    findings = report.get("findings", [])

    # Score + grade row
    score = sc.get("score", 0)
    grade = sc.get("grade", "?")
    risk  = sc.get("overall_risk", "low")
    risk_col = RISK_COLOR.get(risk, C_INFO)

    score_data = [
        [Paragraph("Security Score", styles["label"]),
         Paragraph("Grade", styles["label"]),
         Paragraph("Overall Risk", styles["label"]),
         Paragraph("Findings", styles["label"])],
        [Paragraph(f"<b>{score}/100</b>", ParagraphStyle("sv", fontName="Helvetica-Bold",
              fontSize=16, textColor=risk_col, alignment=TA_CENTER)),
         Paragraph(f"<b>{grade}</b>", ParagraphStyle("gv", fontName="Helvetica-Bold",
              fontSize=16, textColor=risk_col, alignment=TA_CENTER)),
         Paragraph(f'<b><font color="{risk_col.hexval()}">{risk.upper()}</font></b>',
              ParagraphStyle("rv", fontName="Helvetica-Bold", fontSize=11,
                             textColor=risk_col, alignment=TA_CENTER)),
         Paragraph(f"<b>{len(findings)}</b>", ParagraphStyle("fv", fontName="Helvetica-Bold",
              fontSize=16, textColor=C_TEXT, alignment=TA_CENTER))],
    ]
    qw = COL_W / 4
    st = Table(score_data, colWidths=[qw, qw, qw, qw])
    st.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  C_BG_BAND),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",   (0, 1), (-1, 1),  C_BG_ROW_ALT),
    ]))
    elems.append(st)
    elems.append(_spacer(0.4))

    # Risk breakdown per module
    elems.append(Paragraph("Risk by Module", styles["h2"]))
    mods = report.get("modules", {})
    risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    mod_risks = sorted(
        [(k, v.get("risk", "low")) for k, v in mods.items() if isinstance(v, dict)],
        key=lambda x: risk_order.get(x[1], 0), reverse=True,
    )
    cols = 3
    while len(mod_risks) % cols != 0:
        mod_risks.append(("", ""))
    rows_data = []
    for i in range(0, len(mod_risks), cols):
        row = []
        for name, r in mod_risks[i:i+cols]:
            if not name:
                row.append(Paragraph("", styles["body"]))
            else:
                rc = RISK_COLOR.get(r, C_INFO)
                row.append(Paragraph(
                    f'<b>{name.upper()}</b>  <font color="{rc.hexval()}">{r.upper()}</font>',
                    styles["body"],
                ))
        rows_data.append(row)
    cw = COL_W / cols
    mt = Table(rows_data, colWidths=[cw] * cols)
    mt.setStyle(TableStyle([
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.white, C_BG_ROW_ALT]),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(mt)
    elems.append(_spacer(0.4))

    # All findings
    if findings:
        elems.append(Paragraph("All Findings", styles["h2"]))
        t = _findings_table(findings, styles)
        if t:
            elems.append(t)

    elems.append(PageBreak())
    return elems


def _build_whois(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("WHOIS", "🔍")]
    elems.append(_spacer(0.2))
    rows = [
        ("Registrar",    data.get("registrar") or "—"),
        ("Created",      data.get("creation_date") or "—"),
        ("Expires",      data.get("expiration_date") or "—"),
        ("Updated",      data.get("updated_date") or "—"),
        ("Registrant",   data.get("org") or "—"),
        ("Country",      data.get("registrant_country") or "—"),
        ("Name Servers", ", ".join(data.get("name_servers") or [])),
        ("DNSSEC",       data.get("dnssec") or "—"),
        ("Emails",       ", ".join(data.get("emails") or [])),
    ]
    elems.append(_kv_table(rows))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_dns(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("DNS RECORDS", "🌐")]
    elems.append(_spacer(0.2))
    records = data.get("records", {})
    rows = []
    for rtype, vals in records.items():
        for v in vals:
            rows.append((rtype, v))
    if rows:
        t = Table(rows, colWidths=[1.8 * cm, COL_W - 1.8 * cm])
        t.setStyle(TableStyle([
            ("FONTNAME",     (0, 0), (-1, -1), "Courier"),
            ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
            ("TOPPADDING",   (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
            ("TEXTCOLOR",    (0, 0), (0, -1),  C_TEXT_MUTED),
        ]))
        elems.append(t)
    if data.get("zone_transfer_vulnerable"):
        elems.append(_spacer(0.15))
        elems.append(Paragraph(
            '<font color="#ef4444"><b>⚠ Zone Transfer ENABLED — critical exposure</b></font>',
            styles["body"],
        ))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_dnssec(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("DNSSEC", "🔐")]
    elems.append(_spacer(0.2))
    rows = [
        ("Signed",       _check(data.get("signed"))),
        ("Validated",    _check(data.get("validated"))),
        ("DNSKEY",       _check(data.get("has_dnskey"))),
        ("DS Record",    _check(data.get("has_ds"))),
        ("RRSIG",        _check(data.get("has_rrsig"))),
        ("NSEC3",        _check(data.get("has_nsec3"))),
        ("AD Flag",      _check(data.get("ad_flag"))),
    ]
    elems.append(_kv_table(rows, col_w=(3 * cm, COL_W - 3 * cm)))
    elems.append(_spacer(0.3))
    return elems


def _build_ssl(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("SSL CERTIFICATE", "🔒")]
    elems.append(_spacer(0.2))
    if not data.get("has_ssl"):
        elems.append(Paragraph('<font color="#ef4444"><b>No SSL/TLS certificate found.</b></font>', styles["body"]))
        elems.append(_spacer(0.3))
        return elems
    subj = data.get("subject", {})
    issuer = data.get("issuer", {})
    rows = [
        ("Subject CN",   subj.get("CN") or subj.get("commonName") or "—"),
        ("Issuer",       issuer.get("O") or issuer.get("CN") or "—"),
        ("Valid From",   data.get("valid_from") or "—"),
        ("Valid To",     data.get("valid_to") or "—"),
        ("Days Left",    str(data.get("days_remaining") or "—")),
        ("Protocol",     data.get("protocol") or "—"),
        ("Cipher",       data.get("cipher") or "—"),
        ("Self-Signed",  _check(not data.get("self_signed", False))),
        ("Expired",      _check(not data.get("expired", False))),
    ]
    elems.append(_kv_table(rows))
    san = data.get("san", [])
    if san:
        elems.append(_spacer(0.15))
        san_str = ", ".join(_e(s) for s in san[:20]) + (" ..." if len(san) > 20 else "")
        elems.append(Paragraph(f"SANs ({len(san)}): " + san_str, styles["small"]))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_tls(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("TLS AUDIT", "🛡")]
    elems.append(_spacer(0.2))
    cipher = data.get("cipher") or {}
    hsts   = data.get("hsts")   or {}
    rows = [
        ("Protocol",     data.get("protocol") or "—"),
        ("Cipher",       cipher.get("name") or "—"),
        ("TLS 1.3",      _check(data.get("supports_tls13"))),
        ("TLS 1.2",      _check(data.get("supports_tls12"))),
        ("TLS 1.1",      "⚠ Enabled" if data.get("supports_tls11") else "Disabled"),
        ("TLS 1.0",      "⚠ Enabled" if data.get("supports_tls10") else "Disabled"),
        ("Weak Cipher",  "⚠ Yes" if data.get("weak_cipher") else "No"),
        ("HSTS",         _check(hsts.get("present"))),
        ("HSTS Preload", _check(hsts.get("preload"))),
    ]
    elems.append(_kv_table(rows))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_headers(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("HTTP SECURITY HEADERS", "📡")]
    elems.append(_spacer(0.2))
    rows = [
        ("URL",    data.get("url") or "—"),
        ("Status", str(data.get("status_code") or "—")),
        ("HTTPS Redirect", _check(data.get("redirects_to_https"))),
        ("Score",  str(data.get("score") or "—")),
    ]
    elems.append(_kv_table(rows))

    missing = data.get("headers_missing", [])
    if missing:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Missing Headers ({len(missing)})", styles["h2"]))
        hdr = [["Header", "Severity", "Recommended Value"]]
        for m in missing:
            sev_col = RISK_COLOR.get(m.get("severity", "low"), C_INFO)
            hdr.append([
                Paragraph(_e(m.get("header", "")), styles["mono"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{m.get("severity","").upper()}</font>', styles["small"]),
                Paragraph(_e(m.get("recommended", "")), styles["small"]),
            ])
        ht = Table(hdr, colWidths=[4 * cm, 1.8 * cm, COL_W - 5.8 * cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(ht)

    leaky = data.get("leaky_headers", {})
    if leaky:
        elems.append(_spacer(0.2))
        elems.append(Paragraph("Leaky Headers (information disclosure)", styles["h2"]))
        for k, v in leaky.items():
            elems.append(Paragraph(f"• <b>{_e(k)}</b>: {_e(v)}", styles["finding"]))

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_email(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("EMAIL SECURITY", "📧")]
    elems.append(_spacer(0.2))
    spf   = data.get("spf", {})
    dmarc = data.get("dmarc", {})
    dkim  = data.get("dkim", {})
    rows = [
        ("SPF",    ("✓ " + (spf.get("record") or "")) if spf.get("exists") else "✗ Not configured"),
        ("SPF Policy", spf.get("policy") or "—"),
        ("DMARC",  ("✓ " + (dmarc.get("record") or "")) if dmarc.get("exists") else "✗ Not configured"),
        ("DMARC Policy", dmarc.get("policy") or "—"),
        ("DKIM",   f"✓ {len(dkim.get('selectors_found',[]))} selector(s)" if dkim.get("exists") else "✗ Not found"),
        ("MTA-STS", _check((data.get("mta_sts") or {}).get("exists"))),
        ("BIMI",    _check((data.get("bimi") or {}).get("exists"))),
    ]
    elems.append(_kv_table(rows))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_tech(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("TECHNOLOGY FINGERPRINT", "⚙")]
    elems.append(_spacer(0.2))
    tech = data.get("technologies", [])
    rows = [
        ("Server",    data.get("server") or "—"),
        ("Powered By", data.get("powered_by") or "—"),
        ("Technologies", ", ".join(tech) if tech else "—"),
    ]
    elems.append(_kv_table(rows))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_subdomains(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("SUBDOMAINS", "🔎")]
    elems.append(_spacer(0.2))

    subs = data.get("subdomains", [])
    stats = [
        ("Total Found",       str(data.get("count", 0))),
        ("CRT.sh",            str(data.get("crt_sh_count", 0))),
        ("HackerTarget",      str(data.get("hackertarget_count", 0))),
        ("Passive Total",     str(data.get("passive_count", 0))),
        ("Brute-Force Hits",  str(data.get("brute_force_count", 0))),
    ]
    elems.append(_kv_table(stats, col_w=(3.5 * cm, COL_W - 3.5 * cm)))
    elems.append(_spacer(0.3))

    if subs:
        elems.append(Paragraph(f"All Discovered Subdomains ({len(subs)})", styles["h2"]))
        hdr = [["Subdomain", "IP(s)", "Status"]]
        for s in subs:
            ips = ", ".join(s.get("ips") or []) or "—"
            sensitive = s.get("sensitive", False)
            name = s.get("subdomain", "")
            if sensitive:
                name_p = Paragraph(f'<font color="#f97316"><b>{_e(name)} ⚠</b></font>', styles["mono"])
            else:
                name_p = Paragraph(_e(name), styles["mono"])
            status = s.get("status", "active")
            sc_col = C_LOW if status == "active" else C_TEXT_MUTED
            hdr.append([
                name_p,
                Paragraph(_e(ips), styles["small_mono"]),
                Paragraph(f'<font color="{sc_col.hexval()}">{_e(status)}</font>', styles["small"]),
            ])
        t = Table(hdr, colWidths=[6.5 * cm, 5.5 * cm, 2 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_ports(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("PORT SCAN", "🔌")]
    elems.append(_spacer(0.2))
    rows = [
        ("Target IP",   data.get("ip") or "—"),
        ("Open Ports",  str(data.get("total_open", 0))),
        ("Risky Ports", str(data.get("risky_ports", 0))),
    ]
    elems.append(_kv_table(rows))

    open_ports = data.get("open_ports", [])
    if open_ports:
        elems.append(_spacer(0.2))
        hdr = [["Port", "Service", "State", "Banner"]]
        for p in open_ports:
            risky = p.get("risky", False)
            port_str = str(p.get("port", ""))
            if risky:
                port_p = Paragraph(f'<font color="#f97316"><b>{port_str} ⚠</b></font>', styles["body_bold"])
            else:
                port_p = Paragraph(_e(port_str), styles["mono"])
            hdr.append([
                port_p,
                Paragraph(_e(p.get("service", "")), styles["small"]),
                Paragraph(_e(p.get("state", "")), styles["small"]),
                Paragraph(_e((p.get("banner") or "")[:60]), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[1.5 * cm, 3 * cm, 1.5 * cm, COL_W - 6 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_cors(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("CORS POLICY", "🌍")]
    elems.append(_spacer(0.2))
    rows = [
        ("Misconfigured",       "⚠ YES" if data.get("misconfigured") else "No"),
        ("Reflects Origin",     "⚠ YES" if data.get("reflected_origin") else "No"),
        ("Allows null origin",  "⚠ YES" if data.get("allows_null_origin") else "No"),
        ("Credentials+wildcard","⚠ YES" if data.get("allows_credentials_wildcard") else "No"),
    ]
    elems.append(_kv_table(rows))
    tests = data.get("cors_tests", [])
    if tests:
        elems.append(_spacer(0.2))
        hdr = [["Origin Tested", "ACAO", "Credentials", "Reflected"]]
        for test in tests:
            hdr.append([
                Paragraph(_e(test.get("tested_origin", "")), styles["small_mono"]),
                Paragraph(_e(test.get("acao") or "—"), styles["small_mono"]),
                Paragraph("Yes" if test.get("allow_credentials") else "No", styles["small"]),
                Paragraph("⚠ YES" if test.get("reflected") else "No", styles["small"]),
            ])
        t = Table(hdr, colWidths=[4.5 * cm, 4.5 * cm, 2 * cm, 2 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_cookies(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("COOKIE SECURITY", "🍪")]
    elems.append(_spacer(0.2))
    rows = [
        ("Total Cookies",       str(len(data.get("cookies", [])))),
        ("Insecure Cookies",    str(data.get("insecure_count", 0))),
        ("Missing Secure",      ", ".join(data.get("missing_secure", [])) or "None"),
        ("Missing HttpOnly",    ", ".join(data.get("missing_httponly", [])) or "None"),
        ("Missing SameSite",    ", ".join(data.get("missing_samesite", [])) or "None"),
    ]
    elems.append(_kv_table(rows))
    cookies = data.get("cookies", [])
    if cookies:
        elems.append(_spacer(0.2))
        hdr = [["Cookie Name", "Secure", "HttpOnly", "SameSite"]]
        for ck in cookies:
            hdr.append([
                Paragraph(_e(ck.get("name", "")), styles["mono"]),
                Paragraph(_check(ck.get("secure")), styles["small"]),
                Paragraph(_check(ck.get("httponly")), styles["small"]),
                Paragraph(_e(ck.get("samesite") or "—"), styles["small"]),
            ])
        t = Table(hdr, colWidths=[5 * cm, 2 * cm, 2 * cm, COL_W - 9 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("ALIGN",         (1, 1), (2, -1), "CENTER"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_waf(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("WAF / CDN DETECTION", "🛡")]
    elems.append(_spacer(0.2))
    rows = [
        ("WAF Detected",  "Yes — " + ", ".join(data.get("waf_names", [])) if data.get("waf_found") else "None detected"),
        ("CDN Detected",  "Yes — " + ", ".join(data.get("cdn_names", [])) if data.get("cdn_found") else "None detected"),
        ("Server Headers", ", ".join(data.get("server_names", [])) or "—"),
    ]
    elems.append(_kv_table(rows))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_robots(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("ROBOTS.TXT / SITEMAP", "🤖")]
    elems.append(_spacer(0.2))
    rows = [
        ("robots.txt",        "Found" if data.get("robots_found") else "Not found"),
        ("Disallowed paths",  str(len(data.get("robots_disallowed", [])))),
        ("Sensitive in robots",  ", ".join(data.get("sensitive_in_robots", [])) or "None"),
        ("Sitemap",           "Found" if data.get("sitemap_found") else "Not found"),
        ("Sitemap URLs",      str(data.get("sitemap_url_count", 0))),
        ("Sensitive in sitemap", ", ".join(data.get("sensitive_in_sitemap", [])) or "None"),
    ]
    elems.append(_kv_table(rows))
    disallowed = data.get("robots_disallowed", [])
    if disallowed:
        elems.append(_spacer(0.15))
        elems.append(Paragraph(
            "Disallowed: " + " · ".join(_e(p) for p in disallowed[:30]) + (" + more" if len(disallowed) > 30 else ""),
            styles["small"],
        ))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_admin(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("ADMIN PATH DISCOVERY", "🚪")]
    elems.append(_spacer(0.2))
    rows = [
        ("Paths Probed",  str(data.get("paths_probed", 0))),
        ("Found",         str(data.get("found_count", 0))),
        ("Critical",      str(data.get("critical_count", 0))),
        ("High",          str(data.get("high_count", 0))),
    ]
    elems.append(_kv_table(rows))
    found = data.get("found", [])
    if found:
        elems.append(_spacer(0.2))
        hdr = [["Path", "Status", "Severity", "Content-Type"]]
        for p in found:
            sev = p.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(p.get("path", "")), styles["mono"]),
                Paragraph(_e(str(p.get("status", ""))), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_e(p.get("content_type", "")), styles["small"]),
            ])
        t = Table(hdr, colWidths=[5.5 * cm, 1.5 * cm, 2 * cm, COL_W - 9 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_frontend_cve(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("FRONTEND LIBRARY CVEs", "📦")]
    elems.append(_spacer(0.2))
    rows = [
        ("Libraries Detected", str(data.get("detected_count", 0))),
        ("Total CVEs",         str(data.get("cve_count", 0))),
        ("Critical",           str(data.get("critical_count", 0))),
        ("High",               str(data.get("high_count", 0))),
    ]
    elems.append(_kv_table(rows))
    detected = data.get("detected", [])
    if detected:
        elems.append(_spacer(0.15))
        elems.append(Paragraph("Detected Libraries:", styles["body_bold"]))
        lib_rows = [["Library", "Version", "CVEs"]]
        for lib in detected:
            vc = lib.get("vuln_count", 0)
            vc_text = f'<font color="{RISK_COLOR["critical"].hexval()}">{vc}</font>' if vc > 0 else str(vc)
            lib_rows.append([
                Paragraph(_e(lib.get("name", "")), styles["mono"]),
                Paragraph(_e(lib.get("version", "unknown")), styles["small"]),
                Paragraph(vc_text, styles["small"]),
            ])
        t = Table(lib_rows, colWidths=[6 * cm, 4 * cm, COL_W - 10 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    vulns = data.get("vulnerabilities", [])
    if vulns:
        elems.append(_spacer(0.2))
        elems.append(Paragraph("CVE Findings:", styles["body_bold"]))
        hdr = [["CVE", "Library", "Severity", "Summary"]]
        for v in vulns:
            sev     = v.get("severity", "unknown")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            fixed   = ", ".join(v.get("fixed_versions", []))
            summary = _e(v.get("summary", ""))
            if fixed:
                summary += f" (fix: {_e(fixed)})"
            hdr.append([
                Paragraph(_e(v.get("cve", "?")), styles["mono"]),
                Paragraph(
                    f'{_e(v.get("library", ""))} {_e(v.get("detected_version", ""))}',
                    styles["small"],
                ),
                Paragraph(
                    f'<font color="{sev_col.hexval()}">{sev.upper()}</font>',
                    styles["small"],
                ),
                Paragraph(summary, styles["small"]),
            ])
        t = Table(hdr, colWidths=[2.8 * cm, 3.5 * cm, 2 * cm, COL_W - 8.3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_js_secrets(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("JS SECRETS SCAN", "🔑")]
    elems.append(_spacer(0.2))
    rows = [
        ("JS Files Scanned", str(len(data.get("js_files_scanned", [])))),
        ("Secrets Found",    str(data.get("secret_count", 0))),
    ]
    by_sev = data.get("by_severity", {})
    for sev, cnt in sorted(by_sev.items(), key=lambda x: ["critical","high","medium","low"].index(x[0]) if x[0] in ["critical","high","medium","low"] else 99):
        rows.append((f"  {sev.capitalize()}", str(cnt)))
    elems.append(_kv_table(rows))
    secrets = data.get("secrets_found", [])
    if secrets:
        elems.append(_spacer(0.2))
        hdr = [["Type", "Severity", "File", "Snippet"]]
        for s in secrets:
            sev = s.get("severity", "low")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(s.get("type", "")), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_e(s.get("file", "")[-40:]), styles["small_mono"]),
                Paragraph(_e(s.get("snippet", "")[:60]), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[3 * cm, 1.8 * cm, 4 * cm, COL_W - 8.8 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_exposed(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("EXPOSED FILES", "📂")]
    elems.append(_spacer(0.2))
    rows = [
        ("Total Exposed",   str(data.get("total", 0))),
        ("Critical",        str(data.get("critical_count", 0))),
        ("High",            str(data.get("high_count", 0))),
        ("security.txt",    _check(data.get("has_security_txt"))),
    ]
    elems.append(_kv_table(rows))
    exposed = data.get("exposed", [])
    if exposed:
        elems.append(_spacer(0.2))
        hdr = [["Path", "Status", "Severity", "Description"]]
        for e in exposed:
            sev = e.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(e.get("path", "")), styles["mono"]),
                Paragraph(_e(str(e.get("status", ""))), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_e(e.get("description", "")), styles["small"]),
            ])
        t = Table(hdr, colWidths=[5 * cm, 1.5 * cm, 2 * cm, COL_W - 8.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_breach(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("BREACH & REPUTATION", "💀")]
    elems.append(_spacer(0.2))
    rows = [
        ("Breaches Found",   str(data.get("breach_count", 0))),
        ("Combo Lists",       str(data.get("combo_count", 0))),
        ("Exposed Emails",    str(len(data.get("all_emails", [])))),
    ]
    leakcheck = data.get("leakcheck", {})
    if leakcheck.get("checked"):
        rows.append(("LeakCheck sources", str(leakcheck.get("found", 0))))
    hunter = data.get("hunter", {})
    if hunter.get("checked"):
        rows.append(("Hunter.io emails", str(hunter.get("total", 0))))
    elems.append(_kv_table(rows))

    breaches = data.get("breaches", [])
    if breaches:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Known Breaches ({len(breaches)})", styles["h2"]))
        hdr = [["Breach", "Date", "Records", "Data Types"]]
        for b in breaches:
            hdr.append([
                Paragraph(_e(b.get("title") or b.get("name", "")), styles["small"]),
                Paragraph(_e(b.get("breach_date", "")), styles["small"]),
                Paragraph(f"{b.get('pwn_count',0):,}", styles["small"]),
                Paragraph(_e(", ".join(b.get("data_classes", []))[:60]), styles["small"]),
            ])
        t = Table(hdr, colWidths=[3.5 * cm, 2.5 * cm, 2 * cm, COL_W - 8 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    emails = data.get("all_emails", [])
    if emails:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Exposed Email Addresses ({len(emails)})", styles["h2"]))
        # Render in 2 columns
        half = (len(emails) + 1) // 2
        col1 = emails[:half]
        col2 = emails[half:]
        grid = []
        for i in range(max(len(col1), len(col2))):
            e1 = col1[i] if i < len(col1) else ""
            e2 = col2[i] if i < len(col2) else ""
            grid.append([
                Paragraph(_e(e1), styles["small_mono"]),
                Paragraph(_e(e2), styles["small_mono"]),
            ])
        et = Table(grid, colWidths=[COL_W / 2, COL_W / 2])
        et.setStyle(TableStyle([
            ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
            ("TOPPADDING",   (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ]))
        elems.append(et)

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_blacklist(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("IP REPUTATION / BLACKLIST", "⛔")]
    elems.append(_spacer(0.2))
    rows = [
        ("IP Address",       data.get("ip") or "—"),
        ("All IPs",          ", ".join(data.get("all_ips", [])) or "—"),
        ("DNSBLs Checked",   str(data.get("dnsbl_count", 0))),
        ("Listed On",        str(data.get("listing_count", 0))),
        ("Clean",            _check(data.get("clean"))),
        ("Spamhaus",         "⚠ LISTED" if data.get("spamhaus_listed") else "Clean"),
        ("Barracuda",        "⚠ LISTED" if data.get("barracuda_listed") else "Clean"),
    ]
    urlhaus = data.get("urlhaus", {})
    if urlhaus.get("checked"):
        rows.append(("URLHaus", f"Found {urlhaus.get('url_count',0)} URL(s)" if urlhaus.get("found") else "Clean"))
    elems.append(_kv_table(rows))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_secret_verification(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("SECRET VERIFICATION", "✅")]
    elems.append(_spacer(0.2))
    verified = data.get("verified", [])
    jwt_analysis = data.get("jwt_analysis", [])
    rows = [
        ("Status",          data.get("status") or "—"),
        ("Keys Verified",   str(len(verified))),
        ("Valid Keys",      str(data.get("valid_count", 0))),
        ("JWTs Analyzed",   str(len(jwt_analysis))),
    ]
    elems.append(_kv_table(rows))

    if verified:
        elems.append(_spacer(0.2))
        hdr = [["Type", "Key", "Host", "Verdict", "Evidence"]]
        for v in verified:
            verdict = v.get("verdict", "unknown")
            v_col = {"valid": C_CRITICAL, "invalid": C_LOW}.get(verdict, C_TEXT_MUTED)
            hdr.append([
                Paragraph(_e(v.get("type", "")), styles["small"]),
                Paragraph(_e(v.get("key", "")), styles["small_mono"]),
                Paragraph(_e(v.get("host", "")), styles["small_mono"]),
                Paragraph(f'<font color="{v_col.hexval()}"><b>{verdict.upper()}</b></font>', styles["small"]),
                Paragraph(_e(v.get("evidence", "")), styles["small"]),
            ])
        t = Table(hdr, colWidths=[3 * cm, 2.2 * cm, 3.5 * cm, 1.8 * cm, COL_W - 10.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    if jwt_analysis:
        elems.append(_spacer(0.2))
        elems.append(Paragraph("JWT Analysis", styles["h2"]))
        hdr = [["Token", "Alg", "Issuer", "Issues"]]
        for j in jwt_analysis:
            issues = j.get("issues", [])
            hdr.append([
                Paragraph(_e(j.get("key", "")), styles["small_mono"]),
                Paragraph(_e(j.get("alg") or "—"), styles["small"]),
                Paragraph(_e((j.get("iss") or "—")[:40]), styles["small"]),
                Paragraph(
                    f'<font color="{C_HIGH.hexval()}">{_e("; ".join(issues))}</font>' if issues
                    else "None",
                    styles["small"],
                ),
            ])
        t = Table(hdr, colWidths=[2.5 * cm, 1.5 * cm, 4 * cm, COL_W - 8 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_cloud_storage(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("CLOUD STORAGE EXPOSURE", "☁")]
    elems.append(_spacer(0.2))
    rows = [
        ("Candidates Checked",       str(data.get("candidates_checked", 0))),
        ("Endpoints Probed",         str(data.get("endpoints_probed", 0))),
        ("Exposed Buckets",          str(data.get("exposed_count", 0))),
        ("Existing Private Buckets", str(data.get("existing_private", 0))),
    ]
    elems.append(_kv_table(rows))
    exposed = data.get("exposed", [])
    if exposed:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Exposed Buckets ({len(exposed)})", styles["h2"]))
        hdr = [["Name", "Provider", "Status", "Severity", "URL"]]
        for b in exposed:
            sev = b.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(b.get("name", "")), styles["mono"]),
                Paragraph(_e(b.get("provider", "")).upper(), styles["small"]),
                Paragraph(_e(str(b.get("status", ""))), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_e(b.get("url", "")), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[3.5 * cm, 2 * cm, 1.5 * cm, 2 * cm, COL_W - 9 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    private_list = data.get("existing_private_list") or []
    if private_list:
        elems.append(_spacer(0.15))
        names = ", ".join(_e(p.get("name", "")) for p in private_list[:20])
        elems.append(Paragraph(f"Private buckets found (not publicly accessible): {names}", styles["small"]))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_api_exposure(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("API EXPOSURE", "🔗")]
    elems.append(_spacer(0.2))
    rows = [
        ("Paths Checked",         str(data.get("paths_checked", 0))),
        ("Endpoints Found",       str(data.get("found_count", 0))),
        ("Swagger/OpenAPI",       "⚠ Found" if data.get("swagger_found") else "Not found"),
        ("GraphQL",               "⚠ Found" if data.get("graphql_found") else "Not found"),
        ("GraphQL Introspection", "⚠ Enabled" if data.get("has_graphql_introspection") else "Disabled/N/A"),
    ]
    elems.append(_kv_table(rows))
    found = data.get("found", [])
    if found:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Discovered Endpoints ({len(found)})", styles["h2"]))
        hdr = [["Path", "Label", "Status", "Severity"]]
        for e in found:
            sev = e.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(e.get("path", "")), styles["mono"]),
                Paragraph(_e(e.get("label", "")), styles["small"]),
                Paragraph(_e(str(e.get("status", ""))), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
            ])
        t = Table(hdr, colWidths=[6 * cm, 4 * cm, 2 * cm, COL_W - 12 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    repos = data.get("github_repos") or []
    if repos:
        elems.append(_spacer(0.15))
        elems.append(Paragraph("GitHub Repositories Found:", styles["body_bold"]))
        for r in repos[:10]:
            elems.append(Paragraph(f"• {_e(r.get('name',''))} — {_e(r.get('url',''))}", styles["finding"]))
    postman = (data.get("postman_collections") or []) + (data.get("postman_workspaces") or [])
    if postman:
        elems.append(_spacer(0.15))
        elems.append(Paragraph("Postman Collections/Workspaces Found:", styles["body_bold"]))
        for p in postman[:10]:
            elems.append(Paragraph(f"• {_e(p.get('name',''))} — {_e(p.get('url',''))}", styles["finding"]))
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_wayback(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("WAYBACK MACHINE — HISTORICAL EXPOSURE", "🕰")]
    elems.append(_spacer(0.2))
    rows = [
        ("URLs Indexed",      str(data.get("urls_indexed", 0))),
        ("Snapshots Fetched", str(data.get("snapshots_fetched", 0))),
        ("Sensitive URLs",    str(data.get("sensitive_count", 0))),
        ("Secrets Found",     str(data.get("secret_count", 0))),
    ]
    elems.append(_kv_table(rows))
    sensitive = data.get("sensitive_urls", [])
    if sensitive:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Sensitive Archived URLs ({len(sensitive)})", styles["h2"]))
        hdr = [["URL", "Timestamp", "Label", "Severity"]]
        for u in sensitive:
            sev = u.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(u.get("url", "")), styles["small_mono"]),
                Paragraph(_e(u.get("timestamp", "")), styles["small"]),
                Paragraph(_e(u.get("label", "")), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
            ])
        t = Table(hdr, colWidths=[COL_W - 8.5 * cm, 2.5 * cm, 3 * cm, 2 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    secrets = data.get("secrets_found", [])
    if secrets:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Secrets Found in Archived Pages ({len(secrets)})", styles["h2"]))
        hdr = [["Type", "Severity", "URL", "Snippet"]]
        for s in secrets:
            sev = s.get("severity", "low")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(s.get("secret_type", "")), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_e(s.get("url", "")), styles["small_mono"]),
                Paragraph(_e(s.get("snippet", "")[:60]), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[2.5 * cm, 1.8 * cm, 5 * cm, COL_W - 9.3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_nuclei(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("NUCLEI VULNERABILITY SCAN", "🎯")]
    elems.append(_spacer(0.2))
    by_sev = data.get("by_severity", {})
    rows = [("Total Findings", str(data.get("findings_count", 0)))]
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in by_sev:
            rows.append((f"  {sev.capitalize()}", str(by_sev[sev])))
    elems.append(_kv_table(rows))
    detail = data.get("findings_detail", [])
    if detail:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Template Matches ({len(detail)})", styles["h2"]))
        hdr = [["Template", "Severity", "CVE(s)", "Matched At"]]
        for n in detail:
            sev = n.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            cves = ", ".join(n.get("cve_ids") or []) or "—"
            hdr.append([
                Paragraph(_e(n.get("name") or n.get("template_id", "")), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_e(cves), styles["small_mono"]),
                Paragraph(_e(n.get("matched_at", "")), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[5 * cm, 1.8 * cm, 3 * cm, COL_W - 9.8 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_mobile_apps(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("MOBILE APPS DISCOVERY", "📱")]
    elems.append(_spacer(0.2))
    apps = data.get("apps", [])
    suspicious = data.get("suspicious", [])
    rows = [
        ("Brand",           data.get("brand") or "—"),
        ("Confirmed Apps",  str(len(apps))),
        ("Suspicious Apps", str(len(suspicious))),
    ]
    elems.append(_kv_table(rows))

    if apps:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Confirmed Apps ({len(apps)})", styles["h2"]))
        hdr = [["Name", "Store", "OS", "Version", "Developer", "Updated"]]
        for a in apps:
            hdr.append([
                Paragraph(_e(a.get("name", "")), styles["small"]),
                Paragraph(_e(a.get("store", "")), styles["small"]),
                Paragraph(_e(a.get("os", "")), styles["small"]),
                Paragraph(_e(a.get("version") or "—"), styles["small"]),
                Paragraph(_e(a.get("developer") or "—"), styles["small"]),
                Paragraph(_e(a.get("updated") or "—"), styles["small"]),
            ])
        t = Table(hdr, colWidths=[4 * cm, 2.2 * cm, 1.5 * cm, 2 * cm, 4 * cm, COL_W - 13.7 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    if suspicious:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Suspicious / Unverified Apps ({len(suspicious)})", styles["h2"]))
        hdr = [["Name", "Store", "Developer", "LLM Verdict"]]
        for a in suspicious:
            verdict = a.get("llm_verdict") or "unknown"
            v_col = {"suspicious": C_CRITICAL, "unrelated": C_TEXT_MUTED, "official": C_LOW}.get(verdict, C_TEXT_MUTED)
            hdr.append([
                Paragraph(_e(a.get("name", "")), styles["small"]),
                Paragraph(_e(a.get("store", "")), styles["small"]),
                Paragraph(_e(a.get("developer") or "—"), styles["small"]),
                Paragraph(f'<font color="{v_col.hexval()}">{_e(verdict.upper())}</font>', styles["small"]),
            ])
        t = Table(hdr, colWidths=[5 * cm, 2.5 * cm, 5 * cm, COL_W - 12.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_reverse_ip(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("REVERSE IP / SHARED HOSTING", "🧭")]
    elems.append(_spacer(0.2))
    ips_checked = data.get("ips_checked", [])
    attributed  = data.get("attributed", [])
    neighbors   = data.get("neighbors", [])
    rows = [
        ("IPs Checked",         str(len(ips_checked))),
        ("Shared Hosting Risk", "⚠ YES" if data.get("shared_hosting_risk") else "No"),
        ("Attributed Hosts",    str(len(attributed))),
        ("Neighbor Domains",    str(len(neighbors))),
    ]
    elems.append(_kv_table(rows))

    if ips_checked:
        elems.append(_spacer(0.2))
        elems.append(Paragraph("IP Lookups", styles["h2"]))
        hdr = [["IP", "CDN", "Skipped", "Note"]]
        for ip in ips_checked:
            hdr.append([
                Paragraph(_e(ip.get("ip", "")), styles["mono"]),
                Paragraph(_e(ip.get("cdn") or "—"), styles["small"]),
                Paragraph(_check(ip.get("skipped")), styles["small"]),
                Paragraph(_e(ip.get("note") or "—"), styles["small"]),
            ])
        t = Table(hdr, colWidths=[3.5 * cm, 3 * cm, 2 * cm, COL_W - 8.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    if attributed:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Attributed Hosts ({len(attributed)})", styles["h2"]))
        hdr = [["Domain", "IP", "Kind"]]
        for a in attributed[:30]:
            hdr.append([
                Paragraph(_e(a.get("domain", "")), styles["mono"]),
                Paragraph(_e(a.get("ip", "")), styles["small_mono"]),
                Paragraph(_e(a.get("kind", "")), styles["small"]),
            ])
        t = Table(hdr, colWidths=[COL_W - 8 * cm, 4 * cm, 4 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
        if len(attributed) > 30:
            elems.append(_spacer(0.1))
            elems.append(Paragraph(_e(f"+ {len(attributed) - 30} more."), styles["small"]))

    if neighbors:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Neighbor Domains — Shared Hosting ({len(neighbors)})", styles["h2"]))
        hdr = [["Domain", "IP"]]
        for n in neighbors[:30]:
            hdr.append([
                Paragraph(_e(n.get("domain", "")), styles["mono"]),
                Paragraph(_e(n.get("ip", "")), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[COL_W - 5 * cm, 5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
        if len(neighbors) > 30:
            elems.append(_spacer(0.1))
            elems.append(Paragraph(_e(f"+ {len(neighbors) - 30} more."), styles["small"]))

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_subdomain_eval(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("CHAINED SUBDOMAIN EVALUATION", "🧬")]
    elems.append(_spacer(0.2))

    if data.get("status") == "skipped":
        elems.append(Paragraph(_e(data.get("reason") or "Skipped — no new subdomains to evaluate."), styles["body"]))
        elems.append(_spacer(0.3))
        return elems

    evaluated = data.get("evaluated", [])
    rows = [
        ("Newly Evaluated", str(data.get("evaluated_count", 0))),
        ("Alive",            str(data.get("alive_count", 0))),
    ]
    elems.append(_kv_table(rows))

    if evaluated:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Evaluated Subdomains ({len(evaluated)})", styles["h2"]))
        hdr = [["Subdomain", "Alive", "HTTP", "Risk", "Note"]]
        for e in evaluated:
            risk = e.get("risk", "low")
            risk_col = RISK_COLOR.get(risk, C_INFO)
            hdr.append([
                Paragraph(_e(e.get("subdomain", "")), styles["mono"]),
                Paragraph(_check(e.get("alive")), styles["small"]),
                Paragraph(_e(e.get("http_status") if e.get("http_status") is not None else "—"), styles["small"]),
                Paragraph(f'<font color="{risk_col.hexval()}">{risk.upper()}</font>', styles["small"]),
                Paragraph(_e(e.get("note") or "—"), styles["small"]),
            ])
        t = Table(hdr, colWidths=[5.5 * cm, 1.5 * cm, 1.5 * cm, 2 * cm, COL_W - 10.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    sv = data.get("secret_verification")
    if sv:
        elems.append(_spacer(0.2))
        elems.append(Paragraph("Secret Verification (from new subdomains)", styles["h2"]))
        elems.append(_kv_table([
            ("Keys Verified", str(len(sv.get("verified", [])))),
            ("Valid Keys",    str(sv.get("valid_count", 0))),
        ], col_w=(3.5 * cm, COL_W - 3.5 * cm)))
        for v in sv.get("verified", []):
            verdict = v.get("verdict", "unknown")
            v_col = {"valid": C_CRITICAL, "invalid": C_LOW}.get(verdict, C_TEXT_MUTED)
            elems.append(Paragraph(
                f'• {_e(v.get("type",""))} on {_e(v.get("host",""))} — '
                f'<font color="{v_col.hexval()}"><b>{_e(verdict.upper())}</b></font> — {_e(v.get("evidence",""))}',
                styles["finding"],
            ))

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_smart_fuzz(data: dict, styles: dict) -> list:
    if not data:
        return []
    elems: list = [_section_header("SMART PATH FUZZING", "🧵")]
    elems.append(_spacer(0.2))
    paths = data.get("paths_found", [])
    rows = [
        ("Wordlists Used", ", ".join(data.get("wordlist_used", [])) or "—"),
        ("Requests Made",  str(data.get("requests_made", 0))),
        ("Paths Found",    str(len(paths))),
        ("WAF Blocked",    "⚠ YES" if data.get("waf_blocked") else "No"),
    ]
    if "directed_count" in data:
        rows.append(("LLM-Directed Probes", str(data.get("directed_count", 0))))
    elems.append(_kv_table(rows))

    if paths:
        elems.append(_spacer(0.2))
        elems.append(Paragraph(f"Discovered Paths ({len(paths)})", styles["h2"]))
        hdr = [["Path", "Status", "Severity", "Directed", "Evidence"]]
        for p in paths:
            sev = p.get("severity", "info")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            hdr.append([
                Paragraph(_e(p.get("path", "")), styles["mono"]),
                Paragraph(_e(str(p.get("status", ""))), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
                Paragraph(_check(p.get("directed")), styles["small"]),
                Paragraph(_e((p.get("evidence") or "—")[:60]), styles["small_mono"]),
            ])
        t = Table(hdr, colWidths=[4.5 * cm, 1.5 * cm, 2 * cm, 1.8 * cm, COL_W - 9.8 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)

    for f in data.get("findings", []):
        elems.append(Paragraph(f"• {_e(f)}", styles["finding"]))
    elems.append(_spacer(0.3))
    return elems


def _build_ai_summary(report: dict, styles: dict) -> list:
    ai = report.get("ai_summary") or {}
    if ai.get("status") != "ok":
        return []
    elems: list = [_section_header("AI EXECUTIVE SUMMARY", "🤖")]
    elems.append(_spacer(0.2))

    summary = ai.get("executive_summary") or ""
    if summary:
        for line in summary.splitlines():
            line = line.strip()
            if not line:
                elems.append(_spacer(0.15))
            elif line.startswith("#"):
                elems.append(Paragraph(_e(line.lstrip("#").strip()), styles["h2"]))
            elif line.startswith(("- ", "* ")):
                elems.append(Paragraph(f"• {_e(line[2:].strip())}", styles["finding"]))
            else:
                elems.append(Paragraph(_e(line), styles["body"]))
        elems.append(_spacer(0.2))

    scenarios = ai.get("attack_scenarios") or []
    if scenarios:
        elems.append(Paragraph("Attack Scenarios", styles["h2"]))
        for s in scenarios:
            elems.append(Paragraph(f"• {_e(s)}", styles["finding"]))
        elems.append(_spacer(0.2))

    plan = ai.get("remediation_plan") or []
    if plan:
        elems.append(Paragraph("Remediation Plan", styles["h2"]))
        hdr = [["Action", "Effort", "Impact"]]
        for item in plan:
            if not isinstance(item, dict):
                continue
            effort = (item.get("effort") or "").lower()
            impact = (item.get("impact") or "").lower()
            hdr.append([
                Paragraph(_e(item.get("action", "")), styles["small"]),
                Paragraph(_e(effort.upper() or "—"), styles["small"]),
                Paragraph(
                    f'<font color="{RISK_COLOR.get(impact, C_INFO).hexval()}"><b>{_e(impact.upper() or "—")}</b></font>',
                    styles["small"],
                ),
            ])
        if len(hdr) > 1:
            t = Table(hdr, colWidths=[COL_W - 4.5 * cm, 2.2 * cm, 2.3 * cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
                ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(t)
    elems.append(_spacer(0.3))
    return elems


# ─── Master Builder ───────────────────────────────────────────────────────────

def generate_pdf(report: dict) -> bytes:
    """
    Build a complete PDF report from a scan result dict.
    Returns the PDF as bytes.
    """
    buf    = io.BytesIO()
    domain = report.get("domain", "unknown")
    styles = _build_styles()

    # ── Document with two page templates ──
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN_L,
        rightMargin=MARGIN_R,
        topMargin=MARGIN_T + 30,   # extra top for header band on content pages
        bottomMargin=MARGIN_B + 22, # extra bottom for footer band
        title=f"Security Assessment — {domain}",
        author="Sauron",
        subject="Automated ASM Report",
    )
    doc._report_domain = domain

    cover_frame   = Frame(0, 0, PAGE_W, PAGE_H, id="cover")
    content_frame = Frame(MARGIN_L, MARGIN_B + 22, COL_W, PAGE_H - MARGIN_T - MARGIN_B - 52, id="content")

    doc.addPageTemplates([
        PageTemplate(id="cover",   frames=[cover_frame],   onPage=_cover_page_bg),
        PageTemplate(id="content", frames=[content_frame], onPage=_content_page_bg),
    ])

    mods = report.get("modules", {})
    story: list = []

    # Cover (uses cover template)
    story.extend(_build_cover(domain, report, styles))

    # Switch to content template
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # Executive Summary
    story.extend(_build_executive_summary(report, styles))

    # AI Executive Summary (only when the AI layer produced one)
    _safe_extend(story, "ai_summary", _build_ai_summary, report, styles)

    # ── Infrastructure & DNS ──
    _safe_extend(story, "whois",      _build_whois,      mods.get("whois") or {}, styles)
    _safe_extend(story, "dns",        _build_dns,        mods.get("dns") or {}, styles)
    _safe_extend(story, "dnssec",     _build_dnssec,     mods.get("dnssec") or {}, styles)
    _safe_extend(story, "subdomains", _build_subdomains, mods.get("subdomains") or {}, styles)

    # ── TLS / SSL ──
    _safe_extend(story, "ssl",        _build_ssl,        mods.get("ssl") or {}, styles)
    _safe_extend(story, "tls",        _build_tls,        mods.get("tls") or {}, styles)

    # ── HTTP Security ──
    _safe_extend(story, "headers",    _build_headers,    mods.get("headers") or {}, styles)
    _safe_extend(story, "cors",       _build_cors,       mods.get("cors") or {}, styles)
    _safe_extend(story, "cookies",    _build_cookies,    mods.get("cookies") or {}, styles)
    _safe_extend(story, "waf",        _build_waf,        mods.get("waf") or {}, styles)

    # ── Recon ──
    _safe_extend(story, "email",      _build_email,      mods.get("email") or {}, styles)
    _safe_extend(story, "tech",       _build_tech,       mods.get("tech") or {}, styles)
    _safe_extend(story, "robots",     _build_robots,     mods.get("robots") or {}, styles)

    # ── Digital Footprint ──
    _safe_extend(story, "mobile_apps", _build_mobile_apps, mods.get("mobile_apps") or {}, styles)
    _safe_extend(story, "reverse_ip",  _build_reverse_ip,  mods.get("reverse_ip") or {}, styles)

    # ── Attack Surface ──
    _safe_extend(story, "admin",        _build_admin,        mods.get("admin") or {}, styles)
    _safe_extend(story, "frontend_cve", _build_frontend_cve, mods.get("frontend_cve") or {}, styles)
    _safe_extend(story, "js_secrets",   _build_js_secrets,   mods.get("js_secrets") or {}, styles)
    _safe_extend(story, "secret_verification", _build_secret_verification, mods.get("secret_verification") or {}, styles)
    _safe_extend(story, "exposed",    _build_exposed,    mods.get("exposed") or {}, styles)
    _safe_extend(story, "ports",      _build_ports,      mods.get("ports") or {}, styles)
    _safe_extend(story, "cloud_storage",  _build_cloud_storage,  mods.get("cloud_storage") or {}, styles)
    _safe_extend(story, "api_exposure",   _build_api_exposure,   mods.get("api_exposure") or {}, styles)
    _safe_extend(story, "smart_fuzz",     _build_smart_fuzz,     mods.get("smart_fuzz") or {}, styles)
    _safe_extend(story, "subdomain_eval", _build_subdomain_eval, mods.get("subdomain_eval") or {}, styles)

    # ── Vulnerability Scanning ──
    _safe_extend(story, "nuclei",      _build_nuclei,      mods.get("nuclei") or {}, styles)

    # ── Reputation / Threat Intel ──
    _safe_extend(story, "breach",     _build_breach,     mods.get("breach") or {}, styles)
    _safe_extend(story, "blacklist",  _build_blacklist,  mods.get("blacklist") or {}, styles)
    _safe_extend(story, "wayback",    _build_wayback,    mods.get("wayback") or {}, styles)

    # Pre-validate all Paragraphs so we get a useful error message if XML is broken
    import xml.etree.ElementTree as _ET
    for idx, elem in enumerate(story):
        if hasattr(elem, "text") and hasattr(elem, "style"):
            raw = getattr(elem, "text", "") or ""
            try:
                _ET.fromstring(f"<root>{raw}</root>")
            except _ET.ParseError as xml_err:
                raise RuntimeError(
                    f"PDF build aborted — invalid XML in Paragraph at story[{idx}]: "
                    f"{raw[:120]!r} — {xml_err}"
                ) from xml_err

    doc.build(story)
    return buf.getvalue()


def _safe_extend(story: list, builder_name: str, builder_fn, *args) -> None:
    """Call a section builder and extend story; raises with section name on failure."""
    import logging as _logging
    try:
        story.extend(builder_fn(*args))
    except Exception as exc:
        _logging.getLogger(__name__).error(f"PDF section '{builder_name}' failed: {exc}")
        raise RuntimeError(f"PDF section '{builder_name}' failed: {exc}") from exc


# ─── Consolidated Company Report ──────────────────────────────────────────────

_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _fmt_scan_date(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%b %d, %Y %H:%M UTC")
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %H:%M UTC")
    except Exception:
        return str(value)


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        r = (f.get("risk") or "low").lower()
        if r in counts:
            counts[r] += 1
    return counts


def _build_company_cover(
    company_name: str,
    domains_data: list[dict],
    totals: dict[str, int],
    styles: dict,
) -> list:
    """Cover page for the consolidated company report."""
    scanned = [d for d in domains_data if d.get("scan_id")]
    scores = [d.get("score") for d in scanned if isinstance(d.get("score"), (int, float))]
    avg_score = round(sum(scores) / len(scores)) if scores else 0
    grade = _grade_for_score(avg_score) if scores else "?"
    risk = "low"
    for d in scanned:
        r = (d.get("overall_risk") or "low").lower()
        if _RISK_ORDER.get(r, 9) < _RISK_ORDER.get(risk, 9):
            risk = r
    total_findings = sum(totals.values())
    date_str = datetime.now().strftime("%B %d, %Y  %H:%M UTC")

    elems: list = []
    elems.append(Spacer(1, 4.2 * cm))

    elems.append(Paragraph(
        '<font color="#10b981">SAURON</font>',
        ParagraphStyle("brand", fontName="Helvetica-Bold", fontSize=13,
                       textColor=C_CYBER, alignment=TA_CENTER, leading=18,
                       letterSpacing=4),
    ))
    elems.append(_spacer(0.5))

    elems.append(Paragraph("Consolidated Security Report", styles["cover_title"]))
    elems.append(_spacer(0.6))

    elems.append(Paragraph(
        f'<font color="#10b981">{_e(company_name)}</font>',
        ParagraphStyle("company", fontName="Helvetica-Bold", fontSize=18,
                       textColor=C_CYBER, alignment=TA_CENTER, leading=24),
    ))
    elems.append(_spacer(1.2))

    circle = ScoreCircle(avg_score, grade, risk, size=4.5 * cm)
    t = Table([[circle]], colWidths=[COL_W])
    t.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    elems.append(t)
    elems.append(_spacer(0.3))

    elems.append(Paragraph(
        '<font color="#94a3b8">Average score across scanned domains</font>',
        ParagraphStyle("avg", fontName="Helvetica", fontSize=8,
                       textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER, leading=12),
    ))
    elems.append(_spacer(0.3))

    risk_col = RISK_COLOR.get(risk, C_INFO)
    elems.append(Paragraph(
        f'<font color="{risk_col.hexval()}"><b>Worst Domain Risk: {risk.upper()}</b></font>',
        ParagraphStyle("or", fontName="Helvetica-Bold", fontSize=11,
                       textColor=risk_col, alignment=TA_CENTER, leading=16),
    ))
    elems.append(_spacer(1.6))

    meta_rows = [
        ["Generated on", date_str],
        ["Domains tracked", str(len(domains_data))],
        ["Domains scanned", str(len(scanned))],
        ["Total Findings", str(total_findings)],
        ["Critical / High", f"{totals['critical']} / {totals['high']}"],
        ["Medium / Low", f"{totals['medium']} / {totals['low']}"],
    ]
    data = [[
        Paragraph(_e(k), ParagraphStyle("mk", fontName="Helvetica-Bold", fontSize=8,
                                    textColor=colors.HexColor("#94a3b8"), alignment=TA_RIGHT)),
        Paragraph(_e(v), ParagraphStyle("mv", fontName="Helvetica", fontSize=8,
                                    textColor=colors.white)),
    ] for k, v in meta_rows]
    mt = Table(data, colWidths=[4.5 * cm, 6 * cm], hAlign="CENTER")
    mt.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.3, colors.HexColor("#1e293b")),
    ]))
    elems.append(mt)
    return elems


def _build_domain_overview(domains_data: list[dict], styles: dict) -> list:
    """Summary table with one row per domain."""
    elems: list = [_section_header("DOMAIN OVERVIEW", "🗂")]
    elems.append(_spacer(0.3))

    rows = [[
        Paragraph("Domain", styles["label"]),
        Paragraph("Grade", styles["label"]),
        Paragraph("Score", styles["label"]),
        Paragraph("Risk", styles["label"]),
        Paragraph("Findings", styles["label"]),
        Paragraph("Last Scan", styles["label"]),
    ]]
    for d in domains_data:
        risk = (d.get("overall_risk") or "low").lower()
        risk_col = RISK_COLOR.get(risk, C_INFO)
        rows.append([
            Paragraph(_e(d.get("domain")), styles["body_bold"]),
            Paragraph(f"<b>{_e(d.get('grade') or '—')}</b>", styles["body"]),
            Paragraph(_e(d.get("score") if d.get("score") is not None else "—"), styles["body"]),
            Paragraph(
                f'<font color="{risk_col.hexval()}"><b>{risk.upper() if d.get("scan_id") else "—"}</b></font>',
                styles["body"],
            ),
            Paragraph(str(len(d.get("findings") or [])), styles["body"]),
            Paragraph(_e(_fmt_scan_date(d.get("completed_at"))), styles["small"]),
        ])
    t = Table(rows, colWidths=[4.6 * cm, 1.4 * cm, 1.5 * cm, 2.0 * cm, 1.8 * cm,
                               COL_W - 11.3 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG_BAND),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(t)
    elems.append(_spacer(0.4))
    return elems


def _build_company_domain_section(d: dict, styles: dict) -> list:
    """One section per domain: score strip, severity counts, all findings."""
    elems: list = [_section_header(f"DOMAIN — {str(d.get('domain', '')).upper()}", "🌐")]
    elems.append(_spacer(0.3))

    if not d.get("scan_id"):
        elems.append(Paragraph(
            "No completed scan for this domain yet — it is excluded from the consolidated totals.",
            styles["body"],
        ))
        elems.append(_spacer(0.4))
        return elems

    findings = d.get("findings") or []
    counts = _severity_counts(findings)
    risk = (d.get("overall_risk") or "low").lower()
    risk_col = RISK_COLOR.get(risk, C_INFO)
    score = d.get("score")
    grade = d.get("grade") or "?"

    strip = [[
        Paragraph("Grade", styles["label"]),
        Paragraph("Score", styles["label"]),
        Paragraph("Overall Risk", styles["label"]),
        Paragraph("Findings", styles["label"]),
        Paragraph("Scanned on", styles["label"]),
    ], [
        Paragraph(f"<b>{_e(grade)}</b>", ParagraphStyle("gv", fontName="Helvetica-Bold",
              fontSize=16, textColor=risk_col, alignment=TA_CENTER)),
        Paragraph(f"<b>{score}/100</b>" if score is not None else "<b>—</b>",
              ParagraphStyle("sv", fontName="Helvetica-Bold",
                             fontSize=16, textColor=risk_col, alignment=TA_CENTER)),
        Paragraph(f'<b><font color="{risk_col.hexval()}">{risk.upper()}</font></b>',
              ParagraphStyle("rv", fontName="Helvetica-Bold", fontSize=11,
                             textColor=risk_col, alignment=TA_CENTER)),
        Paragraph(f"<b>{len(findings)}</b>", ParagraphStyle("fv", fontName="Helvetica-Bold",
              fontSize=16, textColor=C_TEXT, alignment=TA_CENTER)),
        Paragraph(_e(_fmt_scan_date(d.get("completed_at"))), ParagraphStyle(
            "dt", fontName="Helvetica", fontSize=8, textColor=C_TEXT, alignment=TA_CENTER)),
    ]]
    qw = COL_W / 5
    st = Table(strip, colWidths=[qw] * 5)
    st.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  C_BG_BAND),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",   (0, 1), (-1, 1),  C_BG_ROW_ALT),
    ]))
    elems.append(st)
    elems.append(_spacer(0.3))

    # Severity badges row
    badge_cells = []
    for sev in ("critical", "high", "medium", "low"):
        badge_cells.append([
            RiskBadge(sev),
            Paragraph(f"<b>{counts[sev]}</b>", ParagraphStyle(
                "sc", fontName="Helvetica-Bold", fontSize=10,
                textColor=C_TEXT, alignment=TA_CENTER)),
        ])
    bt = Table([badge_cells], colWidths=[COL_W / 4] * 4)
    bt.setStyle(TableStyle([
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ]))
    elems.append(bt)
    elems.append(_spacer(0.35))

    ranked = sorted(findings, key=lambda f: _RISK_ORDER.get((f.get("risk") or "low").lower(), 9))
    if ranked:
        elems.append(Paragraph(f"All {len(ranked)} Findings (by severity)", styles["h2"]))
        t = _findings_table(ranked, styles)
        if t:
            elems.append(t)
    else:
        elems.append(Paragraph("No findings in the latest scan.", styles["body"]))

    elems.append(_spacer(0.5))
    return elems


def _build_company_inventory(assets_summary: dict, styles: dict) -> list:
    """Aggregated asset inventory summary."""
    elems: list = [_section_header("ASSET INVENTORY SUMMARY", "📦")]
    elems.append(_spacer(0.3))
    rows = [
        ("Subdomains",    str(assets_summary.get("subdomains", 0))),
        ("IP addresses",  str(assets_summary.get("ips", 0))),
        ("Endpoints",     str(assets_summary.get("endpoints", 0))),
        ("Technologies",  str(assets_summary.get("technologies", 0))),
        ("Admin panels",  str(assets_summary.get("admin_panels", 0))),
        ("Exposed files", str(assets_summary.get("exposed_files", 0))),
        ("Open ports",    str(assets_summary.get("open_ports", 0))),
        ("Mobile apps",   str(assets_summary.get("apps", 0))),
        ("Neighbors (shared hosting)", str(assets_summary.get("neighbors", 0))),
        ("New in last cycle", str(assets_summary.get("new_last_cycle", 0))),
    ]
    elems.append(_kv_table(rows))
    elems.append(_spacer(0.3))
    return elems


def _asset_table(rows: list[list], headers: list[str], col_widths: list[float]) -> Table:
    """Generic detail table for the company asset-inventory listing sections."""
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BG_BAND),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_ROW_ALT]),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _build_company_asset_detail(assets: dict, styles: dict) -> list:
    """Full per-asset listing (hosts, endpoints, ports, etc.) aggregated across
    every domain of the company — the detail behind the inventory summary counts."""
    elems: list = []

    subs = assets.get("subdomains") or []
    if subs:
        elems.append(_section_header(f"SUBDOMAINS ({len(subs)})", "🔎"))
        elems.append(_spacer(0.2))
        rows = []
        for s in subs:
            ips = ", ".join(s.get("ips") or []) or "—"
            name = _e(s.get("value", "")) + (" 🆕" if s.get("is_new") else "")
            rows.append([
                Paragraph(name, styles["mono"]),
                Paragraph(_e(s.get("domain", "")), styles["small"]),
                Paragraph(_e(ips), styles["small_mono"]),
                Paragraph(_e(s.get("http_status") if s.get("http_status") is not None else "—"), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["Subdomain", "Domain", "IP(s)", "HTTP"],
                                   [5.5 * cm, 3.5 * cm, 5 * cm, COL_W - 14 * cm]))
        elems.append(_spacer(0.3))

    ips = assets.get("ips") or []
    if ips:
        elems.append(_section_header(f"IP ADDRESSES ({len(ips)})", "🌐"))
        elems.append(_spacer(0.2))
        rows = []
        for ip in ips:
            doms = ", ".join(ip.get("domains") or []) or "—"
            ports = ", ".join(
                f'{p.get("port")}/{p.get("service") or "?"}' for p in (ip.get("open_ports") or [])
            ) or "—"
            rows.append([
                Paragraph(_e(ip.get("value", "")), styles["mono"]),
                Paragraph(_e(doms), styles["small"]),
                Paragraph(_e(ports), styles["small_mono"]),
            ])
        elems.append(_asset_table(rows, ["IP", "Domain(s)", "Open Ports"],
                                   [3.5 * cm, 5 * cm, COL_W - 8.5 * cm]))
        elems.append(_spacer(0.3))

    endpoints = assets.get("endpoints") or []
    if endpoints:
        elems.append(_section_header(f"ENDPOINTS ({len(endpoints)})", "🔗"))
        elems.append(_spacer(0.2))
        rows = []
        for e in endpoints:
            rows.append([
                Paragraph(_e(e.get("value", "")), styles["mono"]),
                Paragraph(_e(e.get("domain", "")), styles["small"]),
                Paragraph(_e(e.get("source") or "—"), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["Path", "Domain", "Source"],
                                   [COL_W - 8 * cm, 4 * cm, 4 * cm]))
        elems.append(_spacer(0.3))

    techs = assets.get("technologies") or []
    if techs:
        elems.append(_section_header(f"TECHNOLOGIES ({len(techs)})", "⚙"))
        elems.append(_spacer(0.2))
        rows = []
        for tch in techs:
            rows.append([
                Paragraph(_e(tch.get("value", "")), styles["small"]),
                Paragraph(_e(tch.get("category") or "—"), styles["small"]),
                Paragraph(_e(tch.get("domain", "")), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["Technology", "Category", "Domain"],
                                   [6 * cm, 4 * cm, COL_W - 10 * cm]))
        elems.append(_spacer(0.3))

    admin_panels = assets.get("admin_panels") or []
    if admin_panels:
        elems.append(_section_header(f"ADMIN PANELS ({len(admin_panels)})", "🚪"))
        elems.append(_spacer(0.2))
        rows = []
        for a in admin_panels:
            rows.append([
                Paragraph(_e(a.get("value", "")), styles["mono"]),
                Paragraph(_e(a.get("domain", "")), styles["small"]),
                Paragraph(_e(a.get("http_status") if a.get("http_status") is not None else "—"), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["URL", "Domain", "HTTP"],
                                   [COL_W - 7 * cm, 4 * cm, 3 * cm]))
        elems.append(_spacer(0.3))

    exposed_files = assets.get("exposed_files") or []
    if exposed_files:
        elems.append(_section_header(f"EXPOSED FILES ({len(exposed_files)})", "📂"))
        elems.append(_spacer(0.2))
        rows = []
        for ef in exposed_files:
            sev = ef.get("risk", "low")
            sev_col = RISK_COLOR.get(sev, C_INFO)
            rows.append([
                Paragraph(_e(ef.get("value", "")), styles["mono"]),
                Paragraph(_e(ef.get("domain", "")), styles["small"]),
                Paragraph(f'<font color="{sev_col.hexval()}">{sev.upper()}</font>', styles["small"]),
            ])
        elems.append(_asset_table(rows, ["Path", "Domain", "Risk"],
                                   [COL_W - 7 * cm, 4 * cm, 3 * cm]))
        elems.append(_spacer(0.3))

    ports = assets.get("ports") or []
    if ports:
        elems.append(_section_header(f"OPEN PORTS ({len(ports)})", "🔌"))
        elems.append(_spacer(0.2))
        rows = []
        for p in ports:
            rows.append([
                Paragraph(_e(p.get("ip", "")), styles["mono"]),
                Paragraph(_e(p.get("port") if p.get("port") is not None else "—"), styles["small"]),
                Paragraph(_e(p.get("service") or "—"), styles["small"]),
                Paragraph(_e(p.get("domain", "")), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["IP", "Port", "Service", "Domain"],
                                   [3.5 * cm, 1.8 * cm, 4 * cm, COL_W - 9.3 * cm]))
        elems.append(_spacer(0.3))

    apps = assets.get("apps") or []
    if apps:
        elems.append(_section_header(f"MOBILE APPS ({len(apps)})", "📱"))
        elems.append(_spacer(0.2))
        rows = []
        for a in apps:
            name = _e(a.get("value", "")) + (" ⚠" if a.get("suspicious") else "")
            rows.append([
                Paragraph(name, styles["small"]),
                Paragraph(_e(a.get("store") or "—"), styles["small"]),
                Paragraph(_e(a.get("os") or "—"), styles["small"]),
                Paragraph(_e(a.get("version") or "—"), styles["small"]),
                Paragraph(_e(a.get("developer") or "—"), styles["small"]),
                Paragraph(_e(a.get("domain", "")), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["Name", "Store", "OS", "Version", "Developer", "Domain"],
                                   [4 * cm, 2.2 * cm, 1.5 * cm, 2 * cm, 3.5 * cm, COL_W - 13.2 * cm]))
        elems.append(_spacer(0.3))

    neighbors = assets.get("neighbors") or []
    if neighbors:
        elems.append(_section_header(f"NEIGHBORS — SHARED HOSTING ({len(neighbors)})", "🧭"))
        elems.append(_spacer(0.2))
        rows = []
        for n in neighbors:
            rows.append([
                Paragraph(_e(n.get("value", "")), styles["mono"]),
                Paragraph(_e(n.get("ip") or "—"), styles["small_mono"]),
                Paragraph(_e(n.get("neighbor_of") or "—"), styles["small"]),
                Paragraph(_e(n.get("domain", "")), styles["small"]),
            ])
        elems.append(_asset_table(rows, ["Domain", "IP", "Neighbor Of", "Company Domain"],
                                   [5 * cm, 3 * cm, 4 * cm, COL_W - 12 * cm]))
        elems.append(_spacer(0.3))

    return elems


def generate_company_pdf(
    company_name: str,
    domains_data: list[dict],
    assets_summary: dict | None = None,
    assets_detail: dict | None = None,
) -> bytes:
    """
    Build a consolidated PDF report for a company from per-domain findings data
    (same shape as GET /api/companies/{id}/findings domains) plus an optional
    aggregated asset-inventory summary and an optional full asset listing
    (subdomains, IPs, endpoints, ports, etc. — same shape as GET
    /api/companies/{id}/assets `assets`). Returns the PDF as bytes.
    """
    buf = io.BytesIO()
    styles = _build_styles()

    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in domains_data:
        for k, v in _severity_counts(d.get("findings") or []).items():
            totals[k] += v

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN_L,
        rightMargin=MARGIN_R,
        topMargin=MARGIN_T + 30,
        bottomMargin=MARGIN_B + 22,
        title=f"Consolidated Security Report — {company_name}",
        author="Sauron",
        subject="Consolidated ASM Report",
    )
    doc._report_domain = company_name

    cover_frame   = Frame(0, 0, PAGE_W, PAGE_H, id="cover")
    content_frame = Frame(MARGIN_L, MARGIN_B + 22, COL_W, PAGE_H - MARGIN_T - MARGIN_B - 52, id="content")

    doc.addPageTemplates([
        PageTemplate(id="cover",   frames=[cover_frame],   onPage=_cover_page_bg),
        PageTemplate(id="content", frames=[content_frame], onPage=_content_page_bg),
    ])

    story: list = []
    story.extend(_build_company_cover(company_name, domains_data, totals, styles))
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    _safe_extend(story, "domain_overview", _build_domain_overview, domains_data, styles)
    if assets_summary:
        _safe_extend(story, "inventory", _build_company_inventory, assets_summary, styles)
    story.append(PageBreak())

    for d in domains_data:
        _safe_extend(story, f"domain:{d.get('domain')}", _build_company_domain_section, d, styles)

    if assets_detail:
        story.append(PageBreak())
        _safe_extend(story, "asset_detail", _build_company_asset_detail, assets_detail, styles)

    import xml.etree.ElementTree as _ET
    for idx, elem in enumerate(story):
        if hasattr(elem, "text") and hasattr(elem, "style"):
            raw = getattr(elem, "text", "") or ""
            try:
                _ET.fromstring(f"<root>{raw}</root>")
            except _ET.ParseError as xml_err:
                raise RuntimeError(
                    f"PDF build aborted — invalid XML in Paragraph at story[{idx}]: "
                    f"{raw[:120]!r} — {xml_err}"
                ) from xml_err

    doc.build(story)
    return buf.getvalue()
