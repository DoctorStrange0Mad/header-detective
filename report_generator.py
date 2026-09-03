"""
Header Detective — PDF Report Generator

Generates a self-contained PDF report from the scorecard + report data
produced by ScorecardBuilder. Uses reportlab for PDF rendering.

Usage:
    from report_generator import ReportGenerator

    gen = ReportGenerator()
    gen.generate_pdf(scorecard_report_dict, output_path="report.pdf")

CLI:
    python report_generator.py <scorecard_output.json> [-o report.pdf]
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Page geometry
# ---------------------------------------------------------------------------

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
USABLE_W = PAGE_W - 2 * MARGIN  # ~553pt


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

RISK_COLORS = {
    "none": colors.HexColor("#22c55e"),
    "low": colors.HexColor("#22c55e"),
    "medium": colors.HexColor("#eab308"),
    "high": colors.HexColor("#f97316"),
    "critical": colors.HexColor("#ef4444"),
}

SEVERITY_COLORS = {
    "info": colors.HexColor("#3b82f6"),
    "low": colors.HexColor("#22c55e"),
    "medium": colors.HexColor("#eab308"),
    "high": colors.HexColor("#f97316"),
    "critical": colors.HexColor("#ef4444"),
}

RESULT_COLORS = {
    "pass": colors.HexColor("#22c55e"),
    "fail": colors.HexColor("#ef4444"),
    "softfail": colors.HexColor("#eab308"),
    "neutral": colors.HexColor("#6b7280"),
    "none": colors.HexColor("#6b7280"),
    "error": colors.HexColor("#ef4444"),
}

HEADER_BG = colors.HexColor("#1e293b")
SECTION_BG = colors.HexColor("#f1f5f9")
LIGHT_GRAY = colors.HexColor("#e2e8f0")
WHITE = colors.white
BLACK = colors.black


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=22, leading=26,
            textColor=HEADER_BG, spaceAfter=2, alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontSize=10, leading=13,
            textColor=colors.HexColor("#64748b"), spaceAfter=8, alignment=TA_LEFT,
        ),
        "section": ParagraphStyle(
            "section", parent=base["Heading2"], fontSize=13, leading=16,
            textColor=HEADER_BG, spaceBefore=14, spaceAfter=4, alignment=TA_LEFT,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9, leading=12,
            textColor=BLACK, alignment=TA_LEFT,
        ),
        "body_bold": ParagraphStyle(
            "body_bold", parent=base["Normal"], fontSize=9, leading=12,
            textColor=BLACK, fontName="Helvetica-Bold", alignment=TA_LEFT,
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"], fontSize=8, leading=10,
            textColor=colors.HexColor("#64748b"), alignment=TA_LEFT,
        ),
        "score_large": ParagraphStyle(
            "score_large", parent=base["Normal"], fontSize=42, leading=46,
            alignment=TA_CENTER, textColor=BLACK, fontName="Helvetica-Bold",
        ),
        "risk_label": ParagraphStyle(
            "risk_label", parent=base["Normal"], fontSize=12, leading=15,
            alignment=TA_CENTER, textColor=colors.HexColor("#64748b"),
            fontName="Helvetica-Bold",
        ),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"], fontSize=8, leading=10,
            alignment=TA_LEFT,
        ),
        "cell_center": ParagraphStyle(
            "cell_center", parent=base["Normal"], fontSize=8, leading=10,
            alignment=TA_CENTER,
        ),
        "cell_bold": ParagraphStyle(
            "cell_bold", parent=base["Normal"], fontSize=8, leading=10,
            fontName="Helvetica-Bold", alignment=TA_LEFT,
        ),
        "cell_bold_center": ParagraphStyle(
            "cell_bold_center", parent=base["Normal"], fontSize=8, leading=10,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "rec": ParagraphStyle(
            "rec", parent=base["Normal"], fontSize=9, leading=12,
            textColor=BLACK, leftIndent=14, bulletIndent=0, alignment=TA_LEFT,
        ),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_width_table(data, col_widths=None, header_rows=1):
    """Build a table that spans the full usable width with consistent styling."""
    if col_widths is None:
        n_cols = len(data[0]) if data else 1
        col_widths = [USABLE_W / n_cols] * n_cols

    t = Table(data, colWidths=col_widths, repeatRows=header_rows)
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    # Shade header rows
    for r in range(header_rows):
        style_cmds.append(("BACKGROUND", (0, r), (-1, r), SECTION_BG))
    t.setStyle(TableStyle(style_cmds))
    return t


def _p(text: str, style) -> Paragraph:
    return Paragraph(text, style)


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates a PDF report from a scorecard + report dictionary."""

    def __init__(self):
        self.styles = _build_styles()

    def generate_pdf(self, scorecard_report: dict[str, Any], output_path: str) -> str:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN,
            bottomMargin=MARGIN,
        )

        story: list[Any] = []
        sc = scorecard_report.get("scorecard", {})
        report = scorecard_report.get("report", {})
        findings = report.get("detailed_findings", {})

        story.extend(self._build_header(report, sc))
        story.extend(self._build_scorecard_summary(sc))
        story.extend(self._build_key_indicators(sc))
        story.extend(self._build_auth_section(findings.get("authentication", {})))
        story.extend(self._build_geo_section(findings.get("geolocation", {})))
        story.extend(self._build_language_section(findings.get("language", {})))
        story.extend(self._build_routing_section(findings.get("routing", {})))
        story.extend(self._build_timeline_section(report.get("timeline", [])))
        story.extend(self._build_recommendations(sc))

        story.append(Spacer(1, 20))
        story.append(_p(
            f"Generated by Header Detective Scorecard Module &nbsp;|&nbsp; "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            self.styles["small"],
        ))

        doc.build(story)
        return output_path

    # -------------------------------------------------------------------
    # Header
    # -------------------------------------------------------------------

    def _build_header(self, report: dict, sc: dict) -> list:
        s = self.styles
        risk = sc.get("overall_risk_level", "none")
        color = RISK_COLORS.get(risk, colors.gray)

        file_hash = report.get("file_hash", "N/A")
        domain = report.get("sender_domain") or "unknown"
        hash_short = file_hash[:16] + "..." if len(file_hash) > 16 else file_hash

        # Row 1: Title (left) + risk badge (right), aligned in one table
        title_p = _p("Header Detective — Threat Analysis Report", s["title"])
        badge_label = _p(
            f'<font color="#ffffff"><b>{risk.upper()}</b></font>',
            ParagraphStyle("b", alignment=TA_CENTER, fontSize=13, leading=16,
                           textColor=WHITE, fontName="Helvetica-Bold"),
        )
        header_table = Table(
            [[title_p, badge_label]],
            colWidths=[USABLE_W - 90, 80],
        )
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "CENTER"),
            ("BACKGROUND", (1, 0), (1, 0), color),
            ("TOPPADDING", (1, 0), (1, 0), 6),
            ("BOTTOMPADDING", (1, 0), (1, 0), 6),
            ("LEFTPADDING", (1, 0), (1, 0), 4),
            ("RIGHTPADDING", (1, 0), (1, 0), 4),
        ]))

        return [
            Spacer(1, 4),
            header_table,
            _p(f"Sender: {domain} &nbsp;&nbsp;|&nbsp;&nbsp; File: {hash_short}", s["subtitle"]),
            Spacer(1, 6),
        ]

    # -------------------------------------------------------------------
    # Scorecard summary — full-width layout
    # -------------------------------------------------------------------

    def _build_scorecard_summary(self, sc: dict) -> list:
        s = self.styles
        score = sc.get("overall_score", 0)
        risk = sc.get("overall_risk_level", "none")
        color = RISK_COLORS.get(risk, colors.gray)
        comp = sc.get("component_scores", {})

        elements = [_p("Overall Threat Score", s["section"])]

        # --- Score gauge row: score on left, component table on right ---
        score_para = _p(
            f'<font color="{color.hexval()}" size="42"><b>{score}</b></font>'
            f'<font size="14" color="#94a3b8"> / 100</font>',
            ParagraphStyle("sv", alignment=TA_LEFT, leading=46, fontName="Helvetica-Bold"),
        )
        risk_para = _p(
            f'<font color="{color.hexval()}"><b>{risk.upper()} RISK</b></font>',
            ParagraphStyle("rl", fontSize=11, leading=14, alignment=TA_LEFT,
                           fontName="Helvetica-Bold"),
        )

        # Component table (right side)
        comp_rows = [
            [_p("<b>Component</b>", s["cell_bold"]),
             _p("<b>Score</b>", s["cell_bold_center"]),
             _p("<b>Max</b>", s["cell_bold_center"])],
            [_p("Authentication", s["cell"]),
             _p(str(comp.get("auth_score", 0)), s["cell_center"]),
             _p("30", s["cell_center"])],
            [_p("Geolocation", s["cell"]),
             _p(str(comp.get("geo_score", 0)), s["cell_center"]),
             _p("30", s["cell_center"])],
            [_p("Language", s["cell"]),
             _p(str(comp.get("language_score", 0)), s["cell_center"]),
             _p("30", s["cell_center"])],
            [_p("Link / Attachment", s["cell"]),
             _p(str(comp.get("link_attachment_score", 0)), s["cell_center"]),
             _p("30", s["cell_center"])],
        ]
        comp_table = _full_width_table(comp_rows, col_widths=[130, 70, 50])
        # Right-align the score/max columns
        comp_table_style = comp_table._argW  # not used; apply via style
        comp_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))

        # Combine: left = score + risk label, right = component table
        left_stack = Table(
            [[score_para], [Spacer(1, 2)], [risk_para]],
            colWidths=[150],
        )
        left_stack.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        layout = Table(
            [[left_stack, comp_table]],
            colWidths=[170, USABLE_W - 170],
        )
        layout.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))

        elements.append(layout)
        elements.append(Spacer(1, 8))
        return elements

    # -------------------------------------------------------------------
    # Key indicators — full-width table
    # -------------------------------------------------------------------

    def _build_key_indicators(self, sc: dict) -> list:
        indicators = sc.get("key_indicators", [])
        if not indicators:
            return []

        s = self.styles
        elements = [_p("Key Indicators", s["section"])]

        rows = [[
            _p("<b>Signal</b>", s["cell_bold"]),
            _p("<b>Severity</b>", s["cell_bold_center"]),
            _p("<b>Description</b>", s["cell_bold"]),
        ]]

        for ind in indicators[:10]:
            severity = ind.get("severity", "info")
            sev_color = SEVERITY_COLORS.get(severity, colors.gray)
            rows.append([
                _p(ind.get("signal", "?"), s["cell"]),
                _p(f'<font color="{sev_color.hexval()}"><b>{severity.upper()}</b></font>', s["cell_bold_center"]),
                _p(ind.get("description", ""), s["cell"]),
            ])

        t = _full_width_table(rows, col_widths=[60, 70, USABLE_W - 130])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        return elements

    # -------------------------------------------------------------------
    # Authentication — full-width table
    # -------------------------------------------------------------------

    def _build_auth_section(self, auth: dict) -> list:
        s = self.styles
        elements = [_p("Authentication Results", s["section"])]

        rows = [[
            _p("<b>Protocol</b>", s["cell_bold"]),
            _p("<b>Result</b>", s["cell_bold_center"]),
            _p("<b>Explanation</b>", s["cell_bold"]),
        ]]

        for proto, label in [("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")]:
            detail = auth.get(proto, {})
            result = detail.get("result", "none")
            explanation = detail.get("explanation", "")
            res_color = RESULT_COLORS.get(result, colors.gray)
            rows.append([
                _p(f"<b>{label}</b>", s["cell_bold"]),
                _p(f'<font color="{res_color.hexval()}"><b>{result.upper()}</b></font>', s["cell_bold_center"]),
                _p(explanation, s["cell"]),
            ])

        t = _full_width_table(rows, col_widths=[70, 70, USABLE_W - 140])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        return elements

    # -------------------------------------------------------------------
    # Geolocation
    # -------------------------------------------------------------------

    def _build_geo_section(self, geo: dict) -> list:
        s = self.styles
        elements = [_p("Geolocation Analysis", s["section"])]

        resolved = geo.get("resolved_hops", 0)
        unresolved = geo.get("unresolved_hops", 0)
        countries = geo.get("countries_visited", [])
        anomalies = geo.get("anomalies", [])

        # Summary row
        rows = [[
            _p("<b>Metric</b>", s["cell_bold"]),
            _p("<b>Value</b>", s["cell_bold_center"]),
        ]]
        rows.append([_p("Resolved hops", s["cell"]), _p(str(resolved), s["cell_center"])])
        rows.append([_p("Unresolved hops", s["cell"]), _p(str(unresolved), s["cell_center"])])
        rows.append([_p("Countries visited", s["cell"]),
                     _p(", ".join(countries) if countries else "N/A", s["cell_center"])])

        t = _full_width_table(rows, col_widths=[USABLE_W * 0.45, USABLE_W * 0.55])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

        if anomalies:
            elements.append(Spacer(1, 6))
            elements.append(_p("<b>Anomalies:</b>", s["body_bold"]))
            for a in anomalies:
                elements.append(_p(f"\u2022 {a}", s["rec"]))

        return elements

    # -------------------------------------------------------------------
    # Language analysis
    # -------------------------------------------------------------------

    def _build_language_section(self, lang: dict) -> list:
        s = self.styles
        elements = [_p("Language Analysis", s["section"])]

        classification = lang.get("classification", "low_risk")
        threat_score = lang.get("threat_score", 0.0)

        # Summary row
        class_color = RISK_COLORS.get(
            "critical" if "critical" in classification
            else "high" if "high" in classification
            else "medium" if "medium" in classification
            else "low",
            colors.gray,
        )
        rows = [[
            _p("<b>Metric</b>", s["cell_bold"]),
            _p("<b>Value</b>", s["cell_bold_center"]),
        ]]
        rows.append([
            _p("Classification", s["cell"]),
            _p(f'<font color="{class_color.hexval()}"><b>{classification}</b></font>', s["cell_bold_center"]),
        ])
        rows.append([
            _p("Threat score", s["cell"]),
            _p(f"{threat_score:.4f}", s["cell_center"]),
        ])

        t = _full_width_table(rows, col_widths=[USABLE_W * 0.45, USABLE_W * 0.55])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

        # Indicators
        top_indicators = lang.get("top_indicators", [])
        if top_indicators:
            elements.append(Spacer(1, 6))
            elements.append(_p("<b>Top indicators:</b>", s["body_bold"]))
            for ind in top_indicators:
                cat = ind.get("category", "?")
                phrase = ind.get("phrase", "?")
                sev = ind.get("severity", "medium")
                sev_color = SEVERITY_COLORS.get(sev, colors.gray)
                elements.append(_p(
                    f'\u2022 <font color="{sev_color.hexval()}"><b>[{sev.upper()}]</b></font> '
                    f'[{cat}] &ldquo;{phrase}&rdquo;',
                    s["rec"],
                ))

        # Entities
        entities = lang.get("extracted_entities", {})
        if entities:
            elements.append(Spacer(1, 6))
            ent_parts = []
            if entities.get("persons"):
                ent_parts.append(f"Persons: {', '.join(entities['persons'][:3])}")
            if entities.get("organizations"):
                ent_parts.append(f"Orgs: {', '.join(entities['organizations'][:3])}")
            if entities.get("money"):
                ent_parts.append(f"Money: {', '.join(entities['money'][:3])}")
            if ent_parts:
                elements.append(_p("<b>Extracted entities:</b>", s["body_bold"]))
                elements.append(_p(" &nbsp;|&nbsp; ".join(ent_parts), s["body"]))

        return elements

    # -------------------------------------------------------------------
    # Routing analysis
    # -------------------------------------------------------------------

    def _build_routing_section(self, routing: dict) -> list:
        s = self.styles
        elements = [_p("Routing Analysis", s["section"])]

        total = routing.get("total_hops", 0)
        protocols = routing.get("protocols_used", [])
        patterns = routing.get("suspicious_patterns", [])

        rows = [[
            _p("<b>Metric</b>", s["cell_bold"]),
            _p("<b>Value</b>", s["cell_bold_center"]),
        ]]
        rows.append([_p("Total hops", s["cell"]), _p(str(total), s["cell_center"])])
        rows.append([
            _p("Protocols used", s["cell"]),
            _p(", ".join(protocols) if protocols else "N/A", s["cell_center"]),
        ])

        t = _full_width_table(rows, col_widths=[USABLE_W * 0.45, USABLE_W * 0.55])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

        if patterns:
            elements.append(Spacer(1, 6))
            elements.append(_p("<b>Suspicious patterns:</b>", s["body_bold"]))
            for p_text in patterns:
                elements.append(_p(f"\u2022 {p_text}", s["rec"]))

        return elements

    # -------------------------------------------------------------------
    # Relay timeline — full-width, proportional columns
    # -------------------------------------------------------------------

    def _build_timeline_section(self, timeline: list) -> list:
        if not timeline:
            return []

        s = self.styles
        elements = [_p("Relay Timeline", s["section"])]

        # Proportional widths: # | From | By | IP | Proto | Location | Time
        # Sum = USABLE_W
        col_ratios = [0.05, 0.18, 0.18, 0.15, 0.12, 0.17, 0.15]
        col_widths = [USABLE_W * r for r in col_ratios]

        header = [
            _p("<b>#</b>", s["cell_bold_center"]),
            _p("<b>From</b>", s["cell_bold"]),
            _p("<b>By</b>", s["cell_bold"]),
            _p("<b>IP</b>", s["cell_bold"]),
            _p("<b>Proto</b>", s["cell_bold_center"]),
            _p("<b>Location</b>", s["cell_bold"]),
            _p("<b>Time</b>", s["cell_bold"]),
        ]
        rows = [header]

        for entry in timeline:
            from ipaddress import ip_address as _ip_parse

            hop_idx = entry.get("hop_index", "?")
            from_host = entry.get("from_host") or "-"
            by_host = entry.get("by_host") or "-"
            from_ip = entry.get("from_ip") or "-"
            protocol = entry.get("protocol") or "-"
            city = entry.get("city") or ""
            country = entry.get("country") or ""
            location = ", ".join(filter(None, [city, country])) or "-"
            timestamp = entry.get("timestamp") or "-"
            if timestamp and len(timestamp) > 19:
                timestamp = timestamp[:19]

            is_private = False
            if entry.get("from_ip"):
                try:
                    ip_obj = _ip_parse(entry["from_ip"])
                    is_private = ip_obj.is_private or ip_obj.is_loopback
                except (ValueError, AttributeError):
                    pass

            ip_style = s["cell_bold"] if is_private else s["cell"]
            ip_text = from_ip[:18]
            if is_private:
                ip_text = f'<font color="#ef4444"><b>{ip_text}</b></font>'

            rows.append([
                _p(str(hop_idx), s["cell_center"]),
                _p(from_host[:28], s["cell"]),
                _p(by_host[:28], s["cell"]),
                _p(ip_text, s["cell"]),
                _p(protocol[:14], s["cell_center"]),
                _p(location[:22], s["cell"]),
                _p(timestamp[:19], s["cell"]),
            ])

        t = Table(rows, colWidths=col_widths, repeatRows=1)
        style_cmds = [
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (4, 0), (4, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        # Zebra stripe
        for i in range(1, len(rows)):
            if i % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8fafc")))
        t.setStyle(TableStyle(style_cmds))
        elements.append(t)

        return elements

    # -------------------------------------------------------------------
    # Recommendations
    # -------------------------------------------------------------------

    def _build_recommendations(self, sc: dict) -> list:
        recs = sc.get("recommendations", [])
        if not recs:
            return []

        s = self.styles
        elements = [_p("Recommendations", s["section"])]
        for rec in recs:
            elements.append(_p(f"\u2022 {rec}", s["rec"]))

        return elements


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <scorecard_output.json> [-o output.pdf]")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    output = "report.pdf"
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output = sys.argv[idx + 1]

    gen = ReportGenerator()
    path = gen.generate_pdf(data, output)
    print(f"PDF report written to: {path}")
