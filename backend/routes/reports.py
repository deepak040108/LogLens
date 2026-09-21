"""routes/reports.py - Enterprise 3-page Security Intelligence Report."""

import os, sys, csv, io, math
from datetime import datetime
from flask import Blueprint, jsonify, request, Response

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
reports_bp = Blueprint("reports", __name__)

PW, LM, RM, TM = 210, 12, 12, 14
CW = PW - LM - RM


def _get_job_queue():
    from app import job_queue
    return job_queue


@reports_bp.get("/reports/<job_id>")
def get_report(job_id):
    jq = _get_job_queue()
    job = jq.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "completed":
        return jsonify({"error": "Report not available"}), 409
    fmt = request.args.get("format", "json")
    summary = job["summary"]
    if fmt == "pdf":
        return _pdf_report(job_id, job, summary)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["ip", "count", "country", "city", "organization", "topAttack", "severity", "lastSeen"])
        w.writeheader()
        for r in summary["topAttackers"]:
            w.writerow({k: r.get(k) for k in w.fieldnames})
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="loglens-report-{job_id[:8]}.csv"'})
    if fmt == "json":
        return Response(_json_report(job_id, job, summary), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="loglens-report-{job_id[:8]}.json"'})
    return jsonify({"error": f"Unsupported format '{fmt}'"}), 400


C = {
    "navy": (15, 23, 42), "blue": (37, 99, 235), "blue_d": (29, 78, 216),
    "white": (255, 255, 255),
    "g50": (248, 250, 252), "g100": (241, 245, 249), "g200": (226, 232, 240),
    "g300": (203, 213, 225), "g400": (148, 163, 184), "g500": (100, 116, 139),
    "g600": (71, 85, 105), "g700": (51, 65, 85), "g800": (30, 41, 59),
    "red": (239, 68, 68), "red6": (220, 38, 38), "red7": (185, 28, 28), "red9": (127, 29, 29), "red_bg": (254, 242, 242),
    "amber": (245, 158, 11), "amber6": (217, 119, 6), "amber_bg": (255, 251, 235),
    "green": (34, 197, 94), "green6": (22, 163, 74), "green7": (21, 128, 61), "green_bg": (240, 253, 244),
}
SEV_CLR = {
    "critical": (C["red9"], C["red"], C["red_bg"]),
    "high": (C["red7"], C["red6"], C["red_bg"]),
    "medium": (C["amber6"], C["amber"], C["amber_bg"]),
    "low": (C["green7"], C["green"], C["green_bg"]),
}
SEV_ORDER = ["critical", "high", "medium", "low"]


def _s(v):
    if v is None: return ""
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)): return ""
    if isinstance(v, float) and v == int(v): return str(int(v))
    return str(v)


def _safe(t):
    s = str(t) if t else ""
    for o, n in [("\u2014", "--"), ("\u2013", "-"), ("\u2018", "'"), ("\u2019", "'"),
                 ("\u201c", '"'), ("\u201d", '"'), ("\u2026", "..."), ("\u00a0", " ")]:
        s = s.replace(o, n)
    return s


def _pdf_report(job_id, job, summary):
    from fpdf import FPDF

    total_req = summary.get("totalRequests", 0)
    total_atk = summary.get("totalAttacks", 0)
    malformed = summary.get("malformedLines", 0)
    attack_rate = round(100 * total_atk / total_req, 1) if total_req else 0
    sev = summary.get("severityBreakdown", [])
    ts = summary.get("threatScoring", {})
    overall_score = ts.get("overallScore", 0)
    overall_level = ts.get("overallLevel", "info")
    top_attackers = summary.get("topAttackers", [])
    by_type = summary.get("byType", [])
    by_country = summary.get("byCountry", [])
    correlations = summary.get("correlationFindings", [])
    timeline = summary.get("timeline", [])
    recent = summary.get("recentFindings", [])
    per_attacker = ts.get("perAttacker", {})
    unique_ips = summary.get("uniqueAttackerIps", 0)

    sev_counts = {}
    for s_item in sev:
        sev_counts[s_item["severity"]] = s_item.get("count", 0)

    rpt_id = job_id[:8]
    gen_date = datetime.utcnow().strftime("%B %d, %Y")
    gen_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    source_file = _safe(job.get("originalName", "Unknown"))

    class Report(FPDF):
        def __init__(self):
            super().__init__()
            self._page_type = ""
            self.set_auto_page_break(auto=False)
            self.set_left_margin(LM)
            self.set_right_margin(RM)

        def header(self):
            if self._page_type == "cover":
                return
            self.set_y(3)
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*C["navy"])
            self.cell(CW / 2, 4, "LOGLENS", new_x="END")
            self.set_font("Helvetica", "", 5)
            self.set_text_color(*C["g500"])
            self.cell(CW / 2, 4, "Security Intelligence Report", align="R")
            self.set_y(8)
            self.set_draw_color(*C["blue"])
            self.set_line_width(0.4)
            self.line(LM, self.get_y(), PW - RM, self.get_y())
            self.set_line_width(0.2)
            self.set_y(TM)

        def footer(self):
            self.set_y(-7)
            self.set_draw_color(*C["g200"])
            self.line(LM, self.get_y(), PW - RM, self.get_y())
            self.set_font("Helvetica", "B", 4)
            self.set_text_color(*C["red6"])
            self.cell(CW / 2, 4, "CONFIDENTIAL  |  AUTHORIZED USE ONLY")
            self.set_xy(LM, self.get_y())
            self.set_font("Helvetica", "", 4)
            self.set_text_color(*C["g400"])
            self.cell(CW, 4, f"Report ID: {rpt_id}  |  Page {self.page_no()} of 3", align="R")

        def page_title(self, title):
            self.set_font("Helvetica", "B", 7.5)
            self.set_text_color(*C["navy"])
            self.cell(CW, 4, title)
            self.ln(4.5)
            self.set_draw_color(*C["blue"])
            self.set_line_width(0.25)
            self.line(LM, self.get_y(), LM + 25, self.get_y())
            self.set_line_width(0.15)
            self.ln(2)

        def sub_title(self, title):
            self.set_font("Helvetica", "B", 6)
            self.set_text_color(*C["blue"])
            self.cell(CW, 3.5, title)
            self.ln(3.8)

        def body_text(self, text):
            self.set_font("Helvetica", "", 5.5)
            self.set_text_color(*C["g700"])
            self.multi_cell(CW, 2.8, _safe(text))
            self.ln(0.5)

        def kpi_card(self, label, value, x, y, w=28, h=14):
            self.set_fill_color(*C["g50"])
            self.set_draw_color(*C["g200"])
            self.rect(x, y, w, h, "FD")
            self.set_fill_color(*C["blue"])
            self.rect(x, y, w, 1, "F")
            self.set_xy(x, y + 2.5)
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*C["navy"])
            self.cell(w, 5, str(value), align="C")
            self.set_xy(x, y + 8)
            self.set_font("Helvetica", "", 4.5)
            self.set_text_color(*C["g500"])
            self.cell(w, 3, label, align="C")

        def mini_table(self, headers, rows, widths):
            self.set_font("Helvetica", "B", 4.5)
            self.set_fill_color(*C["g800"])
            self.set_text_color(*C["white"])
            for i, h in enumerate(headers):
                self.cell(widths[i], 4.5, h, border=0, fill=True, align="C")
            self.ln(4.5)
            self.set_text_color(*C["g700"])
            for idx, row in enumerate(rows):
                bg = C["white"] if idx % 2 == 0 else C["g50"]
                self.set_fill_color(*bg)
                self.set_font("Helvetica", "", 4)
                for i, val in enumerate(row):
                    self.cell(widths[i], 3.5, _safe(str(val))[:35], border=0, fill=True, align="C")
                self.ln(3.5)

    pdf = Report()
    pdf.alias_nb_pages()

    # =========================================================================
    #  PAGE 1 — SECURITY OVERVIEW & THREAT SUMMARY
    # =========================================================================
    pdf._page_type = "cover"
    pdf.add_page()
    pdf._page_type = "content"

    # Cover header bar
    pdf.set_fill_color(*C["blue"])
    pdf.rect(0, 0, PW, 18, "F")
    pdf.set_xy(LM, 4)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C["white"])
    pdf.cell(CW, 7, "LOGLENS", align="C")
    pdf.set_xy(LM, 11)
    pdf.set_font("Helvetica", "", 7)
    pdf.cell(CW, 5, "Security Intelligence Report", align="C")

    # Metadata row
    y = 22
    pdf.set_xy(LM, y)
    pdf.set_font("Helvetica", "", 5)
    pdf.set_text_color(*C["g600"])
    meta = [
        f"Report ID: {rpt_id}",
        f"Source: {source_file}",
        f"Generated: {gen_date}",
        "Classification: CONFIDENTIAL | AUTHORIZED USE ONLY",
    ]
    pdf.cell(CW, 3.5, "  |  ".join(meta), align="C")

    # Executive Summary
    y = 30
    pdf.set_xy(LM, y)
    pdf.page_title("Executive Summary")

    # KPI Cards — 6 cards in 2 rows of 3
    kpi_w = 56
    kpi_h = 13
    kpi_gap = 5
    row1_x = LM + (CW - 3 * kpi_w - 2 * kpi_gap) / 2
    row1_y = pdf.get_y() + 1

    kpis = [
        ("Total Requests", f"{total_req:,}"),
        ("Attacks Detected", f"{total_atk:,}"),
        ("Attack Rate", f"{attack_rate}%"),
        ("Unique Attacker IPs", f"{unique_ips}"),
        ("Threat Score", f"{overall_score}/100"),
        ("Overall Level", overall_level.upper()),
    ]
    for i, (lbl, val) in enumerate(kpis):
        col = i % 3
        row = i // 3
        kx = row1_x + col * (kpi_w + kpi_gap)
        ky = row1_y + row * (kpi_h + 3)
        pdf.kpi_card(lbl, val, kx, ky, kpi_w, kpi_h)

    pdf.set_y(row1_y + 2 * (kpi_h + 3) + 2)

    # Summary text
    pdf.body_text(
        f"Analysis of '{source_file}': {total_req:,} requests, {total_atk:,} attacks detected "
        f"({attack_rate}% rate), {unique_ips} unique attacker IPs, overall threat score "
        f"{overall_score}/100 ({overall_level.upper()})."
    )
    pdf.ln(1)

    # Severity Breakdown
    pdf.page_title("Severity Breakdown")
    sev_data = [(s["severity"], s["count"]) for s in sev if s.get("count", 0) > 0]
    sev_data.sort(key=lambda x: SEV_ORDER.index(x[0]) if x[0] in SEV_ORDER else 99)
    if sev_data:
        mx = max((c for _, c in sev_data), default=1)
        bar_w = 50
        y = pdf.get_y() + 1
        for sn, cnt in sev_data:
            clrs = SEV_CLR.get(sn, (C["g500"], C["g500"], C["g100"]))
            pdf.set_xy(LM, y)
            pdf.set_font("Helvetica", "B", 5)
            pdf.set_text_color(*clrs[0])
            pdf.cell(18, 4, sn.upper())
            pdf.set_fill_color(*C["g100"])
            pdf.rect(LM + 20, y + 0.5, bar_w, 3, "F")
            pdf.set_fill_color(*clrs[1])
            fill_w = max(0.5, bar_w * cnt / mx) if mx else 0
            pdf.rect(LM + 20, y + 0.5, fill_w, 3, "F")
            pdf.set_font("Helvetica", "B", 5)
            pdf.set_text_color(*C["navy"])
            pdf.set_xy(LM + 22 + bar_w, y)
            pdf.cell(10, 4, str(cnt))
            y += 5
        pdf.set_y(y + 1)

    pdf.mini_table(
        ["Severity", "Description", "Examples"],
        [["Critical", "Active exploitation", "SQL injection, command injection"],
         ["High", "Confirmed attack attempts", "XSS, directory traversal"],
         ["Medium", "Suspicious activity", "Scanner patterns"],
         ["Low", "Informational", "Minor anomalies"]],
        [CW * 0.15, CW * 0.45, CW * 0.40],
    )
    pdf.ln(1)

    # Attack Distribution
    pdf.page_title("Attack Distribution by Type")
    if by_type:
        mx = max((t.get("count", 0) for t in by_type), default=1)
        bar_w = 50
        y = pdf.get_y() + 1
        for item in by_type[:8]:
            at = _safe(item.get("attack_type", "").replace("_", " ").title())
            cnt = item.get("count", 0)
            pct = round(100 * cnt / total_atk, 1) if total_atk else 0
            pdf.set_xy(LM, y)
            pdf.set_font("Helvetica", "", 5)
            pdf.set_text_color(*C["g700"])
            pdf.cell(30, 4, _safe(at)[:28])
            pdf.set_fill_color(*C["g100"])
            pdf.rect(LM + 32, y + 0.5, bar_w, 3, "F")
            pdf.set_fill_color(*C["blue"])
            fill_w = max(0.5, bar_w * cnt / mx) if mx else 0
            pdf.rect(LM + 32, y + 0.5, fill_w, 3, "F")
            pdf.set_font("Helvetica", "B", 5)
            pdf.set_text_color(*C["navy"])
            pdf.set_xy(LM + 34 + bar_w, y)
            pdf.cell(15, 4, f"{cnt}  ({pct}%)")
            y += 5
        pdf.set_y(y + 1)

        pdf.mini_table(
            ["Attack Type", "Count", "% of Total"],
            [[_safe(t.get("attack_type", "")).replace("_", " ").title(),
              str(t.get("count", 0)),
              f"{round(100 * t.get('count', 0) / total_atk, 1) if total_atk else 0}%"]
             for t in by_type[:8]],
            [CW * 0.50, CW * 0.25, CW * 0.25],
        )

    # Key Findings panel
    pdf.ln(2)
    pdf.page_title("Key Findings")
    panel_y = pdf.get_y()
    pdf.set_fill_color(*C["g50"])
    pdf.set_draw_color(*C["blue"])
    pdf.set_line_width(0.3)
    pdf.rect(LM, panel_y, CW, 22, "FD")
    pdf.set_line_width(0.15)

    findings = [
        f"{total_atk} attacks detected from {total_req} requests.",
    ]
    if by_type:
        top2 = sorted(by_type, key=lambda x: x.get("count", 0), reverse=True)[:2]
        for t in top2:
            at = _safe(t.get("attack_type", "")).replace("_", " ").title()
            cnt = t.get("count", 0)
            pct = round(100 * cnt / total_atk, 1) if total_atk else 0
            findings.append(f"{at} accounts for {pct}% of detected attacks.")
    findings.append(f"{unique_ips} unique attacker IPs identified.")
    findings.append(f"Overall threat score is {overall_score}/100.")

    fy = panel_y + 2
    pdf.set_font("Helvetica", "", 5)
    pdf.set_text_color(*C["g700"])
    for finding in findings[:5]:
        pdf.set_xy(LM + 3, fy)
        pdf.cell(2, 2.5, "-")
        pdf.set_x(LM + 6)
        pdf.cell(CW - 8, 2.5, _safe(finding))
        fy += 3.2

    # =========================================================================
    #  PAGE 2 — ATTACKER INTELLIGENCE & EVENT ANALYSIS
    # =========================================================================
    pdf.add_page()

    # Top Attacker IPs
    pdf.page_title("Top Attacker IPs")
    if top_attackers:
        rows = []
        for idx, a in enumerate(top_attackers[:10]):
            country = _s(a.get("country"))
            if not country or country.lower() == "nan":
                country = "N/A"
            rows.append([
                str(idx + 1), _s(a.get("ip")), str(a.get("count", 0)),
                country[:16],
                _safe(a.get("topAttack", "")).replace("_", " ")[:18],
                _s(a.get("severity"))[:8],
            ])
        pdf.mini_table(
            ["Rank", "IP Address", "Hits", "Location", "Top Attack", "Severity"],
            rows,
            [10, 30, 12, 30, 40, 20],
        )
    pdf.ln(1)

    # Threat Score Analysis
    pdf.page_title("Threat Score Analysis")
    if per_attacker:
        scored = sorted(per_attacker.items(), key=lambda x: x[1].get("score", 0), reverse=True)[:8]
        bar_w = 55
        y = pdf.get_y() + 1
        for ip, sc in scored:
            score = sc.get("score", 0)
            level = sc.get("level", "info")
            fill_w = max(1, int(bar_w * score / 100))
            lvl_clr = {"critical": C["red"], "high": C["red7"], "medium": C["amber6"], "low": C["green6"]}
            clr = lvl_clr.get(level, C["blue"])
            pdf.set_xy(LM, y)
            pdf.set_font("Courier", "", 5)
            pdf.set_text_color(*C["g700"])
            pdf.cell(28, 4, _s(ip)[:26])
            pdf.set_fill_color(*C["g100"])
            pdf.rect(LM + 30, y + 0.5, bar_w, 3, "F")
            pdf.set_fill_color(*clr)
            pdf.rect(LM + 30, y + 0.5, fill_w, 3, "F")
            pdf.set_font("Helvetica", "B", 5)
            pdf.set_text_color(*clr)
            pdf.set_xy(LM + 32 + bar_w, y)
            pdf.cell(10, 4, str(score))
            pdf.set_font("Helvetica", "", 4)
            pdf.set_text_color(*C["g500"])
            pdf.cell(18, 4, level.upper())
            y += 4.5
        pdf.set_y(y + 1)

    # Scoring model
    pdf.sub_title("Scoring Model")
    model_y = pdf.get_y()
    pdf.set_fill_color(*C["g50"])
    pdf.set_draw_color(*C["g200"])
    pdf.rect(LM, model_y, CW, 8, "FD")
    weights = [("Severity", "40%"), ("Frequency", "25%"), ("Diversity", "20%"), ("Recency", "15%")]
    wx = LM + 2
    for wl, wp in weights:
        pdf.set_xy(wx, model_y + 1.5)
        pdf.set_font("Helvetica", "B", 4.5)
        pdf.set_text_color(*C["navy"])
        pdf.cell(18, 2.5, wl)
        pdf.set_xy(wx, model_y + 4.5)
        pdf.set_font("Helvetica", "", 4.5)
        pdf.set_text_color(*C["blue"])
        pdf.cell(18, 2.5, wp)
        wx += 22
    pdf.set_y(model_y + 10)

    # Correlation Analysis
    if correlations:
        pdf.page_title("Correlation Analysis")
        for cf in correlations[:3]:
            cf_y = pdf.get_y()
            ctype = _safe(cf.get("type", "Unknown"))
            cdesc = _safe(cf.get("description", ""))
            cseverity = cf.get("severity", "medium")
            cips = cf.get("ips", [])
            clrs = SEV_CLR.get(cseverity, (C["g500"], C["g500"], C["g100"]))

            pdf.set_fill_color(*clrs[2])
            pdf.set_draw_color(*clrs[0])
            pdf.set_line_width(0.3)
            pdf.rect(LM, cf_y, CW, 16, "FD")
            pdf.set_line_width(0.15)

            pdf.set_xy(LM + 3, cf_y + 1.5)
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C["navy"])
            pdf.cell(CW - 25, 4, ctype)

            pdf.set_fill_color(*clrs[0])
            pdf.rect(PW - RM - 20, cf_y + 1.5, 18, 3.5, "F")
            pdf.set_xy(PW - RM - 20, cf_y + 1.5)
            pdf.set_font("Helvetica", "B", 4.5)
            pdf.set_text_color(*C["white"])
            pdf.cell(18, 3.5, cseverity.upper(), align="C")

            pdf.set_xy(LM + 3, cf_y + 6)
            pdf.set_font("Helvetica", "", 5)
            pdf.set_text_color(*C["g600"])
            pdf.multi_cell(CW - 6, 2.5, _safe(cdesc))

            pdf.set_xy(LM + 3, cf_y + 12)
            pdf.set_font("Helvetica", "I", 4)
            pdf.set_text_color(*C["g500"])
            pdf.cell(CW - 6, 2.5, f"IPs: {', '.join(str(_s(ip)) for ip in cips[:5])}")

            pdf.set_y(cf_y + 18)

    # Attack Timeline
    if timeline:
        pdf.page_title("Attack Timeline")
        sorted_tl = sorted(timeline, key=lambda x: x.get("count", 0), reverse=True)[:8]
        mx = max((t.get("count", 0) for t in sorted_tl), default=1)
        bar_w = 55
        y = pdf.get_y() + 1
        for item in sorted_tl:
            hour = str(item.get("hour", "N/A"))
            cnt = item.get("count", 0)
            pdf.set_xy(LM, y)
            pdf.set_font("Helvetica", "", 5)
            pdf.set_text_color(*C["g700"])
            pdf.cell(28, 4, f"Hour {hour}")
            pdf.set_fill_color(*C["g100"])
            pdf.rect(LM + 30, y + 0.5, bar_w, 3, "F")
            pdf.set_fill_color(*C["blue_d"])
            fill_w = max(0.5, bar_w * cnt / mx) if mx else 0
            pdf.rect(LM + 30, y + 0.5, fill_w, 3, "F")
            pdf.set_font("Helvetica", "B", 5)
            pdf.set_text_color(*C["blue_d"])
            pdf.set_xy(LM + 32 + bar_w, y)
            pdf.cell(15, 4, f"{cnt} events")
            y += 4.5
        pdf.set_y(y + 1)

    # Recent Threat Events
    if recent:
        pdf.page_title("Recent Threat Events")
        rows = []
        for f_item in recent[:10]:
            ts_val = f_item.get("timestamp", "")
            if ts_val and "T" in ts_val:
                ts_val = ts_val.replace("T", " ").split("+")[0][:16]
            path = _safe(f_item.get("path", ""))[:32]
            rows.append([
                ts_val[:16] if ts_val else "-",
                _s(f_item.get("ip"))[:16],
                _s(f_item.get("method"))[:5],
                path,
                _safe(f_item.get("attack_type", "")).replace("_", " ")[:16],
                _s(f_item.get("severity"))[:6],
            ])
        pdf.mini_table(
            ["Timestamp", "IP", "Method", "Path", "Attack Type", "Severity"],
            rows,
            [28, 26, 12, 42, 28, 16],
        )

    # =========================================================================
    #  PAGE 3 — DETECTION METHODOLOGY & RESPONSE
    # =========================================================================
    pdf.add_page()

    # Detection Methodology
    pdf.page_title("Detection Methodology")
    pdf.body_text(
        "LogLens uses regex-based signature matching and behavioral analysis to detect threats "
        "in Apache/Nginx access logs. The detection engine processes each log line through a "
        "multi-stage pipeline: parsing, field extraction, signature matching, event collection, "
        "and aggregation."
    )
    pdf.ln(1)

    # Detection Categories as badges
    pdf.sub_title("Detection Categories")
    cats = [
        "SQL Injection", "XSS", "Directory Traversal", "Command Injection",
        "Log4Shell (CVE-2021-44228)", "Reconnaissance / Scanning",
        "Sensitive Data Access", "Brute Force",
    ]
    badge_y = pdf.get_y()
    badge_x = LM
    badge_h = 5
    badge_gap = 2
    for cat in cats:
        cat_w = pdf.get_string_width(cat) + 5
        if badge_x + cat_w > PW - RM:
            badge_x = LM
            badge_y += badge_h + badge_gap
        pdf.set_fill_color(*C["blue"])
        pdf.set_text_color(*C["white"])
        pdf.set_font("Helvetica", "B", 4.5)
        pdf.rect(badge_x, badge_y, cat_w, badge_h, "F")
        pdf.set_xy(badge_x, badge_y + 0.8)
        pdf.cell(cat_w, 3.5, cat, align="C")
        badge_x += cat_w + badge_gap
    pdf.set_y(badge_y + badge_h + 4)

    # Threat Scoring Model
    pdf.page_title("Threat Scoring Model")
    pdf.body_text(
        "Each attacker IP receives a composite threat score between 0 and 100, calculated from "
        "four weighted factors. Higher scores indicate greater threat."
    )
    pdf.ln(1)

    # Scoring visualization
    model_y = pdf.get_y()
    pdf.set_fill_color(*C["g50"])
    pdf.set_draw_color(*C["g200"])
    pdf.rect(LM, model_y, CW, 16, "FD")

    bar_total = CW - 4
    weights_data = [("Severity", 0.40, C["red7"]), ("Frequency", 0.25, C["blue"]),
                    ("Diversity", 0.20, C["amber6"]), ("Recency", 0.15, C["green6"])]
    bx = LM + 2
    for wl, wp, wc in weights_data:
        bw = int(bar_total * wp)
        pdf.set_fill_color(*wc)
        pdf.rect(bx, model_y + 2, bw, 4, "F")
        pdf.set_xy(bx, model_y + 7)
        pdf.set_font("Helvetica", "B", 4.5)
        pdf.set_text_color(*C["navy"])
        pdf.cell(bw, 2.5, wl, align="C")
        pdf.set_xy(bx, model_y + 10)
        pdf.set_font("Helvetica", "", 4.5)
        pdf.set_text_color(*C["g500"])
        pdf.cell(bw, 2.5, f"{int(wp*100)}%", align="C")
        bx += bw + 1

    pdf.set_y(model_y + 18)
    pdf.set_font("Helvetica", "", 5)
    pdf.set_text_color(*C["g700"])
    pdf.set_x(LM)
    pdf.cell(CW, 3, "Score Range:  0-25 LOW  |  26-50 MEDIUM  |  51-75 HIGH  |  76-100 CRITICAL")
    pdf.ln(5)

    # Security Recommendations
    pdf.page_title("Security Recommendations")
    recs = [
        "Block IPs with threat scores above 75 at the network firewall.",
        "Review all critical-severity findings for successful exploitation.",
        "Implement WAF rules for top attack patterns identified in this report.",
        "Use parameterized queries to prevent SQL injection.",
        "Deploy Content-Security-Policy headers to mitigate XSS.",
        "Restrict web access to sensitive files (.env, .git, backups).",
        "Implement account lockout after repeated failed logins.",
        "Update Log4j to version 2.17.1+ if Java services are exposed.",
        "Forward logs to a centralized SIEM for continuous monitoring.",
        "Schedule regular penetration testing and vulnerability assessments.",
    ]

    col_w = (CW - 4) / 2
    y_left = pdf.get_y() + 1
    y_right = y_left
    for i, rec in enumerate(recs):
        col = i % 2
        if col == 0:
            rx = LM
            ry = y_left
        else:
            rx = LM + col_w + 4
            ry = y_right

        pdf.set_xy(rx, ry)
        pdf.set_font("Helvetica", "B", 5)
        pdf.set_text_color(*C["blue"])
        pdf.cell(5, 3, f"{i + 1}.")
        pdf.set_font("Helvetica", "", 4.5)
        pdf.set_text_color(*C["g700"])
        pdf.set_x(rx + 5)
        pdf.multi_cell(col_w - 6, 2.5, _safe(rec))

        line_h = ry + 2.5 * (1 + len(rec) // int((col_w - 6) / 2))
        if col == 0:
            y_left = max(y_left, ry + 8)
        else:
            y_right = max(y_right, ry + 8)

    # Output
    pdf_bytes = pdf.output()
    return Response(
        bytes(pdf_bytes), mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="loglens-report-{rpt_id}.pdf"'}
    )


def _json_report(job_id, job, summary):
    import json as _json
    return _json.dumps({
        "file": job.get("originalName"),
        "job_id": job_id,
        "generated": datetime.utcnow().isoformat() + "Z",
        "totalRequests": summary["totalRequests"],
        "totalAttacks": summary["totalAttacks"],
        "malformedLines": summary["malformedLines"],
        "uniqueAttackerIps": summary["uniqueAttackerIps"],
        "threatScoring": summary.get("threatScoring", {}),
        "severityBreakdown": summary["severityBreakdown"],
        "byType": summary["byType"],
        "byCountry": summary["byCountry"],
        "topAttackers": summary["topAttackers"],
        "correlationFindings": summary.get("correlationFindings", []),
        "timeline": summary["timeline"],
        "recentFindings": summary["recentFindings"],
    }, indent=2)
