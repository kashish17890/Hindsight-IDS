"""Report builder: one block model rendered to PDF, Word, HTML, Markdown, JSON or CSV."""
import csv, io, json
from xml.sax.saxutils import escape as X


def blocks(res, evs, inc_id=0):
    S = res["summary"]; incs = [i for i in res["incidents"] if inc_id in (0, i["id"])]
    B = [("h1", "Security incident report" if inc_id == 0 else f"Incident #{inc_id} report"),
         ("p", f"Period analysed: {S['span']}. {S['events']:,} events checked, {S['alerts']} warnings raised, {len(res['incidents'])} incident(s) found, {S['suppressed']} look-alikes cleared as harmless.")]
    if not incs: B.append(("p", "No incidents were found in this data."))
    for inc in incs:
        al = [res["alerts"][i] for i in inc["alerts"]]
        B += [("h2", f"Incident #{inc['id']}: {inc['title']}"), ("p", f"Severity: {inc['severity']}. Confidence: {round(inc['confidence'] * 100)}%. Window: {inc['start']} to {inc['end']} (UTC)."),
              ("h3", "What happened (plain English)"), ("p", inc["plain"]), ("h3", "What to do now"), ("ul", inc["actions"]),
              ("h3", "Why we believe this"), ("ul", inc["factors"]),
              ("h3", "Timeline"), ("table", ["Time (UTC)", "What happened", "Severity", "MITRE"], [[a["ts"], a["why"], a["severity"], a["mitre"]] for a in al]),
              ("h3", "Evidence (sample of raw log lines)"),
              ("table", ["Time", "Host", "User", "IP", "Event", "Detail"],
               [[e["ts"], e["host"], e["user"], e["ip"], f"{e['event']} {e['outcome']}".strip(), e["detail"] or (f"{e['bytes']:,} bytes" if e["bytes"] else "")]
                for a in al for e in [evs[i] for i in a["evidence"][:3]]][:18])]
    return B


def to_md(B):
    o = []
    for b in B:
        if b[0] in ("h1", "h2", "h3"): o.append("#" * int(b[0][1]) + " " + b[1])
        elif b[0] == "p": o.append(b[1])
        elif b[0] == "ul": o += [f"- {x}" for x in b[1]]
        else: o += ["| " + " | ".join(b[1]) + " |", "|" + "---|" * len(b[1])] + ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in b[2]]
        o.append("")
    return "\n".join(o).encode()


def to_html(B):
    o = ["<!doctype html><meta charset=utf-8><title>Incident report</title><style>body{font:15px/1.5 Segoe UI,sans-serif;max-width:900px;margin:30px auto;color:#222;padding:0 16px}h1,h2{color:#434777}h3{color:#534789}table{border-collapse:collapse;width:100%;font-size:12px}th{background:#405580;color:#fff;text-align:left}td,th{border:1px solid #ccd;padding:4px 6px;vertical-align:top}</style>"]
    for b in B:
        if b[0] in ("h1", "h2", "h3"): o.append(f"<{b[0]}>{X(b[1])}</{b[0]}>")
        elif b[0] == "p": o.append(f"<p>{X(b[1])}</p>")
        elif b[0] == "ul": o.append("<ul>" + "".join(f"<li>{X(x)}</li>" for x in b[1]) + "</ul>")
        else: o.append("<table><tr>" + "".join(f"<th>{X(h)}</th>" for h in b[1]) + "</tr>" + "".join("<tr>" + "".join(f"<td>{X(str(c))}</td>" for c in r) + "</tr>" for r in b[2]) + "</table>")
    return "".join(o).encode()


def to_pdf(B):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
    st = getSampleStyleSheet(); cell = ParagraphStyle("c", parent=st["BodyText"], fontSize=7, leading=8.5)
    buf = io.BytesIO(); doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    F = []
    for b in B:
        if b[0] in ("h1", "h2", "h3"): F += [Paragraph(X(b[1]), st["Heading" + b[0][1]]), Spacer(1, 3)]
        elif b[0] == "p": F += [Paragraph(X(b[1]), st["BodyText"]), Spacer(1, 4)]
        elif b[0] == "ul": F += [ListFlowable([ListItem(Paragraph(X(x), st["BodyText"])) for x in b[1]], bulletType="bullet"), Spacer(1, 4)]
        else:
            w = doc.width / len(b[1]); data = [[Paragraph(f"<b>{X(h)}</b>", cell) for h in b[1]]] + [[Paragraph(X(str(c)), cell) for c in r] for r in b[2]]
            t = Table(data, colWidths=[w * 0.9, w * 1.6, w * 0.7, w * 0.7][:len(b[1])] if len(b[1]) == 4 else None, repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#405580")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#99a"))]))
            F += [t, Spacer(1, 6)]
    doc.build(F); return buf.getvalue()


def to_docx(B):
    from docx import Document
    d = Document()
    for b in B:
        if b[0] in ("h1", "h2", "h3"): d.add_heading(b[1], int(b[0][1]) - 1)
        elif b[0] == "p": d.add_paragraph(b[1])
        elif b[0] == "ul":
            for x in b[1]: d.add_paragraph(x, style="List Bullet")
        else:
            t = d.add_table(rows=1, cols=len(b[1])); t.style = "Light Grid Accent 1"
            for i, h in enumerate(b[1]): t.rows[0].cells[i].text = h
            for r in b[2]:
                cs = t.add_row().cells
                for i, c in enumerate(r): cs[i].text = str(c)
    buf = io.BytesIO(); d.save(buf); return buf.getvalue()


def render(res, evs, inc_id, fmt):
    if fmt == "json":
        incs = [i for i in res["incidents"] if inc_id in (0, i["id"])]
        return json.dumps(dict(summary=res["summary"], incidents=incs, alerts=[res["alerts"][a] for i in incs for a in i["alerts"]]), indent=2).encode(), "application/json"
    if fmt == "csv":
        incs = [i for i in res["incidents"] if inc_id in (0, i["id"])]; buf = io.StringIO(); w = csv.writer(buf)
        w.writerow(["incident", "time", "severity", "rule", "mitre", "ip", "user", "host", "what_happened"])
        for i in incs:
            for a in (res["alerts"][x] for x in i["alerts"]): w.writerow([i["id"], a["ts"], a["severity"], a["rule"], a["mitre"], a["ip"], a["user"], a["host"], a["why"]])
        return buf.getvalue().encode(), "text/csv"
    B = blocks(res, evs, inc_id)
    return {"md": (to_md, "text/markdown"), "html": (to_html, "text/html"), "pdf": (to_pdf, "application/pdf"),
            "docx": (to_docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}[fmt][0](B), \
           {"md": "text/markdown", "html": "text/html", "pdf": "application/pdf", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}[fmt]
