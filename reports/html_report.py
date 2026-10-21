"""Print-friendly, escaped report built exclusively from stored evidence."""

from html import escape


def render_run_report(run):
    def text(value):
        return escape(str(value if value is not None else "N/A"))

    def percent(value):
        return "N/A" if value is None else f"{value * 100:.1f}%"

    sections = []
    for name, arm in run["arms"].items():
        m = arm["metrics"]
        metrics = [
            ("System ASR", percent(m["attack_success_rate"])),
            (
                "Robustness",
                percent(
                    None
                    if m["robustness_score"] is None
                    else m["robustness_score"] / 100
                ),
            ),
            ("Benign false positives", percent(m["false_positive_rate"])),
            ("Scored attacks", m["scored_attacks"]),
            ("Errors / inconclusive", f"{m['errors']} / {m['inconclusive']}"),
        ]
        cards = "".join(
            f"<div><small>{text(label)}</small><strong>{text(value)}</strong></div>"
            for label, value in metrics
        )
        rows = "".join(
            f"<tr><td>{text(r['test_case']['id'])}<small>{text(r['test_case']['name'])}</small></td>"
            f"<td>{text(r['verdict'])}</td><td>{text(r['defense_layer_triggered'])}</td>"
            f"<td>{text('; '.join(r['evidence']) or r['error'] or r['notes'])}</td></tr>"
            for r in arm["results"]
        )
        sections.append(
            f"<section><h2>{text(name.title())}</h2><div class='metrics'>{cards}</div><table><thead><tr><th>Probe</th><th>Outcome</th><th>Defense</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></section>"
        )
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Security Lab · Demo report</title>
<style>body{max-width:1100px;margin:48px auto;padding:24px;font:13px/1.7 system-ui;color:#17251f}header{border-bottom:2px solid #294c36;padding-bottom:25px}h1{font-size:32px;letter-spacing:-1px}h2{margin-top:38px}small{display:block;color:#6c7c70;font-size:10px}p,code{overflow-wrap:anywhere}.notice{padding:16px;background:#edf4e5;border:1px solid #d6e3cc}.metrics{display:flex;gap:14px;margin:20px 0}.metrics div{flex:1;padding:16px;border:1px solid #dfe6dc;border-radius:8px}.metrics strong{display:block;font-size:23px;margin-top:10px;font-weight:500}table{border-collapse:collapse;width:100%;font-size:11px}th,td{text-align:left;border-bottom:1px solid #dfe6dc;padding:12px;vertical-align:top;overflow-wrap:anywhere}th{background:#f4f7ef}button{padding:10px 20px;background:#17251f;color:white;border:0;border-radius:6px;cursor:pointer}footer{margin-top:35px;border-top:1px solid #dfe6dc;padding-top:15px;color:#6c7c70}@media print{button{display:none}body{margin:0;padding:0}thead{display:table-header-group}tr,.metrics{break-inside:avoid}@page{size:A4;margin:15mm}}@media(max-width:700px){.metrics{flex-wrap:wrap}.metrics div{min-width:100px}body{margin:10px;padding:12px}table{font-size:9px}th,td{padding:6px}}</style></head><body>""" + (
        f"<header><small>AI SECURITY LAB / OFFLINE DEMO</small><h1>Security evaluation report</h1>"
        f"<p class='notice'>{text(run['notice'])}</p><p><strong>Run:</strong> {text(run['id'])}<br>"
        f"<strong>Status:</strong> {text(run['status'])} · {run['completed']} / {run['planned']} executions<br>"
        f"<strong>Target:</strong> {text(run['config']['provider'])} · {text(run['config']['profile'])} · seed {run['config']['seed']}<br>"
        f"<strong>Dataset SHA256:</strong> <code>{text(run['dataset_sha256'])}</code><br>"
        f"<strong>Created:</strong> {text(run['created_at'])}</p><button onclick='window.print()'>Print / Save PDF</button></header>"
        + "".join(sections)
        + ("<p>No scored evidence. Metrics: N/A.</p>" if not sections else "")
        + "<footer>Errors and inconclusive results are excluded from ASR. Timings measure local processing; tokens are estimates. Tool proposals were never executed. Synthetic fixtures do not establish commercial model security or regulatory compliance. Full prompts, responses and traces are available in the JSON export.</footer></body></html>"
    )
