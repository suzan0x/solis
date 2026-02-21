# builds the standalone HTML report from scan results
# all styling is inline so the file works without any external deps

import os
import datetime


def generate_report(results, output_dir="reports", comparison=None):
    """Generate a clean, corporate HTML security report."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f"solis_report_{ts}.html")

    score = results.get('score', {})
    system = results.get('system', {})
    security = results.get('security', {})
    processes = results.get('processes', {})
    network = results.get('network', {})
    updates = results.get('updates', {})
    software = results.get('software', {})
    startup = results.get('startup', {})
    users = results.get('users', {})
    disks = results.get('disks', {})
    usb = results.get('usb', {})
    findings = results.get('findings', [])
    scan_time = results.get('scan_time', 'N/A')

    score_val = score.get('value', 0)
    grade = score.get('grade', '?')

    crit = len([f for f in findings if f['severity'] == 'critical'])
    high = len([f for f in findings if f['severity'] == 'high'])
    med = len([f for f in findings if f['severity'] == 'medium'])
    low = len([f for f in findings if f['severity'] == 'low'])
    total_issues = crit + high + med + low
    passed = len([s for s in score.get('details', []) if s['passed']])
    failed = len([s for s in score.get('details', []) if not s['passed']])

    # Score bar color
    if score_val >= 80:
        score_color = '#22c55e'
        score_label = 'Bon'
    elif score_val >= 60:
        score_color = '#f59e0b'
        score_label = 'Moyen'
    else:
        score_color = '#ef4444'
        score_label = 'Critique'

    # Findings rows with recommendations
    findings_html = ""
    sev_cls = {'critical': 'sev-crit', 'high': 'sev-high', 'medium': 'sev-med', 'low': 'sev-low', 'info': 'sev-info'}
    sev_labels = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info'}
    for idx, f in enumerate(sorted(findings, key=lambda x: ['critical','high','medium','low','info'].index(x['severity']))):
        cls = sev_cls.get(f['severity'], 'sev-info')
        lab = sev_labels.get(f['severity'], '?')
        mitre = f'<code class="mitre">{f["mitre"]}</code>' if f.get('mitre') else ''
        rec = f.get('recommendation', {})
        rec_html = ''
        if rec:
            steps_html = ''.join(f'<li>{s}</li>' for s in rec.get('steps', []))
            cmd_html = f'<div class="rec-cmd"><span class="text-muted">PowerShell :</span><code>{rec["command"]}</code></div>' if rec.get('command') else ''
            rec_html = f'''<tr class="rec-row" id="rec-{idx}" style="display:none"><td colspan="4">
                <div class="rec-box">
                    <div class="rec-title">{rec.get('summary','')}</div>
                    <div class="rec-risk">{rec.get('risk','')}</div>
                    <ol class="rec-steps">{steps_html}</ol>
                    {cmd_html}
                </div>
            </td></tr>'''
        toggle = f' <button class="rec-toggle" onclick="toggleRec({idx})">Fix ▸</button>' if rec else ''
        findings_html += f'<tr><td><span class="badge {cls}">{lab}</span></td><td><strong>{f["title"]}</strong>{toggle}<br><span class="text-muted">{f["detail"]}</span></td><td>{f.get("category","")}</td><td>{mitre}</td></tr>{rec_html}'

    # Comparison section
    comp_html = ''
    if comparison:
        delta = comparison.get('score_delta', 0)
        arrow = '\u2191' if delta > 0 else '\u2193' if delta < 0 else '\u2192'
        delta_cls = 'val-ok' if delta > 0 else 'val-crit' if delta < 0 else ''
        resolved_rows = ''.join(f'<tr><td><span class="check-pass">✓</span></td><td>{r["title"]}</td></tr>' for r in comparison.get('resolved', []))
        new_rows = ''.join(f'<tr><td><span class="check-fail">✗</span></td><td>{r["title"]}</td></tr>' for r in comparison.get('new_issues', []))
        change_rows = ''
        for ch in comparison.get('check_changes', []):
            was = '✓' if ch['was'] else '✗'
            now = '✓' if ch['now'] else '✗'
            now_cls = 'check-pass' if ch['now'] else 'check-fail'
            change_rows += f'<tr><td>{ch["check"]}</td><td>{was}</td><td><span class="{now_cls}">{now}</span></td></tr>'
        comp_html = f'''<div class="section open">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Comparison with previous scan</div>
        <div class="section-count">{comparison.get('previous_time','?')}</div>
    </div>
    <div class="section-body">
        <div class="info-grid" style="margin-bottom:16px">
            <div class="info-item"><div class="info-label">Previous Score</div><div class="info-value">{comparison.get('score_prev',0)}</div></div>
            <div class="info-item"><div class="info-label">Current Score</div><div class="info-value">{comparison.get('score_curr',0)}</div></div>
            <div class="info-item"><div class="info-label">Change</div><div class="info-value {delta_cls}">{arrow} {"+" if delta>0 else ""}{delta} points</div></div>
            <div class="info-item"><div class="info-label">Issues Resolved</div><div class="info-value val-ok">{len(comparison.get('resolved',[]))}</div></div>
        </div>
        {f'<div class="sub-title">Resolved Issues</div><table><tr><th style="width:40px"></th><th>Description</th></tr>{resolved_rows}</table>' if resolved_rows else ''}
        {f'<div class="sub-title">New Issues</div><table><tr><th style="width:40px"></th><th>Description</th></tr>{new_rows}</table>' if new_rows else ''}
        {f'<div class="sub-title">Status Changes</div><table><tr><th>Check</th><th>Before</th><th>Now</th></tr>{change_rows}</table>' if change_rows else ''}
        {"<div class='empty-state'>No changes detected since last scan.</div>" if not resolved_rows and not new_rows and not change_rows else ''}
    </div>
</div>'''

    # Score checks
    checks_html = ""
    for s in score.get('details', []):
        icon_cls = 'check-pass' if s['passed'] else 'check-fail'
        icon = '✓' if s['passed'] else '✗'
        checks_html += f'<tr><td><span class="{icon_cls}">{icon}</span></td><td>{s["check"]}</td><td class="text-right">{s["points"]}/{s["max_points"]}</td></tr>'

    # Processes
    proc_rows = ""
    for p in processes.get('top', [])[:20]:
        proc_rows += f'<tr><td class="mono">{p["pid"]}</td><td>{p["name"]}</td><td>{p["cpu"]}%</td><td>{p["memory"]}%</td><td>{p["user"]}</td></tr>'

    # Open ports
    ports_rows = ""
    for p in network.get('open_ports', []):
        cls = ' class="row-warn"' if p.get('suspicious') else ''
        ports_rows += f'<tr{cls}><td class="mono">{p["port"]}</td><td>{p["service"]}</td><td>{p["process"]}</td></tr>'

    # ARP devices
    dev_rows = ""
    for d in network.get('devices', []):
        dev_rows += f'<tr><td>{d["ip"]}</td><td class="mono">{d["mac"]}</td><td>{d["type"]}</td></tr>'

    # Software
    sw_rows = ""
    for s in software.get('list', [])[:60]:
        sw_rows += f'<tr><td>{s["name"]}</td><td>{s["version"]}</td><td class="text-muted">{s["publisher"]}</td></tr>'

    # Startup
    start_rows = ""
    for s in startup.get('list', []):
        start_rows += f'<tr><td>{s["name"]}</td><td class="mono cell-truncate">{s["command"][:90]}</td><td>{s["location"]}</td></tr>'

    # Users
    users_rows = ""
    for u in users.get('list', []):
        badge = '<span class="badge sev-high">Admin</span>' if u.get('is_admin') else ''
        enabled = '<span class="check-pass">●</span>' if u.get('enabled') else '<span class="text-muted">●</span>'
        pwd = '<span class="check-pass">✓</span>' if u.get('pwd_required') else '<span class="check-fail">✗</span>'
        users_rows += f'<tr><td>{enabled} {u["name"]} {badge}</td><td>{pwd}</td><td>{u.get("last_logon","—")}</td><td class="text-muted">{u.get("desc","")}</td></tr>'

    # Disks
    disk_rows = ""
    bitlocker = disks.get('bitlocker', {})
    for d in disks.get('partitions', []):
        pct = d['percent']
        bar_cls = 'bar-ok' if pct < 80 else 'bar-warn' if pct < 95 else 'bar-crit'
        bl = bitlocker.get(d['mount'], {})
        bl_txt = '<span class="check-pass">Active</span>' if bl.get('protected') else '<span class="text-muted">No</span>' if bl else '<span class="text-muted">—</span>'
        disk_rows += f'<tr><td class="mono">{d["mount"]}</td><td>{d["fs"]}</td><td>{d["used"]} / {d["total"]} GB</td><td><div class="bar-bg"><div class="bar-fill {bar_cls}" style="width:{pct}%"></div></div><span class="text-muted">{pct}%</span></td><td>{bl_txt}</td></tr>'

    # Updates
    upd_rows = ""
    for u in updates.get('list', []):
        upd_rows += f'<tr><td class="mono">{u["id"]}</td><td>{u["desc"]}</td><td>{u["date"]}</td></tr>'

    # USB
    usb_rows = ""
    for d in usb.get('devices', []):
        usb_rows += f'<tr><td>{d["vendor"]}</td><td>{d["product"]}</td><td class="mono">{d["serial"]}</td></tr>'

    # Firewall
    fw_rows = ""
    for name, enabled in security.get('firewall', {}).items():
        ico = '<span class="check-pass">✓</span>' if enabled else '<span class="check-fail">✗</span>'
        fw_rows += f'<tr><td>{ico}</td><td>{name}</td><td>{"Enabled" if enabled else "Disabled"}</td></tr>'

    # Security summary items
    def sec_row(label, val, ok='Enabled', bad='Disabled'):
        if val is True:
            return f'<tr><td><span class="check-pass">✓</span></td><td>{label}</td><td>{ok}</td></tr>'
        elif val is False:
            return f'<tr><td><span class="check-fail">✗</span></td><td>{label}</td><td class="text-danger">{bad}</td></tr>'
        return f'<tr><td><span class="text-muted">—</span></td><td>{label}</td><td class="text-muted">N/A</td></tr>'

    sec_table = sec_row('Windows Defender', security.get('defender'))
    sec_table += sec_row('Real-time Protection', security.get('realtime'))
    sec_table += sec_row("UAC", security.get('uac'))
    sec_table += sec_row("Secure Boot", security.get('secure_boot'))

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOLIS — Security Report | {system.get("hostname","")}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Reset & Base ─────────────────────────────── */
*{{margin:0;padding:0;box-sizing:border-box}}
body{{
    font-family:'Inter',system-ui,-apple-system,sans-serif;
    background:#111;color:#e5e5e5;line-height:1.5;
    font-size:14px;-webkit-font-smoothing:antialiased;
}}
a{{color:#3b82f6;text-decoration:none}}

/* ── Layout ───────────────────────────────────── */
.wrap{{max-width:1100px;margin:0 auto;padding:0 24px}}

/* ── Header ───────────────────────────────────── */
.header{{
    background:#0a0a0a;border-bottom:1px solid #222;
    padding:20px 0;
}}
.header-inner{{
    display:flex;align-items:center;justify-content:space-between;
}}
.brand{{display:flex;align-items:center;gap:12px}}
.brand-icon{{
    width:36px;height:36px;background:#fff;border-radius:8px;
    display:flex;align-items:center;justify-content:center;
    font-weight:700;font-size:16px;color:#111;
}}
.brand-text{{font-size:18px;font-weight:700;color:#fff;letter-spacing:1px}}
.brand-sub{{font-size:11px;color:#666;letter-spacing:0.5px}}
.header-meta{{display:flex;gap:24px;font-size:12px;color:#666}}
.header-meta span{{display:flex;align-items:center;gap:4px}}

/* ── Summary Bar ──────────────────────────────── */
.summary{{
    display:grid;grid-template-columns:280px 1fr;gap:24px;
    padding:24px 0;
}}
.score-card{{
    background:#161616;border:1px solid #222;border-radius:10px;
    padding:28px;text-align:center;
}}
.score-value{{
    font-size:64px;font-weight:700;color:{score_color};
    line-height:1;margin-bottom:2px;
}}
.score-max{{font-size:14px;color:#666;margin-bottom:8px}}
.score-grade{{
    display:inline-block;padding:4px 16px;border-radius:6px;
    font-size:13px;font-weight:600;letter-spacing:1px;
    background:{score_color}18;color:{score_color};
    border:1px solid {score_color}33;
}}
.score-bar-wrap{{margin-top:16px}}
.score-bar-bg{{
    height:6px;background:#222;border-radius:3px;overflow:hidden;
}}
.score-bar-fill{{
    height:100%;border-radius:3px;background:{score_color};
    width:0%;animation:fillBar 1s ease forwards;
}}
@keyframes fillBar{{to{{width:{score_val}%}}}}
.score-label{{font-size:12px;color:#666;margin-top:6px}}

.kpi-grid{{
    display:grid;grid-template-columns:repeat(4,1fr);gap:12px;
    align-content:start;
}}
.kpi{{
    background:#161616;border:1px solid #222;border-radius:10px;
    padding:20px;
}}
.kpi-val{{font-size:28px;font-weight:700;color:#fff;line-height:1;margin-bottom:4px}}
.kpi-label{{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:0.5px}}
.kpi-val.val-crit{{color:#ef4444}}
.kpi-val.val-warn{{color:#f59e0b}}
.kpi-val.val-ok{{color:#22c55e}}

/* ── Accordion Sections ───────────────────────── */
.section{{
    background:#161616;border:1px solid #222;border-radius:10px;
    margin-bottom:12px;overflow:hidden;
}}
.section-head{{
    display:flex;align-items:center;padding:16px 20px;
    cursor:pointer;user-select:none;gap:12px;
    transition:background 0.15s;
}}
.section-head:hover{{background:#1a1a1a}}
.section-chevron{{
    width:20px;height:20px;display:flex;align-items:center;
    justify-content:center;transition:transform 0.25s ease;
    color:#555;flex-shrink:0;
}}
.section-chevron svg{{width:14px;height:14px}}
.section.open .section-chevron{{transform:rotate(90deg)}}
.section-title{{flex:1;font-size:14px;font-weight:600;color:#fff}}
.section-count{{
    font-size:12px;color:#666;background:#222;
    padding:2px 10px;border-radius:10px;font-weight:500;
}}
.section-body{{
    display:none;padding:0 20px 20px;
    border-top:1px solid #1e1e1e;
}}
.section.open .section-body{{display:block}}

/* ── Tables ───────────────────────────────────── */
table{{width:100%;border-collapse:collapse}}
th{{
    text-align:left;padding:8px 10px;font-size:11px;
    color:#666;font-weight:600;text-transform:uppercase;
    letter-spacing:0.5px;border-bottom:1px solid #222;
    background:#111;position:sticky;top:0;
}}
td{{padding:7px 10px;border-bottom:1px solid #1a1a1a;font-size:13px;vertical-align:top}}
tr:hover td{{background:#1a1a1a}}
.text-right{{text-align:right}}
.text-muted{{color:#555}}
.text-danger{{color:#ef4444}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:12px}}
.cell-truncate{{max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.row-warn td{{background:rgba(239,68,68,0.05)}}

/* ── Badges & Icons ───────────────────────────── */
.badge{{
    display:inline-block;padding:2px 8px;border-radius:4px;
    font-size:11px;font-weight:600;white-space:nowrap;
}}
.sev-crit{{background:#ef444420;color:#ef4444;border:1px solid #ef444433}}
.sev-high{{background:#f9731620;color:#f97316;border:1px solid #f9731633}}
.sev-med{{background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b33}}
.sev-low{{background:#3b82f620;color:#3b82f6;border:1px solid #3b82f633}}
.sev-info{{background:#64748b20;color:#94a3b8;border:1px solid #64748b33}}
.check-pass{{color:#22c55e;font-weight:700}}
.check-fail{{color:#ef4444;font-weight:700}}
.mitre{{
    font-family:'JetBrains Mono',monospace;font-size:11px;
    padding:2px 6px;background:#222;border-radius:3px;color:#94a3b8;
}}

/* ── Progress Bars ────────────────────────────── */
.bar-bg{{
    display:inline-block;width:80px;height:5px;
    background:#222;border-radius:3px;overflow:hidden;
    vertical-align:middle;margin-right:6px;
}}
.bar-fill{{height:100%;border-radius:3px}}
.bar-ok{{background:#22c55e}}
.bar-warn{{background:#f59e0b}}
.bar-crit{{background:#ef4444}}

/* ── Sub-headings inside sections ─────────────── */
.sub-title{{
    font-size:13px;font-weight:600;color:#999;
    margin:16px 0 8px;padding-bottom:6px;
    border-bottom:1px solid #1e1e1e;
    text-transform:uppercase;letter-spacing:0.5px;
}}
.sub-title:first-child{{margin-top:12px}}

/* ── Info grid ────────────────────────────────── */
.info-grid{{
    display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
    gap:1px;background:#222;border-radius:8px;overflow:hidden;
    margin-bottom:16px;
}}
.info-item{{background:#161616;padding:14px 16px}}
.info-label{{font-size:11px;color:#555;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px}}
.info-value{{font-size:14px;font-weight:600;color:#ddd}}

/* ── Footer ───────────────────────────────────── */
.footer{{
    padding:24px 0;margin-top:24px;border-top:1px solid #1e1e1e;
    text-align:center;font-size:12px;color:#444;
}}

/* ── No-findings state ────────────────────────── */
.empty-state{{padding:24px;text-align:center;color:#555;font-size:13px}}

/* ── Recommendations ──────────────────────────── */
.rec-toggle{{
    background:none;border:1px solid #333;color:#94a3b8;border-radius:4px;
    padding:2px 8px;font-size:11px;cursor:pointer;margin-left:8px;
    transition:all 0.15s;
}}
.rec-toggle:hover{{border-color:#555;color:#ddd}}
.rec-row td{{padding:0!important;border:none!important}}
.rec-box{{
    margin:0 10px 12px 10px;padding:16px 20px;
    background:#111;border:1px solid #1e1e1e;border-radius:8px;
    border-left:3px solid #3b82f6;
}}
.rec-title{{font-weight:600;font-size:13px;color:#ddd;margin-bottom:6px}}
.rec-risk{{font-size:12px;color:#888;margin-bottom:10px}}
.rec-steps{{margin:0 0 10px 16px;font-size:13px;color:#ccc}}
.rec-steps li{{margin-bottom:4px}}
.rec-cmd{{
    padding:8px 12px;background:#0a0a0a;border-radius:4px;
    font-size:12px;display:flex;align-items:center;gap:8px;
}}
.rec-cmd code{{
    font-family:'JetBrains Mono',monospace;color:#22c55e;
    word-break:break-all;
}}

/* ── PDF button ───────────────────────────────── */
.pdf-btn{{
    background:#fff;color:#111;border:none;padding:8px 18px;
    border-radius:6px;font-size:12px;font-weight:600;
    cursor:pointer;letter-spacing:0.5px;transition:opacity 0.15s;
}}
.pdf-btn:hover{{opacity:0.85}}

/* ── Print ────────────────────────────────────── */
@media print{{
    body{{background:#fff;color:#111}}
    .section-body{{display:block!important}}
    .header{{background:#fff;border-color:#ddd}}
    .section,.kpi,.score-card{{border-color:#ddd;background:#fff}}
    th{{background:#f5f5f5}}
    td{{border-color:#eee}}
    .pdf-btn,.rec-toggle{{display:none}}
    .rec-row{{display:table-row!important}}
    .rec-box{{border-color:#ddd;background:#f9f9f9}}
    .kpi-val{{color:#111}}
    .info-grid{{background:#ddd}}
    .info-item{{background:#fff}}
}}

@media(max-width:768px){{
    .summary{{grid-template-columns:1fr}}
    .kpi-grid{{grid-template-columns:1fr 1fr}}
    .header-meta{{display:none}}
}}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
<div class="wrap header-inner">
    <div class="brand">
        <div class="brand-icon">S</div>
        <div>
            <div class="brand-text">SOLIS</div>
            <div class="brand-sub">System Security Auditor</div>
        </div>
    </div>
    <div class="header-meta">
        <span>{scan_time}</span>
        <span>{system.get('hostname','—')}</span>
        <span>{system.get('os','—')}</span>
        <span>{'Admin' if system.get('is_admin') else 'Standard'}</span>
        <button class="pdf-btn" onclick="window.print()">Export PDF</button>
    </div>
</div>
</div>

<div class="wrap">

<!-- ── Summary ──────────────────────────────────── -->
<div class="summary">
    <div class="score-card">
        <div class="score-value">{score_val}</div>
        <div class="score-max">/ 100</div>
        <div class="score-grade">Grade {grade}</div>
        <div class="score-bar-wrap">
            <div class="score-bar-bg"><div class="score-bar-fill"></div></div>
            <div class="score-label">{score.get('earned',0)} / {score.get('total',0)} points</div>
        </div>
    </div>
    <div class="kpi-grid">
        <div class="kpi"><div class="kpi-val val-crit">{crit}</div><div class="kpi-label">Critical</div></div>
        <div class="kpi"><div class="kpi-val val-warn">{high}</div><div class="kpi-label">High</div></div>
        <div class="kpi"><div class="kpi-val{' val-ok' if med == 0 else ''}">{med}</div><div class="kpi-label">Medium</div></div>
        <div class="kpi"><div class="kpi-val val-ok">{passed}</div><div class="kpi-label">Checks OK</div></div>
        <div class="kpi"><div class="kpi-val">{processes.get('total',0)}</div><div class="kpi-label">Processes</div></div>
        <div class="kpi"><div class="kpi-val">{network.get('total_conns',0)}</div><div class="kpi-label">Connections</div></div>
        <div class="kpi"><div class="kpi-val">{len(network.get('open_ports',[]))}</div><div class="kpi-label">Open Ports</div></div>
        <div class="kpi"><div class="kpi-val">{len(network.get('devices',[]))}</div><div class="kpi-label">LAN Devices</div></div>
    </div>
</div>

{comp_html}

<!-- ── Findings ─────────────────────────────────── -->
<div class="section{' open' if findings else ''}">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Detected Issues</div>
        <div class="section-count">{total_issues}</div>
    </div>
    <div class="section-body">
        {f'<table><tr><th style="width:90px">Severity</th><th>Details</th><th>Category</th><th>MITRE ATT&CK</th></tr>{findings_html}</table>' if findings else '<div class="empty-state">No issues detected — all checks passed.</div>'}
    </div>
</div>

<!-- ── Score Details ────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Score Details</div>
        <div class="section-count">{passed} / {passed + failed}</div>
    </div>
    <div class="section-body">
        <table><tr><th style="width:40px"></th><th>Check</th><th class="text-right" style="width:80px">Points</th></tr>{checks_html}</table>
    </div>
</div>

<!-- ── Security Status ──────────────────────────── -->
<div class="section open">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">System Security</div>
    </div>
    <div class="section-body">
        <div class="sub-title">Protection</div>
        <table><tr><th style="width:40px"></th><th>Component</th><th>Status</th></tr>{sec_table}</table>
        {f'<p style="margin-top:10px;font-size:12px;color:#555">Signatures: {security.get("sig_date","—")} · Last scan: {security.get("last_scan","—")}</p>' if security.get('sig_date') else ''}
        <div class="sub-title">Windows Firewall</div>
        <table><tr><th style="width:40px"></th><th>Profile</th><th>Status</th></tr>{fw_rows}</table>
    </div>
</div>

<!-- ── System Info ──────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">System Information</div>
    </div>
    <div class="section-body">
        <div class="info-grid">
            <div class="info-item"><div class="info-label">OS</div><div class="info-value">{system.get('os','—')}</div></div>
            <div class="info-item"><div class="info-label">Version</div><div class="info-value">{system.get('os_version','—')}</div></div>
            <div class="info-item"><div class="info-label">Edition</div><div class="info-value">{system.get('os_edition','—')}</div></div>
            <div class="info-item"><div class="info-label">Architecture</div><div class="info-value">{system.get('architecture','—')}</div></div>
            <div class="info-item"><div class="info-label">CPU</div><div class="info-value">{system.get('cpu_cores','—')}C / {system.get('cpu_threads','—')}T</div></div>
            <div class="info-item"><div class="info-label">Frequency</div><div class="info-value">{system.get('cpu_freq','—')} MHz</div></div>
            <div class="info-item"><div class="info-label">RAM</div><div class="info-value">{system.get('ram_used','—')} / {system.get('ram_total','—')} GB ({system.get('ram_percent','—')}%)</div></div>
            <div class="info-item"><div class="info-label">Uptime</div><div class="info-value">{system.get('uptime','—')}</div></div>
        </div>
    </div>
</div>

<!-- ── Processes ─────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Active Processes</div>
        <div class="section-count">{processes.get('total',0)}</div>
    </div>
    <div class="section-body">
        <p style="font-size:12px;color:#555;margin-bottom:10px">Top 20 by memory usage</p>
        <table><tr><th>PID</th><th>Process</th><th>CPU</th><th>Memory</th><th>User</th></tr>{proc_rows}</table>
    </div>
</div>

<!-- ── Network ──────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Network</div>
        <div class="section-count">{network.get('total_conns',0)} connections</div>
    </div>
    <div class="section-body">
        <div class="info-grid" style="margin-bottom:16px">
            <div class="info-item"><div class="info-label">Total Connections</div><div class="info-value">{network.get('total_conns',0)}</div></div>
            <div class="info-item"><div class="info-label">Listening</div><div class="info-value">{network.get('listening',0)}</div></div>
            <div class="info-item"><div class="info-label">Established</div><div class="info-value">{network.get('established',0)}</div></div>
        </div>
        <div class="sub-title">Open Ports</div>
        <table><tr><th>Port</th><th>Service</th><th>Process</th></tr>{ports_rows}</table>
        <div class="sub-title">LAN Devices</div>
        <table><tr><th>IP Address</th><th>MAC Address</th><th>Type</th></tr>{dev_rows}</table>
    </div>
</div>

<!-- ── Disks ─────────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Storage & Encryption</div>
    </div>
    <div class="section-body">
        <table><tr><th>Volume</th><th>FS</th><th>Space</th><th>Usage</th><th>BitLocker</th></tr>{disk_rows}</table>
    </div>
</div>

<!-- ── Users ─────────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">User Accounts</div>
        <div class="section-count">{users.get('total',0)} accounts · {users.get('admins',0)} admin(s)</div>
    </div>
    <div class="section-body">
        <table><tr><th>Account</th><th>Password</th><th>Last Login</th><th>Description</th></tr>{users_rows}</table>
    </div>
</div>

<!-- ── Updates ───────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Windows Updates</div>
        <div class="section-count">Build {updates.get('build','—')}</div>
    </div>
    <div class="section-body">
        <table><tr><th>KB</th><th>Type</th><th>Date</th></tr>{upd_rows}</table>
    </div>
</div>

<!-- ── Startup ───────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Startup Programs</div>
        <div class="section-count">{startup.get('total',0)}</div>
    </div>
    <div class="section-body">
        <table><tr><th>Name</th><th>Command</th><th>Location</th></tr>{start_rows}</table>
    </div>
</div>

<!-- ── Software ──────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Installed Software</div>
        <div class="section-count">{software.get('total',0)}</div>
    </div>
    <div class="section-body">
        <table><tr><th>Name</th><th>Version</th><th>Publisher</th></tr>{sw_rows}</table>
    </div>
</div>

<!-- ── USB ────────────────────────────────────────── -->
<div class="section">
    <div class="section-head" onclick="toggleSection(this)">
        <div class="section-chevron"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5l7 7-7 7"/></svg></div>
        <div class="section-title">Historique USB</div>
        <div class="section-count">{usb.get('total',0)}</div>
    </div>
    <div class="section-body">
        <table><tr><th>Vendor</th><th>Product</th><th>Serial Number</th></tr>{usb_rows}</table>
    </div>
</div>

</div><!-- /wrap -->

<div class="footer">
    <div class="wrap">
        SOLIS v1.0.0 · Report generated {scan_time} · {system.get('hostname','—')}
    </div>
</div>

<script>
function toggleSection(head){{
    head.parentElement.classList.toggle('open');
}}
function toggleRec(idx){{
    var row=document.getElementById('rec-'+idx);
    if(row){{row.style.display=row.style.display==='none'?'table-row':'none'}}
}}
</script>
</body>
</html>'''

    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)

    return os.path.abspath(path)
