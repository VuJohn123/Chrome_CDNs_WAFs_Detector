// CDN/WAF Detector — Crowd-sourced signature collector + Dashboard
// Deploy: wrangler deploy   (see README.md)
// KV binding: REPORTS

const MAX_PER_PROVIDER = 500;
const MAX_NOTE_LENGTH  = 300;

function withCors(resp) {
  const h = new Headers(resp.headers);
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  h.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(resp.body, { status: resp.status, headers: h });
}
const json = (data, status = 200) =>
  withCors(new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json' }
  }));
const html = (body, status = 200) =>
  new Response(body, { status, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildDashboard(data) {
  const providers = Object.keys(data).sort();
  const totalReports = Object.values(data).reduce((s, v) => s + v.length, 0);

  const rows = providers.map(pid => {
    const reports = data[pid];
    if (!reports.length) return '';
    const freq = {};
    for (const r of reports) {
      for (const note of (r.notes || [])) {
        const k = note.toLowerCase().trim();
        freq[k] = (freq[k] || 0) + 1;
      }
    }
    const sorted = Object.entries(freq).sort((a,b) => b[1]-a[1]).slice(0, 20);
    const noteRows = sorted.map(([note, count]) =>
      `<tr><td>${escHtml(note)}</td><td class="num">${count}</td></tr>`
    ).join('');
    return `
      <section>
        <h2>${escHtml(pid)} <span class="badge">${reports.length} reports</span></h2>
        <table><thead><tr><th>Note</th><th>Count</th></tr></thead>
        <tbody>${noteRows || '<tr><td colspan="2" class="empty">No text notes yet</td></tr>'}</tbody></table>
      </section>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CDN/WAF Detector — Crowd Report Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d111a;color:#dde4f0;padding:32px;font-size:13px;line-height:1.55}
  h1{font-size:22px;font-weight:700;color:#e2e8f0;margin-bottom:6px}
  .meta{color:#6b7a95;font-size:11.5px;margin-bottom:28px}
  section{background:#131922;border:1px solid #1e2a3a;border-radius:10px;padding:18px 20px;margin-bottom:16px}
  h2{font-size:14px;font-weight:700;color:#c8d6f0;margin-bottom:12px;display:flex;align-items:center;gap:10px}
  .badge{font-size:10px;background:#1e2a3a;color:#8694a8;padding:2px 9px;border-radius:20px;font-weight:400}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:7px 10px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#4a5a70;border-bottom:1px solid #1e2a3a}
  td{padding:7px 10px;border-bottom:1px solid #131922;font-size:11.5px;color:#8694a8;word-break:break-all}
  td:first-child{color:#c8d6f0}
  .num{text-align:right;font-family:monospace;color:#1ed4ff!important;font-weight:600}
  .empty{color:#4a5a70;font-style:italic;text-align:center;padding:12px}
  .stats{display:flex;gap:20px;margin-bottom:24px}
  .stat{background:#131922;border:1px solid #1e2a3a;border-radius:8px;padding:12px 18px}
  .stat-n{font-size:26px;font-weight:700;color:#1ed4ff;font-family:monospace}
  .stat-l{font-size:10px;color:#4a5a70;margin-top:2px;text-transform:uppercase;letter-spacing:.5px}
  .empty-state{color:#4a5a70;font-style:italic;padding:20px 0;text-align:center}
</style>
</head>
<body>
<h1>CDN/WAF Detector — Crowd Reports</h1>
<div class="meta">Anonymous signal submissions from opted-in extension installs. Use these to spot new provider signatures.<br>
Endpoint: <code>POST /report</code> · Review: <code>GET /reports?provider=ID</code> · Add auth before making this public.</div>
<div class="stats">
  <div class="stat"><div class="stat-n">${providers.length}</div><div class="stat-l">Providers with reports</div></div>
  <div class="stat"><div class="stat-n">${totalReports}</div><div class="stat-l">Total submissions</div></div>
</div>
${rows || '<div class="empty-state">No reports yet. Enable crowd reporting in the extension Settings and set this worker\'s URL as the endpoint.</div>'}
</body></html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }));

    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/dashboard')) {
      try {
        const keys  = await env.REPORTS.list();
        const data  = {};
        await Promise.all(keys.keys.map(async k => {
          const pid = k.name.replace(/^provider:/, '');
          const raw = await env.REPORTS.get(k.name);
          data[pid] = raw ? JSON.parse(raw) : [];
        }));
        return html(buildDashboard(data));
      } catch (e) {
        return html(`<pre>Error: ${e.message}</pre>`, 500);
      }
    }

    if (request.method === 'POST' && url.pathname === '/report') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      const providerId = String(body.providerId || '').slice(0, 40).replace(/[^a-z0-9_-]/gi, '');
      if (!providerId) return json({ error: 'Missing providerId' }, 400);
      const notes = [
        ...(Array.isArray(body.unknownHeaderNames) ? body.unknownHeaderNames : []),
        ...(body.notes ? [body.notes] : [])
      ].map(s => String(s).slice(0, MAX_NOTE_LENGTH)).filter(Boolean).slice(0, 5);
      if (!notes.length) return json({ error: 'Empty report' }, 400);
      const key      = `provider:${providerId}`;
      const existing = JSON.parse(await env.REPORTS.get(key) || '[]');
      existing.unshift({ notes, engineVersion: body.engineVersion || null, ts: Date.now() });
      await env.REPORTS.put(key, JSON.stringify(existing.slice(0, MAX_PER_PROVIDER)));
      return json({ ok: true });
    }

    if (request.method === 'GET' && url.pathname === '/reports') {
      const pid = (url.searchParams.get('provider') || '').replace(/[^a-z0-9_-]/gi, '');
      if (!pid) return json({ error: '?provider= required' }, 400);
      const raw = await env.REPORTS.get(`provider:${pid}`);
      return json(raw ? JSON.parse(raw) : []);
    }

    return json({ error: 'Not found' }, 404);
  }
};
