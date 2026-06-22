// CDN/WAF Detector — crowd-sourced signature report collector
// Deploy with: wrangler deploy   (see README.md in this folder)
//
// Receives anonymous { providerId, unknownHeaderNames|notes, engineVersion }
// payloads from extension installs that opted in (Settings → Crowd-sourced
// signatures). No domain, IP, or any other identifying field is ever sent
// by the extension client — see background.js maybeSubmitCrowdReport().
//
// Storage: a single KV namespace, bound as REPORTS in wrangler.toml.
// Each report is appended to a per-provider list capped at MAX_PER_PROVIDER
// most-recent entries, so the namespace can't grow unbounded.

const MAX_PER_PROVIDER = 500;
const MAX_NOTE_LENGTH  = 300;

function cors(resp) {
  resp.headers.set('Access-Control-Allow-Origin', '*');
  resp.headers.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  resp.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return resp;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return cors(new Response(null, { status: 204 }));

    if (request.method === 'POST' && url.pathname === '/report') {
      let body;
      try { body = await request.json(); } catch { return cors(new Response('Invalid JSON', { status: 400 })); }

      const providerId = String(body.providerId || '').slice(0, 40).replace(/[^a-z0-9_-]/gi, '');
      if (!providerId) return cors(new Response('Missing providerId', { status: 400 }));

      const notes = (body.unknownHeaderNames || []).concat(body.notes ? [body.notes] : [])
        .map(s => String(s).slice(0, MAX_NOTE_LENGTH))
        .filter(Boolean)
        .slice(0, 5); // cap how many strings one report can carry
      if (!notes.length) return cors(new Response('Empty report', { status: 400 }));

      const key = `provider:${providerId}`;
      const existingRaw = await env.REPORTS.get(key);
      const existing = existingRaw ? JSON.parse(existingRaw) : [];
      existing.unshift({ notes, engineVersion: body.engineVersion || null, ts: Date.now() });
      await env.REPORTS.put(key, JSON.stringify(existing.slice(0, MAX_PER_PROVIDER)));

      return cors(new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } }));
    }

    // Simple read endpoint so YOU (the maintainer) can review submissions —
    // not used by the extension. Consider adding your own auth before
    // exposing this publicly long-term; it's left open here for simplicity.
    if (request.method === 'GET' && url.pathname === '/reports') {
      const providerId = (url.searchParams.get('provider') || '').replace(/[^a-z0-9_-]/gi, '');
      if (!providerId) return cors(new Response('?provider= required', { status: 400 }));
      const raw = await env.REPORTS.get(`provider:${providerId}`);
      return cors(new Response(raw || '[]', { headers: { 'Content-Type': 'application/json' } }));
    }

    return cors(new Response('Not found', { status: 404 }));
  }
};
