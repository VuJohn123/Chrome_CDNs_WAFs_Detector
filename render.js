// Render.com Provider  v9.1 (new in this build)
// Confidence notes: Render's own infra-added response headers are not
// well-documented publicly (community threads mention Render not adding
// much beyond what your app sets, and occasional CORS-header omissions).
// Detection here is intentionally conservative and leans almost entirely
// on the documented custom-domain pattern (CNAME to *.onrender.com), which
// IS officially documented and stable, rather than guessing at header names.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'render', name: 'Render', color: '#46e3b7', icon: '🎨',

  knownHeaders: [
    'x-render-origin-server',
  ],
  productType: 'App/static hosting (not a traditional CDN)',

  freshSignals: () => ({
    renderCname: false,
    renderHeaderHeuristic: false, // unconfirmed — low weight only
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';
    // Not independently verified — kept as a weak corroborator only.
    if (/render/i.test(hR('server')) || /render/i.test(hR('x-render-origin-server'))) {
      s.renderHeaderHeuristic = true;
    }
  },

  probes: [],

  cnamePatterns: [
    { re: /\.onrender\.com$/, signal: 'renderCname' },
  ],
  ptrPatterns: [],
  orgNames: ['render', 'render services'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.renderCname)             n = Math.max(n, 88); // documented official CNAME target
    if (s.renderHeaderHeuristic)   n += 10;
    if (s.ipEvidenceMatch)         n += 10;
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Likely Render';
    else if (n >= 45) label = 'Possible Render';
    else if (n >= 22) label = 'Weak Render Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
