// PerimeterX / HUMAN Security Bot Protection Provider  v7.5 (NEW)
// ============================================================
// PerimeterX was acquired by HUMAN Security in 2022. The product is
// still commonly branded "PerimeterX" in cookies and collector domains.
// Deployed inline (module/middleware), not as a reverse-proxy CDN.
//
// Documented signals:
//   Cookies: _px, _px2, _px3, _pxvid, _pxhd, _pxcts — clearance/visitor/session triple
//     _pxvid — persistent visitor ID (up to 1 year)
//     _px3   — main "Security Token" clearance cookie (short-lived, ~60s revalidation window)
//     _pxhd  — session indicator, set via JS not Set-Cookie header
//   Header: X-PX-Authorization — required alongside _px3 for validation
//   Collector domains referenced in page body/script src:
//     collector-{id}.perimeterx.net, collector-{id}.px-cloud.net, {appId}.px-cdn.net
//   "Press & Hold" human-challenge widget text in body
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'perimeterx', name: 'PerimeterX', color: '#ff5a5f', icon: '🧩',

  knownHeaders: [
    'x-px-authorization',
  ],
  ipConfig: null,

  freshSignals: () => ({
    xPxAuthorization: false,
    pxCollectorRef: false, pxCdnRef: false,
    pxPressHoldChallenge: false, pxScriptRef: false, humanSecurityRef: false,
    cookies: { px: false, px2: false, px3: false, pxvid: false, pxhd: false, pxcts: false },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';
    if (res.headers.has('x-px-authorization')) s.xPxAuthorization = true;

    if (!body) return;
    // Collector domains — exclusive to PerimeterX/HUMAN infrastructure
    if (/collector-[\w.-]*\.(perimeterx\.net|px-cloud\.net)/i.test(body)) s.pxCollectorRef = true;
    if (/[\w-]+\.px-cdn\.net/i.test(body))                                s.pxCdnRef        = true;
    if (/press\s*(&|and)\s*hold/i.test(body))                             s.pxPressHoldChallenge = true;
    if (/\bpx\.js\b|_pxAppId|pxConfig/i.test(body))                       s.pxScriptRef     = true;
    if (/human\s*security|humansecurity\.com/i.test(body))                s.humanSecurityRef = true;
  },

  probes: [],
  cnamePatterns: [], // PerimeterX/HUMAN is inline middleware, not CNAME-based
  ptrPatterns: [
    { re: /perimeterx\.net$|px-cloud\.net$|px-cdn\.net$/, signal: 'pxCollectorRef' },
  ],
  orgNames: ['perimeterx', 'human security', 'humansecurity'],

  extractCookies(cookies, s) {
    const names = new Set(cookies.map(c => c.name));
    s.cookies.px    = names.has('_px');
    s.cookies.px2   = names.has('_px2');
    s.cookies.px3   = names.has('_px3');
    s.cookies.pxvid = names.has('_pxvid');
    s.cookies.pxhd  = names.has('_pxhd');
    s.cookies.pxcts = names.has('_pxcts');
  },

  score(s) {
    let n = 0;
    const c = s.cookies || {};
    // Treat the cookie family as one "session coherence" signal rather than
    // independently-summable points: a single isolated cookie (e.g. just
    // _px2, which is a generic enough name to collide) is weak evidence,
    // but two or more of this specific, distinctive family appearing
    // together is strong evidence none of them would individually justify.
    const coherentCount = [c.px, c.px2, c.px3, c.pxvid, c.pxhd, c.pxcts].filter(Boolean).length;
    if (coherentCount >= 2) {
      n += 50 + Math.min(coherentCount - 2, 3) * 8; // 50 for the pair, +8 per extra
    } else if (coherentCount === 1) {
      n += 18; // isolated single cookie — weak on its own
    }

    if (s.xPxAuthorization)          n += 45; // Required header in PerimeterX's own validation chain
    if (s.pxCollectorRef)            n += 44; // Exclusive collector domain
    if (s.pxCdnRef)                  n += 40;
    if (s.pxPressHoldChallenge)      n += 38; // Distinctive UX pattern unique to this vendor
    if (s.pxScriptRef)               n += 30;
    if (s.humanSecurityRef)          n += 26;
    if (s.ipEvidenceMatch)           n += 15; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed PerimeterX / HUMAN Security';
    else if (n >= 55) label = 'Highly Likely PerimeterX';
    else if (n >= 32) label = 'Possible PerimeterX';
    return { score: n, label, detected: n >= 32 };
  }
});
