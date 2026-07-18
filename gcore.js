// Gcore CDN Provider  v7.3
// 2026 updates:
//  • Gcore expanded PoP network significantly in APAC and Southeast Asia (2024-2026)
//  • x-id format: ed-{N}-{N}-{N}-{N} confirmed stable — encodes edge server IP
//  • x-cached-since: timestamp format now also seen as ISO 8601 with T separator
//    e.g. both "2025-11-14 08:32:19" and "2025-11-14T08:32:19" observed
//  • x-gcore-pop: PoP location code — now more commonly present on responses (2025+)
//  • server: Gcore — still present on a subset of deployments
//  • g-shield: Gcore DDoS protection header present on shield-enabled zones (2025+)
//  • Gcore acquired CDN77 (2022); cdn77.com CNAMEs may still be active

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'gcore', name: 'Gcore', color: '#f04e23', icon: '🌐',

  knownHeaders: [
    'g-shield',
    'x-cached-since',
    'x-gcore-location',
    'x-gcore-pop',
    'x-id',
  ],
  ipConfig: null,

  freshSignals: () => ({
    gcoreCname: false,
    serverGcore: false,
    xId: false, xIdValid: false,
    xCachedSince: false, xCacheGcore: false,
    gcorePop: false,
    // 2026: g-shield header (DDoS protection indicator)
    gShield: false,
    gcoreErrorPage: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { serverId: null, cachedSince: null, pop: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    if (/^Gcore$/i.test(hR('server').trim())) s.serverGcore = true;

    const xId = hR('x-id');
    if (xId.trim()) {
      s.xId = true;
      s.meta.serverId = xId.trim().slice(0, 80);
      if (/^ed-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$/.test(xId.trim())) s.xIdValid = true;
    }

    // x-cached-since: accept both space-separated and T-separated ISO formats
    const cs = hR('x-cached-since');
    if (cs.trim()) { s.xCachedSince = true; s.meta.cachedSince = cs.trim(); }

    if (/^(HIT|MISS)$/i.test(hR('x-cache').trim()) && (s.xId || s.gcoreCname || s.serverGcore))
      s.xCacheGcore = true;

    const pop = hR('x-gcore-pop') || hR('x-gcore-location');
    if (pop.trim()) { s.gcorePop = true; s.meta.pop = pop.trim(); }

    // 2026: g-shield header — Gcore DDoS protection layer
    if (res.headers.has('g-shield'))             s.gShield = true;

    if (!body) return;
    if (/gcore\.com|gcdn\.co|G-Core|Gcore\b/i.test(body)) s.gcoreErrorPage = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.gcdn\.co$/,        signal: 'gcoreCname' },
    { re: /\.gc\.onl$/,         signal: 'gcoreCname' },
    { re: /\.gcorelabs\.com$/,  signal: 'gcoreCname' },
    { re: /\.gccdn\.net$/,      signal: 'gcoreCname' },
    { re: /\.gcore\.com$/,      signal: 'gcoreCname' },
    { re: /\.g-core\.com$/,     signal: 'gcoreCname' },
    // CDN77 (acquired by Gcore 2022) — still active
    { re: /\.cdn77\.org$/,      signal: 'gcoreCname' },
    { re: /\.cdn77\.com$/,      signal: 'gcoreCname' },
  ],
  ptrPatterns: [
    { re: /gcdn\.co$|gcore\.com$|cdn77\.(com|org)$/, signal: 'gcoreCname' },
  ],
  orgNames: ['gcore', 'cdn77'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.serverGcore)                       n = Math.max(n, 92);
    if (s.gcoreCname)                        n = Math.max(n, 88);
    if (s.xIdValid && s.xCachedSince)        n = Math.max(n, 75);
    else if (s.xIdValid)                     n = Math.max(n, 48);
    else if (s.xId && s.xCachedSince)        n = Math.max(n, 58);
    if (s.xCachedSince)                      n += 18;
    if (s.gcoreErrorPage)                    n += 20;
    if (s.gcorePop)                          n += 22;
    if (s.gShield)                           n += 16; // 2026 new signal
    if (n >= 30 && s.xCacheGcore)            n += 10;
    if (s.xId && !s.xIdValid)               n += 8;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 88) label = 'Confirmed Gcore CDN';
    else if (n >= 65) label = 'Highly Likely Gcore';
    else if (n >= 42) label = 'Possible Gcore';
    else if (n >= 22) label = 'Weak Gcore Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
