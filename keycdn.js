// KeyCDN Provider  v7.3
// 2026 updates:
//  • server: keycdn-engine — still the primary definitive identifier, confirmed stable
//  • x-0-cache / x-0-cid: alternative header names used by KeyCDN on some PoPs (2024+)
//  • x-cache-hits now also seen as x-0-cache-hits on some KeyCDN zones
//  • KeyCDN was acquired by Proinity LLC; infrastructure and headers unchanged as of 2026
//  • x-edge-location values: city names or IATA codes depending on PoP configuration
//  • No changes to CNAME patterns — *.kxcdn.com remains the primary pull-zone CNAME

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'keycdn', name: 'KeyCDN', color: '#2a99ff', icon: '🔑',

  knownHeaders: [
    'x-0-cache',
    'x-0-cid',
    'x-edge-ip',
    'x-edge-location',
    'x-pull-zone',
    'x-unique-id',
  ],
  ipConfig: null,

  freshSignals: () => ({
    keyCname: false,
    serverKeycdn: false,
    xEdgeLocation: false, xEdgeIp: false, xUniqueId: false,
    xCacheKeycdn: false, xPullZone: false, xCacheHits: false,
    // 2026: alternative header names seen on some KeyCDN PoPs
    x0Cache: false,      // x-0-cache: HIT/MISS (alternate cache status)
    x0Cid: false,        // x-0-cid: connection/request ID on some PoPs
    keyCdnErrorPage: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { edgeLocation: null, edgeIp: null, uniqueId: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    if (/^keycdn-engine$/i.test(hR('server').trim())) s.serverKeycdn = true;

    const el = hR('x-edge-location');
    if (el.trim()) { s.xEdgeLocation = true; s.meta.edgeLocation = el.trim(); }

    const ei = hR('x-edge-ip');
    if (ei.trim()) { s.xEdgeIp = true; s.meta.edgeIp = ei.trim(); }

    const uid = hR('x-unique-id');
    if (uid.trim()) { s.xUniqueId = true; s.meta.uniqueId = uid.trim().slice(0, 64); }

    const xc = hR('x-cache');
    if (/^(HIT|MISS)$/i.test(xc.trim()) && (s.serverKeycdn || s.xEdgeLocation || s.xEdgeIp))
      s.xCacheKeycdn = true;

    if (res.headers.has('x-pull-zone'))   s.xPullZone  = true;
    if (hR('x-cache-hits') !== '')         s.xCacheHits = true;

    // 2026: x-0-cache and x-0-cid (alternate names seen on some KeyCDN PoPs)
    const x0c = hR('x-0-cache');
    if (/^(HIT|MISS)$/i.test(x0c.trim()))  s.x0Cache   = true;
    if (res.headers.has('x-0-cid'))        s.x0Cid     = true;

    if (!body) return;
    if (/keycdn\.com|keycdn-engine|KeyCDN/i.test(body)) s.keyCdnErrorPage = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.kxcdn\.com$/,    signal: 'keyCname' },
    { re: /\.keycdn\.com$/,   signal: 'keyCname' },
    { re: /\.keycdns\.net$/,  signal: 'keyCname' },
  ],
  ptrPatterns: [
    { re: /kxcdn\.com$|keycdn\.com$/, signal: 'keyCname' },
  ],
  orgNames: ['keycdn'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.serverKeycdn)    n = Math.max(n, 97);
    if (s.keyCname)        n = Math.max(n, 90);
    if (s.xEdgeLocation)   n += 28;
    if (s.xEdgeIp)         n += 22;
    if (s.xUniqueId)       n += 18;
    if (s.keyCdnErrorPage) n += 20;
    if (n >= 30) {
      if (s.xCacheKeycdn)  n += 12;
      if (s.xPullZone)     n += 10;
      if (s.xCacheHits)    n += 8;
      // 2026 alternate headers (additive with strong signals only)
      if (s.x0Cache)       n += 10;
      if (s.x0Cid)         n += 8;
    }
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 90) label = 'Confirmed KeyCDN';
    else if (n >= 65) label = 'Highly Likely KeyCDN';
    else if (n >= 40) label = 'Possible KeyCDN';
    else if (n >= 22) label = 'Weak KeyCDN Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
