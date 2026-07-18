// StackPath / EdgeCast / Limelight Provider  v7.3
// 2026 update notes:
//  • StackPath was acquired by Zayo in 2023; the EdgeCast platform continues under Edgio.
//    Edgio filed for bankruptcy Aug 2024 and was acquired by Akamai/others in late 2024.
//    Many ex-Edgio customers migrated; however live traffic still exists on these CNAMEs.
//  • ECAcc / ECS server header and hwcdn.net x-cache patterns remain valid identifiers
//    for any remaining active deployments.
//  • x-ec-* header family: confirmed still emitted by the EdgeCast origin tier.
//  • Added Edgio-specific signals: x-edgio-* response headers (2023-2024 rebrand).
//  • Limelight (llnwi.net) still operational under Edgio/successor entity.
//  Treat detections with moderate confidence given ongoing infrastructure transitions.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'stackpath', name: 'StackPath', color: '#2196f3', icon: '⚙',

  knownHeaders: [
    'x-cache-age',
    'x-ec-custom-error',
    'x-edgio-cache',
    'x-edgio-request-id',
    'x-pull-zone',
    'x-sp-',
    'x-sp-uid',
  ],
  ipConfig: null,

  freshSignals: () => ({
    stackpathCname: false,
    serverEcacc: false, serverEcs: false,
    xSpUid: false, xEcCustomError: false,
    xCacheHwcdn: false, xCacheHwcdnValid: false,
    xCacheHits: false, xCacheAge: false,
    xPullZone: false, xSpEdge: false,
    // 2026: Edgio rebrand headers (present on Edgio-era deployments 2023-2024)
    xEdgioRequestId: false,
    xEdgioCache: false,
    ecErrorBody: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    // `brandHints` tracks which specific legacy entity's signals fired, since
    // "StackPath/EdgeCast/Edgio/Limelight" lumped into one label can overstate
    // certainty about which (now-distinct, differently-owned) tier is live.
    meta: { cacheNode: null, spUid: null, brandHints: [] }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';
    const server = hR('server');
    const addBrand = b => { if (!s.meta.brandHints.includes(b)) s.meta.brandHints.push(b); };

    if (/^ECAcc$/i.test(server.trim()))  { s.serverEcacc = true; addBrand('EdgeCast'); }
    if (/^ECS$/i.test(server.trim()))    { s.serverEcs   = true; addBrand('EdgeCast'); }

    const spUid = hR('x-sp-uid');
    if (spUid) { s.xSpUid = true; s.meta.spUid = spUid; addBrand('StackPath'); }

    if (hR('x-ec-custom-error') === '1') { s.xEcCustomError = true; addBrand('EdgeCast'); }

    const xCache = hR('x-cache');
    if (/hwcdn\.net/i.test(xCache)) {
      s.xCacheHwcdn = true;
      s.meta.cacheNode = xCache;
      addBrand('StackPath');
      if (/HIT|MISS/.test(xCache)) s.xCacheHwcdnValid = true;
    } else if (/stackpath|edgecast|edgio/i.test(xCache)) {
      s.xCacheHwcdn = true;
    }

    if (hR('x-cache-hits') !== '')   s.xCacheHits = true;
    if (hR('x-cache-age') !== '')    s.xCacheAge  = true;
    if (res.headers.has('x-pull-zone')) { s.xPullZone = true; addBrand('StackPath'); }
    if (Array.from(res.headers.keys()).some(k => k.startsWith('x-sp-'))) s.xSpEdge = true;

    // 2026: Edgio rebrand headers (2023+ deployments)
    if (res.headers.has('x-edgio-request-id')) { s.xEdgioRequestId = true; addBrand('Edgio'); }
    if (res.headers.has('x-edgio-cache'))      { s.xEdgioCache     = true; addBrand('Edgio'); }

    if (!body) return;
    if (/EdgeCast|StackPath|Edgio|hwcdn\.net|edgecastcdn\.net/i.test(body))
      s.ecErrorBody = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.hwcdn\.net$/,          signal: 'stackpathCname' },
    { re: /\.stackpathcdn\.com$/,   signal: 'stackpathCname' },
    { re: /\.netdna-cdn\.com$/,     signal: 'stackpathCname' },
    { re: /\.maxcdn-edge\.com$/,    signal: 'stackpathCname' },
    { re: /\.stackpath\.com$/,      signal: 'stackpathCname' },
    { re: /\.edgecastcdn\.net$/,    signal: 'stackpathCname' },
    { re: /\.llnwi\.net$/,          signal: 'stackpathCname' },
    { re: /\.limelight\.com$/,      signal: 'stackpathCname' },
    // 2026: Edgio CNAMEs
    { re: /\.edgio\.net$/,          signal: 'stackpathCname' },
    { re: /\.edgioapis\.com$/,      signal: 'stackpathCname' },
  ],
  ptrPatterns: [
    { re: /hwcdn\.net$|edgecastcdn\.net$|llnwi\.net$|edgio\.net$/, signal: 'stackpathCname' },
  ],
  orgNames: ['stackpath', 'edgecast', 'edgio', 'limelight', 'lumen'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.serverEcacc)          n = Math.max(n, 88);
    if (s.serverEcs)            n = Math.max(n, 82);
    if (s.xCacheHwcdnValid)     n = Math.max(n, 85);
    else if (s.xCacheHwcdn)     n = Math.max(n, 78);
    // Edgio: strong if found
    if (s.xEdgioRequestId)      n = Math.max(n, 80);
    if (s.xEdgioCache)          n = Math.max(n, 72);
    if (s.stackpathCname)       n += 25;
    if (s.xSpUid)               n += 22;
    if (s.xEcCustomError)       n += 18;
    if (s.ecErrorBody)          n += 16;
    if (s.xPullZone)            n += 14;
    if (s.xSpEdge)              n += 12;
    if (n >= 25) {
      if (s.xCacheHits)  n += 8;
      if (s.xCacheAge)   n += 6;
    }
    if (s.ipEvidenceMatch)      n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    const brand = s.meta?.brandHints?.length === 1 ? ` (${s.meta.brandHints[0]})` :
      s.meta?.brandHints?.length > 1 ? ' (mixed signals — verify which tier is live)' : '';
    if      (n >= 82) label = `Confirmed StackPath / Edgio / EdgeCast${brand}`;
    else if (n >= 62) label = `Highly Likely StackPath / Edgio${brand}`;
    else if (n >= 40) label = `Possible StackPath / EdgeCast${brand}`;
    else if (n >= 22) label = `Weak StackPath Indicators${brand}`;
    return { score: n, label, detected: n >= 22 };
  }
});
