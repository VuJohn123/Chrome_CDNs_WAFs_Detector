// F5 Distributed Cloud (Volterra / Shape Security) WAAP+CDN Provider  v7.5 (NEW)
// ============================================================
// F5 acquired Volterra (2021, became F5 Distributed Cloud) and Shape
// Security (2020, became F5 Distributed Cloud Bot Defense). The CDN
// Load Balancer product fronts origins with combined WAAP + CDN.
//
// Documented signals (F5 official Distributed Cloud docs):
//   server: volt-cdn                    — exclusive to F5 XC CDN Load Balancer
//   x-cache-status: HIT/MISS            — F5 XC cache status (shared pattern, needs corroboration)
//   x-request-id                        — F5 XC default response header
//   x-volterra-*                        — predefined header variable family
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'f5xc', name: 'F5 Distributed Cloud', color: '#e4002b', icon: '🟥',

  knownHeaders: [
    'x-cache-status','x-request-id','x-volterra-',
  ],
  ipConfig: null, // F5 XC does not publish a consolidated public IP range list

  freshSignals: () => ({
    serverVoltCdn: false,
    xCacheStatusF5: false, xVolterraHeader: false, xRequestIdF5: false,
    f5ShapeChallenge: false, f5BotDefenseRef: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { volterraHeaders: [] }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    // server: volt-cdn is documented as the exact value for F5 XC CDN Load Balancer
    if (/^volt-cdn$/i.test(hR('server').trim())) s.serverVoltCdn = true;

    // x-cache-status — only counted alongside the server signal (shared header name with others)
    if (/^(HIT|MISS)$/i.test(hR('x-cache-status').trim()) && s.serverVoltCdn)
      s.xCacheStatusF5 = true;

    // x-volterra-* predefined header family — record the actual header names
    // found so the UI can show concrete evidence instead of a bare boolean.
    const volterraKeys = Array.from(res.headers.keys()).filter(k => k.startsWith('x-volterra-'));
    if (volterraKeys.length) {
      s.xVolterraHeader = true;
      s.meta.volterraHeaders = volterraKeys.slice(0, 5);
    }

    if (res.headers.has('x-request-id') && s.serverVoltCdn) s.xRequestIdF5 = true;

    if (!body) return;
    if (/shape\s*security|f5\s*distributed\s*cloud|volterra/i.test(body)) s.f5BotDefenseRef = true;
    if (/access\s*denied.*shape|shape.*access\s*denied/is.test(body))     s.f5ShapeChallenge = true;
  },

  probes: [],
  cnamePatterns: [
    { re: /\.volterra\.io$/,    signal: 'serverVoltCdn' },
    { re: /\.ves\.io$/,         signal: 'serverVoltCdn' },
    { re: /\.f5\.com$/,         signal: 'serverVoltCdn' },
  ],
  ptrPatterns: [
    { re: /\.volterra\.io$|\.ves\.io$/, signal: 'serverVoltCdn' },
  ],
  orgNames: ['f5 networks', 'f5, inc', 'volterra'],

  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.serverVoltCdn)      n = Math.max(n, 92); // Exclusive server value, documented by F5
    // x-volterra-* alone, without the exclusive server value or any other
    // corroborator, is treated cautiously — the header family naming isn't
    // impossible to imitate, so it shouldn't carry full weight in isolation.
    if (s.xVolterraHeader)    n += s.serverVoltCdn ? 35 : 18;
    if (s.xCacheStatusF5)     n += 22;
    if (s.xRequestIdF5)       n += 14;
    if (s.f5BotDefenseRef)    n += 30;
    if (s.f5ShapeChallenge)   n += 32;
    if (s.ipEvidenceMatch)    n += 15; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed F5 Distributed Cloud (Volterra/Shape)';
    else if (n >= 55) label = 'Highly Likely F5 XC';
    else if (n >= 30) label = 'Possible F5 XC';
    return { score: n, label, detected: n >= 30 };
  }
});
