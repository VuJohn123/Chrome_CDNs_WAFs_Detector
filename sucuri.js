// Sucuri / CloudProxy WAF Provider  v7.3
// 2026 updates:
//  • GoDaddy acquired Sucuri; some CNAMEs now route through godaddy-securesites.net
//  • x-sucuri-id format: 8–18 digit numeric — confirmed stable
//  • x-sucuri-cache valid values: HIT, MISS, BYPASS, EXPIRED, STALE — confirmed stable
//  • x-sucuri-country: 2-letter ISO code present on some deployments (new passive signal)
//  • server: CloudProxy — still active on legacy Sucuri deployments
//  • Block page body check expanded: "Sucuri Website Firewall" and GoDaddy WAF variants
//  • No cookie signals — Sucuri does not issue WAF cookies by default

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'sucuri', name: 'Sucuri', color: '#e77b30', icon: '🔒',

  knownHeaders: [
    'x-sucuri-cache',
    'x-sucuri-country',
    'x-sucuri-generated-time',
    'x-sucuri-id',
    'x-sucuri-version',
  ],
  ipConfig: null,

  freshSignals: () => ({
    sucuriCname: false,
    xSucuriId: false, xSucuriIdValid: false,
    xSucuriCache: false, xSucuriCacheValid: false,
    xSucuriVersion: false, xSucuriGeneratedTime: false,
    // 2026: new passive signal — country header present on some Sucuri deployments
    xSucuriCountry: false,
    serverCloudProxy: false,
    sucuriBlockPage: false, sucuriAccessDenied: false,
    sucuriJsChallenge: false, sucuriCsrf: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { sucuriId: null, cacheStatus: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    const sid = hR('x-sucuri-id');
    if (sid) {
      s.xSucuriId = true;
      s.meta.sucuriId = sid;
      if (/^\d{8,18}$/.test(sid.trim())) s.xSucuriIdValid = true;
    }

    const cache = hR('x-sucuri-cache');
    if (cache) {
      s.xSucuriCache = true;
      s.meta.cacheStatus = cache;
      if (/^(HIT|MISS|BYPASS|EXPIRED|STALE)$/i.test(cache.trim())) s.xSucuriCacheValid = true;
    }

    if (hR('x-sucuri-version'))                        s.xSucuriVersion       = true;
    if (hR('x-sucuri-generated-time'))                 s.xSucuriGeneratedTime = true;
    // x-sucuri-country: ISO country code — seen on some Sucuri deployments (2025+)
    if (/^[A-Z]{2}$/i.test(hR('x-sucuri-country').trim())) s.xSucuriCountry  = true;
    if (/^cloudproxy/i.test(hR('server')))             s.serverCloudProxy     = true;

    if (!body) return;
    if (/sucuri\.net|cloudproxy\.sucuri|Sucuri WebSite Firewall|sucuri website firewall/i.test(body))
      s.sucuriBlockPage = true;
    if (/Access Denied.*sucuri|sucuri.*Access Denied/is.test(body))
      s.sucuriAccessDenied = true;
    if (/sucuri_cloudproxy_js|_sucuri_/i.test(body))   s.sucuriJsChallenge    = true;
    if (/sucuri.+csrf|csrf.+sucuri/i.test(body))       s.sucuriCsrf           = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.sucuri\.net$/,              signal: 'sucuriCname' },
    { re: /\.cloudproxy\.sucuri\.net$/,  signal: 'sucuriCname' },
    { re: /\.sucuridns\.net$/,           signal: 'sucuriCname' },
    // GoDaddy-managed Sucuri (post-acquisition routing)
    { re: /\.godaddy-securesites\.net$/, signal: 'sucuriCname' },
  ],
  ptrPatterns: [
    { re: /sucuri\.net$/, signal: 'sucuriCname' },
  ],
  orgNames: ['sucuri', 'godaddy'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.xSucuriIdValid)       n = Math.max(n, 97);
    else if (s.xSucuriId)       n = Math.max(n, 92);
    if (s.xSucuriCacheValid)    n = Math.max(n, 88);
    else if (s.xSucuriCache)    n = Math.max(n, 82);
    if (s.serverCloudProxy)     n = Math.max(n, 80);
    if (s.sucuriCname)          n += 25;
    if (s.sucuriBlockPage)      n += 22;
    if (s.xSucuriVersion)       n += 20;
    if (s.xSucuriGeneratedTime) n += 18;
    if (s.sucuriJsChallenge)    n += 18;
    if (s.sucuriAccessDenied)   n += 16;
    if (s.xSucuriCountry)       n += 12; // New 2026 — corroborator
    if (s.sucuriCsrf)           n += 12;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 88) label = 'Confirmed Sucuri / CloudProxy WAF';
    else if (n >= 65) label = 'Highly Likely Sucuri';
    else if (n >= 40) label = 'Possible Sucuri';
    else if (n >= 22) label = 'Weak Sucuri Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
