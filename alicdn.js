// Alibaba Cloud CDN Provider  v7.5 (NEW)
// ============================================================
// Alibaba Cloud CDN is one of the largest CDNs in Asia, built on the
// "Swift" caching layer (the underlying tech name appears in headers).
//
// Documented signals (Alibaba Cloud official docs, 2026):
//   X-Cache: HIT/MISS                   — standard cache header
//   X-Swift-SaveTime                    — GMT timestamp when resource first cached
//   X-Swift-CacheTime                   — cache duration metadata
//   Age                                 — standard caching header (corroborator only)
//   CNAME → *.kunlunar.com, *.kunlun*.com, *.alikunlun.com — Alibaba CDN CNAME targets
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'alicdn', name: 'Alibaba Cloud CDN', color: '#ff6a00', icon: '🅰',

  knownHeaders: [
    'x-swift-cachetime',
    'x-swift-savetime',
  ],
  ipConfig: null, // Alibaba Cloud CDN IP ranges are not published as a single static list

  freshSignals: () => ({
    aliCname: false,
    xSwiftSaveTime: false, xSwiftCacheTime: false,
    xCacheSwift: false, ageHeader: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    // X-Swift-SaveTime / X-Swift-CacheTime — exclusive to Alibaba Cloud CDN's Swift layer
    if (res.headers.has('x-swift-savetime'))  s.xSwiftSaveTime  = true;
    if (res.headers.has('x-swift-cachetime')) s.xSwiftCacheTime = true;

    // X-Cache only counted alongside a Swift-specific header (shared header name otherwise)
    if (/^(HIT|MISS)$/i.test(hR('x-cache').trim()) && (s.xSwiftSaveTime || s.xSwiftCacheTime || s.aliCname))
      s.xCacheSwift = true;

    if (res.headers.has('age')) s.ageHeader = true;
  },

  probes: [],
  cnamePatterns: [
    { re: /\.kunlunar\.com$/,    signal: 'aliCname' },
    { re: /\.kunlun[a-z0-9]*\.com$/, signal: 'aliCname' },
    { re: /\.alikunlun\.com$/,   signal: 'aliCname' },
    { re: /\.alicdn\.com$/,      signal: 'aliCname' },
    { re: /\.aliyuncs\.com$/,    signal: 'aliCname' },
  ],
  ptrPatterns: [
    { re: /alicdn\.com$|aliyuncs\.com$|alibaba-inc\.com$/, signal: 'aliCname' },
  ],
  orgNames: ['alibaba', 'aliyun'],

  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.aliCname)                          n = Math.max(n, 85);
    if (s.xSwiftSaveTime && s.xSwiftCacheTime) n = Math.max(n, 88); // Both Swift headers together = definitive
    else if (s.xSwiftSaveTime || s.xSwiftCacheTime) n = Math.max(n, 68);
    if (s.xCacheSwift)                       n += 22;
    if (n >= 30 && s.ageHeader)               n += 8; // Weak corroborator only
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Alibaba Cloud CDN';
    else if (n >= 55) label = 'Highly Likely Alibaba Cloud CDN';
    else if (n >= 30) label = 'Possible Alibaba Cloud CDN';
    return { score: n, label, detected: n >= 30 };
  }
});
