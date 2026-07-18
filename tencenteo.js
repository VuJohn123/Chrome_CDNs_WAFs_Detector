// Tencent EdgeOne CDN Provider  v7.5 (NEW)
// ============================================================
// Tencent EdgeOne is Tencent Cloud's edge platform (CDN + security +
// serverless), the leading CDN in mainland China/Asia by node count.
//
// Documented signals (Tencent EdgeOne official docs, 2025-2026):
//   server: TencentEdgeOne              — added by EdgeOne when no origin Server header exists
//   EO-Cache-Status: Hit/Miss/RefreshHit/Expired/Dynamic — cache status header
//   EO-Connecting-IP                    — origin-pull request header (client IP)
//   EO-LOG-UUID                         — unique request identifier
//   CDN-Loop: tencent                   — loop-prevention header value for EdgeOne
//   EO-Client-Device                    — optional custom preset header
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'tencenteo', name: 'Tencent EdgeOne', color: '#00a4ff', icon: '🐧',

  knownHeaders: [
    'eo-cache-status',
    'eo-client-device',
    'eo-connecting-ip',
    'eo-log-uuid',
  ],
  ipConfig: null, // Tencent does not publish a single consolidated public EdgeOne IP list

  freshSignals: () => ({
    tencentCname: false,
    serverTencentEo: false,
    eoCacheStatus: false, eoCacheStatusValid: false,
    eoConnectingIp: false, eoLogUuid: false, eoClientDevice: false,
    cdnLoopTencent: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { logUuid: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';
    const h  = n => hR(n).toLowerCase();

    // server: TencentEdgeOne — default when origin has no Server header (documented default)
    if (/tencentedgeone/i.test(hR('server'))) s.serverTencentEo = true;

    const cs = hR('eo-cache-status');
    if (cs) {
      s.eoCacheStatus = true;
      if (/^(hit|miss|refreshhit|expired|dynamic|stale)$/i.test(cs.trim())) s.eoCacheStatusValid = true;
    }

    if (res.headers.has('eo-connecting-ip')) s.eoConnectingIp = true;
    const uuid = hR('eo-log-uuid');
    if (uuid) { s.eoLogUuid = true; s.meta.logUuid = uuid; }
    if (res.headers.has('eo-client-device')) s.eoClientDevice = true;

    // CDN-Loop: tencent — distinct value from cloudflare/fastly
    if (/\btencent\b/i.test(h('cdn-loop'))) s.cdnLoopTencent = true;
  },

  probes: [],
  cnamePatterns: [
    { re: /\.qcloud\.com$/,       signal: 'tencentCname' },
    { re: /\.cdn\.qcloud\.com$/,  signal: 'tencentCname' },
    { re: /\.edgeone\.app$/,      signal: 'tencentCname' },
    { re: /\.tencentedgeone\.com$/, signal: 'tencentCname' },
    { re: /\.tencent-cloud\.net$/, signal: 'tencentCname' },
  ],
  ptrPatterns: [
    { re: /qcloud\.com$|tencent-cloud\.net$/, signal: 'tencentCname' },
  ],
  orgNames: ['tencent'],

  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.serverTencentEo)     n = Math.max(n, 88);
    if (s.cdnLoopTencent)      n = Math.max(n, 85); // Loop-prevention value is exclusive
    if (s.tencentCname)        n = Math.max(n, 82);
    if (s.eoCacheStatusValid)  n += 38;
    else if (s.eoCacheStatus)  n += 28;
    if (s.eoLogUuid)           n += 32;
    if (s.eoConnectingIp)      n += 24;
    if (s.eoClientDevice)      n += 14;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Tencent EdgeOne';
    else if (n >= 55) label = 'Highly Likely Tencent EdgeOne';
    else if (n >= 32) label = 'Possible Tencent EdgeOne';
    return { score: n, label, detected: n >= 32 };
  }
});
