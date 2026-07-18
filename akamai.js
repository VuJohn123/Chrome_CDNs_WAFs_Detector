// Akamai Provider  v7.3
// 2026 updates:
//  • Pragma debug replaced by Akamai-Debug header (Enhanced Debug) in modern configs
//    Legacy Pragma probe still sent for backward compat; new Akamai-Debug probe added
//  • Edge-Cache-Tag header: returned when Pragma: akamai-x-get-cache-tags or always
//  • X-Akamai-Staging: present on staging network — useful corroborator
//  • Akamai-EW-Trace: EdgeWorkers trace header (modern Akamai serverless)
//  • X-Akamai-Session-Info: variable debug — returned on pragma or Enhanced Debug request

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'akamai', name: 'Akamai', color: '#009bde', icon: '🌊',

  knownHeaders: [
    'akamai-cache-status',
    'akamai-ew-trace',
    'akamai-grn',
    'akamai-origin-hop',
    'edge-cache-tag',
    'x-akamai-edgescape',
    'x-akamai-edgeworker-trace',
    'x-akamai-request-id',
    'x-akamai-session-info',
    'x-akamai-ssl-client-sid',
    'x-akamai-staging',
    'x-akamai-transformed',
    'x-check-cacheable',
    'x-serial',
    'x-true-cache-key',
  ],

  freshSignals: () => ({
    akamaiCname: false,
    serverAkamai: false, xAkamaiTransformed: false, xAkamaiRequestId: false,
    xAkamaiEdgescape: false, xAkamaiOriginHop: false, xAkamaiGrn: false,
    xAkamaiCacheStatus: false, xAkamaiSslSid: false, xAkamaiSessionInfo: false,
    xTrueCacheKey: false, xSerial: false, xCacheAkamai: false, xCheckCacheable: false,
    // 2026: Edge-Cache-Tag (returned in pragma/enhanced-debug mode or always-on)
    edgeCacheTag: false,
    // 2026: Akamai EdgeWorkers trace header
    akamaiEwTrace: false,
    // 2026: Akamai-Staging (staging network indicator)
    akamaiStaging: false,
    pragmaProbe: false, akamaiSureRoute: false, akamaiMpulse: false,
    akamaiWafBlock: false, akamaiErrorBody: false,
    cookies: { abck: false, bmSz: false, akBmsc: false, bmSv: false, bmMi: false },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { edgescape: null, cacheNode: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    if (/akamaighost|netstorage/i.test(hR('server')))              s.serverAkamai          = true;
    if (res.headers.has('x-akamai-transformed'))                    s.xAkamaiTransformed    = true;
    if (res.headers.has('x-akamai-request-id'))                    s.xAkamaiRequestId      = true;

    const esc = hR('x-akamai-edgescape');
    if (esc) { s.xAkamaiEdgescape = true; s.meta.edgescape = esc; }

    if (res.headers.has('akamai-origin-hop'))                       s.xAkamaiOriginHop      = true;
    if (res.headers.has('akamai-grn'))                              s.xAkamaiGrn            = true;
    if (res.headers.has('akamai-cache-status'))                    s.xAkamaiCacheStatus    = true;
    if (res.headers.has('x-akamai-ssl-client-sid'))                s.xAkamaiSslSid         = true;
    if (res.headers.has('x-akamai-session-info'))                  s.xAkamaiSessionInfo    = true;
    if (res.headers.has('x-true-cache-key'))                       s.xTrueCacheKey         = true;
    if (res.headers.has('x-serial'))                               s.xSerial               = true;
    if (res.headers.has('x-check-cacheable'))                      s.xCheckCacheable       = true;

    // Edge-Cache-Tag (returned always or via debug — strong Akamai signal)
    if (res.headers.has('edge-cache-tag'))                         s.edgeCacheTag          = true;

    // Akamai EdgeWorkers trace header (2026 docs)
    if (res.headers.has('x-akamai-edgeworker-trace') ||
        res.headers.has('akamai-ew-trace'))                        s.akamaiEwTrace         = true;

    // Staging network indicator
    if (/essl/i.test(hR('x-akamai-staging')))                     s.akamaiStaging         = true;

    // X-Cache from Akamai nodes: TCP_* from *.akamai.net
    const xc = hR('x-cache');
    if (/TCP_/i.test(xc) && /akamai/i.test(xc)) {
      s.xCacheAkamai = true;
      const node = xc.match(/from\s+(\S+)/i)?.[1] || null;
      if (node) s.meta.cacheNode = node;
    }

    if (!body) return;
    if (/reference #\d+\.\d+/i.test(body))   s.akamaiWafBlock  = true;
    if (/akamai error/i.test(body))           s.akamaiErrorBody = true;
  },

  probes: [
    // Legacy Pragma probe — still works on sites that haven't enabled Enhanced Debug
    {
      url: d => `https://${d}/`,
      opts: {
        headers: {
          'Pragma': 'akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-request-id, akamai-x-get-true-cache-key',
          'Cache-Control': 'no-cache'
        },
        cache: 'no-store'
      },
      validStatuses: [200,301,302,403,404,503],
      handler: (res, s) => {
        if (res.headers.has('x-cache') || res.headers.has('x-check-cacheable') ||
            res.headers.has('x-true-cache-key') || res.headers.has('x-akamai-request-id'))
          s.pragmaProbe = true;
      }
    },
    // Enhanced Debug probe (modern Akamai, alias for full pragma set)
    {
      url: d => `https://${d}/`,
      opts: {
        headers: { 'Akamai-Debug': 'cache vars' },
        cache: 'no-store'
      },
      validStatuses: [200,301,302,403,404,503],
      handler: (res, s) => {
        // Returns same debug headers as full pragma — any of these confirm Akamai
        if (res.headers.has('x-true-cache-key') || res.headers.has('x-check-cacheable') ||
            res.headers.has('x-akamai-request-id'))
          s.pragmaProbe = true;
      }
    },
    { url: d => `https://${d}/akamai/sureroute-test-object.html`,
      validStatuses: [200,403,404], handler: (_, s) => { s.akamaiSureRoute = true; } },
    { url: d => `https://${d}/_mPulse/api/v1/`,
      validStatuses: [200,400,403,404], handler: (_, s) => { s.akamaiMpulse = true; } },
  ],

  cnamePatterns: [
    { re: /\.akamaiedge\.net$/,   signal: 'akamaiCname' },
    { re: /\.edgekey\.net$/,      signal: 'akamaiCname' },
    { re: /\.edgesuite\.net$/,    signal: 'akamaiCname' },
    { re: /\.akamai\.net$/,       signal: 'akamaiCname' },
    { re: /\.akamized\.net$/,     signal: 'akamaiCname' },
    { re: /\.srip\.net$/,         signal: 'akamaiCname' },
    { re: /\.akamaihd\.net$/,     signal: 'akamaiCname' },
  ],
  ptrPatterns: [
    { re: /akamaiedge\.net$|akamai\.net$|akamaitechnologies\.com$/, signal: 'akamaiCname' },
  ],
  orgNames: ['akamai'],
  nsPatterns: [
    { re: /\.akam\.net$/,         signal: 'akamaiCname' },
  ],

  extractCookies(cookies, s) {
    const names = cookies.map(c => c.name);
    s.cookies.abck  = names.some(n => n === '_abck');
    s.cookies.bmSz  = names.some(n => n === 'bm_sz');
    s.cookies.akBmsc = names.some(n => n === 'ak_bmsc');
    s.cookies.bmSv  = names.some(n => n === 'bm_sv');
    s.cookies.bmMi  = names.some(n => n === 'bm_mi');
  },

  score(s) {
    let n = 0;
    if (s.serverAkamai)        n += 55;
    if (s.xAkamaiEdgescape)    n += 52;
    if (s.xAkamaiGrn)          n += 50;
    if (s.akamaiCname)         n += 48;
    if (s.cookies?.abck)       n += 45;
    if (s.xAkamaiTransformed)  n += 42;
    if (s.xAkamaiRequestId)    n += 40;
    if (s.pragmaProbe)         n += 38;
    if (s.edgeCacheTag)        n += 36; // New 2026 signal
    if (s.xTrueCacheKey)       n += 34;
    if (s.xCacheAkamai)        n += 32;
    if (s.akamaiMpulse)        n += 28;
    if (s.xAkamaiCacheStatus)  n += 26;
    if (s.xSerial)             n += 24;
    if (s.xAkamaiSessionInfo)  n += 22;
    if (s.akamaiSureRoute)     n += 20;
    if (s.cookies?.bmSz)       n += 20;
    if (s.cookies?.akBmsc)     n += 18;
    if (s.xAkamaiOriginHop)    n += 18;
    if (s.xCheckCacheable)     n += 16;
    if (s.xAkamaiSslSid)       n += 14;
    if (s.akamaiEwTrace)       n += 14;
    if (s.cookies?.bmSv)       n += 12;
    if (s.cookies?.bmMi)       n += 10;
    if (s.akamaiWafBlock)      n += 30; // Kona WAF block very specific
    if (s.akamaiErrorBody)     n += 20;
    if (s.akamaiStaging)       n += 10;
    if (s.dnsShortTtl && n >= 20) n += 5;

    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Akamai';
    else if (n >= 55) label = 'Highly Likely Akamai';
    else if (n >= 35) label = 'Possible Akamai';
    return { score: n, label, detected: n >= 35 };
  }
});
