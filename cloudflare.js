// Cloudflare Provider  v7.3
// 2026 updates:
//  • Server-Timing: cfL4 (L4 telemetry), cfWorker (Workers exec time), cdn-cache — new official metrics
//  • CF-Ray format: 16-hex-{3-letter-IATA} still valid; also accept longer IDs (CF expanding)
//  • cf-request-id removed from scoring (officially deprecated since 2021, now truly rare)
//  • Server-Timing cfWorker signal = Workers active (replaces weaker cfEwVia alone)
//  • NEL endpoint updated to a.nel.cloudflare.com/report/v4 (current 2025+ format)
//  • AI Labyrinth: _cf_chl_opt still valid; also cf-ew-trace signal for Workers
//  • Turnstile script path updated: challenges.cloudflare.com/turnstile/v0/
//  • WARP / Gateway / RBI / Post-Quantum KEX from /cdn-cgi/trace remain stable

self._cfParseTrace = function(text) {
  const m = new Map();
  for (const line of text.trim().split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) m.set(line.slice(0, i).trim(), line.slice(i + 1).trim());
  }
  return m;
};

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'cloudflare', name: 'Cloudflare', color: '#f38020', icon: '⛅',

  // Feeds the automatic unknown-header detector (crowd-report upgrade) —
  // any response header NOT in this list, seen on a domain where this
  // provider was detected, gets surfaced as a possible new signal.
  knownHeaders: [
    'cf-ray','cf-cache-status','cf-connecting-ip','true-client-ip','cf-visitor',
    'cf-edge-cache','cf-mitigated','cf-bgj','cf-ew-via','cf-ew-trace','cdn-loop',
    'cf-pages-commit-sha','cf-pages-deployment-id','alt-svc','nel','report-to',
    'server','server-timing',
  ],

  ipConfig: {
    ipSignal: 'cfIP', storageKey: 'ip_cf', singleFile: false,
    v4Url: 'https://www.cloudflare.com/ips-v4',
    v6Url: 'https://www.cloudflare.com/ips-v6',
    v4: [
      '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
      '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
      '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
      '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'
    ],
    v6: ['2400:cb00::/32','2606:4700::/32','2803:f800::/32',
         '2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32']
  },

  freshSignals: () => ({
    cfIP: false, cfCname: false, cfPages: false, cfEmailMx: false,
    cfRay: false, cfRayValid: false, serverHeader: false, cdnLoop: false,
    cfEwVia: false, cfVisitor: false, cfEdgeCache: false, cfTrueClientIp: false,
    cfPagesHeaders: false, cfBgj: false,
    cfCache: false, cfCacheValid: false, cfMitigated: false,
    nelCloudflare: false, h3AltSvc: false,
    // Server-Timing sub-metrics (2026 Cloudflare changelog)
    cfServerTimingL4: false,    // cfL4 = L4 TCP/QUIC telemetry (confirmed CF infrastructure)
    cfServerTimingWorker: false, // cfWorker = Workers execution time (confirms Workers active)
    cfServerTimingCdnCache: false, // cdn-cache = cache status via Server-Timing
    trace: false, traceConfirmed: false, traceWarp: false, traceGateway: false,
    traceRbi: false, traceKex: false,
    assets: false, cfRum: false, cfZaraz: false, cfImageResizing: false,
    cfBotManagement: false,
    waitingRoom: false, zeroTrust: false,
    challengePage: false, turnstile: false, aiLabyrinth: false,
    cfRocketLoader: false, cfEmailObfuscation: false, cfErrorCode: false,
    cfCvParams: false, cfEwTrace: false,
    cookies: { cfClearance: false, cfBm: false, cfWaiting: false, cfAccess: false },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {
      dataCenter: null, httpVersion: null, tlsVersion: null,
      kex: null, warp: null, gateway: null, rbi: null, cfRayId: null, flightId: null
    }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';
    if (/cloudflare/i.test(hR('server')))                           s.serverHeader      = true;
    if (res.headers.has('cf-ray'))                                   s.cfRay             = true;
    if (res.headers.has('cf-cache-status'))                         s.cfCache           = true;
    if (res.headers.has('cf-ew-via'))                               s.cfEwVia           = true;
    if (res.headers.has('cf-visitor'))                              s.cfVisitor         = true;
    if (res.headers.has('cf-edge-cache'))                           s.cfEdgeCache       = true;
    if (res.headers.has('cf-bgj'))                                  s.cfBgj             = true;
    if (res.headers.has('true-client-ip') || res.headers.has('cf-connecting-ip'))
                                                                     s.cfTrueClientIp    = true;
    if (res.headers.has('cf-pages-commit-sha') || res.headers.has('cf-pages-deployment-id'))
                                                                     s.cfPagesHeaders    = true;
    if (res.headers.has('cf-ew-trace'))                             s.cfEwTrace         = true;
    if (/\bcloudflare\b/i.test(h('cdn-loop')))                      s.cdnLoop           = true;
    if (/challenge/i.test(h('cf-mitigated')))                       s.cfMitigated       = true;

    // NEL / Report-To — match both legacy and new v4 endpoint format
    const reportTo = hR('report-to') + hR('nel');
    if (/nel\.cloudflare\.com/i.test(reportTo))                     s.nelCloudflare     = true;

    const cst = hR('cf-cache-status').toUpperCase();
    if (/^(HIT|MISS|EXPIRED|STALE|UPDATING|REVALIDATING|DYNAMIC|BYPASS|NONE)$/.test(cst))
                                                                     s.cfCacheValid      = true;

    const alt = hR('alt-svc');
    if (/h3=":443"/i.test(alt))                                     s.h3AltSvc          = true;

    // CF-Ray format: 16 hex chars + hyphen + 3-letter IATA
    // CF is expanding to longer IDs but current live format remains {16hex}-{IATA}
    const ray = hR('cf-ray');
    if (ray) {
      s.meta.cfRayId = ray;
      if (/^[0-9a-f]{16}-[A-Z]{3}$/i.test(ray)) s.cfRayValid = true;
    }

    // Server-Timing: parse Cloudflare-specific metrics (2026 changelog)
    // cfL4 = L4 TCP/QUIC telemetry — only present on CF infrastructure
    // cfWorker = time in Workers execution (new Feb 2026)
    // cdn-cache = cache decision exposed via Server-Timing
    const st = hR('server-timing');
    if (st) {
      if (/\bcfL4\b/i.test(st))                                     s.cfServerTimingL4      = true;
      if (/\bcfWorker\b/i.test(st))                                  s.cfServerTimingWorker  = true;
      if (/\bcdn-cache\b/i.test(st))                                 s.cfServerTimingCdnCache = true;
    }

    if (!body) return;
    if (/checking your browser|attention required|cloudflare ray id|__cf_chl|cf-mitigated/i.test(body))
      s.challengePage = true;
    // Turnstile — updated path: challenges.cloudflare.com/turnstile/v0/
    if (/cf-turnstile|challenges\.cloudflare\.com\/turnstile|turnstile\.cloudflare\.com/i.test(body))
      s.turnstile = true;
    if (/cf-waitingroom|waiting.?room/i.test(body))                  s.waitingRoom         = true;
    if (/cf_access|cloudflare.?access/i.test(body))                  s.zeroTrust           = true;
    if (/_cf_chl_opt\s*=|cf-honeypot|cf-ai-labyrinth/i.test(body))  s.aiLabyrinth         = true;
    if (/\/cdn-cgi\/scripts\//i.test(body))                          s.cfRocketLoader      = true;
    if (/data-cfemail=/i.test(body))                                  s.cfEmailObfuscation  = true;
    if (/\berror\s*(?:code[:\s]*)?\s*1\d{3}\b/i.test(body))         s.cfErrorCode         = true;
    if (/window\.__CF\$cv\$params/i.test(body))                      s.cfCvParams          = true;
  },

  probes: [
    { url: d => `https://${d}/cdn-cgi/trace`, validStatuses: [200],
      handler: async (res, s) => {
        s.trace = true;
        const text = await res.text().catch(() => '');
        if (!text.includes('colo=')) return;
        const t = self._cfParseTrace(text);
        s.traceConfirmed   = true;
        s.meta.dataCenter  = t.get('colo')    || null;
        s.meta.httpVersion = t.get('http')    || null;
        s.meta.tlsVersion  = t.get('tls')     || null;
        s.meta.kex         = t.get('kex')     || null;
        s.meta.warp        = t.get('warp')    || null;
        s.meta.gateway     = t.get('gateway') || null;
        s.meta.rbi         = t.get('rbi')     || null;
        s.meta.flightId    = t.get('fl')      || null;
        if (t.get('warp')    === 'on') s.traceWarp    = true;
        if (t.get('gateway') === 'on') s.traceGateway = true;
        if (t.get('rbi')     === 'on') s.traceRbi     = true;
        // Post-quantum KEX: X25519Kyber768 / MLKEM768 (CF uses both names across PoPs)
        if (/kyber|mlkem|x25519.*768/i.test(t.get('kex') || '')) s.traceKex = true;
      }
    },
    { url: d => `https://${d}/cdn-cgi/challenge-platform/`,
      validStatuses: [200,400,403,503], handler: (_, s) => { s.assets = true; } },
    { url: d => `https://${d}/cdn-cgi/rum`,
      validStatuses: [200,204,400],    handler: (_, s) => { s.cfRum = true; } },
    { url: d => `https://${d}/cdn-cgi/zaraz/i.js`,
      validStatuses: [200],            handler: (_, s) => { s.cfZaraz = true; } },
    { url: d => `https://${d}/cdn-cgi/image/width=1,format=auto/`,
      validStatuses: [400,403,404],
      handler: async (res, s) => {
        if (res.headers.has('cf-ray') || /cloudflare/i.test(res.headers.get('server') || ''))
          s.cfImageResizing = true;
      }
    },
    { url: d => `https://${d}/cdn-cgi/bot-management`,
      validStatuses: [200,403,404,429],
      handler: (res, s) => { if (res.headers.has('cf-ray')) s.cfBotManagement = true; }
    },
    { url: d => `https://${d}/cdn-cgi/waitingroom/`,
      validStatuses: [200,403,503], handler: (_, s) => { s.waitingRoom = true; } },
    { url: d => `https://${d}/cdn-cgi/access/`,
      validStatuses: [200,403,503], handler: (_, s) => { s.zeroTrust  = true; } }
  ],

  cnamePatterns: [
    { re: /\.cdn\.cloudflare\.net$/, signal: 'cfCname' },
    { re: /\.cloudflare\.net$/,      signal: 'cfCname' },
    { re: /\.pages\.dev$/,           signal: 'cfPages' },
    { re: /\.workers\.dev$/,         signal: 'cfEwVia' },
  ],
  ptrPatterns: [
    { re: /\.cloudflare\.com$/, signal: 'cfCname' },
  ],
  orgNames: ['cloudflare'],
  mxPatterns: [
    { re: /\.mx\.cloudflare\.net$/, signal: 'cfEmailMx' },
  ],
  // Cloudflare vanity NS (free/pro plans use *.ns.cloudflare.com)
  nsPatterns: [
    { re: /\.ns\.cloudflare\.com$/, signal: 'cfCname' },
  ],

  extractCookies(cookies, s) {
    const names = new Set(cookies.map(c => c.name));
    s.cookies.cfClearance = names.has('cf_clearance');
    s.cookies.cfBm        = names.has('__cf_bm');
    s.cookies.cfWaiting   = names.has('__cfwaitingroom');
    s.cookies.cfAccess    = names.has('CF_Authorization') || names.has('cf-access-token');
  },

  score(s) {
    let n = 0;
    // Tier 1 — definitive / exclusive CF signals
    if (s.cookies?.cfClearance)      n += 58; // Only CF issues this after challenge
    if (s.turnstile)                  n += 55;
    if (s.traceConfirmed)             n += 55; // /cdn-cgi/trace with colo= confirmed
    if (s.cfMitigated)                n += 52;
    if (s.cdnLoop)                    n += 50; // CDN-Loop: cloudflare = CF edge
    if (s.cfServerTimingL4)           n += 45; // cfL4 is CF-exclusive Server-Timing metric
    // Tier 2
    if (s.cfRay)                      n += 42;
    if (s.cfIP)                       n += 40;
    if (s.nelCloudflare)              n += 40;
    if (s.cfCname)                    n += 40;
    if (s.cfPages)                    n += 38;
    if (s.aiLabyrinth)                n += 38;
    if (s.trace)                      n += 35;
    if (s.cfServerTimingWorker)       n += 32; // cfWorker = Workers active
    if (s.cfEwVia)                    n += 32; // CF-EW-Via = Workers (still emitted)
    if (s.cookies?.cfBm)              n += 32;
    if (s.zeroTrust)                  n += 32;
    if (s.cfPagesHeaders)             n += 30;
    if (s.cfEdgeCache)                n += 28;
    if (s.cfCvParams)                 n += 28;
    if (s.cfEwTrace)                  n += 26; // CF-EW-Trace = Workers tracing
    // Tier 3
    if (s.serverHeader)               n += 26;
    if (s.cfVisitor)                  n += 26;
    if (s.traceGateway)               n += 26;
    if (s.cfErrorCode)                n += 26;
    if (s.assets)                     n += 24;
    if (s.cfBotManagement)            n += 24;
    if (s.cfZaraz)                    n += 22;
    if (s.cfImageResizing)            n += 22;
    if (s.cfCacheValid)               n += 22;
    if (s.cfServerTimingCdnCache)     n += 20; // cdn-cache metric in Server-Timing
    if (s.cfRum)                      n += 20;
    if (s.waitingRoom)                n += 20;
    if (s.cookies?.cfWaiting)        n += 20;
    if (s.cookies?.cfAccess)         n += 20;
    if (s.cfEmailMx)                  n += 18;
    if (s.traceRbi)                   n += 18;
    if (s.cfBgj)                      n += 16;
    // Tier 4
    if (s.h3AltSvc)                   n += 14;
    if (s.traceKex)                   n += 14;
    if (s.cfRocketLoader)             n += 14;
    if (s.cfEmailObfuscation)         n += 12;
    if (s.traceWarp)                  n += 12;
    if (s.cfRayValid)                 n += 10;
    if (s.cfTrueClientIp)             n += 10;
    // TTL corroborator
    if (s.dnsShortTtl && n >= 20)     n += 5;

    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 95) label = 'Confirmed Enterprise (Bot Management)';
    else if (n >= 80) label = 'Confirmed Cloudflare';
    else if (n >= 65 && !s.cookies?.cfClearance) label = 'Confirmed Stealth Mode';
    else if (n >= 50) label = 'Highly Likely Cloudflare';
    else if (n >= 35) label = 'Possible Cloudflare';
    return { score: n, label, detected: n >= 35 };
  }
});
