// Fastly Provider  v7.3
// 2026 updates:
//  • X-Fastly-Request-ID: confirmed 40 lowercase hex chars (stable — verified via http.dev/x-fastly-request-id)
//  • Shielded deployments: X-Served-By contains multiple comma-separated entries
//  • X-Timer format: S{epoch}.{usec},VS0,VE{ms} — confirmed stable
//  • Fastly Next-Gen WAF (NGWAF, formerly Signal Sciences): X-SigSci-* headers on origin
//    but NOT typically exposed to client — omit from client-facing detection
//  • CDN-Loop: fastly — distinct from Cloudflare's CDN-Loop: cloudflare
//  • Surrogate-Control remains exclusive Fastly/Varnish cache directive header
//  • Fastly-Restarts present when VCL restart occurred (debugging signal)

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'fastly', name: 'Fastly', color: '#ff282d', icon: '⚡',

  knownHeaders: [
    'fastly-debug-digest',
    'fastly-debug-path',
    'fastly-debug-ttl',
    'fastly-restarts',
    'surrogate-control',
    'surrogate-key',
    'x-fastly-imageopto-api',
    'x-fastly-request-id',
    'x-served-by',
    'x-timer',
    'x-varnish',
  ],

  ipConfig: {
    ipSignal: 'fastlyIP', storageKey: 'ip_fastly',
    v4Url: 'https://api.fastly.com/public-ip-list',
    singleFile: true,
    parseResponse(text) {
      try {
        const j = JSON.parse(text);
        return [...(j.addresses || []), ...(j.ipv6_addresses || [])];
      } catch { return []; }
    },
    v4: [
      '23.235.32.0/20','43.249.72.0/22','103.244.50.0/24','103.245.222.0/23',
      '103.245.224.0/24','104.156.80.0/20','140.248.64.0/18','140.248.128.0/17',
      '146.75.0.0/17','151.101.0.0/16','157.52.64.0/18','167.82.0.0/17',
      '167.82.128.0/20','167.82.160.0/20','167.82.224.0/20','172.111.64.0/18',
      '185.31.16.0/22','199.27.72.0/21','199.232.0.0/16','202.21.128.0/24',
      '203.57.145.0/24','211.75.72.0/24'
    ],
    v6: []
  },

  freshSignals: () => ({
    fastlyIP: false, fastlyCname: false,
    xServedByValid: false, xServedByShielded: false,
    xTimerValid: false, cdnLoopFastly: false,
    fastlyRequestId: false, fastlyRequestIdValid: false,
    fastlyImageOpto: false, fastlyRestarts: false,
    xCacheHits: false, xCacheMultiHit: false, surrogateControl: false,
    fastlyDebugDigest: false, fastlyDebugTtl: false,
    fastlyDebugPath: false, fastlySurrogateKey: false,
    viaVarnish: false, serverVarnish: false, xVarnish: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { cacheNode: null, shieldNode: null, elapsedMs: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    // X-Served-By: cache-{city}{id}-{IATA} per Fastly docs
    const xsb = hR('x-served-by');
    if (xsb) {
      const parts = xsb.split(',').map(p => p.trim());
      // Validated format: cache-{word}{digits}-{3-letter IATA} or cache-{word}-{IATA}
      if (parts.some(p => /^cache-[a-z]+\d*-[A-Z]{3}$/i.test(p))) s.xServedByValid = true;
      if (parts.length > 1) s.xServedByShielded = true; // multi-entry = shielded deployment
      s.meta.cacheNode  = parts[parts.length - 1] || null;
      if (parts.length > 1) s.meta.shieldNode = parts[0] || null;
    }

    // X-Timer: S{epoch}.{us},VS0,VE{ms} — Fastly exclusive timing header
    const xt = hR('x-timer');
    if (xt) {
      if (/^S\d+\.\d+,VS0,VE\d+$/i.test(xt.trim())) {
        s.xTimerValid = true;
        const ms = xt.match(/VE(\d+)/)?.[1];
        if (ms) s.meta.elapsedMs = `${ms}ms`;
      }
    }

    // CDN-Loop: fastly — loop prevention distinct from Cloudflare
    if (/\bfastly\b/i.test(h('cdn-loop')))                         s.cdnLoopFastly        = true;

    // X-Fastly-Request-ID: 40 lowercase hex chars (confirmed stable spec)
    const frid = hR('x-fastly-request-id');
    if (frid) {
      s.fastlyRequestId = true;
      if (/^[0-9a-f]{40}$/.test(frid.trim())) s.fastlyRequestIdValid = true;
    }

    if (res.headers.has('x-fastly-imageopto-api'))                  s.fastlyImageOpto      = true;
    if (res.headers.has('fastly-restarts'))                         s.fastlyRestarts       = true;
    if (res.headers.has('x-cache-hits'))                            s.xCacheHits           = true;
    if (res.headers.has('surrogate-control'))                       s.surrogateControl     = true;

    // X-Cache multi-value = shielded/clustered
    const xc = hR('x-cache');
    if (/,/.test(xc) && /HIT|MISS/i.test(xc))                     s.xCacheMultiHit       = true;

    // Varnish signals (lower confidence — Fastly uses Varnish under the hood)
    if (/1\.1 varnish/i.test(h('via')))                            s.viaVarnish           = true;
    if (/^varnish$/i.test(hR('server')))                           s.serverVarnish        = true;
    if (res.headers.has('x-varnish'))                              s.xVarnish             = true;

    // Fastly Debug headers — only returned when Fastly-Debug: 1 is sent in request
    if (res.headers.has('fastly-debug-digest'))                    s.fastlyDebugDigest    = true;
    if (res.headers.has('fastly-debug-ttl'))                       s.fastlyDebugTtl       = true;
    if (res.headers.has('fastly-debug-path'))                      s.fastlyDebugPath      = true;
    if (res.headers.has('surrogate-key') && s.fastlyDebugDigest)  s.fastlySurrogateKey   = true;
  },

  probes: [
    // Fastly-Debug: 1 probe — triggers debug response headers (non-destructive)
    {
      url: d => `https://${d}/`,
      opts: { headers: { 'Fastly-Debug': '1' }, cache: 'no-store' },
      validStatuses: [200,301,302,403,404,503],
      handler: (res, s) => {
        if (res.headers.has('fastly-debug-digest') || res.headers.has('fastly-debug-ttl') ||
            res.headers.has('fastly-debug-path'))
          s.fastlyDebugDigest = true;
      }
    }
  ],

  cnamePatterns: [
    { re: /\.fastly\.net$/,      signal: 'fastlyCname' },
    { re: /\.fastlylb\.net$/,    signal: 'fastlyCname' },
    { re: /\.fastlycdn\.com$/,   signal: 'fastlyCname' },
    { re: /\.freetls\.fastly\.net$/, signal: 'fastlyCname' },
    { re: /\.global\.prod\.fastly\.net$/, signal: 'fastlyCname' },
  ],
  ptrPatterns: [
    { re: /fastly\.net$/, signal: 'fastlyCname' },
  ],
  orgNames: ['fastly'],

  score(s) {
    let n = 0;
    if (s.fastlyRequestIdValid) n += 55; // 40-hex confirmed per Fastly docs
    if (s.xServedByValid)       n += 52;
    if (s.xTimerValid)          n += 50;
    if (s.fastlyCname)          n += 48;
    if (s.fastlyIP)             n += 45;
    if (s.cdnLoopFastly)        n += 45;
    if (s.fastlyDebugDigest)    n += 40;
    if (s.xServedByShielded)    n += 30;
    if (s.fastlyRequestId)      n += 28;
    if (s.surrogateControl)     n += 24;
    if (s.fastlyDebugTtl)       n += 22;
    if (s.fastlyDebugPath)      n += 20;
    if (s.fastlySurrogateKey)   n += 18;
    if (s.xCacheMultiHit)       n += 18;
    if (s.xCacheHits)           n += 14;
    if (s.fastlyImageOpto)      n += 14;
    if (s.fastlyRestarts)       n += 12;
    // Varnish: corroborator only — not diagnostic alone
    if (s.viaVarnish && n >= 15) n += 10;
    if (s.serverVarnish && n >= 15) n += 8;
    if (s.xVarnish && n >= 15)   n += 6;
    if (s.dnsShortTtl && n >= 20) n += 5;

    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Fastly';
    else if (n >= 55) label = 'Highly Likely Fastly';
    else if (n >= 35) label = 'Possible Fastly';
    return { score: n, label, detected: n >= 35 };
  }
});
