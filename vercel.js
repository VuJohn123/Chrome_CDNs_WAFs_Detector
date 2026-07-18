// Vercel Edge Network Provider  v7.3
// 2026 updates:
//  • X-Vercel-Id format confirmed stable (single/multi-region ::chained:: prefixes)
//  • x-vercel-cache: PRERENDER confirmed valid value for ISR (incremental static regen)
//  • x-vercel-sk: Skew Protection token (Vercel 2024+, still active 2026)
//  • x-deployment-id: dpl_{base36} format confirmed
//  • Vercel Firewall (2024+): x-vercel-waf-action header on blocked requests
//  • x-vercel-ip-country: country code forwarded to origin — now client-visible on some configs
//  • Bot Protection (Vercel 2025): x-vercel-challenge header on challenge pages

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'vercel', name: 'Vercel', color: '#e2e8f0', icon: '▲',

  knownHeaders: [
    'x-deployment-id',
    'x-matched-path',
    'x-middleware-invoke',
    'x-middleware-rewrite',
    'x-next-cache-tags',
    'x-nextjs-cache',
    'x-nextjs-prerender',
    'x-nextjs-stale-time',
    'x-vercel-cache',
    'x-vercel-challenge',
    'x-vercel-error',
    'x-vercel-execution-region',
    'x-vercel-id',
    'x-vercel-ip-country',
    'x-vercel-proxy-signature',
    'x-vercel-sk',
    'x-vercel-waf-action',
  ],
  ipConfig: null,

  freshSignals: () => ({
    vercelCname: false,
    xVercelId: false, xVercelIdValid: false,
    xVercelCache: false, xVercelCacheValid: false,
    serverVercel: false, xMatchedPath: false, xDeploymentId: false,
    xNextjsPrerender: false, xNextjsStaleTime: false,
    xNextjsCache: false, xNextCacheTags: false,
    xVercelError: false, xVercelExecRegion: false,
    xVercelSk: false,
    xMiddlewareRewrite: false, xMiddlewareInvoke: false,
    // 2026: Vercel Firewall WAF action header
    xVercelWafAction: false,
    // 2026: IP country forwarding (visible in some configurations)
    xVercelIpCountry: false,
    // 2026: Bot Protection challenge header
    xVercelChallenge: false,
    // v7.4: proxy-signature header — present when Vercel acts as a rewrite
    // proxy (confirmed via Vercel/Next.js team GitHub discussion; used for
    // request verification on rewrites, not officially documented but
    // observed consistently in production)
    xVercelProxySignature: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { vercelId: null, region: null, deploymentId: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    const vid = hR('x-vercel-id');
    if (vid) {
      s.xVercelId = true;
      s.meta.vercelId = vid;
      const m = vid.match(/^([a-z]{2,6}\d?)::/i);
      if (m) s.meta.region = m[1];
      // Format: one or more {region}:: prefixes + {node}-{ts_ms}-{hex}
      if (/^(?:[a-z]{2,6}\d?::){1,4}[a-z0-9]+-\d{10,}-[a-z0-9]+$/i.test(vid.trim()))
        s.xVercelIdValid = true;
    }

    const vc = hR('x-vercel-cache');
    if (vc) {
      s.xVercelCache = true;
      // PRERENDER added for ISR pages (confirmed active 2026)
      if (/^(HIT|MISS|STALE|BYPASS|PRERENDER|ERROR)$/i.test(vc.trim())) s.xVercelCacheValid = true;
    }

    if (/^Vercel$/i.test(hR('server')))                 s.serverVercel      = true;
    if (res.headers.has('x-matched-path'))              s.xMatchedPath      = true;
    if (res.headers.has('x-deployment-id')) {
      s.xDeploymentId      = true;
      s.meta.deploymentId  = hR('x-deployment-id');
    }
    if (res.headers.has('x-nextjs-prerender'))          s.xNextjsPrerender  = true;
    if (res.headers.has('x-nextjs-stale-time'))         s.xNextjsStaleTime  = true;
    if (res.headers.has('x-nextjs-cache'))              s.xNextjsCache      = true;
    if (res.headers.has('x-next-cache-tags'))           s.xNextCacheTags    = true;
    if (res.headers.has('x-vercel-error'))              s.xVercelError      = true;
    if (res.headers.has('x-vercel-execution-region'))   s.xVercelExecRegion = true;
    if (res.headers.has('x-vercel-sk'))                 s.xVercelSk         = true;
    if (res.headers.has('x-middleware-rewrite'))        s.xMiddlewareRewrite = true;
    if (res.headers.has('x-middleware-invoke'))         s.xMiddlewareInvoke = true;
    // 2026 new signals
    if (res.headers.has('x-vercel-waf-action'))         s.xVercelWafAction  = true;
    if (/^[A-Z]{2}$/i.test(hR('x-vercel-ip-country').trim())) s.xVercelIpCountry = true;
    if (res.headers.has('x-vercel-challenge'))          s.xVercelChallenge  = true;
    if (res.headers.has('x-vercel-proxy-signature'))    s.xVercelProxySignature = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.vercel\.app$/,          signal: 'vercelCname' },
    { re: /\.vercel-dns\.com$/,      signal: 'vercelCname' },
    { re: /\.vercel\.dev$/,          signal: 'vercelCname' },
    { re: /\.now\.sh$/,              signal: 'vercelCname' },
    { re: /cname\.vercel-dns\.com$/, signal: 'vercelCname' },
  ],
  ptrPatterns: [
    { re: /vercel\.com$|vercel-dns\.com$/, signal: 'vercelCname' },
  ],
  orgNames: ['vercel'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.xVercelIdValid)       n = Math.max(n, 97);
    else if (s.xVercelId)       n = Math.max(n, 92);
    if (s.xVercelCacheValid)    n = Math.max(n, 88);
    else if (s.xVercelCache)    n = Math.max(n, 82);
    if (s.serverVercel)         n = Math.max(n, 85);
    if (s.vercelCname)          n = Math.max(n, 82);
    if (s.xMatchedPath)         n += 20;
    if (s.xDeploymentId)        n += 18;
    if (s.xNextjsPrerender)     n += 16;
    if (s.xNextjsStaleTime)     n += 14;
    if (s.xNextCacheTags)       n += 14;
    if (s.xNextjsCache)         n += 12;
    if (s.xVercelSk)            n += 14;
    if (s.xMiddlewareRewrite)   n += 12;
    if (s.xMiddlewareInvoke)    n += 10;
    if (s.xVercelError)         n += 12;
    if (s.xVercelExecRegion)    n += 10;
    if (s.xVercelWafAction)     n += 16; // Vercel Firewall active
    if (s.xVercelChallenge)     n += 14;
    if (s.xVercelProxySignature) n += 16;
    if (s.xVercelIpCountry)     n += 8;
    if (s.dnsVeryShortTtl && n >= 30) n += 8; // Vercel commonly uses 60s TTL
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 88) label = 'Confirmed Vercel Edge Network';
    else if (n >= 65) label = 'Highly Likely Vercel';
    else if (n >= 42) label = 'Possible Vercel';
    else if (n >= 22) label = 'Weak Vercel Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
