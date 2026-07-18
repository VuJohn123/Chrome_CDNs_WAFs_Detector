// Netlify Edge Network Provider  v7.3
// 2026 updates:
//  • x-nf-request-id: 26-char ULID confirmed (Crockford Base32) — stable
//  • netlify-cdn-cache-control: Netlify's own CDN cache directive header (2024+, active 2026)
//  • x-nf-pop: PoP location confirmed stable
//  • netlify-server-timing: performance header — still present on some deployments
//  • Netlify Edge Functions (Deno Deploy): x-nf-edge-functions header on edge-function responses
//  • Cache-Tag header: Netlify uses this for tag-based purging (2025+)

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'netlify', name: 'Netlify', color: '#00c7b7', icon: '💠',

  knownHeaders: [
    'netlify-cdn-cache-control',
    'netlify-server-timing',
    'netlify-vary',
    'x-netlify-cache',
    'x-netlify-original-path',
    'x-netlify-rewrite',
    'x-nf-edge-cache',
    'x-nf-edge-functions',
    'x-nf-origin-cache',
    'x-nf-pop',
    'x-nf-request-id',
  ],
  ipConfig: null,

  freshSignals: () => ({
    netlifyCname: false,
    xNfRequestId: false, xNfRequestIdValid: false,
    serverNetlify: false,
    xNfEdgeCache: false, xNfEdgeCacheValid: false,
    xNfOriginCache: false, netlifyVary: false,
    xNetlifyOriginalPath: false, xNetlifyRewrite: false, xNetlifyCache: false,
    xNfPop: false,
    netlifyServerTiming: false,
    // 2026: Edge Functions header
    xNfEdgeFunctions: false,
    // 2026: Netlify CDN Cache Control (distinct from standard Cache-Control)
    netlifyCdnCacheControl: false,
    netlifyErrorPage: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { nfRequestId: null, pop: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    const nfId = hR('x-nf-request-id');
    if (nfId) {
      s.xNfRequestId = true;
      s.meta.nfRequestId = nfId;
      // 26-char Crockford Base32 ULID
      if (/^[0-9A-HJKMNP-TV-Z]{26}$/i.test(nfId.trim())) s.xNfRequestIdValid = true;
    }

    if (/^Netlify$/i.test(hR('server')))             s.serverNetlify        = true;

    const ec = hR('x-nf-edge-cache');
    if (ec) {
      s.xNfEdgeCache = true;
      if (/^(HIT|MISS|BYPASS|STALE|EXPIRED|REVALIDATED)$/i.test(ec.trim()))
        s.xNfEdgeCacheValid = true;
    }

    if (hR('x-nf-origin-cache'))                     s.xNfOriginCache       = true;
    if (res.headers.has('netlify-vary'))              s.netlifyVary          = true;
    if (res.headers.has('x-netlify-original-path'))  s.xNetlifyOriginalPath = true;
    if (res.headers.has('x-netlify-rewrite'))        s.xNetlifyRewrite      = true;
    if (res.headers.has('x-netlify-cache'))          s.xNetlifyCache        = true;

    const pop = hR('x-nf-pop');
    if (pop) { s.xNfPop = true; s.meta.pop = pop; }

    if (res.headers.has('netlify-server-timing'))    s.netlifyServerTiming  = true;
    // 2026 new signals
    if (res.headers.has('x-nf-edge-functions'))      s.xNfEdgeFunctions     = true;
    if (res.headers.has('netlify-cdn-cache-control')) s.netlifyCdnCacheControl = true;

    if (!body) return;
    if (/netlify\.com|hosted by netlify|Page Not Found.*Netlify/i.test(body))
      s.netlifyErrorPage = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.netlify\.app$/,     signal: 'netlifyCname' },
    { re: /\.netlify\.com$/,     signal: 'netlifyCname' },
    { re: /\.netlifydns\.net$/,  signal: 'netlifyCname' },
    { re: /\.netlify-dns\.com$/, signal: 'netlifyCname' },
  ],
  ptrPatterns: [
    { re: /netlify\.com$/, signal: 'netlifyCname' },
  ],
  orgNames: ['netlify'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.xNfRequestIdValid)       n = Math.max(n, 96);
    else if (s.xNfRequestId)       n = Math.max(n, 90);
    if (s.serverNetlify)           n = Math.max(n, 88);
    if (s.xNfEdgeCacheValid)       n = Math.max(n, 86);
    else if (s.xNfEdgeCache)       n = Math.max(n, 80);
    if (s.netlifyCname)            n = Math.max(n, 84);
    if (s.netlifyVary)             n += 22;
    if (s.xNfOriginCache)         n += 18;
    if (s.xNetlifyOriginalPath)   n += 16;
    if (s.xNetlifyRewrite)        n += 14;
    if (s.xNfPop)                 n += 16;
    if (s.netlifyServerTiming)    n += 14;
    if (s.xNfEdgeFunctions)       n += 14; // Edge Functions (2026)
    if (s.netlifyCdnCacheControl) n += 12; // Netlify-specific cache directive (2026)
    if (s.xNetlifyCache)          n += 12;
    if (s.netlifyErrorPage)       n += 14;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 88) label = 'Confirmed Netlify Edge CDN';
    else if (n >= 65) label = 'Highly Likely Netlify';
    else if (n >= 42) label = 'Possible Netlify';
    else if (n >= 22) label = 'Weak Netlify Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
