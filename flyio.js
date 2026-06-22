// Fly.io Provider  v9.1 (new in this build)
// Confidence notes (be honest about what's verified vs not):
//  • fly-request-id: documented as part of Fly Proxy's default response headers
//    (removable via fly.toml, which implies present-by-default) — treated as
//    the strongest single signal here, but NOT given "exclusively Fly.io"
//    status the way e.g. X-Amz-Cf-Id is for CloudFront, since we could not
//    independently verify its exact format is unique/stable.
//  • No published downloadable IP range list was found for Fly.io's shared
//    anycast addresses, so there is no ipConfig block here (unlike most
//    other providers) — network-layer detection relies on CNAME only.
//  • Server/Via header content from Fly's proxy was not independently
//    confirmed in this build, so those checks stay in the lower-confidence
//    "present" tier rather than a validated-format tier.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'flyio', name: 'Fly.io', color: '#8b5cf6', icon: '🪰',
  productType: 'Edge compute / app hosting (not a traditional CDN)',

  freshSignals: () => ({
    flyCname: false,
    flyRequestId: false, flyRegion: false, flyForwardedPort: false,
    viaFly: false, serverFlyHeuristic: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { requestId: null, region: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    const reqId = hR('fly-request-id');
    if (reqId) { s.flyRequestId = true; s.meta.requestId = reqId; }

    const region = hR('fly-region');
    if (region) { s.flyRegion = true; s.meta.region = region; }

    if (res.headers.has('fly-forwarded-port')) s.flyForwardedPort = true;

    if (/\bfly\.io\b/i.test(hR('via'))) s.viaFly = true;
    // Unconfirmed format — treated as a weak heuristic only, not validated.
    if (/fly/i.test(hR('server'))) s.serverFlyHeuristic = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.fly\.dev$/, signal: 'flyCname' },
  ],
  ptrPatterns: [],
  orgNames: ['fly.io', 'fly io'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.flyRequestId)        n = Math.max(n, 80); // documented as Fly's own header, but format not independently validated here
    if (s.flyCname)            n += 24;
    if (s.flyRegion)           n += 16;
    if (s.flyForwardedPort)    n += 10;
    if (s.viaFly)              n += 30;
    if (s.serverFlyHeuristic)  n += 12; // weak — Server header content unconfirmed
    if (s.ipEvidenceMatch)     n += 10;
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Likely Fly.io (header format not independently validated)';
    else if (n >= 50) label = 'Possible Fly.io';
    else if (n >= 22) label = 'Weak Fly.io Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
