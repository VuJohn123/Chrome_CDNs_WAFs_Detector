// Railway Provider  v9.1 (new in this build)
// Confidence notes: a Railway community thread confirms Railway modifies
// the Server response header, but does not state the exact value, so that
// check stays a weak heuristic. The *.up.railway.app hostname pattern is
// directly observable in Railway's own documentation/support threads and
// is the reliable signal here.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'railway', name: 'Railway', color: '#9f5fff', icon: '🚆',
  productType: 'App hosting (not a traditional CDN)',

  freshSignals: () => ({
    railwayCname: false,
    railwayHeaderHeuristic: false, // unconfirmed exact value — low weight only
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';
    if (/railway/i.test(hR('server'))) s.railwayHeaderHeuristic = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.up\.railway\.app$/, signal: 'railwayCname' },
  ],
  ptrPatterns: [],
  orgNames: ['railway'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.railwayCname)             n = Math.max(n, 88); // documented default hostname pattern
    if (s.railwayHeaderHeuristic)   n += 10;
    if (s.ipEvidenceMatch)          n += 10;
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Likely Railway';
    else if (n >= 45) label = 'Possible Railway';
    else if (n >= 22) label = 'Weak Railway Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
