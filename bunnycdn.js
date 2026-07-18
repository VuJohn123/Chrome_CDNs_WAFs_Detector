// BunnyCDN (bunny.net) Provider  v7.3
// 2026 updates:
//  • cdn-requestid: 32-char hex confirmed stable per bunny.net docs
//  • bunny.net rebranded some infrastructure: bunny.net TLD now primary (bunny.net/cdn)
//  • cdn-cache now also returns REVALIDATING on stale-while-revalidate (2024+)
//  • cdn-noderegion: new header present on some PoPs identifying region (EU/US/AS/OC)
//  • Bunny Shield (DDoS/WAF layer, 2024+): x-bunny-shield header on blocked requests
//  • server: BunnyCDN-{location}-{id} format confirmed; location can be 2 or 3-char code

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'bunnycdn', name: 'BunnyCDN', color: '#f5a623', icon: '🐰',

  knownHeaders: [
    'cdn-cache',
    'cdn-cachedat',
    'cdn-edgestorageid',
    'cdn-noderegion',
    'cdn-proxyver',
    'cdn-pullzone',
    'cdn-requestcountrycode',
    'cdn-requestid',
    'cdn-requestpullcode',
    'cdn-requestpullsuccess',
    'cdn-status',
    'cdn-uid',
    'x-bunny-shield',
  ],

  ipConfig: {
    ipSignal: 'bunnyIP', storageKey: 'ip_bunny',
    v4Url: 'https://bunnycdn.com/api/system/edgeserverlist',
    v6Url: 'https://bunnycdn.com/api/system/edgeserverlist/IPv6',
    singleFile: false,
    v4: [], v6: [],
    parseResponse(text) {
      try {
        const d = JSON.parse(text);
        return Array.isArray(d) ? d.filter(ip => typeof ip === 'string') : [];
      } catch {
        return text.trim().split('\n').map(l => l.trim()).filter(Boolean);
      }
    }
  },

  freshSignals: () => ({
    bunnyIP: false, bunnyCname: false,
    serverBunny: false, serverBunnyValid: false,
    cdnCache: false, cdnCacheValid: false,
    cdnPullzone: false, cdnUid: false,
    cdnRequestId: false, cdnRequestIdValid: false,
    cdnRequestCountryCode: false, cdnCachedAt: false,
    cdnProxyVer: false, cdnRequestPullCode: false,
    cdnRequestPullSuccess: false, cdnEdgeStorageId: false, cdnStatus: false,
    viaBunny: false,
    // 2026: new signals
    cdnNodeRegion: false,    // cdn-noderegion: region code (EU/US/AS/OC)
    xBunnyShield: false,     // x-bunny-shield: DDoS/WAF block indicator
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { serverNode: null, pullzone: null, uid: null, requestId: null, country: null, region: null }
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    const server = hR('server');
    if (/^BunnyCDN-/i.test(server)) {
      s.serverBunny = true;
      s.meta.serverNode = server;
      // Format: BunnyCDN-{2-4 alpha/numeric location}-{integer}
      // Location can be 2-char country code or 3-char airport code
      if (/^BunnyCDN-[A-Z0-9]{2,4}-\d+$/i.test(server.trim())) s.serverBunnyValid = true;
    }

    const cdnCache = hR('cdn-cache');
    if (cdnCache) {
      s.cdnCache = true;
      // Added REVALIDATING for stale-while-revalidate (2024+)
      if (/^(HIT|MISS|BYPASS|EXPIRED|REVALIDATING)$/i.test(cdnCache.trim())) s.cdnCacheValid = true;
    }

    const pz = hR('cdn-pullzone');
    if (pz && /^\d+$/.test(pz.trim())) { s.cdnPullzone = true; s.meta.pullzone = pz.trim(); }

    const uid = hR('cdn-uid');
    if (uid) {
      s.cdnUid = true;
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uid.trim()))
        s.meta.uid = uid.trim();
    }

    const reqId = hR('cdn-requestid');
    if (reqId) {
      s.cdnRequestId = true;
      s.meta.requestId = reqId;
      if (/^[0-9a-f]{32}$/i.test(reqId.trim())) s.cdnRequestIdValid = true;
    }

    const cc = hR('cdn-requestcountrycode');
    if (cc && /^[A-Z]{2}$/i.test(cc.trim())) {
      s.cdnRequestCountryCode = true;
      s.meta.country = cc.trim().toUpperCase();
    }

    if (hR('cdn-cachedat'))                          s.cdnCachedAt          = true;
    if (hR('cdn-proxyver'))                          s.cdnProxyVer          = true;
    if (hR('cdn-requestpullcode'))                   s.cdnRequestPullCode   = true;
    if (/True/i.test(hR('cdn-requestpullsuccess'))) s.cdnRequestPullSuccess = true;
    if (hR('cdn-edgestorageid'))                     s.cdnEdgeStorageId     = true;
    if (hR('cdn-status'))                            s.cdnStatus            = true;

    // 2026: cdn-noderegion and x-bunny-shield
    const region = hR('cdn-noderegion');
    if (region.trim()) { s.cdnNodeRegion = true; s.meta.region = region.trim(); }
    if (res.headers.has('x-bunny-shield'))           s.xBunnyShield         = true;

    if (/\bBunnyCDN\b/i.test(hR('via')))             s.viaBunny             = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.b-cdn\.net$/,    signal: 'bunnyCname' },
    { re: /\.bunnycdn\.com$/, signal: 'bunnyCname' },
    { re: /\.bunny\.net$/,    signal: 'bunnyCname' },
  ],
  ptrPatterns: [
    { re: /b-cdn\.net$|bunny\.net$/, signal: 'bunnyCname' },
  ],
  orgNames: ['bunny.net', 'bunnycdn', 'bunny'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.serverBunnyValid)        n = Math.max(n, 98);
    else if (s.serverBunny)        n = Math.max(n, 94);
    if (s.cdnRequestIdValid)       n = Math.max(n, 92);
    else if (s.cdnRequestId)       n = Math.max(n, 86);
    if (s.cdnUid)                  n = Math.max(n, 88);
    if (s.viaBunny)                n = Math.max(n, 86);
    if (s.cdnCacheValid)           n = Math.max(n, 82);
    if (s.bunnyCname)              n += 22;
    if (s.bunnyIP)                 n += 18;
    if (s.cdnPullzone)             n += 18;
    if (s.cdnCachedAt)             n += 16;
    if (s.cdnProxyVer)             n += 16;
    if (s.cdnRequestPullSuccess)   n += 14;
    if (s.cdnRequestPullCode)      n += 12;
    if (s.cdnEdgeStorageId)        n += 12;
    if (s.cdnRequestCountryCode)   n += 10;
    if (s.cdnNodeRegion)           n += 10; // 2026 new signal
    if (s.xBunnyShield)            n += 14; // 2026 Bunny Shield WAF
    if (s.cdnStatus)               n += 8;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 90) label = 'Confirmed BunnyCDN';
    else if (n >= 70) label = 'Highly Likely BunnyCDN';
    else if (n >= 45) label = 'Possible BunnyCDN';
    else if (n >= 22) label = 'Weak BunnyCDN Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
