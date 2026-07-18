// CloudFront Provider  v7.3
// 2026 updates:
//  • X-Amz-Cf-Pop format confirmed: {IATA}{2-digits}-{tier}{1-digit} e.g. LAX54-P1, BOS50-C3
//    (both P-tier = PoP and C-tier = cache node observed in production 2025–2026)
//  • X-Amz-Cf-Id: base64-like ~56 chars — confirmed non-removable header per AWS re:Post
//  • Via: 1.1 {hex}.cloudfront.net — 32-hex UUID format observed in practice
//  • x-amzn-waf-action header (AWS WAF action: ALLOW/BLOCK/COUNT)
//  • aws-waf-token cookie: issued after AWS WAF Bot Control challenge
//  • CloudFront-Viewer-Header-Order / CloudFront-Viewer-Header-Count: added to origin
//    requests for bot detection (2023+, still active 2026) — not visible client-side
//  • Route 53 NS (awsdns-*) is a medium-confidence corroborator for CF distribution

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'cloudfront', name: 'CloudFront', color: '#ff9900', icon: '☁',

  knownHeaders: [
    'x-amz-bucket-region',
    'x-amz-cf-id',
    'x-amz-cf-pop',
    'x-amz-delete-marker',
    'x-amz-id-2',
    'x-amz-storage-class',
    'x-amz-version-id',
    'x-amzn-requestid',
    'x-amzn-trace-id',
    'x-amzn-waf-action',
  ],

  ipConfig: {
    ipSignal: 'cloudfrontIP', storageKey: 'ip_cf_aws',
    v4Url: 'https://ip-ranges.amazonaws.com/ip-ranges.json',
    singleFile: true,
    parseResponse(text) {
      try {
        const j = JSON.parse(text);
        return (j.prefixes || [])
          .filter(p => p.service === 'CLOUDFRONT')
          .map(p => p.ip_prefix);
      } catch { return []; }
    },
    v4: [
      '120.52.22.96/27','205.251.192.0/19','205.251.249.0/24',
      '54.230.0.0/16','54.239.128.0/18','52.222.128.0/17',
      '64.252.64.0/18','64.252.128.0/18','99.84.0.0/16',
      '204.246.164.0/22','204.246.168.0/22','204.246.174.0/23',
      '204.246.176.0/20','130.176.0.0/17','130.176.128.0/18',
      '108.156.0.0/14','13.32.0.0/15','13.35.0.0/16',
      '13.224.0.0/14','13.249.0.0/16','52.46.0.0/18',
      '52.84.0.0/15','70.132.0.0/18','143.204.0.0/16'
    ],
    v6: ['2600:9000::/23']
  },

  freshSignals: () => ({
    cloudfrontIP: false, cloudfrontCname: false,
    xAmzCfIdValid: false, xAmzCfId: false,
    xAmzCfPopValid: false, xAmzCfPop: false,
    viaCF: false, serverCF: false, xCacheCF: false,
    xAmzWaf: false, xAmzRequestId: false, xAmzTraceId: false,
    // 2026: aws-waf-token cookie (Bot Control challenge)
    serverS3: false, xAmzId2: false, xAmzBucketRegion: false,
    xAmzVersionId: false, xAmzStorageClass: false,
    xAmzDeleteMarker: false, etagS3Format: false,
    cloudfrontErrorPage: false,
    cookies: { cfPolicy: false, cfSignature: false, cfKeyPair: false, awsWafToken: false },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { cfPop: null, cfRequestId: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    // X-Amz-Cf-Id — non-removable per AWS documentation (cannot be stripped by customers)
    const cfid = hR('x-amz-cf-id');
    if (cfid) {
      s.xAmzCfId = true;
      s.meta.cfRequestId = cfid;
      // Base64-like ~56 chars ending with ==
      if (/^[A-Za-z0-9+/\-_]{40,70}={0,2}$/.test(cfid.trim())) s.xAmzCfIdValid = true;
    }

    // X-Amz-Cf-Pop: {IATA}{digits}-{tier}{digit} e.g. LAX54-P1, BOS50-C3, FRA6-C1
    const pop = hR('x-amz-cf-pop');
    if (pop) {
      s.xAmzCfPop = true;
      s.meta.cfPop = pop;
      if (/^[A-Z]{3}\d+-[A-Z]\d+$/.test(pop.trim())) s.xAmzCfPopValid = true;
    }

    // Via: 1.1 {32hex}.cloudfront.net (CloudFront)
    if (/cloudfront\.net/i.test(hR('via')))                        s.viaCF              = true;
    if (/^cloudfront$/i.test(hR('server')))                        s.serverCF           = true;
    if (/\b(hit|miss)\s+from\s+cloudfront/i.test(hR('x-cache')))  s.xCacheCF           = true;

    // AWS WAF
    if (res.headers.has('x-amzn-waf-action'))                      s.xAmzWaf            = true;
    if (res.headers.has('x-amzn-requestid'))                       s.xAmzRequestId      = true;
    if (res.headers.has('x-amzn-trace-id'))                        s.xAmzTraceId        = true;

    // S3 origin headers
    if (/^amazons3$/i.test(hR('server')))                          s.serverS3           = true;
    if (res.headers.has('x-amz-id-2'))                             s.xAmzId2            = true;
    if (res.headers.has('x-amz-bucket-region'))                    s.xAmzBucketRegion   = true;
    if (res.headers.has('x-amz-version-id'))                       s.xAmzVersionId      = true;
    if (res.headers.has('x-amz-storage-class'))                    s.xAmzStorageClass   = true;
    if (res.headers.has('x-amz-delete-marker'))                    s.xAmzDeleteMarker   = true;

    // S3 ETag format: "hex32" for unencrypted, "hex32-N" for multipart
    const etag = hR('etag').replace(/"/g, '');
    if (/^[0-9a-f]{32}(-\d+)?$/.test(etag))                       s.etagS3Format       = true;

    if (!body) return;
    if (/generated by cloudfront/i.test(body))                     s.cloudfrontErrorPage = true;
  },

  probes: [], // CloudFront has no public probe endpoints; rely on header/DNS signals

  cnamePatterns: [
    { re: /\.cloudfront\.net$/,   signal: 'cloudfrontCname' },
  ],
  ptrPatterns: [
    { re: /\.cloudfront\.net$/, signal: 'cloudfrontCname' },
  ],
  orgNames: ['amazon.com', 'amazon technologies', 'amazon web services'],
  nsPatterns: [
    // Route 53 NS is a medium-confidence corroborator — many CF distributions use Route 53
    { re: /\.awsdns-\d+\./,       signal: 'cloudfrontIP' },
  ],

  extractCookies(cookies, s) {
    const names = new Set(cookies.map(c => c.name));
    s.cookies.cfPolicy    = names.has('CloudFront-Policy');
    s.cookies.cfSignature = names.has('CloudFront-Signature');
    s.cookies.cfKeyPair   = names.has('CloudFront-Key-Pair-Id');
    // aws-waf-token: issued after AWS WAF Bot Control passes (2023+, active 2026)
    s.cookies.awsWafToken = names.has('aws-waf-token');
  },

  score(s) {
    let n = 0;
    if (s.xAmzCfIdValid)          n += 60; // Exclusive to CloudFront, non-removable
    if (s.xAmzCfPopValid)         n += 55;
    if (s.cloudfrontCname)        n += 50;
    if (s.cloudfrontIP)           n += 48;
    if (s.viaCF)                  n += 45;
    if (s.serverCF)               n += 45;
    if (s.xCacheCF)               n += 42;
    if (s.xAmzCfId)               n += 38;
    if (s.xAmzCfPop)              n += 36;
    if (s.cookies?.cfPolicy)      n += 38; // Signed URL cookies = definitive CF
    if (s.cookies?.cfSignature)   n += 38;
    if (s.cookies?.cfKeyPair)     n += 36;
    if (s.cookies?.awsWafToken)   n += 32; // Bot Control challenge passed
    if (s.xAmzWaf)                n += 30;
    if (s.xAmzRequestId)          n += 22;
    if (s.xAmzTraceId)            n += 20;
    if (s.serverS3)               n += 24; // S3 origin behind CF
    if (s.xAmzId2)                n += 20;
    if (s.xAmzBucketRegion)       n += 18;
    if (s.etagS3Format)           n += 12;
    if (s.cloudfrontErrorPage)    n += 35;
    if (s.dnsShortTtl && n >= 20) n += 5;

    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Amazon CloudFront';
    else if (n >= 55) label = 'Highly Likely CloudFront';
    else if (n >= 35) label = 'Possible CloudFront';
    return { score: n, label, detected: n >= 35 };
  }
});
