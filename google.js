// Google GFE / Cloud CDN Provider  v7.3
// 2026 updates:
//  • x-goog-hash: crc32c= or md5= — Cloud Storage content integrity header
//  • x-goog-expiration: signed URL expiry timestamp (Cloud Storage signed URLs)
//  • Cloud Armor block page pattern updated — now includes "Your request was blocked"
//  • google-cloud-trace header: newer trace format used by Cloud Run/Functions 2025+
//  • x-google-cache-control: internal cache directive present on GFE responses
//  • Via: 1.1 google — simpler format also seen on newer GFE deployments

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'google', name: 'Google', color: '#4285f4', icon: '🔵',

  knownHeaders: [
    'google-cloud-trace',
    'x-appengine-city',
    'x-appengine-country',
    'x-cloud-trace-context',
    'x-firebase',
    'x-gfe-request-stage',
    'x-goog-expiration',
    'x-goog-generation',
    'x-goog-hash',
    'x-goog-stored-content-encoding',
    'x-google-backends',
    'x-google-cache-control',
    'x-google-gfe-request-stage',
    'x-guploader-uploadid',
  ],

  ipConfig: {
    ipSignal: 'googleIP', storageKey: 'ip_google',
    v4Url: 'https://www.gstatic.com/ipranges/goog.json', singleFile: true,
    v4: [], v6: [],
    parseResponse(text, family) {
      try {
        const d = JSON.parse(text);
        if (family === 'v4') return (d.prefixes || []).filter(p => p.ipv4Prefix).map(p => p.ipv4Prefix);
        return (d.prefixes || []).filter(p => p.ipv6Prefix).map(p => p.ipv6Prefix);
      } catch { return []; }
    }
  },

  freshSignals: () => ({
    googleIP: false, googleCname: false, googleFirebaseCname: false,
    googleRunCname: false, googleWorkspaceMx: false,
    viaGoogle: false, viaGoogleValid: false,
    serverGws: false, serverEsf: false, serverGse: false, serverUploadServer: false,
    googleH3: false,
    xCloudTrace: false, xCloudTraceValid: false,
    // 2026: google-cloud-trace (newer format — Cloud Run/Functions)
    googleCloudTrace: false,
    xGoogBackends: false, xGfeStage: false, xAppEngine: false,
    xGoogStoredContent: false, xGuploader: false, xFirebase: false,
    xGoogHash: false,
    xGoogExpiration: false,
    // 2026: x-google-cache-control — internal GFE cache directive
    xGoogleCacheControl: false,
    cloudArmorBlock: false, googleErrorPage: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { traceContext: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    const via = hR('via');
    if (/\bgoogle\b/i.test(via)) {
      s.viaGoogle = true;
      // Both "1.1 google" (simple) and "1.1 {node}.google.com" formats
      if (/1\.1 google$|[a-z0-9\-]+\.google\.com\b/i.test(via)) s.viaGoogleValid = true;
    }

    const server = hR('server');
    if (/^gws$/i.test(server))           s.serverGws          = true;
    if (/^esf$/i.test(server))           s.serverEsf          = true;
    if (/^gse$/i.test(server))           s.serverGse          = true;
    if (/^UploadServer$/i.test(server))  s.serverUploadServer = true;

    if (/ma=2592000/i.test(hR('alt-svc'))) s.googleH3          = true;

    // x-cloud-trace-context (standard GCP format)
    const trace = hR('x-cloud-trace-context');
    if (trace) {
      s.xCloudTrace = true;
      s.meta.traceContext = trace;
      if (/^[0-9a-f]{32}\/\d+;o=[01]$/.test(trace)) s.xCloudTraceValid = true;
    }

    // google-cloud-trace — newer format on Cloud Run/Functions (2025+)
    if (res.headers.has('google-cloud-trace'))                      s.googleCloudTrace       = true;

    if (res.headers.has('x-google-backends') || res.headers.has('x-gfe-request-stage') ||
        res.headers.has('x-google-gfe-request-stage'))              s.xGoogBackends          = true;
    if (res.headers.has('x-gfe-request-stage'))                    s.xGfeStage              = true;
    if (res.headers.has('x-appengine-country') || res.headers.has('x-appengine-city'))
                                                                    s.xAppEngine             = true;
    if (res.headers.has('x-goog-stored-content-encoding') ||
        res.headers.has('x-goog-generation'))                       s.xGoogStoredContent     = true;
    if (res.headers.has('x-guploader-uploadid'))                   s.xGuploader             = true;
    if (res.headers.has('x-goog-hash'))                            s.xGoogHash              = true;
    if (res.headers.has('x-goog-expiration'))                      s.xGoogExpiration        = true;
    // x-google-cache-control: internal GFE directive (2026)
    if (res.headers.has('x-google-cache-control'))                 s.xGoogleCacheControl    = true;
    if (Array.from(res.headers.keys()).some(k => k.startsWith('x-firebase')))
                                                                    s.xFirebase              = true;

    if (!body) return;
    // Cloud Armor block patterns (updated for 2025-2026 page wording)
    if (/request was blocked|cloud armor|google\.com\/support\/webmasters/i.test(body))
      s.cloudArmorBlock = true;
    if (/Error\s+\d{3}\s*<\/title>|\/\/www\.google\.com\/intl\//i.test(body))
      s.googleErrorPage = true;
  },

  probes: [],

  cnamePatterns: [
    { re: /\.googleusercontent\.com$/, signal: 'googleCname'         },
    { re: /\.gvt1\.com$/,              signal: 'googleCname'         },
    { re: /\.gvt2\.com$/,              signal: 'googleCname'         },
    { re: /\.1e100\.net$/,             signal: 'googleCname'         },
    { re: /\.appspot\.com$/,           signal: 'googleCname'         },
    { re: /\.google\.com$/,            signal: 'googleCname'         },
    { re: /\.web\.app$/,               signal: 'googleFirebaseCname' },
    { re: /\.firebaseapp\.com$/,       signal: 'googleFirebaseCname' },
    { re: /\.run\.app$/,               signal: 'googleRunCname'      },
    { re: /\.cloudfunctions\.net$/,    signal: 'googleRunCname'      },
    { re: /\.a\.run\.app$/,            signal: 'googleRunCname'      },
    { re: /\.cloudfunctions\.net$/,    signal: 'googleRunCname'      },
  ],
  ptrPatterns: [
    { re: /1e100\.net$|googleusercontent\.com$/, signal: 'googleCname' },
  ],
  orgNames: ['google llc', 'google'],
  mxPatterns: [
    { re: /aspmx\.l\.google\.com$/,           signal: 'googleWorkspaceMx' },
    { re: /alt[1-4]\.aspmx\.l\.google\.com$/, signal: 'googleWorkspaceMx' },
    { re: /\.googlemail\.com$/,               signal: 'googleWorkspaceMx' },
  ],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.viaGoogleValid)      n = Math.max(n, 82); else if (s.viaGoogle) n = Math.max(n, 70);
    if (s.serverGws)           n = Math.max(n, 82);
    if (s.serverEsf)           n = Math.max(n, 78);
    if (s.serverGse)           n = Math.max(n, 75);
    if (s.googleFirebaseCname) n = Math.max(n, 78);
    if (s.googleRunCname)      n = Math.max(n, 78);
    if (s.googleCname)         n = Math.max(n, 72);
    if (s.xCloudTraceValid)    n = Math.max(n, 72);
    if (s.googleIP)            n = Math.max(n, 65);
    if (s.xGoogBackends)       n += 18;
    if (s.xGfeStage)           n += 16;
    if (s.xGoogStoredContent)  n += 16;
    if (s.xGuploader)          n += 14;
    if (s.xGoogHash)           n += 14;
    if (s.xGoogExpiration)     n += 12;
    if (s.xCloudTrace)         n += 12;
    if (s.googleCloudTrace)    n += 12; // 2026 new signal
    if (s.xGoogleCacheControl) n += 10; // 2026 new signal
    if (s.serverUploadServer)  n += 14;
    if (s.googleWorkspaceMx)   n += 12;
    if (s.xFirebase)           n += 14;
    if (s.xAppEngine)          n += 12;
    if (s.cloudArmorBlock)     n += 14;
    if (s.googleH3)            n += 10;
    if (s.googleErrorPage)     n += 10;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 85) label = 'Confirmed Google GFE / Cloud CDN';
    else if (n >= 65) label = 'Confirmed Google';
    else if (n >= 45) label = 'Likely Google';
    else if (n >= 28) label = 'Possible Google';
    return { score: n, label, detected: n >= 28 };
  }
});
