// Imperva / Incapsula Provider  v7.4
// 2026 updates:
//  • reese84 is now the *primary* bot-management cookie (replaces ___utmvc as main signal)
//    ___utmvc still seen but increasingly rare on modern Imperva deployments (2025-2026)
//  • Imperva block pages: 200 OK with body "Powered By Incapsula" — status check alone insufficient
//  • X-Iinfo validation regex updated — format confirmed stable: N-N-N-N S:N:N:N:N ...
//  • incap_ses_ and visid_incap_ cookie prefixes remain primary passive identifiers
//  • reese84 script served from obscure path with ?d= query param — not detectable passively
//    but the cookie itself IS detectable via cookies API
//  • v7.4 (research-verified): incap_sh_ cookie prefix confirmed as a newer session cookie
//    used specifically in the GeeTest-CAPTCHA challenge flow (TakionAPI, evisionnow docs,
//    2026) — added as an additional passive cookie signal
//  • v7.4: scoring hardened against thin-signal false positives — a detection now requires
//    signals from at least 2 independent categories (header/cookie/body/CNAME) to reach the
//    "detected" threshold on weaker signals alone; a single strong exclusive signal (X-Iinfo
//    valid format, CNAME match) can still detect on its own since those are definitive.
//  • Note on what's NOT detectable here: Imperva's real defense in 2026 is TLS/JA4
//    fingerprinting, HTTP/2 frame analysis, and JS environment fingerprinting (Canvas,
//    WebGL, Client Hints consistency) — none of which are readable from a browser
//    extension's fetch() response. This detector identifies Imperva's PRESENCE via its
//    passive HTTP/cookie footprint, not its bot-scoring internals.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'imperva', name: 'Imperva', color: '#e84d1c', icon: '🛡',

  knownHeaders: [
    'x-cdn',
    'x-cdn-forward',
    'x-iinfo',
    'x-imforwards',
  ],

  freshSignals: () => ({
    impervaCname: false,
    xIinfoValid: false, xIinfo: false, xCdnIncapsula: false,
    xPoweredByIncapsula: false, xCdnForward: false, xImforwards: false,
    impervaCsp: false,
    incapsulaResource: false, incapsulaResourceDynamic: false,
    incapsulaJsLoader: false, incapsulaBlock: false,
    incapsulaErrorClass: false, impervaBody: false,
    // 2026: reese84 is now the primary bot-management cookie signal
    cookies: {
      visidIncap: false, incapSes: false, nlbi: false,
      reese84: false,    // Primary Gen-3 Bot Management (now dominant)
      utmvc: false,      // Legacy fingerprinting (declining prevalence)
      incapSh: false,    // v7.4: newer session cookie, GeeTest CAPTCHA flow
    },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { iinfoHeader: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    // X-Iinfo: definitively Imperva — format: N-N-N-N S:N:N:N:N ...
    const iinfo = hR('x-iinfo');
    if (iinfo) {
      s.xIinfo = true;
      s.meta.iinfoHeader = iinfo;
      // Validate format: starts with digits-digits-digits-digits
      if (/^\d+-\d+-\d+-\d+\s/.test(iinfo)) s.xIinfoValid = true;
    }

    if (/incapsula/i.test(h('x-cdn')))                             s.xCdnIncapsula        = true;
    if (/incapsula/i.test(h('x-powered-by')))                     s.xPoweredByIncapsula  = true;
    if (res.headers.has('x-cdn-forward'))                          s.xCdnForward          = true;
    if (res.headers.has('x-imforwards'))                           s.xImforwards          = true;

    // CSP header mentioning incapsula.com
    const csp = hR('content-security-policy');
    if (/incapsula\.com/i.test(csp))                               s.impervaCsp           = true;

    if (!body) return;
    // _Incapsula_Resource in body — JS challenge delivery endpoint reference
    if (/_Incapsula_Resource/i.test(body))                         s.incapsulaJsLoader    = true;
    // v7.4: real deployments serve the challenge from a RANDOMIZED path with
    // a "?d=<hostname>" query param (confirmed via 2026 detection writeups),
    // not always the literal "_Incapsula_Resource" string in markup. Match
    // any script/form src pointing at a same-origin path with ?d=<domain>.
    const dParamPattern = new RegExp(`\\?d=${s._domainEscaped || ''}`, 'i');
    if (s._domainEscaped && dParamPattern.test(body))              s.incapsulaResourceDynamic = true;
    // "Powered by Incapsula" or "Powered By Imperva" — block page (may be 200 OK)
    if (/powered\s+by\s+incapsula|powered\s+by\s+imperva/i.test(body)) s.impervaBody      = true;
    // Imperva WAF block page with incident ID
    if (/incapsula incident id|imperva\s+waf/i.test(body))         s.incapsulaBlock       = true;
    if (/class=["']incapsula-error/i.test(body))                   s.incapsulaErrorClass  = true;
  },

  probes: [
    { url: d => `https://${d}/_Incapsula_Resource`,
      validStatuses: [200,302,400,403,404],
      handler: async (res, s) => {
        // The resource endpoint exists and responds (even 403) = strong Imperva signal
        s.incapsulaResource = true;
      }
    }
  ],

  cnamePatterns: [
    { re: /\.incapdns\.net$/,      signal: 'impervaCname' },
    { re: /\.impervadns\.net$/,    signal: 'impervaCname' },
    { re: /\.imperva\.com$/,       signal: 'impervaCname' },
    { re: /\.incapsula\.com$/,     signal: 'impervaCname' },
  ],
  ptrPatterns: [
    { re: /incapdns\.net$|imperva\.com$/, signal: 'impervaCname' },
  ],
  orgNames: ['imperva', 'incapsula'],

  extractCookies(cookies, s) {
    const names = cookies.map(c => c.name);
    s.cookies.visidIncap = names.some(n => /^visid_incap_/i.test(n));
    s.cookies.incapSes   = names.some(n => /^incap_ses_/i.test(n));
    s.cookies.nlbi       = names.some(n => /^nlbi_/i.test(n));
    // reese84 — Gen 3 bot management (now primary)
    s.cookies.reese84    = names.some(n => n === 'reese84');
    // ___utmvc — legacy fingerprinting cookie (declining)
    s.cookies.utmvc      = names.some(n => n === '___utmvc');
    // v7.4: incap_sh_ — newer session cookie tied to the GeeTest CAPTCHA
    // challenge flow, confirmed in 2026 detection writeups (TakionAPI docs)
    s.cookies.incapSh    = names.some(n => /^incap_sh_/i.test(n));
  },

  score(s) {
    let n = 0;
    let strongSignalCount = 0;   // signals confirmed reliable/exclusive to Imperva
    let categoriesHit = new Set(); // header, cookie, body, cname — diversity check

    // Definitive exclusive signals — these alone are trustworthy
    if (s.xIinfoValid)            { n += 65; strongSignalCount++; categoriesHit.add('header'); }
    if (s.impervaCname)           { n += 52; strongSignalCount++; categoriesHit.add('cname'); }
    if (s.cookies?.visidIncap)    { n += 48; strongSignalCount++; categoriesHit.add('cookie'); }
    if (s.cookies?.incapSes)      { n += 46; strongSignalCount++; categoriesHit.add('cookie'); }

    // Corroborating signals — real, but individually weaker / less exclusive
    if (s.xIinfo && !s.xIinfoValid) { n += 30; categoriesHit.add('header'); } // malformed X-Iinfo, still likely
    if (s.cookies?.reese84)       { n += 44; categoriesHit.add('cookie'); }
    if (s.cookies?.incapSh)       { n += 30; categoriesHit.add('cookie'); } // v7.4
    if (s.xCdnIncapsula)          { n += 44; categoriesHit.add('header'); }
    if (s.incapsulaBlock)         { n += 40; categoriesHit.add('body'); }
    if (s.incapsulaResource)      { n += 38; categoriesHit.add('probe'); }
    if (s.incapsulaResourceDynamic) { n += 34; categoriesHit.add('body'); } // v7.4
    if (s.cookies?.nlbi)          { n += 36; categoriesHit.add('cookie'); }
    if (s.impervaBody)            { n += 35; categoriesHit.add('body'); }
    if (s.incapsulaJsLoader)      { n += 32; categoriesHit.add('body'); }
    if (s.xPoweredByIncapsula)    { n += 30; categoriesHit.add('header'); }
    if (s.impervaCsp)             { n += 28; categoriesHit.add('header'); }
    if (s.incapsulaErrorClass)    { n += 26; categoriesHit.add('body'); }

    // Weakest, least-exclusive signals — these headers exist on non-Imperva
    // infrastructure too, so they only ever corroborate, never lead alone.
    if (s.xCdnForward)            { n += 18; categoriesHit.add('header-weak'); }
    if (s.xImforwards)            { n += 14; categoriesHit.add('header-weak'); }

    // ___utmvc: still a corroborator but less reliable now
    if (s.cookies?.utmvc && n > 10) n += 10;
    if (s.timingAnomaly && n > 20) n += 12;
    if (s.dnsShortTtl && n >= 20)  n += 5;

    if (s.ipEvidenceMatch) { n += 10; categoriesHit.add('ip'); } // Independent PTR/RDAP corroborator

    // v7.4: hardening against thin-signal false positives. If NOTHING
    // strong/exclusive fired and the score is being carried entirely by
    // weak header-presence signals from only 1 category, cap the score
    // below the detection threshold — a lone X-Cdn-Forward header isn't
    // enough to call this "Imperva" on its own; it needs at least one
    // more corroborating category.
    if (strongSignalCount === 0 && categoriesHit.size <= 1) {
      n = Math.min(n, 30); // sits in "unlikely" territory regardless of raw sum
    }

    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Imperva (Incapsula)';
    else if (n >= 55) label = 'Highly Likely Imperva';
    else if (n >= 35) label = 'Possible Imperva';
    return { score: n, label, detected: n >= 35 };
  }
});
