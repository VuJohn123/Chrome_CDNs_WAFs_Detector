// DataDome Bot Protection / WAAP (Web App & API Protection) Provider  v8.0
// ============================================================
// NOTE: DataDome is NOT a CDN. It is a bot-management/WAAP product, almost
// always deployed inline on top of a customer's existing CDN or load
// balancer (or invoked synchronously via the Protection API). The UI label
// should read "Bot Protection", not "CDN", to avoid implying it terminates
// or accelerates traffic the way Cloudflare/Akamai/Fastly do.
//
// Documented signals (DataDome official docs + verified observation):
//   Set-Cookie: datadome={value}        — primary clearance cookie (JS-issued)
//   X-DataDome: protected               — present in API-mode integrations
//   X-DataDome-*: (request-headers, botname, botfamily, isbot, ClientID)
//                                        — only visible on Protection-API block responses
//   X-DD-B: 1                           — backend signal header
//   datadome cookie expiry              — typically short-session (~hours), reissued on JS challenge
//   Collector / challenge JS often referenced as ct.captcha-delivery.com
//     or geo.captcha-delivery.com in page body
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'datadome', name: 'DataDome', color: '#7c3aed', icon: '🤖',

  knownHeaders: [
    'x-datadome',
    'x-datadome-botfamily',
    'x-datadome-botname',
    'x-datadome-clientid',
    'x-datadome-isbot',
    'x-dd-b',
  ],
  ipConfig: null, // DataDome does not publish machine-readable IP ranges (deployed inline, not as a proxy network)

  freshSignals: () => ({
    xDataDome: false, xDataDomeValid: false,
    xDataDomeBotHeaders: false, xDdB: false,
    captchaDeliveryRef: false, ddJsChallenge: false,
    ddBlockBody: false,
    cookies: { datadome: false },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';

    // X-DataDome: protected — set on API-integrated deployments
    if (/protected/i.test(hR('x-datadome'))) { s.xDataDome = true; s.xDataDomeValid = true; }
    else if (res.headers.has('x-datadome'))    s.xDataDome = true;

    // X-DataDome-* family only appears on block/challenge responses
    if (res.headers.has('x-datadome-botname') || res.headers.has('x-datadome-botfamily') ||
        res.headers.has('x-datadome-isbot')   || res.headers.has('x-datadome-clientid'))
      s.xDataDomeBotHeaders = true;

    if (res.headers.has('x-dd-b')) s.xDdB = true;

    if (!body) return;
    // Collector/challenge JS domains referenced in page body
    if (/captcha-delivery\.com/i.test(body))            s.captchaDeliveryRef = true;
    if (/\bdd=['"]?[\w-]{8,}|datadome[_-]?js|dataDomeOptions/i.test(body)) s.ddJsChallenge = true;
    if (/datadome/i.test(body) && /(blocked|verify you are human|automated request)/i.test(body))
      s.ddBlockBody = true;
  },

  probes: [],

  cnamePatterns: [], // DataDome is not CNAME-based; it's an inline module

  // DataDome has no public IP ranges, but its challenge/collector infra and
  // RDAP org name can still corroborate a detection independently of headers.
  ptrPatterns: [
    { re: /datadome\.co$/, signal: 'captchaDeliveryRef' },
  ],
  orgNames: ['datadome'],

  extractCookies(cookies, s) {
    s.cookies.datadome = cookies.some(c => c.name === 'datadome');
  },

  score(s) {
    let n = 0;
    // The bare "datadome" cookie name is not cryptographically tied to the
    // vendor — any site could set a cookie with that name. Treat it as a
    // strong signal only when corroborated by a header, body pattern, or
    // independent IP/PTR/RDAP evidence; otherwise cap it well below the
    // "Highly Likely" threshold to avoid a false positive from name alone.
    const hasCorroboration = s.xDataDome || s.xDataDomeBotHeaders || s.ddBlockBody ||
      s.captchaDeliveryRef || s.ddJsChallenge || s.xDdB || s.ipEvidenceMatch;

    if (s.cookies?.datadome) n += hasCorroboration ? 55 : 25;
    if (s.xDataDomeValid)        n += 50;
    else if (s.xDataDome)        n += 40;
    if (s.xDataDomeBotHeaders)   n += 48; // Only present on DataDome-branded block pages
    if (s.ddBlockBody)           n += 42;
    if (s.captchaDeliveryRef)    n += 38; // Challenge delivery domain is DataDome-exclusive
    if (s.ddJsChallenge)         n += 30;
    if (s.xDdB)                  n += 22;
    if (s.ipEvidenceMatch)       n += 15; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed DataDome';
    else if (n >= 55) label = 'Highly Likely DataDome';
    else if (n >= 32) label = 'Possible DataDome';
    return { score: n, label, detected: n >= 32 };
  }
});
