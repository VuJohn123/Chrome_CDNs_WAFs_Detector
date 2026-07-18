// Azure CDN / Front Door Provider  v7.4
// 2026 updates:
//  • X-Azure-RequestChain hops= format confirmed stable in 2026 AFD docs
//  • AFD classic (CDN legacy) retired Aug 2025; NS/CNAME detection remains valid
//  • X-Azure-Ref: both old base64 and new timestamp formats accepted
//  • Azure Front Door switched from Anycast → Unicast routing (Mar–Apr 2026)
//  • X-Azure-DebugInfo probe still functional when sent as request header
//  • v7.4 (research-corrected): removed X-Azure-JA4-Fingerprint check. Verified
//    against Microsoft's own Front Door HTTP headers documentation
//    (MicrosoftDocs/azure-docs) that this header is attached to the request
//    Front Door forwards to the ORIGIN server, not to the response sent back
//    to the client — a browser extension reading fetch() responses can never
//    observe it. The previous version silently carried this as always-false
//    dead code contributing a 48-point weight that could never actually fire.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'azure', name: 'Azure', color: '#0078d4', icon: '🔷',

  knownHeaders: [
    'x-azure-externalerror',
    'x-azure-fdid',
    'x-azure-internalerror',
    'x-azure-originstatus',
    'x-azure-ref',
    'x-azure-requestchain',
    'x-ms-access-tier',
    'x-ms-activity-id',
    'x-ms-blob-type',
    'x-ms-client-request-id',
    'x-ms-creation-time',
    'x-ms-request-id',
    'x-ms-routing-name',
    'x-ms-server-encrypted',
    'x-ms-version',
  ],

  freshSignals: () => ({
    azureCname: false, azureTrafficMgr: false,
    xAzureRefValid: false, xAzureRef: false,
    xAzureFdidValid: false, xAzureFdid: false,
    viaAzure: false, xAzureRequestChain: false, xAzureCacheHit: false,
    xMsRoutingName: false, xMsRequestId: false, xMsVersion: false,
    xMsClientRequestId: false, xMsActivityId: false, xMsEdge: false,
    serverAzureStorage: false, xMsBlobType: false, xMsAccessTier: false,
    xMsServerEncrypted: false, xMsCreationTime: false,
    azureDebugHeaders: false, serverIIS: false,
    azureWafBlock: false, azureErrorPage: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { azureRef: null, fdid: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    // CNAME detection handled by cnamePatterns
    if (/1\.1 azure/i.test(hR('via')))                             s.viaAzure          = true;

    // X-Azure-Ref — unique request reference string
    const ref = hR('x-azure-ref');
    if (ref) {
      s.xAzureRef = true;
      s.meta.azureRef = ref;
      // Old format: base64-like opaque string starting with digits or alphanums
      // New 2026 format also includes timestamp component — both valid
      if (/^0[A-Za-z0-9+/=]{20,}/.test(ref) || /^\d{4}-\d{2}/.test(ref))
        s.xAzureRefValid = true;
      else if (ref.length > 20)
        s.xAzureRefValid = true; // Accept any sufficiently long AFD ref
    }

    // X-Azure-FDID — UUID identifying the Front Door profile
    const fdid = hR('x-azure-fdid');
    if (fdid) {
      s.xAzureFdid = true;
      s.meta.fdid  = fdid;
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(fdid))
        s.xAzureFdidValid = true;
    }

    // X-Azure-RequestChain — loop detection header (hops=N)
    if (/hops=\d+/i.test(hR('x-azure-requestchain')))             s.xAzureRequestChain = true;

    // X-Cache — AFD sets this for cache status
    if (/\bCONFIG_NOCACHE\b|\bTCP_HIT\b|\bTCP_MISS\b|\bTCP_EXPIRED_HIT\b/i.test(hR('x-cache')) ||
        /azure/i.test(hR('x-cache')))
                                                                    s.xAzureCacheHit    = true;

    // NOTE: X-Azure-JA4-Fingerprint was previously checked here, but research
    // against Microsoft's own Front Door documentation confirmed this header
    // is added to the OUTGOING request Front Door sends to the origin/backend
    // server — it is never returned in the response a client receives. A
    // browser extension can only read response headers via fetch(), so this
    // check could never fire and was silently inflating confidence with a
    // signal that was structurally impossible to observe. Removed rather
    // than left as always-false dead weight.

    // X-MS-* family headers
    if (res.headers.has('x-ms-routing-name'))                       s.xMsRoutingName     = true;
    if (res.headers.has('x-ms-request-id'))                        s.xMsRequestId      = true;
    if (res.headers.has('x-ms-version'))                           s.xMsVersion        = true;
    if (res.headers.has('x-ms-client-request-id'))                 s.xMsClientRequestId = true;
    if (res.headers.has('x-ms-activity-id'))                       s.xMsActivityId     = true;
    if (/^x-ms-edge/i.test([...res.headers.keys()].join(' ')))     s.xMsEdge           = true;

    // Azure Blob Storage
    if (/windows-azure-(blob|table)/i.test(hR('server')))          s.serverAzureStorage = true;
    if (res.headers.has('x-ms-blob-type'))                         s.xMsBlobType       = true;
    if (res.headers.has('x-ms-access-tier'))                       s.xMsAccessTier     = true;
    if (/true/i.test(hR('x-ms-server-encrypted')))                 s.xMsServerEncrypted = true;
    if (res.headers.has('x-ms-creation-time'))                     s.xMsCreationTime   = true;

    if (/microsoft-iis/i.test(hR('server')))                       s.serverIIS         = true;

    if (!body) return;
    if (/microsoft azure application gateway|azure waf/i.test(body)) s.azureWafBlock   = true;
    if (/microsoft azure|windows azure|azurefd\.net/i.test(body))    s.azureErrorPage  = true;
  },

  probes: [
    // X-Azure-DebugInfo probe: send header, expect AFD debug response headers
    {
      url: d => `https://${d}/`,
      opts: { headers: { 'X-Azure-DebugInfo': '1' }, cache: 'no-store' },
      validStatuses: [200,301,302,403,404,503],
      handler: (res, s) => {
        if (res.headers.has('x-azure-originstatus') ||
            res.headers.has('x-azure-internalerror') ||
            res.headers.has('x-azure-externalerror'))
          s.azureDebugHeaders = true;
      }
    }
  ],

  cnamePatterns: [
    { re: /\.azureedge\.net$/,         signal: 'azureCname'    },
    { re: /\.azurefd\.net$/,           signal: 'azureCname'    },
    { re: /\.z\d+\.web\.core\.windows\.net$/, signal: 'azureCname' },
    { re: /\.trafficmanager\.net$/,    signal: 'azureTrafficMgr' },
    { re: /\.azure\.com$/,             signal: 'azureCname'    },
    { re: /\.msedge\.net$/,            signal: 'azureCname'    },
  ],
  ptrPatterns: [
    { re: /cloudapp\.azure\.com$|azureedge\.net$|msedge\.net$/, signal: 'azureCname' },
  ],
  orgNames: ['microsoft corporation', 'microsoft azure', 'microsoft'],
  nsPatterns: [
    { re: /azure-dns\.(com|net|org|info)$/, signal: 'azureCname' },
  ],

  score(s) {
    let n = 0;
    if (s.xAzureRefValid)     n += 55;
    if (s.xAzureFdidValid)    n += 52;
    if (s.azureCname)         n += 42;
    if (s.xAzureRequestChain) n += 38;
    if (s.viaAzure)           n += 36;
    if (s.xAzureRef)          n += 32;
    if (s.xAzureFdid)         n += 32;
    if (s.azureDebugHeaders)  n += 30;
    if (s.xAzureCacheHit)     n += 28;
    if (s.xMsRequestId)       n += 24;
    if (s.xMsRoutingName)     n += 22;
    if (s.xMsVersion)         n += 20;
    if (s.azureTrafficMgr)    n += 20;
    if (s.serverAzureStorage) n += 26;
    if (s.xMsBlobType)        n += 24;
    if (s.xMsAccessTier)      n += 18;
    if (s.xMsServerEncrypted) n += 16;
    if (s.xMsCreationTime)    n += 14;
    if (s.xMsEdge)            n += 14;
    if (s.xMsClientRequestId) n += 12;
    if (s.xMsActivityId)      n += 12;
    if (s.serverIIS)          n += 8;
    if (s.azureWafBlock)      n += 26;
    if (s.azureErrorPage)     n += 22;
    if (s.dnsShortTtl && n >= 20) n += 5;

    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Azure Front Door / CDN';
    else if (n >= 55) label = 'Highly Likely Azure';
    else if (n >= 35) label = 'Possible Azure';
    return { score: n, label, detected: n >= 35 };
  }
});
