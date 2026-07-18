// ============================================================
// Multi-CDN/WAF Detector — popup.js  v7.1
// Bug fixes from v6:
//   • Vercel color changed to #e2e8f0 (visible on dark bg)
//   • Full null-guard on pv?.verdict?.label ?? 'Unlikely'
//   • pc-bar hidden when score=0 (no spurious colored stub)
//   • Re-scan button bypasses 5-min cache
//   • DNS TTL displayed in Session Intel
//   • Multi-provider overlap warning
//   • 12-provider grid (3-col) with correct layout
// ============================================================

const PROVIDER_UI = {
  cloudflare: { name:'Cloudflare', color:'#f38020', icon:'⛅', groups:[
    { title:'Network', signals:[
      {key:'cfIP',               label:'Resolves to CF IP',                tip:'A/AAAA in Cloudflare IP ranges'},
      {key:'cfCname',            label:'CNAME → cdn.cloudflare.net'},
      {key:'cfPages',            label:'CNAME → *.pages.dev',              tip:'Cloudflare Pages hosting'},
      {key:'cfEmailMx',          label:'MX → mx.cloudflare.net',           tip:'CF Email Routing'},
    ]},
    { title:'Identity Headers', signals:[
      {key:'cfRay',              label:'CF-RAY present'},
      {key:'cfRayValid',         label:'CF-RAY valid {16hex}-{IATA}'},
      {key:'serverHeader',       label:'Server: cloudflare'},
      {key:'cdnLoop',            label:'CDN-Loop: cloudflare',              tip:'Loop-prevention header — proves CF edge'},
      {key:'cfEwVia',            label:'CF-EW-Via (Workers active)'},
      {key:'cfVisitor',          label:'CF-Visitor (proxy JSON)'},
      {key:'cfEdgeCache',        label:'CF-Edge-Cache (Enterprise)'},
      {key:'cfTrueClientIp',     label:'True-Client-IP / CF-Connecting-IP'},
      {key:'cfPagesHeaders',     label:'CF-Pages-Commit-SHA / Deployment-ID'},
      {key:'cfBgj',              label:'CF-BGJ (Enterprise internal)'},
      {key:'cfRequestId',        label:'CF-Request-ID (supplementary trace ID)'},
    ]},
    { title:'Cache / WAF / H3', signals:[
      {key:'cfCacheValid',       label:'CF-Cache-Status valid value'},
      {key:'cfMitigated',        label:'CF-Mitigated: challenge'},
      {key:'nelCloudflare',      label:'Report-To: nel.cloudflare.com'},
      {key:'h3AltSvc',           label:'Alt-Svc: h3=\":443\" (CF format)'},
    ]},
    { title:'cdn-cgi Probes', signals:[
      {key:'trace',              label:'/cdn-cgi/trace reachable'},
      {key:'traceConfirmed',     label:'Trace colo= confirmed',             tip:'Proves live CF edge proxying'},
      {key:'assets',             label:'/cdn-cgi/challenge-platform'},
      {key:'cfRum',              label:'/cdn-cgi/rum (RUM beacon)'},
      {key:'cfZaraz',            label:'/cdn-cgi/zaraz (Zaraz tag mgr)'},
      {key:'cfImageResizing',    label:'/cdn-cgi/image (Image Resizing)'},
      {key:'cfBotManagement',    label:'/cdn-cgi/bot-management probe'},
    ]},
    { title:'Trace Intel', signals:[
      {key:'traceKex',           label:'Post-Quantum KEX (MLKEM768)'},
      {key:'traceGateway',       label:'Zero Trust Gateway (gateway=on)'},
      {key:'traceWarp',          label:'WARP VPN (warp=on)'},
      {key:'traceRbi',           label:'Remote Browser Isolation (rbi=on)'},
    ]},
    { title:'Content Analysis', signals:[
      {key:'challengePage',      label:'Challenge / 5-second screen'},
      {key:'turnstile',          label:'Turnstile / JS Challenge'},
      {key:'aiLabyrinth',        label:'AI Labyrinth honeypot',             tip:'_cf_chl_opt injection'},
      {key:'cfCvParams',         label:'window.__CF$cv$params in body'},
      {key:'cfRocketLoader',     label:'Rocket Loader (/cdn-cgi/scripts/)'},
      {key:'cfEmailObfuscation', label:'Email Obfuscation (data-cfemail)'},
      {key:'cfErrorCode',        label:'CF error code 1xxx in body'},
    ]},
    { title:'Cookies', signals:[
      {key:'cookies.cfClearance',label:'cf_clearance',                      tip:'Issued after passing a challenge'},
      {key:'cookies.cfBm',       label:'__cf_bm (Bot Management)'},
      {key:'cookies.cfWaiting',  label:'__cfwaitingroom'},
      {key:'cookies.cfAccess',   label:'CF_Authorization (Zero Trust)'},
    ]},
  ]},

  google: { name:'Google', color:'#4285f4', icon:'🔵', groups:[
    { title:'Network', signals:[
      {key:'googleIP',            label:'Resolves to Google IP'},
      {key:'googleCname',         label:'CNAME → Google infrastructure'},
      {key:'googleFirebaseCname', label:'CNAME → Firebase (*.web.app)'},
      {key:'googleRunCname',      label:'CNAME → Cloud Run (*.run.app)'},
      {key:'googleWorkspaceMx',   label:'MX → Google Workspace'},
    ]},
    { title:'Via / Server', signals:[
      {key:'viaGoogleValid',      label:'Via: *.google.com (validated)',     tip:'Strongest single GFE signal'},
      {key:'viaGoogle',           label:'Via: 1.1 google (generic)'},
      {key:'serverGws',           label:'Server: gws (Google Web Server)'},
      {key:'serverEsf',           label:'Server: ESF (Endpoints ServiceFront)'},
      {key:'serverGse',           label:'Server: GSE (App Engine)'},
      {key:'serverUploadServer',  label:'Server: UploadServer (Cloud Storage)'},
      {key:'googleH3',            label:'Alt-Svc ma=2592000 (Google H3)'},
    ]},
    { title:'Tracing / Internal Headers', signals:[
      {key:'xCloudTraceValid',    label:'X-Cloud-Trace-Context (validated)'},
      {key:'xCloudTrace',         label:'X-Cloud-Trace-Context present'},
      {key:'xGoogBackends',       label:'X-Google-Backends / X-GFE headers'},
      {key:'xGfeStage',           label:'X-GFE-Request-Stage'},
      {key:'xAppEngine',          label:'X-AppEngine-Country/City'},
      {key:'xGoogStoredContent',  label:'X-Goog-Stored-Content (GCS)'},
      {key:'xGoogHash',           label:'X-Goog-Hash (GCS content hash)'},
      {key:'xGoogExpiration',     label:'X-Goog-Expiration (signed URL)'},
      {key:'xGuploader',          label:'X-GUploader-UploadId (GCS)'},
      {key:'xFirebase',           label:'X-Firebase-* headers'},
    ]},
    { title:'WAF / Content', signals:[
      {key:'cloudArmorBlock',     label:'Cloud Armor WAF block page'},
      {key:'googleErrorPage',     label:'Google GFE error page'},
    ]},
  ]},

  akamai: { name:'Akamai', color:'#009bde', icon:'🌊', groups:[
    { title:'Network', signals:[
      {key:'akamaiCname',        label:'CNAME → Akamai',                   tip:'*.akamaiedge.net, *.edgekey.net…'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverAkamai',        label:'Server: AkamaiGHost / NetStorage', tip:'Exclusively Akamai'},
      {key:'xAkamaiTransformed',  label:'X-Akamai-Transformed'},
      {key:'xAkamaiRequestId',    label:'X-Akamai-Request-ID'},
      {key:'xAkamaiEdgescape',    label:'X-Akamai-Edgescape (geo data)'},
      {key:'xAkamaiOriginHop',    label:'Akamai-Origin-Hop'},
      {key:'xAkamaiGrn',          label:'Akamai-GRN (Ghost Request #)'},
      {key:'xAkamaiCacheStatus',  label:'Akamai-Cache-Status'},
      {key:'xAkamaiSslSid',       label:'X-Akamai-SSL-Client-Sid'},
      {key:'xAkamaiSessionInfo',  label:'X-Akamai-Session-Info (Bot Mgr)'},
      {key:'xTrueCacheKey',       label:'X-True-Cache-Key'},
      {key:'xSerial',             label:'X-Serial (edge serial #)'},
      {key:'xCacheAkamai',        label:'X-Cache: TCP_* from *.akamai.net'},
      {key:'xCheckCacheable',     label:'X-Check-Cacheable (pragma probe)'},
    ]},
    { title:'Active Probes', signals:[
      {key:'pragmaProbe',         label:'Pragma probe returned diagnostics'},
      {key:'akamaiSureRoute',     label:'/akamai/sureroute-test-object.html'},
      {key:'akamaiMpulse',        label:'/_mPulse/api/v1/ (Akamai RUM)'},
    ]},
    { title:'WAF / Content', signals:[
      {key:'akamaiWafBlock',      label:'Kona WAF block (Reference #)'},
      {key:'akamaiErrorBody',     label:'Akamai Error in body'},
    ]},
    { title:'Bot Manager Cookies', signals:[
      {key:'cookies.abck',        label:'_abck (Bot Manager sensor)'},
      {key:'cookies.bmSz',        label:'bm_sz (session size)'},
      {key:'cookies.akBmsc',      label:'ak_bmsc (session)'},
      {key:'cookies.bmSv',        label:'bm_sv (visitor)'},
      {key:'cookies.bmMi',        label:'bm_mi (machine info)'},
    ]},
  ]},

  fastly: { name:'Fastly', color:'#ff282d', icon:'⚡', groups:[
    { title:'Network', signals:[
      {key:'fastlyIP',            label:'Resolves to Fastly IP'},
      {key:'fastlyCname',         label:'CNAME → *.fastly.net'},
    ]},
    { title:'Fastly-Proprietary Headers', signals:[
      {key:'xServedByValid',      label:'X-Served-By (validated)',          tip:'cache-{city}{id}-{IATA} per Fastly docs'},
      {key:'xServedByShielded',   label:'X-Served-By: 2+ entries (shielded)'},
      {key:'xTimerValid',         label:'X-Timer (validated format)'},
      {key:'cdnLoopFastly',       label:'CDN-Loop: Fastly',                 tip:'Distinct from CDN-Loop: cloudflare'},
      {key:'fastlyRequestId',     label:'X-Fastly-Request-ID present'},
      {key:'fastlyRequestIdValid',label:'X-Fastly-Request-ID (validated 40-hex)', tip:'40 lowercase hex chars confirmed per 2026 Fastly docs'},
      {key:'fastlyImageOpto',     label:'X-Fastly-Imageopto-Api'},
      {key:'fastlyRestarts',      label:'Fastly-Restarts'},
      {key:'xCacheHits',          label:'X-Cache-Hits (per-hop count)'},
      {key:'xCacheMultiHit',      label:'X-Cache multi-value (shielded)'},
      {key:'surrogateControl',    label:'Surrogate-Control'},
    ]},
    { title:'Debug Probe (Fastly-Debug: 1)', signals:[
      {key:'fastlyDebugDigest',   label:'Fastly-Debug-Digest',              tip:'Only returned when Fastly-Debug: 1 sent'},
      {key:'fastlyDebugTtl',      label:'Fastly-Debug-TTL'},
      {key:'fastlyDebugPath',     label:'Fastly-Debug-Path'},
      {key:'fastlySurrogateKey',  label:'Surrogate-Key (debug-visible)'},
    ]},
    { title:'Varnish (lower confidence)', signals:[
      {key:'viaVarnish',          label:'Via: 1.1 varnish',                 tip:'Fastly uses Varnish; others do too'},
      {key:'serverVarnish',       label:'Server: Varnish'},
      {key:'xVarnish',            label:'X-Varnish (transaction ID)'},
    ]},
  ]},

  imperva: { name:'Imperva', color:'#e84d1c', icon:'🛡', groups:[
    { title:'Network', signals:[
      {key:'impervaCname',        label:'CNAME → Imperva',                  tip:'*.incapdns.net, *.impervadns.net'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xIinfoValid',         label:'X-Iinfo (validated)',              tip:'Exclusively Imperva — definitively identifies'},
      {key:'xIinfo',              label:'X-Iinfo present'},
      {key:'xCdnIncapsula',       label:'X-CDN: Incapsula'},
      {key:'xPoweredByIncapsula', label:'X-Powered-By: Incapsula'},
      {key:'xCdnForward',         label:'X-Cdn-Forward'},
      {key:'xImforwards',         label:'X-Imforwards'},
      {key:'impervaCsp',          label:'incapsula.com in CSP header'},
    ]},
    { title:'Active Probes', signals:[
      {key:'incapsulaResource',   label:'/_Incapsula_Resource reachable',   tip:'Imperva JS challenge delivery endpoint'},
    ]},
    { title:'Content Analysis', signals:[
      {key:'incapsulaJsLoader',   label:'_Incapsula_Resource in body'},
      {key:'incapsulaBlock',      label:'Imperva WAF block page'},
      {key:'incapsulaErrorClass', label:'CSS class "incapsula-error"'},
      {key:'impervaBody',         label:'"Powered by Imperva" in body'},
    ]},
    { title:'Bot Management Cookies', signals:[
      {key:'cookies.visidIncap',  label:'visid_incap_{id}'},
      {key:'cookies.incapSes',    label:'incap_ses_{port}_{id}'},
      {key:'cookies.nlbi',        label:'nlbi_{id}'},
      {key:'cookies.reese84',     label:'reese84 (Gen 3 Bot Management)'},
      {key:'cookies.utmvc',       label:'___utmvc (fingerprinting)'},
    ]},
  ]},

  cloudfront: { name:'CloudFront', color:'#ff9900', icon:'☁', groups:[
    { title:'Network', signals:[
      {key:'cloudfrontIP',        label:'Resolves to CloudFront IP'},
      {key:'cloudfrontCname',     label:'CNAME → *.cloudfront.net'},
    ]},
    { title:'CloudFront-Exclusive Headers', signals:[
      {key:'xAmzCfIdValid',       label:'X-Amz-Cf-Id (validated)',          tip:'Exclusively CloudFront — no other CDN'},
      {key:'xAmzCfId',            label:'X-Amz-Cf-Id present'},
      {key:'xAmzCfPopValid',      label:'X-Amz-Cf-Pop (validated format)'},
      {key:'xAmzCfPop',           label:'X-Amz-Cf-Pop present'},
      {key:'viaCF',               label:'Via: 1.1 *.cloudfront.net'},
      {key:'serverCF',            label:'Server: CloudFront'},
      {key:'xCacheCF',            label:'X-Cache: Hit/Miss from cloudfront'},
    ]},
    { title:'AWS WAF / Lambda', signals:[
      {key:'xAmzWaf',             label:'X-Amzn-Waf-Action'},
      {key:'xAmzRequestId',       label:'X-Amzn-Requestid (Lambda@Edge)'},
      {key:'xAmzTraceId',         label:'X-Amzn-Trace-Id (X-Ray)'},
    ]},
    { title:'S3 Origin Headers', signals:[
      {key:'serverS3',            label:'Server: AmazonS3'},
      {key:'xAmzId2',             label:'X-Amz-Id-2'},
      {key:'xAmzBucketRegion',    label:'X-Amz-Bucket-Region'},
      {key:'xAmzVersionId',       label:'X-Amz-Version-Id'},
      {key:'xAmzStorageClass',    label:'X-Amz-Storage-Class'},
      {key:'xAmzDeleteMarker',    label:'X-Amz-Delete-Marker'},
      {key:'etagS3Format',        label:'ETag matches S3 MD5 format'},
    ]},
    { title:'Signed URL Cookies', signals:[
      {key:'cookies.cfPolicy',    label:'CloudFront-Policy'},
      {key:'cookies.cfSignature', label:'CloudFront-Signature'},
      {key:'cookies.cfKeyPair',   label:'CloudFront-Key-Pair-Id'},
    ]},
    { title:'Content', signals:[
      {key:'cloudfrontErrorPage', label:'CF error page ("Generated by cloudfront")'},
    ]},
  ]},

  azure: { name:'Azure', color:'#0078d4', icon:'🔷', groups:[
    { title:'Network', signals:[
      {key:'azureCname',          label:'CNAME → Azure CDN / Front Door',   tip:'*.azureedge.net, *.azurefd.net'},
      {key:'azureTrafficMgr',     label:'CNAME → *.trafficmanager.net'},
    ]},
    { title:'Front Door Headers', signals:[
      {key:'xAzureRefValid',      label:'X-Azure-Ref (validated)',           tip:'Both old base64 & new 2026 timestamp formats accepted'},
      {key:'xAzureRef',           label:'X-Azure-Ref present'},
      {key:'xAzureFdidValid',     label:'X-Azure-FDID (validated UUID)'},
      {key:'xAzureFdid',          label:'X-Azure-FDID present'},
      {key:'viaAzure',            label:'Via: 1.1 Azure'},
      {key:'xAzureRequestChain',  label:'X-Azure-RequestChain (loop detection)', tip:'hops={N} — confirmed in 2026 AFD docs'},
      {key:'xAzureCacheHit',      label:'X-Cache with AFD context'},
    ]},
    { title:'X-MS-* Headers', signals:[
      {key:'xMsRoutingName',      label:'X-MS-Routing-Name'},
      {key:'xMsRequestId',        label:'X-MS-Request-Id'},
      {key:'xMsVersion',          label:'X-MS-Version'},
      {key:'xMsClientRequestId',  label:'X-MS-Client-Request-Id'},
      {key:'xMsActivityId',       label:'X-MS-Activity-Id'},
      {key:'xMsEdge',             label:'X-MS-Edge-* family'},
    ]},
    { title:'Blob Storage Headers', signals:[
      {key:'serverAzureStorage',  label:'Server: Windows-Azure-Blob/Table'},
      {key:'xMsBlobType',         label:'X-MS-Blob-Type'},
      {key:'xMsAccessTier',       label:'X-MS-Access-Tier (Hot/Cool/Archive)'},
      {key:'xMsServerEncrypted',  label:'X-MS-Server-Encrypted: true'},
      {key:'xMsCreationTime',     label:'X-MS-Creation-Time'},
    ]},
    { title:'Probe / WAF / Content', signals:[
      {key:'azureDebugHeaders',   label:'X-Azure-DebugInfo probe responded'},
      {key:'serverIIS',           label:'Server: Microsoft-IIS'},
      {key:'azureWafBlock',       label:'Azure WAF block page'},
      {key:'azureErrorPage',      label:'Azure error page body'},
    ]},
  ]},

  sucuri: { name:'Sucuri', color:'#e77b30', icon:'🔒', groups:[
    { title:'Network', signals:[
      {key:'sucuriCname',         label:'CNAME → Sucuri',                   tip:'*.sucuri.net, *.cloudproxy.sucuri.net'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xSucuriIdValid',      label:'X-Sucuri-ID (validated)',           tip:'Definitively Sucuri — numeric request ID'},
      {key:'xSucuriId',           label:'X-Sucuri-ID present'},
      {key:'xSucuriCacheValid',   label:'X-Sucuri-Cache (valid value)'},
      {key:'xSucuriCache',        label:'X-Sucuri-Cache present'},
      {key:'xSucuriVersion',      label:'X-Sucuri-Version'},
      {key:'xSucuriGeneratedTime',label:'X-Sucuri-Generated-Time'},
      {key:'serverCloudProxy',    label:'Server: cloudproxy'},
    ]},
    { title:'Content Analysis', signals:[
      {key:'sucuriBlockPage',     label:'Sucuri WAF block page body'},
      {key:'sucuriJsChallenge',   label:'Sucuri JS browser verification'},
      {key:'sucuriAccessDenied',  label:'"Access Denied" from Sucuri'},
      {key:'sucuriCsrf',          label:'Sucuri CSRF protection page'},
    ]},
  ]},

  // Vercel color: #e2e8f0 (light slate — visible on dark bg, matches Vercel dark-mode branding)
  // v6 used #000000 which was invisible against the dark popup background
  vercel: { name:'Vercel', color:'#e2e8f0', icon:'▲', groups:[
    { title:'Network', signals:[
      {key:'vercelCname',         label:'CNAME → Vercel',                   tip:'*.vercel.app, *.vercel-dns.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xVercelIdValid',      label:'X-Vercel-ID (validated)',           tip:'2026 format: {region}::[{region}::]{node}-{ts_ms}-{hex} — multi-region allowed'},
      {key:'xVercelId',           label:'X-Vercel-ID present'},
      {key:'xVercelCacheValid',   label:'X-Vercel-Cache (valid value)'},
      {key:'xVercelCache',        label:'X-Vercel-Cache present'},
      {key:'serverVercel',        label:'Server: Vercel'},
      {key:'xMatchedPath',        label:'X-Matched-Path (routing)',          tip:'Exclusive to Vercel routing internals'},
      {key:'xDeploymentId',       label:'X-Deployment-ID'},
      {key:'xVercelSk',           label:'X-Vercel-SK (Skew Protection)'},
    ]},
    { title:'Next.js / Edge Functions', signals:[
      {key:'xNextjsPrerender',    label:'X-Nextjs-Prerender (ISR)'},
      {key:'xNextjsStaleTime',    label:'X-Nextjs-Stale-Time'},
      {key:'xNextCacheTags',      label:'X-Next-Cache-Tags'},
      {key:'xNextjsCache',        label:'X-Nextjs-Cache'},
      {key:'xMiddlewareRewrite',  label:'X-Middleware-Rewrite'},
      {key:'xMiddlewareInvoke',   label:'X-Middleware-Invoke'},
      {key:'xVercelError',        label:'X-Vercel-Error'},
      {key:'xVercelExecRegion',   label:'X-Vercel-Execution-Region'},
    ]},
  ]},

  netlify: { name:'Netlify', color:'#00c7b7', icon:'💠', groups:[
    { title:'Network', signals:[
      {key:'netlifyCname',        label:'CNAME → Netlify',                  tip:'*.netlify.app, *.netlify.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xNfRequestIdValid',   label:'X-NF-Request-ID (validated ULID)',  tip:'Exactly 26-char Crockford Base32 ULID — confirmed per Netlify docs July 2025'},
      {key:'xNfRequestId',        label:'X-NF-Request-ID present'},
      {key:'serverNetlify',       label:'Server: Netlify'},
      {key:'xNfEdgeCacheValid',   label:'X-NF-Edge-Cache (valid value)'},
      {key:'xNfEdgeCache',        label:'X-NF-Edge-Cache present'},
      {key:'xNfOriginCache',      label:'X-NF-Origin-Cache'},
      {key:'xNfPop',              label:'X-NF-Pop (edge PoP location)'},
      {key:'netlifyVary',         label:'Netlify-Vary (cache variation)'},
      {key:'xNetlifyOriginalPath',label:'X-Netlify-Original-Path'},
      {key:'xNetlifyRewrite',     label:'X-Netlify-Rewrite'},
      {key:'netlifyServerTiming', label:'Netlify-Server-Timing'},
      {key:'xNetlifyCache',       label:'X-Netlify-Cache'},
    ]},
    { title:'Content', signals:[
      {key:'netlifyErrorPage',    label:'Netlify error page body'},
    ]},
  ]},

  bunnycdn: { name:'BunnyCDN', color:'#f5a623', icon:'🐰', groups:[
    { title:'Network', signals:[
      {key:'bunnyIP',             label:'Resolves to BunnyCDN IP'},
      {key:'bunnyCname',          label:'CNAME → bunny.net',               tip:'*.b-cdn.net, *.bunnycdn.com'},
    ]},
    { title:'Server Header', signals:[
      {key:'serverBunnyValid',    label:'Server: BunnyCDN-{loc}-{id} (validated)', tip:'Definitively BunnyCDN per docs'},
      {key:'serverBunny',         label:'Server: BunnyCDN-* present'},
      {key:'viaBunny',            label:'Via: BunnyCDN'},
    ]},
    { title:'CDN-* Header Family', signals:[
      {key:'cdnRequestIdValid',   label:'CDN-RequestId (valid 32-hex)',     tip:'Documented BunnyCDN request tracking ID'},
      {key:'cdnRequestId',        label:'CDN-RequestId present'},
      {key:'cdnUid',              label:'CDN-UID (account UUID)'},
      {key:'cdnCacheValid',       label:'CDN-Cache (HIT/MISS/BYPASS)'},
      {key:'cdnCache',            label:'CDN-Cache present'},
      {key:'cdnPullzone',         label:'CDN-PullZone (numeric ID)'},
      {key:'cdnCachedAt',         label:'CDN-CachedAt (cache timestamp)'},
      {key:'cdnProxyVer',         label:'CDN-ProxyVer (proxy version)'},
      {key:'cdnRequestPullSuccess',label:'CDN-RequestPullSuccess: True'},
      {key:'cdnEdgeStorageId',    label:'CDN-EdgeStorageId'},
      {key:'cdnRequestCountryCode',label:'CDN-RequestCountryCode'},
    ]},
  ]},

  stackpath: { name:'StackPath', color:'#2196f3', icon:'⚙', groups:[
    { title:'Network', signals:[
      {key:'stackpathCname',      label:'CNAME → StackPath / EdgeCast',    tip:'*.hwcdn.net, *.stackpathcdn.com…'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverEcacc',         label:'Server: ECAcc (EdgeCast Accelerator)', tip:'Exclusively EdgeCast/StackPath'},
      {key:'serverEcs',           label:'Server: ECS (EdgeCast Server)'},
      {key:'xCacheHwcdnValid',    label:'X-Cache: HIT from *.hwcdn.net',   tip:'hwcdn.net FQDN proves StackPath'},
      {key:'xCacheHwcdn',         label:'X-Cache includes hwcdn.net'},
      {key:'xSpUid',              label:'X-SP-UID (StackPath unique ID)'},
      {key:'xEcCustomError',      label:'X-EC-Custom-Error: 1 (EdgeCast)'},
      {key:'xPullZone',           label:'X-Pull-Zone'},
      {key:'xSpEdge',             label:'X-SP-* header family'},
      {key:'xCacheHits',          label:'X-Cache-Hits'},
      {key:'xCacheAge',           label:'X-Cache-Age (seconds)'},
    ]},
    { title:'Content', signals:[
      {key:'ecErrorBody',         label:'EdgeCast / StackPath error page'},
    ]},
  ]},

  keycdn: { name:'KeyCDN', color:'#2a99ff', icon:'🔑', groups:[
    { title:'Network', signals:[
      {key:'keyCname',            label:'CNAME → KeyCDN',                  tip:'*.kxcdn.com, *.keycdn.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverKeycdn',        label:'Server: keycdn-engine',           tip:'Exclusively KeyCDN per published docs'},
      {key:'xEdgeLocation',       label:'X-Edge-Location (PoP name)'},
      {key:'xEdgeIp',             label:'X-Edge-Ip (edge server IP)'},
      {key:'xUniqueId',           label:'X-Unique-Id (per-request ID)'},
      {key:'xCacheKeycdn',        label:'X-Cache HIT/MISS (KeyCDN context)'},
      {key:'xPullZone',           label:'X-Pull-Zone (pull config ID)'},
      {key:'xCacheHits',          label:'X-Cache-Hits (cumulative count)'},
    ]},
    { title:'Content', signals:[
      {key:'keyCdnErrorPage',     label:'KeyCDN error page body'},
    ]},
  ]},

  gcore: { name:'Gcore', color:'#f04e23', icon:'🌐', groups:[
    { title:'Network', signals:[
      {key:'gcoreCname',          label:'CNAME → Gcore',                   tip:'*.gcdn.co, *.gc.onl, *.gcorelabs.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverGcore',         label:'Server: Gcore'},
      {key:'xIdValid',            label:'X-ID: ed-{a}-{b}-{c}-{d} (validated)',  tip:'Gcore encodes edge IP in X-ID'},
      {key:'xId',                 label:'X-ID present'},
      {key:'xCachedSince',        label:'X-Cached-Since (cache timestamp)', tip:'ISO datetime of edge cache population'},
      {key:'xCacheGcore',         label:'X-Cache HIT/MISS (Gcore context)'},
      {key:'gcorePop',            label:'X-Gcore-Pop (edge PoP)'},
      {key:'gShield',             label:'G-Shield (DDoS protection layer)'},
    ]},
    { title:'Content', signals:[
      {key:'gcoreErrorPage',      label:'Gcore error page body'},
    ]},
  ]},

  datadome: { name:'DataDome', color:'#7c3aed', icon:'🤖', productType:'Bot Protection (WAAP)', groups:[
    { title:'Cookies', signals:[
      {key:'cookies.datadome',       label:'datadome clearance cookie'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xDataDomeValid',         label:'X-DataDome: protected'},
      {key:'xDataDome',              label:'X-DataDome present'},
      {key:'xDataDomeBotHeaders',    label:'X-DataDome-Bot* headers (block response)'},
      {key:'xDdB',                   label:'X-DD-B backend signal'},
    ]},
    { title:'Content', signals:[
      {key:'captchaDeliveryRef',     label:'captcha-delivery.com reference', tip:'DataDome challenge delivery domain'},
      {key:'ddJsChallenge',          label:'DataDome JS challenge markers'},
      {key:'ddBlockBody',            label:'DataDome block page body'},
    ]},
  ]},

  perimeterx: { name:'PerimeterX', color:'#ff5a5f', icon:'🧩', productType:'Bot Protection (HUMAN Security)', groups:[
    { title:'Cookies', signals:[
      {key:'cookies.px3',            label:'_px3 Security Token cookie'},
      {key:'cookies.pxvid',          label:'_pxvid visitor ID cookie'},
      {key:'cookies.pxhd',           label:'_pxhd session cookie'},
      {key:'cookies.pxcts',          label:'_pxcts cookie'},
      {key:'cookies.px2',            label:'_px2 cookie'},
      {key:'cookies.px',             label:'_px cookie'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xPxAuthorization',       label:'X-PX-Authorization present'},
    ]},
    { title:'Content', signals:[
      {key:'pxCollectorRef',         label:'collector-*.perimeterx.net / px-cloud.net ref'},
      {key:'pxCdnRef',               label:'*.px-cdn.net reference'},
      {key:'pxPressHoldChallenge',   label:'"Press & Hold" challenge widget'},
      {key:'pxScriptRef',            label:'px.js / pxConfig script reference'},
      {key:'humanSecurityRef',       label:'HUMAN Security brand reference'},
    ]},
  ]},

  f5xc: { name:'F5 Distributed Cloud', color:'#e4002b', icon:'🟥', productType:'CDN + WAAP Hybrid', groups:[
    { title:'Network', signals:[
      {key:'serverVoltCdn',          label:'CNAME → F5 XC (volterra.io / ves.io)'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverVoltCdn',          label:'Server: volt-cdn',               tip:'Exclusive to F5 XC CDN Load Balancer'},
      {key:'xVolterraHeader',        label:'X-Volterra-* header family'},
      {key:'xCacheStatusF5',         label:'X-Cache-Status (F5 XC context)'},
      {key:'xRequestIdF5',           label:'X-Request-ID (F5 XC context)'},
    ]},
    { title:'Content', signals:[
      {key:'f5BotDefenseRef',        label:'F5/Shape/Volterra brand reference'},
      {key:'f5ShapeChallenge',       label:'Shape Security block page'},
    ]},
  ]},

  tencenteo: { name:'Tencent EdgeOne', color:'#00a4ff', icon:'🐧', groups:[
    { title:'Network', signals:[
      {key:'tencentCname',           label:'CNAME → Tencent EdgeOne',        tip:'*.qcloud.com, *.edgeone.app'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverTencentEo',        label:'Server: TencentEdgeOne'},
      {key:'cdnLoopTencent',         label:'CDN-Loop: tencent'},
      {key:'eoCacheStatusValid',     label:'EO-Cache-Status valid value'},
      {key:'eoCacheStatus',          label:'EO-Cache-Status present'},
      {key:'eoLogUuid',              label:'EO-LOG-UUID (request identifier)'},
      {key:'eoConnectingIp',         label:'EO-Connecting-IP'},
      {key:'eoClientDevice',         label:'EO-Client-Device'},
    ]},
  ]},

  alicdn: { name:'Alibaba Cloud CDN', color:'#ff6a00', icon:'🅰', groups:[
    { title:'Network', signals:[
      {key:'aliCname',               label:'CNAME → Alibaba Cloud CDN',      tip:'*.kunlunar.com, *.alicdn.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xSwiftSaveTime',         label:'X-Swift-SaveTime',               tip:'Exclusive to Alibaba Cloud Swift cache layer'},
      {key:'xSwiftCacheTime',        label:'X-Swift-CacheTime'},
      {key:'xCacheSwift',            label:'X-Cache HIT/MISS (Swift context)'},
      {key:'ageHeader',              label:'Age header present (weak corroborator)'},
    ]},
  ]},

  arvancloud: { name:'ArvanCloud', color:'#ff5252', icon:'🛰', groups:[
    { title:'Network', signals:[
      {key:'arvanCname',             label:'CNAME → ArvanCloud',             tip:'*.cdn.arvancloud.ir / .com'},
    ]},
    { title:'Content', signals:[
      {key:'arvanWafBlock',          label:'ArvanCloud WAF block page'},
      {key:'arvanChallengeBody',     label:'ArvanCloud DDoS challenge page'},
    ]},
    { title:'Cookies', signals:[
      {key:'cookies.arvanDdos',      label:'ArvanCloud DDoS challenge cookie (heuristic name match)'},
    ]},
  ]},

  vncdn: { name:'VNCDN (VNETWORK)', color:'#0072ce', icon:'🇻🇳', productType:'CDN (heuristic, low public docs)', groups:[
    { title:'Network', signals:[
      {key:'vncdnCname',             label:'CNAME → VNCDN / VNIS',           tip:'*.vncdn.net, *.vncdn.cloud, *.vnetwork.vn — unverified spec, lower confidence'},
    ]},
    { title:'Response Headers', signals:[
      {key:'vncdnHeaderRef',         label:'Server/Via mentions VNCDN/VNETWORK'},
    ]},
    { title:'Content', signals:[
      {key:'vnisBlockBody',          label:'VNIS/VNETWORK protection page body'},
    ]},
  ]},
};


// ── CF PoP city lookup ────────────────────────────────────────
const CF_POPS = {
  ATL:'Atlanta',BOS:'Boston',CMH:'Columbus',DEN:'Denver',DFW:'Dallas',
  DTW:'Detroit',EWR:'Newark',HNL:'Honolulu',IAD:'Ashburn',IAH:'Houston',
  LAX:'Los Angeles',MCI:'Kansas City',MCO:'Orlando',MIA:'Miami',
  MSP:'Minneapolis',ORD:'Chicago',PDX:'Portland',PHX:'Phoenix',
  SEA:'Seattle',SFO:'San Francisco',SJC:'San Jose',TPA:'Tampa',
  YTO:'Toronto',YUL:'Montreal',YVR:'Vancouver',
  AMS:'Amsterdam',ARN:'Stockholm',ATH:'Athens',BCN:'Barcelona',
  BRU:'Brussels',BUD:'Budapest',CDG:'Paris',CPH:'Copenhagen',
  DUB:'Dublin',DUS:'Düsseldorf',FRA:'Frankfurt',GVA:'Geneva',
  HAM:'Hamburg',HEL:'Helsinki',LHR:'London',LIS:'Lisbon',
  MAD:'Madrid',MAN:'Manchester',MXP:'Milan',OSL:'Oslo',
  OTP:'Bucharest',PRG:'Prague',VIE:'Vienna',WAW:'Warsaw',ZRH:'Zurich',
  BKK:'Bangkok',BLR:'Bangalore',BOM:'Mumbai',DEL:'Delhi',
  HAN:'Hanoi',HKG:'Hong Kong',ICN:'Seoul',KIX:'Osaka',
  KUL:'Kuala Lumpur',MNL:'Manila',NRT:'Tokyo',SGN:'Ho Chi Minh City',
  SIN:'Singapore',SYD:'Sydney',TPE:'Taipei',DXB:'Dubai',
  DOH:'Doha',TLV:'Tel Aviv',GRU:'São Paulo',SCL:'Santiago',
};
function formatPoP(iata) {
  if (!iata) return null;
  const c = CF_POPS[iata.toUpperCase()];
  return c ? `${iata} — ${c}` : iata;
}

// ── DOM refs ──────────────────────────────────────────────────
const scanBtn     = document.getElementById('scan');
const rescanBtn   = document.getElementById('rescan');
const statusTextEl = document.getElementById('status-text');
const cachedBadgeEl = document.getElementById('cached-badge');
const domainInput = document.getElementById('domain');
const resultsEl   = document.getElementById('results');

// ── #11: Keyboard navigation within results ──────────────────
// j/k move a "focused" highlight between provider rows/cards; Enter opens
// the focused provider's detail; Esc goes back to the overview. Only
// listens when focus isn't inside a text input (so typing in the domain
// field or a settings textarea is never intercepted).
let kbdFocusIndex = -1;
function kbdFocusableItems() {
  return [...resultsEl.querySelectorAll('.provider-card, .provider-row-compact')];
}
function applyKbdFocus(items) {
  items.forEach((el, i) => el.classList.toggle('kbd-focused', i === kbdFocusIndex));
  if (kbdFocusIndex >= 0 && items[kbdFocusIndex]) {
    items[kbdFocusIndex].scrollIntoView({ block: 'nearest' });
  }
}
document.addEventListener('keydown', e => {
  const tag = document.activeElement?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return; // never hijack typing

  const items = kbdFocusableItems();
  if (!items.length) return;

  if (e.key === 'j') {
    e.preventDefault();
    kbdFocusIndex = Math.min(kbdFocusIndex + 1, items.length - 1);
    applyKbdFocus(items);
  } else if (e.key === 'k') {
    e.preventDefault();
    kbdFocusIndex = Math.max(kbdFocusIndex - 1, 0);
    applyKbdFocus(items);
  } else if (e.key === 'Enter' && kbdFocusIndex >= 0 && items[kbdFocusIndex]) {
    e.preventDefault();
    items[kbdFocusIndex].click();
  } else if (e.key === 'Escape') {
    const backBtn = resultsEl.querySelector('.back-btn');
    if (backBtn) { e.preventDefault(); backBtn.click(); }
  }
});

const progressEl  = document.getElementById('progress');
const pctEl       = document.getElementById('pct');
const barEl       = document.getElementById('pbar');
const activityEl  = document.getElementById('activity');
const historyBtn  = document.getElementById('history');
const pinBtn       = document.getElementById('pinBtn');
const pinsViewBtn  = document.getElementById('pinsViewBtn');
const batchBtn     = document.getElementById('batchBtn');
const compareBtn   = document.getElementById('compareBtn');
const settingsBtn  = document.getElementById('settingsBtn');
const themeToggle  = document.getElementById('themeToggle');
const watchlistBtn = document.getElementById('watchlistBtn');
const sidePanelBtn = document.getElementById('sidePanelBtn');

// ── i18n: apply chrome.i18n messages to static markup ─────────
// Scope note: only top-level chrome (buttons, headers, status copy) is
// localized this way. The hundreds of per-signal technical labels inside
// PROVIDER_UI stay in English, matching the convention most security/dev
// tooling uses for protocol- and header-level terminology.
(function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const msg = chrome.i18n.getMessage(el.dataset.i18n);
    if (msg) el.textContent = msg;
  });
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const msg = chrome.i18n.getMessage(el.dataset.i18nTitle);
    if (msg) { el.title = msg; el.setAttribute('aria-label', msg); }
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const msg = chrome.i18n.getMessage(el.dataset.i18nPlaceholder);
    if (msg) el.placeholder = msg;
  });
})();

// ── Side panel (improvement #1) ────────────────────────────────
// Opens the same UI in a persistent side surface: chrome.sidePanel on
// Chrome, sidebar_action on Firefox (no equivalent exists on older Chrome —
// button simply becomes a no-op there, silently).
if (sidePanelBtn) {
  sidePanelBtn.addEventListener('click', async () => {
    try {
      if (chrome.sidePanel?.open) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.windowId != null) await chrome.sidePanel.open({ windowId: tab.windowId });
      } else if (chrome.sidebarAction?.open) {
        await chrome.sidebarAction.open();
      }
    } catch (e) { console.warn('Side panel not available:', e); }
  });
}


// ── Auto-fill current tab hostname ────────────────────────────
try {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const url = tabs[0]?.url;
    if (url && /^https?:/.test(url)) domainInput.value = new URL(url).hostname;
  });
} catch {}

// ── C1: Theme — system preference by default, persisted toggle override ──
function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === 'light') root.setAttribute('data-theme', 'light');
  else if (theme === 'dark') root.removeAttribute('data-theme'); // dark is the base stylesheet
  else { // 'system'
    const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    if (prefersLight) root.setAttribute('data-theme', 'light');
    else root.removeAttribute('data-theme');
  }
}
chrome.runtime.sendMessage({ action: 'getSettings' }, s => {
  applyTheme(s?.theme || 'system');
});
themeToggle.addEventListener('click', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const next = isLight ? 'dark' : 'light';
  applyTheme(next);
  chrome.runtime.sendMessage({ action: 'setSettings', patch: { theme: next } });
});

// ── C3: Pin button reflects current domain's pin state ────────
async function refreshPinButton() {
  const d = domainInput.value.trim().toLowerCase();
  chrome.runtime.sendMessage({ action: 'getPins' }, res => {
    const pinned = (res?.pins || []).includes(d);
    pinBtn.classList.toggle('pinned', pinned);
    pinBtn.title = pinned ? 'Unpin this domain' : 'Pin this domain';
  });
}
pinBtn.addEventListener('click', () => {
  const d = getDomain();
  if (!d) return;
  chrome.runtime.sendMessage({ action: 'togglePin', domain: d }, () => refreshPinButton());
});
domainInput.addEventListener('input', refreshPinButton);
refreshPinButton();

// ── B5: If a context-menu "Scan this domain" click queued a target while
// the popup was closed, pick it up and scan immediately on open.
chrome.storage.local.get('pending_scan_domain', res => {
  const pending = res?.pending_scan_domain;
  if (pending) {
    chrome.storage.local.remove('pending_scan_domain');
    domainInput.value = pending;
    setTimeout(() => doScan(pending, false), 50); // doScan is defined later in this file
  }
});

// ── B2 / B1: open the full-tab Compare / Batch pages ───────────
batchBtn.addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('batch.html') }));
compareBtn.addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('compare.html') }));

// ── Validation ────────────────────────────────────────────────
function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(o => +o >= 0 && +o <= 255);
}
function isIPv6(s) {
  return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
}
function isValidDomain(d) {
  if (isIPv4(d) || isIPv6(d)) return true;
  return d.length > 1 && d.length < 256 && /^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/i.test(d);
}

// ── Signal resolver — supports "cookies.cfBm" dot notation ───
function getSig(signals, key) {
  return key.split('.').reduce((o, k) => o?.[k], signals) ?? false;
}

// ── Status helpers ────────────────────────────────────────────
function setStatus(text, mod) {
  statusTextEl.className = mod === 'scanning' ? 'status-scan'
    : mod === 'detected' ? 'status-ok'
    : mod === 'not-detected' ? 'status-fail'
    : 'status-idle';
  statusTextEl.textContent = text;
  cachedBadgeEl.hidden = true;
}

// ── Progress UI ───────────────────────────────────────────────
function showProgress(show) {
  progressEl.hidden = !show;
  if (show) {
    barEl.classList.add('scanning');
  } else {
    barEl.classList.remove('scanning');
  }
}
function updateProgress(pct, activity) {
  if (pct > 0) barEl.classList.remove('scanning');
  pctEl.textContent     = `${pct}%`;
  barEl.style.width     = `${Math.min(pct, 100)}%`;
  activityEl.textContent = activity;
}

// ── Row renderers ─────────────────────────────────────────────
function boolRow(label, value, tip) {
  const t = tip ? ` title="${tip}"` : '';
  return `<div class="result-row ${value ? 'hit' : 'miss'}"${t}>
    <span>${label}</span><strong>${value ? '✔' : '✖'}</strong>
  </div>`;
}
function infoRow(label, value) {
  if (!value) return '';
  const safe = String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
  return `<div class="result-row info"><span>${label}</span><strong title="${safe}">${safe}</strong></div>`;
}
function sectionHdr(title) {
  return `<div class="section-header">${title}</div>`;
}
const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

// ── B3: Export ───────────────────────────────────────────────
function downloadBlob(filename, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename, saveAs: false }, () => {
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  });
}
function exportJson(result) {
  const domain = domainInput.value.trim() || 'scan';
  downloadBlob(`cdnwaf-${domain}-${Date.now()}.json`, 'application/json', JSON.stringify(result, null, 2));
}
function exportCsv(result) {
  const domain = domainInput.value.trim() || 'scan';
  const rows = [['provider', 'detected', 'score', 'label']];
  for (const id of Object.keys(PROVIDER_UI)) {
    const pv = result.providers?.[id];
    if (!pv) continue;
    rows.push([PROVIDER_UI[id].name, pv.verdict?.detected ? 'yes' : 'no', pv.verdict?.score ?? 0, pv.verdict?.label ?? '']);
  }
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadBlob(`cdnwaf-${domain}-${Date.now()}.csv`, 'text/csv', csv);
}
function exportPrintable(result) {
  // No PDF library is bundled, so this opens a clean printable report in a
  // new tab — the person uses the browser's own "Print → Save as PDF",
  // which is the honest zero-dependency way to get a PDF from an extension.
  const domain   = domainInput.value.trim() || 'scan';
  const detected = Object.keys(PROVIDER_UI).filter(id => result.providers?.[id]?.verdict?.detected);
  const rows = Object.keys(PROVIDER_UI).map(id => {
    const pv = result.providers?.[id];
    if (!pv) return '';
    return `<tr><td>${escHtml(PROVIDER_UI[id].name)}</td><td>${pv.verdict?.detected ? 'Detected' : '—'}</td><td>${pv.verdict?.score ?? 0}%</td><td>${escHtml(pv.verdict?.label ?? '')}</td></tr>`;
  }).join('');
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CDN/WAF report — ${escHtml(domain)}</title>
  <style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:32px;color:#111}
  h1{font-size:18px}table{border-collapse:collapse;width:100%;margin-top:16px}
  td,th{border:1px solid #ddd;padding:6px 10px;font-size:12px;text-align:left}
  th{background:#f2f2f2}.meta{color:#666;font-size:11px;margin-bottom:4px}</style></head>
  <body><h1>CDN / WAF Detector report</h1>
  <div class="meta">Domain: ${escHtml(domain)}</div>
  <div class="meta">Scanned: ${escHtml(result.scannedAt || '')}</div>
  <div class="meta">Detected: ${detected.length ? escHtml(detected.map(id => PROVIDER_UI[id].name).join(', ')) : 'None'}</div>
  <table><tr><th>Provider</th><th>Status</th><th>Score</th><th>Label</th></tr>${rows}</table>
  </body></html>`;
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
  chrome.tabs.create({ url });
}

// ── A2: Origin-leak on-demand check ───────────────────────────
function renderOriginLeak(domain) {
  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Origin Leak Check</span>
    </div>
    <div class="leak-disclaimer">Probing common subdomains + Certificate Transparency logs (crt.sh) for hosts that resolve outside the IP ranges of already-detected providers. This can take a little while and does not read TLS certificates directly — browsers don't expose that to extensions.</div>
    <div class="empty-state">Checking…</div>`;
  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
  });
  chrome.runtime.sendMessage({ action: 'checkOriginLeak', domain }, res => {
    if (!resultsEl.querySelector('.leak-disclaimer')) return; // user navigated away
    const findings = res?.findings || [];
    const body = findings.length
      ? findings.map(f => `<div class="leak-finding"><span class="leak-host">${escHtml(f.host)}</span><br><span class="leak-ip">${escHtml(f.ip)} — not in any known provider's IP range</span></div>`).join('')
      : `<div class="leak-clean">✓ No obvious origin exposure found among ${res?.checkedCount ?? 0} candidate subdomains (${res?.ctSourceCount ?? 0} from Certificate Transparency).</div>`;
    resultsEl.innerHTML = `
      <div class="detail-header">
        <button class="back-btn" id="backBtn">← Back</button>
        <span class="detail-name">Origin Leak Check</span>
      </div>
      <div class="leak-disclaimer">Best-effort check only — absence of findings doesn't guarantee the origin is hidden, and the reverse: a finding here means a subdomain resolves outside known CDN ranges, not necessarily that it's the true origin.</div>
      ${body}`;
    document.getElementById('backBtn').addEventListener('click', () => {
      if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
    });
  });
}

// ── D4: CVE threat-intel lookup, called from the detail view ─
function renderCveLookup(pid, providerName) {
  const panel = document.getElementById('cvePanel');
  if (!panel) return;
  panel.innerHTML = '<div class="empty-state">Looking up recent CVEs…</div>';
  chrome.runtime.sendMessage({ action: 'getCves', providerName }, res => {
    if (res?.error) { panel.innerHTML = `<div class="empty-state">Lookup failed: ${escHtml(res.error)}</div>`; return; }
    const items = res?.items || [];
    if (!items.length) { panel.innerHTML = '<div class="empty-state">No recent CVEs found via NVD keyword search.</div>'; return; }
    panel.innerHTML = items.map(c => `
      <div class="cve-row">
        <span class="cve-id">${escHtml(c.id || '')}</span><span class="cve-date">${escHtml((c.published || '').slice(0, 10))}</span>
        <div class="cve-summary">${escHtml(c.summary || '')}</div>
      </div>`).join('') + '<div class="breakdown-note">Source: NVD keyword search on the provider name — may include unrelated results sharing the same word.</div>';
  });
}

// ── Overview grid ─────────────────────────────────────────────
// ── Collapsible group helper ────────────────────────────────────
// Renders a clickable header + a body that starts collapsed or expanded.
// Used throughout renderOverview to group dense technical output (network
// signals, the full 24-provider list, tool buttons) behind a tap instead
// of dumping everything onto the screen at once.
function groupSection(id, title, count, bodyHtml, startCollapsed) {
  const countBadge = count > 0 ? `<span class="group-count">${count}</span>` : '';
  return `
    <div class="group-block" data-group="${id}">
      <div class="group-header">
        <span class="group-chevron">${startCollapsed ? '▸' : '▾'}</span>
        <span class="group-title">${title}</span>
        ${countBadge}
      </div>
      <div class="group-body${startCollapsed ? ' collapsed' : ''}">${bodyHtml}</div>
    </div>`;
}

function renderOverview(result, cached, diff) {
  if (!result?.providers) {
    resultsEl.innerHTML = '<div class="empty-state">No data to display.</div>';
    return;
  }

  const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const order    = Object.keys(PROVIDER_UI);
  const detected = order.filter(id => result.providers[id]?.verdict?.detected === true);
  const undetected = order.filter(id => !detected.includes(id));

  // Update status bar
  statusTextEl.className = detected.length > 0 ? 'status-ok' : 'status-fail';
  statusTextEl.innerHTML = detected.length > 0
    ? `${detected.length} provider${detected.length > 1 ? 's' : ''} detected — tap to inspect`
    : 'No providers detected';
  if (cached) cachedBadgeEl.hidden = false;

  // ── GROUP 1: Summary — always visible, this is the headline answer ──
  const ipList = result.resolvedIPs || [];
  const ipChipsHtml = ipList.map(ip => {
    const ev = result.ipEvidence?.[ip];
    const tag = ev?.org ? ` title="${escHtml(ev.org)}${ev.ptr ? ' · ' + escHtml(ev.ptr) : ''}"` : '';
    const verified = ev?.matchedProviders?.length ? ' ip-verified' : '';
    return `<span class="ip-chip${verified}" data-ip="${escHtml(ip)}"${tag}>${escHtml(ip)}</span>`;
  }).join('');

  // 1-2 IPs: show inline, no point wrapping something this small in a group.
  // 3+ IPs (very common with anycast CDNs): its own styled, collapsible
  // group with a count badge — previously this rendered as a long unstyled
  // wrapped line of chips directly under the summary text.
  const ipsInlineHtml = ipList.length > 0 && ipList.length <= 2
    ? `<div class="scan-ips">${ipChipsHtml}</div>` : '';
  const ipsGroupHtml = ipList.length > 2
    ? groupSection('resolved-ips', '🌐 Resolved IPs', ipList.length,
        `<div class="ip-chip-grid">${ipChipsHtml}</div>
         <div class="breakdown-note" style="margin-top:8px">Tap an IP for PTR/RDAP cross-verification. ${ipList.length} IPs usually means anycast (multiple edge locations), not a problem to fix.</div>`,
        true)
    : '';

  const summaryText = detected.length === 0
    ? 'No providers detected'
    : `${detected.length} provider${detected.length > 1 ? 's' : ''} detected: <strong>${detected.map(id => PROVIDER_UI[id]?.name || id).join(', ')}</strong>`;
  const metaLine = `<div class="scan-meta"><span>${summaryText}</span>${ipsInlineHtml}</div>`;

  // ── STATUS LINES — consolidated into ONE compact block instead of
  // 5-6 separate stacked banners. Each line is short; only lines that
  // actually apply are shown. This is the fix for the "still cluttered
  // with 2+ providers" case (e.g. Cloudflare + Google both detected):
  // previously diff/overlap/migration/anycast-note/chain were each their
  // own full-width colored banner, stacking up fast with multi-CDN sites.
  const statusLines = [];
  if (diff?.changed) {
    const nameOf = id => PROVIDER_UI[id]?.name || id;
    const bits = [];
    if (diff.added?.length)   bits.push(`+${diff.added.map(nameOf).join(', ')}`);
    if (diff.removed?.length) bits.push(`−${diff.removed.map(nameOf).join(', ')}`);
    statusLines.push({ icon: '↻', text: `Changed since ${new Date(diff.priorTs).toLocaleDateString()}: ${bits.join(' · ')}`, tone: 'changed' });
  } else if (diff?.priorTs) {
    statusLines.push({ icon: '✓', text: `Same as last scan (${new Date(diff.priorTs).toLocaleDateString()})`, tone: 'unchanged' });
  }
  if (result.migrationWarning) {
    // Specific warning (2+ actual CDNs, not just CDN+WAF) — this already
    // says what matters, so it replaces the generic "Multi-CDN/WAF" line
    // instead of stacking both (they used to say almost the same thing twice).
    statusLines.push({ icon: '⚠', text: result.migrationWarning.note, tone: 'changed' });
  } else if (detected.length > 1) {
    // CDN + WAF together (e.g. Cloudflare + Imperva) is a normal, common
    // setup — neutral tone, no warning icon, since nothing here is concerning.
    statusLines.push({ icon: 'ℹ', text: `${detected.length} providers working together (CDN + WAF is a common combination)`, tone: 'unchanged' });
  }

  // Layer order folds into status lines too, as one line instead of its own block
  const lc = result.layerChain;
  if (lc?.chain && lc.chain.length > 1) {
    const nameOf = id => PROVIDER_UI[id]?.name || id;
    const hops = lc.chain.map(nameOf).join(' → ');
    statusLines.push({ icon: '📶', text: `Layer order: ${hops}`, tone: 'unchanged' });
  }
  // Note: "layer order unknown" is intentionally NOT shown as a status line —
  // absence of a Via header is the common case, not something worth a line
  // of its own every time. It's still visible in the Tree view for anyone
  // who specifically wants to check layer order.

  const statusBlock = statusLines.length
    ? `<div class="status-block">${statusLines.map(l => `<div class="status-line status-${l.tone}"><span class="status-icon">${l.icon}</span>${escHtml(l.text)}</div>`).join('')}</div>`
    : '';

  // ── GROUP 2: Detected providers ─────────────────────────────────
  // Single provider → full card (there's room, and it's the headline
  // answer). 2+ providers → compact rows instead of full cards, since
  // stacking 2-4 full cards (each with head/bar/label) is exactly what
  // made the multi-CDN case feel cluttered.
  const singleProviderMode = (detected.length + (result.customProviders ? Object.values(result.customProviders).filter(v => v.verdict?.detected).length : 0)) <= 1;

  const fullCard = (id, ui, pv, isCustom) => {
    const score = pv?.verdict?.score ?? 0;
    const label = pv?.verdict?.label ?? 'Unlikely';
    const weakSignal = !isCustom && (pv?.breakdown?.length === 1);
    const weakBadge = weakSignal ? `<span class="weak-signal-badge" title="Only 1 signal supports this detection — higher chance of a false positive">⚠</span>` : '';
    return `
      <div class="provider-card detected" data-provider="${isCustom ? '' : id}" data-custom="${isCustom ? id : ''}" style="--pc:${ui.color}">
        <div class="pc-head"><div class="pc-dot"></div>
          <span class="pc-name">${escHtml(ui.name)}</span>${weakBadge}
          <span class="pc-score">${score}%</span></div>
        <div class="pc-bar-wrap">${score > 0 ? `<div class="pc-bar" style="width:${score}%"></div>` : ''}</div>
        <div class="pc-label">${escHtml(label)}${isCustom ? ' <em style="font-size:9px">(custom)</em>' : ''}</div>
      </div>`;
  };
  const compactRow = (id, ui, pv, isCustom) => {
    const score = pv?.verdict?.score ?? 0;
    const label = pv?.verdict?.label ?? 'Unlikely';
    const weakSignal = !isCustom && (pv?.breakdown?.length === 1);
    const weakBadge = weakSignal ? `<span class="weak-signal-badge" title="Only 1 signal supports this detection — higher chance of a false positive">⚠</span>` : '';
    return `
      <div class="provider-row-compact" data-provider="${isCustom ? '' : id}" data-custom="${isCustom ? id : ''}" style="--pc:${ui.color}">
        <div class="pc-dot"></div>
        <span class="pc-name">${escHtml(ui.name)}</span>${weakBadge}
        <span class="pc-label-inline">${escHtml(label)}${isCustom ? ' (custom)' : ''}</span>
        <span class="pc-score">${score}%</span>
      </div>`;
  };

  const cardFn = singleProviderMode ? fullCard : compactRow;
  const detectedCards = detected.map(id => cardFn(id, PROVIDER_UI[id], result.providers[id], false)).join('');
  const customEntries = Object.entries(result.customProviders || {}).filter(([, v]) => v.verdict?.detected);
  const customCards = customEntries.map(([id, v]) => cardFn(id, v.def || { color: '#94a3b8', name: id }, v, true)).join('');

  const detectedGroup = (detectedCards || customCards)
    ? `<div class="${singleProviderMode ? 'providers-grid' : 'providers-compact-list'}">${detectedCards}${customCards}</div>`
    : `<div class="empty-state" style="padding:16px 0">No providers matched — see "All ${order.length} providers" below to check individually.</div>`;

  // ── GROUP 4: Network & infrastructure signals — collapsed by default ──
  // This is where round 1-6's DNS/TLS/ECS/anycast/DNSSEC signals live.
  // Simulated against google.com: this group would hold DNSSEC pill, ECS
  // banner (Google's own resolver WILL show ECS behavior), anycast spread,
  // DNS provider, SPF/DMARC, HTTPS-record/ECH — exactly the kind of dense
  // technical detail that shouldn't be forced onto the main view.
  const netSignals = [];
  if (result.dnsProvider) netSignals.push(`<div class="info-pill">🔑 DNS: <strong>${escHtml(result.dnsProvider)}</strong></div>`);
  if (result.httpsRecord) {
    const hr = result.httpsRecord, bits = [];
    if (hr.ech) bits.push('<strong>ECH ✓</strong>');
    if (hr.alpn?.length) bits.push(`ALPN: ${hr.alpn.map(escHtml).join(', ')}`);
    if (hr.ipv4hints?.length) bits.push(`IP hints: ${hr.ipv4hints.map(escHtml).join(', ')}`);
    if (bits.length) netSignals.push(`<div class="info-pill">📋 HTTPS RR: ${bits.join(' · ')}</div>`);
  }
  if (result.spfDmarc) {
    const sd = result.spfDmarc, bits = [];
    if (sd.spfProvider) bits.push(`✉ Email: <strong>${escHtml(sd.spfProvider)}</strong>`);
    if (sd.dmarcPolicy) bits.push(`DMARC: p=${escHtml(sd.dmarcPolicy)}`);
    if (bits.length) netSignals.push(`<div class="info-pill">${bits.join(' · ')}</div>`);
  }
  if (result.tlsIntel) {
    const t = result.tlsIntel;
    netSignals.push(`<div class="info-pill tls-pill">🔒 ${escHtml(t.protocol || '')} · ${escHtml(t.cipher || '')}${t.ech ? ' · ECH ✓' : ''}${t.certIssuer ? ` · Issuer: ${escHtml(t.certIssuer.slice(0, 60))}` : ''}</div>`);
  }
  if (result.anycast?.dnssecValidated) netSignals.push(`<span class="info-pill" style="color:var(--green)">🔒 DNSSEC validated</span>`);
  if (result.anycast?.fastestResolver) netSignals.push(`<span class="info-pill">⚡ Fastest resolver: ${escHtml(result.anycast.fastestResolver)}</span>`);
  if (result.unknownHeaders?.length) netSignals.push(`<span class="info-pill" style="color:var(--amber)">📋 ${result.unknownHeaders.length} unrecognized header${result.unknownHeaders.length > 1 ? 's' : ''} — see detected provider's detail view to report</span>`);

  const netBanners = [];
  if (result.anycast?.diverges) {
    const rows = result.anycast.entries.map(e => `${escHtml(e.resolver)}: ${e.ips.map(escHtml).join(', ')}`).join(' | ');
    netBanners.push(`<div class="diff-banner changed">🌐 Anycast divergence: ${rows}</div>`);
  }
  if (result.anycast?.ecsLeakSuspected) {
    netBanners.push(`<div class="diff-banner changed">📡 ECS geo-routing suspected — Google's DoH (sends partial client IP via ECS) and Cloudflare's DoH (no ECS) resolved to fully different edge IPs.</div>`);
  }

  const netGroupBody = netSignals.length || netBanners.length
    ? `${netBanners.join('')}<div class="info-bar">${netSignals.join('')}</div>`
    : `<div class="breakdown-note">No additional DNS/TLS signals surfaced for this scan.</div>`;
  const netGroupCount = netSignals.length + netBanners.length;

  // ── GROUP 5: All providers (including undetected) — collapsed, opt-in ──
  const allCards = order.map(id => {
    const ui = PROVIDER_UI[id]; if (!ui) return '';
    const pv = result.providers?.[id];
    const score = pv?.verdict?.score ?? 0;
    const label = pv?.verdict?.label ?? 'Unlikely';
    const det = pv?.verdict?.detected ?? false;
    return `
      <div class="provider-card ${det ? 'detected' : 'undetected'}" data-provider="${id}" style="--pc:${ui.color}">
        <div class="pc-head"><div class="pc-dot"></div><span class="pc-name">${escHtml(ui.name)}</span><span class="pc-score">${score}%</span></div>
        <div class="pc-bar-wrap">${score > 0 ? `<div class="pc-bar" style="width:${score}%"></div>` : ''}</div>
        <div class="pc-label">${escHtml(label)}</div>
      </div>`;
  }).join('');

  // ── GROUP 6: Tools — export/share/analysis actions, collapsed ──────
  const toolsGroupBody = `
    <div class="tools-grid">
      <button id="exportJsonBtn">⇩ JSON</button>
      <button id="exportCsvBtn">⇩ CSV</button>
      <button id="exportMdBtn">⇩ Markdown</button>
      <button id="exportPrintBtn">⇩ Report</button>
      <button id="originLeakBtn">🔎 Origin leak</button>
      <button id="shareCodeBtn">⧉ Share</button>
      <button id="timelineBtn">📅 Timeline</button>
      <button id="treeBtn">🌲 Tree</button>
    </div>`;

  // ── Assemble: always-visible summary, then collapsible groups ──────
  resultsEl.innerHTML = `
    ${metaLine}
    ${statusBlock}
    ${detectedGroup}
    ${ipsGroupHtml}

    ${groupSection('net-signals', '📡 Network & infrastructure signals', netGroupCount, netGroupBody, netGroupCount === 0)}
    ${groupSection('all-providers', `📋 All ${order.length} providers (incl. undetected)`, undetected.length, `<div class="providers-grid">${allCards}</div>`, true)}
    ${groupSection('tools', '🛠 Tools & export', 8, toolsGroupBody, true)}
  `;

  // Wire collapsible group toggles
  resultsEl.querySelectorAll('.group-header').forEach(h => {
    h.addEventListener('click', () => {
      const body = h.nextElementSibling;
      const collapsed = body.classList.toggle('collapsed');
      h.querySelector('.group-chevron').textContent = collapsed ? '▸' : '▾';
    });
  });

  document.getElementById('exportJsonBtn').addEventListener('click', () => exportJson(result));
  document.getElementById('exportCsvBtn').addEventListener('click', () => exportCsv(result));
  document.getElementById('exportMdBtn').addEventListener('click', () => exportMarkdown(result));
  document.getElementById('exportPrintBtn').addEventListener('click', () => exportPrintable(result));
  document.getElementById('originLeakBtn').addEventListener('click', () => renderOriginLeak(domainInput.value.trim()));
  document.getElementById('timelineBtn').addEventListener('click', () => renderTimeline(domainInput.value.trim()));
  document.getElementById('treeBtn').addEventListener('click', () => renderTree(result, domainInput.value.trim()));
  document.getElementById('shareCodeBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'makeShareCode', result }, res => {
      if (!res?.code) return;
      navigator.clipboard.writeText(res.code).catch(() => {});
      const btn = document.getElementById('shareCodeBtn');
      if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { if (btn) btn.textContent = '⧉ Share'; }, 2000); }
    });
  });

  resultsEl.querySelectorAll('.provider-card, .provider-row-compact').forEach(card =>
    card.addEventListener('click', () => {
      if (card.dataset.provider) renderDetail(result, card.dataset.provider);
    })
  );
  resultsEl.querySelectorAll('.ip-chip').forEach(chip =>
    chip.addEventListener('click', () => renderIpEvidence(result, chip.dataset.ip))
  );
}

// ── IP evidence detail (PTR / RDAP cross-verification) ────────
function renderIpEvidence(result, ip) {
  const ev = result.ipEvidence?.[ip];
  const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

  const rows = [];
  rows.push(infoRow('IP', ip));
  if (ev) {
    rows.push(infoRow('Reverse DNS (PTR)', ev.ptr || 'No PTR record'));
    rows.push(infoRow('Organization (RDAP)', ev.org || 'Unknown'));
    rows.push(infoRow('ASN Handle', ev.asnHandle));
    rows.push(infoRow('CIDR', ev.cidr));
    rows.push(infoRow('Country', ev.country));
    if (ev.matchedProviders?.length) {
      const names = ev.matchedProviders.map(id => PROVIDER_UI[id]?.name || id).join(', ');
      rows.push(`<div class="result-row hit"><span>Corroborates</span><strong>${escHtml(names)}</strong></div>`);
    } else {
      rows.push(`<div class="result-row miss"><span>Corroborates</span><strong>No provider match</strong></div>`);
    }
  } else {
    rows.push(`<div class="result-row miss"><span>Status</span><strong>No evidence gathered</strong></div>`);
  }

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">IP Evidence — ${escHtml(ip)}</span>
    </div>
    <div class="checks-list">
      ${sectionHdr('Cross-Verification (PTR + RDAP)')}
      ${rows.filter(Boolean).join('')}
    </div>`;

  document.getElementById('backBtn').addEventListener('click', () => {
    renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
  });
}

// ── Detail view ───────────────────────────────────────────────
// ── Session Intel field config — replaces the old per-provider if-chain.
// Each entry is a list of [label, getter(meta) => value|null] pairs.
// Adding a new provider's intel fields means adding one map entry here,
// not another `if (pid === ...)` branch in renderDetail.
const META_INTEL_CONFIG = {
  cloudflare: meta => [
    ['Data Center', formatPoP(meta.dataCenter)],
    ['CF-RAY ID',   meta.cfRayId],
    ['TLS',         meta.tlsVersion],
    ['HTTP',        meta.httpVersion],
    ['KEX',         meta.kex],
    ...(meta.warp    === 'on' ? [['WARP',    'Active']] : []),
    ...(meta.gateway === 'on' ? [['Gateway', 'Active']] : []),
    ...(meta.rbi     === 'on' ? [['RBI',     'Active']] : []),
    ['Flight ID',   meta.flightId],
  ],
  akamai: meta => [
    ['Edgescape',  (meta.edgescape || '').slice(0, 80)],
    ['Cache Node', (meta.cacheNode || '').slice(0, 60)],
  ],
  fastly: meta => [
    ['Cache Node',   meta.cacheNode],
    ['Shield Node',  meta.shieldNode],
    ['Edge Elapsed', meta.elapsedMs],
  ],
  imperva: meta => [
    ['X-Iinfo', (meta.iinfoHeader || '').slice(0, 80)],
  ],
  cloudfront: meta => [
    ['CF PoP',      meta.cfPop],
    ['Request ID', (meta.cfRequestId || '').slice(0, 55)],
  ],
  azure: meta => [
    ['Azure-Ref', (meta.azureRef || '').slice(0, 70)],
    ['FDID',       meta.fdid],
  ],
  sucuri: meta => [
    ['Sucuri ID', meta.sucuriId],
    ['Cache',     meta.cacheStatus],
  ],
  vercel: meta => [
    ['Vercel ID', (meta.vercelId || '').slice(0, 55)],
    ['Region',     meta.region],
    ['Deploy ID', (meta.deploymentId || '').slice(0, 45)],
  ],
  netlify: meta => [
    ['NF Request ID', meta.nfRequestId],
    ['Edge PoP',       meta.pop],
  ],
  google: meta => [
    ['Trace Context', (meta.traceContext || '').slice(0, 60)],
  ],
  bunnycdn: meta => [
    ['Server Node', meta.serverNode],
    ['Pull Zone',   meta.pullzone],
    ['Account UID', meta.uid],
    ['Request ID',  meta.requestId],
    ['Country',     meta.country],
  ],
  stackpath: meta => [
    ['Cache Node', (meta.cacheNode || '').slice(0, 60)],
    ['SP-UID',      meta.spUid],
  ],
  keycdn: meta => [
    ['Edge PoP',   meta.edgeLocation],
    ['Edge IP',    meta.edgeIp],
    ['Unique ID', (meta.uniqueId || '').slice(0, 55)],
  ],
  gcore: meta => [
    ['Server ID',    meta.serverId],
    ['Cached Since', meta.cachedSince],
    ['Edge PoP',     meta.pop],
  ],
};

function buildIntelRows(pid, signals) {
  const meta = signals.meta || {};
  const rows = [];

  const fields = META_INTEL_CONFIG[pid];
  if (fields) {
    for (const [label, value] of fields(meta)) rows.push(infoRow(label, value));
  }

  // Cross-cutting fields common to all providers
  if (signals.dnsVeryShortTtl)
    rows.push(infoRow('DNS TTL', '< 60s (very short — strong CDN indicator)'));
  else if (signals.dnsShortTtl)
    rows.push(infoRow('DNS TTL', '< 300s (CDN-typical short TTL)'));

  if (signals.ipEvidenceMatch)
    rows.push(infoRow('IP Cross-Verification', 'PTR/RDAP corroborates this provider'));

  return rows.filter(Boolean);
}

// ── Detail view ───────────────────────────────────────────────
function renderDetail(result, pid) {
  const ui = PROVIDER_UI[pid];
  const pv = result?.providers?.[pid];
  if (!ui || !pv) return;

  const signals = pv.signals || {};
  const verdict = pv.verdict  || { score: 0, label: 'Unlikely', detected: false };

  const groupsHtml = ui.groups.map(g =>
    sectionHdr(g.title) + g.signals.map(s =>
      boolRow(s.label, getSig(signals, s.key), s.tip || '')
    ).join('')
  ).join('');

  const metaHtml = buildIntelRows(pid, signals).join('');
  const intelSection = metaHtml ? sectionHdr('Session Intel') + metaHtml : '';

  const productTypeHtml = ui.productType
    ? `<div class="product-type-note">${ui.productType}</div>` : '';

  // ── A3: staleness warning ──────────────────────────────────
  const decay = pv.decay;
  const decayHtml = decay?.stale
    ? `<div class="decay-warn">⚠ Signature last reviewed ${escHtml(decay.lastReviewed)} (~${decay.monthsAgo} months ago) — provider may have changed infrastructure since. Treat this score as possibly outdated.</div>`
    : '';

  // ── C2: confidence breakdown — approximate marginal contribution ──
  function labelForSignal(key) {
    for (const g of ui.groups) {
      const found = g.signals.find(s => s.key === key);
      if (found) return found.label;
    }
    return key;
  }
  const breakdown = pv.breakdown || [];
  const breakdownHtml = breakdown.length ? `
    ${sectionHdr('Confidence breakdown (approx.)')}
    <div class="breakdown-list">
      ${breakdown.map(b => `
        <div class="breakdown-row">
          <span class="bd-label">${escHtml(labelForSignal(b.signal))}</span>
          <span class="bd-bar-wrap" style="--pc:${ui.color}"><span class="bd-bar" style="width:${Math.min(100, b.points)}%"></span></span>
          <span class="bd-pts">+${b.points}</span>
        </div>`).join('')}
    </div>
    <div class="breakdown-note">Computed by toggling each fired signal off and re-scoring — an approximation, not an exact decomposition (scoring may cap/clamp, so parts won't always sum to the total).</div>` : '';

  resultsEl.innerHTML = `
    <div class="detail-header" style="--pc:${ui.color}">
      <button class="back-btn" id="backBtn">← Back</button>
      <div class="detail-dot"></div>
      <span class="detail-name">${ui.name}</span>
      <span class="detail-score">${verdict.score}%</span>
    </div>
    ${productTypeHtml}
    ${decayHtml}
    <div class="detail-verdict ${verdict.detected ? 'detected' : 'not-detected'}">${verdict.label}</div>
    <div class="checks-list">
      ${breakdownHtml}
      ${groupsHtml}
      ${intelSection}
      ${sectionHdr('Threat intel — CVEs (D4)')}
      <button class="link-btn" id="cveBtn">🛈 Check recent CVEs for "${escHtml(ui.name)}" via NVD</button>
      <div id="cvePanel"></div>
      ${sectionHdr('Threat intel — IP lookup (D3)')}
      ${(result.resolvedIPs || []).length
        ? `<div class="breakdown-note">Click an IP to query Shodan InternetDB (free) + optional Shodan/Censys full API (keys in Settings):</div>
           <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px">
           ${(result.resolvedIPs).map(ip => `<button class="link-btn ip-threat-btn" data-ip="${escHtml(ip)}">${escHtml(ip)}</button>`).join('')}
           </div>
           <div id="threatIntelPanel"></div>`
        : '<div class="breakdown-note">No resolved IPs for this scan.</div>'}
      ${sectionHdr('Tab correlation')}
      <div id="tabCorrelationPanel"><div class="breakdown-note">Loading cross-tab data…</div></div>
      ${sectionHdr('Help improve this signature (opt-in)')}
      ${(result.unknownHeaders?.length)
        ? `<div class="breakdown-note">This scan saw ${result.unknownHeaders.length} header${result.unknownHeaders.length > 1 ? 's' : ''} no provider recognizes yet — click to report it (only sent if crowd reporting is enabled in Settings):</div>
           <div style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0">
           ${result.unknownHeaders.map(h => `<button class="link-btn unknown-header-btn" data-header="${escHtml(h)}">📋 ${escHtml(h)}</button>`).join('')}
           </div>`
        : '<div class="breakdown-note">No unrecognized headers detected on this scan.</div>'}
      <div class="breakdown-note" style="margin-top:8px">Or describe something else this provider isn't tracking yet:</div>
      <input type="text" id="crowdNoteInput" class="settings-input" placeholder="e.g. new cookie xyz_session seen on Cloudflare">
      <button class="link-btn" id="crowdSubmitBtn">Send report</button>
      <div id="crowdSubmitResult"></div>
    </div>`;

  document.getElementById('cveBtn').addEventListener('click', () => renderCveLookup(pid, ui.name));
  // Wire one-click unknown-header report buttons
  resultsEl.querySelectorAll('.unknown-header-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const header = btn.dataset.header;
      chrome.runtime.sendMessage({ action: 'submitCrowdReport', providerId: pid, notes: `Unrecognized header: ${header}` }, res => {
        const resultEl = document.getElementById('crowdSubmitResult');
        if (resultEl) resultEl.innerHTML = `<div class="breakdown-note" style="margin-top:6px">✓ Reported "${escHtml(header)}" (if crowd reporting is enabled in Settings).</div>`;
        btn.disabled = true;
        btn.textContent = `✓ ${header}`;
      });
    });
  });
  // D3: wire IP threat intel buttons
  resultsEl.querySelectorAll('.ip-threat-btn').forEach(btn => {
    btn.addEventListener('click', () => renderThreatIntel(btn.dataset.ip));
  });

  // Load tab correlation async
  const domain = domainInput.value.trim();
  chrome.runtime.sendMessage({ action: 'getTabCorrelation', domain }, res => {
    const panel = document.getElementById('tabCorrelationPanel');
    if (!panel) return;
    if (!res || res.entryCount < 2) {
      panel.innerHTML = '<div class="breakdown-note">Only one tab scanned this domain — open more tabs on the same site and re-scan to see cross-tab routing variance.</div>';
      return;
    }
    const cls = res.hasVariance ? 'tab-correlation-row variance' : 'tab-correlation-row';
    panel.innerHTML = `<div class="${cls}">${escHtml(res.note)}</div>
      <div class="breakdown-note">${res.entryCount} tab${res.entryCount > 1 ? 's' : ''} recorded for ${escHtml(res.apex)}.</div>`;
  });
  document.getElementById('crowdSubmitBtn').addEventListener('click', () => {
    const note = document.getElementById('crowdNoteInput').value.trim();
    if (!note) return;
    chrome.runtime.sendMessage({ action: 'submitCrowdReport', providerId: pid, notes: note }, () => {
      document.getElementById('crowdNoteInput').value = '';
      const resultEl = document.getElementById('crowdSubmitResult');
      if (resultEl) resultEl.innerHTML = '<div class="breakdown-note" style="margin-top:6px">✓ Sent (if crowd reporting is enabled in Settings).</div>';
    });
  });

  document.getElementById('backBtn').addEventListener('click', () => {
    renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
  });
}

// ── Scan orchestrator ─────────────────────────────────────────
// Centralized state for the scan lifecycle. Previously this was spread
// across `activePort`, `resultsEl._scan`, `resultsEl._cached`, and ad-hoc
// button-disable toggles in three different places (result/error/disconnect
// handlers) — easy to forget one when adding a new exit path. Now there's
// one place that knows what "idle" means.
const appState = {
  activePort: null,
  lastResult: null,
  lastCached: false,
};

function setUiIdle() {
  appState.activePort   = null;
  scanBtn.disabled       = false;
  rescanBtn.disabled     = false;
  showProgress(false);
}

function resetScanState() {
  appState.lastResult = null;
  appState.lastCached = false;
  resultsEl._scan   = null;
  resultsEl._cached = false;
}

function doScan(domain, forceRefresh) {
  if (!isValidDomain(domain)) {
    setStatus('Invalid input — enter a domain (example.com) or IP (1.2.3.4)');
    return;
  }

  // Abort any in-flight scan
  if (appState.activePort) { try { appState.activePort.disconnect(); } catch {} appState.activePort = null; }

  resetScanState();
  setStatus('Scanning…', 'scanning');
  resultsEl.innerHTML = '';
  showProgress(true);
  updateProgress(0, 'Connecting…');
  scanBtn.disabled   = true;
  rescanBtn.disabled = true;

  const port = chrome.runtime.connect({ name: 'scan' });
  appState.activePort = port;

  port.onMessage.addListener(msg => {
    if (msg.type === 'progress') {
      updateProgress(msg.pct, msg.activity);

    } else if (msg.type === 'result') {
      setUiIdle();

      const result = msg.data;
      const cached = !!msg.cached;

      appState.lastResult = result;
      appState.lastCached = cached;
      resultsEl._scan   = result;
      resultsEl._cached = cached;
      resultsEl._diff   = msg.diff || null;
      renderOverview(result, cached, msg.diff || null);
      refreshPinButton();
      addWatchButton(domain || domainInput.value.trim());

    } else if (msg.type === 'error') {
      setUiIdle();
      resetScanState();
      setStatus(`Scan failed — ${msg.message || 'unknown error'}`);
    }
  });

  port.onDisconnect.addListener(() => {
    if (appState.activePort) {
      setUiIdle();
      // Only show a disconnect error if no result ever arrived for this scan
      if (!appState.lastResult) {
        resetScanState();
        setStatus('Disconnected — try again');
      }
    }
  });

  port.postMessage({ action: 'scan', domain, forceRefresh: !!forceRefresh });
}

// ── Button handlers ───────────────────────────────────────────
function getDomain() {
  let v = domainInput.value.trim().toLowerCase();
  if (!v) return v;

  // Allow pasted full URLs: strip scheme, then path/query/fragment.
  v = v.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '');
  // IPv6 in bracket notation must be peeled before we touch ':' or '/' generically,
  // e.g. "[2606:4700::1]:443/path" or "[2606:4700::1]".
  const bracketMatch = v.match(/^\[([0-9a-f:]+)\](?::\d+)?(\/.*)?$/i);
  if (bracketMatch) {
    v = bracketMatch[1];
  } else {
    // Strip any path/query/fragment, then a trailing :port (but never touch
    // a bare, unbracketed IPv6 address — those contain multiple ':' and have
    // no path component to strip in normal usage).
    v = v.replace(/[/?#].*$/, '');
    if (!v.includes('::') && v.split(':').length === 2) v = v.split(':')[0];
  }

  v = v.trim();
  // Collapse internal whitespace some users paste accidentally, and drop a
  // trailing root-zone dot ("example.com." is a valid but unusual FQDN form).
  v = v.replace(/\s+/g, '').replace(/\.$/, '');

  // Best-effort IDN → punycode so DoH/RDAP lookups behave for non-ASCII domains.
  if (/[^\x00-\x7f]/.test(v) && !isIPv4(v) && !isIPv6(v)) {
    try { v = new URL(`https://${v}`).hostname; } catch { /* leave as-is, validation will reject if truly invalid */ }
  }

  return v;
}

scanBtn.addEventListener('click', () => {
  const d = getDomain();
  domainInput.value = d;
  doScan(d, false);
});

rescanBtn.addEventListener('click', () => {
  const d = getDomain();
  domainInput.value = d;
  doScan(d, true);
});

domainInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') scanBtn.click();
});

// ── History view ───────────────────────────────────────────────
function renderHistory(list) {
  if (!list.length) {
    resultsEl.innerHTML = `
      <div class="detail-header">
        <button class="back-btn" id="backBtn">← Back</button>
        <span class="detail-name">Scan History</span>
      </div>
      <div class="empty-state">No scans yet.</div>`;
    document.getElementById('backBtn').addEventListener('click', () => {
      if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
      else resultsEl.innerHTML = '';
    });
    return;
  }

  const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const rows = list.map(e => {
    const date = new Date(e.ts).toLocaleString();
    const names = e.detected.map(id => PROVIDER_UI[id]?.name || id).join(', ') || 'None detected';
    const tag = e.isDirectIP ? ' <span class="history-ip-tag">IP</span>' : '';
    return `
      <div class="history-row" data-domain="${escHtml(e.domain)}">
        <div class="history-row-top">
          <strong>${escHtml(e.domain)}</strong>${tag}
          <span class="history-date">${escHtml(date)}</span>
        </div>
        <div class="history-row-providers">${escHtml(names)}</div>
      </div>`;
  }).join('');

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Scan History</span>
      <button class="btn-icon" id="clearHistoryBtn" title="Clear history">✕</button>
    </div>
    <div class="checks-list history-list">${rows}</div>`;

  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
    else resultsEl.innerHTML = '';
  });
  document.getElementById('clearHistoryBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'clearHistory' }, () => renderHistory([]));
  });
  resultsEl.querySelectorAll('.history-row').forEach(row => {
    row.addEventListener('click', () => {
      const d = row.dataset.domain;
      domainInput.value = d;
      doScan(d, false);
    });
  });
}

historyBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'getHistory' }, res => {
    renderHistory(res?.history || []);
  });
});

// ── C3: Pinned domains view ───────────────────────────────────
function renderPins(list) {
  if (!list.length) {
    resultsEl.innerHTML = `
      <div class="detail-header">
        <button class="back-btn" id="backBtn">← Back</button>
        <span class="detail-name">Pinned Domains</span>
      </div>
      <div class="empty-state">No pinned domains yet — tap the ★ next to a domain to pin it.</div>`;
    document.getElementById('backBtn').addEventListener('click', () => {
      if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
      else resultsEl.innerHTML = '';
    });
    return;
  }
  const rows = list.map(d => `
    <div class="history-row" data-domain="${escHtml(d)}">
      <div class="history-row-top"><strong>${escHtml(d)}</strong></div>
    </div>`).join('');
  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Pinned Domains</span>
    </div>
    <div class="checks-list history-list">${rows}</div>`;
  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
    else resultsEl.innerHTML = '';
  });
  resultsEl.querySelectorAll('.history-row').forEach(row => {
    row.addEventListener('click', () => {
      const d = row.dataset.domain;
      domainInput.value = d;
      doScan(d, false);
    });
  });
}
pinsViewBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'getPins' }, res => renderPins(res?.pins || []));
});

// ── Settings view (expanded for v9.1) ─────────────────────────
function renderSettings(settings) {
  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Settings</span>
    </div>
    <div class="checks-list">
      <div class="settings-section-title">Appearance</div>
      <div class="settings-row">
        <span class="settings-label">Theme</span>
        <select id="themeSelect" class="settings-input" style="width:auto;margin-top:0">
          <option value="system">System</option>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
        </select>
      </div>

      <div class="settings-section-title">Passive ambient detection (beta)</div>
      <div class="settings-row">
        <span class="settings-label">Enable ambient mode
          <span class="settings-hint">Silently fingerprints CDN/WAF on every page you browse using read-only header observation — no Scan button needed. Badge shows provider count per tab. All data is local and cleared when you close the tab. Off by default.</span>
        </span>
        <label class="toggle-switch"><input type="checkbox" id="ambientToggle"><span class="slider"></span></label>
      </div>

      <div class="settings-section-title">Watchlist auto-rescan interval</div>
      <div class="settings-row">
        <span class="settings-label">Re-check every
          <span class="settings-hint">Minimum 60 minutes. Notifies you when a watched domain's detected provider set changes.</span>
        </span>
        <select id="watchIntervalSelect" class="settings-input" style="width:auto;margin-top:0">
          <option value="60">1 hour</option>
          <option value="180">3 hours</option>
          <option value="360">6 hours</option>
          <option value="720">12 hours</option>
          <option value="1440">24 hours</option>
        </select>
      </div>

      <div class="settings-section-title">Crowd-sourced signatures (opt-in)</div>
      <div class="settings-row">
        <span class="settings-label">Enable reporting
          <span class="settings-hint">Every scan now automatically checks for response headers no provider recognizes yet, and surfaces them as one-click "report this?" buttons in each detected provider's detail view — no need to notice or type anything by hand. Sends only a provider ID + the header name or a short note — never your domain or IP. Requires your own deployed endpoint (see /worker/README.md).</span>
        </span>
        <label class="toggle-switch"><input type="checkbox" id="crowdToggle"><span class="slider"></span></label>
      </div>
      <input type="text" id="crowdEndpointInput" class="settings-input" placeholder="https://your-worker.example.workers.dev/report">
      <div class="breakdown-note" style="margin-top:6px">View submitted reports and their frequency at your Worker's own URL (e.g. <code>https://your-worker.workers.dev/</code>) — the dashboard is built into the Worker code.</div>

      <div class="settings-section-title">Import a scan code</div>
      <div class="breakdown-note">Paste a share code (generated via the ⧉ Share button) to view a scan result from another session or machine.</div>
      <textarea id="importCodeArea" class="share-code-area" placeholder="Paste share code here…" rows="3"></textarea>
      <button class="btn-primary-sm" id="importCodeBtn">Load scan</button>
      <div id="importCodeResult"></div>

      <div class="settings-section-title">About</div>
      <div class="breakdown-note">CDN/WAF Detector v9.1 — local scoring only, no telemetry by default.<br>
      Keyboard shortcuts: <strong>Ctrl+Shift+S</strong> open popup · <strong>Ctrl+Shift+D</strong> side panel · <strong>Ctrl+Shift+V</strong> scan clipboard · <strong>j/k</strong> navigate results · <strong>Enter</strong> open detail · <strong>Esc</strong> back.<br>
      Pinned domains and watchlist sync across your Chrome profiles automatically via <code>chrome.storage.sync</code> (same Google account, no server needed).</div>

      <div class="settings-section-title">Threat intel API keys (D3 — optional)</div>
      <div class="breakdown-note">Keys are stored locally and sent only to Shodan/Censys when you click an IP lookup. Leave blank to use only the free Shodan InternetDB (no key needed).</div>
      <div class="settings-row"><span class="settings-label">Shodan API key<span class="settings-hint">api.shodan.io — free tier available</span></span></div>
      <input type="password" id="shodanKeyInput" class="settings-input" placeholder="Your Shodan API key">
      <div class="settings-row" style="margin-top:8px"><span class="settings-label">Censys API ID<span class="settings-hint">search.censys.io</span></span></div>
      <input type="text" id="censysIdInput" class="settings-input" placeholder="Censys API ID">
      <div class="settings-row" style="margin-top:6px"><span class="settings-label">Censys API Secret</span></div>
      <input type="password" id="censysSecretInput" class="settings-input" placeholder="Censys API secret" style="margin-bottom:8px">
    </div>`;

  document.getElementById('themeSelect').value = settings.theme || 'system';
  document.getElementById('crowdToggle').checked = !!settings.crowdReportEnabled;
  document.getElementById('crowdEndpointInput').value = settings.crowdReportEndpoint || '';
  document.getElementById('ambientToggle').checked = !!settings.ambientModeEnabled;
  document.getElementById('watchIntervalSelect').value = String(settings.watchlistIntervalMin || 360);

  document.getElementById('themeSelect').addEventListener('change', e => {
    applyTheme(e.target.value);
    chrome.runtime.sendMessage({ action: 'setSettings', patch: { theme: e.target.value } });
  });
  document.getElementById('crowdToggle').addEventListener('change', e => {
    chrome.runtime.sendMessage({ action: 'setSettings', patch: { crowdReportEnabled: e.target.checked } });
  });
  document.getElementById('crowdEndpointInput').addEventListener('change', e => {
    chrome.runtime.sendMessage({ action: 'setSettings', patch: { crowdReportEndpoint: e.target.value.trim() } });
  });
  document.getElementById('ambientToggle').addEventListener('change', e => {
    chrome.runtime.sendMessage({ action: 'setSettings', patch: { ambientModeEnabled: e.target.checked } });
  });
  document.getElementById('watchIntervalSelect').addEventListener('change', e => {
    chrome.runtime.sendMessage({ action: 'setSettings', patch: { watchlistIntervalMin: Number(e.target.value) } });
  });
  // D3 API key inputs
  document.getElementById('shodanKeyInput').value  = settings.shodanApiKey    || '';
  document.getElementById('censysIdInput').value   = settings.censysApiId     || '';
  document.getElementById('censysSecretInput').value = settings.censysApiSecret || '';
  ['shodanKeyInput','censysIdInput','censysSecretInput'].forEach(id => {
    const field = id.replace('Input', '').replace('shodan','shodanApi').replace('censysId','censysApiId').replace('censysSecret','censysApiSecret');
    const keyMap = { shodanKeyInput: 'shodanApiKey', censysIdInput: 'censysApiId', censysSecretInput: 'censysApiSecret' };
    document.getElementById(id).addEventListener('change', e => {
      chrome.runtime.sendMessage({ action: 'setSettings', patch: { [keyMap[id]]: e.target.value.trim() } });
    });
  });
  document.getElementById('importCodeBtn').addEventListener('click', () => {
    const code = document.getElementById('importCodeArea').value.trim();
    const el = document.getElementById('importCodeResult');
    if (!code) { el.textContent = 'Paste a code first.'; return; }
    el.textContent = 'Loading…';
    chrome.runtime.sendMessage({ action: 'decodeShareCode', code }, res => {
      if (res?.error) { el.innerHTML = `<div class="import-result-err">Error: ${escHtml(res.error)}</div>`; return; }
      resultsEl._scan = res.result; resultsEl._cached = false; resultsEl._diff = null;
      renderOverview(res.result, false, null);
    });
  });

  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
    else resultsEl.innerHTML = '';
  });
}
settingsBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'getSettings' }, s => renderSettings(s || {}));
});

// ── Watchlist view ─────────────────────────────────────────────
function renderWatchlist(list) {
  const backBtn = () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
    else resultsEl.innerHTML = '';
  };
  const rows = list.length
    ? list.map(d => `
        <div class="watchlist-row">
          <span class="wr-domain">${escHtml(d)}</span>
          <div class="wr-actions">
            <button class="wr-btn" data-action="scan" data-domain="${escHtml(d)}">Scan now</button>
            <button class="wr-btn" data-action="remove" data-domain="${escHtml(d)}">Remove</button>
          </div>
        </div>`).join('')
    : '<div class="empty-state">No watched domains yet — use the 👁 button next to a scan result to add one.</div>';

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Watchlist</span>
      <button class="link-btn" id="rescanAllBtn" style="margin-left:auto;font-size:10px">↻ Re-scan all now</button>
    </div>
    <div class="breakdown-note">Watched domains are re-scanned automatically. You get a notification when their detected provider set changes.</div>
    <div id="watchlistRows">${rows}</div>`;

  document.getElementById('backBtn').addEventListener('click', backBtn);
  document.getElementById('rescanAllBtn')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'runWatchlistNow' }, () => {
      const btn = document.getElementById('rescanAllBtn');
      if (btn) btn.textContent = '✓ Done';
    });
  });
  resultsEl.querySelectorAll('.wr-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const d = btn.dataset.domain;
      if (btn.dataset.action === 'scan') { domainInput.value = d; doScan(d, false); }
      if (btn.dataset.action === 'remove') {
        chrome.runtime.sendMessage({ action: 'toggleWatch', domain: d }, res => renderWatchlist(res?.watchlist || []));
      }
    });
  });
}
if (watchlistBtn) {
  watchlistBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'getWatchlist' }, res => renderWatchlist(res?.watchlist || []));
  });
}

// ── Ambient mode banner in popup when enabled ──────────────────
chrome.runtime.sendMessage({ action: 'getSettings' }, s => {
  if (s?.ambientModeEnabled) {
    const banner = document.createElement('div');
    banner.className = 'ambient-banner';
    banner.textContent = '● Passive ambient detection is ON — badge shows CDN/WAF count per tab';
    const statusBar = document.getElementById('status-bar');
    if (statusBar) statusBar.parentNode.insertBefore(banner, statusBar);
  }
});

// ── Watchlist button wired to current scan result ──────────────
// Popup adds a small "👁 Watch" inline button in the export row once a
// scan completes (handled here since we need the result in scope).
function addWatchButton(domain) {
  const exportRow = resultsEl.querySelector('.export-row');
  if (!exportRow || exportRow.querySelector('#watchInlineBtn')) return;
  const btn = document.createElement('button');
  btn.id = 'watchInlineBtn';
  btn.textContent = '👁 Watch';
  btn.title = 'Add to watchlist for auto re-scan notifications';
  exportRow.appendChild(btn);
  chrome.runtime.sendMessage({ action: 'getWatchlist' }, res => {
    if ((res?.watchlist || []).includes(domain)) btn.textContent = '👁 Watching';
  });
  btn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'toggleWatch', domain }, res => {
      const watching = (res?.watchlist || []).includes(domain);
      btn.textContent = watching ? '👁 Watching' : '👁 Watch';
    });
  });
}

// Custom provider management page (accessible from Settings)
function renderCustomProviders(providers) {
  const rows = providers.length
    ? providers.map(p => `
        <div class="watchlist-row">
          <span class="wr-domain" style="color:${escHtml(p.color)}">${escHtml(p.name)}</span>
          <div class="wr-actions">
            <button class="wr-btn remove-custom" data-id="${escHtml(p.id)}">Remove</button>
          </div>
        </div>`).join('')
    : '<div class="empty-state">No custom provider packs imported yet.</div>';

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Custom Providers</span>
    </div>
    ${rows}
    ${sectionHdr('Import a provider pack (JSON)')}
    <div class="breakdown-note">Must match the custom provider schema. See CHANGELOG.md for the supported fields: id (custom_*), name, color, cnamePatterns [{pattern, points}], headerChecks [{header, valuePattern?, points}].</div>
    <textarea id="cpJsonArea" class="import-json-area" placeholder='{"id":"custom_mycdn","name":"MyCDN","cnamePatterns":[{"pattern":"\\.mycdn\\.net$","points":80}]}'></textarea>
    <button class="btn-primary-sm" id="cpImportBtn">Import</button>
    <div id="cpResult"></div>`;

  // #14: pick up a draft rule handed off from the crowd-report suggester
  chrome.storage.local.get('pending_custom_rule_draft', res => {
    if (res?.pending_custom_rule_draft) {
      chrome.storage.local.remove('pending_custom_rule_draft');
      const area = document.getElementById('cpJsonArea');
      if (area) { area.value = res.pending_custom_rule_draft; area.scrollIntoView({ behavior: 'smooth' }); }
    }
  });

  document.getElementById('backBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'getSettings' }, s => renderSettings(s || {}));
  });
  document.getElementById('cpImportBtn').addEventListener('click', () => {
    const json = document.getElementById('cpJsonArea').value.trim();
    chrome.runtime.sendMessage({ action: 'importCustomProvider', json }, res => {
      const el = document.getElementById('cpResult');
      if (res?.ok) {
        el.innerHTML = `<div class="import-result-ok">✓ Imported "${escHtml(res.provider.name)}" (${escHtml(res.provider.id)})</div>`;
        chrome.runtime.sendMessage({ action: 'getCustomProviders' }, r => renderCustomProviders(r?.providers || []));
      } else {
        el.innerHTML = `<div class="import-result-err">Error: ${escHtml(res?.error || 'unknown')}</div>`;
      }
    });
  });
  resultsEl.querySelectorAll('.remove-custom').forEach(btn => {
    btn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'removeCustomProvider', id: btn.dataset.id }, res => {
        renderCustomProviders(res?.providers || []);
      });
    });
  });
}

// ════════════════════════════════════════════════════════════════
// Round-3 popup additions
// ════════════════════════════════════════════════════════════════

// ── B3: Clipboard scan ────────────────────────────────────────
// Reads clipboard text, extracts first domain/IP candidate, scans it.
// Called from the clipboard button in the header or via keyboard shortcut.
async function scanFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    const match = text.trim().match(/([a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})/);
    if (!match) {
      statusTextEl.className = 'status-fail';
      statusTextEl.textContent = chrome.i18n.getMessage('statusInvalid') || 'No domain/IP found in clipboard';
      return;
    }
    const candidate = match[1].toLowerCase();
    domainInput.value = candidate;
    doScan(candidate, false);
  } catch (e) {
    // Clipboard permission denied — fall back to prompting the user
    domainInput.focus();
    domainInput.placeholder = 'Paste domain here…';
  }
}

// Wire clipboard scan to pending flag (set by keyboard shortcut in SW)
chrome.storage.local.get('clipboard_scan_pending', res => {
  if (res?.clipboard_scan_pending) {
    chrome.storage.local.remove('clipboard_scan_pending');
    scanFromClipboard();
  }
});

// ── B4: Markdown export ───────────────────────────────────────
function exportMarkdown(result) {
  const domain  = domainInput.value.trim() || 'scan';
  const order   = Object.keys(PROVIDER_UI);
  const detected = order.filter(id => result.providers?.[id]?.verdict?.detected);

  let md = `# CDN / WAF Report — ${domain}\n\n`;
  md += `**Scanned:** ${result.scannedAt || ''}\n\n`;
  md += `**IPs:** ${(result.resolvedIPs || []).join(', ') || '—'}\n\n`;

  if (result.dnsProvider) md += `**DNS Provider:** ${result.dnsProvider}\n\n`;
  if (result.spfDmarc?.spfProvider) md += `**Email Provider (SPF):** ${result.spfDmarc.spfProvider}\n\n`;
  if (result.spfDmarc?.dmarcPolicy) md += `**DMARC Policy:** p=${result.spfDmarc.dmarcPolicy}\n\n`;
  if (result.httpsRecord?.ech) md += `**ECH (Encrypted Client Hello):** Enabled\n\n`;
  if (result.httpsRecord?.alpn?.length) md += `**ALPN:** ${result.httpsRecord.alpn.join(', ')}\n\n`;

  if (result.layerChain?.chain) {
    md += `**Layer order (visitor→origin):** ${result.layerChain.chain.map(id => PROVIDER_UI[id]?.name || id).join(' → ')}\n\n`;
  }

  md += `## Detected Providers\n\n`;
  if (!detected.length) {
    md += '_None detected._\n\n';
  } else {
    md += '| Provider | Score | Label |\n|---|---|---|\n';
    for (const id of detected) {
      const v = result.providers[id].verdict;
      md += `| ${PROVIDER_UI[id]?.name || id} | ${v.score}% | ${v.label} |\n`;
    }
    md += '\n';
  }

  md += `## All Providers\n\n`;
  md += '| Provider | Score | Detected |\n|---|---|---|\n';
  for (const id of order) {
    const v = result.providers?.[id]?.verdict;
    if (!v) continue;
    md += `| ${PROVIDER_UI[id]?.name || id} | ${v.score}% | ${v.detected ? '✓' : '—'} |\n`;
  }

  const blob = new Blob([md], { type: 'text/markdown' });
  const url  = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename: `cdnwaf-${domain}-${Date.now()}.md` }, () => {
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  });
}

// ── D1: Timeline / snapshot diff view ─────────────────────────
function renderTimeline(domain) {
  if (!domain) return;
  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">📅 Timeline — ${escHtml(domain)}</span>
    </div>
    <div class="empty-state">Loading snapshots…</div>`;
  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
  });

  chrome.runtime.sendMessage({ action: 'getSnapshotHistory', domain }, res => {
    const snaps = res?.snapshots || [];
    if (!snaps.length) {
      resultsEl.querySelector('.empty-state').textContent = 'No snapshots yet — scan this domain a few times to build a timeline.';
      return;
    }

    const rows = snaps.map((s, i) => {
      const detected = Object.entries(s.result?.providers || {})
        .filter(([, v]) => v.verdict?.detected)
        .map(([id]) => PROVIDER_UI[id]?.name || id);
      const prev = snaps[i + 1];
      let diffTag = '';
      if (prev) {
        const prevDet = new Set(Object.entries(prev.result?.providers || {})
          .filter(([, v]) => v.verdict?.detected).map(([id]) => id));
        const curDet  = new Set(Object.entries(s.result?.providers || {})
          .filter(([, v]) => v.verdict?.detected).map(([id]) => id));
        const added   = [...curDet].filter(id => !prevDet.has(id));
        const removed = [...prevDet].filter(id => !curDet.has(id));
        if (added.length || removed.length) {
          diffTag = ` <span class="diff-banner changed" style="display:inline;padding:1px 6px;font-size:9.5px">`
            + (added.length   ? `+${added.map(id => PROVIDER_UI[id]?.name || id).join(',')} ` : '')
            + (removed.length ? `−${removed.map(id => PROVIDER_UI[id]?.name || id).join(',')}` : '')
            + '</span>';
        }
      }
      return `<div class="history-row">
        <div class="history-row-top">
          <span>${new Date(s.ts).toLocaleString()}</span>${diffTag}
        </div>
        <div style="font-size:11px;color:var(--text-dim);margin-top:3px">
          ${detected.length ? escHtml(detected.join(', ')) : 'None detected'}
          ${s.result?.dnsProvider ? ` · DNS: ${escHtml(s.result.dnsProvider)}` : ''}
          ${s.result?.anycast?.dnssecValidated ? ' · 🔒 DNSSEC' : ''}
          ${s.result?.anycast?.ecsLeakSuspected ? ' · 📡 ECS leak' : ''}
        </div>
      </div>`;
    }).join('');

    resultsEl.innerHTML = `
      <div class="detail-header">
        <button class="back-btn" id="backBtn">← Back</button>
        <span class="detail-name">📅 Timeline — ${escHtml(domain)}</span>
      </div>
      <div style="padding:0 14px 8px"><button class="link-btn" id="exportDiffOnlyBtn">⇩ Export changes only (skip unchanged snapshots)</button></div>
      <div class="checks-list history-list">${rows}</div>`;
    document.getElementById('backBtn').addEventListener('click', () => {
      if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
    });
    document.getElementById('exportDiffOnlyBtn').addEventListener('click', () => {
      // #10: filter to only snapshots that changed vs the one immediately
      // before them — most domains scanned repeatedly show "no change" the
      // majority of the time, so this trims a Timeline export down to just
      // the moments that matter.
      const changedOnly = [];
      for (let i = 0; i < snaps.length; i++) {
        const cur = snaps[i], prev = snaps[i + 1];
        if (!prev) { changedOnly.push(snaps[i]); continue; } // first-ever scan always included
        const prevIds = new Set(Object.entries(prev.result?.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => id));
        const curIds  = new Set(Object.entries(cur.result?.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => id));
        const changed = curIds.size !== prevIds.size || [...curIds].some(id => !prevIds.has(id));
        if (changed) changedOnly.push(cur);
      }
      const md = [`# ${domain} — changes only`, '', `${changedOnly.length} of ${snaps.length} snapshots involved a change.`, ''];
      for (const s of changedOnly) {
        const names = Object.entries(s.result?.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => PROVIDER_UI[id]?.name || id);
        md.push(`## ${new Date(s.ts).toLocaleString()}`, `Detected: ${names.join(', ') || 'None'}`, '');
      }
      const blob = new Blob([md.join('\n')], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      chrome.downloads.download({ url, filename: `cdnwaf-${domain}-changes-${Date.now()}.md` }, () => setTimeout(() => URL.revokeObjectURL(url), 10000));
    });
  });
}

// ── D3: Threat intel panel in provider detail ─────────────────
function renderThreatIntel(ip) {
  const panel = document.getElementById('threatIntelPanel');
  if (!panel) return;
  panel.innerHTML = '<div class="empty-state">Querying Shodan InternetDB…</div>';
  chrome.runtime.sendMessage({ action: 'queryThreatIntel', ip }, res => {
    if (!panel.closest('#results')) return; // navigated away
    const si = res?.shodanInternetDb;
    const sh = res?.shodan;
    const ce = res?.censys;
    let html = '';

    if (si && !si.detail) {
      // Shodan InternetDB (free, no key)
      const ports = (si.ports || []).join(', ') || '—';
      const vulns = (si.vulns || []).slice(0, 5).map(v => `<span class="info-pill" style="color:var(--red)">${escHtml(v)}</span>`).join('') || '—';
      const tags  = (si.tags  || []).join(', ') || '—';
      html += `<div class="tls-panel"><strong>Shodan InternetDB</strong><br>
        Open ports: ${escHtml(ports)}<br>Tags: ${escHtml(tags)}<br>CVEs: ${vulns}</div>`;
    } else if (si?.detail) {
      html += `<div class="breakdown-note">Shodan: ${escHtml(si.detail)}</div>`;
    }

    if (sh && !sh.error) {
      const org  = sh.org  || sh.isp || '—';
      const os   = sh.os   || '—';
      const country = sh.country_name || '—';
      html += `<div class="tls-panel"><strong>Shodan Full</strong><br>
        Org: ${escHtml(org)} · OS: ${escHtml(os)} · ${escHtml(country)}</div>`;
    } else if (sh?.error && !sh.error.includes('401')) {
      html += `<div class="breakdown-note">Shodan full: ${escHtml(sh.error)}</div>`;
    }

    if (ce && !ce.error) {
      const services = (ce.services || []).slice(0, 4).map(s => escHtml(`${s.port}/${s.transport_protocol || 'tcp'}`)).join(', ') || '—';
      html += `<div class="tls-panel"><strong>Censys</strong><br>
        Services: ${services}</div>`;
    }

    panel.innerHTML = html || '<div class="breakdown-note">No threat-intel data. Add Shodan/Censys API keys in Settings to unlock full results.</div>';
  });
}

// ── C4: Infrastructure tree / hierarchy view ──────────────────
function renderTree(result, domain) {
  if (!result) return;

  // ── 4-layer taxonomy ─────────────────────────────────────────
  // Order follows observed traffic flow: WAF/Bot → CDN/Delivery → Edge-hosting.
  // Within a layer, use Via-header chain order when available; otherwise
  // sort by confidence score so the strongest signal leads.
  const TAXONOMY = [
    {
      id: 'waf', label: 'WAF / Bot Protection', icon: '🛡', color: '#f0555a',
      ids: ['imperva','sucuri','datadome','perimeterx','f5xc'],
      tip: 'Filters malicious traffic before it reaches the CDN or origin',
      // Providers in this list are true "full CDN" services — having 2+ of
      // THESE together in the same layer is unusual (most sites use one
      // primary CDN), unlike WAF+CDN combos which are completely normal.
      competingFullServices: false,
    },
    {
      id: 'cdn', label: 'CDN / Global Delivery', icon: '🌐', color: '#1ed4ff',
      ids: ['cloudflare','google','akamai','fastly','cloudfront','azure',
            'bunnycdn','stackpath','keycdn','gcore','tencenteo','alicdn','arvancloud','vncdn'],
      tip: 'Caches and delivers content from edge PoPs near end-users',
      competingFullServices: true,
    },
    {
      id: 'hosting', label: 'Edge Hosting / Serverless', icon: '⚡', color: '#8b5cf6',
      ids: ['vercel','netlify','flyio','render','railway'],
      tip: 'Application hosting with built-in edge delivery; often the origin itself',
      competingFullServices: true,
    },
  ];

  const detectedMap = {};    // id -> score
  const breakdownMap = {};   // id -> breakdown array (for weak-signal check)
  for (const id of Object.keys(PROVIDER_UI)) {
    const pv = result.providers?.[id];
    if (pv?.verdict?.detected) { detectedMap[id] = pv.verdict.score; breakdownMap[id] = pv.breakdown || []; }
  }

  const chainOrder = result.layerChain?.chain || [];
  const sortByChain = ids => {
    const inChain  = ids.filter(id => chainOrder.includes(id))
      .sort((a,b) => chainOrder.indexOf(a) - chainOrder.indexOf(b));
    const notChain = ids.filter(id => !chainOrder.includes(id))
      .sort((a,b) => (detectedMap[b]||0) - (detectedMap[a]||0));
    return [...inChain, ...notChain];
  };

  // Track which provider IDs got "absorbed" into a chip (so sidebar items
  // that match one of them can merge instead of listing separately).
  const absorbedProviderIds = new Set();

  const chip = (id, layerColor) => {
    const ui      = PROVIDER_UI[id];
    const score   = detectedMap[id] ?? 0;
    const color   = ui?.color || layerColor;
    const inChain = chainOrder.includes(id);
    const weak    = (breakdownMap[id]?.length === 1);
    const weakBadge = weak ? `<span class="weak-signal-badge" title="Only 1 signal supports this — higher chance of false positive">⚠</span>` : '';
    absorbedProviderIds.add(id);
    return `<span class="tree-chip${inChain ? ' chain-confirmed' : ''}"
      style="border-color:${escHtml(color)};color:${escHtml(color)}"
      title="${escHtml(ui?.name || id)} — ${score}% confidence${inChain ? ' (confirmed by Via header)' : ''}${weak ? ' — WEAK: only 1 supporting signal' : ''}">
      ${escHtml(ui?.name || id)}${weakBadge} <span class="tree-chip-score">${score}%</span>
    </span>`;
  };

  const arrowDown  = `<div class="tree-arrow">↓</div>`;
  const clientNode = `<div class="tree-node tree-client">🌐 Visitor</div>`;

  let layersHtml = '', detectedCount = 0;
  const layerConflicts = []; // collects human-readable conflict notes
  for (const layer of TAXONOMY) {
    const presentIds = sortByChain(layer.ids.filter(id => detectedMap[id] !== undefined));
    if (!presentIds.length) continue;
    detectedCount += presentIds.length;

    // ── Conflict detection: 2+ competing full-service providers in one
    // layer is unusual and often means at least one is a false positive
    // (shared IP ranges, stale CNAME, or a genuine mid-migration state).
    // Flagged directly on the layer instead of silently listing both as
    // if they were equally certain.
    let conflictNote = '';
    if (layer.competingFullServices && presentIds.length > 1) {
      const names = presentIds.map(id => PROVIDER_UI[id]?.name || id);
      layerConflicts.push({ layer: layer.label, providers: names });
      conflictNote = `<div class="tree-layer-conflict">⚠ ${presentIds.length} providers competing for the same role — unusual for one site. Could be a mid-migration state, a shared-IP false positive, or a genuine multi-CDN setup. Check the weaker score's signal count before trusting it.</div>`;
    }

    layersHtml += `
      ${arrowDown}
      <div class="tree-layer" style="--layer-color:${layer.color}">
        <div class="tree-layer-label">${layer.icon} ${escHtml(layer.label)}</div>
        <div class="tree-chips">${presentIds.map(id => chip(id, layer.color)).join('')}</div>
        <div class="tree-layer-tip">${escHtml(layer.tip)}</div>
        ${conflictNote}
      </div>`;
  }

  const customDetected = Object.entries(result.customProviders || {}).filter(([,v]) => v.verdict?.detected);
  if (customDetected.length) {
    const chips = customDetected.map(([id, v]) =>
      `<span class="tree-chip" style="border-color:#94a3b8;color:#94a3b8">${escHtml(v.def?.name || id)} <span class="tree-chip-score">${v.verdict.score}%</span></span>`
    ).join('');
    layersHtml += `${arrowDown}<div class="tree-layer" style="--layer-color:#94a3b8"><div class="tree-layer-label">📦 Custom Providers</div><div class="tree-chips">${chips}</div></div>`;
  }

  // ── Sidebar — same-provider linking ─────────────────────────────
  // If the DNS provider (or another sidebar fact) names a company that's
  // ALSO one of the detected chips above, that's the same vendor doing
  // double duty (e.g. Cloudflare as both WAF and DNS). Instead of listing
  // "DNS: Cloudflare" as an unrelated fact next to a separate "Cloudflare"
  // chip, tag it onto the existing chip's tooltip and only show the
  // remaining, genuinely-separate context items in the sidebar.
  const nameToId = {};
  for (const id of Object.keys(PROVIDER_UI)) nameToId[PROVIDER_UI[id].name.toLowerCase()] = id;
  const matchesDetectedProvider = name => {
    const guess = Object.keys(nameToId).find(n => name?.toLowerCase().includes(n.split(' ')[0]));
    return guess ? nameToId[guess] : null;
  };

  const linkedNotes = []; // "Cloudflare also handles DNS" style notes shown under the matching chip's layer
  const sideItems = [];

  const dnsMatch = result.dnsProvider ? matchesDetectedProvider(result.dnsProvider) : null;
  if (result.dnsProvider && dnsMatch && absorbedProviderIds.has(dnsMatch)) {
    linkedNotes.push(`${PROVIDER_UI[dnsMatch].name} also manages DNS for this domain`);
  } else if (result.dnsProvider) {
    sideItems.push({ icon: '🔑', label: 'DNS', value: result.dnsProvider, color: '#2ecc71' });
  }

  if (result.spfDmarc?.spfProvider) sideItems.push({ icon: '✉', label: 'Email', value: result.spfDmarc.spfProvider, color: '#f5a623' });
  if (result.httpsRecord?.ech) sideItems.push({ icon: '🔒', label: 'ECH', value: 'Enabled', color: '#1ed4ff' });
  if (result.anycast?.diverges) sideItems.push({ icon: '🌍', label: 'Anycast', value: `${result.anycast.uniqueIps?.length || '?'} edges seen`, color: '#1ed4ff' });
  if (result.layerChain?.chain) sideItems.push({ icon: '📋', label: 'Layer order', value: 'Via header confirmed', color: '#8b5cf6' });
  if (result.anycast?.dnssecValidated) sideItems.push({ icon: '🔒', label: 'DNSSEC', value: 'Validated', color: '#2ecc71' });
  if (result.anycast?.ecsLeakSuspected) sideItems.push({ icon: '📡', label: 'ECS leak', value: 'Suspected', color: '#f0555a' });
  if (result.anycast?.fastestResolver) sideItems.push({ icon: '⚡', label: 'Fastest resolver', value: result.anycast.fastestResolver, color: '#94a3b8' });

  const linkedNotesHtml = linkedNotes.length
    ? `<div class="tree-linked-notes">${linkedNotes.map(n => `<div class="tree-linked-note">🔗 ${escHtml(n)}</div>`).join('')}</div>` : '';

  const sideBar = sideItems.length ? `
    <div class="tree-sidebar">
      <div class="tree-sidebar-title">Additional context</div>
      ${sideItems.map(s => `<div class="tree-side-item" style="border-left-color:${s.color}">
        <span class="tree-side-icon">${s.icon}</span>
        <span class="tree-side-label">${escHtml(s.label)}</span>
        <span class="tree-side-value" style="color:${s.color}">${escHtml(s.value)}</span>
      </div>`).join('')}
    </div>` : '';

  const originNode = `${arrowDown}<div class="tree-node tree-origin">🏠 Origin — ${escHtml(domain)}</div>`;

  const chainNote = (!result.layerChain?.chain && detectedCount > 1)
    ? `<div class="breakdown-note" style="text-align:center;margin-top:10px">Layer order is grouped by product type — Via header absent, so exact sequence within/between layers is unconfirmed.</div>` : '';

  const treeContent = !detectedCount
    ? '<div class="empty-state" style="padding:28px 0">No providers detected — nothing to visualize.</div>'
    : `<div class="tree-wrapper">
        <div class="tree-view">${clientNode}${layersHtml}${linkedNotesHtml}${originNode}</div>
        ${sideBar}
      </div>${chainNote}`;

  // ── All action buttons — grouped into one collapsible Tools section
  // instead of two dense rows dumped directly under the tree (which had
  // the exact same "chi chít" problem the Overview redesign fixed).
  const toolsBody = `
    <div class="tools-grid">
      <button id="distProbeBtn">🌍 Probe 12 locations</button>
      <button id="waybackBtn">🕰 Wayback history</button>
      <button id="fingerprintBtn">🔖 Fingerprint string</button>
      <button id="statusPageBtn">📡 Check status pages</button>
      <button id="dnsBlockBtn">🚧 Check DNS blocking</button>
      <button id="explainBtn">💬 Explain in plain words</button>
      <button id="explainBossBtn">📧 Explain for a report</button>
      <button id="quickCompareBtn">⇄ Quick compare</button>
    </div>
    <div id="distProbePanel"></div>
    <div id="round5Panel"></div>
    <div id="round7Panel"></div>`;

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">🌲 Infrastructure Stack</span>
    </div>
    <div class="checks-list" style="padding:12px 14px">
      ${treeContent}
      ${groupSection('tree-tools', '🛠 Analysis tools', 8, toolsBody, true)}
    </div>`;

  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached, resultsEl._diff);
  });
  resultsEl.querySelectorAll('.group-header').forEach(h => {
    h.addEventListener('click', () => {
      const body = h.nextElementSibling;
      const collapsed = body.classList.toggle('collapsed');
      h.querySelector('.group-chevron').textContent = collapsed ? '▸' : '▾';
    });
  });
  document.getElementById('distProbeBtn').addEventListener('click', () =>
    renderDistributedProbe(domain, document.getElementById('distProbePanel'))
  );
  document.getElementById('waybackBtn').addEventListener('click', () => renderWayback(domain));
  document.getElementById('fingerprintBtn').addEventListener('click', () => renderFingerprint(result));
  document.getElementById('statusPageBtn').addEventListener('click', () => renderStatusCheck(result));
  document.getElementById('dnsBlockBtn').addEventListener('click', () => renderDnsBlockCheck(domain));
  document.getElementById('explainBtn').addEventListener('click', () => renderExplainPlain(result, domain));
  document.getElementById('explainBossBtn').addEventListener('click', () => renderExplainForReport(result, domain));
  document.getElementById('quickCompareBtn').addEventListener('click', () => renderQuickCompare(domain));
}

// ── Explain in plain words — turns breakdown/signals into a sentence ──
function renderExplainPlain(result, domain) {
  const panel = document.getElementById('round7Panel');
  if (!panel) return;
  const detected = Object.entries(result.providers || {}).filter(([, v]) => v.verdict?.detected);
  if (!detected.length) {
    panel.innerHTML = `<div class="tls-panel">No providers were detected for ${escHtml(domain)}, so there's nothing to explain yet.</div>`;
    return;
  }
  const sentences = detected.map(([id, pv]) => {
    const name = PROVIDER_UI[id]?.name || id;
    const breakdown = pv.breakdown || [];
    if (!breakdown.length) return `<strong>${escHtml(name)}</strong> was detected (${pv.verdict.score}% confidence), but the exact signals that triggered it weren't itemized.`;
    const signalNames = breakdown.slice(0, 4).map(b => {
      // Reuse the same label lookup pattern as the detail view
      for (const ui of [PROVIDER_UI[id]]) {
        for (const g of (ui?.groups || [])) {
          const found = g.signals.find(s => s.key === b.signal);
          if (found) return found.label;
        }
      }
      return b.signal;
    });
    const n = breakdown.length;
    return `<strong>${escHtml(name)}</strong> was detected via ${signalNames.map(escHtml).join(', ')}${n > signalNames.length ? ` and ${n - signalNames.length} more signal${n - signalNames.length > 1 ? 's' : ''}` : ''} (${n} signal${n > 1 ? 's' : ''} total, ${pv.verdict.score}% confidence).`;
  });
  panel.innerHTML = `<div class="tls-panel">${sentences.join('<br><br>')}</div>`;
}

// ── #4: Explain for a report — non-technical summary to paste elsewhere ──
function renderExplainForReport(result, domain) {
  const panel = document.getElementById('round7Panel');
  if (!panel) return;
  const detected = Object.entries(result.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => PROVIDER_UI[id]?.name || id);
  const wafNames = ['Imperva', 'Sucuri', 'DataDome', 'PerimeterX', 'F5 Distributed Cloud'];
  const cdnNames = detected.filter(n => !wafNames.includes(n));
  const wafDetected = detected.filter(n => wafNames.includes(n));

  let text;
  if (!detected.length) {
    text = `${domain} does not appear to use a recognizable third-party CDN or WAF service — it may be served directly from its own infrastructure, or use a provider not yet covered by this tool.`;
  } else {
    const parts = [];
    if (cdnNames.length) parts.push(`${cdnNames.join(' and ')} for content delivery`);
    if (wafDetected.length) parts.push(`${wafDetected.join(' and ')} for security/bot protection`);
    text = `${domain} uses ${parts.join(', with ')}. `;
    if (detected.length > 1) text += `Multiple providers working together is a normal setup for larger sites. `;
    if (result.anycast?.dnssecValidated) text += `DNS is protected with DNSSEC. `;
    text += `No further action is needed unless you're specifically investigating a migration or an incident.`;
  }
  panel.innerHTML = `
    <div class="tls-panel">${escHtml(text)}</div>
    <button class="link-btn" id="copyExplainBtn" style="margin-top:8px">⧉ Copy this text</button>`;
  document.getElementById('copyExplainBtn').addEventListener('click', () => {
    navigator.clipboard.writeText(text).catch(() => {});
    const btn = document.getElementById('copyExplainBtn');
    if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { if (btn) btn.textContent = '⧉ Copy this text'; }, 2000); }
  });
}

// ── Quick compare — inline, without leaving the popup ──────────
function renderQuickCompare(domainA) {
  const panel = document.getElementById('round7Panel');
  if (!panel) return;
  panel.innerHTML = `
    <div class="tls-panel">
      <strong>Quick compare: ${escHtml(domainA)} vs…</strong>
      <input type="text" id="quickCompareInput" class="settings-input" placeholder="other-domain.com" style="margin-top:8px">
      <button class="link-btn" id="quickCompareRunBtn" style="margin-top:8px">Scan & compare</button>
      <div id="quickCompareResult"></div>
    </div>`;
  document.getElementById('quickCompareRunBtn').addEventListener('click', () => {
    const domainB = document.getElementById('quickCompareInput').value.trim().toLowerCase();
    if (!domainB) return;
    const resultEl = document.getElementById('quickCompareResult');
    resultEl.innerHTML = '<div class="empty-state">Scanning…</div>';
    const port = chrome.runtime.connect({ name: 'scan' });
    port.onMessage.addListener(msg => {
      if (msg.type === 'result') {
        port.disconnect();
        const detA = new Set(Object.entries(resultsEl._scan?.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => id));
        const detB = new Set(Object.entries(msg.data.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => id));
        const shared = [...detA].filter(id => detB.has(id));
        const onlyA  = [...detA].filter(id => !detB.has(id));
        const onlyB  = [...detB].filter(id => !detA.has(id));
        const nameOf = id => PROVIDER_UI[id]?.name || id;
        resultEl.innerHTML = `
          <div class="breakdown-note">Shared: ${shared.length ? shared.map(nameOf).join(', ') : '—'}</div>
          <div class="breakdown-note">Only ${escHtml(domainA)}: ${onlyA.length ? onlyA.map(nameOf).join(', ') : '—'}</div>
          <div class="breakdown-note">Only ${escHtml(domainB)}: ${onlyB.length ? onlyB.map(nameOf).join(', ') : '—'}</div>`;
      } else if (msg.type === 'error') {
        port.disconnect();
        resultEl.innerHTML = `<div class="breakdown-note">Failed: ${escHtml(msg.message)}</div>`;
      }
    });
    port.postMessage({ action: 'scan', domain: domainB, forceRefresh: false });
  });
}

// ── #1: DNS-blocking/censorship diagnostic panel ────────────────
// Reports whether a policy-filtering DNS resolver behaves differently from
// a neutral one for this domain. Purely diagnostic — never attempts to
// route around or bypass anything it finds.
function renderDnsBlockCheck(domain) {
  const panel = document.getElementById('round5Panel');
  if (!panel) return;
  panel.innerHTML = '<div class="empty-state">Comparing a neutral resolver against a policy-filtering resolver…</div>';
  chrome.runtime.sendMessage({ action: 'checkDnsBlocking', domain }, res => {
    if (!panel.isConnected) return;
    if (!res?.checked) {
      panel.innerHTML = `<div class="breakdown-note">Could not complete check: ${escHtml(res?.reason || 'unknown error')}</div>`;
      return;
    }
    const confidenceLabel = res.confidence === 'medium-high' ? 'Medium-high confidence'
      : res.confidence === 'low-medium' ? 'Low-medium confidence — this IP list can go stale' : '';
    const banner = res.blocked
      ? `<div class="diff-banner changed">🚧 Possible DNS-policy block detected${confidenceLabel ? ` (${confidenceLabel})` : ''}</div>`
      : `<div class="diff-banner unchanged">✓ No DNS-policy blocking detected</div>`;
    const cacheNote = res.fromCache ? '<div class="breakdown-note" style="margin-top:4px">Cached result (rechecked automatically every 10 min).</div>' : '';
    panel.innerHTML = `
      ${banner}
      <div class="tls-panel">${escHtml(res.detail)}</div>
      ${cacheNote}
      <div class="breakdown-note" style="margin-top:6px">This compares Cloudflare's DNS (no content policy) against OpenDNS FamilyShield (blocks by policy). A difference here reflects DNS-layer blocking only — it says nothing about IP-level or DPI-based blocking, which this check cannot see. A "no answer at all" mismatch is more reliable than an IP-match, since block-page IPs can change over time.</div>`;
  });
}

// ── CDN status-page correlation ─────────────────────────────
function renderStatusCheck(result) {
  const panel = document.getElementById('round5Panel');
  if (!panel) return;
  const detected = Object.entries(result.providers || {})
    .filter(([, v]) => v.verdict?.detected).map(([id]) => id);
  const checkable = detected.filter(id => ['cloudflare','fastly','akamai','vercel','netlify','google'].includes(id));
  if (!checkable.length) { panel.innerHTML = '<div class="breakdown-note">No detected providers have a known public status page.</div>'; return; }
  panel.innerHTML = '<div class="empty-state">Checking provider status pages…</div>';
  Promise.all(checkable.map(id => new Promise(resolve =>
    chrome.runtime.sendMessage({ action: 'checkProviderStatus', providerId: id }, r => resolve({ id, status: r?.status }))
  ))).then(results => {
    if (!panel.isConnected) return;
    const rows = results.map(({ id, status }) => {
      const name = PROVIDER_UI[id]?.name || id;
      if (!status) return `<div class="tls-panel">${escHtml(name)}: <span class="breakdown-note" style="display:inline">status page unavailable</span></div>`;
      const indicatorColor = status.indicator === 'none' ? 'var(--green)' : status.indicator === 'incident' ? 'var(--red)' : 'var(--amber)';
      return `<div class="tls-panel"><strong style="color:${indicatorColor}">${escHtml(name)}</strong> — ${escHtml(status.description || status.indicator)}</div>`;
    }).join('');
    panel.innerHTML = `<div class="breakdown-note" style="margin-bottom:6px">Useful for telling apart "provider actually changed" vs "provider is just having an outage" in watchlist diffs.</div>${rows}`;
  });
}

// ── #10: Shareable infrastructure fingerprint string ────────────
function renderFingerprint(result) {
  const panel = document.getElementById('round5Panel');
  if (!panel) return;
  chrome.runtime.sendMessage({ action: 'buildFingerprint', result }, res => {
    if (!panel.isConnected) return;
    if (!res?.fingerprint) { panel.innerHTML = '<div class="breakdown-note">Could not build fingerprint.</div>'; return; }
    panel.innerHTML = `
      <div class="tls-panel">
        <strong>Infrastructure fingerprint</strong>
        <div style="font-family:var(--mono);font-size:12px;margin-top:6px;word-break:break-all;color:var(--accent)">${escHtml(res.fingerprint)}</div>
        <button class="link-btn" id="copyFingerprintBtn" style="margin-top:8px">⧉ Copy</button>
        <div class="breakdown-note" style="margin-top:6px">Compact summary of detected providers, DNS provider, ECH/anycast flags, and layer count — paste this to compare with another scan at a glance. Not a security hash.</div>
      </div>`;
    document.getElementById('copyFingerprintBtn').addEventListener('click', () => {
      navigator.clipboard.writeText(res.fingerprint).catch(() => {});
      const btn = document.getElementById('copyFingerprintBtn');
      if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { if (btn) btn.textContent = '⧉ Copy'; }, 2000); }
    });
  });
}

// ── #11: Wayback Machine historical cross-check ─────────────────
function renderWayback(domain) {
  const panel = document.getElementById('round5Panel');
  if (!panel) return;
  panel.innerHTML = '<div class="empty-state">Querying Wayback Machine CDX API…</div>';
  chrome.runtime.sendMessage({ action: 'queryWaybackHistory', domain }, res => {
    if (!panel.isConnected) return;
    const data = res?.data;
    if (!data) { panel.innerHTML = '<div class="breakdown-note">No Wayback Machine snapshots found for this domain.</div>'; return; }
    panel.innerHTML = `
      <div class="tls-panel">
        <strong>Archive history</strong><br>
        First snapshot: <strong>${escHtml(data.earliestYear)}</strong> (${escHtml(data.firstSnapshot)})<br>
        <a href="https://web.archive.org/web/${escHtml(data.firstSnapshot)}/${escHtml(domain)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:10.5px">View earliest archived snapshot ↗</a>
        <div class="breakdown-note" style="margin-top:6px">Extends historical context beyond this extension's own local scan history (which only goes back to when you started scanning).</div>
      </div>`;
  });
}

// ── Distributed probing UI (check-host.net) ───────────────────
function renderDistributedProbe(domain, panelEl) {
  if (!panelEl) return;
  panelEl.innerHTML = '<div class="empty-state">Probing from up to 12 global locations… (~10-15s, be patient)</div>';
  chrome.runtime.sendMessage({ action: 'probeDistributed', domain }, res => {
    if (!panelEl.isConnected) return; // user navigated away
    if (res?.error) {
      panelEl.innerHTML = `<div class="breakdown-note">Probe failed: ${escHtml(res.error)}</div>
        <div class="breakdown-note" style="margin-top:4px">This uses the free check-host.net public API. If this keeps failing, their service may be temporarily rate-limiting or blocking this host.</div>`;
      return;
    }
    if (!res.nodeResults?.length) {
      panelEl.innerHTML = '<div class="breakdown-note">No nodes responded. Try again in a moment.</div>';
      return;
    }
    const rows = res.nodeResults.map(n => {
      const statusClass = n.status === 'ok' ? 'st-done' : n.status === 'fail' ? 'st-error' : 'st-pending';
      return `<tr>
        <td>${escHtml(n.country || '?')}${n.city ? ` · ${escHtml(n.city)}` : ''}</td>
        <td class="${statusClass}">${n.status}</td>
        <td>${n.httpCode ?? '—'}</td>
        <td>${n.latencyMs != null ? n.latencyMs + 'ms' : '—'}</td>
        <td style="font-size:9.5px;color:var(--text-faint)">${escHtml(n.asn || '—')}</td>
      </tr>`;
    }).join('');

    panelEl.innerHTML = `
      <div class="breakdown-note" style="margin-bottom:6px">${res.okNodes}/${res.totalNodes} nodes reached the domain successfully. This shows reachability + latency from real global vantage points — it does not read response headers or confirm anycast (that's what the Anycast check above already does via DNS).</div>
      <table class="batch-table" style="margin-top:4px;font-size:10.5px">
        <thead><tr><th>Location</th><th>Status</th><th>HTTP</th><th>Latency</th><th>Probe node ASN</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="breakdown-note" style="margin-top:6px">Data via <a href="https://check-host.net" target="_blank" rel="noopener" style="color:var(--accent)">check-host.net</a> public API.</div>
      <div class="breakdown-note" style="margin-top:6px">Data via check-host.net public API — ${res.okNodes}/${res.totalNodes} nodes responded.</div>`;
  });
}

