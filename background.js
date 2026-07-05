// ============================================================
// Multi-CDN/WAF Detector — background.js  v8.1
// 2026 update: resilient multi-provider DoH fallback, NS lookup,
// stricter signal scoring, common-header expansion, shared ALPN probe
//
// CROSS-BROWSER NOTE (Chrome / Edge / Opera / Firefox, all MV3):
// - Uses `self` (not `window`) for shared globals — valid in both the
//   Chromium service-worker context and Firefox's background-page fallback.
// - Uses `chrome.*` namespace — Firefox aliases `chrome` to `browser`
//   automatically, and every API called here (storage, cookies, runtime)
//   is Promise-compatible on both, so no callback/Promise branching needed.
// - `importScripts()` works identically in a Chromium service worker and
//   in Firefox's non-module background script (manifest's "scripts" key).
// - No localStorage/sessionStorage/DOMParser — unavailable in service
//   workers and intentionally avoided so the same file runs unmodified
//   under either background mode declared in manifest.json.
// ============================================================

importScripts(
  'cloudflare.js',
  'google.js',
  'akamai.js',
  'fastly.js',
  'imperva.js',
  'cloudfront.js',
  'azure.js',
  'sucuri.js',
  'vercel.js',
  'netlify.js',
  'bunnycdn.js',
  'stackpath.js',
  'keycdn.js',
  'gcore.js',
  'datadome.js',
  'perimeterx.js',
  'f5distributed.js',
  'tencenteo.js',
  'alicdn.js',
  'arvancloud.js',
  'vncdn.js',
  'flyio.js',
  'render.js',
  'railway.js'
);

// ── Constants ─────────────────────────────────────────────────
const WEEK_MS          = 7 * 24 * 60 * 60 * 1000;
const CACHE_TTL_MS     = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;
const PROBE_TIMEOUT_MS = 6000;
const DOH_TIMEOUT_MS   = 6000;
const PROBE_CONCURRENCY = 6;

// Bump this whenever scoring/signal logic changes meaningfully, so existing
// cache entries (which may reflect outdated logic) are invalidated automatically.
const ENGINE_VERSION = 2;

// rangesReady is a Promise that resolves once IP-range lists have been loaded
// from cache (or fetched fresh). It is assigned once loadCachedRanges() is
// defined further below. performScan() always awaits it so IP-signal scoring
// never runs before the ranges are available, even on a cold service-worker
// wake-up where the assignment happens before any scan can be triggered.
let rangesReady;   // assigned at module init after loadCachedRanges() is defined

// A lightweight hash of the active provider set + engine version. Cache
// entries are keyed against this so that loading new/updated provider
// files (different probe count, different ids) naturally busts stale cache
// instead of silently returning results scored under old rules.
function computeRulesHash() {
  const providers = self.CDN_PROVIDERS || [];
  const sig = providers
    .map(p => `${p.id}:${(p.probes || []).length}:${(p.cnamePatterns || []).length}`)
    .sort()
    .join('|');
  let h = 0;
  const full = `${ENGINE_VERSION}|${sig}`;
  for (let i = 0; i < full.length; i++) h = (h * 31 + full.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

// Multi-provider DoH fallback — if Cloudflare DoH fails, try Google, then NextDNS
// All are RFC 8484 compliant. We try in order and use the first success.
const DOH_PROVIDERS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
  'https://dns.nextdns.io/dns-query'
];

// ── CIDR matching ─────────────────────────────────────────────
function ip4Int(ip) {
  return ip.split('.').reduce((a, o) => (a * 256 + parseInt(o, 10)) >>> 0, 0);
}
function inCIDR4(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const mask = (0xffffffff << (32 - +bits)) >>> 0;
  return (ip4Int(ip) & mask) === (ip4Int(base) & mask);
}

// Full IPv6 -> 128-bit BigInt, expanding "::" correctly regardless of
// where it occurs (start/middle/end) and how many groups it elides.
function ip6ToBigInt(ip) {
  const clean = ip.split('%')[0]; // strip zone index if present
  let head = [], tail = [];
  if (clean.includes('::')) {
    const [h, t] = clean.split('::');
    head = h ? h.split(':') : [];
    tail = t ? t.split(':') : [];
  } else {
    head = clean.split(':');
  }
  const missing = 8 - head.length - tail.length;
  const groups = [...head, ...Array(Math.max(missing, 0)).fill('0'), ...tail];
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(parseInt(g || '0', 16));
  return n;
}
function inCIDR6(ip, cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = +bitsStr;
  const ipN   = ip6ToBigInt(ip);
  const baseN = ip6ToBigInt(base);
  const mask  = bits === 0 ? 0n : (((1n << 128n) - 1n) << BigInt(128 - bits)) & ((1n << 128n) - 1n);
  return (ipN & mask) === (baseN & mask);
}
function ipMatches(ip, v4, v6) {
  if (!ip) return false;
  try {
    if (ip.includes(':')) return (v6 || []).some(c => inCIDR6(ip, c));
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return (v4 || []).some(c => inCIDR4(ip, c));
  } catch { /* malformed IP/CIDR — treat as no match */ }
  return false;
}

// ── Timeout fetch ─────────────────────────────────────────────
async function fetchT(url, opts = {}, ms = FETCH_TIMEOUT_MS) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

// ── DoH query with multi-provider fallback ───────────────────
// Returns parsed JSON or null. Tries each provider in order.
async function doh(domain, type) {
  for (const provider of DOH_PROVIDERS) {
    try {
      const res = await fetchT(
        `${provider}?name=${encodeURIComponent(domain)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' }, cache: 'no-store' },
        DOH_TIMEOUT_MS
      );
      if (res.ok) {
        const json = await res.json();
        // Validate we got a real DNS response structure
        if (json && typeof json.Status === 'number') return json;
      }
    } catch { /* try next provider */ }
  }
  return null;
}

// ── Unified DNS lookup: A, AAAA, CNAME, MX, NS, TXT ─────────
// Returns { ips, cname, mxRecords, nsRecords, txtRecords, minTTL }
// NS is used for vanity-NS CDN detection (Cloudflare, Azure, etc.)
// TXT is used for verification tokens (Google, Azure, etc.)
async function doHLookup(domain) {
  const ips    = [];
  let   cname  = null;
  const mx     = [];
  const ns     = [];
  const txt    = [];
  let   minTTL = Infinity;

  await Promise.allSettled([
    doh(domain, 'A').then(d => {
      for (const r of (d?.Answer || [])) {
        if (r.type === 1) {
          const ip = r.data.trim();
          if (!ips.includes(ip)) ips.push(ip);
          if (r.TTL < minTTL) minTTL = r.TTL;
        }
        // A query also returns CNAMEs in Answer section
        if (r.type === 5 && !cname) cname = r.data.toLowerCase().replace(/\.$/, '');
      }
    }),
    doh(domain, 'AAAA').then(d => {
      for (const r of (d?.Answer || [])) {
        if (r.type === 28) {
          const ip = r.data.trim().toLowerCase();
          if (!ips.includes(ip)) ips.push(ip);
          if (r.TTL < minTTL) minTTL = r.TTL;
        }
        if (r.type === 5 && !cname) cname = r.data.toLowerCase().replace(/\.$/, '');
      }
    }),
    doh(domain, 'CNAME').then(d => {
      // Explicit CNAME query — overrides any cname found above if both present
      const rec = (d?.Answer || []).find(r => r.type === 5);
      if (rec) cname = rec.data.toLowerCase().replace(/\.$/, '');
    }),
    doh(domain, 'MX').then(d => {
      for (const r of (d?.Answer || []))
        if (r.type === 15) {
          const host = (r.data.trim().split(/\s+/)[1] || '').toLowerCase().replace(/\.$/, '');
          if (host && !mx.includes(host)) mx.push(host);
        }
    }),
    doh(domain, 'NS').then(d => {
      for (const r of (d?.Answer || []))
        if (r.type === 2) {
          const host = r.data.trim().toLowerCase().replace(/\.$/, '');
          if (host && !ns.includes(host)) ns.push(host);
        }
    }),
    doh(domain, 'TXT').then(d => {
      for (const r of (d?.Answer || []))
        if (r.type === 16) txt.push((r.data || '').replace(/^"|"$/g, '').toLowerCase());
    }),
  ]);

  return {
    ips,
    cname,
    mxRecords:  mx,
    nsRecords:  ns,
    txtRecords: txt,
    minTTL: minTTL === Infinity ? null : minTTL
  };
}

// ── NS pattern matching (providers that use vanity NS) ────────
const NS_PATTERNS = [
  { re: /\.ns\.cloudflare\.com$/, signal: 'cfCname',     pid: 'cloudflare' },
  { re: /\.cloudflare\.com$/,     signal: 'cfCname',     pid: 'cloudflare' },
  { re: /akam\.net$/,             signal: 'akamaiCname', pid: 'akamai'     },
  { re: /akamaiedge\.net$/,       signal: 'akamaiCname', pid: 'akamai'     },
  { re: /awsdns-/,                signal: 'cloudfrontIP',pid: 'cloudfront'  }, // Route 53 NS → likely CloudFront
  { re: /azure-dns\./,            signal: 'azureCname',  pid: 'azure'       },
];

// ── IP / domain input detection ───────────────────────────────
function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) &&
    s.split('.').every(o => +o >= 0 && +o <= 255);
}
function isIPv6(s) {
  return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
}
function isIPLiteral(s) {
  return isIPv4(s) || isIPv6(s);
}

// ── Reverse DNS (PTR) via DoH ─────────────────────────────────
function ipToPtrName(ip) {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  if (isIPv6(ip)) {
    // Expand to full 8-group form, then nibble-reverse for ip6.arpa
    const parts = ip.split('::');
    let groups;
    if (parts.length === 2) {
      const head = parts[0] ? parts[0].split(':') : [];
      const tail = parts[1] ? parts[1].split(':') : [];
      const fill = Array(8 - head.length - tail.length).fill('0');
      groups = [...head, ...fill, ...tail];
    } else {
      groups = ip.split(':');
    }
    const nibbles = groups.map(g => g.padStart(4, '0')).join('').split('').reverse();
    return nibbles.join('.') + '.ip6.arpa';
  }
  return null;
}

async function reversePtr(ip) {
  const name = ipToPtrName(ip);
  if (!name) return null;
  try {
    const d = await doh(name, 'PTR');
    const rec = (d?.Answer || []).find(r => r.type === 12);
    return rec ? rec.data.toLowerCase().replace(/\.$/, '') : null;
  } catch { return null; }
}

// ── RDAP (ASN / org) lookup — replaces legacy whois, no API key needed ─
// Uses the IANA RDAP bootstrap redirector which is publicly accessible.
async function rdapLookup(ip) {
  try {
    const res = await fetchT(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json' }
    }, 7000);
    if (!res.ok) return null;
    const j = await res.json();
    const org = (j.entities || [])
      .flatMap(e => e.vcardArray?.[1] || [])
      .find(v => v[0] === 'fn')?.[3] || j.name || null;
    const asnHandle = j.handle || null;
    const cidr = Array.isArray(j.cidr0_cidrs) && j.cidr0_cidrs[0]
      ? `${j.cidr0_cidrs[0].v4prefix || j.cidr0_cidrs[0].v6prefix}/${j.cidr0_cidrs[0].length}`
      : null;
    return { org, asnHandle, cidr, country: j.country || null };
  } catch { return null; }
}

// ── Cross-verification: for each resolved IP, gather PTR + RDAP evidence
// and check it against provider CNAME/NS hints already collected in allSig.
// This produces independent corroboration that isn't based on header spoofing.
async function buildIpEvidence(ips, providers) {
  const evidence = {};
  await runPooled(ips, PROBE_CONCURRENCY, async ip => {
    const [ptr, rdap] = await Promise.all([reversePtr(ip), rdapLookup(ip)]);
    const matchedProviders = [];
    if (ptr) {
      for (const p of providers) {
        for (const { re, signal, pid } of (p.ptrPatterns || [])) {
          if (re.test(ptr)) matchedProviders.push(pid || p.id);
        }
      }
      // Also reuse NS_PATTERNS-style org/ptr hints embedded per-provider via cnamePatterns
      // when the PTR hostname itself looks like a CDN edge node.
      for (const p of providers) {
        for (const { re, signal } of (p.cnamePatterns || [])) {
          if (re.test(ptr)) matchedProviders.push(p.id);
        }
      }
    }
    if (rdap?.org) {
      const orgLower = rdap.org.toLowerCase();
      for (const p of providers) {
        if ((p.orgNames || []).some(n => orgLower.includes(n))) matchedProviders.push(p.id);
      }
    }
    evidence[ip] = {
      ptr,
      org: rdap?.org || null,
      asnHandle: rdap?.asnHandle || null,
      cidr: rdap?.cidr || null,
      country: rdap?.country || null,
      matchedProviders: [...new Set(matchedProviders)]
    };
  });
  return evidence;
}


function parseIPList(p, text, family) {
  if (p.ipConfig?.parseResponse) return p.ipConfig.parseResponse(text, family);
  return text.trim().split('\n').map(l => l.trim()).filter(Boolean);
}

async function refreshAllIPRanges() {
  const providers = self.CDN_PROVIDERS || [];
  await Promise.allSettled(providers.filter(p => p.ipConfig?.v4Url).map(async p => {
    try {
      const ic = p.ipConfig;
      const r4 = await fetchT(ic.v4Url, {}, 10000);
      if (!r4.ok) return;
      const txt4 = await r4.text();
      const p4   = parseIPList(p, txt4, 'v4');
      if (p4.length) ic.v4 = p4;

      if (ic.singleFile) {
        const p6 = parseIPList(p, txt4, 'v6');
        if (p6.length) ic.v6 = p6;
      } else if (ic.v6Url) {
        const r6 = await fetchT(ic.v6Url, {}, 10000);
        if (r6.ok) {
          const p6 = parseIPList(p, await r6.text(), 'v6');
          if (p6.length) ic.v6 = p6;
        }
      }

      if (ic.storageKey)
        await chrome.storage.local.set({ [ic.storageKey]: { v4: ic.v4, v6: ic.v6 } });
    } catch {}
  }));
}

async function loadCachedRanges() {
  const providers = self.CDN_PROVIDERS || [];
  const keys = providers.filter(p => p.ipConfig?.storageKey).map(p => p.ipConfig.storageKey);
  if (!keys.length) return;

  const stored = await chrome.storage.local.get(['ip_refresh_ts', ...keys]);
  for (const p of providers) {
    const cache = p.ipConfig?.storageKey && stored[p.ipConfig.storageKey];
    if (cache?.v4) p.ipConfig.v4 = cache.v4;
    if (cache?.v6) p.ipConfig.v6 = cache.v6;
  }

  const lastTs = stored.ip_refresh_ts || 0;
  if (Date.now() - lastTs > WEEK_MS) {
    refreshAllIPRanges()
      .then(() => chrome.storage.local.set({ ip_refresh_ts: Date.now() }))
      .catch(() => {});
  }
}

// ── Scan result cache ─────────────────────────────────────────
function cacheKey(domain) {
  return `scan_${domain}_${computeRulesHash()}`;
}
async function getCached(domain) {
  try {
    const key = cacheKey(domain);
    const d = await chrome.storage.local.get(key);
    const e = d[key];
    if (e && Date.now() - e.ts < CACHE_TTL_MS) return e.result;
  } catch {}
  return null;
}

async function setCached(domain, result) {
  try {
    await chrome.storage.local.set({ [cacheKey(domain)]: { ts: Date.now(), result } });
  } catch {}
}

// ── Scan history (separate from the short-lived cache; kept until user clears it) ─
const HISTORY_KEY      = 'scan_history';
const HISTORY_MAX_ITEMS = 50;

async function addToHistory(domain, result) {
  try {
    const detected = Object.entries(result.providers || {})
      .filter(([, v]) => v.verdict?.detected)
      .map(([id]) => id);
    const entry = {
      domain,
      ts: Date.now(),
      detected,
      ipCount: (result.resolvedIPs || []).length,
      isDirectIP: !!result.isDirectIP
    };
    const { [HISTORY_KEY]: existing = [] } = await chrome.storage.local.get(HISTORY_KEY);
    // Remove any prior entry for the same domain, then prepend the fresh one
    const next = [entry, ...existing.filter(e => e.domain !== domain)].slice(0, HISTORY_MAX_ITEMS);
    await chrome.storage.local.set({ [HISTORY_KEY]: next });
  } catch {}
}

async function getHistory() {
  try {
    const { [HISTORY_KEY]: list = [] } = await chrome.storage.local.get(HISTORY_KEY);
    return list;
  } catch { return []; }
}

async function clearHistory() {
  try { await chrome.storage.local.remove(HISTORY_KEY); } catch {}
}

// ── A4: Diff against the most recent prior scan of the same domain ─
// Must be called BEFORE addToHistory() overwrites the entry for `domain`.
async function diffAgainstHistory(domain, result) {
  try {
    const list = await getHistory();
    const prior = list.find(e => e.domain === domain);
    if (!prior) return null; // first time we've ever scanned this domain
    const nowDetected = Object.entries(result.providers || {})
      .filter(([, v]) => v.verdict?.detected)
      .map(([id]) => id);
    const before = new Set(prior.detected || []);
    const after  = new Set(nowDetected);
    const added   = nowDetected.filter(id => !before.has(id));
    const removed = (prior.detected || []).filter(id => !after.has(id));
    if (!added.length && !removed.length) return { changed: false, priorTs: prior.ts };
    return { changed: true, priorTs: prior.ts, added, removed };
  } catch { return null; }
}

// ── C3: Pinned/bookmarked domains (manual, distinct from auto history) ─
const PINS_KEY = 'pinned_domains';
async function getPins() {
  try { const { [PINS_KEY]: list = [] } = await chrome.storage.local.get(PINS_KEY); return list; }
  catch { return []; }
}
async function togglePin(domain) {
  try {
    const list = await getPins();
    const idx = list.indexOf(domain);
    if (idx >= 0) list.splice(idx, 1); else list.unshift(domain);
    await chrome.storage.local.set({ [PINS_KEY]: list.slice(0, 200) });
    return list;
  } catch { return []; }
}

// ── A4 (improvement): Watchlist — auto re-scan + notify on change ──
// Distinct from pins: pinning is "quick access", watching adds a scheduled
// background re-scan via chrome.alarms and a chrome.notifications alert
// when the detected provider set changes between checks.
const WATCHLIST_KEY = 'watchlist_domains';
const WATCHLIST_ALARM = 'cdnwaf-watchlist-check';
const WATCHLIST_DEFAULT_INTERVAL_MIN = 360; // 6h — gentle default, configurable in Settings

async function getWatchlist() {
  try { const { [WATCHLIST_KEY]: list = [] } = await chrome.storage.local.get(WATCHLIST_KEY); return list; }
  catch { return []; }
}
async function toggleWatch(domain) {
  try {
    const list = await getWatchlist();
    const idx = list.indexOf(domain);
    if (idx >= 0) list.splice(idx, 1); else list.unshift(domain);
    await chrome.storage.local.set({ [WATCHLIST_KEY]: list.slice(0, 100) });
    return list;
  } catch { return []; }
}
async function ensureWatchlistAlarm() {
  const settings = await getSettings();
  const minutes = Math.max(60, settings.watchlistIntervalMin || WATCHLIST_DEFAULT_INTERVAL_MIN);
  try {
    chrome.alarms.create(WATCHLIST_ALARM, { periodInMinutes: minutes });
  } catch {}
}
async function runWatchlistCheck() {
  const domains = await getWatchlist();
  for (const domain of domains) {
    try {
      const result = await performScan(domain, () => {});
      const diff = await diffAgainstHistory(domain, result);
      await setCached(domain, result);
      await addToHistory(domain, result);
      if (diff?.changed) {
        const addedNames = (diff.added || []).join(', ');
        const removedNames = (diff.removed || []).join(', ');
        const bits = [addedNames && `+${addedNames}`, removedNames && `−${removedNames}`].filter(Boolean).join(' · ');
        try {
          chrome.notifications.create(`watch-${domain}-${Date.now()}`, {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: `CDN/WAF changed: ${domain}`,
            message: bits || 'Detected provider set changed.',
          });
        } catch {}
      }
    } catch { /* one failed domain shouldn't stop the rest of the watchlist */ }
  }
}

// ── A3: Confidence decay — best-effort "last reviewed" map per provider,
// derived from in-source dated comments at the time this build was authored.
// This is NOT automatic; bump an entry's value when you next verify/update
// that provider file so the staleness warning stays meaningful.
const PROVIDER_LAST_REVIEWED = {
  cloudflare: '2026-01', google: '2026-01', akamai: '2026-01', fastly: '2026-01',
  imperva: '2026-01', cloudfront: '2026-01', azure: '2026-01', sucuri: '2026-01',
  vercel: '2026-01', netlify: '2026-01', bunnycdn: '2026-01', stackpath: '2026-01',
  keycdn: '2026-01', gcore: '2026-01', tencenteo: '2025-06', alicdn: '2025-06',
  // No dated "2026 updates" comment block found in source for these three —
  // treated as last touched earlier, so they decay sooner.
  datadome: '2025-06', perimeterx: '2025-06', f5xc: '2025-06',
  arvancloud: '2025-06',
  // Explicitly marked in-source as an unverified/heuristic header spec —
  // always shown as lower-confidence regardless of decay.
  vncdn: '2025-01',
};
const STALE_AFTER_MONTHS = 6;
function monthsSince(yyyyMm) {
  const [y, m] = yyyyMm.split('-').map(Number);
  const now = new Date();
  return (now.getFullYear() - y) * 12 + (now.getMonth() + 1 - m);
}
function decayInfoFor(pid) {
  const reviewed = PROVIDER_LAST_REVIEWED[pid];
  if (!reviewed) return { lastReviewed: null, stale: false, monthsAgo: null };
  const months = monthsSince(reviewed);
  return { lastReviewed: reviewed, stale: months >= STALE_AFTER_MONTHS, monthsAgo: months };
}

// ── A1: Multi-layer chain ordering ─────────────────────────────
// We only have evidence visible at the client edge — the `Via` header is
// the one standardized field that's supposed to list every proxy hop in
// order (RFC 9110 §7.6.3, outermost-last as written by each hop, but in
// practice CDNs prepend/append inconsistently so we treat order as a
// *signal*, not gospel) — combined with which providers actually got
// detected, so we never invent a hop with no other corroborating evidence.
function inferLayerChain(viaHeaderRaw, detectedProviderIds, providerNameOf) {
  if (!detectedProviderIds.length) return null;
  const via = (viaHeaderRaw || '').toLowerCase();
  if (detectedProviderIds.length === 1) {
    return { chain: [detectedProviderIds[0]], basis: 'single-provider', confidence: 'n/a' };
  }
  if (!via) {
    // Multiple providers detected but no Via header to sequence them —
    // we genuinely don't know the order. Say so instead of guessing.
    return { chain: null, basis: 'no-via-header', confidence: 'unknown' };
  }
  // Via can list multiple hops comma-separated, e.g. "1.1 varnish, 1.1 google".
  // Match each detected provider's known via-token against position in the string.
  const VIA_TOKENS = {
    cloudflare: ['cloudflare'], google: ['google'], akamai: ['akamai'],
    fastly: ['varnish', 'fastly'], cloudfront: ['cloudfront'], azure: ['azure'],
    vercel: ['vercel'], netlify: ['netlify'], bunnycdn: ['bunnycdn', 'bunny'],
    stackpath: ['ecacc', 'ecs', 'edgecast'], keycdn: ['keycdn'], gcore: ['gcore'],
    sucuri: ['sucuri'], tencenteo: ['tencent'], alicdn: ['alicdn', 'alibaba'],
    arvancloud: ['arvan'], vncdn: ['vncdn', 'vnetwork'],
  };
  const positions = [];
  for (const pid of detectedProviderIds) {
    const tokens = VIA_TOKENS[pid] || [];
    let pos = -1;
    for (const t of tokens) { const i = via.indexOf(t); if (i >= 0 && (pos === -1 || i < pos)) pos = i; }
    if (pos >= 0) positions.push({ pid, pos });
  }
  if (positions.length < 2) {
    // Via header exists but didn't mention enough of the detected providers
    // by name (common — many CDNs strip themselves from Via on egress).
    return { chain: null, basis: 'via-incomplete', confidence: 'low', viaHeaderRaw };
  }
  positions.sort((a, b) => a.pos - b.pos);
  // Via order as written is client-facing-first → origin-last per RFC intent,
  // so the chain reads left-to-right as "closest to visitor" → "closest to origin".
  const chain = positions.map(p => p.pid);
  // Note any detected provider that never appeared in Via at all — likely a
  // layer the client edge can't see directly (e.g. a WAF in front of origin
  // that doesn't append itself), surfaced as "position unconfirmed" rather
  // than silently dropped.
  const unconfirmed = detectedProviderIds.filter(pid => !chain.includes(pid));
  return { chain, unconfirmed, basis: 'via-header-order', confidence: 'medium', viaHeaderRaw };
}

// ── C2: Confidence breakdown — approximate, marginal-contribution method.
// We don't modify each provider's score() internals (21 files, high risk of
// drift); instead we toggle each currently-true boolean signal off one at a
// time and re-run score() to see how many points it was worth. This is an
// approximation — if a provider's scoring has caps/clamps or interaction
// effects between signals, the parts won't always sum exactly to the total.
// We label it as such in the UI rather than claim it's exact.
function computeBreakdown(provider, signals, baseScore) {
  const parts = [];
  for (const key of Object.keys(signals)) {
    if (signals[key] !== true) continue; // only booleans that fired contribute
    const probe = { ...signals, [key]: false };
    let altScore = 0;
    try { altScore = provider.score(probe).score || 0; } catch { altScore = baseScore; }
    const delta = baseScore - altScore;
    if (delta > 0) parts.push({ signal: key, points: delta });
  }
  parts.sort((a, b) => b.points - a.points);
  return parts;
}

// ── A2: Origin-IP-leak check (on-demand, not run on every default scan) ─
// Uses crt.sh (public Certificate Transparency log search, no API key) to
// enumerate subdomains/SANs the domain has ever issued certs for, then
// probes a short list of commonly-unprotected subdomains to see whether
// any of them resolve OUTSIDE the IP ranges of the CDN/WAF providers
// already detected for the apex domain. We deliberately do NOT attempt to
// read raw TLS certificate fields via fetch() — the browser/extension API
// surface has no access to the peer certificate, so crt.sh is the only
// honest no-cost source here.
const COMMON_LEAK_SUBDOMAINS = [
  'direct', 'origin', 'origin-www', 'old', 'dev', 'staging', 'ftp', 'mail',
  'cpanel', 'webdisk', 'autodiscover', 'server', 'host', 'backend', 'api-origin',
];
async function crtShSubdomains(domain) {
  try {
    const res = await fetchT(
      `https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`,
      {}, 12000
    );
    if (!res.ok) return [];
    const json = await res.json().catch(() => []);
    const names = new Set();
    for (const row of (Array.isArray(json) ? json : [])) {
      for (const n of String(row.name_value || '').split('\n')) {
        const clean = n.trim().toLowerCase().replace(/^\*\./, '');
        if (clean.endsWith(`.${domain}`) || clean === domain) names.add(clean);
      }
    }
    return [...names];
  } catch { return []; }
}
async function checkOriginLeak(domain, knownProviderRanges) {
  const candidates = new Set(COMMON_LEAK_SUBDOMAINS.map(s => `${s}.${domain}`));
  const ctNames = await crtShSubdomains(domain);
  for (const n of ctNames.slice(0, 150)) candidates.add(n);

  const findings = [];
  await runPooled([...candidates], PROBE_CONCURRENCY, async sub => {
    try {
      const d = await doh(sub, 'A');
      const ips = (d?.Answer || []).filter(r => r.type === 1).map(r => r.data.trim());
      for (const ip of ips) {
        const behindKnownCdn = knownProviderRanges.some(({ v4, v6 }) => ipMatches(ip, v4, v6));
        if (!behindKnownCdn) findings.push({ host: sub, ip });
      }
    } catch {}
  });
  return { checkedCount: candidates.size, ctSourceCount: ctNames.length, findings };
}

// ── Shared common-header extraction ──────────────────────────
// Called once per HTTP response; result is merged into every provider's signals.
function extractCommonSignals(res) {
  const hR = n => res.headers.get(n) || '';
  const h  = n => hR(n).toLowerCase();

  // Server-Timing: Cloudflare now emits cfL4, cfWorker, cdn-cache sub-metrics.
  // We flag presence generically — individual providers narrow this down.
  const st = hR('server-timing');

  return {
    hasAge:               res.headers.has('age'),
    hasSMaxAge:           /s-maxage\s*=\s*\d+/i.test(hR('cache-control')),
    timingAllowOrigin:    hR('timing-allow-origin') === '*',
    // HTTP/2 & HTTP/3 — detected via alt-svc or response protocol
    hasAltSvcH3:          /h3/i.test(hR('alt-svc')),
    // NEL / Report-To are strong CDN indicators regardless of provider
    hasNel:               res.headers.has('nel'),
    hasReportTo:          res.headers.has('report-to'),
    // Server-Timing present — individual providers inspect specific metrics
    hasServerTiming:      st.length > 0,
    serverTimingRaw:      st,
    // Via header (generic CDN signal; providers parse specific values)
    viaHeader:            hR('via'),
    // X-Cache (generic; providers check for provider-specific values)
    xCacheHeader:         hR('x-cache'),
  };
}

// ── Concurrency-limited task pool ──────────────────────────────
// Runs `items` through `worker` with at most `limit` in flight at once.
// Plain Promise.allSettled over 50-100+ probes fires every request
// simultaneously, which adds noise (easily flagged as a burst by WAFs)
// and increases tail latency; this keeps a steady, bounded window instead.
async function runPooled(items, limit, worker) {
  let idx = 0;
  async function runNext() {
    while (idx < items.length) {
      const i = idx++;
      await worker(items[i], i);
    }
  }
  const workers = Array(Math.min(limit, items.length)).fill(0).map(runNext);
  await Promise.allSettled(workers);
}

// ── Main scan ─────────────────────────────────────────────────
async function performScan(domain, progress) {
  await rangesReady;
  const providers = self.CDN_PROVIDERS || [];
  const allSig    = Object.fromEntries(providers.map(p => {
    const s = p.freshSignals();
    s.dnsShortTtl     = false;
    s.dnsVeryShortTtl = false;
    return [p.id, s];
  }));
  let resolvedIPs = [];
  const isDirectIP = isIPLiteral(domain);

  // ── Phase 1: DNS/DoH + Cookies (parallel) ────────────────
  if (isDirectIP) {
    // Direct IP scan: skip DNS resolution, use the literal IP as the only target.
    resolvedIPs = [domain];
    progress({ pct: 8, activity: 'Direct IP target — skipping DNS…' });

    for (const p of providers) {
      if (p.ipConfig?.ipSignal && ipMatches(domain, p.ipConfig.v4, p.ipConfig.v6))
        allSig[p.id][p.ipConfig.ipSignal] = true;
    }
  } else {
  progress({ pct: 5, activity: 'DNS lookup (A/AAAA/CNAME/MX/NS/TXT/HTTPS)…' });

  await Promise.allSettled([

    // DNS: A, AAAA, CNAME, MX, NS, TXT
    doHLookup(domain).then(({ ips, cname, mxRecords, nsRecords, txtRecords, minTTL }) => {
      resolvedIPs = ips;

      // TTL thresholds: CDNs typically use ≤300s; very short (<60s) is strong
      const shortTtl     = minTTL !== null && minTTL < 300;
      const veryShortTtl = minTTL !== null && minTTL < 60;

      // IP range matching
      for (const ip of ips) {
        for (const p of providers) {
          if (p.ipConfig?.ipSignal && ipMatches(ip, p.ipConfig.v4, p.ipConfig.v6))
            allSig[p.id][p.ipConfig.ipSignal] = true;
        }
      }

      // CNAME pattern matching
      if (cname) {
        for (const p of providers)
          for (const { re, signal } of (p.cnamePatterns || []))
            if (re.test(cname)) allSig[p.id][signal] = true;
      }

      // MX pattern matching
      for (const mx of mxRecords)
        for (const p of providers)
          for (const { re, signal } of (p.mxPatterns || []))
            if (re.test(mx)) allSig[p.id][signal] = true;

      // NS pattern matching — vanity NS is a medium-confidence signal
      for (const nsHost of nsRecords) {
        for (const { re, signal, pid } of NS_PATTERNS) {
          if (re.test(nsHost) && allSig[pid] && signal in allSig[pid])
            allSig[pid][signal] = true;
        }
        // Per-provider nsPatterns hook (optional)
        for (const p of providers)
          for (const { re, signal } of (p.nsPatterns || []))
            if (re.test(nsHost)) allSig[p.id][signal] = true;
      }

      // TXT record matching (per-provider txtPatterns hook)
      for (const rec of txtRecords)
        for (const p of providers)
          for (const { re, signal } of (p.txtPatterns || []))
            if (re.test(rec)) allSig[p.id][signal] = true;

      // Stamp TTL signals on all providers
      for (const p of providers) {
        allSig[p.id].dnsShortTtl     = shortTtl;
        allSig[p.id].dnsVeryShortTtl = veryShortTtl;
      }
      // Store nsRecords on the first provider's bag so Phase 5 can read them
      // for DNS-provider identification without a second lookup.
      if (providers[0]) allSig[providers[0].id].nsRecords = nsRecords;
    }),

    // A1: HTTPS DNS record — ECH key, ALPN, IP hints (RFC 9460)
    probeHttpsRecord(domain).then(hr => {
      if (hr) {
        // ECH present → strong Cloudflare signal (they pioneered ECH deployment)
        if (hr.ech && allSig['cloudflare']) allSig['cloudflare'].echPresent = true;
        // h3/h2 ALPN hints corroborate HTTP/3-capable providers
        if (hr.alpn.includes('h3')) {
          for (const id of ['cloudflare','google','fastly','cloudfront'])
            if (allSig[id]) allSig[id].quicH3Hint = true;
        }
        // Store on first provider's bag for result export
        if (providers[0]) allSig[providers[0].id]._httpsRecord = hr;
      }
    }),

    // A4: SPF + DMARC — email infra fingerprint
    probeSPFandDMARC(domain).then(sd => {
      if (providers[0]) allSig[providers[0].id]._spfDmarc = sd;
    }),

    // A5: Anycast divergence — query 3 resolvers, flag if IPs differ
    anyCastMap(domain).then(ac => {
      if (providers[0]) allSig[providers[0].id]._anycast = ac;
      // If IPs diverge across resolvers, it's a strong anycast (CDN) indicator
      if (ac.diverges) {
        for (const p of providers)
          if ('dnsShortTtl' in allSig[p.id]) allSig[p.id].anycastDivergence = true;
      }
    }),

    // Cookie scan
    (async () => {
      try {
        // Domain-scoped cookies (Domain attribute set, e.g. ".example.com")
        // plus host-only cookies (no Domain attribute — exact host match only).
        const [domainScoped, hostOnly] = await Promise.all([
          chrome.cookies.getAll({ domain: `.${domain}` }),
          chrome.cookies.getAll({ domain })
        ]);
        const seen = new Set();
        const cookies = [];
        for (const c of [...domainScoped, ...hostOnly]) {
          const key = `${c.name}|${c.domain}|${c.path}`;
          if (!seen.has(key)) { seen.add(key); cookies.push(c); }
        }
        for (const p of providers)
          if (p.extractCookies) p.extractCookies(cookies, allSig[p.id]);
      } catch {}
    })()
  ]);
  }

  // ── Phase 2: HTTP header + body (apex + www, or bare IP) ──
  // We skip www if its final URL is the same as apex (dedup redirect)
  const targets = isDirectIP
    ? [`https://${domain}`, `http://${domain}`]
    : domain.startsWith('www.')
      ? [`https://${domain}`]
      : [`https://${domain}`, `https://www.${domain}`];
  const timings    = [];
  let   lastFinalUrl = null;

  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    progress({ pct: 18 + i * 14, activity: `Fetching ${url}…` });

    try {
      const t0  = performance.now();
      const res = await fetchT(url, {
        redirect: 'follow',
        cache: 'no-store',
        // Send a realistic browser-like Accept to avoid serving bot-deflection pages
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        }
      });
      timings.push(performance.now() - t0);

      // Dedup: skip if redirect chain leads to same final URL
      const finalUrl = res.url;
      if (finalUrl === lastFinalUrl) continue;
      lastFinalUrl = finalUrl;

      // Read body for 200, 403, 503; also 429 (rate-limit/challenge pages)
      let body = null;
      if ([200, 403, 429, 503].includes(res.status))
        body = await res.text().catch(() => null);

      // Common signals — extracted once and merged into every provider
      const common = extractCommonSignals(res);
      for (const p of providers) {
        Object.assign(allSig[p.id], common);
        try { p.extract(res, body, allSig[p.id]); }
        catch { /* provider extractor must not crash the shared pass */ }
      }
    } catch {}
  }

  // ── Phase 3: Provider-specific probes (bounded concurrency) ─
  const allProbes = providers.flatMap(p =>
    (p.probes || []).map(probe => ({ p, probe }))
  );
  progress({ pct: 48, activity: `Running ${allProbes.length} targeted probes…` });

  let done = 0;
  await runPooled(allProbes, PROBE_CONCURRENCY, async ({ p, probe }) => {
    try {
      const res = await fetchT(probe.url(domain), probe.opts || {}, PROBE_TIMEOUT_MS);
      if ((probe.validStatuses || [200]).includes(res.status))
        await probe.handler(res, allSig[p.id]);
    } catch {}
    done++;
    const pct = 48 + Math.round((done / Math.max(allProbes.length, 1)) * 36);
    progress({ pct: Math.min(pct, 84), activity: `Probing ${p.name}…` });
  });

  // ── Phase 4: Timing anomaly ───────────────────────────────
  // First-request latency spike relative to subsequent requests suggests
  // a challenge/JS-injection layer (common in Cloudflare, Imperva, DataDome)
  if (timings.length >= 2) {
    const first   = timings[0];
    const avgRest = timings.slice(1).reduce((a, b) => a + b, 0) / (timings.length - 1);
    const anomaly = first > avgRest * 1.8 && first > 300;
    if (anomaly) {
      for (const p of providers)
        if ('timingAnomaly' in allSig[p.id]) allSig[p.id].timingAnomaly = true;
    }
  }

  // ── Phase 4.5: IP cross-verification (PTR + RDAP) ────────
  // Independent evidence that doesn't rely on response headers, so it
  // corroborates (or contradicts) the header/cookie-based signals above.
  progress({ pct: 86, activity: `Cross-verifying ${resolvedIPs.length} IP(s) via PTR/RDAP…` });
  const ipEvidence = await buildIpEvidence(resolvedIPs, providers);
  for (const ip of resolvedIPs) {
    const ev = ipEvidence[ip];
    if (!ev) continue;
    for (const pid of ev.matchedProviders) {
      if (allSig[pid]) allSig[pid].ipEvidenceMatch = true;
    }
  }

  // ── Phase 5: Score ────────────────────────────────────────
  progress({ pct: 92, activity: `Scoring ${providers.length} providers…` });

  const results = {};
  // Build a lightweight raw-header snapshot for custom-provider scoring
  // (we keep it as a plain {header: value} object rather than a Headers instance
  // so it survives serialisation into result objects if needed).
  const headerSnapshot = {};
  for (const id of Object.keys(allSig)) {
    const s = allSig[id];
    if (typeof s === 'object') {
      for (const [k, v] of Object.entries(s)) {
        if (typeof v === 'string' && v) headerSnapshot[k.toLowerCase()] = v;
      }
    }
  }
  // Raw header values are stored under specific known keys; the below covers
  // the most common ones extracted in extractCommonSignals.
  const rawHdrKeys = ['viaHeader','xCacheHeader','serverHeader','cfRay','xAmzCfId','xVercelId','xNfRequestId'];
  for (const p of providers) {
    const s = allSig[p.id];
    for (const k of rawHdrKeys) if (s?.[k] && typeof s[k] === 'string') headerSnapshot[k] = s[k];
  }

  for (const p of providers) {
    let verdict;
    try   { verdict = p.score(allSig[p.id]); }
    catch { verdict = { score: 0, label: 'Unlikely', detected: false }; }
    const breakdown = verdict.score > 0 ? computeBreakdown(p, allSig[p.id], verdict.score) : [];
    results[p.id] = { signals: allSig[p.id], verdict, breakdown, decay: decayInfoFor(p.id) };
  }

  // ── Custom provider scoring (declarative rules, no eval) ──────
  const customDefs = await getCustomProviders();
  const customResults = {};
  for (const def of customDefs) {
    const cname = Object.values(allSig).find(s => s?.cname)?.cname || null;
    const verdict = scoreCustomProvider(def, cname, headerSnapshot);
    customResults[def.id] = { def, verdict };
  }

  // ── B6: DNS-provider fingerprint — shown in results but NOT mixed into
  // CDN/WAF scoring because they're independent infrastructure layers.
  const dnsProvider = identifyDnsProvider(
    // nsRecords are collected in doHLookup() and flow through via the first
    // provider's signal bag (all providers share the same nsRecords).
    allSig[providers[0]?.id]?.nsRecords || []
  );

  // ── B2: Firefox TLS intel (if ambient listener captured it) ───
  const tlsIntel = tlsIntelByRequestId.get(`https://${domain}/`) || null;

  // ── Migration-conflict detection (improvement #15) ─────────
  // Fires when two or more non-overlapping providers are both detected at
  // medium-to-high confidence AND share no known joint-deployment pattern.
  // The simple version: look for (non-WAF-over-CDN) pairs, e.g. two CDNs.
  const detectedIds = Object.entries(results)
    .filter(([, v]) => v.verdict?.detected)
    .map(([id]) => id);
  const WAF_IDS = new Set(['imperva', 'sucuri', 'datadome', 'perimeterx', 'f5xc']);
  const cdn_detected = detectedIds.filter(id => !WAF_IDS.has(id));
  let migrationWarning = null;
  if (cdn_detected.length >= 2) {
    migrationWarning = {
      candidates: cdn_detected,
      note: 'Two or more CDN/edge providers detected simultaneously. This may indicate an in-progress infrastructure migration, a misconfigured CNAME chain, or a deliberate multi-CDN setup — worth verifying.'
    };
  }

  // ── A1: layer-order inference, using the now-known detected set ───
  const layerChain = inferLayerChain(allSig[providers[0]?.id]?.viaHeader, detectedIds, id => id);

  // Pull out enrichment data stashed on the first provider's signal bag
  const _firstSig  = allSig[providers[0]?.id] || {};
  const httpsRecord = _firstSig._httpsRecord || null;
  const spfDmarc    = _firstSig._spfDmarc    || null;
  const anycast     = _firstSig._anycast      || null;

  return {
    providers: results,
    customProviders: customResults,
    resolvedIPs,
    ipEvidence,
    isDirectIP,
    layerChain,
    dnsProvider,
    tlsIntel,
    migrationWarning,
    httpsRecord,   // A1 — ECH, ALPN, IPv4 hints from HTTPS RR
    spfDmarc,      // A4 — email infra (SPF provider + DMARC policy)
    anycast,       // A5 — multi-resolver IP divergence map
    scannedAt: new Date().toISOString()
  };
}

// ── B6: Badge — shows detected-provider count on the toolbar icon ──
async function updateBadge(result) {
  try {
    const count = Object.values(result?.providers || {}).filter(v => v.verdict?.detected).length;
    await chrome.action.setBadgeText({ text: count > 0 ? String(count) : '' });
    await chrome.action.setBadgeBackgroundColor({ color: count > 0 ? '#2ecc71' : '#4a5a70' });
  } catch {}
}

// ── D4: Threat-intel — recent CVEs mentioning a provider, via NVD's public
// CVE API (no key required at low volume; cached 24h locally to stay well
// under NVD's public rate limit and avoid hammering it on every popup open).
const CVE_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
async function fetchProviderCves(providerName) {
  const cacheKey = `cve_${providerName.toLowerCase().replace(/\s+/g, '_')}`;
  try {
    const { [cacheKey]: cached } = await chrome.storage.local.get(cacheKey);
    if (cached && Date.now() - cached.ts < CVE_CACHE_TTL_MS) return cached.data;
  } catch {}
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(providerName)}&resultsPerPage=8`;
    const res = await fetchT(url, {}, 10000);
    if (!res.ok) return { error: `NVD returned ${res.status}`, items: [] };
    const json = await res.json();
    const items = (json.vulnerabilities || []).map(v => ({
      id: v.cve?.id,
      published: v.cve?.published,
      summary: (v.cve?.descriptions || []).find(d => d.lang === 'en')?.value?.slice(0, 220) || ''
    }));
    const data = { items, fetchedAt: Date.now() };
    await chrome.storage.local.set({ [cacheKey]: { ts: Date.now(), data } });
    return data;
  } catch (e) { return { error: e.message || 'lookup failed', items: [] }; }
}

// ── D2: Crowd-sourced signature reporting — OPT-IN ONLY, disabled unless
// the person both flips the toggle AND supplies their own deployed
// endpoint (see /worker/README.md). We never send domain, IP, or any
// per-scan identifying data — only "this provider emitted a header we
// don't recognize", which is the minimum needed to spot new signatures.
const SETTINGS_KEY = 'app_settings';
const DEFAULT_SETTINGS = {
  theme: 'system', crowdReportEnabled: false, crowdReportEndpoint: '',
  watchlistIntervalMin: 360, ambientModeEnabled: false,
  // D3: optional third-party threat-intel API keys (stored locally, never transmitted except to their respective APIs)
  shodanApiKey: '', censysApiId: '', censysApiSecret: '',
};
async function getSettings() {
  try {
    const { [SETTINGS_KEY]: s } = await chrome.storage.local.get(SETTINGS_KEY);
    return { ...DEFAULT_SETTINGS, ...(s || {}) };
  } catch { return DEFAULT_SETTINGS; }
}
async function setSettings(patch) {
  const next = { ...(await getSettings()), ...patch };
  try { await chrome.storage.local.set({ [SETTINGS_KEY]: next }); } catch {}
  return next;
}
async function maybeSubmitCrowdReport(providerId, unknownHeaderNames) {
  if (!unknownHeaderNames.length) return;
  const settings = await getSettings();
  if (!settings.crowdReportEnabled || !settings.crowdReportEndpoint) return;
  try {
    await fetchT(settings.crowdReportEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ providerId, unknownHeaderNames, engineVersion: ENGINE_VERSION })
    }, 5000);
  } catch { /* best-effort, never block or surface errors to the user */ }
}


// ── B9: Custom provider packs (local import, MV3-safe) ─────────
// MV3 forbids executing remotely-fetched code, so this is NOT a plugin
// system that runs arbitrary JS — it's a small declarative JSON schema
// (CNAME regex strings + simple header-presence checks + point values)
// that this same trusted, already-bundled code interprets. No eval(), no
// new Function(), no remote script loading. This is the realistic core of
// "let people add providers without an extension update" within MV3's
// rules — a discovery/sharing hub on top of it is a separate, bigger
// project (not built here; the crowd-report Worker could grow into one).
const CUSTOM_PROVIDERS_KEY = 'custom_providers';
function validateCustomProviderSchema(p) {
  if (!p || typeof p !== 'object') throw new Error('Not an object');
  if (!/^custom_[a-z0-9_]{1,30}$/.test(p.id || '')) throw new Error('id must match custom_[a-z0-9_]{1,30}');
  if (!p.name || typeof p.name !== 'string') throw new Error('Missing name');
  const cname = Array.isArray(p.cnamePatterns) ? p.cnamePatterns : [];
  const headers = Array.isArray(p.headerChecks) ? p.headerChecks : [];
  if (!cname.length && !headers.length) throw new Error('Need at least one cnamePattern or headerCheck');
  for (const c of cname) { if (typeof c.pattern !== 'string' || typeof c.points !== 'number') throw new Error('Bad cnamePattern entry'); new RegExp(c.pattern); }
  for (const h of headers) { if (typeof h.header !== 'string' || typeof h.points !== 'number') throw new Error('Bad headerCheck entry'); if (h.valuePattern) new RegExp(h.valuePattern); }
  return { id: p.id, name: String(p.name).slice(0, 60), color: /^#[0-9a-f]{6}$/i.test(p.color || '') ? p.color : '#94a3b8', cnamePatterns: cname.slice(0, 10), headerChecks: headers.slice(0, 15) };
}
async function getCustomProviders() {
  try { const { [CUSTOM_PROVIDERS_KEY]: list = [] } = await chrome.storage.local.get(CUSTOM_PROVIDERS_KEY); return list; }
  catch { return []; }
}
async function importCustomProvider(json) {
  try {
    const parsed = typeof json === 'string' ? JSON.parse(json) : json;
    const clean = validateCustomProviderSchema(parsed);
    const list = (await getCustomProviders()).filter(p => p.id !== clean.id);
    list.push(clean);
    await chrome.storage.local.set({ [CUSTOM_PROVIDERS_KEY]: list.slice(0, 25) });
    return { ok: true, provider: clean };
  } catch (e) { return { ok: false, error: e.message }; }
}
async function removeCustomProvider(id) {
  const list = (await getCustomProviders()).filter(p => p.id !== id);
  await chrome.storage.local.set({ [CUSTOM_PROVIDERS_KEY]: list });
  return list;
}
// Scores a custom provider against the SAME signal bag already gathered for
// the run (cname match flags + raw header access via a small res-shaped
// passthrough is not available post-hoc, so custom providers score off the
// CNAME the run already resolved plus a recorded raw-header snapshot taken
// during Phase 2 — see capturedHeadersForCustom in performScan).
function scoreCustomProvider(def, cname, headerSnapshot) {
  let n = 0;
  const hits = [];
  for (const c of def.cnamePatterns) {
    try { if (cname && new RegExp(c.pattern, 'i').test(cname)) { n += c.points; hits.push(`cname:${c.pattern}`); } } catch {}
  }
  for (const h of def.headerChecks) {
    const val = headerSnapshot?.[h.header.toLowerCase()];
    if (val === undefined) continue;
    try {
      if (!h.valuePattern || new RegExp(h.valuePattern, 'i').test(val)) { n += h.points; hits.push(`header:${h.header}`); }
    } catch {}
  }
  n = Math.min(n, 100);
  return { score: n, label: n >= 50 ? `Possible ${def.name}` : n >= 20 ? `Weak ${def.name} indicators` : 'Unlikely', detected: n >= 20, hits };
}

// ── B5: Share / import a scan as a compact code (not a universal link) ──
// chrome-extension://<id>/... URLs only work for someone who already has
// THIS install of the extension (extension IDs differ per machine unless
// published with a fixed key), so this is a copy/paste code, not a magic
// clickable link that works for anyone.
async function makeShareCode(result) {
  try {
    const json = JSON.stringify(result);
    if (typeof CompressionStream === 'function') {
      const stream = new Blob([json]).stream().pipeThrough(new CompressionStream('gzip'));
      const buf = await new Response(stream).arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = ''; for (const b of bytes) bin += String.fromCharCode(b);
      return 'gz1:' + btoa(bin);
    }
    return 'raw1:' + btoa(unescape(encodeURIComponent(json)));
  } catch (e) { return null; }
}
async function decodeShareCode(code) {
  if (!code || typeof code !== 'string') throw new Error('Empty code');
  const [tag, payload] = code.split(':');
  if (!payload) throw new Error('Malformed code');
  const bin = atob(payload);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  if (tag === 'gz1') {
    if (typeof DecompressionStream !== 'function') throw new Error('This browser cannot decompress gz1 codes');
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    const text = await new Response(stream).text();
    return JSON.parse(text);
  }
  if (tag === 'raw1') return JSON.parse(decodeURIComponent(escape(bin)));
  throw new Error('Unknown code format');
}

// ── B6: DNS-provider fingerprint — separate from CDN/WAF detection.
// Looks at NS records to identify the authoritative DNS provider, which is
// frequently a different company than whatever fronts the HTTP traffic.
const DNS_PROVIDER_PATTERNS = [
  { re: /\.ns\.cloudflare\.com$/,        name: 'Cloudflare DNS' },
  { re: /awsdns-.*\.(org|com|net|co\.uk)$/, name: 'Amazon Route 53' },
  { re: /\.domaincontrol\.com$/,         name: 'GoDaddy DNS' },
  { re: /\.azure-dns\.(com|net|org|info)$/, name: 'Azure DNS' },
  { re: /\.googledomains\.com$/,         name: 'Google Domains DNS' },
  { re: /\.ns\.cloud\.google\.com$/,     name: 'Google Cloud DNS' },
  { re: /\.dnsmadeeasy\.com$/,           name: 'DNS Made Easy' },
  { re: /\.nsone\.net$/,                 name: 'NS1' },
  { re: /\.dynect\.net$/,                name: 'Oracle Dyn' },
  { re: /\.digitalocean\.com$/,          name: 'DigitalOcean DNS' },
  { re: /\.namecheaphosting\.com$/,      name: 'Namecheap DNS' },
  { re: /\.vnpt\.vn$/i,                  name: 'VNPT DNS' },
  { re: /\.matbao\.net$/i,               name: 'Mat Bao DNS' },
  { re: /\.pavietnam\.vn$/i,             name: 'P.A Vietnam DNS' },
  { re: /\.inet\.vn$/i,                  name: 'Vietnix DNS' },
];
function identifyDnsProvider(nsRecords) {
  for (const ns of (nsRecords || [])) {
    for (const { re, name } of DNS_PROVIDER_PATTERNS) if (re.test(ns)) return name;
  }
  return null;
}

// ── B2: Firefox-only real TLS/cert intel via webRequest.getSecurityInfo().
// EXPERIMENTAL — feature-detected because this API does not exist on
// Chrome (no equivalent has shipped there as of this build; there is a
// 2025 W3C proposal, github.com/w3c/webextensions#882, to add one). On
// Chrome this whole block is simply inert. Requires "blocking" on
// onHeadersReceived, which itself requires the "webRequestBlocking"
// permission — declared in manifest.json but only meaningful on Firefox.
const tlsIntelByRequestId = new Map();
try {
  if (typeof browser !== 'undefined' && browser.webRequest && browser.webRequest.getSecurityInfo) {
    browser.webRequest.onHeadersReceived.addListener(
      async details => {
        try {
          const info = await browser.webRequest.getSecurityInfo(details.requestId, { certificateChain: true });
          if (info.state === 'secure' || info.state === 'weak') {
            tlsIntelByRequestId.set(details.url, {
              protocol: info.protocolVersion, cipher: info.cipherSuite,
              certSubject: info.certificates?.[0]?.subject || null,
              certIssuer: info.certificates?.[0]?.issuer || null,
              certSha256: info.certificates?.[0]?.fingerprint?.sha256 || null,
              ech: !!info.usedEch, weaknessReasons: info.weaknessReasons || [],
            });
          }
        } catch {}
        return {};
      },
      { urls: ['<all_urls>'] },
      ['blocking']
    );
  }
} catch { /* not Firefox, or permission unavailable — silently inert */ }

// ── B1: Passive ambient detection — OFF by default, opt-in in Settings.
// Read-only header observation (NOT "blocking" — no webRequestBlocking
// needed for this listener) across every request the browser makes, used
// to build a lightweight per-tab badge of detected providers without the
// person ever clicking "Scan". Results are heuristic-only (no DNS/cookie/
// probe corroboration like a real scan has) and are intentionally not
// merged into scan history — they're a hint, not a verdict.
const ambientByTab = new Map(); // tabId -> Set(providerName)
async function ambientHeadersListener(details) {
  try {
    const settings = await getSettings();
    if (!settings.ambientModeEnabled) return;
    if (details.tabId < 0) return;
    const hint = ambientGuessFromHeaders(details.responseHeaders || []);
    if (!hint) return;
    const set = ambientByTab.get(details.tabId) || new Set();
    set.add(hint);
    ambientByTab.set(details.tabId, set);
    chrome.action.setBadgeText({ tabId: details.tabId, text: String(set.size) });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: '#1ed4ff' });
  } catch {}
}
function ambientGuessFromHeaders(headerList) {
  const h = name => (headerList.find(x => x.name.toLowerCase() === name)?.value || '');
  if (h('cf-ray') || /cloudflare/i.test(h('server'))) return 'Cloudflare';
  if (/^akamaighost/i.test(h('server'))) return 'Akamai';
  if (h('x-amz-cf-id')) return 'CloudFront';
  if (h('x-served-by') || /^varnish/i.test(h('server'))) return 'Fastly';
  if (h('x-iinfo')) return 'Imperva';
  if (h('x-azure-ref')) return 'Azure Front Door';
  if (h('x-vercel-id')) return 'Vercel';
  if (h('x-nf-request-id')) return 'Netlify';
  return null;
}
try {
  chrome.webRequest.onHeadersReceived.addListener(
    ambientHeadersListener,
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['responseHeaders']
  );
  chrome.tabs.onRemoved.addListener(tabId => ambientByTab.delete(tabId));
  chrome.tabs.onUpdated.addListener((tabId, info) => {
    if (info.status === 'loading') { ambientByTab.delete(tabId); chrome.action.setBadgeText({ tabId, text: '' }); }
  });
} catch { /* webRequest unavailable — ambient mode simply won't activate */ }

// ── Firefox TLS intel via webRequest.getSecurityInfo() ────────
// This API exists only on Firefox; it requires the (MV2-only)
// "webRequestBlocking" permission on Chrome, which is not available in
// MV3. We feature-detect it so the block is completely inert on Chrome/Edge.
// "blocking" mode is ONLY requested on Firefox via the `browser` namespace;
// using `chrome.webRequest` here (without blocking) would be a no-op anyway.
try {
  if (typeof browser !== 'undefined' && typeof browser.webRequest?.getSecurityInfo === 'function') {
    browser.webRequest.onHeadersReceived.addListener(
      async details => {
        try {
          const info = await browser.webRequest.getSecurityInfo(
            details.requestId, { certificateChain: true }
          );
          if (info.state === 'secure' || info.state === 'weak') {
            tlsIntelByRequestId.set(details.url, {
              protocol:       info.protocolVersion,
              cipher:         info.cipherSuite,
              certSubject:    info.certificates?.[0]?.subject || null,
              certIssuer:     info.certificates?.[0]?.issuer  || null,
              certSha256:     info.certificates?.[0]?.fingerprint?.sha256 || null,
              ech:            !!info.usedEch,
              weaknessReasons: info.weaknessReasons || [],
            });
          }
        } catch {}
        return {};
      },
      { urls: ['<all_urls>'] },
      ['blocking']   // valid on Firefox MV3 when accessed via `browser.*`
    );
  }
} catch { /* not Firefox — silently inert */ }

// ════════════════════════════════════════════════════════════════
// Round-3 additions: C1, A1, A2/A3, A4, A5
// ════════════════════════════════════════════════════════════════

// ── C1: Service-worker keep-alive heartbeat ───────────────────
// MV3 service workers are killed after ~30 s of inactivity.
// A periodic alarm every ~20 s reactivates the SW before Chrome
// terminates it, so long batch/watchlist scans don't silently abort.
const KEEPALIVE_ALARM = 'cdnwaf-keepalive';
chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.33 });

// ── A5: Multi-resolver anycast mapping ───────────────────────
const ANYCAST_RESOLVERS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google',     url: 'https://dns.google/dns-query' },
  { name: 'Quad9',      url: 'https://dns.quad9.net/dns-query' },
];
async function dohAlt(resolverUrl, domain) {
  try {
    const res = await fetchT(
      `${resolverUrl}?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { Accept: 'application/dns-json' } }, 5000
    );
    if (!res.ok) return [];
    const j = await res.json();
    return (j.Answer || []).filter(r => r.type === 1).map(r => r.data.trim());
  } catch { return []; }
}
async function anyCastMap(domain) {
  const rows = await Promise.allSettled(
    ANYCAST_RESOLVERS.map(r => dohAlt(r.url, domain).then(ips => ({ resolver: r.name, ips })))
  );
  const entries = rows.filter(r => r.status === 'fulfilled').map(r => r.value);
  const allIps  = [...new Set(entries.flatMap(e => e.ips))];
  const diverges = allIps.length > 1 && entries.some(e =>
    JSON.stringify([...e.ips].sort()) !== JSON.stringify([...entries[0].ips].sort())
  );
  return { entries, diverges, uniqueIps: allIps };
}

// ── A1: HTTPS DNS record (RFC 9460) ──────────────────────────
// HTTPS RR carries ECH public keys (→ Cloudflare signal), ALPN (h3/h2),
// and IP hints — all verifiable via DoH, zero TLS handshake needed.
async function probeHttpsRecord(domain) {
  try {
    const res = await fetchT(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=HTTPS`,
      { headers: { Accept: 'application/dns-json' } }, 6000
    );
    if (!res.ok) return null;
    const j = await res.json();
    const answers = (j.Answer || []).filter(r => r.type === 65);
    if (!answers.length) return null;
    const raw = answers.map(a => a.data).join(' ');
    const echPresent = /\bech=/.test(raw);
    const alpnMatch  = raw.match(/alpn="([^"]+)"/);
    const alpn       = alpnMatch ? alpnMatch[1].split(',').map(s => s.trim()) : [];
    const ip4Match   = raw.match(/ipv4hint="([^"]+)"/);
    const ipv4hints  = ip4Match ? ip4Match[1].split(',').map(s => s.trim()) : [];
    return { ech: echPresent, alpn, ipv4hints, raw };
  } catch { return null; }
}

// ── A4: SPF + DMARC fingerprint ──────────────────────────────
const SPF_PROVIDERS = [
  { re: /include:_spf\.google\.com/,           name: 'Google Workspace' },
  { re: /include:spf\.protection\.outlook/,    name: 'Microsoft 365' },
  { re: /include:.*mimecast/,                  name: 'Mimecast' },
  { re: /include:.*proofpoint/,                name: 'Proofpoint' },
  { re: /include:.*sendgrid/,                  name: 'SendGrid' },
  { re: /include:.*mailchimp/,                 name: 'Mailchimp' },
  { re: /include:.*amazonses\.com/,            name: 'Amazon SES' },
  { re: /include:.*zoho/,                      name: 'Zoho Mail' },
  { re: /include:.*mailgun/,                   name: 'Mailgun' },
];
async function probeSPFandDMARC(domain) {
  const out = { spfProvider: null, dmarcPolicy: null, spfRaw: null };
  try {
    const [spf, dmarc] = await Promise.allSettled([
      doh(domain, 'TXT'), doh(`_dmarc.${domain}`, 'TXT')
    ]);
    const spfRec = (spf.value?.Answer || [])
      .map(r => r.data).find(d => /v=spf1/i.test(d));
    if (spfRec) {
      out.spfRaw = spfRec;
      for (const { re, name } of SPF_PROVIDERS)
        if (re.test(spfRec)) { out.spfProvider = name; break; }
    }
    const dmarcRec = (dmarc.value?.Answer || [])
      .map(r => r.data).find(d => /v=DMARC1/i.test(d));
    if (dmarcRec) {
      const pm = dmarcRec.match(/\bp=(\w+)/i);
      out.dmarcPolicy = pm ? pm[1] : 'present';
    }
  } catch {}
  return out;
}

// Assign now that loadCachedRanges() is defined. Any scan triggered before
// this resolves will correctly await it — no race condition possible because
// the first scan can only be triggered by a user action, which comes after
// the full script has been evaluated.
rangesReady = loadCachedRanges().catch(() => {});

// ════════════════════════════════════════════════════════════════
// Distributed probing via check-host.net public API
// Runs HTTP checks from real servers in ~50 countries, returns response
// headers + resolved IP + latency per node — reveals anycast routing
// and lets us see CDN edge headers from multiple geographic vantage points.
// Public, free, no auth. Capped to be a good API citizen.
// Docs: https://check-host.net/about/api
// ════════════════════════════════════════════════════════════════
const CHECK_HOST_MAX_NODES = 12;
const CHECK_HOST_POLL_INTERVAL_MS = 2000;
const CHECK_HOST_MAX_POLLS = 5;

const PROBE_HEADER_PATTERNS = [
  { name: 'cloudflare',  re: /\bcf-ray\b/i },
  { name: 'cloudflare',  re: /server:\s*cloudflare\b/i },
  { name: 'akamai',      re: /\bx-check-cacheable\b/i },
  { name: 'akamai',      re: /\bakamai-cache-status\b/i },
  { name: 'fastly',      re: /x-served-by.*cache/i },
  { name: 'fastly',      re: /\bfastly-/i },
  { name: 'cloudfront',  re: /\bx-amz-cf-id\b/i },
  { name: 'azure',       re: /\bx-azure-ref\b/i },
  { name: 'google',      re: /via:.*google\b/i },
  { name: 'vercel',      re: /\bx-vercel-id\b/i },
  { name: 'netlify',     re: /\bx-nf-request-id\b/i },
  { name: 'imperva',     re: /\bx-iinfo\b/i },
  { name: 'bunnycdn',    re: /\bbunnycdn-cache\b/i },
];
function extractCdnFromHeaders(headersStr) {
  const detected = new Set();
  for (const { name, re } of PROBE_HEADER_PATTERNS) if (re.test(headersStr)) detected.add(name);
  return [...detected];
}
function parseProbeHeaders(headersStr) {
  const lines = (headersStr || '').split(/\r?\n/);
  const obj = {};
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      const key = line.slice(0, colon).trim().toLowerCase();
      const val = line.slice(colon + 1).trim();
      if (!obj[key]) obj[key] = val;
    }
  }
  return obj;
}
async function probeDistributed(domain) {
  let token, nodes;
  try {
    const init = await fetchT(
      `https://check-host.net/check-http?host=${encodeURIComponent(domain)}&max_nodes=${CHECK_HOST_MAX_NODES}`,
      { headers: { Accept: 'application/json' } }, 10000
    );
    if (!init.ok) return { error: `check-host.net returned ${init.status}` };
    const j = await init.json();
    token = j.request_token;
    nodes = j.nodes || {};
  } catch (e) { return { error: e.message || 'Failed to reach check-host.net' }; }
  if (!token) return { error: 'No request token in response' };

  let resultData = {};
  for (let poll = 0; poll < CHECK_HOST_MAX_POLLS; poll++) {
    await new Promise(r => setTimeout(r, CHECK_HOST_POLL_INTERVAL_MS));
    try {
      const res = await fetchT(`https://check-host.net/check-result/${token}`, { headers: { Accept: 'application/json' } }, 8000);
      if (!res.ok) continue;
      resultData = await res.json();
      const pending = Object.values(resultData).filter(v => v === null).length;
      if (pending === 0) break;
    } catch {}
  }

  const nodeResults = [];
  for (const [nodeId, result] of Object.entries(resultData)) {
    const nodeInfo = nodes[nodeId];
    if (!nodeInfo) continue;
    const [, countryCode, city, countryName] = nodeInfo;
    if (!result || !result[0]) {
      nodeResults.push({ nodeId, country: countryName || countryCode, city, status: 'pending' });
      continue;
    }
    const [connectCode, , httpCode, headersStr, latency] = result[0];
    const parsedHeaders = parseProbeHeaders(headersStr || '');
    nodeResults.push({
      nodeId, country: countryName || countryCode, city,
      status: connectCode === 1 ? 'ok' : 'fail',
      httpCode, latencyMs: latency ? Math.round(latency * 1000) : null,
      cdnSignals: extractCdnFromHeaders(headersStr || ''),
      resolvedIp: parsedHeaders['x-real-ip'] || null,
      serverHeader: parsedHeaders['server'] || null,
      cacheHeader: parsedHeaders['cf-cache-status'] || parsedHeaders['x-cache'] || null,
    });
  }

  const uniqueIps = [...new Set(nodeResults.filter(r => r.resolvedIp).map(r => r.resolvedIp))];
  return {
    domain, nodeResults,
    uniqueEdgeIps: uniqueIps,
    anycastConfirmed: uniqueIps.length > 1,
    cdnSignalsSeen: [...new Set(nodeResults.flatMap(r => r.cdnSignals || []))],
    totalNodes: nodeResults.length,
    okNodes: nodeResults.filter(r => r.status === 'ok').length,
  };
}

// ════════════════════════════════════════════════════════════════
// ASN / org lookup via ipinfo.io (free tier)
// ════════════════════════════════════════════════════════════════
const asnCache = new Map();
async function queryASN(ip) {
  if (asnCache.has(ip)) return asnCache.get(ip);
  try {
    const res = await fetchT(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {}, 6000);
    if (!res.ok) return null;
    const data = await res.json();
    const result = {
      asn: data.org?.split(' ')[0] || null,
      org: data.org?.slice(data.org.indexOf(' ') + 1) || null,
      country: data.country || null,
      city: data.city || null,
    };
    asnCache.set(ip, result);
    return result;
  } catch { return null; }
}

// ── Port listener (progress streaming) ───────────────────────
chrome.runtime.onConnect.addListener(port => {
  if (port.name !== 'scan') return;
  let dead = false;
  port.onDisconnect.addListener(() => { dead = true; });

  port.onMessage.addListener(async msg => {
    if (msg.action !== 'scan') return;
    const { domain, forceRefresh } = msg;

    if (!forceRefresh) {
      const cached = await getCached(domain);
      if (cached) {
        if (!dead) port.postMessage({ type: 'result', data: cached, cached: true });
        return;
      }
    }

    const emit = update => { if (!dead) port.postMessage({ type: 'progress', ...update }); };
    try {
      const result = await performScan(domain, emit);
      const diff = await diffAgainstHistory(domain, result); // before history is overwritten
      await setCached(domain, result);
      await addToHistory(domain, result);
      await saveSnapshot(domain, result); // D1: full snapshot for timeline diff
      await updateBadge(result);
      // Record for multi-tab correlation
      const tabId = port.sender?.tab?.id;
      if (tabId != null) recordTabResult(tabId, domain, result);
      const tabCorrelation = getTabCorrelation(domain);
      if (!dead) port.postMessage({ type: 'result', data: { ...result, tabCorrelation }, cached: false, diff });
    } catch (err) {
      if (!dead) port.postMessage({ type: 'error', message: err.message || 'Unknown error' });
    }
  });
});

// ── Legacy one-shot (fallback) ────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.action === 'scan') {
    (async () => {
      const r = await performScan(msg.domain, () => {});
      const diff = await diffAgainstHistory(msg.domain, r);
      await setCached(msg.domain, r);
      await addToHistory(msg.domain, r);
      await saveSnapshot(msg.domain, r); // D1
      await updateBadge(r);
      const tabCorrelation = getTabCorrelation(msg.domain);
      return { ...r, tabCorrelation, diff };
    })()
      .then(r  => sendResponse(r))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.action === 'getHistory') {
    getHistory().then(list => sendResponse({ history: list }));
    return true;
  }
  if (msg.action === 'clearHistory') {
    clearHistory().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.action === 'getPins') {
    getPins().then(list => sendResponse({ pins: list }));
    return true;
  }
  if (msg.action === 'togglePin') {
    togglePin(msg.domain).then(list => sendResponse({ pins: list }));
    return true;
  }
  if (msg.action === 'getCves') {
    fetchProviderCves(msg.providerName).then(data => sendResponse(data));
    return true;
  }
  if (msg.action === 'checkOriginLeak') {
    (async () => {
      const providers = self.CDN_PROVIDERS || [];
      const ranges = providers.filter(p => p.ipConfig?.v4 || p.ipConfig?.v6)
        .map(p => ({ v4: p.ipConfig.v4, v6: p.ipConfig.v6 }));
      // Use favicon-enhanced version so false-positives get flagged
      return checkOriginLeakWithFavicon(msg.domain, ranges);
    })().then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message, findings: [] }));
    return true;
  }
  if (msg.action === 'getSettings') {
    getSettings().then(s => sendResponse(s));
    return true;
  }
  if (msg.action === 'setSettings') {
    setSettings(msg.patch || {}).then(s => sendResponse(s));
    return true;
  }
  if (msg.action === 'warmCache') {
    // B2: offscreen document asks SW to warm IP ranges on startup
    rangesReady = loadCachedRanges().catch(() => {});
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'submitCrowdReport') {
    maybeSubmitCrowdReport(msg.providerId, msg.notes ? [msg.notes] : [])
      .then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.action === 'getTabCorrelation') {
    sendResponse(getTabCorrelation(msg.domain));
    return true;
  }
  if (msg.action === 'getAmbientResults') {
    const tabId = msg.tabId;
    sendResponse({ providers: tabId != null ? [...(ambientByTab.get(tabId) || [])] : [] });
    return true;
  }
  if (msg.action === 'getWatchlist') {
    getWatchlist().then(list => sendResponse({ watchlist: list }));
    return true;
  }
  if (msg.action === 'toggleWatch') {
    toggleWatch(msg.domain).then(async list => {
      await ensureWatchlistAlarm();
      sendResponse({ watchlist: list });
    });
    return true;
  }
  if (msg.action === 'runWatchlistNow') {
    runWatchlistCheck().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.action === 'getCustomProviders') {
    getCustomProviders().then(list => sendResponse({ providers: list }));
    return true;
  }
  if (msg.action === 'importCustomProvider') {
    importCustomProvider(msg.json).then(res => sendResponse(res));
    return true;
  }
  if (msg.action === 'removeCustomProvider') {
    removeCustomProvider(msg.id).then(list => sendResponse({ providers: list }));
    return true;
  }
  if (msg.action === 'makeShareCode') {
    makeShareCode(msg.result).then(code => sendResponse({ code }));
    return true;
  }
  if (msg.action === 'decodeShareCode') {
    decodeShareCode(msg.code).then(result => sendResponse({ result }))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.action === 'getTimingData') {
    injectAndGetTimingData(msg.tabId).then(data => sendResponse({ data }));
    return true;
  }
  // D1: Full snapshot for infrastructure-diff timeline
  if (msg.action === 'getSnapshotHistory') {
    getSnapshotHistory(msg.domain).then(list => sendResponse({ snapshots: list }));
    return true;
  }
  // D3: Shodan/Censys lookup (user-supplied key)
  if (msg.action === 'queryThreatIntel') {
    queryThreatIntel(msg.ip, msg.provider).then(r => sendResponse(r))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }
  // Distributed probing (check-host.net) — 12 global vantage points
  if (msg.action === 'probeDistributed') {
    probeDistributed(msg.domain).then(r => sendResponse(r))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }
  // ASN/org lookup for a specific IP
  if (msg.action === 'queryASN') {
    queryASN(msg.ip).then(r => sendResponse({ data: r }));
    return true;
  }
  // Clipboard scan: background receives domain from popup clipboard button
  if (msg.action === 'scanClipboardDomain') {
    (async () => {
      const r = await performScan(msg.domain, () => {});
      const diff = await diffAgainstHistory(msg.domain, r);
      await setCached(msg.domain, r);
      await addToHistory(msg.domain, r);
      await updateBadge(r);
      return { ...r, diff };
    })().then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }
});

// ── A4 improvement: scheduled watchlist re-scans ──────────────
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === KEEPALIVE_ALARM) return; // no-op — just reactivates SW
  if (alarm.name === WATCHLIST_ALARM) runWatchlistCheck();
});
ensureWatchlistAlarm();

// ── B5: Right-click "Scan this domain/link" context menu ──────
chrome.runtime.onInstalled.addListener(() => {
  try {
    chrome.contextMenus.create({
      id: 'cdnwaf-scan-page',
      title: 'Scan this domain with CDN/WAF Detector',
      contexts: ['page']
    });
    chrome.contextMenus.create({
      id: 'cdnwaf-scan-link',
      title: 'Scan this link\u2019s domain with CDN/WAF Detector',
      contexts: ['link']
    });
  } catch {}
});
chrome.contextMenus.onClicked.addListener(async (info) => {
  try {
    const target = info.menuItemId === 'cdnwaf-scan-link' ? info.linkUrl : info.pageUrl;
    if (!target) return;
    const hostname = new URL(target).hostname;
    await chrome.storage.local.set({ pending_scan_domain: hostname });
    // openPopup() requires Chrome 99+ and a recent user gesture — a context
    // menu click satisfies that. Falls back silently (popup.js will also
    // pick up pending_scan_domain next time the popup is opened manually).
    if (chrome.action.openPopup) await chrome.action.openPopup();
  } catch {}
});

// ── C3: Keyboard commands ─────────────────────────────────────
chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'open-side-panel') {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.windowId != null) await chrome.sidePanel.open({ windowId: tab.windowId });
    } catch {}
  }
  if (command === 'scan-clipboard') {
    // B3: Read clipboard, detect domain/IP, trigger scan and open popup
    // Note: clipboard access in SW requires a focused document — we store a
    // flag and let the popup/sidepanel read it on next open instead.
    await chrome.storage.local.set({ clipboard_scan_pending: true });
    try { if (chrome.action.openPopup) await chrome.action.openPopup(); } catch {}
  }
});

// ── B2: Offscreen document for cache warming ──────────────────
// Chrome 116+: offscreen documents can keep a hidden DOM-backed page alive
// so that IP-range JSON can be fetched + cached without waiting for the SW
// to wake from cold. Gracefully absent on older Chrome or Firefox.
async function ensureOffscreenDocument() {
  if (!chrome.offscreen) return; // Chrome <116 or Firefox — skip
  try {
    const existing = await chrome.offscreen.hasDocument().catch(() => false);
    if (!existing) {
      await chrome.offscreen.createDocument({
        url: chrome.runtime.getURL('offscreen.html'),
        reasons: ['BLOBS'],
        justification: 'Warm IP-range cache on extension startup to eliminate cold-start scan delay'
      });
    }
  } catch {} // non-fatal if offscreen not available
}
ensureOffscreenDocument();

// ── B5: API mode docs anchor ──────────────────────────────────
// The onMessageExternal listener below accepts scan requests from pages
// listed in manifest.json > externally_connectable > matches.
// Default: empty array → nothing can connect. To enable:
//   1. Add your origin to manifest.json externally_connectable.matches
//   2. From your page: chrome.runtime.sendMessage(EXT_ID, {action:'scan',domain:'...'})
//   3. Response is the full performScan result JSON

// ── B4: Local "webhook" ───────────────────────────────────────
chrome.runtime.onMessageExternal.addListener((msg, _sender, sendResponse) => {
  if (msg?.action === 'scan' && msg.domain) {
    performScan(msg.domain, () => {})
      .then(r => sendResponse(r))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }
  sendResponse({ error: 'Unsupported action' });
});


// ════════════════════════════════════════════════════════════════
// D1: Full infrastructure snapshot — diff timeline
// Unlike addToHistory() which only stores detected[] provider IDs,
// snapshots store the FULL result object so callers can diff individual
// signals, scores, and HTTPS/anycast/SPF intel across time.
// ════════════════════════════════════════════════════════════════
const SNAPSHOT_KEY_PREFIX = 'snap_';
const MAX_SNAPSHOTS_PER_DOMAIN = 30;

async function saveSnapshot(domain, result) {
  const key = SNAPSHOT_KEY_PREFIX + domain;
  try {
    const { [key]: existing = [] } = await chrome.storage.local.get(key);
    existing.unshift({ ts: Date.now(), result });
    await chrome.storage.local.set({ [key]: existing.slice(0, MAX_SNAPSHOTS_PER_DOMAIN) });
  } catch {}
}
async function getSnapshotHistory(domain) {
  const key = SNAPSHOT_KEY_PREFIX + domain;
  try {
    const { [key]: list = [] } = await chrome.storage.local.get(key);
    return list;
  } catch { return []; }
}

// ════════════════════════════════════════════════════════════════
// D3: Threat intel — optional Shodan / Censys lookups
// Users bring their own API keys (stored in settings, never sent
// anywhere except the respective vendor's API). Both APIs are CORS-
// permissive from browser context, so fetch() works directly.
// ════════════════════════════════════════════════════════════════
async function queryThreatIntel(ip, provider) {
  const settings = await getSettings();
  const results  = {};

  // Shodan InternetDB (free, no key, CORS-open) — basic port/vuln info
  try {
    const res = await fetchT(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {}, 8000);
    if (res.ok) results.shodanInternetDb = await res.json();
    else results.shodanInternetDb = null;
  } catch { results.shodanInternetDb = null; }

  // Shodan full API — requires user key
  if (settings.shodanApiKey) {
    try {
      const res = await fetchT(
        `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(settings.shodanApiKey)}`,
        {}, 10000
      );
      results.shodan = res.ok ? await res.json() : { error: `HTTP ${res.status}` };
    } catch (e) { results.shodan = { error: e.message }; }
  }

  // Censys hosts API — requires API ID + secret
  if (settings.censysApiId && settings.censysApiSecret) {
    try {
      const auth = btoa(`${settings.censysApiId}:${settings.censysApiSecret}`);
      const res  = await fetchT(
        `https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`,
        { headers: { Authorization: `Basic ${auth}`, Accept: 'application/json' } }, 10000
      );
      results.censys = res.ok ? (await res.json())?.result : { error: `HTTP ${res.status}` };
    } catch (e) { results.censys = { error: e.message }; }
  }

  return results;
}

// Wire snapshot saving into the port and onMessage scan handlers
// (done below by patching: after addToHistory, also call saveSnapshot)

// ── #18: Multi-tab correlation ─────────────────────────────────
// Accumulates scan results for the same apex domain across different tabs
// so the popup can surface "Tab A got Cloudflare, Tab B got Fastly for
// the same domain" — indicates anycast routing variance by path/region.
const tabResultsByDomain = new Map(); // apexDomain -> [{tabId, result}]

function apexOf(domain) {
  const parts = domain.split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : domain;
}

function recordTabResult(tabId, domain, result) {
  const apex = apexOf(domain);
  const list = tabResultsByDomain.get(apex) || [];
  const idx = list.findIndex(e => e.tabId === tabId);
  const entry = { tabId, domain, result, ts: Date.now() };
  if (idx >= 0) list[idx] = entry; else list.push(entry);
  // Keep at most 20 tab entries per apex domain, drop oldest first
  if (list.length > 20) list.splice(0, list.length - 20);
  tabResultsByDomain.set(apex, list);
}

function getTabCorrelation(domain) {
  const apex = apexOf(domain);
  const list = tabResultsByDomain.get(apex) || [];
  if (list.length < 2) return null;
  // Build a set of detected-provider-id sets per tab
  const tabSets = list.map(e => ({
    tabId: e.tabId, domain: e.domain, ts: e.ts,
    detected: new Set(Object.entries(e.result.providers || {})
      .filter(([, v]) => v.verdict?.detected).map(([id]) => id))
  }));
  // Check for variance: any two tabs disagreeing on at least one provider
  let hasVariance = false;
  for (let i = 0; i < tabSets.length; i++) {
    for (let j = i + 1; j < tabSets.length; j++) {
      const a = tabSets[i].detected, b = tabSets[j].detected;
      const diff = [...a].filter(id => !b.has(id)).concat([...b].filter(id => !a.has(id)));
      if (diff.length) { hasVariance = true; break; }
    }
    if (hasVariance) break;
  }
  return {
    apex, entryCount: list.length,
    tabs: tabSets.map(t => ({ tabId: t.tabId, domain: t.domain, ts: t.ts, detected: [...t.detected] })),
    hasVariance,
    note: hasVariance
      ? 'Different providers detected across tabs for the same apex domain — likely anycast routing variance (different PoPs or paths are being served differently).'
      : 'All tabs for this domain show the same provider set — consistent routing.'
  };
}

chrome.tabs.onRemoved.addListener(tabId => {
  for (const [apex, list] of tabResultsByDomain) {
    const filtered = list.filter(e => e.tabId !== tabId);
    if (filtered.length) tabResultsByDomain.set(apex, filtered);
    else tabResultsByDomain.delete(apex);
  }
});

// ── A5: Favicon-hash corroboration for origin-leak candidates ──
// Technique: compute a simple hash of the favicon bytes from the domain's
// canonical favicon path, then compare against the same path on any
// "possibly-leaking" subdomain found by checkOriginLeak(). Matching hash
// = high confidence same origin behind different IPs — massively cuts
// false-positives where a subdomain happens to resolve outside CDN ranges
// but is actually a totally separate service (e.g. a marketing subdomain
// hosted on a different provider by choice).
//
// We use mmh3 / FNV-1a (both royalty-free, implementable in a few lines)
// rather than a cryptographic hash — the goal is content fingerprinting, not
// collision resistance.
function fnv32a(buf) {
  let h = 0x811c9dc5;
  for (const b of new Uint8Array(buf)) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).padStart(8, '0');
}
async function faviconHash(hostname) {
  const paths = ['/favicon.ico', '/favicon.png', '/apple-touch-icon.png'];
  for (const path of paths) {
    try {
      const res = await fetchT(`https://${hostname}${path}`, {}, 6000);
      if (!res.ok || !res.headers.get('content-type')?.includes('image')) continue;
      const buf = await res.arrayBuffer();
      if (buf.byteLength < 16) continue; // skip redirect/empty stubs
      return { path, hash: fnv32a(buf), size: buf.byteLength };
    } catch {}
  }
  return null;
}
async function checkOriginLeakWithFavicon(domain, knownProviderRanges) {
  const base = await checkOriginLeak(domain, knownProviderRanges);
  if (!base.findings.length) return base;
  const baseHash = await faviconHash(domain);
  const enriched = await Promise.all(base.findings.map(async f => {
    const fh = await faviconHash(f.host);
    const sameOrigin = baseHash && fh && baseHash.hash === fh.hash;
    return { ...f, faviconHash: fh?.hash || null, sameOrigin };
  }));
  return { ...base, findings: enriched, baseFaviconHash: baseHash?.hash || null };
}

// ── C5: Resource Timing signal injection (content script approach) ──
// Extension content scripts can call performance.getEntriesByType('resource')
// on the actual page and read nextHopProtocol (h2/h3-**/quic/http/1.1 etc.)
// without any special permissions beyond "activeTab". This gives us the
// *real* negotiated protocol for the main-frame connection — more reliable
// than the Alt-Svc header heuristic used in background.js, which sees the
// fetch() connection, not the tab's TLS session.
// Implementation: background injects a tiny content script on-demand when
// the popup or side panel requests timing data for the current tab.
async function injectAndGetTimingData(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const entries = performance.getEntriesByType('navigation');
        const nav = entries[0] || {};
        return {
          nextHopProtocol: nav.nextHopProtocol || null,
          domainLookupTime: (nav.domainLookupEnd - nav.domainLookupStart) || null,
          connectTime: (nav.connectEnd - nav.connectStart) || null,
          ttfb: (nav.responseStart - nav.requestStart) || null,
        };
      },
    });
    return results?.[0]?.result || null;
  } catch { return null; }
}
