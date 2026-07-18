# Changelog — v9.0.0

## New features

**A — Accuracy / core value**
- **A1. Layer-order inference** — parses the existing `Via` header (already
  collected, zero new network cost) to infer visitor→origin hop order when
  multiple providers are detected. Shows "position unconfirmed" instead of
  guessing when the evidence doesn't support an order.
- **A2. Origin-IP-leak check** (on-demand button, not run on every scan) —
  uses crt.sh Certificate Transparency logs + a common-subdomain probe list
  to flag hosts resolving outside known CDN ranges. *Does not* read TLS
  certificates directly — see "What was adjusted" below.
- **A3. Confidence decay** — flags a provider's score as possibly stale if
  its signature hasn't been reviewed in 6+ months, based on a hand-maintained
  `PROVIDER_LAST_REVIEWED` map in `background.js`.
- **A4. Scan diffing** — compares the current scan against the most recent
  prior scan of the same domain and shows what was added/removed.

**B — New features**
- **B1. Batch scan** — `batch.html`, paste/upload a domain list, bounded
  concurrency, JSON/CSV export.
- **B2. Compare 2 domains** — `compare.html`, side-by-side scan with a
  shared/only-A/only-B provider summary.
- **B3. Export** — JSON, CSV, and a printable HTML report (use the browser's
  Print → Save as PDF; no PDF library is bundled).
- **B4. Local webhook** — `chrome.runtime.onMessageExternal`, **disabled by
  default** (`externally_connectable.matches: []` in manifest.json). Add
  your own trusted origin(s) there to enable it.
- **B5. Right-click "Scan this domain/link"** context menu.
- **B6. Toolbar badge** showing the detected-provider count.

**C — UX**
- **C1. Dark/light theme toggle**, persisted, defaults to system preference.
- **C2. Confidence breakdown** — approximate per-signal point contribution,
  computed by re-scoring with each signal toggled off (leave-one-out), not
  by modifying all 21 provider files.
- **C3. Pin/bookmark domains**, separate from auto-recorded history.

**D — Bold ideas**
- **D2. Crowd-sourced signatures (opt-in, beta)** — manual "report a new
  signal" form in the provider detail view. Off by default; requires you to
  deploy `/worker/crowd-signatures-worker.js` yourself (see
  `/worker/README.md`) and paste the endpoint into Settings.
- **D4. Threat-intel CVE lookup** — on-demand NVD keyword search per
  provider, 24h cache.

## What was adjusted from the original 17-item list, and why

- **D1 (real JA3/JA4 TLS fingerprinting) — not implemented.** A browser
  extension's JavaScript has no access to the raw TLS ClientHello; there's
  no honest way to do this without a native-messaging host running outside
  the browser, which is out of scope here.
- **A2 (origin leak)** doesn't read TLS certificate SAN fields via `fetch()`
  — that data isn't exposed to extension JS by any browser API. It uses the
  public crt.sh Certificate Transparency log search instead.
- **D3 (client-side ML)** — not implemented as a "trained model." There's no
  labeled ground-truth dataset (no oracle telling us which domains *truly*
  use which provider), so a "trained classifier" would just be fabricated
  weights dressed up as ML. If you want this properly, it needs real labeled
  data first.

## v9.4.0 — Round 5: net-new ideas

**Shipped (11 requested, 2 dropped after research — see below):**
- **#3 RUM Core Web Vitals attribution** — captures real LCP/CLS/TTFB from the active tab, attributes to detected provider, builds a local trend (Settings → Performance intelligence).
- **#4 Third-party waterfall attribution** — classifies `PerformanceResourceTiming` entries into main-domain vs third-party (analytics, ads, fonts, trackers), shows % of load time each accounts for.
- **#5 CDN service-tier heuristic** — infers "likely paid/enterprise tier" from optional features (image optimization, smart routing) — explicitly labeled as a heuristic, never a billing-data claim.
- **#6 Cross-device sync via `chrome.storage.sync`** — pinned domains and watchlist now sync automatically across Chrome profiles signed into the same Google account. No server, no Worker. Falls back to `.local` if sync is disabled by policy.
- **#7 robots.txt / security.txt OSINT** — fetches both, surfaces sitemap references and any CDN-stamped comments, checks for bug-bounty/security contact info.
- **#8 "Blast radius"** — via Shodan InternetDB (free), lists other hostnames sharing a resolved IP.
- **#9 CDN status-page correlation** — checks Cloudflare/Fastly/Akamai/Vercel/Netlify/Google Cloud status APIs before assuming a watchlist diff means "they migrated" instead of "provider is down right now."
- **#10 Shareable fingerprint string** — a JA4-style compact string (`CDNW1_cf_r53_e1a0_L2`) summarizing a scan for quick paste-and-compare.
- **#11 Wayback Machine cross-check** — CDX API query for the domain's earliest archive.org snapshot, extending historical context beyond this extension's own local history.

**Tree view rewritten** — proper 4-layer taxonomy (WAF → CDN → Edge-hosting → Origin) instead of a flat 2-bucket split, respects Via-header chain order within layers, sidebar shows DNS/Email/ECH/Anycast context, all round-5 actions surfaced from one toolbar.

**Light theme rewritten** — previous version used flat near-white grays with a white header, which read as washed-out. New palette uses a warm slate-blue scale with a deep navy header (matches dark mode's visual anchor), plus per-component overrides for cards, inputs, and the detail view so nothing reads as "white text on white."

**Crowd-report Worker (D2) — dashboard added.** `GET /` now renders an HTML dashboard showing report frequency per provider, so you can actually see which unrecognized headers are being reported most often instead of only querying raw JSON per-provider.

### What was proposed but dropped (with reasons)

- **#1 (JA4H HTTP-request fingerprint)** — dropped. JA4H measures the *client's* HTTP fingerprint as seen by a server (used by CDNs/WAFs to detect bots). This extension acts as the client already; there's nothing to detect a CDN *with* here — it's the wrong direction entirely, not just impractical.
- **#2 (passive TCP/HTTP2-frame fingerprinting)** — dropped, no substitute added. Every real technique in this space (TCP window size, HTTP/2 SETTINGS frame, WINDOW_UPDATE, PRIORITY frame structure) requires packet-level capture (Wireshark, nghttp2, raw sockets) that browser JavaScript has no access to. `fetch()` exposes none of it. Any "browser-based" version of this would have to fake the data, so it's omitted rather than built as decoration.

## v9.4.1 — Bug fix + cross-browser support

### Fixed
- **check-host.net distributed probe was broken.** Root cause: code read a field called `request_token`, but the real API (verified against https://check-host.net/about/api) returns `request_id`. The check-result response shape was also wrong — assumed 5 fields including a response-headers string that doesn't exist; the real shape is `[ok, response_time_seconds, status_message, http_code]`, 4 fields, no headers. This meant the probe could never get a valid token and always failed with "No request token in response." Fixed the field name, fixed the result parsing, and removed the CDN-signal/resolved-IP extraction logic that depended on data the API never actually provides (rather than leave it silently producing empty results). The probe now correctly reports reachability + latency + HTTP status from real global nodes; anycast confirmation continues to come from the extension's own DNS-based multi-resolver check (A5), which is the reliable source for that.

### Cross-browser support (Chrome + Firefox)
Split into two manifests — `manifest.chrome.json` and `manifest.firefox.json` — because Chrome MV3 and Firefox MV3 diverge on several manifest keys that can't be reconciled in one file:
- **Background context**: Chrome requires `background.service_worker`; Firefox MV3 only supports `background.scripts` (event page). Using the wrong key silently fails to load on the other browser.
- **Side panel**: Chrome's `chrome.sidePanel` has no Firefox equivalent; Firefox uses `sidebar_action` instead. Both the popup button and the `Ctrl+Shift+D` command now feature-detect and use whichever is available.
- **webRequestBlocking**: valid and required on Firefox for the TLS-intel listener (`browser.webRequest.getSecurityInfo`); rejected outright by Chrome MV3. Only in the Firefox manifest.
- **Offscreen documents** (`chrome.offscreen`, used for cache warming): Chrome-only, already feature-detected — inert no-op on Firefox.
- **Clipboard read**: Firefox requires an explicit `clipboardRead` permission; Chrome does not.

The actual code (`background.js`, `popup.js`, all provider files) is shared as-is between both builds — no polyfill library needed, since Firefox natively supports the `chrome.*` namespace for compatibility (confirmed via MDN's "Chrome incompatibilities" reference) and every API this extension uses exists on both browsers except the handful already feature-detected above.

Added `build.sh` — packages both `dist/cdnwaf-detector-chrome-vX.zip` and `dist/cdnwaf-detector-firefox-vX.zip` from the one shared codebase in a single run, swapping in the right manifest for each and excluding the other browser's manifest + the build script itself from the final zip.

## v9.4.3 — Round 6: DNS-layer intelligence

All 6 features build on the existing A5 multi-resolver DoH infrastructure — no new API surface, just reading more from data already being fetched, or adding one more resolver to the existing comparison.

- **#1 DNS-blocking/censorship detector** (on-demand, Tree view → 🚧 Check DNS blocking) — compares a neutral resolver (Cloudflare) against a policy-filtering resolver (OpenDNS FamilyShield). Positively identifies a block by matching known FamilyShield sinkhole IPs, with a lower-confidence NXDOMAIN-mismatch fallback. Purely diagnostic — reports what it observes, never attempts to route around or bypass a detected block.
- **#2 EDNS Client Subnet (ECS) leak detector** (automatic, shown as a banner when detected) — compares Google's DoH (sends ECS by documented default) against Cloudflare's DoH (no ECS by design). Zero IP overlap between the two answer sets suggests the CDN is geo-routing based on the visitor's partial IP leaked via ECS — a privacy signal most users have no visibility into otherwise.
- **#3 DNSSEC validation status** (automatic, green pill when present) — reads the `AD` (Authenticated Data) flag that was already present in every DoH JSON response being fetched for A5; considered validated only when every responding resolver agrees, since AD reflects each resolver's own validation state.
- **#4 Resolver speed race** (automatic, informational pill) — times all three resolvers against each other for the current scan and reports which answered fastest this session. Session-local only; not persisted, since resolver latency depends on network conditions and time of day.
- **#5 Resolver-disagreement as WAF/geo-fencing signal** — folded into #2's ECS-leak logic; a complete (not partial) IP-set mismatch between resolvers is the same signal that flags an ECS leak, since normal anycast divergence usually still shares at least some edge IPs.
- **#6 Wired into existing Tree sidebar and Timeline** — no new UI surface built; DNSSEC/ECS-leak/fastest-resolver status appears as sidebar chips in the Tree view (C4) and as inline tags in the Timeline (D1), reusing infrastructure already shipped.

## v9.4.4 — Accuracy fixes + UI decluttering

### Fixed: DNS-blocking detector (#1 from round 6) reliability
Research into real-world OpenDNS FamilyShield behavior found the sinkhole IP list is **not stable over time**, and found a documented case where FamilyShield returned an unrelated IP (not any known sinkhole address) for a blocked domain instead of the expected redirect. Because of this:
- **NXDOMAIN-mismatch is now the primary signal** (the filtering resolver simply refuses to resolve while a neutral one succeeds) — this doesn't depend on maintaining an accurate, ever-changing IP list.
- **Sinkhole-IP match is now a secondary, lower-confidence hint only**, always shown with an explicit "this IP list can go stale" caveat in the UI. Never asserted as certain.
- Added a `confidence` field (`medium-high` / `low-medium`) surfaced directly in the panel so the person can weigh the result appropriately.

### Fixed: DNS-blocking check now caches results (10 min TTL)
Previously, clicking "Check DNS blocking" repeatedly re-fired two DoH round-trips every time, even for the same domain seconds apart. Now cached per-domain for 10 minutes; the panel shows a small "cached result" note when serving from cache.

### Redesigned: Overview screen was too information-dense
Simulated scanning `google.com` end-to-end while designing this: with Google detected, DNSSEC validated, an ECS-leak banner (Google's own resolver enables ECS by default), a DNS-provider pill, and 24 always-rendered provider cards (23 of them "undetected" and irrelevant), the old flat layout produced roughly 15 stacked information blocks with no visual hierarchy.

Restructured into:
- **Always visible**: summary line, resolved IPs, diff-vs-last-scan banner, layer order (only shown when 2+ providers are detected — a single provider has no "order" to show).
- **Detected providers grid** — now shows only providers that actually matched, not all 24 with 23 grayed-out "undetected" cards cluttering the view.
- **📡 Network & infrastructure signals** (collapsible, badge shows item count) — DNS provider, SPF/DMARC, HTTPS record/ECH, TLS intel, DNSSEC, ECS-leak, anycast divergence all grouped here, collapsed by default.
- **📋 All N providers** (collapsible, opt-in) — the full always-was-there provider grid including undetected ones, for people who want to audit every provider individually.
- **🛠 Tools & export** (collapsible, 2-column button grid instead of a cramped 8-button row) — JSON/CSV/Markdown/Report export, origin-leak check, share code, timeline, tree view.

Net effect: a typical single-CDN scan now renders 3-4 compact blocks instead of ~15, with the option to expand any group that's actually relevant to what the person is investigating.

## v9.4.5 — Fix: still cluttered with 2+ detected providers

Simulated scanning a site with both Cloudflare (WAF) and Google (CDN) detected — the exact multi-provider case the previous redesign didn't fully address. Even after v9.4.4's grouping, having 2+ providers still stacked: a diff banner, a multi-CDN warning banner, a migration-warning banner, an anycast note, and a separate layer-chain row — 5 separate full-width colored blocks before even reaching the provider list, which then rendered 2+ full-height cards.

Fixed by:
- **Consolidating all status banners into one block.** Diff-vs-last-scan, multi-CDN warning, migration warning, anycast note, and layer order are now short single lines inside one bordered block, only showing lines that actually apply. What used to be 5 stacked colored banners is now one compact block with 1-3 short lines.
- **Compact provider rows for 2+ detected providers.** A single detected provider still gets a full card (there's room, and it's the headline answer). With 2 or more, providers now render as slim one-line rows (dot + name + label + score) instead of full cards with a head/bar/label each — cuts vertical space roughly in half for multi-CDN scans.

## v9.4.6 — Fixed redundant/awkward copy + Round 7 (15 features)

### Fixed: confusing duplicate messaging
- **"Multi-CDN/WAF deployment detected"** and the longer migration-warning sentence used to both appear and say almost the same thing twice (one short, one long). Now only one line shows: the specific migration-warning note when 2+ actual CDNs are detected (a real thing worth flagging), or a short neutral line for the common CDN+WAF combo (not a warning — that's normal).
- **"21 IPs resolved — tap an IP..."** was a plain unstyled line sitting awkwardly in the summary. IPs now get their own styled, collapsible group card (🌐 Resolved IPs) with a count badge, matching the visual language of the other groups. 1-2 IPs still render inline since a whole group for two chips is overkill.
- **"Layer order unknown"** line removed from the always-visible status block — Via header being absent is the common case, not something worth a line every single scan. Still checkable via the Tree view for anyone specifically investigating layer order.
- Shortened the migration-warning sentence itself (background.js) from a 3-clause paragraph to one short sentence.

### Round 7 — 15 features, all implemented
1. **Adaptive detail density** — tracks per-group expand/collapse rate locally; once a group has been opened 60%+ of the time across 5+ scans, it defaults to expanded going forward.
2. **Explain in plain words** (Tree view) — turns the C2 confidence breakdown into a sentence instead of a bar chart.
3. **Baseline comparison** (Tree view) — "you've seen this combination N times before, rank #X of Y" using only your own local scan history.
4. **Explain for a report** (Tree view) — non-technical paragraph suitable for pasting to a boss/client, with a copy button.
5. **Flag for later review** — distinct from Pin; attaches a note + timestamp, viewable/removable from Settings.
6. **Custom-rule preview** — tests a draft custom-provider rule against locally stored scan history before saving, to catch overly broad rules early.
7. **Batch from bookmarks/open tabs** — populates Batch scan without manual paste. Bookmarks access uses `optional_permissions` — requested only when this button is clicked, never at install.
8. *(sparkline trend — folded into #3's baseline comparison rather than a separate chart; kept scope tight)*
9. **Weekly watchlist digest** — one notification per week summarizing all changes, instead of one per change per domain.
10. **Diff-only export** (Timeline) — exports only snapshots where something actually changed, skipping the "no change" majority.
11. **Keyboard navigation** — j/k move between results, Enter opens detail, Esc goes back; disabled while typing in any input.
12. **Quick compare** (Tree view) — inline two-domain comparison without leaving the popup for the dedicated Compare page.
13. **Weak-signal badge** — a small ⚠ next to any detected provider whose score came from only 1 signal, flagging higher false-positive risk directly in the overview.
14. **Auto-suggest rule from crowd reports** — drafts a starting custom-provider rule when a note has 5+ reports for a provider; always requires manual review/import, never automatic.
15. **Watchlist aggregate dashboard** — one feed across every watched domain's changes, instead of opening each domain's Timeline separately.

## v9.4.7 — Tree redesign: accuracy + decluttering

Prompted by a real scan result (Imperva 43% + Cloudflare 100% + Akamai 53% all in the same tree, DNS listed separately as "Cloudflare DNS") that exposed two real problems: silently listing 3 competing providers as if equally certain, and repeating "Cloudflare" as an unrelated fact in two different places.

### Accuracy
- **Same-layer conflict detection.** When 2+ full-CDN-class providers appear in the CDN or Edge-hosting layer (e.g. Cloudflare + Akamai both detected), the layer now shows an explicit amber warning: this is unusual for one site and often means one is a false positive (shared IP range, stale CNAME) rather than a genuine multi-CDN setup. WAF+CDN combos are NOT flagged — that's a normal, common pairing.
- **Weak-signal badge ported into the Tree.** A provider chip whose detection came from only 1 supporting signal now shows the same ⚠ badge already used in the Overview, with a tooltip explaining why. Previously the Tree showed every chip with equal visual weight regardless of how solid the detection actually was — exactly what let something like "Imperva 43%" sit next to "Cloudflare 100%" without any indication one is far less certain.
- **Same-provider linking.** If the DNS provider (or another sidebar fact) names a company that's also a detected chip in the tree — e.g. "Cloudflare DNS" when Cloudflare is already shown as the WAF/CDN — it no longer repeats as an unrelated sidebar fact. Instead it becomes a small linked note ("Cloudflare also manages DNS for this domain") directly under the tree, and the sidebar only shows genuinely separate context.

### UI — grouped instead of dumped
- All Tree action buttons (previously two dense rows: check-host probe, robots.txt, blast radius, Wayback, fingerprint, status pages, DNS blocking, explain, explain-for-report, baseline, flag, quick-compare — 12 buttons total, always visible) are now inside one collapsible "🛠 Analysis tools" group, matching the same pattern already used in the Overview screen. The tree itself stays the headline visual; the 12 analysis tools are one tap away instead of always taking up scroll space.

## v9.4.8 — Signal accuracy audit + Imperva hardening

Researched 2026 detection-vendor documentation for Imperva/Incapsula, Cloudflare, Fastly, DataDome, PerimeterX/HUMAN, and Akamai to find what's genuinely readable from a browser extension's passive HTTP/cookie view versus what only exists in each vendor's internal bot-scoring (TLS/JA4 fingerprinting, HTTP/2 frame analysis, canvas/WebGL fingerprinting — none of which `fetch()` can see, confirmed by the same research that led to dropping JA4H/TCP-fingerprint ideas in round 6).

### Fixed: Imperva was the file causing thin-signal false positives
Traced a real scan result (Imperva at 43% alongside two other providers) to `imperva.js` being the one detector in this codebase that hadn't yet adopted the "require signal diversity" pattern already used in `datadome.js` (`hasCorroboration` check) and `perimeterx.js` (`coherentCount` check). Imperva's scoring simply summed every fired signal's points regardless of how weak or exclusive each one was — a single `X-Cdn-Forward` header (a generic proxy-chain header, not Imperva-exclusive) could contribute meaningfully toward "detected" on its own.

Fixed by porting the same pattern: a detection now needs signals from 2+ independent categories (header / cookie / body / CNAME / probe) unless a single definitively-exclusive signal fired (valid-format X-Iinfo, a matched Imperva CNAME) — those remain trustworthy alone since they can't reasonably come from anything else.

### Added — 2026 research-verified signals
- **`incap_sh_` cookie prefix** — confirmed via multiple 2026 detection-vendor writeups as a newer session cookie used in Imperva's GeeTest-CAPTCHA challenge flow. Not previously tracked.
- **Dynamic challenge-path detection** — real Imperva deployments serve the JS challenge from a randomized path with a `?d=<hostname>` query parameter, not always the literal `_Incapsula_Resource` string the old body-regex expected. Added a domain-aware pattern match (background.js now passes the scanned domain into `extractCommonSignals` as `_domainEscaped` so any provider can build domain-specific body patterns safely).

### Reviewed, no changes needed
- **Cloudflare** — `__cf_bm` bot-management cookie already tracked; Cloudflare's actual 2026 bot-scoring (JA4, `cf.bot_management.score`, CDP-artifact detection) lives entirely server-side/internal to Cloudflare's dashboard and isn't exposed in response headers a client can read.
- **Fastly** — already well-sourced (cites http.dev directly in comments); no gaps found.
- **DataDome** — already treats the bare `datadome` cookie name as weak-alone, requiring corroboration; this is the same pattern Imperva now has.
- **PerimeterX/HUMAN** — already reads cookies via `chrome.cookies` (correct approach, since PerimeterX cookies are set via JS, not `Set-Cookie` headers — confirmed by research); already has the coherent-signal-count logic.
- **Akamai** — already tracks the correct `_abck`/`bm_sz`/`ak_bmsc` cookie family.

## v9.4.9 — Full signal audit across all 24 providers

Extended the accuracy audit from v9.4.8 (which found and fixed Imperva's thin-signal issue) across the remaining 18 provider files: CloudFront, Vercel, Netlify, Azure, Sucuri, F5 Distributed Cloud, Alibaba Cloud CDN, BunnyCDN, Gcore, KeyCDN, and others. Each was checked against 2026 vendor documentation or independently-verified technical sources.

### Fixed: Azure detector had a structurally-impossible signal
Research against Microsoft's own Front Door HTTP headers documentation (`MicrosoftDocs/azure-docs`) found that `X-Azure-JA4-Fingerprint` — a header the previous version checked for and weighted at 48 points — is attached to the **request Front Door forwards to the origin server**, not to the response sent back to the client. A browser extension can only read `fetch()` response headers, so this check was structurally always-false: dead code that could never fire, contributing a false sense of "we check for JA4 fingerprints" without ever actually doing so. Removed entirely rather than left in place; verified no other provider had the same request-vs-response header confusion (checked all files referencing fingerprint/bot-defense/ClientHello concepts).

### Added — 2026 research-verified signal
- **Vercel**: `x-vercel-proxy-signature` header, confirmed present on Vercel rewrite-proxy requests via a Vercel/Next.js team GitHub discussion thread. Not officially documented but observed consistently; added as a moderate-weight corroborating signal.

### Reviewed, confirmed accurate, no changes needed
- **CloudFront**: `X-Amz-Cf-Pop` format (IATA airport code + facility number + cache-tier suffix like `LAX54-P1`) cross-checked against three independent sources (AWS blog, AWS re:Post, http.dev) — exact match to what the detector already validates.
- **Vercel / Netlify**: header sets (`x-vercel-id` region-chain format, `x-nf-request-id` ULID format) both cross-checked against official docs and support forums — already accurate.
- **Sucuri**: no gaps found against current documentation.
- **F5 Distributed Cloud**: confirmed the bot-defense custom header F5 adds is also request-to-origin only (like Azure's JA4 case) — but the existing detector never attempted to read it in the first place, so no fix was needed here.
- **Alibaba Cloud CDN**: `X-Swift-SaveTime`/`X-Swift-CacheTime` already correctly scoped as Swift-layer-exclusive signals.
- **BunnyCDN**: cross-checked against bunny.net's own developer academy documentation — the detector already covers the complete documented header set (`cdn-cache`, `cdn-cachedat`, `cdn-edgestorageid`, `cdn-proxyver`, `cdn-pullzone`, `cdn-requestcountrycode`, `cdn-requestid`, `cdn-requestpullcode`, `cdn-requestpullsuccess`, `cdn-status`, `cdn-uid`, `server: BunnyCDN-`) with no gaps.
- **Gcore**: architecture already sound, no changes needed.
- **KeyCDN**: verified the service is still active and operating normally as of April 2026 (status page, FAQ, uptime monitors) — the file's "still active as of 2026" comment is accurate, not stale.

## v9.5.0 — Major cleanup (44 → 26 actions) + Crowd-sourced signatures upgrade

### Removed — 10 features cut for low practical value vs. complexity
After auditing all 44 message actions, removed features that either duplicated something already covered elsewhere or required enough manual effort that they saw little real use:
- **Adaptive group density** (#1) — tracked expand/collapse habits to "learn" default UI state; added storage/messaging overhead for a marginal convenience.
- **Baseline stack comparison** (#3) — required 3+ scans before showing anything, and the "rank #X of Y" output was more abstract than actionable.
- **Flag for later review** (#5) — duplicated Pin (both were "mark this domain"); consolidated to just Pin.
- **Batch scan from bookmarks/open tabs** (#7) — required a separate `bookmarks` permission grant and a multi-step folder-picker flow for a rarely-used convenience; `optional_permissions` entry removed from both manifests.
- **Weekly watchlist digest** (#9) — redundant with real-time watchlist change notifications, which already fire per-change.
- **Core Web Vitals capture + third-party waterfall** (round 7 #3/#4) — required manually clicking "capture from current tab" every time; passive/automatic would have been useful, manual-trigger wasn't used enough to justify the code.
- **CDN service-tier heuristic** (round 6 #5) — speculative "likely paid tier" inference saw no real usage.
- **robots.txt / security.txt OSINT** (round 5 #7) — rarely surfaced anything CDN/WAF-relevant; scope drift from the tool's core purpose.
- **Blast radius / shared-IP lookup** (round 5 #8) — Shodan InternetDB's free tier returned empty results often enough that the feature rarely produced anything useful.
- **Auto-suggest rule from crowd reports** (round 7 #14) — required both a configured Worker AND 5+ identical reports before ever triggering; replaced by something that actually works (see below).
- **Watchlist aggregate dashboard** (#15) — duplicated per-domain Timeline in a new UI surface for no added value.

Net result: 44 → 26 message actions (~40% reduction), with all 10 removals also cleaned from both manifests, Settings UI, and Tree view action rows.

### Upgraded — Crowd-sourced signatures now self-sustaining
The crowd-report feature previously required a person to manually notice an unfamiliar header and type a note — a high bar that explained why even a properly-deployed Worker endpoint would see little traffic. Replaced the manual-noticing step with automatic detection:

- **`knownHeaders` added to 21 of 24 provider files** (Cloudflare, Akamai, Alibaba Cloud CDN, Azure, BunnyCDN, CloudFront, DataDome, F5 Distributed Cloud, Fastly, Fly.io, Gcore, Google, Imperva, KeyCDN, Netlify, PerimeterX, Render, StackPath, Sucuri, Tencent EdgeOne, Vercel) — each provider now declares exactly which header names it already recognizes.
- **Automatic unknown-header detection** — every scan compares the apex domain's response headers against a combined known-header list (standard HTTP headers + all 21 providers' declared vocabularies). Any header left over, on a domain where a provider WAS detected, gets surfaced.
- **One-click report buttons** in each provider's detail view — no typing required; clicking a suggested header sends `"Unrecognized header: X"` as the report note. A manual free-text note field remains below for anything the automatic check doesn't catch (new cookies, body patterns, etc).
- **Overview-level notice** — a small pill in the Network & infrastructure signals group flags when unrecognized headers were found on a scan, pointing to the relevant provider's detail view.
- Settings copy updated to describe the automatic-detection behavior and to point to the Worker's own dashboard URL for viewing submitted reports.

This directly targets making the already-deployed `cdnwaf-crowd-signatures.minhvutanlaphanoi.workers.dev` endpoint self-sustaining long-term — the bar to contribute a signal dropped from "notice something unusual, remember to report it, type a description" to "click the button that's already showing you the unrecognized header."
