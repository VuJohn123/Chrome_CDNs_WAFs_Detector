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
