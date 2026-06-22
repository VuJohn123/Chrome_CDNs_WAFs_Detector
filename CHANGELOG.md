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
