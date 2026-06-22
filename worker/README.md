# Crowd-sourced signature backend (optional, D2)

This is **not loaded by the extension**. It's a separate Cloudflare Worker
you can deploy yourself if you want to turn on "Crowd-sourced signatures"
in the extension's Settings page. The extension works completely fine
without ever deploying this — the feature defaults to **off**.

## What it does

Collects small, anonymous notes like *"saw header X-Foo-Edge on
Cloudflare that isn't tracked yet"*, grouped by provider. Nothing else —
no domain, no IP, no per-scan data is ever sent (see
`maybeSubmitCrowdReport()` in `background.js`).

## Deploy it yourself

You need a free Cloudflare account and `wrangler` (Cloudflare's CLI).

```bash
npm install -g wrangler
wrangler login

# Create the KV namespace that stores reports
wrangler kv namespace create REPORTS
# ^ copy the returned "id" into wrangler.toml below

wrangler deploy
```

### `wrangler.toml` (create this next to `crowd-signatures-worker.js`)

```toml
name = "cdnwaf-crowd-signatures"
main = "crowd-signatures-worker.js"
compatibility_date = "2026-01-01"

kv_namespaces = [
  { binding = "REPORTS", id = "PASTE_YOUR_KV_NAMESPACE_ID_HERE" }
]
```

After `wrangler deploy`, you'll get a URL like
`https://cdnwaf-crowd-signatures.<your-subdomain>.workers.dev`.

## Wire it up in the extension

1. Open the extension popup → **⚙ Settings**.
2. Toggle **Enable reporting** on.
3. Paste `https://your-worker-url/report` into the endpoint field.

## Reviewing submitted reports

`GET https://your-worker-url/reports?provider=cloudflare` returns the raw
JSON list for that provider. This endpoint has **no authentication** in
the code as shipped — add your own (a shared secret header, Cloudflare
Access, etc.) before relying on it for anything beyond casual personal use.

## Limits baked into the Worker

- Max 5 note strings per report, 300 chars each (truncated, not rejected).
- Max 500 stored reports per provider (oldest dropped first).
