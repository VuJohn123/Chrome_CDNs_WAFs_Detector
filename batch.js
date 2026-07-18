'use strict';

const domainListEl  = document.getElementById('domainList');
const csvUploadEl   = document.getElementById('csvUpload');
const runBtn        = document.getElementById('runBtn');
const clearBtn      = document.getElementById('clearBtn');
const progressText  = document.getElementById('progressText');
const progressWrap  = document.getElementById('progressWrap');
const progressBar   = document.getElementById('progressBar');
const tableEl       = document.getElementById('batchTable');
const tbodyEl       = document.getElementById('batchTbody');
const exportJsonBtn = document.getElementById('exportJsonBtn');
const exportCsvBtn  = document.getElementById('exportCsvBtn');

const CONCURRENCY = 3;

// #7: pick up domains handed off from the "batch from bookmarks/tabs" flow
chrome.storage.local.get('batch_prefill_domains', res => {
  const domains = res?.batch_prefill_domains;
  if (domains?.length) {
    chrome.storage.local.remove('batch_prefill_domains');
    domainListEl.value = domains.join('\n');
  }
});

let lastResults = [];   // [{domain, result}]
let scanAborted = false;

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── File upload: accept CSV (take first column) or plain list ──
csvUploadEl.addEventListener('change', () => {
  const file = csvUploadEl.files?.[0];
  if (!file) return;
  const r = new FileReader();
  r.onload = () => {
    const lines = String(r.result)
      .split(/\r?\n/)
      .map(l => l.split(',')[0].replace(/["']/g, '').trim())
      .filter(Boolean);
    const current = domainListEl.value.trim();
    domainListEl.value = (current ? current + '\n' : '') + lines.join('\n');
  };
  r.readAsText(file);
  csvUploadEl.value = '';  // allow re-upload of same file
});
clearBtn.addEventListener('click', () => {
  domainListEl.value = '';
  tableEl.hidden = true;
  tbodyEl.innerHTML = '';
  progressWrap.hidden = true;
  progressBar.style.width = '0%';
  progressText.textContent = '';
  exportJsonBtn.disabled = true;
  exportCsvBtn.disabled = true;
  lastResults = [];
});

// ── One domain via the existing background 'scan' port ─────────
function scanOne(domain) {
  return new Promise(resolve => {
    let settled = false;
    const port = chrome.runtime.connect({ name: 'scan' });
    const done = (status, data) => {
      if (settled) return;
      settled = true;
      try { port.disconnect(); } catch {}
      resolve({ status, data });
    };
    port.onMessage.addListener(msg => {
      if (msg.type === 'result') done('done', msg.data);
      else if (msg.type === 'error') done('error', { message: msg.message });
    });
    port.onDisconnect.addListener(() => done('error', { message: 'Service worker disconnected' }));
    setTimeout(() => done('error', { message: 'Timeout (60 s)' }), 60000);
    port.postMessage({ action: 'scan', domain, forceRefresh: false });
  });
}

async function pooled(items, limit, fn) {
  let i = 0;
  const next = async () => { while (i < items.length) { const idx = i++; await fn(items[idx], idx); } };
  await Promise.allSettled(Array.from({ length: Math.min(limit, items.length) }, next));
}

// ── Run all ────────────────────────────────────────────────────
runBtn.addEventListener('click', async () => {
  const raw = domainListEl.value
    .split(/\r?\n/)
    .map(d => d.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0])
    .filter(Boolean);
  const domains = [...new Set(raw)];
  if (!domains.length) return;

  // Reset state
  scanAborted = false;
  lastResults = [];
  exportJsonBtn.disabled = true;
  exportCsvBtn.disabled = true;
  runBtn.disabled = true;
  runBtn.textContent = '⏹ Running…';
  tableEl.hidden = false;
  progressWrap.hidden = false;
  progressBar.style.width = '0%';

  // Seed table rows
  tbodyEl.innerHTML = domains.map(d => `
    <tr data-domain="${esc(d)}">
      <td style="font-family:var(--mono)">${esc(d)}</td>
      <td class="st-pending">—</td>
      <td>—</td>
      <td>—</td>
      <td>—</td>
    </tr>`).join('');

  let done = 0;
  const setRow = (d, status, cls, providers, ips, topScore) => {
    const row = tbodyEl.querySelector(`tr[data-domain="${CSS.escape(d)}"]`);
    if (!row) return;
    row.cells[1].className = cls; row.cells[1].textContent = status;
    row.cells[2].textContent = providers;
    row.cells[3].textContent = ips;
    row.cells[4].textContent = topScore;
  };

  await pooled(domains, CONCURRENCY, async domain => {
    if (scanAborted) return;
    setRow(domain, 'scanning…', 'st-scanning', '…', '', '');
    const { status, data } = await scanOne(domain);
    done++;
    const pct = Math.round(done / domains.length * 100);
    progressBar.style.width = pct + '%';
    progressText.textContent = `${done} / ${domains.length}`;

    if (status === 'error') {
      setRow(domain, 'error', 'st-error', data?.message || 'failed', '', '');
      return;
    }
    lastResults.push({ domain, result: data });
    const pvs = Object.entries(data.providers || {});
    const detected = pvs.filter(([, v]) => v.verdict?.detected).sort((a, b) => b[1].verdict.score - a[1].verdict.score);
    const names = detected.map(([id]) => PROVIDER_META[id]?.name || id).join(', ') || 'None';
    const ips = (data.resolvedIPs || []).join(', ') || '—';
    const top = detected[0]?.[1]?.verdict?.score;
    setRow(domain, '✓', 'st-done', names, ips, top != null ? top + '%' : '—');
  });

  runBtn.disabled = false;
  runBtn.textContent = '▶ Scan all';
  exportJsonBtn.disabled = !lastResults.length;
  exportCsvBtn.disabled = !lastResults.length;
});

// ── Export ─────────────────────────────────────────────────────
function dl(name, mime, content) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  chrome.downloads.download({ url, filename: name }, () => setTimeout(() => URL.revokeObjectURL(url), 10000));
}
exportJsonBtn.addEventListener('click', () => {
  if (!lastResults.length) return;
  dl(`cdnwaf-batch-${Date.now()}.json`, 'application/json', JSON.stringify(lastResults, null, 2));
});
exportCsvBtn.addEventListener('click', () => {
  if (!lastResults.length) return;
  const header = ['domain', 'detected_providers', 'top_score', 'resolved_ips'];
  const rows = lastResults.map(({ domain, result }) => {
    const pvs = Object.entries(result.providers || {}).filter(([, v]) => v.verdict?.detected)
      .sort((a, b) => b[1].verdict.score - a[1].verdict.score);
    const names = pvs.map(([id]) => PROVIDER_META[id]?.name || id).join('; ');
    const top = pvs[0]?.[1]?.verdict?.score ?? '';
    const ips = (result.resolvedIPs || []).join('; ');
    return [domain, names, top, ips];
  });
  const csv = [header, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  dl(`cdnwaf-batch-${Date.now()}.csv`, 'text/csv', csv);
});
