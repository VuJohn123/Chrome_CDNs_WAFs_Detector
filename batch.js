const domainListEl   = document.getElementById('domainList');
const csvUploadEl    = document.getElementById('csvUpload');
const runBtn         = document.getElementById('runBtn');
const progressTextEl = document.getElementById('batchProgressText');
const tableEl        = document.getElementById('batchTable');
const tbodyEl        = document.getElementById('batchTbody');

const BATCH_CONCURRENCY = 3;
let lastResults = []; // [{domain, result}]

csvUploadEl.addEventListener('change', () => {
  const file = csvUploadEl.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    // Accept a plain list or a CSV — take the first column of each line.
    const lines = String(reader.result).split(/\r?\n/).map(l => l.split(',')[0].trim()).filter(Boolean);
    domainListEl.value = (domainListEl.value ? domainListEl.value + '\n' : '') + lines.join('\n');
  };
  reader.readAsText(file);
});

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function scanOneDomain(domain) {
  return new Promise(resolve => {
    let settled = false;
    const port = chrome.runtime.connect({ name: 'scan' });
    const finish = (status, data) => { if (settled) return; settled = true; try { port.disconnect(); } catch {} resolve({ status, data }); };
    port.onMessage.addListener(msg => {
      if (msg.type === 'result') finish('done', msg.data);
      else if (msg.type === 'error') finish('error', { message: msg.message });
    });
    port.onDisconnect.addListener(() => finish('error', { message: 'disconnected' }));
    port.postMessage({ action: 'scan', domain, forceRefresh: false });
  });
}

async function runPooled(items, limit, worker) {
  let idx = 0;
  async function next() {
    while (idx < items.length) {
      const i = idx++;
      await worker(items[i], i);
    }
  }
  await Promise.allSettled(Array(Math.min(limit, items.length)).fill(0).map(next));
}

function rowHtml(domain, status) {
  return `<tr data-domain="${escHtml(domain)}">
    <td>${escHtml(domain)}</td>
    <td class="batch-status-${status}">${status}</td>
    <td>—</td><td>—</td>
  </tr>`;
}

runBtn.addEventListener('click', async () => {
  const domains = [...new Set(domainListEl.value.split(/\r?\n/).map(d => d.trim().toLowerCase()).filter(Boolean))];
  if (!domains.length) return;

  lastResults = [];
  runBtn.disabled = true;
  tableEl.hidden = false;
  tbodyEl.innerHTML = domains.map(d => rowHtml(d, 'pending')).join('');

  let done = 0;
  progressTextEl.textContent = `0 / ${domains.length}`;

  await runPooled(domains, BATCH_CONCURRENCY, async domain => {
    const rowEl = tbodyEl.querySelector(`tr[data-domain="${CSS.escape(domain)}"]`);
    if (rowEl) rowEl.querySelector('td:nth-child(2)').outerHTML = `<td class="batch-status-scanning">scanning</td>`;

    const { status, data } = await scanOneDomain(domain);
    done++;
    progressTextEl.textContent = `${done} / ${domains.length}`;

    if (!rowEl) return;
    if (status === 'error') {
      rowEl.querySelector('td:nth-child(2)').outerHTML = `<td class="batch-status-error">error</td>`;
      rowEl.querySelector('td:nth-child(3)').textContent = data?.message || 'failed';
      return;
    }
    lastResults.push({ domain, result: data });
    const detected = Object.entries(data.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => PROVIDER_META[id]?.name || id);
    rowEl.querySelector('td:nth-child(2)').outerHTML = `<td class="batch-status-done">done</td>`;
    rowEl.querySelector('td:nth-child(3)').textContent = detected.length ? detected.join(', ') : 'None detected';
    rowEl.querySelector('td:nth-child(4)').textContent = (data.resolvedIPs || []).join(', ') || '—';
  });

  runBtn.disabled = false;
});

function downloadBlob(filename, mime, content) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  chrome.downloads.download({ url, filename, saveAs: false }, () => setTimeout(() => URL.revokeObjectURL(url), 10000));
}
document.getElementById('exportAllJson').addEventListener('click', () => {
  if (!lastResults.length) return;
  downloadBlob(`cdnwaf-batch-${Date.now()}.json`, 'application/json', JSON.stringify(lastResults, null, 2));
});
document.getElementById('exportAllCsv').addEventListener('click', () => {
  if (!lastResults.length) return;
  const rows = [['domain', 'detected_providers', 'resolved_ips']];
  for (const { domain, result } of lastResults) {
    const detected = Object.entries(result.providers || {}).filter(([, v]) => v.verdict?.detected).map(([id]) => PROVIDER_META[id]?.name || id).join('; ');
    rows.push([domain, detected, (result.resolvedIPs || []).join('; ')]);
  }
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadBlob(`cdnwaf-batch-${Date.now()}.csv`, 'text/csv', csv);
});
