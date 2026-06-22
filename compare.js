function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

const state = { A: null, B: null };

function scanOneDomain(domain, onProgress) {
  return new Promise(resolve => {
    let settled = false;
    const port = chrome.runtime.connect({ name: 'scan' });
    const finish = (status, data) => { if (settled) return; settled = true; try { port.disconnect(); } catch {} resolve({ status, data }); };
    port.onMessage.addListener(msg => {
      if (msg.type === 'progress') onProgress?.(msg);
      else if (msg.type === 'result') finish('done', msg.data);
      else if (msg.type === 'error') finish('error', { message: msg.message });
    });
    port.onDisconnect.addListener(() => finish('error', { message: 'disconnected' }));
    port.postMessage({ action: 'scan', domain, forceRefresh: false });
  });
}

function renderColResult(col, result) {
  const el = document.getElementById(`result${col}`);
  const order = Object.keys(PROVIDER_META);
  const detected = order.filter(id => result.providers?.[id]?.verdict?.detected);
  el.innerHTML = detected.length
    ? detected.map(id => `<div class="result-row hit"><span>${escHtml(PROVIDER_META[id].name)}</span><strong>${result.providers[id].verdict.score}%</strong></div>`).join('')
    : '<div class="empty-state">No providers detected</div>';
}

function renderSummary() {
  const sumEl = document.getElementById('compareSummary');
  if (!state.A || !state.B) { sumEl.innerHTML = ''; return; }
  const order = Object.keys(PROVIDER_META);
  const detA = new Set(order.filter(id => state.A.providers?.[id]?.verdict?.detected));
  const detB = new Set(order.filter(id => state.B.providers?.[id]?.verdict?.detected));
  const onlyA  = [...detA].filter(id => !detB.has(id));
  const onlyB  = [...detB].filter(id => !detA.has(id));
  const shared = [...detA].filter(id => detB.has(id));
  const nameOf = id => PROVIDER_META[id]?.name || id;
  sumEl.innerHTML = `
    ${sectionRow('Used by both', shared.map(nameOf))}
    ${sectionRow('Only domain A', onlyA.map(nameOf))}
    ${sectionRow('Only domain B', onlyB.map(nameOf))}`;
}
function sectionRow(title, items) {
  return `<div style="margin-bottom:10px"><div class="section-header">${escHtml(title)}</div>
    <div style="font-size:12px;color:var(--text-dim);padding:6px 0">${items.length ? escHtml(items.join(', ')) : '—'}</div></div>`;
}

document.querySelectorAll('.scan-col-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const col = btn.dataset.col;
    const domain = document.getElementById(`domain${col}`).value.trim().toLowerCase();
    if (!domain) return;
    const resultEl = document.getElementById(`result${col}`);
    btn.disabled = true;
    resultEl.innerHTML = '<div class="empty-state">Scanning…</div>';
    const { status, data } = await scanOneDomain(domain, msg => {
      resultEl.innerHTML = `<div class="empty-state">${msg.pct}% — ${escHtml(msg.activity || '')}</div>`;
    });
    btn.disabled = false;
    if (status === 'error') { resultEl.innerHTML = `<div class="empty-state">Failed: ${escHtml(data?.message || 'error')}</div>`; return; }
    state[col] = data;
    renderColResult(col, data);
    renderSummary();
  });
});
