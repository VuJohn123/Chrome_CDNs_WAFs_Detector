'use strict';

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

const state = { A: null, B: null };

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
    port.onDisconnect.addListener(() => done('error', { message: 'Disconnected' }));
    setTimeout(() => done('error', { message: 'Timeout' }), 60000);
    port.postMessage({ action: 'scan', domain, forceRefresh: false });
  });
}

function renderCol(col, result) {
  const el = document.getElementById(`result${col}`);
  const order = Object.keys(PROVIDER_META);
  const detected = order.filter(id => result.providers?.[id]?.verdict?.detected)
    .sort((a, b) => (result.providers[b].verdict.score || 0) - (result.providers[a].verdict.score || 0));

  if (!detected.length) {
    el.innerHTML = '<div style="color:var(--text-faint);font-size:11.5px;padding:8px 0;font-style:italic">No providers detected</div>';
    return;
  }
  el.innerHTML = detected.map(id => {
    const pv = result.providers[id];
    const color = PROVIDER_META[id]?.color || 'var(--accent)';
    return `<div class="col-result-row hit" style="border-left:3px solid ${esc(color)}">
      <span>${esc(PROVIDER_META[id]?.name || id)}</span>
      <span class="pct">${pv.verdict.score}%</span>
    </div>`;
  }).join('');
}

function renderSummary() {
  const sum = document.getElementById('compareSummary');
  if (!state.A || !state.B) { sum.hidden = true; return; }

  const order = Object.keys(PROVIDER_META);
  const dA = new Set(order.filter(id => state.A.providers?.[id]?.verdict?.detected));
  const dB = new Set(order.filter(id => state.B.providers?.[id]?.verdict?.detected));
  const shared = order.filter(id => dA.has(id) && dB.has(id));
  const onlyA  = order.filter(id => dA.has(id) && !dB.has(id));
  const onlyB  = order.filter(id => !dA.has(id) && dB.has(id));
  const name = id => esc(PROVIDER_META[id]?.name || id);

  const chips = (ids, cls) => ids.length
    ? ids.map(id => `<span class="summary-chip ${cls}">${name(id)}</span>`).join('')
    : '<span class="summary-empty">—</span>';

  document.getElementById('chipsShared').innerHTML = chips(shared, 'shared');
  document.getElementById('chipsOnlyA').innerHTML  = chips(onlyA, 'only-a');
  document.getElementById('chipsOnlyB').innerHTML  = chips(onlyB, 'only-b');
  sum.hidden = false;
}

document.querySelectorAll('.scan-col-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const col = btn.dataset.col;
    const input = document.getElementById(`domain${col}`);
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!domain) { input.focus(); return; }

    const resultEl = document.getElementById(`result${col}`);
    btn.disabled = true;
    btn.textContent = `Scanning ${col}…`;
    resultEl.innerHTML = '<div style="color:var(--text-faint);font-size:11.5px;padding:8px 0">Scanning…</div>';
    state[col] = null;
    document.getElementById('compareSummary').hidden = true;

    const { status, data } = await scanOne(domain);
    btn.disabled = false;
    btn.textContent = `Scan ${col}`;

    if (status === 'error') {
      resultEl.innerHTML = `<div style="color:var(--red);font-size:11.5px;padding:8px 0">Failed: ${esc(data?.message || 'error')}</div>`;
      return;
    }
    state[col] = data;
    renderCol(col, data);
    renderSummary();
  });
});
