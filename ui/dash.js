/* Aegis Security — dashboard + scanning */
'use strict';

let POLL = null;

/* ── dashboard ──────────────────────────────────────────── */
async function refreshDash() {
  if (!API) return;
  let d;
  try { d = await API.dashboard(); } catch (e) { return; }

  const hero = $('#hero'), mark = $('#heroMark'), sh = $('#heroShield');
  const map = {
    protected: ['ok', '#3ddc84', "You're protected",
      'All core shields are running and your definitions are current.',
      'm35 49 11 11 20-22'],
    attention: ['warn', '#ffa116', 'Attention needed',
      'Aegis is running, but some items need your review.',
      'M50 32v22M50 64v2'],
    at_risk: ['bad', '#ff4d4f', "You're at risk",
      'Critical protection is disabled. Resolve the issues below.',
      'M38 38l24 24M62 38L38 62']
  };
  const m = map[d.state] || map.protected;
  hero.className = 'hero ' + m[0];
  sh.style.color = m[1];
  $('#heroTitle').textContent = m[2];
  $('#heroDesc').textContent = m[3];
  mark.setAttribute('d', m[4]);

  $('#issues').innerHTML = d.issues.length
    ? '<div class="list" style="margin-bottom:22px">' + d.issues.map(i =>
      '<div class="li"><div class="dot" style="background:' + (SEVCOL[i.level] || 'var(--warn)') +
      '"></div><div class="body"><div class="t">' + esc(i.title) + '</div>' +
      '<div class="d">' + esc(i.detail) + '</div></div>' +
      '<div class="acts"><button class="btn sm pri" data-act="' + esc(i.action) + '">' +
      esc(i.cta) + '</button></div></div>').join('') + '</div>'
    : '';
  $$('#issues [data-act]').forEach(b => b.onclick = () => {
    const a = b.dataset.act;
    if (a === 'shields_on') API.shields_all_on().then(() => { toast('Real-time protection enabled', '', 'ok'); refreshDash(); });
    else if (a === 'update') doUpdate();
    else if (a === 'smart') runScan('smart');
    else if (a.startsWith('goto:')) go(a.slice(5));
  });

  if ($('#sBlocked')) $('#sBlocked').textContent = num(d.totals.blocked);
  if ($('#sChecked')) $('#sChecked').textContent = num(d.totals.checked);
  if ($('#sScans')) $('#sScans').textContent = num(d.totals.scans);
  if ($('#sChest')) $('#sChest').textContent = num(d.chest_count);

  // Titlebar status badge — reflects the real protection state so it
  // flips out of "PROTECTED" the moment any shield is switched off (or paused).
  const tray = $('#trayStatus'), dot = $('#trayDot'), label = $('#trayLabel');
  if (tray && dot && label) {
    let tv = { protected: ['ok', 'PROTECTED'], attention: ['warn', 'ATTENTION'],
               at_risk: ['bad', 'AT RISK'] }[d.state] || ['ok', 'PROTECTED'];
    // If protection is paused with auto re-enable, show PAUSED explicitly.
    if (API._pausedUntil && API._pausedUntil > Date.now()) tv = ['warn', 'PAUSED'];
    dot.className = 'dot ' + tv[0];
    label.textContent = tv[1];
    tray.classList.toggle('bad', d.state === 'at_risk' || tv[0] === 'warn');
  }

  const cb = $('#chestBadge');
  cb.textContent = d.chest_count;
  cb.classList.toggle('hidden', !d.chest_count);

  $('#navDefs').textContent = d.intel.last_update_h;
  $('#navRules').textContent = num(d.intel.rules);

  $('#recent').innerHTML = d.events.length ? d.events.map(e =>
    '<div class="li"><div class="dot" style="background:' + (SEVCOL[e.severity] || 'var(--tx3)') +
    '"></div><div class="body"><div class="t">' + esc(e.title) + '</div>' +
    (e.detail ? '<div class="d">' + esc(e.detail) + '</div>' : '') +
    '</div><div class="when">' + when(e.ts) + '</div></div>').join('')
    : emptyState('No activity yet', 'Actions and detections will appear here.');
}

/* ── start / control scans ──────────────────────────────── */
async function runScan(kind, paths) {
  window.LAST_SCAN_KIND = kind;
  go('scan');
  const r = await API.start_scan(kind, paths || null);
  if (!r.ok) { toast('Cannot start scan', r.error, 'warn'); return; }
  $('#scanPick').classList.add('hidden');
  $('#scanDoneView').classList.add('hidden');
  $('#scanRun').classList.remove('hidden');
  $('#liveThreats').innerHTML = '';
  $('#btnPause').textContent = 'Pause';
  if (POLL) clearInterval(POLL);
  POLL = setInterval(tickScan, 400);
}

async function pickCustom() {
  const f = await API.pick_folder();
  if (f && f.length) runScan('custom', f);
}

async function togglePause() {
  const b = $('#btnPause');
  if (b.textContent === 'Pause') { await API.pause_scan(); b.textContent = 'Resume'; }
  else { await API.resume_scan(); b.textContent = 'Pause'; }
}

async function tickScan() {
  let s;
  try { s = await API.scan_status(); } catch (e) { return; }
  const pct = s.percent || 0;
  $('#scanPct').textContent = Math.round(pct) + '%';
  $('#ringFg').style.strokeDashoffset = (527.8 * (1 - pct / 100)).toFixed(1);
  $('#scanState').textContent =
    s.state === 'enumerating' ? 'building list' : (s.state || '');
  $('#scanFile').textContent = s.current || '\u00a0';
  $('#scanDone').textContent = num(s.done);
  $('#scanTot').textContent = num(s.total);
  $('#scanThr').textContent = num(s.threat_count);
  $('#scanEta').textContent = s.eta ? dur(s.eta) : '—';

  if (s.threats && s.threats.length) {
    $('#liveThreats').innerHTML = '<h2>Detected <span class="cnt">' +
      s.threats.length + '</span></h2><div class="list">' +
      s.threats.slice(-8).reverse().map(t => threatRow(t, false)).join('') + '</div>';
  }
  if (['done', 'cancelled', 'error'].includes(s.state)) {
    clearInterval(POLL); POLL = null; onScanFinished(s);
  }
}

/* ── results ────────────────────────────────────────────── */
function threatRow(t, actions) {
  const sev = t.severity || 'medium';
  const reason = (t.detections && t.detections[0]) ? t.detections[0].reason : '';
  const engines = (t.detections || []).map(d => d.engine)
    .filter((v, i, a) => a.indexOf(v) === i).join(', ');
  return '<div class="li" data-path="' + esc(t.path) + '">' +
    '<div class="dot" style="background:' + (SEVCOL[sev] || 'var(--warn)') + '"></div>' +
    '<div class="body"><div class="t">' + esc(t.name || 'Threat') +
    '<span class="pill ' + esc(sev) + '">' + esc(sev) + '</span>' +
    (t.resolved ? '<span class="pill done">' + esc(t.action || 'resolved') + '</span>' : '') +
    '</div><div class="p">' + esc(t.path) + '</div>' +
    (reason ? '<div class="d">' + esc(reason) + '</div>' : '') +
    (engines ? '<div class="d dim" style="font-size:11px">Engines: ' + esc(engines) +
      ' · ' + bytes(t.size) + '</div>' : '') +
    '</div>' + (actions && !t.resolved ?
      '<div class="acts">' +
      '<button class="btn sm pri" data-a="quarantine">Quarantine</button>' +
      '<button class="btn sm dgr" data-a="delete">Delete</button>' +
      '<button class="btn sm gho" data-a="ignore">Ignore</button></div>' : '') +
    '</div>';
}

function onScanFinished(s) {
  if (POLL) { clearInterval(POLL); POLL = null; }
  $('#scanRun').classList.add('hidden');
  $('#scanDoneView').classList.remove('hidden');
  const n = (s.threats || []).length;
  const hero = $('#resHero'), shield = $('#resShield');
  hero.className = 'hero ' + (n ? 'bad' : 'ok');
  shield.style.color = n ? '#ff4d4f' : '#3ddc84';
  $('#resMark').setAttribute('d', n ? 'M38 38l24 24M62 38L38 62' : 'm35 49 11 11 20-22');
  $('#resTitle').textContent = n
    ? n + (n === 1 ? ' threat found' : ' threats found')
    : (s.state === 'cancelled' ? 'Scan stopped' : 'No threats found');
  $('#resDesc').textContent = num(s.done) + ' files examined in ' + dur(s.elapsed) +
    (s.skipped ? ' · ' + num(s.skipped) + ' skipped' : '') +
    (n ? '. Review the items below and choose an action.'
      : '. This PC looks clean.');

  $('#resActs').innerHTML = (n
    ? '<button class="btn pri" onclick="resolveAll(\'quarantine\')">Quarantine all</button>'
    : '') +
    '<button class="btn" onclick="scanAgain()">Scan again</button>' +
    '<button class="btn" onclick="backToScans()">Back to scans</button>';

  $('#resList').innerHTML = n
    ? '<h2>Detections <span class="cnt">' + n + '</span></h2><div class="list">' +
      s.threats.map(t => threatRow(t, true)).join('') + '</div>'
    : '';

  $$('#resList [data-a]').forEach(b => b.onclick = async () => {
    const row = b.closest('.li');
    const path = row.dataset.path;
    const t = s.threats.find(x => x.path === path);
    b.disabled = true;
    const r = await API.resolve_threat(path, (t && t.name) || 'Threat',
      b.dataset.a, (t && t.sha256) || '');
    if (r.ok) {
      if (t) { t.resolved = true; t.action = b.dataset.a; }
      row.outerHTML = threatRow(Object.assign({}, t, { resolved: true, action: b.dataset.a }), false);
      toast('Threat ' + b.dataset.a + 'd', base(path), 'ok');
      refreshDash();
    } else { b.disabled = false; toast('Action failed', r.error, 'bad'); }
  });
  refreshDash();
}

async function resolveAll(action) {
  const r = await API.resolve_all(action);
  if (r.ok) {
    toast('Resolved ' + r.resolved + ' threat(s)',
      r.failed ? r.failed + ' could not be handled' : 'Moved to the Virus Chest', 'ok');
    const s = await API.scan_status();
    onScanFinished(s);
  }
}

function backToScans() {
  $('#scanDoneView').classList.add('hidden');
  $('#scanPick').classList.remove('hidden');
  loadScanHistory();
}

/* Re-run the scan that produced the current results, straight from the
   results screen. The backend allows a new scan once the previous one is
   done, but the results view previously only offered "Back to scans", which
   made it look like you couldn't scan again. */
function scanAgain() {
  const kind = (window.LAST_SCAN_KIND || 'smart');
  runScan(kind);
}

async function loadScanHistory() {
  const h = await API.scan_history();
  $('#scanHist').innerHTML = h.length ? h.map(s =>
    '<div class="li"><div class="dot" style="background:' +
    (s.threats ? 'var(--bad)' : 'var(--ok)') + '"></div><div class="body">' +
    '<div class="t">' + esc(s.kind[0].toUpperCase() + s.kind.slice(1)) + ' scan' +
    (s.threats ? '<span class="pill high">' + s.threats + ' found</span>'
      : '<span class="pill ok">clean</span>') + '</div>' +
    '<div class="d">' + num(s.files) + ' files · ' + dur(s.duration) + '</div></div>' +
    '<div class="when">' + when(s.ts) + '</div></div>').join('')
    : emptyState('No scans yet', 'Run a Smart Scan to get started.');
}

/* ── boot-time scan ─────────────────────────────────────── */
async function bootScanDialog() {
  const st = await API.bootscan_status();
  modal('Boot-Time Scan',
    'Runs before Windows finishes starting, so rootkits and drivers that hide ' +
    'themselves once the desktop loads can still be seen. Requires Administrator.',
    '<div class="mut" style="font-size:12.5px">Current state: <b>' +
    (st.scheduled ? 'scheduled for next boot' : 'not scheduled') + '</b></div>',
    st.scheduled
      ? [{ label: 'Cancel scheduled scan', cls: 'dgr', fn: async () => {
          const r = await API.bootscan_cancel();
          toast(r.ok ? 'Boot-time scan cancelled' : 'Could not cancel', r.detail || '', r.ok ? 'ok' : 'warn');
        } }, { label: 'Close' }]
      : [{ label: 'Schedule for next boot', cls: 'pri', fn: async () => {
          const r = await API.bootscan_schedule();
          toast(r.ok ? 'Boot-time scan scheduled' : 'Scheduling failed',
            r.ok ? 'It will run the next time this PC starts.' : (r.error || r.detail),
            r.ok ? 'ok' : 'bad');
        } }, { label: 'Cancel' }]);
}
