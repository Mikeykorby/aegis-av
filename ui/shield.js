/* Aegis Security — shields, virus chest, activity log */
'use strict';

const SHIELD_DEFS = [
  ['file', 'File Shield',
    'Scans every file the moment it is created, opened or modified in high-risk folders.'],
  ['web', 'Web Shield',
    'Blocks connections to hosts known to distribute malware, using the live URLhaus feed.'],
  ['behavior', 'Behaviour Shield',
    'Watches running processes for attack patterns — encoded PowerShell, LOLBin abuse, tampering.'],
  ['ransomware', 'Ransomware Shield',
    'Guards your documents with canary files and detects mass-encryption bursts.'],
  ['email', 'Mail Shield',
    'Inspects attachments saved from mail clients before they can be opened.']
];

async function enableProtection() {
  await API.set_protection(true);
  toast('Real-time protection enabled', '', 'ok');
  loadShields(); refreshDash();
}

async function disableProtection() {
  const mins = Number($('#rtpMins').value) || 10;
  const r = await API.disable_protection_for(mins);
  if (r.ok) {
    toast('Protection paused', 'Auto re-enable in ' + mins + ' min', 'warn');
    loadShields(); refreshDash();
  } else toast('Could not pause protection', '', 'bad');
}

/* Master toggle with a label that always reflects the CURRENT state:
   when protection is ON the primary button reads "Disable protection"
   (clicking it turns it off); when OFF it reads "Enable protection". */
async function toggleProtection() {
  const running = API._running;
  if (running) {
    await API.set_protection(false);
    toast('Real-time protection disabled', '', 'warn');
  } else {
    await API.set_protection(true);
    toast('Real-time protection enabled', '', 'ok');
  }
  loadShields(); refreshDash();
}

/* Keep the master-protection panel + titlebar in sync with the engine.
   Called from refreshDash() on every dashboard poll. */
function refreshRtp() {
  const panel = $('#rtpPanel'), status = $('#rtpStatus');
  if (!panel || !status) return;
  const pausedUntil = API._pausedUntil || null;
  const running = API._running;
  const disableBtn = $('#rtpDisable'), mainBtn = $('#rtpMain');
  if (pausedUntil && pausedUntil > Date.now()) {
    const left = Math.max(0, Math.round((pausedUntil - Date.now()) / 1000));
    const m = Math.floor(left / 60), s = left % 60;
    status.textContent = 'Paused — re-enabling in ' + (m ? m + 'm ' : '') + s + 's';
    status.style.color = 'var(--warn)';
    if (disableBtn) disableBtn.disabled = true;
    if (mainBtn) { mainBtn.disabled = false; mainBtn.textContent = 'Enable protection'; }
  } else {
    status.textContent = running ? 'Active — all shields running' : 'Disabled';
    status.style.color = running ? 'var(--ok)' : 'var(--bad)';
    if (disableBtn) disableBtn.disabled = !running;
    if (mainBtn) {
      mainBtn.disabled = false;
      mainBtn.textContent = running ? 'Disable protection' : 'Enable protection';
    }
  }
}

/* drive the panel + titlebar countdown every second while on the page */
let RTP_TICK = null;
async function loadShields() {
  const s = await API.shield_status();
  API._running = s.running;
  API._pausedUntil = (await API.protection_paused_until()) || null;
  $('#shieldList').innerHTML = SHIELD_DEFS.map(([k, name, desc]) => {
    const on = !!s[k];
    return '<div class="trow ' + (on ? 'on' : 'off') + '">' +
      '<div class="ti"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor">' +
      (on ? '<path d="M12 3 5 6v6c0 4.4 3 8.3 7 9.3 4-1 7-4.9 7-9.3V6l-7-3Z" stroke-linejoin="round"/><path d="m9 12 2 2 4-4.5" stroke-linecap="round" stroke-linejoin="round"/>'
          : '<path d="M12 3 5 6v6c0 4.4 3 8.3 7 9.3 4-1 7-4.9 7-9.3V6l-7-3Z" stroke-linejoin="round"/><path d="M12 8v5M12 15.5v.5" stroke-linecap="round"/>') +
      '</svg></div><div class="tb"><div class="tt">' + esc(name) + '</div>' +
      '<div class="td">' + esc(desc) + '</div></div>' +
      '<div class="sw ' + (on ? 'on' : '') + '" data-k="' + k + '"></div></div>';
  }).join('');

  $$('#shieldList .sw').forEach(sw => sw.onclick = async () => {
    const k = sw.dataset.k, turningOn = !sw.classList.contains('on');
    if (!turningOn && (k === 'file' || k === 'ransomware')) {
      modal('Turn off ' + k + ' protection?',
        'This leaves a real attack path unmonitored. Only do this if you are ' +
        'troubleshooting a specific problem.', '',
        [{ label: 'Keep it on' },
         { label: 'Turn off anyway', cls: 'dgr', fn: () => applyShield(k, false) }]);
      return;
    }
    applyShield(k, turningOn);
  });

  $('#shFiles').textContent = num(s.files_checked);
  $('#shProcs').textContent = num(s.procs_checked);
  $('#shAlerts').textContent = num(s.behaviour_alerts + s.canary_alerts);

  refreshRtp();
  if (RTP_TICK) clearInterval(RTP_TICK);
  RTP_TICK = setInterval(refreshRtp, 1000);
}

async function applyShield(k, on) {
  await API.shield_toggle(k, on);
  const st = await API.shield_status();
  if (on && !st.running) await API.shields_start();
  loadShields(); refreshDash();
  toast((on ? 'Enabled ' : 'Disabled ') + k + ' shield', '', on ? 'ok' : 'warn');
}

async function makeEicar() {
  const r = await API.make_eicar();
  if (r.ok) toast('EICAR test file created',
    'Saved to your Desktop. If the File Shield is active it should be detected within seconds.', 'ok');
  else toast('Could not create test file', r.error, 'bad');
}

/* ── virus chest ────────────────────────────────────────── */
async function loadChest() {
  const rows = await API.chest_list();
  $('#chestList').innerHTML = rows.length ? rows.map(r =>
    '<div class="li"><div class="dot" style="background:var(--bad)"></div>' +
    '<div class="body"><div class="t">' + esc(r.threat) + '</div>' +
    '<div class="p">' + esc(r.orig_path) + '</div>' +
    '<div class="d dim" style="font-size:11px">' + esc(r.size_h) + ' · quarantined ' +
    esc(r.when) + (r.engine ? ' · ' + esc(r.engine) : '') + '</div></div>' +
    '<div class="acts">' +
    '<button class="btn sm" data-i="' + r.id + '" data-a="info">Details</button>' +
    '<button class="btn sm" data-i="' + r.id + '" data-a="restore">Restore</button>' +
    '<button class="btn sm dgr" data-i="' + r.id + '" data-a="del">Delete</button>' +
    '</div></div>').join('')
    : emptyState('The chest is empty',
      'Quarantined threats appear here. They are encrypted and cannot execute.');

  $$('#chestList [data-a]').forEach(b => b.onclick = () => {
    const id = Number(b.dataset.i);
    const rec = rows.find(x => x.id === id);
    if (b.dataset.a === 'info') {
      modal('Quarantined item', rec.threat,
        '<dl class="kv"><dt>Original path</dt><dd>' + esc(rec.orig_path) + '</dd>' +
        '<dt>SHA-256</dt><dd>' + esc(rec.sha256 || 'n/a') + '</dd>' +
        '<dt>Size</dt><dd>' + esc(rec.size_h) + '</dd>' +
        '<dt>Detected by</dt><dd>' + esc(rec.engine || 'scan') + '</dd>' +
        '<dt>Quarantined</dt><dd>' + esc(rec.when) + '</dd></dl>');
    } else if (b.dataset.a === 'restore') {
      modal('Restore this file?',
        'The file will be put back and its path added to your exclusions, so Aegis ' +
        'will stop flagging it. Only restore files you are certain are safe.',
        '<div class="mono dim" style="font-size:11.5px;word-break:break-all">' +
        esc(rec.orig_path) + '</div>',
        [{ label: 'Cancel' }, { label: 'Restore file', cls: 'pri', fn: async () => {
          const r = await API.chest_restore(id);
          toast(r.ok ? 'File restored' : 'Restore failed', r.ok ? r.path : r.error,
            r.ok ? 'ok' : 'bad');
          loadChest(); refreshDash();
        } }]);
    } else {
      modal('Delete permanently?',
        'The file will be overwritten and removed. This cannot be undone.', '',
        [{ label: 'Cancel' }, { label: 'Delete forever', cls: 'dgr', fn: async () => {
          const r = await API.chest_delete(id);
          toast(r.ok ? 'Deleted permanently' : 'Delete failed', r.error || '', r.ok ? 'ok' : 'bad');
          loadChest(); refreshDash();
        } }]);
    }
  });
}

async function chestAdd() {
  const f = await API.pick_files();
  if (!f || !f.length) return;
  for (const p of f) {
    const r = await API.chest_add(p);
    toast(r.ok ? 'Added to chest' : 'Could not add', r.ok ? base(p) : r.error,
      r.ok ? 'ok' : 'bad');
  }
  loadChest(); refreshDash();
}

function chestEmpty() {
  modal('Empty the Virus Chest?',
    'Every quarantined file will be securely overwritten and deleted. This cannot be undone.',
    '', [{ label: 'Cancel' }, { label: 'Empty chest', cls: 'dgr', fn: async () => {
      const r = await API.chest_empty();
      toast('Chest emptied', r.deleted + ' item(s) removed', 'ok');
      loadChest(); refreshDash();
    } }]);
}

/* ── activity log ───────────────────────────────────────── */
let LOGKIND = '';
$$('#logTabs .tab').forEach(t => t.onclick = () => {
  $$('#logTabs .tab').forEach(x => x.classList.remove('on'));
  t.classList.add('on'); LOGKIND = t.dataset.k; loadLog();
});

async function loadLog() {
  const rows = await API.event_log(LOGKIND, 200);
  $('#logList').innerHTML = rows.length ? rows.map(e =>
    '<div class="li"><div class="dot" style="background:' +
    (SEVCOL[e.severity] || 'var(--tx3)') + '"></div><div class="body">' +
    '<div class="t">' + esc(e.title) +
    '<span class="pill ' + esc(e.severity) + '">' + esc(e.kind) + '</span></div>' +
    (e.detail ? '<div class="d">' + esc(e.detail) + '</div>' : '') +
    (e.path ? '<div class="p">' + esc(e.path) + '</div>' : '') +
    '</div><div class="when">' + esc(e.when) + '</div></div>').join('')
    : emptyState('Nothing logged yet', 'Activity in this category will appear here.');
}

/* ── web shield page ────────────────────────────────────── */
async function loadWeb() {
  const s = await API.get_settings();
  const st = await API.shield_status();
  $('#webHosts').textContent = num(s._system.urls);
  $('#webSigs').textContent = num(s._system.signatures);
  $('#webBlocked').textContent = num(st.web_blocked || 0);

  const tr = await API.browser_tracks();
  $('#tracksList').innerHTML = tr.length ? tr.map(b =>
    '<div class="li"><div class="dot" style="background:var(--blue)"></div>' +
    '<div class="body"><div class="t">' + esc(b.browser) + '</div>' +
    '<div class="d">' + b.items.map(i => esc(i.name) + ' (' + esc(i.size) + ')').join(' · ') +
    '</div></div></div>').join('')
    : emptyState('No browser data found', 'Aegis could not locate a supported browser profile.');
}

async function checkUrl() {
  const v = $('#urlIn').value.trim();
  if (!v) return;
  const r = await API.check_url(v);
  $('#urlOut').innerHTML =
    '<div class="li" style="border-radius:8px;border:1px solid ' +
    (r.blocked ? 'rgba(255,77,79,.4)' : 'rgba(61,220,132,.35)') + '">' +
    '<div class="dot" style="background:' + (r.blocked ? 'var(--bad)' : 'var(--ok)') + '"></div>' +
    '<div class="body"><div class="t">' + esc(r.host) +
    '<span class="pill ' + (r.blocked ? 'critical' : 'ok') + '">' +
    (r.blocked ? 'blocked' : 'no match') + '</span></div><div class="d">' +
    esc(r.blocked ? r.reason
      : 'This host is not on the malware distribution list. That is not a guarantee of safety.') +
    '</div></div></div>';
}
