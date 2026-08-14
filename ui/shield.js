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

/* Per-shield sub-settings, rendered inside an expandable row. */
const SHIELD_CFG = {
  file: [
    ['autorun', 'Scan Auto-Run', 'Scan USB/DVD auto-start files the moment a drive is mounted.'],
    ['onexecute', 'Scan programs when executing', 'Scan applications the moment they launch.'],
    ['openwrite', 'Scan files when opening/writing', 'Scan a file every time it is opened or saved.']
  ],
  behavior: [
    ['sensitivity', 'sensitivity', 'Behaviour sensitivity',
      'Low raises fewer alerts; High is paranoid mode with more false positives.']
  ],
  web: [
    ['https', 'HTTPS Scanning', 'Scan encrypted (HTTPS) web traffic. Turn off to fix some browser cert errors.'],
    ['script', 'Script Scanning', 'Check JavaScript for drive-by attacks. Turn off only if it breaks a site.'],
    ['quic', 'QUIC / HTTP3 Scanning', 'Scan Google\u2019s modern QUIC protocol.']
  ],
  email: [
    ['inbound', 'Scan Inbound (POP3/IMAP)', 'Scan incoming email attachments.'],
    ['outbound', 'Scan Outbound (SMTP)', 'Scan attachments you send.'],
    ['signature', 'Add Signature', 'Add a \u201cScanned by Aegis\u201d footer to outgoing mail.']
  ],
  ransomware: [
    ['mode', 'mode', 'Ransomware mode',
      'Smart auto-allows trusted apps; Strict asks before any protected-folder write.']
  ]
};

const SENS_OPTS = ['low', 'balanced', 'high'];
const RANSOM_OPTS = ['smart', 'strict'];

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
  // engine stores paused_until in SECONDS; convert to ms for Date.now() compare
  const pausedUntil = (API._pausedUntil || 0) * 1000;
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
  const cfg = s;

  $('#shieldList').innerHTML = SHIELD_DEFS.map(([k, name, desc]) => {
    const on = !!s[k];
    const sub = SHIELD_CFG[k] || [];
    let inner = '';
    if (sub.length) {
      inner = '<div class="shcfg">' + sub.map(o => {
        if (o[0] === 'sensitivity') {
          const val = (cfg.behavior_cfg && cfg.behavior_cfg.sensitivity) || 'balanced';
          return '<div class="trow"><div class="tb"><div class="tt">' + o[2] + '</div>' +
            '<div class="td">' + o[3] + '</div></div>' +
            '<select class="shsel" data-k="' + k + '" data-sub="sensitivity" style="width:130px;flex:0 0 130px">' +
            SENS_OPTS.map(v => '<option value="' + v + '"' + (v === val ? ' selected' : '') + '>' +
              v[0].toUpperCase() + v.slice(1) + '</option>').join('') + '</select></div>';
        }
        if (o[0] === 'mode') {
          const val = (cfg.ransomware_cfg && cfg.ransomware_cfg.mode) || 'smart';
          return '<div class="trow"><div class="tb"><div class="tt">' + o[2] + '</div>' +
            '<div class="td">' + o[3] + '</div></div>' +
            '<select class="shsel" data-k="' + k + '" data-sub="mode" style="width:130px;flex:0 0 130px">' +
            RANSOM_OPTS.map(v => '<option value="' + v + '"' + (v === val ? ' selected' : '') + '>' +
              v[0].toUpperCase() + v.slice(1) + '</option>').join('') + '</select></div>';
        }
        const map = ({ file: cfg.file_cfg, web: cfg.web_cfg, email: cfg.email_cfg })[k] || {};
        const subOn = map[o[0]] !== false;
        return '<div class="trow"><div class="tb"><div class="tt">' + o[1] + '</div>' +
          '<div class="td">' + o[2] + '</div></div>' +
          '<div class="sw ' + (subOn ? 'on' : '') + '" data-k="' + k + '" data-sub="' + o[0] + '"></div></div>';
      }).join('') + '</div>';
    }
    return '<div class="shieldRow" data-k="' + k + '">' +
      '<div class="trow ' + (on ? 'on' : 'off') + ' head">' +
      '<div class="ti"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor">' +
      (on ? '<path d="M12 3 5 6v6c0 4.4 3 8.3 7 9.3 4-1 7-4.9 7-9.3V6l-7-3Z" stroke-linejoin="round"/><path d="m9 12 2 2 4-4.5" stroke-linecap="round" stroke-linejoin="round"/>'
          : '<path d="M12 3 5 6v6c0 4.4 3 8.3 7 9.3 4-1 7-4.9 7-9.3V6l-7-3Z" stroke-linejoin="round"/><path d="M12 8v5M12 15.5v.5" stroke-linecap="round"/>') +
      '</svg></div><div class="tb"><div class="tt">' + esc(name) + '</div>' +
      '<div class="td">' + esc(desc) + '</div></div>' +
      '<div class="sw ' + (on ? 'on' : '') + ' main" data-k="' + k + '"></div>' +
      (sub.length ? '<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m6 9 6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg>' : '') +
      '</div>' + inner + '</div>';
  }).join('');

  // main shield toggles
  $$('#shieldList .sw.main').forEach(sw => sw.onclick = async (e) => {
    e.stopPropagation();
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

  // expand/collapse on header click (not on the switch)
  $$('#shieldList .shieldRow').forEach(row => {
    const head = row.querySelector('.head');
    head.onclick = () => row.classList.toggle('exp');
  });

  // sub-setting switches + selects
  $$('#shieldList .shcfg .sw').forEach(sw => sw.onclick = async () => {
    const k = sw.dataset.k, sub = sw.dataset.sub;
    const turningOn = !sw.classList.contains('on');
    sw.classList.toggle('on');
    sw.closest('.trow').className = 'trow ' + (turningOn ? 'on' : 'off');
    await API.shield_config_set(k, sub, turningOn);
    toast((turningOn ? 'Enabled ' : 'Disabled ') + sub, '', turningOn ? 'ok' : 'warn');
  });
  $$('#shieldList .shcfg select.shsel').forEach(sel => sel.onchange = async () => {
    const k = sel.dataset.k, sub = sel.dataset.sub, val = sel.value;
    if (sub === 'sensitivity') await API.shield_sensitivity_set(val);
    else if (sub === 'mode') await API.ransomware_mode_set(val);
    toast('Updated ' + k + ' shield', sub + ' = ' + val, 'ok');
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

/* ── kernel companion page ─────────────────────────────── */ 
function _kernRow(label, val, cls) {
  return '<div class="row"><span>' + esc(label) + '</span>' +
    '<span class="v ' + cls + '">' + esc(val) + '</span></div>';
}

function _kernBadge(state) {
  if (state === 'active') return ['ok', 'Kernel companion active'];
  if (state === 'inactive') return ['', 'Kernel companion off — user-mode shields only'];
  if (state === 'missing-driver') return ['bad', 'ON but driver missing'];
  if (state === 'blocked') return ['bad', 'ON but OS will not load driver'];
  return ['', 'Unknown'];
}

async function loadKernel() {
  let st;
  try { st = await API.kernel_status(); }
  catch (e) { $('#kernState').textContent = 'Could not query kernel state.'; return; }

  const [cls, label] = _kernBadge(st.state);
  const el = $('#kernState');
  el.className = 'kstat ' + cls;
  el.textContent = label;

  $('#kernSw').classList.toggle('on', !!st.enabled);
  $('#kernToggleDesc').textContent = st.loadable
    ? 'Enforce blocking and self-defense from kernel mode.'
    : 'Turn on to remember the choice; the driver still needs the requirements below.';

  const rows = [
    _kernRow('Architecture (x64 required)', st.arch + (st.is_x64 ? '' : ' — unsupported'), st.is_x64 ? 'pass' : 'fail'),
    _kernRow('Administrator', st.admin ? 'yes' : 'no', st.admin ? 'pass' : 'fail'),
    _kernRow('Test Signing', st.test_signing, st.test_signing === 'on' ? 'pass' : (st.test_signing === 'off' ? 'fail' : 'unk')),
    _kernRow('Secure Boot', st.secure_boot, st.secure_boot === 'off' ? 'pass' : (st.secure_boot === 'unknown' ? 'unk' : 'fail')),
    _kernRow('aegis_kernel.sys present', st.driver_present ? 'yes' : 'no', st.driver_present ? 'pass' : 'fail'),
    _kernRow('Agent present', st.agent_present ? 'yes' : 'no', st.agent_present ? 'pass' : 'unk'),
  ];
  $('#kernCompat').innerHTML = rows.join('');

  $('#kernNote').textContent = st.detail + (st.issues && st.issues.length
    ? '\n\nTo enable: ' + st.issues.join(' ')
    : '');

  const n2 = $('#kernNote2');
  if (n2) {
    n2.textContent = st.driver_present
      ? 'Driver present: ' + (st.driver_path || '')
      : 'No driver bundled. This build does not auto-install a kernel driver — '
        + 'you must build aegis_kernel.sys (in the aegis-kernel repo) and drop it '
        + 'into the kernel directory, or provide a WHQL-signed driver.';
  }
}

async function kernTestSign() {
  const btn = $('#kernNote');
  try {
    const r = await API.kernel_enable_test_signing();
    if (r.ok) {
      toast('Test Signing enabled — reboot to apply', r.detail || '', 'ok');
      $('#kernState').textContent = 'Reboot required';
    } else {
      toast('Could not enable Test Signing', r.error || '', 'warn');
    }
  } catch (e) {
    toast('Test Signing action unavailable', 'Run the desktop app as Administrator.', 'warn');
  }
  loadKernel();
}

async function kernToggle() {
  const on = !$('#kernSw').classList.contains('on');
  const r = on ? await API.kernel_enable() : await API.kernel_disable();
  if (r && r.warning) { /* surfaced via detail on reload */ }
  loadKernel();
}
