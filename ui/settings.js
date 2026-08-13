/* Aegis Security — settings page */
'use strict';

const SCAN_TOGGLES = [
  ['scan.pup', 'Detect potentially unwanted programs',
    'Flags keygens, bundleware and risk tools that are not malware but are rarely wanted.'],
  ['scan.archives', 'Look inside archives',
    'Examines the contents of ZIP and OOXML containers rather than just the wrapper.'],
  ['intel.auto_update', 'Update definitions automatically',
    'Refreshes threat intelligence in the background every few hours.'],
  ['ui.notifications', 'Show desktop notifications',
    'Pops a toast when a threat is blocked or a shield changes state.']
];

async function loadSettings() {
  SETTINGS = await API.get_settings();
  const s = SETTINGS;

  $('#setScan').innerHTML = SCAN_TOGGLES.map(([k, t, d]) => {
    const on = !!s[k];
    return '<div class="trow ' + (on ? 'on' : 'off') + '">' +
      '<div class="tb"><div class="tt">' + esc(t) + '</div>' +
      '<div class="td">' + esc(d) + '</div></div>' +
      '<div class="sw ' + (on ? 'on' : '') + '" data-k="' + k + '"></div></div>';
  }).join('') +
    '<div class="trow"><div class="tb"><div class="tt">Heuristic sensitivity</div>' +
    '<div class="td">Higher sensitivity catches more novel malware but raises the ' +
    'chance of a false positive.</div></div>' +
    '<select id="setHeur" style="width:150px;flex:0 0 150px">' +
    ['relaxed', 'balanced', 'aggressive'].map(v =>
      '<option value="' + v + '"' + (s['scan.heuristics'] === v ? ' selected' : '') + '>' +
      v[0].toUpperCase() + v.slice(1) + '</option>').join('') + '</select></div>' +
    '<div class="trow"><div class="tb"><div class="tt">Default action on detection</div>' +
    '<div class="td">What Aegis does when the real-time shield catches something.</div></div>' +
    '<select id="setAct" style="width:150px;flex:0 0 150px">' +
    '<option value="quarantine"' + (s['action.default'] === 'quarantine' ? ' selected' : '') +
    '>Quarantine</option><option value="report"' +
    (s['action.default'] === 'report' ? ' selected' : '') + '>Report only</option></select></div>' +
    '<div class="trow"><div class="tb"><div class="tt">Maximum file size to scan</div>' +
    '<div class="td">Files larger than this are skipped to keep scans fast.</div></div>' +
    '<div class="inline" style="flex:0 0 150px"><input type="number" id="setMax" min="1" max="2048" value="' +
    (s['scan.max_file_mb'] || 64) + '"><span class="mut" style="font-size:12px">MB</span></div></div>' +
    '<div class="trow"><div class="tb"><div class="tt">Scanner threads</div>' +
    '<div class="td">More threads scan faster but use more CPU.</div></div>' +
    '<input type="number" id="setThr" min="1" max="32" style="width:150px;flex:0 0 150px" value="' +
    (s['scan.threads'] || 4) + '"></div>';

  $$('#setScan .sw').forEach(sw => sw.onclick = async () => {
    sw.classList.toggle('on');
    const on = sw.classList.contains('on');
    sw.closest('.trow').className = 'trow ' + (on ? 'on' : 'off');
    await API.set_setting(sw.dataset.k, on);
  });
  $('#setHeur').onchange = e => API.set_setting('scan.heuristics', e.target.value);
  $('#setAct').onchange = e => API.set_setting('action.default', e.target.value);
  $('#setMax').onchange = e => API.set_setting('scan.max_file_mb', Number(e.target.value));
  $('#setThr').onchange = e => API.set_setting('scan.threads', Number(e.target.value));

  const up = await API.update_status();
  $('#defInfo').textContent =
    num(up.signatures) + ' hash signatures · ' + num(up.rules) + ' YARA rules · ' +
    num(up.urls) + ' malicious hosts — updated ' + up.last_update_h;

  /* schedules */
  const sch = s._schedules || [];
  $('#schedList').innerHTML = sch.length ? sch.map(x =>
    '<div class="trow ' + (x.enabled ? 'on' : 'off') + '"><div class="tb">' +
    '<div class="tt">' + esc(x.kind[0].toUpperCase() + x.kind.slice(1)) + ' scan — ' +
    esc(x.freq) + ' at ' + String(x.hour).padStart(2, '0') + ':' +
    String(x.minute).padStart(2, '0') + '</div>' +
    '<div class="td">Last run ' + when(x.last_run) + '</div></div>' +
    '<div class="sw ' + (x.enabled ? 'on' : '') + '" data-s="' + x.id + '"></div>' +
    '<button class="btn sm dgr" data-rm="' + x.id + '">Remove</button></div>').join('')
    : '<div class="trow"><div class="tb"><div class="td mut">No scheduled scans configured.</div></div></div>';
  $$('#schedList [data-s]').forEach(sw => sw.onclick = async () => {
    sw.classList.toggle('on');
    await API.schedule_toggle(Number(sw.dataset.s), sw.classList.contains('on'));
  });
  $$('#schedList [data-rm]').forEach(b => b.onclick = async () => {
    await API.schedule_del(Number(b.dataset.rm)); loadSettings();
  });

  /* exclusions */
  const ex = s._exclusions || [];
  $('#exclList').innerHTML = ex.length ? ex.map(x =>
    '<div class="li"><div class="dot" style="background:var(--tx3)"></div>' +
    '<div class="body"><div class="p">' + esc(x.path) + '</div>' +
    (x.note ? '<div class="d dim" style="font-size:11.5px">' + esc(x.note) + '</div>' : '') +
    '</div><button class="btn sm dgr" data-ex="' + x.id + '">Remove</button></div>').join('')
    : '<div class="trow"><div class="tb"><div class="td mut">' +
      'No exclusions. Everything is scanned.</div></div></div>';
  $$('#exclList [data-ex]').forEach(b => b.onclick = async () => {
    await API.exclusion_del(Number(b.dataset.ex)); loadSettings();
  });

  /* ransomware folders */
  const rf = s['ransom.folders'] || [];
  $('#ransomList').innerHTML = rf.map((p, n) =>
    '<div class="li"><div class="dot" style="background:var(--ok)"></div>' +
    '<div class="body"><div class="p">' + esc(p) + '</div></div>' +
    '<button class="btn sm dgr" data-rf="' + n + '">Remove</button></div>').join('') ||
    '<div class="trow"><div class="tb"><div class="td mut">No folders protected.</div></div></div>';
  $$('#ransomList [data-rf]').forEach(b => b.onclick = async () => {
    const list = (SETTINGS['ransom.folders'] || []).slice();
    list.splice(Number(b.dataset.rf), 1);
    await API.set_setting('ransom.folders', list);
    loadSettings();
  });

  /* about */
  const sy = s._system;
  $('#aboutKv').innerHTML =
    '<dt>Product</dt><dd>Aegis Security 2.1 (Premium)</dd>' +
    '<dt>Engine</dt><dd>' + esc(sy.engine) + '</dd>' +
    '<dt>Detection rules</dt><dd>' + esc(sy.yara) + '</dd>' +
    '<dt>Hash signatures</dt><dd>' + num(sy.signatures) + '</dd>' +
    '<dt>Malicious hosts</dt><dd>' + num(sy.urls) + '</dd>' +
    '<dt>Operating system</dt><dd>' + esc(sy.os) + '</dd>' +
    '<dt>Runtime</dt><dd>Python ' + esc(sy.python) + '</dd>' +
    '<dt>Virus Chest</dt><dd>' + esc(s._paths.chest) + '</dd>' +
    '<dt>Intelligence</dt><dd>abuse.ch MalwareBazaar · URLhaus · YARA Forge</dd>';

  await loadStartup();
  await loadSelfDefense();
  await loadGeneral();
  await loadShredSettings();
}

/* General & Notifications: Silent Mode, Passive Mode, data sharing (Avast-style) */
async function loadGeneral() {
  const s = SETTINGS;
  const rows = [
    ['general.silent', 'Silent Mode',
      'Stop all pop-ups, alerts and sounds — ideal for gaming or movies.'],
    ['general.passive', 'Passive Mode',
      'Turn off all active shields so Aegis can run alongside another antivirus (e.g. Norton, McAfee).'],
    ['general.community_iq', 'Share with Community IQ',
      'Send anonymous detection data to Aegis to improve the engine.'],
    ['general.third_party', 'Third-party sharing',
      'Allow sharing anonymised data for analytics/marketing.']
  ];
  $('#setGeneral').innerHTML = rows.map(([k, t, d]) => {
    const on = !!s[k];
    return '<div class="trow ' + (on ? 'on' : 'off') + '"><div class="tb"><div class="tt">' + t +
      '</div><div class="td">' + d + '</div></div>' +
      '<div class="sw ' + (on ? 'on' : '') + '" data-g="' + k + '"></div></div>';
  }).join('') +
    '<div class="trow"><div class="tb"><div class="tt">Pop-up duration</div>' +
    '<div class="td">How long alerts stay on screen (1s for gaming, 20s default).</div></div>' +
    '<div class="inline" style="flex:0 0 130px"><input type="number" id="setPop" min="1" max="60" value="' +
    (s['general.popup_sec'] || 20) + '"><span class="mut" style="font-size:12px">s</span></div></div>';
  $$('#setGeneral .sw').forEach(sw => sw.onclick = async () => {
    const k = sw.dataset.g, on = !sw.classList.contains('on');
    sw.classList.toggle('on');
    sw.closest('.trow').className = 'trow ' + (on ? 'on' : 'off');
    await API.set_setting(k, on);
    if (k === 'general.passive') {
      if (on) { await API.shields_stop(); toast('Passive mode on', 'Active shields disabled', 'warn'); }
      else { await API.shields_all_on(); toast('Active shields restored', '', 'ok'); }
      refreshDash();
    } else toast((on ? 'Enabled ' : 'Disabled ') + k.split('.').pop(), '', on ? 'ok' : 'warn');
  });
  $('#setPop').onchange = e => API.set_setting('general.popup_sec', Number(e.target.value));
}

/* Self-Defense: stop malware from tampering with/uninstalling Aegis */
async function loadSelfDefense() {
  const r = await API.self_defense_status();
  const on = !!r.enabled;
  $('#setSelfDef').innerHTML =
    '<div class="trow ' + (on ? 'on' : 'off') + '"><div class="tb"><div class="tt">Enable Self-Defense</div>' +
    '<div class="td">Deny non-admins write/delete on the Aegis program folder so malware cannot disable or uninstall it. Uncheck only to manually delete Aegis files.</div></div>' +
    '<div class="sw ' + (on ? 'on' : '') + '" id="sdDefSw"></div></div>';
  $('#sdDefSw').onclick = async () => {
    const want = !$('#sdDefSw').classList.contains('on');
    const res = await API.self_defense_set(want);
    if (res.ok) { $('#sdDefSw').classList.toggle('on', want);
      $('#sdDefSw').closest('.trow').className = 'trow ' + (want ? 'on' : 'off');
      toast(want ? 'Self-Defense enabled' : 'Self-Defense disabled', '', want ? 'ok' : 'warn'); }
    else toast('Self-Defense unavailable', res.detail || 'Run as admin to apply', 'bad');
  };
}

/* App Updater — now a dedicated sidebar page (App Updates) */
async function loadApps() {
  const s = await API.apps_status();
  const auto = !!s.enabled;
  const sw = $('#appsAutoSw');
  if (sw) sw.classList.toggle('on', auto);
  const note = $('#appsAutoNote');
  if (note) note.textContent = s.winget
    ? 'Use winget to keep other apps patched in the background.'
    : 'winget not found — install App Installer from the Microsoft Store to enable app updates.';
}
async function appsToggleAuto() {
  const sw = $('#appsAutoSw');
  const want = !sw.classList.contains('on');
  const r = await API.apps_set_auto(want);
  if (r.ok) { sw.classList.toggle('on', want); toast(want ? 'App auto-update on' : 'App auto-update off', '', want ? 'ok' : 'warn'); }
  else toast('Could not change setting', r.error || '', 'bad');
}
async function appsCheckSelf() {
  const out = $('#appsOut');
  if (!out) return;
  out.innerHTML = '<div class="mut"><span class="spin"></span> Checking for an Aegis update…</div>';
  const r = await API.apps_self_check();
  if (r.ok && r.available) {
    out.innerHTML = '<div class="li"><div class="dot" style="background:var(--accent)"></div>' +
      '<div class="body"><div class="t">Update available: v' + esc(r.latest) + '</div>' +
      '<div class="d"><a href="' + esc(r.url) + '" target="_blank" rel="noopener">Download from GitHub</a></div></div></div>';
  } else if (r.ok) {
    out.innerHTML = '<div class="li"><div class="dot" style="background:var(--ok)"></div>' +
      '<div class="body"><div class="t">Aegis is up to date (v' + esc(SETTINGS._system_aegis_ver || '2.2.0') + ')</div></div></div>';
  } else {
    out.innerHTML = '<div class="li"><div class="dot" style="background:var(--warn)"></div>' +
      '<div class="body"><div class="t">Could not reach the update server</div>' +
      '<div class="d">' + esc(r.error || '') + '</div></div></div>';
  }
}
async function appsListUpgrades() {
  const out = $('#appsOut');
  if (!out) return;
  out.innerHTML = '<div class="mut"><span class="spin"></span> Scanning installed apps…</div>';
  const apps = await API.apps_list();
  if (!apps.length) {
    out.innerHTML = '<div class="li"><div class="dot" style="background:var(--ok)"></div>' +
      '<div class="body"><div class="t">All apps up to date</div></div></div>';
    return;
  }
  out.innerHTML = '<div class="list" style="margin-top:6px">' + apps.map((a, n) =>
    '<div class="li"><div class="dot" style="background:var(--warn)"></div>' +
    '<div class="body"><div class="t">' + esc(a.name) + ' <span class="pill medium">' +
    esc(a.current) + ' → ' + esc(a.available) + '</span></div></div>' +
    '<button class="btn sm pri" data-n="' + n + '">Update</button></div>').join('') + '</div>';
  $$('#appsOut [data-n]').forEach(b => b.onclick = async () => {
    const a = apps[Number(b.dataset.n)];
    b.disabled = true; b.textContent = 'Updating…';
    const r = await API.apps_update_one(a.id);
    toast(r.ok ? 'Updated ' + a.name : 'Update failed', '', r.ok ? 'ok' : 'bad');
    appsListUpgrades();
  });
}

/* Shredder default algorithm (mirrors the Shredder page) */
async function loadShredSettings() {
  const algos = await API.shredder_algorithms();
  const cur = SETTINGS['shred.algorithm'] || 'random';
  $('#setShred').innerHTML =
    '<label class="fl">Default shred algorithm</label>' +
    '<select id="setShredAlgo" class="field" style="max-width:320px">' +
    algos.map(a => '<option value="' + a.id + '"' + (a.id === cur ? ' selected' : '') + '>' +
      a.name + ' (' + a.passes + ' pass' + (a.passes > 1 ? 'es' : '') + ')</option>').join('') +
    '</select>';
  $('#setShredAlgo').onchange = async () => {
    await API.set_setting('shred.algorithm', $('#setShredAlgo').value);
    toast('Default shred algorithm set', $('#setShredAlgo').value, 'ok');
  };
}

async function loadStartup() {
  const sw = $('#startupSw');
  if (!sw) return;
  try {
    const r = await API.startup_status();
    sw.classList.toggle('on', !!r.enabled);
  } catch (e) {}
}

async function toggleStartup() {
  const sw = $('#startupSw');
  if (!sw) return;
  const want = !sw.classList.contains('on');
  try {
    const r = want ? await API.startup_enable() : await API.startup_disable();
    if (r.ok) {
      sw.classList.toggle('on', want);
      toast(want ? 'Aegis will launch at startup' : 'Startup launch disabled',
            want ? 'Protected on next logon' : '', want ? 'ok' : 'warn');
    } else {
      toast('Could not change startup', r.detail || '', 'bad');
    }
  } catch (e) {
    toast('Startup toggle failed', '', 'bad');
  }
}

async function schedAdd() {
  const kind = $('#schKind').value, freq = $('#schFreq').value;
  const h = Number($('#schH').value), m = Number($('#schM').value);
  await API.schedule_add(kind + ' scan', kind, freq, h, m);
  toast('Schedule added', kind + ' scan ' + freq + ' at ' +
    String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0'), 'ok');
  loadSettings();
}

async function exclAddFolder() {
  const f = await API.pick_folder();
  if (f && f.length) { await API.exclusion_add(f[0], 'User exclusion'); loadSettings(); }
}
async function exclAddFile() {
  const f = await API.pick_files();
  if (f && f.length) { for (const p of f) await API.exclusion_add(p, 'User exclusion'); loadSettings(); }
}
async function ransomAdd() {
  const f = await API.pick_folder();
  if (!f || !f.length) return;
  const list = (SETTINGS['ransom.folders'] || []).slice();
  if (!list.includes(f[0])) list.push(f[0]);
  await API.set_setting('ransom.folders', list);
  toast('Folder protected', f[0], 'ok');
  loadSettings();
}
