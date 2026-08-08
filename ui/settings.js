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
