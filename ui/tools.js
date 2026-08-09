/* Aegis Security — Wi-Fi, health, junk, startup, breach, settings */
'use strict';

/* ── Wi-Fi Inspector ────────────────────────────────────── */
async function wifiScan() {
  const b = $('#wifiBtn');
  b.disabled = true; b.innerHTML = '<span class="spin"></span> Scanning network…';
  let r;
  try { r = await API.wifi_scan(); }
  finally { b.disabled = false; b.textContent = 'Scan network'; }

  const i = r.info;
  $('#wifiOut').innerHTML =
    '<div class="grid g4" style="margin-bottom:18px">' +
    scoreCard(r.score, 'Network score') +
    statCard(i.ssid || 'Wired', 'Network') +
    statCard(i.auth || 'n/a', 'Encryption') +
    statCard(r.issues, 'Issues found') + '</div>' +
    '<h2>Findings <span class="cnt">' + r.findings.length + '</span></h2>' +
    '<div class="list" style="margin-bottom:22px">' +
    r.findings.map(findingRow).join('') + '</div>' +
    '<h2>Devices on this network <span class="cnt">' + i.devices.length + '</span></h2>' +
    '<div class="list">' + (i.devices.length ? i.devices.map(d =>
      '<div class="li"><div class="dot" style="background:' +
      (d.is_gateway ? 'var(--acc)' : d.is_self ? 'var(--ok)' : 'var(--blue)') + '"></div>' +
      '<div class="body"><div class="t">' + esc(d.ip) +
      (d.is_gateway ? '<span class="pill info">router</span>' : '') +
      (d.is_self ? '<span class="pill ok">this pc</span>' : '') + '</div>' +
      '<div class="d dim" style="font-size:11.5px" class="mono">' + esc(d.mac) +
      ' · ' + esc(d.vendor) + '</div></div></div>').join('')
      : emptyState('No devices resolved', 'The ARP table returned no neighbours.')) + '</div>';
}

function statCard(v, k) {
  return '<div class="card stat"><div class="v" style="font-size:19px">' +
    esc(v) + '</div><div class="k">' + esc(k) + '</div></div>';
}
function scoreCard(score, label) {
  const col = score >= 80 ? 'var(--ok)' : score >= 55 ? 'var(--warn)' : 'var(--bad)';
  return '<div class="card stat"><div class="v" style="color:' + col + '">' + score +
    '<span style="font-size:14px;color:var(--tx3)">/100</span></div>' +
    '<div class="k">' + esc(label) + '</div>' +
    '<div class="bar"><i style="width:' + score + '%;background:' + col + '"></i></div></div>';
}

/* ── System Health ──────────────────────────────────────── */
async function healthScan() {
  const b = $('#healthBtn');
  b.disabled = true; b.innerHTML = '<span class="spin"></span> Checking…';
  let r;
  try { r = await API.health_scan(); }
  finally { b.disabled = false; b.textContent = 'Run health check'; }

  const i = r.info;
  $('#healthOut').innerHTML =
    '<div class="grid g4" style="margin-bottom:18px">' +
    scoreCard(r.score, 'Health score') +
    '<div class="card stat"><div class="v" style="font-size:19px">' + (i.cpu || 0) + '%</div>' +
    '<div class="k">CPU load</div><div class="bar"><i style="width:' + (i.cpu || 0) + '%"></i></div></div>' +
    '<div class="card stat"><div class="v" style="font-size:19px">' + (i.ram_used || 0) +
    ' / ' + (i.ram_total || 0) + ' GB</div><div class="k">Memory</div>' +
    '<div class="bar"><i class="' + barCls(i.ram_pct) + '" style="width:' + (i.ram_pct || 0) + '%"></i></div></div>' +
    '<div class="card stat"><div class="v" style="font-size:19px">' + (i.disk_free || 0) +
    ' GB free</div><div class="k">System drive</div>' +
    '<div class="bar"><i class="' + barCls(i.disk_pct) + '" style="width:' + (i.disk_pct || 0) + '%"></i></div></div>' +
    '</div>' +
    '<h2>Security posture <span class="cnt">' + r.findings.length + '</span></h2>' +
    '<div class="list">' + r.findings.map(findingRow).join('') + '</div>' +
    '<div class="mut" style="font-size:12px;margin-top:12px">Uptime ' + dur(i.uptime) +
    ' · ' + num(i.procs) + ' processes running</div>';
}
function barCls(p) { return p > 88 ? 'bad' : p > 75 ? 'warn' : 'ok'; }

/* ── Junk Cleanup ───────────────────────────────────────── */
let JUNK = null;
async function junkAnalyze() {
  const b = $('#junkBtn');
  b.disabled = true; b.innerHTML = '<span class="spin"></span> Analysing…';
  try { JUNK = await API.junk_analyze(); }
  finally { b.disabled = false; b.textContent = 'Analyse disk'; }

  if (!JUNK.groups.length) {
    $('#junkOut').innerHTML = emptyState('Nothing to clean', 'No removable junk was found.');
    return;
  }
  $('#junkOut').innerHTML =
    '<div class="card" style="margin-bottom:16px;display:flex;align-items:center;gap:20px">' +
    '<div><div class="v" style="font-size:30px;font-weight:600;color:var(--acc)">' +
    esc(JUNK.total) + '</div><div class="k mut" style="font-size:12px">reclaimable</div></div>' +
    '<button class="btn pri" style="margin-left:auto" onclick="junkClean()">Clean selected</button></div>' +
    '<div class="list">' + JUNK.groups.map((g, n) =>
      '<div class="li"><div class="sw on" data-n="' + n + '" style="flex:0 0 40px"></div>' +
      '<div class="body"><div class="t">' + esc(g.label) + '</div>' +
      '<div class="d dim" style="font-size:11.5px">' + num(g.files) + ' files · ' +
      esc(g.path) + '</div></div>' +
      '<div class="when" style="font-size:13px;color:var(--tx);font-weight:600">' +
      esc(g.size) + '</div></div>').join('') + '</div>';

  $$('#junkOut .sw').forEach(sw => sw.onclick = () => {
    sw.classList.toggle('on');
    JUNK.groups[Number(sw.dataset.n)].selected = sw.classList.contains('on');
  });
}

function junkClean() {
  const sel = JUNK.groups.filter(g => g.selected);
  if (!sel.length) { toast('Nothing selected', '', 'warn'); return; }
  const total = sel.reduce((a, g) => a + g.bytes, 0);
  modal('Clean ' + bytes(total) + '?',
    'These caches and temporary files will be deleted. Documents, photos and ' +
    'installed programs are never touched.',
    '<div class="mut" style="font-size:12.5px">' +
    sel.map(g => esc(g.label) + ' — ' + esc(g.size)).join('<br>') + '</div>',
    [{ label: 'Cancel' }, { label: 'Clean now', cls: 'pri', fn: async () => {
      const r = await API.junk_clean(sel.map(g => g.label));
      toast('Cleanup complete', r.freed_h + ' reclaimed · ' + num(r.removed) +
        ' files removed' + (r.failed ? ' · ' + r.failed + ' locked' : ''), 'ok');
      junkAnalyze();
    } }]);
}

/* ── Startup Manager ────────────────────────────────────── */
async function startupLoad() {
  const b = $('#startBtn');
  b.disabled = true; b.innerHTML = '<span class="spin"></span> Analysing…';
  let items;
  try { items = await API.startup_list(); }
  finally { b.disabled = false; b.textContent = 'Analyse startup items'; }

  const risky = items.filter(i => ['high', 'critical', 'medium'].includes(i.verdict.level)).length;
  $('#startupOut').innerHTML =
    '<div class="grid g3" style="margin-bottom:18px">' +
    statCard(items.length, 'Startup entries') +
    statCard(risky, 'Flagged as risky') +
    statCard(items.filter(i => i.impact === 'high').length, 'High boot impact') + '</div>' +
    '<div class="list">' + (items.length ? items.map((it, n) =>
      '<div class="li"><div class="dot" style="background:' +
      (SEVCOL[it.verdict.level] || 'var(--ok)') + '"></div><div class="body">' +
      '<div class="t">' + esc(it.name) +
      '<span class="pill ' + esc(it.verdict.level) + '">' + esc(it.verdict.level) + '</span>' +
      '<span class="pill info">' + esc(it.location) + '</span>' +
      (it.impact === 'high' ? '<span class="pill medium">high impact</span>' : '') +
      '</div><div class="p">' + esc(it.command) + '</div>' +
      '<div class="d">' + esc(it.verdict.reason) + '</div></div>' +
      '<div class="acts"><button class="btn sm dgr" data-n="' + n + '">Disable</button></div></div>'
    ).join('') : emptyState('No startup entries', 'Nothing is configured to run at logon.')) + '</div>';

  $$('#startupOut [data-n]').forEach(btn => btn.onclick = async () => {
    const it = items[Number(btn.dataset.n)];
    btn.disabled = true;
    const r = await API.startup_disable(it.name, it.location);
    if (r.ok) { toast('Startup item disabled', it.name, 'ok'); startupLoad(); }
    else { btn.disabled = false; toast('Could not disable', r.error, 'bad'); }
  });
}

/* ── Breach Monitor ─────────────────────────────────────── */
async function breachCheck() {
  const em = $('#breachEmail').value.trim();
  if (!em) return;
  $('#breachOut').innerHTML = '<div class="mut"><span class="spin"></span> Checking breach databases…</div>';
  const r = await API.breach_check(em);
  if (!r.ok) { $('#breachOut').innerHTML = emptyState('Lookup failed', r.error); return; }
  if (!r.count) {
    $('#breachOut').innerHTML =
      '<div class="card" style="border-color:rgba(61,220,132,.35)">' +
      '<div class="t" style="font-size:15px;font-weight:600;color:var(--ok);margin-bottom:5px">No breaches found</div>' +
      '<p>' + esc(em) + ' does not appear in any known breach in this database. ' +
      'Keep using unique passwords — new breaches surface constantly.</p></div>';
    return;
  }
  $('#breachOut').innerHTML =
    '<div class="card" style="border-color:rgba(255,77,79,.4);margin-bottom:16px">' +
    '<div style="font-size:15px;font-weight:600;color:var(--bad);margin-bottom:5px">' +
    'Found in ' + r.count + ' breach' + (r.count > 1 ? 'es' : '') + '</div>' +
    '<p>Change the password on any site below where you reused it, and enable ' +
    'two-factor authentication.</p></div>' +
    '<div class="list">' + r.breaches.map(b =>
      '<div class="li"><div class="dot" style="background:var(--bad)"></div>' +
      '<div class="body"><div class="t">' + esc(b.name) + '</div></div></div>').join('') + '</div>';
}

/* ── updates ────────────────────────────────────────────── */
async function doUpdate() {
  const b = $('#updBtn');
  if (b) { b.disabled = true; b.innerHTML = '<span class="spin"></span> Updating…'; }
  toast('Updating definitions', 'Downloading the latest threat intelligence…');
  const r = await API.update_now(true);
  if (!r.ok && b) { b.disabled = false; b.textContent = 'Update now'; toast('Update failed', r.error, 'bad'); }
}

/* ══ New engines — Process Watchdog / Ransomware Trap / Port Audit / USB Sentry ══
   These wire the four pages from the Hy3 dossier to the real Python backend.
   Each backend method returns live system data; if the bridge is unavailable
   (e.g. opened in a plain browser) the function degrades to a short notice. */

/* 1 — Process Watchdog: live process / memory inspection */
async function runWatchdogScan() {
  const list = $('#watchdogList');
  if (!list) return;
  list.innerHTML = '<div class="li"><div class="dot" style="background:var(--blue)"></div>' +
    '<div class="body"><div class="t">Scanning running processes and RAM handles…</div></div></div>';
  try {
    const procs = await API.scan_watchdog();
    list.innerHTML = procs.map(p =>
      '<div class="li"><div class="dot" style="background:' +
      (p.status === 'ACTIVE GUARD' ? 'var(--ok)' : p.status === 'TRUSTED' ? 'var(--tx3)' : 'var(--warn)') +
      '"></div><div class="body"><div class="t">' + esc(p.name) +
      ' <span class="pill info">' + esc(String(p.pid)) + '</span>' +
      (p.status === 'ACTIVE GUARD' ? '<span class="pill ok">active guard</span>' : '') + '</div>' +
      '<div class="d">' + esc(p.status) + (p.detail ? ' — ' + esc(p.detail) : '') + '</div></div></div>'
    ).join('');
  } catch (e) {
    list.innerHTML = '<div class="li"><div class="dot" style="background:var(--warn)"></div>' +
      '<div class="body"><div class="t">Memory inspection unavailable</div>' +
      '<div class="d">Run Aegis from the desktop app to inspect live processes.</div></div></div>';
  }
}

/* 2 — Ransomware Canary Traps: verify/deploy decoy honeyfiles */
async function redeployTraps() {
  try {
    const r = await API.verify_canary_traps();
    const armed = r.status === 'ARMED';
    $('#ransomState') && ($('#ransomState').textContent = r.status);
    $('#ransomActive') && ($('#ransomActive').textContent = r.active);
    $('#ransomTripped') && ($('#ransomTripped').textContent = r.tripped);
    toast(armed ? 'Canary traps verified' : 'Canary traps not armed',
      r.active + ' honeyfiles across Documents & Desktop', armed ? 'ok' : 'warn');
  } catch (e) {
    toast('Canary verification unavailable', 'Open the desktop app to manage traps.', 'warn');
  }
}

/* 3 — Port & Socket Firewall Audit: live listening sockets */
async function auditPorts() {
  const list = $('#portList');
  if (!list) return;
  list.innerHTML = '<div class="li"><div class="dot" style="background:var(--blue)"></div>' +
    '<div class="body"><div class="t">Auditing open listening sockets…</div></div></div>';
  try {
    const ports = await API.audit_network_ports();
    list.innerHTML = ports.map(pt =>
      '<div class="li"><div class="dot" style="background:var(--tx3)"></div>' +
      '<div class="body"><div class="t">' + esc(pt.service || 'Unknown') +
      ' <span class="pill info">' + esc(pt.protocol) + ' ' + esc(String(pt.port)) + '</span></div>' +
      '<div class="d">' + esc(pt.state) + '</div></div></div>'
    ).join('') || emptyState('No listening sockets', 'No open ports were found.');
  } catch (e) {
    list.innerHTML = '<div class="li"><div class="dot" style="background:var(--warn)"></div>' +
      '<div class="body"><div class="t">Port audit unavailable</div>' +
      '<div class="d">Run the desktop app to inspect live network sockets.</div></div></div>';
  }
}

/* 4 — USB & Removable Media Sentry: enumerate mounted drives */
async function checkUsbDrives() {
  const list = $('#usbList');
  if (!list) return;
  list.innerHTML = '<div class="li"><div class="dot" style="background:var(--blue)"></div>' +
    '<div class="body"><div class="t">Polling USB bus and volume mounts…</div></div></div>';
  try {
    const drives = await API.scan_usb_drives();
    if (!drives.length) {
      list.innerHTML = '<div class="li"><div class="dot" style="background:var(--ok)"></div>' +
        '<div class="body"><div class="t">No removable drives detected</div>' +
        '<div class="d">No unauthorized storage is currently mounted.</div></div></div>';
    } else {
      list.innerHTML = drives.map(d =>
        '<div class="li"><div class="dot" style="background:var(--ok)"></div>' +
        '<div class="body"><div class="t">' + esc(d.letter) + ' <span class="pill ok">clean</span></div>' +
        '<div class="d">' + esc(d.label || 'Removable media') + ' — ' + esc(d.status || 'mounted') + '</div></div></div>'
      ).join('');
    }
  } catch (e) {
    list.innerHTML = '<div class="li"><div class="dot" style="background:var(--warn)"></div>' +
      '<div class="body"><div class="t">USB scan unavailable</div>' +
      '<div class="d">Run the desktop app to inspect mounted drives.</div></div></div>';
  }
}

/* 5 — Brute-Force Shield: scan the Security log for 4625 bursts */
async function runBruteScan() {
  const out = $('#bfOut');
  if (out) out.innerHTML = '<div class="li"><div class="dot" style="background:var(--blue)"></div><div class="body"><div class="t">Reading Windows Security log…</div></div></div>';
  try {
    const r = await API.bruteforce_scan();
    const s = await API.bruteforce_status();
    $('#bfHits') && ($('#bfHits').textContent = num(r.hits));
    $('#bfFlagged') && ($('#bfFlagged').textContent = num((r.flagged || []).length));
    $('#bfWindow') && ($('#bfWindow').textContent = s.window_min + 'm');
    if (out) {
      if (!r.ok) {
        out.innerHTML = '<div class="li"><div class="dot" style="background:var(--warn)"></div><div class="body"><div class="t">Could not read the Security log</div><div class="d">' + esc(r.error || '') + '</div></div></div>';
      } else if (!r.top.length) {
        out.innerHTML = '<div class="li"><div class="dot" style="background:var(--ok)"></div><div class="body"><div class="t">No failed logons in the last ' + s.window_min + ' min</div><div class="d">No credential-guessing activity detected.</div></div></div>';
      } else {
        out.innerHTML = '<h2>Top source IPs</h2><div class="list">' + r.top.map(x =>
          '<div class="li"><div class="dot" style="background:' +
          ((r.flagged || []).some(f => f.ip === x.ip) ? 'var(--bad)' : 'var(--tx3)') + '"></div>' +
          '<div class="body"><div class="t">' + esc(x.ip) +
          ' <span class="pill ' + ((r.flagged || []).some(f => f.ip === x.ip) ? 'critical' : 'info') + '">' +
          x.count + ' attempts</span></div></div></div>').join('') + '</div>';
      }
    }
    refreshDash();
  } catch (e) {
    if (out) out.innerHTML = '<div class="li"><div class="dot" style="background:var(--warn)"></div><div class="body"><div class="t">Brute-force scan unavailable</div></div></div>';
  }
}

/* 6 — Firewall Control */
async function loadFirewall() {
  try {
    const r = await API.firewall_status();
    const on = r.profiles_on > 0;
    const st = $('#fwStatus');
    if (st) st.textContent = r.ok ? (on ? 'On — ' + r.profiles_on + ' profile(s) active' : 'Off — traffic is not being filtered') : 'Status unknown';
    const onBtn = $('#fwOn'), offBtn = $('#fwOff');
    if (onBtn) onBtn.disabled = on;
    if (offBtn) offBtn.disabled = !on;
  } catch (e) {}
}
async function setFirewall(on) {
  await API.firewall_set(on);
  toast('Firewall ' + (on ? 'enabled' : 'disabled'), '', on ? 'ok' : 'warn');
  loadFirewall(); refreshDash();
}

/* 7 — Webcam & Mic Guard */
async function loadPrivacy() {
  try {
    const r = await API.privacy_status();
    const cam = $('#camState'), mic = $('#micState');
    const fmt = v => (v === 'Allow' ? 'Allowed' : v === 'Deny' ? 'Denied' : (v || 'unknown'));
    if (cam) { cam.textContent = fmt(r.webcam_consent); cam.style.color = r.webcam_consent === 'Deny' ? 'var(--ok)' : 'var(--warn)'; }
    if (mic) { mic.textContent = fmt(r.mic_consent); mic.style.color = r.mic_consent === 'Deny' ? 'var(--ok)' : 'var(--warn)'; }
  } catch (e) {}
}

/* 8 — Secure VPN (honest status surface) */
async function loadVpn() {
  try {
    const r = await API.vpn_status();
    const title = $('#vpnTitle'), desc = $('#vpnDesc'), kick = $('#vpnKick'), hero = $('#vpnHero');
    if (r.available && r.profiles.length) {
      const p = r.profiles[0];
      const connected = /connected/i.test(p.ConnectionStatus || '');
      kick.textContent = 'Privacy extra';
      title.textContent = connected ? 'VPN connected' : 'VPN configured';
      desc.textContent = p.Name + (connected ? ' — your traffic is tunneled.' : ' — not connected. Open Windows settings to connect.');
      if (hero) hero.className = 'hero ' + (connected ? 'ok' : 'warn');
    } else {
      kick.textContent = 'Privacy extra';
      title.textContent = 'No OS VPN configured';
      desc.textContent = 'Aegis shows your system VPN state. Connect via your provider, then re-open this page.';
      if (hero) hero.className = 'hero warn';
    }
  } catch (e) {}
}

/* 9 — File Shredder */
async function shredPick() {
  const files = await API.pick_files();
  if (!files || !files.length) return;
  const out = $('#shredOut');
  for (const f of files) {
    const r = await API.shred_file(f);
    if (out) out.innerHTML = '<div class="li"><div class="dot" style="background:' +
      (r.ok ? 'var(--ok)' : 'var(--bad)') + '"></div><div class="body"><div class="t">' +
      esc(base(f)) + '</div><div class="d">' + (r.ok ? 'Securely wiped (' + bytes(r.bytes) + ')' : esc(r.error || 'failed')) +
      '</div></div></div>' + (out.innerHTML || '');
  }
  toast('Shred complete', files.length + ' file(s) processed', 'ok');
}

