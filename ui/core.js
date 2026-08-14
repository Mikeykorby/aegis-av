/* Aegis Security — core: bridge, nav, toasts, modal, helpers */
'use strict';

const api = window.pywebview ? window.pywebview.api : null;
let API = null;               // resolved after pywebviewready
let CUR = 'home';
let SETTINGS = {};

function $(s, r) { return (r || document).querySelector(s); }
function $$(s, r) { return Array.from((r || document).querySelectorAll(s)); }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function num(n) { return Number(n || 0).toLocaleString(); }
function base(p) { return String(p || '').split(/[\\/]/).pop(); }
function bytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
}
function dur(s) {
  s = Math.max(0, Math.round(s || 0));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}
function when(ts) {
  if (!ts) return 'never';
  const d = Date.now() / 1000 - ts;
  if (d < 90) return 'just now';
  if (d < 3600) return Math.floor(d / 60) + ' min ago';
  if (d < 172800) return Math.floor(d / 3600) + ' hours ago';
  return Math.floor(d / 86400) + ' days ago';
}
const SEVCOL = {
  critical: 'var(--bad)', high: 'var(--bad)', medium: 'var(--warn)',
  pup: 'var(--warn)', low: 'var(--blue)', info: 'var(--tx3)', ok: 'var(--ok)'
};

/* ── toasts ─────────────────────────────────────────────── */
function toast(title, desc, kind) {
  const t = document.createElement('div');
  t.className = 'toast ' + (kind || '');
  t.innerHTML = '<div class="tt">' + esc(title) + '</div>' +
    (desc ? '<div class="td">' + esc(desc) + '</div>' : '');
  $('#toasts').appendChild(t);
  setTimeout(() => {
    t.style.transition = 'opacity .3s,transform .3s';
    t.style.opacity = '0'; t.style.transform = 'translateX(30px)';
    setTimeout(() => t.remove(), 320);
  }, kind === 'bad' ? 9000 : 5000);
}

/* ── modal ──────────────────────────────────────────────── */
function modal(title, desc, bodyHtml, buttons) {
  $('#mTitle').textContent = title;
  $('#mDesc').textContent = desc || '';
  $('#mBody').innerHTML = bodyHtml || '';
  const f = $('#mFoot'); f.innerHTML = '';
  (buttons || [{ label: 'Close', cls: '' }]).forEach(b => {
    const el = document.createElement('button');
    el.className = 'btn ' + (b.cls || '');
    el.textContent = b.label;
    el.onclick = () => { closeModal(); if (b.fn) b.fn(); };
    f.appendChild(el);
  });
  $('#modal').classList.add('on');
}
function closeModal() { $('#modal').classList.remove('on'); }
$('#modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

/* ── navigation ─────────────────────────────────────────── */
function go(p) {
  CUR = p;
  $$('.navitem').forEach(n => n.classList.toggle('on', n.dataset.p === p));
  $$('.page').forEach(s => s.classList.toggle('on', s.id === 'p-' + p));
  $('#main').scrollTop = 0;
  if (p === 'chest') loadChest();
  if (p === 'log') loadLog();
  if (p === 'settings') loadSettings();
  if (p === 'shields') loadShields();
  if (p === 'scan') loadScanHistory();
  if (p === 'web') loadWeb();
  if (p === 'home') refreshDash();
  if (p === 'firewall') loadFirewall();
  if (p === 'privacy') loadPrivacy();
  if (p === 'sensitive') loadSensitive();
  if (p === 'apps') loadApps();
  if (p === 'brute') runBruteScan();
  if (p === 'shred') loadShredderAlgos();   // file picker on demand
  if (p === 'kernel') loadKernel();
}
$$('.navitem').forEach(n => n.onclick = () => go(n.dataset.p));

/* ── footer live status bar ───────────────────────────── */
async function updateFoot() {
  const sub = $('#footStatus'), dot = $('#footDot'), prot = $('#footProtect'), defs = $('#footDefs');
  if (!prot) return;
  try {
    const s = await API.status();
    const prots = s.protections || {};
    const active = Object.values(prots).filter(Boolean).length;
    const total = Object.keys(prots).length || 1;
    const ok = active === total;
    dot.className = 'dot ' + (ok ? 'ok' : 'bad');
    prot.textContent = active + '/' + total + ' shields';
    defs.textContent = num(s.signatures || 0) + ' defs';
    if (sub) sub.textContent = ok ? 'Protected' : 'Action needed';
  } catch (e) { if (sub) sub.textContent = 'Status unavailable'; }
}

/* ── empty-state helper ─────────────────────────────────── */
function emptyState(title, desc) {
  return '<div class="empty">' +
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor">' +
    '<circle cx="12" cy="12" r="9"/><path d="M9 12h6" stroke-linecap="round"/></svg>' +
    '<div class="t">' + esc(title) + '</div>' +
    '<div class="d">' + esc(desc || '') + '</div></div>';
}

/* ── finding row (shared by wifi / health) ──────────────── */
function findingRow(f) {
  return '<div class="li"><div class="dot" style="background:' +
    (SEVCOL[f.level] || 'var(--tx3)') + '"></div><div class="body">' +
    '<div class="t">' + esc(f.title) +
    '<span class="pill ' + esc(f.level) + '">' + esc(f.level) + '</span></div>' +
    '<div class="d">' + esc(f.detail) + '</div></div></div>';
}

/* ── event stream from Python ───────────────────────────── */
async function pollEvents() {
  if (!API) return;
  let evs = [];
  try { evs = await API.poll_events(); } catch (e) { return; }
  (evs || []).forEach(ev => {
    const d = ev.data || {};
    if (ev.kind === 'realtime_block') {
      toast('Threat detected: ' + (d.threat || 'malware'),
        base(d.path) + (d.quarantined ? ' — moved to Virus Chest' : ' — detected'), 'bad');
      refreshDash();
    } else if (ev.kind === 'behaviour') {
      toast('Suspicious behaviour', d.desc + ' — ' + (d.name || ''), 'warn');
    } else if (ev.kind === 'ransomware') {
      toast('Ransomware Shield triggered', d.desc || '', 'bad');
    } else if (ev.kind === 'update_done') {
      const b = $('#updBtn');
      if (b) { b.disabled = false; b.textContent = 'Update now'; }
      $('#updBar') && $('#updBar').classList.add('hidden');
      if (d.error) toast('Update finished with issues', d.error, 'warn');
      else toast('Definitions updated', num(d.signatures) + ' signatures · ' +
        num(d.rules) + ' rules', 'ok');
      refreshDash(); if (CUR === 'settings') loadSettings();
    } else if (ev.kind === 'update_progress') {
      const bar = $('#updBar');
      if (bar) { bar.classList.remove('hidden'); bar.firstElementChild.style.width = (d.percent || 0) + '%'; }
    } else if (ev.kind === 'scan_done') {
      onScanFinished(d);
    }
  });
}

/* ── title bar / frameless drag + resize ───────────────────
   The window is frameless (no OS borders), so we implement moving and
   resizing ourselves from ONE document-level mousedown handler (the same
   mechanism that already works for moving). Resize is edge-proximity based,
   so it no longer depends on invisible .rz divs being hittable. Both stop
   precisely on mouseup, so the window never keeps drifting after release. */
const EDGE = 8;          // grab margin from the window border
const _MIN_W = 1060, _MIN_H = 700;

document.addEventListener('mousedown', (e) => {
  if (e.target.closest('.winbtn')) return;          // keep buttons clickable
  if (!API || typeof API.get_window_rect !== 'function') return;

  const vw = window.innerWidth, vh = window.innerHeight;
  const cx = e.clientX, cy = e.clientY;
  let edge = '';                                      // which edges are we near?
  if (cy <= EDGE) edge += 'n';
  if (cy >= vh - EDGE) edge += 's';
  if (cx <= EDGE) edge += 'w';
  if (cx >= vw - EDGE) edge += 'e';
  const onTitle = !!e.target.closest('#titlebar');

  if (!edge && !onTitle) return;                       // let content handle it

  e.preventDefault();
  let rect = null;
  try { rect = API.get_window_rect(); } catch (err) { return; }
  if (!rect || !rect.ok) return;
  const sx = cx, sy = cy;
  const ox = rect.x, oy = rect.y, ow = rect.w, oh = rect.h;

  const move = (ev) => {
    const dx = ev.clientX - sx, dy = ev.clientY - sy;
    let x = ox, y = oy, w = ow, h = oh;
    if (edge.includes('e')) w = Math.max(_MIN_W, ow + dx);
    if (edge.includes('s')) h = Math.max(_MIN_H, oh + dy);
    if (edge.includes('w')) { w = Math.max(_MIN_W, ow - dx); x = ox + (ow - w); }
    if (edge.includes('n')) { h = Math.max(_MIN_H, oh - dy); y = oy + (oh - h); }
    try { API.set_window_rect(x, y, w, h); } catch (err) {}
    ev.preventDefault();
  };
  const up = () => {
    document.removeEventListener('mousemove', move);
    document.removeEventListener('mouseup', up);
    document.body.style.cursor = '';
  };
  document.addEventListener('mousemove', move);
  document.addEventListener('mouseup', up);
});

// The .rz divs are kept only as a hover affordance; the real grip logic above
// is edge-proximity based, so initResize is now a no-op.
function initResize() { /* resizing handled by the unified mousedown handler */ }

/* Double-clicking the title bar maximises/restores, like every Windows app. */
document.addEventListener('dblclick', (e) => {
  if (e.target.closest('.winbtn')) return;
  if (e.target.closest('#titlebar') && API) API.toggle_maximize();
});

/* ── boot ───────────────────────────────────────────────── */
window.addEventListener('pywebviewready', async () => {
  API = window.pywebview.api;
  window.api = API;                 // title-bar buttons use this
  await refreshDash();
  await loadSettings();
  initResize();
  setInterval(pollEvents, 900);
  setInterval(() => { if (CUR === 'home') refreshDash(); }, 6000);
  setInterval(() => { if (CUR === 'shields') loadShields(); }, 3000);
});

/* Surface any uncaught JS error as a visible red banner so a blank page is
   never silent — the user can report exactly what failed. */
window.addEventListener('error', (e) => {
  const b = document.getElementById('errBar');
  if (!b) return;
  b.classList.remove('hidden');
  b.textContent = 'UI error: ' + (e.message || e.error || 'unknown') +
    (e.filename ? ' @ ' + e.filename + ':' + e.lineno : '');
});
window.addEventListener('unhandledrejection', (e) => {
  const b = document.getElementById('errBar');
  if (!b) return;
  b.classList.remove('hidden');
  b.textContent = 'UI error (async): ' + (e.reason && e.reason.message ? e.reason.message : e.reason);
});

/* ══ Theme persistence (Hy3 system-aware light/dark) ══════ */
const THEME_KEY = 'aegis_theme';
APPLIED_THEME = 'auto';

function applyTheme(mode) {
  APPLIED_THEME = mode;
  try { localStorage.setItem(THEME_KEY, mode); } catch (e) {}
  const btn = $('#themeBtn'), sel = $('#themeSelect');
  if (mode === 'auto') {
    document.documentElement.removeAttribute('data-theme');
    if (btn) btn.textContent = 'Auto Theme';
    if (sel) sel.value = 'auto';
  } else {
    document.documentElement.setAttribute('data-theme', mode);
    if (btn) btn.textContent = mode.toUpperCase() + ' MODE';
    if (sel) sel.value = mode;
  }
}

function initTheme() {
  let saved;
  try { saved = localStorage.getItem(THEME_KEY); } catch (e) {}
  applyTheme(saved || 'auto');
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  if (!cur) applyTheme('dark');
  else if (cur === 'dark') applyTheme('light');
  else applyTheme('auto');
}

function setExplicitTheme(v) { applyTheme(v); }

/* Follow the OS only while in auto mode. */
if (window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)')
    .addEventListener('change', () => { if (APPLIED_THEME === 'auto') applyTheme('auto'); });
}

/* Initialise before scripts that rely on the attribute run. */
initTheme();

