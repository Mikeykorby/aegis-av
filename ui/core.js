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
  if (p === 'vpn') loadVpn();
  if (p === 'brute') runBruteScan();
  if (p === 'shred') {}   // file picker on demand
}
$$('.navitem').forEach(n => n.onclick = () => go(n.dataset.p));

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

/* ── title bar ──────────────────────────────────────────────
   pywebview's easy_drag handler listens on document.body and walks UP the
   DOM from the event target, so a click on a window button would also start
   a window drag. Stop it at the capture phase so the buttons stay clickable.
   (The Electron -webkit-app-region:no-drag property has no effect here.) */
document.addEventListener('mousedown', (e) => {
  if (e.target.closest('.winbtn')) e.stopPropagation();
}, true);

/* Double-clicking the title bar maximises/restores, like every Windows app. */
document.addEventListener('dblclick', (e) => {
  if (e.target.closest('.winbtn')) return;
  if (e.target.closest('#titlebar') && API) API.toggle_maximize();
});

/* Frameless window has no OS resize borders — implement edge-drag resize.
   We read the window rect from Python, then on each pointer move recompute
   the rect for the grabbed edge and push it back via set_window_rect. */
let _RZ = null;
function initResize() {
  const MIN_W = 1060, MIN_H = 700;
  $$('.rz').forEach(z => {
    z.addEventListener('mousedown', (e) => {
      e.preventDefault(); e.stopPropagation();
      const edge = z.dataset.e;
      let rect = null;
      try { rect = API.get_window_rect(); } catch (err) { return; }
      if (!rect || !rect.ok) return;
      const sx = e.clientX, sy = e.clientY;
      const ox = rect.x, oy = rect.y, ow = rect.w, oh = rect.h;
      const move = (ev) => {
        const dx = ev.clientX - sx, dy = ev.clientY - sy;
        let x = ox, y = oy, w = ow, h = oh;
        if (edge.includes('e')) w = Math.max(MIN_W, ow + dx);
        if (edge.includes('s')) h = Math.max(MIN_H, oh + dy);
        if (edge.includes('w')) { w = Math.max(MIN_W, ow - dx); x = ox + (ow - w); }
        if (edge.includes('n')) { h = Math.max(MIN_H, oh - dy); y = oy + (oh - h); }
        try { API.set_window_rect(x, y, w, h); } catch (err) {}
        ev.preventDefault();
      };
      const up = () => {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
        _RZ = null;
        document.body.style.cursor = '';
      };
      _RZ = edge;
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
  });
}

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

