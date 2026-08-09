/* KeyGuard — global UI helpers */

'use strict';

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

/* ---------- Toast notifications ---------- */

const TOAST_ICONS = {
  success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>',
  error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
  warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
  info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
};

function toast(message, type = 'info', ms = 4200) {
  const wrap = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `${TOAST_ICONS[type] || TOAST_ICONS.info}<span>${message}</span>`;
  wrap.appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  }, ms);
}

/* ---------- Modal ---------- */

function openModal(title, html) {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = html;
  $('#modal').classList.add('open');
  $('#modalBackdrop').classList.add('open');
}
function closeModal() {
  $('#modal').classList.remove('open');
  $('#modalBackdrop').classList.remove('open');
}
$('#modalClose') && $('#modalClose').addEventListener('click', closeModal);
$('#modalBackdrop') && $('#modalBackdrop').addEventListener('click', closeModal);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

/* ---------- API ---------- */

async function api(url, options = {}) {
  const defaults = { headers: {} };
  if (options.body instanceof FormData === false && options.body !== undefined) {
    defaults.headers['Content-Type'] = 'application/json';
    if (typeof options.body !== 'string') options.body = JSON.stringify(options.body);
  }
  const res = await fetch(url, Object.assign(defaults, options));
  let data;
  try { data = await res.json(); } catch (_) { data = { success: false, error: 'Invalid server response' }; }
  return data;
}

function postJSON(url, payload, button) {
  if (button) setBusy(button, true);
  return api(url, { method: 'POST', body: payload })
    .finally(() => { if (button) setBusy(button, false); });
}

function setBusy(button, busy) {
  if (!button) return;
  if (busy) {
    button.dataset.html = button.innerHTML;
    button.classList.add('busy');
    button.innerHTML = '<span class="spinner"></span><span>Working...</span>';
    button.disabled = true;
  } else {
    button.disabled = false;
    if (button.dataset.html) button.innerHTML = button.dataset.html;
  }
}

/* ---------- Clipboard ---------- */

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
  }
  if (btn) {
    const old = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = old; btn.classList.remove('copied'); }, 1500);
  }
  toast('Copied to clipboard', 'success', 1800);
}

/* ---------- File helpers ---------- */

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function esc(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function bindDropzone(dz, input) {
  dz.addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    if (input.files.length) showDropFile(dz, input.files[0]);
  });
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('dragover'); }));
  dz.addEventListener('drop', (e) => {
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      showDropFile(dz, e.dataTransfer.files[0]);
    }
  });
}
function showDropFile(dz, file) {
  const meta = dz.querySelector('.file-meta');
  const main = dz.querySelector('p');
  if (main) main.textContent = file.name;
  if (meta) { meta.style.display = 'block'; meta.textContent = `${formatBytes(file.size)} · ready`; }
}

/* ---------- Sidebar & clock ---------- */

const menuBtn = $('#menuBtn');
const sidebar = $('#sidebar');
if (menuBtn && sidebar) {
  menuBtn.addEventListener('click', () => sidebar.classList.toggle('open'));
  document.addEventListener('click', (e) => {
    if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && !menuBtn.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
}

function tickClock() {
  const el = $('#clock');
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString('en-GB');
}
tickClock();
setInterval(tickClock, 1000);

/* ---------- Tabs (data-tab / data-panel) ---------- */

document.addEventListener('click', (e) => {
  const tab = e.target.closest('[data-tab]');
  if (!tab) return;
  const group = tab.closest('.tabs');
  $$('.tab', group).forEach((t) => t.classList.remove('active'));
  tab.classList.add('active');
  const target = tab.dataset.tab;
  const scope = tab.closest('[data-tab-group]') || document;
  $$('.tab-panel', scope).forEach((p) => p.classList.toggle('active', p.dataset.panel === target));
});
