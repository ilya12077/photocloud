'use strict';
// Админка. Данные с сервера — только через textContent.

const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
const fmtDT = new Intl.DateTimeFormat('ru', { dateStyle: 'short', timeStyle: 'medium' });
const dt = (ts) => (ts ? fmtDT.format(new Date(ts * 1000)) : '—');
const EVENTS = {
  login: 'каждый вход', login_new_ip: 'вход с нового IP', login_failed: 'неудачный вход', lockout: 'блокировка IP',
  wake: 'кто-то будит ПК', wake_timeout: 'ПК не проснулся', index_error: 'ошибка чтения папки',
};
const AUDIT = {
  login: 'вход', login_google: 'вход через Google', login_failed: 'неудачный вход', login_google_denied: 'Google: аккаунт не привязан',
  login_google_failed: 'Google: ошибка', lockout: 'блокировка IP', logout: 'выход', setup: 'первичная настройка',
  setup_failed: 'неверный токен настройки', user_add: 'добавлен пользователь', user_delete: 'удалён пользователь',
  user_password: 'смена пароля', user_role: 'смена роли', user_google: 'привязка Google', session_revoke: 'сессия закрыта',
  unlock_ip: 'IP разблокирован', settings: 'изменены настройки', wake: 'пробуждение ПК', cache_clear: 'очистка кэша',
};

async function api(path, body) {
  const init = { credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) {
    init.method = 'POST';
    init.headers['X-Requested-With'] = 'photocloud';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const r = await fetch(path, init);
  let j = {};
  try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || j.detail || `HTTP ${r.status}`);
  return j;
}

let toastT = 0;
function toast(msg, bad) {
  const t = $('toast'); t.textContent = msg; t.hidden = false; t.classList.toggle('bad', !!bad);
  clearTimeout(toastT); toastT = setTimeout(() => { t.hidden = true; }, 3500);
}
async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); return null; }
}
function btn(text, onClick, cls) { const b = el('button', 'btn small ' + (cls || ''), text); b.type = 'button'; b.onclick = onClick; return b; }

// ================================================================== вход / первичная настройка

async function boot() {
  const m = location.hash.match(/^#setup=([A-Za-z0-9_-]{10,64})$/);
  if (m) {
    const need = await api('/api/admin/setup-needed').catch(() => ({}));
    if (need.needed) { showSetup(m[1]); return; }
    history.replaceState(null, '', location.pathname);
  }
  let me;
  try { me = await api('/api/me'); } catch (_) { $('denied').hidden = false; return; }
  if (me.role !== 'admin') { $('denied-text').textContent = 'У этой учётной записи нет прав администратора.'; $('denied').hidden = false; return; }
  if (me.name) { $('adm-title').textContent = me.name; document.title = `Админка · ${me.name}`; }
  $('panel').hidden = false;
  showTab('overview');
}

function showSetup(token) {
  $('setup').hidden = false;
  $('setup-form').onsubmit = async (e) => {
    e.preventDefault();
    if ($('sp').value !== $('sp2').value) { $('serr').textContent = 'Пароли не совпадают'; return; }
    try {
      await api('/api/admin/setup', { token, u: $('su').value.trim(), p: $('sp').value });
      history.replaceState(null, '', location.pathname);
      location.href = '/';
    } catch (err) { $('serr').textContent = err.message; }
  };
}

// ================================================================== вкладки

const loaders = { overview: loadOverview, users: loadUsers, security: loadSecurity, settings: loadSettings, perf: loadPerf, logs: loadLogs };
function showTab(name) {
  for (const b of $('tabs').children) b.classList.toggle('on', b.dataset.tab === name);
  for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== name;
  loaders[name]();
}
$('tabs').addEventListener('click', (e) => { const b = e.target.closest('button[data-tab]'); if (b) showTab(b.dataset.tab); });

// ================================================================== обзор

const mb = (b) => (b >= 1048576 ? (b / 1048576).toFixed(1) + ' МБ' : Math.round(b / 1024) + ' КБ');
function dur(s) { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + ' д ' : '') + (h ? h + ' ч ' : '') + m + ' мин'; }

async function loadOverview() {
  const o = await act(() => api('/api/admin/overview')); if (!o) return;
  const ix = o.index;
  const cards = [
    ['Компьютер', { up: 'включён', down: 'выключен', waking: 'просыпается' }[o.pc] || o.pc],
    ['Файлов', `${ix.files.toLocaleString('ru')} (видео ${ix.videos.toLocaleString('ru')})`],
    ['Дата из метаданных', ix.files ? `${ix.with_date.toLocaleString('ru')} (${Math.round(ix.with_date / ix.files * 100)}%)` : '—'],
    ['Дата из имени файла', ix.files ? `${ix.with_name_date.toLocaleString('ru')} (${Math.round(ix.with_name_date / ix.files * 100)}%)` : '—'],
    ['Год по папке', ix.files ? `${(ix.with_folder_year ?? 0).toLocaleString('ru')} (${Math.round((ix.with_folder_year ?? 0) / ix.files * 100)}%)` : '—'],
    ['Индекс', ix.state + (ix.error ? ` (${ix.error})` : '') + (ix.meta[1] && ix.meta[0] < ix.meta[1] ? `, даты ${ix.meta[0]}/${ix.meta[1]}` : '')],
    ['Обновлён', dt(ix.built_at)],
    ['Эскизы в памяти сервера', `${mb(o.cache.thumb[0])} из ${mb(o.cache.thumb[1])}`],
    ['Превью в памяти сервера', `${mb(o.cache.preview[0])} из ${mb(o.cache.preview[1])}`],
    ['Сессий', String(o.sessions)],
    ['Работает', dur(o.uptime)],
  ];
  $('ov-cards').replaceChildren(...cards.map(([k, v]) => { const c = el('div', 'card'); c.append(el('div', 'k', k), el('div', 'v', v)); return c; }));
  const labels = {
    storage: 'Режим', source: 'Источник', smb_encrypt: 'Шифрование SMB', bind: 'Адрес', public_url: 'Внешний адрес',
    cookie_secure: 'Secure cookie', trusted_proxies: 'Доверенные прокси', require_proxy: 'Только через прокси',
    allowed_origins: 'Разрешённые Origin', ha_url: 'Home Assistant', ha_token: 'Токен HA задан', google: 'Вход через Google',
    google_redirect: 'Google redirect URI', ffmpeg: 'ffmpeg', data_dir: 'Папка данных', workers: 'Потоков эскизов',
    timezone: 'Часовой пояс', format: 'Формат эскизов', sizes: 'Размеры',
  };
  const rows = Object.entries(o.config).map(([k, v]) => {
    const tr = el('tr'); const val = Array.isArray(v) ? (v.join(', ') || '—') : typeof v === 'boolean' ? (v ? 'да' : 'нет') : (v === '' ? '—' : String(v));
    tr.append(el('th', null, labels[k] || k), el('td', null, val)); return tr;
  });
  $('ov-config').replaceChildren(...rows);
  if (o.config.storage === 'local') { const tr = el('tr', 'warn'); tr.append(el('th', null, '⚠'), el('td', null, 'Тестовый режим: файлы из локальной папки. В проде отключить.')); $('ov-config').prepend(tr); }
  if (!o.config.cookie_secure) { const tr = el('tr', 'warn'); tr.append(el('th', null, '⚠'), el('td', null, 'COOKIE_SECURE=false — только для теста по http.')); $('ov-config').prepend(tr); }
}

$('act-reindex').onclick = () => act(() => api('/api/reindex', {}), 'Сканирование запущено');
$('act-wake').onclick = () => act(() => api('/api/wake', {}), 'Команда отправлена');
$('act-notify').onclick = () => act(() => api('/api/admin/notify-test', {}), 'Уведомление отправлено');
$('act-cache').onclick = () => act(() => api('/api/admin/cache/clear', {}), 'Кэш очищен').then(loadOverview);

// ================================================================== пользователи

async function loadUsers() {
  const r = await act(() => api('/api/admin/users')); if (!r) return;
  const tb = $('users').tBodies[0];
  tb.replaceChildren(...r.users.map((u) => {
    const tr = el('tr');
    const role = el('select'); for (const [v, t] of [['user', 'пользователь'], ['admin', 'администратор']]) { const o = el('option', null, t); o.value = v; role.append(o); }
    role.value = u.role;
    role.onchange = () => act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/role`, { role: role.value }), 'Роль изменена').then((x) => { if (!x) role.value = u.role; });
    const g = el('td');
    g.append(el('span', 'gmail', u.google || '—'), btn(u.google ? 'изменить' : 'привязать', async () => {
      const email = prompt('Email Google-аккаунта (пусто — отвязать):', u.google || '');
      if (email === null) return;
      await act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/google`, { email: email.trim() || null }), email.trim() ? 'Google привязан' : 'Google отвязан');
      loadUsers();
    }));
    const ops = el('td', 'ops');
    ops.append(btn('пароль', async () => {
      const p = prompt(`Новый пароль для ${u.user} (от 12 символов). Все его сессии будут закрыты.`);
      if (p) act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/password`, { p }), 'Пароль изменён');
    }), btn('удалить', async () => {
      if (!confirm(`Удалить пользователя ${u.user}? Его сессии будут закрыты.`)) return;
      await act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/delete`, {}), 'Пользователь удалён');
      loadUsers();
    }, 'danger'));
    const tdRole = el('td'); tdRole.append(role);
    tr.append(el('td', 'mono', u.user), tdRole, g, el('td', null, dt(u.created)), ops);
    return tr;
  }));
}

$('add-user').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ok = await act(() => api('/api/admin/users', { u: $('nu').value.trim(), p: $('np').value, role: $('nr').value }), 'Пользователь добавлен');
  if (ok) { $('nu').value = ''; $('np').value = ''; loadUsers(); }
});

// ================================================================== сессии / блокировки

async function loadSecurity() {
  const r = await act(() => api('/api/admin/sessions')); if (!r) return;
  $('sessions').tBodies[0].replaceChildren(...r.sessions.map((s) => {
    const tr = el('tr'); const ops = el('td', 'ops');
    if (s.id === r.current) ops.append(el('span', 'dim2', 'текущая'));
    else ops.append(btn('закрыть', async () => { await act(() => api(`/api/admin/sessions/${s.id}/revoke`, {}), 'Сессия закрыта'); loadSecurity(); }, 'danger'));
    tr.append(el('td', 'mono', s.user), el('td', 'mono', s.ip), el('td', null, dt(s.created)), el('td', null, dt(s.last_seen)), ops);
    return tr;
  }));
  const l = await act(() => api('/api/admin/lockouts')); if (!l) return;
  const tb = $('locks').tBodies[0];
  if (!l.locked.length) { const tr = el('tr'); const td = el('td', 'dim2', 'нет'); td.colSpan = 3; tr.append(td); tb.replaceChildren(tr); return; }
  tb.replaceChildren(...l.locked.map((x) => {
    const tr = el('tr'); const ops = el('td', 'ops');
    ops.append(btn('разблокировать', async () => { await act(() => api(`/api/admin/lockouts/${encodeURIComponent(x.ip)}/clear`, {}), 'Разблокирован'); loadSecurity(); }));
    tr.append(el('td', 'mono', x.ip), el('td', null, Math.ceil(x.left / 60) + ' мин'), ops);
    return tr;
  }));
}

// ================================================================== настройки

async function loadSettings() {
  const r = await act(() => api('/api/admin/settings')); if (!r) return;
  const s = r.settings;
  $('s-name').value = s.public_name;
  $('s-notify').value = s.ha_notify_service;
  $('s-wake').value = s.ha_wake_service;
  $('s-wakedata').value = Object.keys(s.ha_wake_data || {}).length ? JSON.stringify(s.ha_wake_data) : '';
  $('s-waket').value = s.wake_timeout; $('s-ttl').value = s.index_ttl; $('s-idle').value = s.session_idle_hours;
  $('s-events').replaceChildren(...r.events.map((ev) => {
    const l = el('label', 'chkline'); const c = el('input'); c.type = 'checkbox'; c.value = ev; c.checked = s.notify_events.includes(ev);
    l.append(c, document.createTextNode(' ' + (EVENTS[ev] || ev))); return l;
  }));
}

$('settings').addEventListener('submit', async (e) => {
  e.preventDefault();
  let wakeData = {};
  if ($('s-wakedata').value.trim()) { try { wakeData = JSON.parse($('s-wakedata').value); } catch (_) { toast('Данные пробуждения: невалидный JSON', true); return; } }
  const body = {
    public_name: $('s-name').value.trim(),
    notify_events: [...$('s-events').querySelectorAll('input:checked')].map((c) => c.value),
    ha_notify_service: $('s-notify').value.trim(),
    ha_wake_service: $('s-wake').value.trim(),
    ha_wake_data: wakeData,
    wake_timeout: +$('s-waket').value, index_ttl: +$('s-ttl').value, session_idle_hours: +$('s-idle').value,
  };
  const r = await act(() => api('/api/admin/settings', body));
  if (r) toast(r.changed.length ? 'Сохранено: ' + r.changed.length : 'Без изменений');
});

// ================================================================== скорость

const KIND = { s: 'эскиз 240', t: 'эскиз 400', m: 'эскиз 900', q: 'быстрое 960', e: 'превью 1280', p: 'превью 2048' };
const ms = (v) => (v == null ? '—' : v >= 1000 ? (v / 1000).toFixed(1) + ' с' : Math.round(v) + '');

async function loadPerf() {
  const r = await act(() => api('/api/admin/perf')); if (!r) return;
  $('perf-meta').textContent = `потоков: ${r.workers} · из кэша: ${r.hit_ratio ?? '—'}% из ${r.requests} · сейчас в работе: ${r.inflight}`;
  const tb = $('perf').tBodies[0];
  if (!r.rows.length) { const tr = el('tr'); const td = el('td', 'dim2', 'пока нет данных — полистай ленту или запусти тест'); td.colSpan = 11; tr.append(td); tb.replaceChildren(tr); return; }
  tb.replaceChildren(...r.rows.map((x) => {
    const tr = el('tr');
    for (const v of [KIND[x.kind] || x.kind, x.fmt, x.n, ms(x.queue), ms(x.read), ms(x.decode), ms(x.resize), ms(x.encode), ms(x.total), ms(x.total_p90), x.kb == null ? '—' : x.kb.toFixed(1)]) tr.append(el('td', null, String(v)));
    return tr;
  }));
}
$('perf-refresh').onclick = loadPerf;

$('bench-run').onclick = async () => {
  $('bench-run').disabled = true; $('bench-verdict').textContent = 'Идёт тест…';
  const r = await act(() => api('/api/admin/bench', {}));
  $('bench-run').disabled = false;
  if (!r) { $('bench-verdict').textContent = ''; return; }
  $('bench').tBodies[0].replaceChildren(...r.items.map((x) => {
    const tr = el('tr');
    const cells = x.error ? [x.fmt, x.name, '', 'ошибка: ' + x.error, '', '', '', '', ''] :
      [x.fmt, x.name, x.mb, ms(x.read), ms(x.decode), ms(x.resize), ms(x.encode), ms(x.total), x.kb];
    for (const v of cells) tr.append(el('td', null, String(v)));
    return tr;
  }));
  // вывод: какой этап съедает больше всего времени
  const ok = r.items.filter((x) => !x.error);
  const sum = (k) => ok.reduce((a, x) => a + (x[k] || 0), 0);
  const parts = { 'чтение файла (диск/сеть)': sum('read'), 'декодирование исходника': sum('decode'), 'уменьшение': sum('resize'), 'сжатие в WebP': sum('encode') };
  const all = Object.values(parts).reduce((a, b) => a + b, 0) || 1;
  const top = Object.entries(parts).sort((a, b) => b[1] - a[1])[0];
  $('bench-verdict').textContent = `Больше всего времени уходит на: ${top[0]} — ${Math.round(top[1] / all * 100)}%. ` +
    `Все ${r.workers} потоков вместе: ${r.parallel.per_sec ?? '—'} эскизов/с (${r.parallel.files} файлов за ${r.parallel.sec} с).`;
  loadPerf();
};

// ================================================================== журнал

let logItems = [];
async function loadLogs() {
  const kind = $('log-kind').value;
  $('log-level').hidden = kind !== 'server';
  const q = kind === 'server' ? `?kind=server&level=${$('log-level').value}` : '?kind=audit';
  const r = await act(() => api('/api/admin/logs' + q)); if (!r) return;
  logItems = r.items.slice().reverse();
  drawLogs();
}
function drawLogs() {
  const kind = $('log-kind').value, f = $('log-filter').value.trim().toLowerCase();
  const rows = [];
  for (const it of logItems) {
    const text = kind === 'server' ? `${it.lvl} ${it.src} ${it.msg}` : `${AUDIT[it.ev] || it.ev} ${it.user} ${it.ip} ${it.detail}`;
    if (f && !text.toLowerCase().includes(f)) continue;
    const tr = el('tr');
    if (kind === 'server') {
      tr.className = 'lvl-' + it.lvl.toLowerCase();
      tr.append(el('td', 'nowrap', dt(it.t)), el('td', null, it.lvl), el('td', 'mono', it.msg));
    } else {
      if (/failed|denied|lockout/.test(it.ev)) tr.className = 'lvl-warning';
      tr.append(el('td', 'nowrap', dt(it.t)), el('td', null, AUDIT[it.ev] || it.ev), el('td', 'mono', it.user), el('td', 'mono', it.ip), el('td', null, it.detail));
    }
    rows.push(tr);
    if (rows.length >= 500) break;
  }
  $('log').tBodies[0].replaceChildren(...rows);
}
$('log-kind').onchange = loadLogs; $('log-level').onchange = loadLogs; $('log-refresh').onclick = loadLogs;
$('log-filter').oninput = drawLogs;

boot();
