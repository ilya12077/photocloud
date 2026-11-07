'use strict';
// Админка. Данные с сервера — только через textContent.

const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
const fmtDT = new Intl.DateTimeFormat('ru', { dateStyle: 'short', timeStyle: 'medium' });
const dt = (ts) => (ts ? fmtDT.format(new Date(ts * 1000)) : '—');
const EVENTS = {
  login: 'каждый вход', login_new_ip: 'вход с нового IP', login_failed: 'неудачный вход', lockout: 'блокировка IP',
  wake: 'кто-то будит ПК', wake_timeout: 'ПК не проснулся', index_error: 'ошибка чтения папки',
  backup_stale: 'бэкап давно не выходил на связь',
  damaged: 'повреждённые файлы на сервере (найден, восстановлен, исправлен)',
};
const AUDIT = {
  login: 'вход', login_google: 'вход через Google', login_failed: 'неудачный вход', login_google_denied: 'Google: аккаунт не привязан',
  login_google_failed: 'Google: ошибка', lockout: 'блокировка IP', logout: 'выход', setup: 'первичная настройка',
  setup_failed: 'неверный токен настройки', user_add: 'добавлен пользователь', user_delete: 'удалён пользователь',
  user_password: 'смена пароля', user_role: 'смена роли', user_google: 'привязка Google', user_folders: 'доступ к папкам', user_wake: 'право включать ПК', group: 'фото сгруппированы', vthumbs: 'подсчёт эскизов видео', ungroup: 'группа разобрана', hide: 'фото скрыты', unhide: 'фото возвращены в галерею', delete_mark: 'помечены на удаление', delete_unmark: 'снята пометка на удаление', info_stop: 'остановлен сбор метаданных', session_revoke: 'сессия закрыта',
  unlock_ip: 'IP разблокирован', settings: 'изменены настройки', wake: 'пробуждение ПК', cache_clear: 'очистка кэша',
  backup_token_add: 'создан токен бэкапа', backup_token_revoke: 'отозван токен бэкапа', backup_denied: 'бэкап: неверный токен',
  hash_stop: 'остановлен подсчёт хешей', hash_verify: 'запущена проверка хешей', hash_verify_done: 'проверка хешей завершена',
  hash_mismatch: 'хеш не совпал', damaged_found: 'повреждён файл на сервере', damaged_restored: 'восстановлена копия в Restored',
  damaged_fixed: 'повреждённый файл исправлен', damaged_lost: 'копию из Restored удалили', damaged_gone: 'повреждённый файл удалён',
  damaged_changed: 'повреждённый файл изменён', damaged_nosource: 'нет правильной копии', damaged_accept: 'принята новая версия файла',
  damaged_retry: 'восстановить заново', damaged_dismiss: 'запись о повреждённом файле убрана', restore_bad: 'присланная копия не совпала по хешу',
};

async function api(path, body) {
  const init = { credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) {
    init.method = 'POST';
    init.headers['X-Requested-With'] = 'photocloud';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const sent = Date.now();
  const r = await fetch(path, init);
  noteServerTime(r, sent);
  // после любого действия (кнопки) — сразу свежие данные открытой вкладки, не ждём опроса
  if (body !== undefined) polledAt = 0;
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
// Живое обновление: открытая вкладка сама перезапрашивает свои данные и перерисовывается,
// только если что-то поменялось. Ошибки фонового опроса не всплывают тостами.
let POLL = false;
const lastData = {};
function unchanged(key, data) {
  const j = JSON.stringify(data);
  const same = lastData[key] === j;
  lastData[key] = j;
  return POLL && same;
}
async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { if (!POLL) toast(e.message, true); return null; }
}
// подписи ячеек для телефона: там таблица показывается карточками «подпись — значение»
function labelize(tbody) {
  const head = tbody.closest('table').tHead;
  if (!head) return;
  const names = [...head.rows[0].cells].map((th) => th.textContent.trim());
  for (const tr of tbody.rows) {
    if (tr.classList.contains('fold-edit')) continue;
    [...tr.cells].forEach((td, i) => { if (names[i]) td.dataset.label = names[i]; });
  }
}
for (const tb of document.querySelectorAll('table.list tbody')) {
  new MutationObserver(() => labelize(tb)).observe(tb, { childList: true });
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

const POLL_MS = { overview: 3000, users: 5000, backup: 2000, perf: 5000, logs: 5000 };   // settings — нет: там форма
let curTab = 'overview', polledAt = 0, polling = false;
setInterval(async () => {
  const ms = POLL_MS[curTab];
  if (!ms || polling || document.hidden || $('panel').hidden || Date.now() - polledAt < ms) return;
  polling = true; POLL = true;
  try { await loaders[curTab](); } catch (_) { /* следующий раз */ } finally { POLL = false; polling = false; polledAt = Date.now(); }
}, 500);
document.addEventListener('visibilitychange', () => { if (!document.hidden) polledAt = 0; });   // вернулся во вкладку — сразу свежее

// «Пользователи» — вместе с сессиями и заблокированными IP
const loaders = { overview: loadOverview, users: () => Promise.all([loadUsers(), loadSecurity()]), backup: loadBackup,
  settings: loadSettings, perf: loadPerf, logs: loadLogs };
function showTab(name) {
  curTab = name; polledAt = Date.now();
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
  if (unchanged('overview', { ...o, uptime: Math.floor(o.uptime / 60) })) return;
  const ix = o.index;
  const cards = [
    ['Версия', o.version || '—'],
    ['Компьютер', { up: 'включён', down: 'выключен', waking: 'просыпается' }[o.pc] || o.pc],
    ['Файлов', `${ix.files.toLocaleString('ru')} (видео ${ix.videos.toLocaleString('ru')})`],
    ['Дата из метаданных', ix.files ? `${ix.with_date.toLocaleString('ru')} (${Math.round(ix.with_date / ix.files * 100)}%)` : '—'],
    ['Дата из имени файла', ix.files ? `${ix.with_name_date.toLocaleString('ru')} (${Math.round(ix.with_name_date / ix.files * 100)}%)` : '—'],
    ['Год по папке', ix.files ? `${(ix.with_folder_year ?? 0).toLocaleString('ru')} (${Math.round((ix.with_folder_year ?? 0) / ix.files * 100)}%)` : '—'],
    ['Индекс', ix.state + (ix.error ? ` (${ix.error})` : '') + (ix.meta[1] && ix.meta[0] < ix.meta[1] ? `, даты ${ix.meta[0]}/${ix.meta[1]}` : '')],
    ['Обновлён', dt(ix.built_at)],
    ...(o.hashes ? [['Хеши файлов', hashText(o.hashes, o.hashes.unhashed, o.hashes.files)]] : []),
    // число — ссылка на свои скрытые (/hidden)
    ['Эскизы видео в базе', (() => {
      const v = o.vthumbs || {}; vtRunning = v.state === 'running';
      $('act-vthumbs').textContent = vtRunning ? 'Остановить эскизы видео' : 'Посчитать эскизы видео';
      const base = `${(v.stored || 0).toLocaleString('ru')} из ${(v.videos || 0).toLocaleString('ru')} (${mb(v.bytes || 0)})`;
      if (vtRunning) return `${base} · считаются: ${v.done.toLocaleString('ru')} из ${v.total.toLocaleString('ru')}`;
      return base + ({ stopped: ' · подсчёт остановлен', pc: ' · ПК выключился — продолжится по кнопке' }[v.state] || '')
        + (v.failed ? ` · не вышло: ${v.failed}` : '');
    })()],
    ['Скрыто (у всех пользователей)', (() => { const a = el('a', null, (o.hidden || 0).toLocaleString('ru')); a.href = '/hidden'; a.title = 'Мои скрытые фото'; return a; })()],
    ['На удаление', `${(o.delete_marks || 0).toLocaleString('ru')} (удалит клиент на ПК — пока его нет)`],
    ['Эскизы в памяти сервера', `${mb(o.cache.thumb[0])} из ${mb(o.cache.thumb[1])}`],
    ['Превью в памяти сервера', `${mb(o.cache.preview[0])} из ${mb(o.cache.preview[1])}`],
    ['Сессий', String(o.sessions)],
    ['Работает', dur(o.uptime)],
  ];
  $('ov-cards').replaceChildren(...cards.map(([k, v]) => {
    const c = el('div', 'card'), vv = el('div', 'v');
    if (v instanceof Node) vv.append(v); else vv.textContent = v;
    c.append(el('div', 'k', k), vv); return c;
  }));
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
// эскизы видео в базе: идёт подсчёт — кнопка останавливает
$('act-vthumbs').onclick = () => (vtRunning
  ? act(() => api('/api/admin/vthumbs/stop', {}), 'Подсчёт остановлен')
  : act(() => api('/api/admin/vthumbs/start', {}), 'Считаю эскизы видео'));
let vtRunning = false;
$('act-wake').onclick = () => act(() => api('/api/wake', {}), 'Команда отправлена');
$('act-notify').onclick = () => act(() => api('/api/admin/notify-test', {}), 'Уведомление отправлено');
$('act-cache').onclick = () => act(() => api('/api/admin/cache/clear', {}), 'Кэш очищен').then(loadOverview);

// ================================================================== пользователи

async function loadUsers() {
  // пока открыт редактор папок или что-то в таблице в фокусе — не перерисовываем под рукой
  if (POLL && (document.querySelector('#users .fold-edit') || (document.activeElement && document.activeElement.closest('#users')))) return;
  const r = await act(() => api('/api/admin/users')); if (!r) return;
  if (unchanged('users', r)) return;
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
      const p = prompt(`Новый пароль для ${u.user} (от 8 символов). Все его сессии будут закрыты.`);
      if (p) act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/password`, { p }), 'Пароль изменён');
    }), btn('удалить', async () => {
      if (!confirm(`Удалить пользователя ${u.user}? Его сессии будут закрыты.`)) return;
      await act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/delete`, {}), 'Пользователь удалён');
      loadUsers();
    }, 'danger'));
    const tdRole = el('td'); tdRole.append(role);
    // папки: админ видит всё; пользователю — все или только выбранные (с подпапками)
    const fd = el('td');
    if (u.role === 'admin') fd.append(el('span', 'dim2', 'все (админ)'));
    else {
      fd.append(el('span', null, foldersText(u)), ' ',
        btn('изменить', () => editFolders(u, tr)));
    }
    // может ли включать компьютер кнопкой «Запустить компьютер» (админ — всегда)
    const wk = el('td');
    if (u.role === 'admin') wk.append(el('span', 'dim2', 'да (админ)'));
    else {
      const lab = el('label', 'wake-chk'), c = el('input'), txt = el('span');
      c.type = 'checkbox'; c.checked = u.wake !== false;
      const show = () => { txt.textContent = c.checked ? 'может' : 'нельзя'; };
      c.onchange = () => act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/wake`, { allow: c.checked }),
        c.checked ? 'Может включать ПК' : 'Не может включать ПК').then((x) => { if (!x) c.checked = !c.checked; show(); });
      show(); lab.append(c, txt); wk.append(lab);
    }
    tr.append(el('td', 'mono', u.user), tdRole, fd, wk, g, el('td', null, dt(u.created)), ops);
    return tr;
  }));
}

let folderList = null;
const under = (rel, fs) => fs.some((f) => rel === f || rel.startsWith(f + '/'));
const canSee = (rel, allow, deny) => (allow == null || under(rel, allow)) && !under(rel, deny || []);
function foldersText(u) {
  const ex = u.exclude && u.exclude.length ? ', кроме ' + u.exclude.join(', ') : '';
  if (u.folders == null) return 'все папки' + ex;
  return (u.folders.length ? u.folders.join(', ') : 'никакие') + ex;
}

// Галочки — просто удобство: отметил папку — отметились и вложенные (их можно снять),
// снял — снялись. При сохранении из галочек получается «разрешённые + скрытые внутри».
async function editFolders(u, tr) {
  if (tr.nextElementSibling && tr.nextElementSibling.classList.contains('fold-edit')) { tr.nextElementSibling.remove(); return; }
  if (!folderList) { const r = await act(() => api('/api/admin/folders')); if (!r) return; folderList = r.folders; }
  const row = el('tr', 'fold-edit'), td = el('td'); td.colSpan = 7; row.append(td);
  const all = el('label', 'fold-all'); const allChk = el('input'); allChk.type = 'checkbox';
  // «все папки» — только целиком, без исключений (старые записи «все, кроме…» показываем списком)
  allChk.checked = u.folders == null && !(u.exclude && u.exclude.length); all.append(allChk, ' все папки (и новые тоже)');
  const box = el('div', 'fold-list');
  const chks = folderList.map((f) => {
    const l = el('label', f.includes('/') ? 'sub' : null), c = el('input'); c.type = 'checkbox'; c.value = f;
    c.checked = canSee(f, u.folders, u.exclude);
    l.append(c, ' ' + f); box.append(l); return c;
  });
  const byName = new Map(chks.map((c) => [c.value, c]));
  const parentOf = (c) => { const i = c.value.lastIndexOf('/'); return i < 0 ? null : byName.get(c.value.slice(0, i)) || null; };
  // из галочек -> «разрешённые + скрытые внутри»
  const compute = () => {
    if (allChk.checked) return { folders: null, exclude: [] };
    return { folders: chks.filter((c) => c.checked && (!parentOf(c) || !parentOf(c).checked)).map((c) => c.value),
      exclude: chks.filter((c) => !c.checked && parentOf(c) && parentOf(c).checked).map((c) => c.value) };
  };
  // итог словами — сразу видно, что получится
  const summary = el('div', 'fold-sum');
  const refresh = () => { summary.textContent = 'Увидит: ' + foldersText(compute()); };
  for (const c of chks) c.addEventListener('change', () => {
    for (const d of chks) if (d.value.startsWith(c.value + '/')) d.checked = c.checked;   // вложенные — так же
    refresh();
  });
  // «все папки» отмечена — список неактивен (всё и так открыто); снята — выбираешь сам
  const syncAll = () => { for (const c of chks) { c.disabled = allChk.checked; if (allChk.checked) c.checked = true; } box.classList.toggle('off', allChk.checked); };
  allChk.addEventListener('change', () => { if (!allChk.checked) for (const c of chks) c.checked = false; syncAll(); refresh(); });
  syncAll(); refresh();
  const save = btn('сохранить', async () => {
    const { folders, exclude } = compute();
    if (folders && !folders.length && !confirm(`${u.user} не увидит ни одного фото. Сохранить?`)) return;
    const ok = await act(() => api(`/api/admin/users/${encodeURIComponent(u.user)}/folders`, { folders, exclude }), 'Доступ изменён');
    if (ok) loadUsers();
  });
  td.append(el('div', 'dim2', 'Отмеченная папка открыта вместе со всеми подпапками, кроме снятых. «Все папки» — всё, и новые папки тоже. Файлы прямо в корне — только при «все папки».'),
    all, box, summary);
  const bar = el('div', 'fold-btns'); bar.append(save, btn('отмена', () => row.remove())); td.append(bar);
  tr.after(row);
}

$('add-user').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ok = await act(() => api('/api/admin/users', { u: $('nu').value.trim(), p: $('np').value, role: $('nr').value }), 'Пользователь добавлен');
  if (ok) { $('nu').value = ''; $('np').value = ''; loadUsers(); }
});

// ================================================================== сессии / блокировки

async function loadSecurity() {
  const r = await act(() => api('/api/admin/sessions')); if (!r) return;
  if (!unchanged('sessions', r)) $('sessions').tBodies[0].replaceChildren(...r.sessions.map((s) => {
    const tr = el('tr'); const ops = el('td', 'ops');
    if (s.id === r.current) ops.append(el('span', 'dim2', 'текущая'));
    else ops.append(btn('закрыть', async () => { await act(() => api(`/api/admin/sessions/${s.id}/revoke`, {}), 'Сессия закрыта'); loadSecurity(); }, 'danger'));
    tr.append(el('td', 'mono', s.user), el('td', 'mono', s.ip), el('td', null, dt(s.created)), el('td', null, dt(s.last_seen)), ops);
    return tr;
  }));
  const l = await act(() => api('/api/admin/lockouts')); if (!l) return;
  if (unchanged('locks', l.locked.map((x) => [x.ip, Math.ceil(x.left / 60)]))) return;
  const tb = $('locks').tBodies[0];
  if (!l.locked.length) { const tr = el('tr'); const td = el('td', 'dim2', 'нет'); td.colSpan = 3; tr.append(td); tb.replaceChildren(tr); return; }
  tb.replaceChildren(...l.locked.map((x) => {
    const tr = el('tr'); const ops = el('td', 'ops');
    ops.append(btn('разблокировать', async () => { await act(() => api(`/api/admin/lockouts/${encodeURIComponent(x.ip)}/clear`, {}), 'Разблокирован'); loadSecurity(); }));
    tr.append(el('td', 'mono', x.ip), el('td', null, Math.ceil(x.left / 60) + ' мин'), ops);
    return tr;
  }));
}

// ================================================================== бэкап

const gb = (b) => (b >= 1073741824 ? (b / 1073741824).toFixed(1) + ' ГБ' : mb(b));
// скорость чтения с ПК — в битах, как у сети: 320 Мбит/с, 1,2 Гбит/с
function mbit(bps) {
  const m = bps * 8 / 1e6;
  return m >= 1000 ? `${(m / 1000).toFixed(1).replace('.', ',')} Гбит/с` : `${m < 10 ? m.toFixed(1).replace('.', ',') : Math.round(m)} Мбит/с`;
}
function leftTime(sec) {
  if (sec < 60) return 'меньше минуты';
  const m = Math.round(sec / 60);
  if (m < 60) return `${m} мин`;
  const h = Math.floor(m / 60), d = Math.floor(h / 24);
  return d ? `${d} д ${h % 24} ч` : `${h} ч ${m % 60} мин`;
}
// «· 320 Мбит/с · осталось ≈ 2 ч 10 мин» — пока скорость не набралась (первые секунды), ничего
const pace = (x) => (x.speed ? ` · ${mbit(x.speed)}` + (x.eta ? ` · осталось ≈ ${leftTime(x.eta)}` : '') : '');
// «Хеши файлов»: есть ли хеш у всех файлов, а если нет — как идёт подсчёт недостающих
function hashText(h, unhashed, files) {
  if (h.state === 'running') return `считаются: ${h.done.toLocaleString('ru')} из ${h.total.toLocaleString('ru')} (${gb(h.bytes_done)} из ${gb(h.bytes_total)})${pace(h)}`;
  if (!unhashed) return `есть у всех: ${files.toLocaleString('ru')}`;
  return `без хеша ${unhashed.toLocaleString('ru')} из ${files.toLocaleString('ru')} — `
    + (h.state === 'stopped' ? 'подсчёт остановлен' : h.state === 'error' ? 'подсчёт прервался из-за ошибок чтения' : 'посчитаются после сканирования');
}
const dday = (ts) => (ts ? new Date(ts * 1000).toLocaleDateString('ru') : '—');
function verifyText(v) {
  const bad = v.bad ? ` · изменённых: ${v.bad}` : '';
  if (v.state === 'running') return `идёт: ${v.done.toLocaleString('ru')} из ${v.total.toLocaleString('ru')} (${gb(v.bytes_done)} из ${gb(v.bytes_total)})${pace(v)}${bad}`;
  const at = v.total ? ` на ${v.done.toLocaleString('ru')} из ${v.total.toLocaleString('ru')}` : '';
  if (v.since && v.paused) return `остановлена${at} — продолжится по кнопке${bad}`;
  if (v.since) return `прервалась${at} — продолжится ${v.pc ? 'сама в течение минуты' : 'когда ПК включится'}${bad}`;
  return v.last ? `последняя ${dday(v.last)}, следующая ${dday(v.next)}${bad}` : 'ещё не было';
}
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
}
// Часы браузера могут спешить или отставать: время «на связи» и отчёты — по часам сервера,
// поэтому «сейчас» тоже берём серверное: сдвиг = время сервера − время браузера (середина запроса).
let clockSkew = 0, skewRtt = Infinity, skewAt = 0;
function noteServerTime(r, sent) {
  const srv = +r.headers.get('x-server-time');
  if (!srv) return;
  const got = Date.now(), rtt = got - sent;
  // точнее всего — самый быстрый ответ; раз в 10 минут берём заново (часы могли перевести)
  if (rtt <= skewRtt || got - skewAt > 600000) { clockSkew = srv - (sent + got) / 2; skewRtt = rtt; skewAt = got; }
}
const serverNow = () => (Date.now() + clockSkew) / 1000;
function ago(ts) {
  if (!ts) return 'ещё не было';
  const s = Math.max(1, Math.round(serverNow() - ts));
  if (s < 60) return `${s} ${plural(s, 'секунду', 'секунды', 'секунд')} назад`;
  if (s < 3600) { const m = Math.floor(s / 60); return `${m} ${plural(m, 'минуту', 'минуты', 'минут')} назад`; }
  if (s < 172800) { const h = Math.floor(s / 3600); return `${h} ${plural(h, 'час', 'часа', 'часов')} назад`; }
  const d = Math.floor(s / 86400); return `${d} ${plural(d, 'день', 'дня', 'дней')} назад`;
}
// «N секунд назад» идёт каждую секунду — без перезапроса и перерисовки таблицы
setInterval(() => { for (const e of document.querySelectorAll('[data-ago]')) e.textContent = ago(+e.dataset.ago); }, 1000);
const BK_STATE = { copying: 'копирует', restoring: 'восстанавливает файл на сервере', disk_full: 'мало места на диске', done: 'всё скопировано', paused: 'пауза', pc_off: 'ждёт включения ПК', waiting: 'ждёт хешей', error: 'ошибка', confirm: 'ждёт подтверждения удалений' };

const mbs = (b) => (b >= 1048576 ? (b / 1048576).toFixed(1).replace('.', ',') + ' МБ/с' : Math.round(b / 1024) + ' КБ/с');
async function loadBackup() {
  loadDamaged();
  const r = await act(() => api('/api/admin/backup')); if (!r) return;
    if (unchanged('backup', r)) return;
  const v = r.verify;
  const hRun = r.hashes.state === 'running', vRun = v.state === 'running';
  const hText = !r.tokens.length ? 'не считаются — нет клиентов' : hashText(r.hashes, r.unhashed, r.files);
  const cards = [['Хеши файлов', hText],
    ['Проверка хешей', !r.tokens.length ? 'не нужна — нет клиентов' : verifyText(v)], ['Клиентов', String(r.tokens.length)]];
  $('bk-cards').replaceChildren(...cards.map(([k, val]) => { const c = el('div', 'card'); c.append(el('div', 'k', k), el('div', 'v', val)); return c; }));
  $('bk-hash-start').hidden = hRun || vRun || !r.unhashed || !r.tokens.length;
  $('bk-hash-stop').hidden = !hRun;
  $('bk-verify-stop').hidden = !vRun;
  $('bk-verify-start').hidden = vRun || hRun || !r.tokens.length;
  $('bk-verify-start').textContent = v.since ? 'Продолжить проверку хешей' : 'Проверить хеши всех файлов';
  const sel = $('bk-user'), cur = sel.value;
  if ([...sel.options].map((o) => o.value).join('\n') !== r.users.join('\n')) {     // открытый список не закрываем зря
    sel.replaceChildren(...r.users.map((u) => { const o = el('option', null, u); o.value = u; return o; }));
    if (cur && r.users.includes(cur)) sel.value = cur;
  }
  const tb = $('bk-tokens').tBodies[0];
  if (!r.tokens.length) { const tr = el('tr'); const td = el('td', 'dim2', 'клиентов пока нет'); td.colSpan = 8; tr.append(td); tb.replaceChildren(tr); return; }
  tb.replaceChildren(...r.tokens.map((t) => {
    const tr = el('tr'), rp = t.report || {}, ops = el('td', 'ops');
    ops.append(btn('отозвать', async () => {
      if (!confirm(`Отозвать токен «${t.name}»? Клиент перестанет копировать, уже скопированное у него останется.`)) return;
      await act(() => api(`/api/admin/backup/tokens/${t.id}/revoke`, {}), 'Токен отозван'); loadBackup();
    }, 'danger'));
    const copied = rp.files != null ? `${(rp.files - (rp.left_files || 0)).toLocaleString('ru')} файлов, ${gb((rp.bytes || 0) - (rp.left_bytes || 0))}` : '—';
    const left = rp.left_files != null ? (rp.left_files ? `${rp.left_files.toLocaleString('ru')} (${gb(rp.left_bytes || 0)})` : 'ничего') : '—';
    const st = el('td');
    st.append(el('div', null, BK_STATE[rp.state] || rp.state || '—'));
    // давно не было отчёта — «копирует» уже не правда
    const fresh = rp.at && serverNow() - rp.at < 60;
    if (rp.state === 'copying' && fresh) {
      const bits = [];
      if (rp.stall) bits.push(`ждёт данные с ПК ${rp.stall} с`);
      else if (rp.speed) bits.push(mbs(rp.speed));
      if (rp.limit_mbps) bits.push(`лимит ${rp.limit_mbps} Мбит/с`);
      if (rp.raw_bytes > rp.wire_bytes && rp.wire_bytes) bits.push(`сжатие −${Math.round((1 - rp.wire_bytes / rp.raw_bytes) * 100)}%`);
      if (bits.length) st.append(el('div', 'dim2', bits.join(' · ')));
      if (rp.current) {
        const pct = rp.cur_size ? ` — ${Math.floor(rp.cur_done / rp.cur_size * 100)}%` : '';
        const f = el('div', 'dim2 bk-cur', rp.current.split('/').pop() + pct); f.title = rp.current; st.append(f);
      }
    } else if (rp.state === 'copying') st.firstChild.textContent = 'копировал, давно нет связи';
    if (rp.pending_delete && rp.state !== 'confirm') st.append(el('div', 'err', `ждёт подтверждения: с ПК пропало ${rp.pending_delete.toLocaleString('ru')} файлов`));
    // пока идёт проверка, отчёт приходит раз в 5 с; старый отчёт с ходом проверки — уже не правда
    // (клиенты до 1.4.2 сообщали об окончании проверки только через 5 минут)
    if (rp.verify_total && (fresh || rp.state === 'paused')) st.append(el('div', 'dim2', `проверка копий: ${rp.verify_done.toLocaleString('ru')} из ${rp.verify_total.toLocaleString('ru')}`));
    else if (rp.verify_last) st.append(el('div', 'dim2', `копии проверены ${dday(rp.verify_last)}`));
    if (rp.verify_bad) st.append(el('div', 'err', `повреждённых копий: ${rp.verify_bad} (скачиваются заново)`));
    if (rp.errors) st.append(el('div', 'dim2', `ошибок: ${rp.errors}`));
    if (rp.error) st.append(el('div', 'err', rp.error));
    const seen = el('td', null, ago(t.last_seen)); if (t.last_ip) seen.title = t.last_ip;
    if (t.last_seen) seen.dataset.ago = t.last_seen;
    tr.append(el('td', null, t.name), el('td', 'mono', t.user), seen, el('td', null, copied), el('td', null, left), st, el('td', null, dt(t.created)), ops);
    return tr;
  }));
}
async function loadDamaged() {
  const r = await act(() => api('/api/admin/damaged')); if (!r) return;
  if (unchanged('damaged', r)) return;
  const tb = $('dmg').tBodies[0];
  $('dmg-check').hidden = !r.items.some((d) => ['found', 'nosource', 'restored', 'lost'].includes(d.state));
  if (!r.items.length) { const tr = el('tr'); const td = el('td', 'dim2', 'нет — всё в порядке'); td.colSpan = 4; tr.append(td); tb.replaceChildren(tr); return; }
  tb.replaceChildren(...r.items.map((d) => {
    const tr = el('tr'), ops = el('td', 'ops'), st = el('td');
    const active = ['found', 'nosource', 'restored', 'lost'].includes(d.state);
    st.append(el('div', active ? 'err' : null, (d.unreadable ? 'не читается · ' : '') + d.text));
    if (d.state === 'restored' && d.restored) st.append(el('div', 'dim2 mono', `${r.folder}/${d.restored}`));
    if (d.note) st.append(el('div', 'dim2', d.note));
    if (active && !d.unreadable) ops.append(btn('это не порча', async () => {
      if (!confirm(`Принять текущий «${d.path}» как правильный? Клиенты скачают его, а их копия уйдёт в «Версии».`)) return;
      await act(() => api('/api/admin/damaged/accept', { path: d.path }), 'Принят как новая версия'); loadDamaged();
    }));
    if (['nosource', 'lost', 'restored'].includes(d.state)) ops.append(btn('восстановить заново', async () => {
      await act(() => api('/api/admin/damaged/retry', { path: d.path }), 'Восстановление запрошено'); loadDamaged();
    }));
    if (!active) ops.append(btn('убрать', async () => {
      await act(() => api('/api/admin/damaged/dismiss', { path: d.path }), 'Убрано из списка'); loadDamaged();
    }));
    tr.append(el('td', 'mono', d.path), el('td', null, dt(d.found)), st, ops);
    return tr;
  }));
}
$('dmg-check').onclick = () => act(() => api('/api/admin/damaged/check', {}), 'Проверено').then(loadDamaged);
$('bk-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await act(() => api('/api/admin/backup/tokens', { name: $('bk-name').value.trim(), user: $('bk-user').value }), 'Токен создан');
  if (!r) return;
  $('bk-name').value = ''; $('bk-token').value = r.token; $('bk-new').hidden = false; $('bk-token').select();
  loadBackup();
});
$('bk-copy').onclick = async () => {
  try { await navigator.clipboard.writeText($('bk-token').value); toast('Скопировано'); } catch (_) { $('bk-token').select(); document.execCommand('copy'); toast('Скопировано'); }
};
$('bk-hash-stop').onclick = () => act(() => api('/api/admin/backup/hashes/stop', {}), 'Подсчёт остановлен').then(loadBackup);
$('bk-verify-start').onclick = () => act(() => api('/api/admin/backup/verify/start', {}), 'Проверка хешей запущена').then(loadBackup);
$('bk-verify-stop').onclick = () => act(() => api('/api/admin/backup/verify/stop', {}), 'Проверка остановлена').then(loadBackup);
$('bk-hash-start').onclick = () => act(() => api('/api/admin/backup/hashes/start', {}), 'Подсчёт хешей запущен').then(loadBackup);

// ================================================================== настройки

async function loadSettings() {
  const r = await act(() => api('/api/admin/settings')); if (!r) return;
  const s = r.settings;
  $('s-name').value = s.public_name;
  $('s-notify').value = s.ha_notify_service;
  $('s-wake').value = s.ha_wake_service;
  $('s-wakedata').value = Object.keys(s.ha_wake_data || {}).length ? JSON.stringify(s.ha_wake_data) : '';
  $('s-waket').value = s.wake_timeout; $('s-ttl').value = s.index_ttl; $('s-idle').value = s.session_idle_hours;
  $('s-bkstale').value = s.backup_stale_days;
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
    backup_stale_days: +$('s-bkstale').value,
  };
  const r = await act(() => api('/api/admin/settings', body));
  if (r) toast(r.changed.length ? 'Сохранено: ' + r.changed.length : 'Без изменений');
});

// ================================================================== скорость

const KIND = { s: 'эскиз 240', t: 'эскиз 400', m: 'эскиз 900', q: 'быстрое 720', p: 'превью 2048' };
const ms = (v) => (v == null ? '—' : v >= 1000 ? (v / 1000).toFixed(1) + ' с' : Math.round(v) + '');

async function loadPerf() {
  const r = await act(() => api('/api/admin/perf')); if (!r) return;
  if (unchanged('perf', r)) return;
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
  if (unchanged('logs' + q, r.items.length ? [r.items.length, r.items[r.items.length - 1]] : [])) return;
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
      // пользователь и IP — в одну строку; длинные имена файлов переносятся только в подробностях
      tr.append(el('td', 'nowrap', dt(it.t)), el('td', null, AUDIT[it.ev] || it.ev), el('td', 'mono nowrap', it.user),
        el('td', 'mono nowrap', it.ip), el('td', 'wrap', it.detail));
    }
    rows.push(tr);
    if (rows.length >= 500) break;
  }
  $('log').tBodies[0].replaceChildren(...rows);
}
$('log-kind').onchange = loadLogs; $('log-level').onchange = loadLogs; $('log-refresh').onclick = loadLogs;
$('log-filter').oninput = drawLogs;

boot();
