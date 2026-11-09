'use strict';
// Photocloud UI. Данные с сервера попадают в DOM только через textContent / атрибуты —
// никакого innerHTML с данными.

const $ = (id) => document.getElementById(id);

// Цвет строки браузера = цвет шапки. Встроенные браузеры (Telegram и т. п.) не понимают theme-color
// с media="(prefers-color-scheme…)" и оставляют строку прозрачной — ставим один тег без media
// с текущим цветом темы и меняем его, если тема переключилась.
(function themeColor() {
  const dark = window.matchMedia && matchMedia('(prefers-color-scheme: dark)');
  const set = () => {
    const c = dark && dark.matches ? '#111214' : '#f6f5f2';
    document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.remove());
    const m = document.createElement('meta'); m.name = 'theme-color'; m.content = c; document.head.append(m);
  };
  set();
  if (dark && dark.addEventListener) dark.addEventListener('change', set);
})();
const MONTHS = ['Январь','Февраль','Март','Апрель','Май','Июнь','Июль','Август','Сентябрь','Октябрь','Ноябрь','Декабрь'];
const MONTHS_SHORT = ['янв','фев','мар','апр','май','июн','июл','авг','сен','окт','ноя','дек'];
const HEAD_H = 46;          // высота заголовка месяца, px
const BUFFER = 1.2;         // сколько экранов рендерим сверху/снизу
const F_VIDEO = 1, F_TAKEN = 2, F_NAME = 4, F_NOPLAY = 8, F_LIVE = 16, F_FOLDER = 32;
// /hidden — та же галерея, но только скрытые фото (тем, кто может скрывать; сервер отдаёт их
// только из папок пользователя)
const HID = location.pathname === '/hidden';
// /starred — избранное пользователя (у каждого своё)
const STARRED = location.pathname === '/starred';
const HQ = HID ? '?hidden=1' : STARRED ? '?starred=1' : '';

const st = {
  me: null,
  lib: null,          // {v, folders, photos:[[id, fidx, name, date, mtime, sizeKB, flags]]}
  children: null, totals: null, cover: null, folderIdx: null, parent: null,
  folder: '', sort: 'new', rec: true,
  list: [],           // текущий отсортированный список
  pc: 'unknown', pollTimer: 0, newVersion: null,
};
const Z = { cols: 3, pinch: null, wheel: 0, sizes: { s: 240, t: 400, m: 900 } };
const L = { rows: [], height: 0, tileH: 0, gap: 3, rendered: new Map(), lastY: 0, idleT: 0, fast: false, calmUntil: 0 };

function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (_) { return null; } }
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

async function api(path, opts = {}) {
  const init = { credentials: 'same-origin', cache: opts.cache || 'no-store', headers: {} };
  if (opts.timeout && window.AbortSignal && AbortSignal.timeout) init.signal = AbortSignal.timeout(opts.timeout);
  if (opts.poll) init.headers['X-Poll'] = '1';     // фоновый опрос: сессию не продлевает
  if (opts.method && opts.method !== 'GET') {
    init.method = opts.method;
    init.headers['X-Requested-With'] = 'photocloud';
    if (opts.body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
  }
  const r = await fetch(path, init);
  if (r.status === 401 && !opts.allow401) { showLogin(); throw new Error('auth'); }
  return r;
}

// ================================================================== вход

const LOGIN_ERRORS = {
  'google': 'Не удалось войти через Google, попробуй ещё раз',
  'google-denied': 'Этот Google-аккаунт не привязан ни к одному пользователю',
  'google-cancel': 'Вход через Google отменён',
  'yandex': 'Не удалось войти через Яндекс ID, попробуй ещё раз',
  'yandex-denied': 'Этот аккаунт Яндекса не привязан ни к одному пользователю',
  'yandex-cancel': 'Вход через Яндекс ID отменён',
  'locked': 'Слишком много попыток входа, подожди 15 минут',
};

async function showLogin(msg) {
  stopPoll(); closeViewer(true); $('pk-offer').hidden = true;
  $('main').hidden = true; $('login').hidden = false;
  $('login-form').hidden = false; $('tfa-form').hidden = true;
  $('lerr').textContent = msg || '';
  try { const r = await fetch('/api/auth/providers', { cache: 'no-store' }); const p = await r.json(); $('lgoogle').hidden = !p.google; $('lyandex').hidden = !p.yandex; googleHref(); } catch (_) {}
  pkLoginPrep();
  setTimeout(() => $('lu').focus(), 0);
}

// ---- вход по ключу (passkey, WebAuthn)
const PK_OK = !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
const b64u = { dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer,
  enc: (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
function pkCred(c) {      // ответ устройства -> JSON для сервера
  const r = c.response, o = { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, response: { clientDataJSON: b64u.enc(r.clientDataJSON) },
    authenticatorAttachment: c.authenticatorAttachment || undefined, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
  if (r.attestationObject) { o.response.attestationObject = b64u.enc(r.attestationObject); if (r.getTransports) o.response.transports = r.getTransports(); }
  if (r.authenticatorData) { o.response.authenticatorData = b64u.enc(r.authenticatorData); o.response.signature = b64u.enc(r.signature);
    if (r.userHandle) o.response.userHandle = b64u.enc(r.userHandle); }
  return o;
}
$('lkey').hidden = !PK_OK;
// Safari (iPhone) разрешает ключ только сразу после нажатия: если перед вызовом ключа ждать ответа
// сервера, он отказывает. Поэтому вызов от сервера (challenge) готовим заранее, пока открыт вход.
const PK = { login: null, at: 0, reg: null };
function pkPrepOpts(opt) {
  opt.challenge = b64u.dec(opt.challenge);
  if (opt.user) opt.user.id = b64u.dec(opt.user.id);
  for (const k of ['allowCredentials', 'excludeCredentials']) if (opt[k]) opt[k] = opt[k].map((c) => ({ ...c, id: b64u.dec(c.id) }));
  return opt;
}
async function pkLoginPrep() {
  PK.login = null;
  if (!PK_OK || $('login').hidden) return;
  try {
    const o = await api('/api/passkey/login/options', { method: 'POST', body: {}, allow401: true });
    if (o.ok) { PK.login = pkPrepOpts(await o.json()); PK.at = Date.now(); }
  } catch (_) {}
}
const pkFresh = () => PK.login && Date.now() - PK.at < 4 * 60 * 1000;   // сервер помнит вызов 5 минут
document.addEventListener('visibilitychange', () => { if (!document.hidden && !$('login').hidden && !pkFresh()) pkLoginPrep(); });
$('lkey').addEventListener('click', async () => {
  const btn = $('lkey'); $('lerr').textContent = '';
  if (!pkFresh()) {
    // вызов не готов (сеть) — получить и попросить нажать ещё раз: так Safari не откажет
    btn.disabled = true; await pkLoginPrep(); btn.disabled = false;
    if (!PK.login) { $('lerr').textContent = 'Вход по ключу сейчас недоступен'; return; }
    if (/iPhone|iPad|Macintosh/.test(navigator.userAgent) && 'ontouchend' in document) { $('lerr').textContent = 'Нажми «Войти по ключу» ещё раз'; return; }
  }
  const opt = PK.login; PK.login = null;
  let cred;
  try { cred = await navigator.credentials.get({ publicKey: opt }); }        // первым делом — сразу после нажатия
  catch (e) {
    $('lerr').textContent = e && e.name === 'NotAllowedError' ? 'Вход по ключу отменён (или на этом устройстве нет ключа для сайта)'
      : 'Вход по ключу не удался' + (e && e.name ? ` (${e.name})` : '');
    pkLoginPrep(); return;
  }
  btn.disabled = true;
  try {
    const r = await api('/api/passkey/login', { method: 'POST', body: { credential: pkCred(cred), r: $('lr').checked }, allow401: true });
    if (r.ok) { await enter(); return; }
    $('lerr').textContent = r.status === 429 ? 'Слишком много попыток, подожди 15 минут'
      : 'Этот ключ не подошёл (возможно, его удалил администратор)';
    pkLoginPrep();
  } catch (_) { $('lerr').textContent = 'Сервер недоступен'; }
  finally { btn.disabled = false; }
});

// предложение админа создать ключ на этом устройстве — после входа
function pkOffer() {
  if (!PK_OK || !st.me || !st.me.passkey_offer || sessionStorageGet('pk-later')) return;
  $('pk-err').textContent = ''; $('pk-offer').hidden = false;
  pkRegPrep();
}
async function pkRegPrep() {          // как и со входом: всё от сервера — заранее, до нажатия «Создать ключ»
  PK.reg = null;
  try {
    const o = await api('/api/passkey/register/options', { method: 'POST', body: {} });
    const j = await o.json();
    if (o.ok) PK.reg = { opt: pkPrepOpts(j.options), ticket: j.ticket, at: Date.now() };
    else $('pk-err').textContent = j.error || ('Ошибка ' + o.status);
  } catch (_) { $('pk-err').textContent = 'Сервер недоступен'; }
}
function sessionStorageGet(k) { try { return sessionStorage.getItem(k); } catch (_) { return null; } }
$('pk-later').addEventListener('click', () => { try { sessionStorage.setItem('pk-later', '1'); } catch (_) {} $('pk-offer').hidden = true; });
$('pk-create').addEventListener('click', async () => {
  const btn = $('pk-create'); $('pk-err').textContent = '';
  if (!PK.reg || Date.now() - PK.reg.at > 4 * 60 * 1000) {
    btn.disabled = true; await pkRegPrep(); btn.disabled = false;
    if (PK.reg) $('pk-err').textContent = 'Готово — нажми «Создать ключ» ещё раз';
    return;
  }
  const { opt, ticket } = PK.reg; PK.reg = null;
  let cred;
  try { cred = await navigator.credentials.create({ publicKey: opt }); }      // сразу после нажатия
  catch (e) {
    $('pk-err').textContent = e && e.name === 'InvalidStateError' ? 'На этом устройстве ключ уже есть'
      : e && e.name === 'NotAllowedError' ? 'Создание ключа отменено' : 'Не удалось создать ключ' + (e && e.name ? ` (${e.name})` : '');
    pkRegPrep(); return;
  }
  btn.disabled = true;
  try {
    const name = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
    const r = await api('/api/passkey/register', { method: 'POST', body: { ticket, credential: pkCred(cred), name } });
    const k = await r.json().catch(() => ({}));
    if (!r.ok) { $('pk-err').textContent = k.error || ('Ошибка ' + r.status); pkRegPrep(); return; }
    st.me.passkey_offer = false; $('pk-offer').hidden = true;
    banner('Ключ входа создан — в следующий раз нажми «Войти по ключу»');
    setTimeout(() => { if (/^Ключ входа создан/.test($('banner-text').textContent)) banner(null); }, 5000);
  } catch (_) { $('pk-err').textContent = 'Сервер недоступен'; }
  finally { btn.disabled = false; }
});

// «Запомнить вход» действует и на вход через Google
const googleHref = () => {
  const q = $('lr').checked ? '?r=1' : '';
  $('lgoogle').href = '/auth/google' + q; $('lyandex').href = '/auth/yandex' + q;
};
$('lr').addEventListener('change', googleHref);

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('lbtn'); btn.disabled = true; $('lerr').textContent = '';
  try {
    const r = await api('/api/login', { method: 'POST', body: { u: $('lu').value.trim(), p: $('lp').value, r: $('lr').checked }, allow401: true });
    if (r.ok) {
      $('lp').value = '';
      const j = await r.json().catch(() => ({}));
      if (j.need === 'totp') { showTfaStep(); return; }
      await enter(); return;
    }
    if (r.status === 429) {
      const j = await r.json().catch(() => ({}));
      $('lerr').textContent = `Слишком много попыток. Подожди ${Math.ceil((j.retry || 900) / 60)} мин.`;
    } else if (r.status === 401) $('lerr').textContent = 'Неверный логин или пароль';
    else $('lerr').textContent = 'Ошибка входа (' + r.status + ')';
  } catch (_) { $('lerr').textContent = 'Сервер недоступен'; }
  finally { btn.disabled = false; }
});

// второй шаг входа
async function showTfaStep(msg) {
  $('main').hidden = true; $('login').hidden = false;
  $('login-form').hidden = true; $('tfa-form').hidden = false;
  $('tc').value = ''; $('terr').textContent = msg || ''; $('tsetup').hidden = true;
  $('thint').textContent = 'Введи 6 цифр из приложения-аутентификатора.';
  // админ включил двухфакторный вход, а приложение ещё не настроено — показать QR-код и ключ
  try {
    const r = await fetch('/api/login/2fa', { credentials: 'same-origin', cache: 'no-store' });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) { showLogin('Время на ввод кода вышло — войди заново'); return; }
    if (j.need === 'setup') {
      $('thint').textContent = 'Администратор включил двухфакторный вход. Добавь аккаунт в приложение '
        + '(Google Authenticator, Яндекс Ключ…): отсканируй QR-код или введи ключ вручную — и введи 6 цифр, которые оно покажет.';
      $('tqr').hidden = !j.qr; if (j.qr) $('tqr').src = j.qr;
      $('tkey').textContent = j.secret.replace(/(.{4})/g, '$1 ').trim();
      $('tsetup').hidden = false;
    }
  } catch (_) {}
  setTimeout(() => $('tc').focus(), 0);
}
$('tback').addEventListener('click', () => showLogin());
$('tfa-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('tbtn'); btn.disabled = true; $('terr').textContent = '';
  try {
    const r = await api('/api/login/2fa', { method: 'POST', body: { code: $('tc').value }, allow401: true });
    const j = await r.json().catch(() => ({}));
    if (r.ok) {
      $('tc').value = '';
      await enter();
      return;
    }
    if (r.status === 429) $('terr').textContent = `Слишком много попыток. Подожди ${Math.ceil((j.retry || 900) / 60)} мин.`;
    else if (j.error === 'expired') showLogin('Время на ввод кода вышло — войди заново');
    else $('terr').textContent = j.left ? `Код не подошёл (осталось попыток: ${j.left})` : 'Код не подошёл — войди заново';
    if (j.error === 'code' && !j.left) setTimeout(() => showLogin(), 1500);
  } catch (_) { $('terr').textContent = 'Сервер недоступен'; }
  finally { btn.disabled = false; }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (_) {}
  st.lib = null; clearGrid(); $('folders').replaceChildren(); hideMenu();
  showLogin();
});

async function enter() {
  let err = null;
  const m = location.hash.match(/^#err=([a-z-]+)$/);
  if (m) { err = LOGIN_ERRORS[m[1]] || 'Ошибка входа'; history.replaceState(null, '', location.pathname); }
  // список файлов запрашиваем сразу, параллельно с проверкой входа — на медленном канале
  // это экономит пару «туда-обратно» до первых эскизов
  st.libPromise = fetch('/api/library' + HQ, { credentials: 'same-origin', cache: 'no-cache' }).catch(() => null);
  const r = await api('/api/me', { allow401: true });
  if (r.status === 401) { st.libPromise = null; showLogin(err); return; }
  const me = await r.json(); st.me = me;
  if (me.name) { $('title').textContent = me.name; document.title = me.name; }
  if (me.sizes) Z.sizes = me.sizes;
  $('admin-link').hidden = me.role !== 'admin';
  $('menu-hidden').hidden = HID;
  $('menu-starred').hidden = STARRED || HID;
  $('menu-all').hidden = !HID && !STARRED;
  // действия с выбранными: скрыть (кому можно), вернуть (на /hidden), избранное (всем, кроме /hidden)
  // скрывать и группировать может каждый (у каждого свои); «удалить окончательно» — только админ
  $('sel-hide').hidden = HID; $('sel-show').hidden = !HID; $('sel-del').hidden = !HID || !me.can_delete;
  $('sel-group').hidden = HID;
  $('sel-star').hidden = HID || STARRED; $('sel-unstar').hidden = !STARRED;
  $('v-star').hidden = HID;
  if (HID || STARRED) {
    document.title = (HID ? 'Скрытые фото — ' : 'Избранное — ') + (me.name || 'Фотоархив');
    // название сайта в шапке ведёт на основную страницу
    const brand = document.querySelector('.top .brand'); brand.href = '/'; brand.title = 'Ко всем фото';
  }
  loadStars();
  if (HID && me.can_delete) loadMarks();
  pkOffer();
  $('login').hidden = true; $('main').hidden = false;
  readRoute(); initZoom();
  poll();
  const early = await st.libPromise; st.libPromise = null;
  if (early && early.ok && !st.lib) await loadLibrary(early);
}

// ================================================================== меню / настройки клиента

function hideMenu() { $('menu').hidden = true; $('menu-btn').setAttribute('aria-expanded', 'false'); }
$('menu-btn').addEventListener('click', (e) => { e.stopPropagation(); const h = !$('menu').hidden; $('menu').hidden = h; $('menu-btn').setAttribute('aria-expanded', String(!h)); });
document.addEventListener('click', (e) => { if (!$('menu').hidden && !e.target.closest('.menu-wrap')) hideMenu(); });


// ================================================================== статус / пробуждение

function stopPoll() { clearTimeout(st.pollTimer); st.pollTimer = 0; }

function banner(text, btnText, onClick, bad) {
  const b = $('banner');
  if (!text) { b.hidden = true; return; }
  b.hidden = false; b.classList.toggle('bad', !!bad);
  $('banner-text').textContent = text;
  const btn = $('banner-btn');
  if (btnText) {
    btn.hidden = false; btn.textContent = btnText; btn.disabled = false;
    // после нажатия — сразу свежее состояние с сервера (надпись меняется сразу, а не при
    // следующем опросе через 10–30 с)
    btn.onclick = async () => {
      btn.disabled = true;
      let r;
      try { r = await onClick(); } catch (_) { /* покажет опрос */ }
      btn.disabled = false;
      if (r !== false) poll();          // false — действие само показало ошибку, не затираем её
    };
  } else btn.hidden = true;
}

async function wake() {
  banner('Отправляю команду включения…');
  try {
    const r = await api('/api/wake', { method: 'POST' });
    if (!r.ok) { banner('Home Assistant не ответил на команду включения', 'Повторить', wake, true); poll(10000); return false; }
  } catch (_) {}
  poll(1500);
}

async function poll(delay) {
  stopPoll();
  if (delay) { st.pollTimer = setTimeout(() => poll(), delay); return; }
  let s;
  try { s = await (await api('/api/status' + HQ, { timeout: 15000, poll: true })).json(); }
  catch (e) {
    if (e.message !== 'auth') { banner('Сервер недоступен, пробую снова…', null, null, true); st.pollTimer = setTimeout(() => poll(), 5000); }
    return;
  }
  const prevPc = st.pc; st.pc = s.pc;
  const ix = s.index;
  let next = 30000;
  const metaBusy = ix.meta && ix.meta[1] > 0 && ix.meta[0] < ix.meta[1];

  if (s.pc === 'down') {
    // сами не будим: включает только пользователь по кнопке
    // эскизы сетки хранятся на сервере — без ПК не открываются только фото и видео целиком
    banner((s.wake_failed ? 'Не удалось включить компьютер' : 'Компьютер выключен') +
      (ix.count ? ' — загружаются только превью, полностью фото не загрузятся' : ' — включите его, чтобы смотреть фото'),
      st.me && st.me.can_wake === false ? null : (s.wake_failed ? 'Попробовать ещё раз' : 'Запустить компьютер'), wake, true);
    next = 10000;
  } else if (s.pc === 'waking') {
    banner(`Компьютер просыпается… (ещё до ${s.wake_left} с)`); next = 2000;
  } else if (ix.state === 'building') {
    banner(ix.count ? `Обновляю список… (${ix.progress})` : `Сканирую папки… найдено ${ix.progress}`); next = 1500;
  } else if (ix.state === 'error') {
    // пересканировать может только админ; остальным — просто сообщение (сервер повторит сам)
    const admin = st.me && st.me.role === 'admin';
    banner('Не удалось прочитать папку на компьютере' + (admin ? ' (проверь доступ)' : ''), admin ? 'Повторить' : null, reindex, true); next = 15000;
  } else if (metaBusy) {
    banner(`Читаю даты съёмки: ${ix.meta[0].toLocaleString('ru')} из ${ix.meta[1].toLocaleString('ru')}`); next = 3000;
  } else if (ix.info && ix.info[2] === 'running') {
    // фоновый сбор подробностей (камера, размеры, место) — админ может остановить
    const admin = st.me && st.me.role === 'admin';
    banner(`Сбор метаданных из файлов (${ix.info[0].toLocaleString('ru')} из ${ix.info[1].toLocaleString('ru')})`,
      admin ? 'Остановить' : null, stopInfo); next = 3000;
  } else if (st.newVersion && st.lib) {
    banner('Список файлов обновился', 'Показать', async () => { st.newVersion = null; banner(null); await loadLibrary(); });
  } else if (s.bg) {
    // фоновый подсчёт или проверка хешей (только админу) — читают файлы с ПК, эскизы медленнее
    const b = s.bg, sp = b.speed ? ` · ${Math.round(b.speed * 8 / 1e6)} Мбит/с` + (b.eta ? ` · осталось ≈ ${leftTime(b.eta)}` : '') : '';
    banner(`${b.kind === 'verify' ? 'Проверка хешей' : 'Считаю хеши для бэкапа'}: ${b.done.toLocaleString('ru')} из ${b.total.toLocaleString('ru')}${sp}`,
      'Остановить', () => api(`/api/admin/backup/${b.kind === 'verify' ? 'verify' : 'hashes'}/stop`, { method: 'POST' }));
    next = 3000;
  } else banner(null);

  if (ix.v && !st.lib && !st.libPromise) await loadLibrary();
  else if (ix.v && st.lib && ix.v !== st.lib.v && ix.state !== 'building') {
    // молча обновляем, только если пользователь ещё не начал листать
    if (window.scrollY < 50 && $('viewer').hidden && Date.now() > L.calmUntil) await loadLibrary();
    else if (!st.newVersion) { st.newVersion = ix.v; next = 100; }
  }
  if (prevPc !== 'up' && s.pc === 'up') retryBroken();
  if (!st.lib && ix.state !== 'error' && s.pc === 'up') next = Math.min(next, 1500);
  st.pollTimer = setTimeout(() => poll(), next);
}

function leftTime(sec) {
  if (sec < 60) return 'меньше минуты';
  const m = Math.round(sec / 60);
  if (m < 60) return `${m} мин`;
  const h = Math.floor(m / 60);
  return h >= 24 ? `${Math.floor(h / 24)} д ${h % 24} ч` : `${h} ч ${m % 60} мин`;
}

async function stopInfo() {
  try { await api('/api/admin/info/stop', { method: 'POST' }); } catch (_) {}
  poll(300);
}

async function reindex() {
  try { await api('/api/reindex', { method: 'POST' }); } catch (_) {}
  poll(500);
}

// ================================================================== библиотека

function decode(j) {
  // колоночный формат -> массив строк [id, fidx, name, date, mtime, sizeKB, flags]
  const n = j.n.length, out = new Array(n);
  let d = 0;
  for (let i = 0; i < n; i++) {
    d = i === 0 ? j.d[0] : d - j.d[i];
    out[i] = [j.id.substr(i * 8, 8), j.f[i], j.n[i], d, d + j.m[i], j.s[i], j.x[i]];
  }
  return { v: j.v, folders: j.folders, photos: out, live: j.live || {}, grp: j.grp || {}, cov: new Set(j.cov || []) };
}

async function loadLibrary(pre) {
  if (st.libLoading) return;
  st.libLoading = true;
  try { await loadLibraryInner(pre); } finally { st.libLoading = false; }
}
async function loadLibraryInner(pre) {
  if (!st.lib) banner('Загружаю список файлов…');
  // cache:'no-cache' — браузер хранит копию и спрашивает сервер по ETag (304 = 0 байт)
  const r = pre || await api('/api/library' + HQ, { cache: 'no-cache' });
  if (!r.ok) return;
  const j = await r.json();
  if (!j.v) return;
  const lib = decode(j);
  st.lib = lib; st.newVersion = null;
  const F = lib.folders.length;
  st.folderIdx = new Map(lib.folders.map((p, i) => [p, i]));
  st.children = Array.from({ length: F }, () => []);
  st.totals = new Uint32Array(F);
  st.cover = new Array(F);
  const parent = new Int32Array(F).fill(-1);
  lib.folders.forEach((p, i) => {
    if (i === 0) return;
    const cut = p.lastIndexOf('/');
    parent[i] = cut < 0 ? 0 : (st.folderIdx.get(p.slice(0, cut)) ?? 0);
    st.children[parent[i]].push(i);
  });
  for (const ph of lib.photos) {      // отсортированы по дате ↓ -> первое в поддереве и есть обложка
    for (let f = ph[1]; f >= 0; f = parent[f]) {
      st.totals[f]++;
      if (!st.cover[f] && !(ph[6] & F_VIDEO)) st.cover[f] = ph;
    }
  }
  const coll = new Intl.Collator('ru', { numeric: true, sensitivity: 'base' });
  for (const ch of st.children) ch.sort((a, b) => coll.compare(lib.folders[a], lib.folders[b]));
  st.parent = parent;
  if (!st.folderIdx.has(st.folder)) st.folder = '';
  render();
  if ($('banner-text').textContent.startsWith('Загружаю')) banner(null);
  if (!st.placed) { st.placed = true; restorePlace(loadPlace()); }   // первая загрузка — туда, где был
}

function readRoute() {
  const h = location.hash.startsWith('#/') ? location.hash.slice(2) : '';
  try { st.folder = h ? h.split('/').map(decodeURIComponent).join('/') : ''; } catch (_) { st.folder = ''; }
  st.sort = ['new', 'old', 'name'].includes(store('pc.sort')) ? store('pc.sort') : 'new';
  st.rec = store('pc.rec') !== '0';
  $('sort').value = st.sort; $('rec').checked = st.rec;
}

function go(folder) { location.hash = '#/' + folder.split('/').filter(Boolean).map(encodeURIComponent).join('/'); }

window.addEventListener('hashchange', () => { readRoute(); if (st.lib) { render(); window.scrollTo(0, 0); } });
$('sort').addEventListener('change', (e) => { st.sort = e.target.value; store('pc.sort', st.sort); render(); });
$('rec').addEventListener('change', (e) => { st.rec = e.target.checked; store('pc.rec', st.rec ? '1' : '0'); render(); });

// ================================================================== адреса картинок

const imgUrl = (kind, ph) => `/img/${kind}/${encodeURIComponent(ph[0])}?v=${ph[4]}`;
const origUrl = (ph, dl) => `/img/o/${encodeURIComponent(ph[0])}${dl ? '?dl=1' : ''}`;

function thumbKind() {
  // сколько реальных пикселей занимает плитка -> ближайший размер эскиза
  // плотность экрана больше 2 на глаз не видна в мелких плитках, а файлы и декод — в разы тяжелее
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  const px = L.tileH * dpr;
  if (px <= Z.sizes.s * 1.15) return 's';
  if (px <= Z.sizes.t * 1.15) return 't';
  return 'm';
}
// на весь экран: быстрое превью 720 -> 2048 -> сразу следом оригинал
const previewKind = () => 'p';

// ================================================================== отрисовка: шапка, папки

function render() {
  const lib = st.lib; if (!lib) return;
  const fi = st.folderIdx.get(st.folder) ?? 0;

  const crumbs = [el('a', null, HID ? 'Скрытые фото' : STARRED ? 'Избранное' : 'Все фото')]; crumbs[0].href = '#/';
  if (st.folder) {
    let acc = '';
    for (const part of st.folder.split('/')) {
      acc = acc ? acc + '/' + part : part;
      const a = el('a', null, part); const target = acc; a.href = '#/';
      a.onclick = (e) => { e.preventDefault(); go(target); };
      crumbs.push(el('span', null, '/'), a);
    }
  }
  $('crumbs').replaceChildren(...crumbs);

  const fwrap = $('folders'); fwrap.replaceChildren();
  // в избранном и скрытых — только папки, где что-то есть
  const kids = HID || STARRED ? st.children[fi].filter((c) => st.totals[c] > 0) : st.children[fi];
  for (const c of kids) {
    const path = lib.folders[c];
    const card = el('a', 'folder'); card.href = '#/';
    card.onclick = (e) => { e.preventDefault(); go(path); };
    const cover = el('div', 'cover');
    if (st.cover[c]) { const im = el('img'); im.loading = 'lazy'; im.decoding = 'async'; im.alt = ''; im.onerror = () => im.remove(); im.src = imgUrl('s', st.cover[c]); cover.append(im); }
    const name = el('div', 'fname', path.slice(path.lastIndexOf('/') + 1));
    name.append(el('small', null, count(st.totals[c])));
    card.append(cover, name); fwrap.append(card);
  }

  let list;
  if (st.rec) {
    const inTree = new Uint8Array(lib.folders.length);
    const stack = [fi];
    while (stack.length) { const f = stack.pop(); inTree[f] = 1; for (const c of st.children[f]) stack.push(c); }
    list = fi === 0 ? lib.photos : lib.photos.filter((p) => inTree[p[1]]);
  } else list = lib.photos.filter((p) => p[1] === fi);
  if (st.sort === 'old') list = list.slice().reverse();
  else if (st.sort === 'name') { const coll = new Intl.Collator('ru', { numeric: true }); list = list.slice().sort((a, b) => coll.compare(a[2], b[2])); }
  st.list = groupList(list);

  const videos = list.reduce((n, p) => n + (p[6] & F_VIDEO ? 1 : 0), 0);
  $('summary').textContent = list.length ? count(list.length) + (videos ? `, из них видео: ${videos.toLocaleString('ru')}` : '') + (st.rec && kids.length ? ' — с подпапками' : '') : '';
  $('empty').hidden = list.length > 0 || kids.length > 0;
  $('empty').textContent = HID ? 'Скрытых фото здесь нет' : STARRED ? 'В избранном пока ничего нет — отметь фото звёздочкой ☆' : 'Здесь пусто';

  relayout(false);
}

// ================================================================== группы (стопки)
// В ленте от группы — одна обложка (её выбрали первой) со значком и числом; нажатие раскрывает
// группу на месте обложки (обратно — после перезагрузки). Фото группы, видимые пользователю
// меньше чем по два, показываются как обычно.
const GX = { open: new Set(), pop: new Set(), of: new Map(), byId: new Map(), cover: new Map() };
function groupList(list) {
  const grp = st.lib.grp || {};
  GX.of = new Map(); GX.byId = new Map(); GX.cover = new Map();
  for (const ph of list) { const g = grp[ph[0]]; if (g) { if (!GX.of.has(g)) GX.of.set(g, []); GX.of.get(g).push(ph); } }
  if (!GX.of.size) return list;
  for (const [g, m] of GX.of) {
    if (m.length < 2) { GX.of.delete(g); continue; }
    GX.cover.set(g, m.find((x) => st.lib.cov.has(x[0])) || m[0]);
    for (const x of m) GX.byId.set(x[0], g);
  }
  const out = [];
  for (const ph of list) {
    const g = GX.byId.get(ph[0]);
    if (!g) { out.push(ph); continue; }
    const cover = GX.cover.get(g);
    if (ph !== cover) continue;                       // члены группы встают за обложкой
    out.push(cover);
    if (GX.open.has(g)) for (const x of GX.of.get(g)) if (x !== cover) out.push(x);
  }
  return out;
}
// дата для заголовков месяцев: у раскрытой группы — дата обложки (группа не рвётся месяцами)
function gdate(i) { const ph = st.list[i], g = GX.byId.get(ph[0]); return g ? GX.cover.get(g)[3] : ph[3]; }
const groupCollapsed = (ph) => { const g = GX.byId.get(ph[0]); return !!g && !GX.open.has(g) && GX.cover.get(g) === ph; };
function openGroup(i) {
  const ph = st.list[i], g = GX.byId.get(ph[0]); if (!g) return;
  GX.open.add(g);
  GX.pop = new Set(GX.of.get(g).filter((x) => x !== ph).map((x) => x[0]));
  // фото встают после обложки, всё выше неё не двигается — прокрутку не трогаем
  render();
  setTimeout(() => { GX.pop.clear(); }, 800);
}
// выбранные с учётом свёрнутых групп: выбрал обложку — значит всю группу
function selIds() {
  const out = [];
  for (const ph of st.list) {
    if (!SEL.set.has(ph[0])) continue;
    if (groupCollapsed(ph)) for (const x of GX.of.get(GX.byId.get(ph[0]))) out.push(x[0]); else out.push(ph[0]);
  }
  return [...new Set(out)];
}

function count(n) { return `${n.toLocaleString('ru')} файл${n % 10 === 1 && n % 100 !== 11 ? '' : (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14)) ? 'а' : 'ов'}`; }
const monthKey = (ts) => { const d = new Date(ts * 1000); return d.getFullYear() * 12 + d.getMonth(); };
const monthName = (k) => `${MONTHS[k % 12]} ${Math.floor(k / 12)}`;

// ================================================================== виртуальная сетка
// В DOM только строки около экрана: десятки тысяч фото не тормозят ни телефон, ни комп.

const gridW = () => $('grid').clientWidth || document.documentElement.clientWidth;
const gridTop = () => $('grid').getBoundingClientRect().top + window.scrollY;

function layout() {
  const W = gridW(), cols = Z.cols;
  L.gap = cols >= 7 ? 1 : cols >= 5 ? 2 : 3;
  L.tileH = (W - L.gap * (cols - 1)) / cols;
  // значки на плитках — в масштабе плитки: полный размер от 160 px, мельче — пропорционально (не меньше 55%)
  $('grid').style.setProperty('--bs', Math.max(0.55, Math.min(1, L.tileH / 160)).toFixed(3));
  const rowH = L.tileH + L.gap;
  const rows = []; let y = 0;
  const byMonth = st.sort !== 'name';
  const list = st.list;
  let i = 0;
  while (i < list.length) {
    let end = list.length, month = -1;
    if (byMonth) {
      month = monthKey(gdate(i));
      end = i + 1;
      while (end < list.length && monthKey(gdate(end)) === month) end++;
      rows.push({ h: true, month, n: end - i, start: i, top: y, height: HEAD_H }); y += HEAD_H;
    }
    for (let s = i; s < end; s += cols) { rows.push({ h: false, start: s, end: Math.min(end, s + cols), month, top: y, height: rowH }); y += rowH; }
    i = end;
  }
  L.rows = rows; L.height = y + 8;
  $('grid').style.height = L.height + 'px';
  document.documentElement.style.setProperty('--cols', cols);
}

function clearGrid() {
  for (const [, node] of L.rendered) cancelImgs(node);
  L.rendered.clear(); $('grid').replaceChildren();
}

function relayout(keepAnchor) {
  // keepAnchor: сохраняем на экране ту же фотографию (смена масштаба/экономии/поворот)
  const anchor = keepAnchor ? topVisibleIndex() : null;
  clearGrid(); layout();
  if (anchor) scrollToIndex(anchor.i, anchor.offset);
  draw(true); updateScrub();
}

function firstRowAt(y) {           // бинпоиск по top
  let lo = 0, hi = L.rows.length - 1, ans = L.rows.length;
  while (lo <= hi) { const mid = (lo + hi) >> 1; const r = L.rows[mid]; if (r.top + r.height >= y) { ans = mid; hi = mid - 1; } else lo = mid + 1; }
  return ans;
}

function rowOfIndex(idx) {
  // последняя строка, начинающаяся не позже idx (у заголовка start = первый файл месяца)
  let lo = 0, hi = L.rows.length - 1, ans = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (L.rows[mid].start <= idx) { ans = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return L.rows[ans] && L.rows[ans].h ? Math.min(ans + 1, L.rows.length - 1) : ans;
}

function topVisibleIndex() {
  const y = window.scrollY - gridTop() + $('banner').offsetHeight + 60;
  const ri = firstRowAt(Math.max(0, y));
  for (let k = ri; k < L.rows.length; k++) if (!L.rows[k].h) { return { i: L.rows[k].start, offset: L.rows[k].top - Math.max(0, y) }; }
  return null;
}

function scrollToIndex(i, offset = 0) {
  const r = L.rows[rowOfIndex(i)]; if (!r) return;
  window.scrollTo(0, gridTop() + r.top - offset - $('banner').offsetHeight - 60);
}

// Скрыли, сгруппировали, пометили — лента пересобирается, но экран остаётся на месте:
// запоминаем первое фото у верха экрана, которое никуда не денется (skip — уходящие),
// и после пересборки ставим его строку на ту же высоту.
function keepPlace(skip) {
  if (window.scrollY < 10) return null;                   // в самом верху — и так на месте
  const vis = topVisibleIndex(); if (!vis) return null;
  for (let i = Math.max(0, vis.i - Z.cols); i < st.list.length; i++) {
    const ph = st.list[i];
    if (skip && skip.has(ph[0])) continue;
    const r = L.rows[rowOfIndex(i)]; if (!r) return null;
    const top = gridTop() + r.top - window.scrollY;
    if (top + r.height < $('banner').offsetHeight + 60) continue;   // строка уже ушла под шапку
    return { id: ph[0], top };
  }
  return null;
}
function restorePlace(a) {
  if (!a || !st.list) return;
  let i = st.list.findIndex((p) => p[0] === a.id);
  if (i < 0) { const g = GX.byId.get(a.id); if (g) i = st.list.indexOf(GX.cover.get(g)); }   // ушло в свёрнутую группу
  if (i < 0) return;
  const r = L.rows[rowOfIndex(i)]; if (!r) return;
  window.scrollTo(0, gridTop() + r.top - a.top);
  draw(true); updateScrub();
}

function draw(force) {
  if ($('main').hidden || !st.lib) return;
  if (force) gridPrefetchSoon();
  const y = window.scrollY, gt = gridTop(), vh = window.innerHeight;
  L.lastY = y;
  // картинки грузим прямо во время прокрутки; пауза только пока тащат ползунок по датам
  // (там за кадр пролетают тысячи строк, и запросы были бы впустую)
  L.fast = L.scrubbing;
  clearTimeout(L.idleT);
  if (L.fast) L.idleT = setTimeout(() => { L.fast = false; loadVisible(true); }, 120);

  const y0 = y - gt - vh * BUFFER, y1 = y - gt + vh * (1 + BUFFER);
  const a = firstRowAt(Math.max(0, y0));
  const keep = new Set();
  for (let k = a; k < L.rows.length && L.rows[k].top <= y1; k++) {
    keep.add(k);
    if (!L.rendered.has(k)) { const node = buildRow(L.rows[k]); L.rendered.set(k, node); $('grid').append(node); }
  }
  for (const [k, node] of L.rendered) if (!keep.has(k)) { cancelImgs(node); node.remove(); L.rendered.delete(k); }
  if (!L.fast) {
    loadVisible(false);
    clearTimeout(L.bufT); L.bufT = setTimeout(() => loadVisible(true), 200);
  }
  // недогруженные плитки, уехавшие далеко за экран, отменяем сразу — освобождаем очередь
  for (const [, node] of L.rendered) {
    const r = node.getBoundingClientRect();
    if (r.bottom < -vh * 0.5 || r.top > vh * 1.5) cancelImgs(node);
  }
  pill(a);
}

function buildRow(r) {
  if (r.h) {
    const h = el('div', 'mhead', monthName(r.month));
    h.append(el('span', null, r.n.toLocaleString('ru')));
    // в режиме выбора — кружок: выбрать (или снять) весь месяц сразу
    h.dataset.start = r.start; h.dataset.n = r.n;
    const c = el('button', 'mcheck'); c.type = 'button';
    c.setAttribute('aria-label', 'Выбрать весь месяц'); c.title = 'Выбрать весь месяц';
    c.addEventListener('click', (e) => { e.stopPropagation(); selMonth(r.start, r.n); });
    h.prepend(c);
    if (SEL.on && monthAllSel(r.start, r.n)) h.classList.add('sel');
    h.style.transform = `translateY(${r.top}px)`;
    return h;
  }
  const row = el('div', 'trow');
  row.style.transform = `translateY(${r.top}px)`; row.style.height = L.tileH + 'px'; row.style.gap = L.gap + 'px';
  const kind = thumbKind();
  for (let i = r.start; i < r.end; i++) {
    const ph = st.list[i];
    const b = el('button', 'tile'); b.type = 'button'; b.dataset.i = i; b.title = ph[2];
    if (SEL.set.has(ph[0])) b.classList.add('sel');
    const img = el('img'); img.alt = ''; img.decoding = 'async'; img.draggable = false; img.dataset.src = imgUrl(kind, ph);
    img.onload = () => { img.classList.add('ok'); img.dataset.loaded = '1'; b.classList.remove('broken'); };
    img.onerror = () => { if (img.getAttribute('src')) thumbFailed(img); };
    b.append(img);
    if (STAR.ids.has(ph[0])) b.append(el('span', 'sbadge', '★'));
    if (HID && MARK.ids.has(ph[0])) { b.classList.add('marked'); b.append(markBadge()); }
    const g = GX.byId.get(ph[0]);
    if (g) {
      // значок с числом — только на первом фото группы (и у свёрнутой, и у раскрытой); у остальных — без значка
      if (GX.cover.get(g) === ph) {
        b.classList.add('grouped');
        const gb = el('span', 'gbadge'); gb.append(GROUP_SVG.cloneNode(true), String(GX.of.get(g).length));
        b.append(gb);
        if (groupCollapsed(ph)) b.title = `${ph[2]} — группа из ${GX.of.get(g).length}, нажми, чтобы раскрыть`;
      }
      if (GX.pop.has(ph[0])) { b.classList.add('pop'); b.style.animationDelay = Math.min(300, (i - r.start) * 30) + 'ms'; }
    }
    if (ph[6] & F_VIDEO) b.append(el('span', 'vbadge', '▶'));
    else if (ph[6] & F_LIVE) b.append(el('span', 'lbadge'));
    row.append(b);
  }
  return row;
}

function screenPending() {
  // на экране есть эскизы, которые запрошены и ещё не пришли
  const vh = window.innerHeight;
  for (const [, node] of L.rendered) {
    const r = node.getBoundingClientRect();
    if (r.bottom <= 0 || r.top >= vh) continue;
    for (const img of node.querySelectorAll('img')) if (img.getAttribute('src') && !img.dataset.loaded) return true;
  }
  return false;
}

function loadVisible(withBuffer, wait = 0) {
  if (L.fast) return;
  // во время прокрутки запрашиваем только то, что на экране; запас сверху/снизу — когда
  // прокрутка замрёт на 200 мс И эскизы на экране догрузятся. Сервер отдаёт сетку «сначала
  // самые свежие запросы», и запас, запрошенный раньше времени, обгонял бы видимые плитки.
  if (withBuffer && wait < 40 && screenPending()) {
    loadVisible(false);
    clearTimeout(L.bufT); L.bufT = setTimeout(() => loadVisible(true, wait + 1), 150);
    return;
  }
  const vh = window.innerHeight, margin = withBuffer ? vh * BUFFER : vh * 0.25;
  for (const [, node] of L.rendered) {
    const r = node.getBoundingClientRect();
    if (r.bottom < -margin || r.top > vh + margin) continue;
    const onScreen = r.bottom > 0 && r.top < vh;
    for (const img of node.querySelectorAll('img')) {
      if (img.getAttribute('src')) continue;
      img.fetchPriority = onScreen ? 'high' : 'low';
      img.src = img.dataset.src;
    }
  }
}

function cancelImgs(node) {
  // недогруженные картинки отменяем, чтобы не тратить канал на то, что уже уехало с экрана
  for (const img of node.querySelectorAll('img')) if (!img.dataset.loaded && img.getAttribute('src')) img.removeAttribute('src');
}

// Эскиз не загрузился (компьютер был занят, сеть моргнула) — повторяем аккуратно:
// через 1 / 3 / 8 с, не больше двух повторов одновременно и только для плиток,
// которые всё ещё на экране. После трёх неудач показываем ⚠.
const RETRY_DELAYS = [1000, 3000, 8000];
const RQ = { queue: [], active: 0 };
let checkT = 0;
function checkPcSoon() {
  // эскиз не пришёл — возможно, компьютер выключили: проверяем сразу, а не через 30 с
  if (checkT || st.pc === 'down' || st.pc === 'waking') return;
  checkT = setTimeout(() => { checkT = 0; poll(); }, 300);
}
function thumbFailed(img) {
  const n = +(img.dataset.tries || 0);
  img.removeAttribute('src');
  if (st.pc === 'down' || st.pc === 'waking') {
    // компьютер выключен: не тратим попытки, перезапросим всё разом, когда он включится
    img.dataset.err = '1'; return;
  }
  checkPcSoon();
  if (n >= RETRY_DELAYS.length) { img.parentElement.classList.add('broken'); img.dataset.err = '1'; return; }
  img.dataset.tries = n + 1;
  setTimeout(() => { RQ.queue.push(img); pumpRetries(); }, RETRY_DELAYS[n]);
}
function pumpRetries() {
  while (RQ.active < 2 && RQ.queue.length) {
    const img = RQ.queue.shift();
    if (!img.isConnected || img.dataset.loaded) continue;       // плитка уже уехала из ленты
    const r = img.getBoundingClientRect();
    if (r.bottom < -innerHeight || r.top > innerHeight * 2) {    // далеко от экрана — загрузится, когда вернёмся
      continue;
    }
    RQ.active++;
    const done = () => { RQ.active--; img.removeEventListener('load', done); img.removeEventListener('error', done); pumpRetries(); };
    img.addEventListener('load', done); img.addEventListener('error', done);
    img.src = img.dataset.src;
  }
}

function retryBroken() {
  for (const [, node] of L.rendered) for (const img of node.querySelectorAll('img[data-err]')) {
    delete img.dataset.err; delete img.dataset.tries; img.parentElement.classList.remove('broken'); img.src = img.dataset.src;
  }
}

let rafPending = false;
// Обновил страницу — лента на том же месте: фото у верха экрана запоминаем во вкладке
// (sessionStorage — у каждой вкладки своё) и после загрузки списка ставим его туда же.
// Обычное восстановление прокрутки браузера тут не работает: лента строится уже после загрузки.
try { history.scrollRestoration = 'manual'; } catch (_) {}
const placeKey = () => location.pathname + location.hash + '|' + st.sort + '|' + (st.rec ? 1 : 0);
let placeT = 0;
function savePlace() {
  clearTimeout(placeT); placeT = 0;
  if (!st.list || $('main').hidden) return;
  try {
    const a = keepPlace(null);
    if (a) sessionStorage.setItem('pc.place', JSON.stringify({ k: placeKey(), ...a }));
    else sessionStorage.removeItem('pc.place');
  } catch (_) {}
}
function loadPlace() {
  try { const a = JSON.parse(sessionStorage.getItem('pc.place') || 'null'); return a && a.k === placeKey() ? a : null; }
  catch (_) { return null; }
}
window.addEventListener('pagehide', savePlace);
document.addEventListener('visibilitychange', () => { if (document.hidden) savePlace(); });

window.addEventListener('scroll', () => {
  if (!placeT) placeT = setTimeout(savePlace, 400);
  gridPrefetchSoon();
  if (rafPending) return; rafPending = true;
  requestAnimationFrame(() => { rafPending = false; draw(false); updateScrub(); });
}, { passive: true });

// Прокрутка остановилась на 0,2 с — заранее качаем быстрые превью видимых плиток (~10 КБ),
// чтобы тап сразу показывал «Превью». Только после того как догрузились эскизы на экране,
// по два запроса, с низким приоритетом; прокрутка или открытие фото всё обрывает.
const GP = { t: 0, ctl: null, tries: 0 };
const prefetched = new Set();         // быстрые превью, которые уже лежат в кэше браузера
function gridPrefetchSoon() {
  clearTimeout(GP.t);
  if (GP.ctl) { GP.ctl.abort(); GP.ctl = null; }
  GP.tries = 0;
  GP.t = setTimeout(gridPrefetch, 200);
}
async function gridPrefetch() {
  if ($('main').hidden || !$('viewer').hidden || !st.lib || L.fast) return;
  const vh = window.innerHeight, want = [];
  let pending = false;
  for (const [, node] of L.rendered) {
    for (const tile of node.querySelectorAll('.tile')) {
      const r = tile.getBoundingClientRect();
      if (r.bottom <= 0 || r.top >= vh) continue;
      const img = tile.querySelector('img');
      if (img && !img.dataset.loaded && !img.dataset.err) pending = true;
      const ph = st.list[+tile.dataset.i];
      if (!ph || (ph[6] & F_VIDEO)) continue;
      const u = imgUrl('q', ph) + '&n=p';
      if (!prefetched.has(u)) want.push(u);
    }
  }
  if (pending && GP.tries++ < 25) { GP.t = setTimeout(gridPrefetch, 200); return; }   // сначала эскизы
  if (!want.length) return;
  const ctl = GP.ctl = new AbortController();
  const worker = async () => {
    while (want.length && !ctl.signal.aborted) {
      const u = want.shift();
      try {
        const r = await fetch(u, { signal: ctl.signal, priority: 'low', headers: { 'X-PF': 'grid' }, credentials: 'same-origin' });
        await r.arrayBuffer();
        if (r.ok) prefetched.add(u);
      } catch (_) { return; }
    }
  };
  await Promise.all([worker(), worker()]);
  if (GP.ctl === ctl) GP.ctl = null;
}

$('grid').addEventListener('click', (e) => {
  const t = e.target.closest('.tile'); if (!t) return;
  if (Date.now() < SEL.ignoreClick) return;                 // клик после долгого нажатия
  if (SEL.on) { selClick(+t.dataset.i, e.shiftKey); return; }
  const ph = st.list[+t.dataset.i];
  if (ph && groupCollapsed(ph)) { openGroup(+t.dataset.i); return; }   // свёрнутая группа — раскрыть
  openViewer(+t.dataset.i);
});

// ================================================================== выбор фото (скрыть / вернуть)
// Телефон: долгое нажатие на фото — режим выбора и само фото; не отпуская палец, ведём —
// выбираются фото, через которые прошёл палец (по диагонали соседние не задеваем: считается
// только середина плитки); у края экрана лента прокручивается сама. Касание — выбрать/снять.
// Компьютер: меню ⋯ → «Выбрать фото», клик — выбрать/снять, Shift+клик — все между этим и
// предыдущим по порядку строк. Сверху — «✕ Выбрано N» и действие.
// anchor — последнее фото, по которому кликнули, anchorOn — выбрали его этим кликом или сняли
const SEL = { on: false, set: new Set(), anchor: -1, anchorOn: true, drag: null, press: null, ignoreClick: 0, raf: 0 };
const LONG_PRESS = 450;
const SEL_EDGE = 0.15;      // протягивание: у краёв плитки (доля стороны) фото не выбирается

function selUpdate() {
  const row = document.querySelector('.top > .row');
  // панель выбора — той же высоты, что строка, которую она заменяет: лента не сдвигается под пальцем
  if (SEL.on && !row.hidden) $('selbar').style.minHeight = row.offsetHeight + 'px';
  $('selbar').hidden = !SEL.on;
  row.hidden = SEL.on;
  $('grid').classList.toggle('selmode', SEL.on);
  $('sel-n').textContent = `Выбрано: ${SEL.set.size.toLocaleString('ru')}`;
  for (const id of ['sel-hide', 'sel-show', 'sel-star', 'sel-unstar', 'sel-del']) $(id).disabled = !SEL.set.size;
  $('sel-group').disabled = selIds().length < 2;
  // «Разгруппировать» — если среди выбранных есть фото из группы
  $('sel-ungroup').hidden = ![...SEL.set].some((id) => GX.byId.has(id));
  // «Не удалять» — когда среди выбранных есть помеченные на удаление
  $('sel-undel').hidden = !HID || !st.me || !st.me.can_delete || ![...SEL.set].some((id) => MARK.ids.has(id));
  for (const h of $('grid').querySelectorAll('.mhead')) h.classList.toggle('sel', SEL.on && monthAllSel(+h.dataset.start, +h.dataset.n));
}
function selStart() { if (!st.me) return false; SEL.on = true; hideMenu(); selUpdate(); return true; }
function selEnd() {
  SEL.on = false; SEL.set.clear(); SEL.anchor = -1; SEL.drag = null;
  for (const t of $('grid').querySelectorAll('.tile.sel')) t.classList.remove('sel');
  selUpdate();
}
function selMark(i, on) {
  const ph = st.list[i]; if (!ph) return;
  if (on) SEL.set.add(ph[0]); else SEL.set.delete(ph[0]);
  const t = $('grid').querySelector(`.tile[data-i="${i}"]`);
  if (t) t.classList.toggle('sel', on);
}
function selClick(i, shift) {
  const ph = st.list[i]; if (!ph) return;
  if (shift && SEL.anchor >= 0 && SEL.anchor !== i) {
    // все между предыдущим и этим — по порядку в ленте, то есть по строкам; как с предыдущим:
    // его выбрали — выбираем, сняли — снимаем
    const [a, b] = SEL.anchor < i ? [SEL.anchor, i] : [i, SEL.anchor];
    for (let k = a; k <= b; k++) selMark(k, SEL.anchorOn);
  } else { SEL.anchorOn = !SEL.set.has(ph[0]); selMark(i, SEL.anchorOn); }
  SEL.anchor = i;
  selUpdate();
}
function monthAllSel(start, n) {
  for (let k = start; k < start + n; k++) if (!st.list[k] || !SEL.set.has(st.list[k][0])) return false;
  return n > 0;
}
function selMonth(start, n) {
  const on = !monthAllSel(start, n);                        // всё уже выбрано — снять, иначе — выбрать всё
  for (let k = start; k < start + n; k++) selMark(k, on);
  SEL.anchor = start + n - 1; SEL.anchorOn = on;
  selUpdate();
}
$('menu-select').addEventListener('click', () => selStart());
$('sel-x').addEventListener('click', () => selEnd());
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && SEL.on && gridActive()) selEnd(); });

async function selApply(hide) {
  const ids = selIds(); if (!ids.length) return;
  const n = ids.length.toLocaleString('ru');
  if (hide && !confirm(`Скрыть ${n} фото? Они пропадут из галереи только у тебя (у других останутся), файлы на компьютере не трогаются. Вернуть можно в меню ⋯ → «Скрытые фото».`)) return;
  const btn = hide ? $('sel-hide') : $('sel-show'); btn.disabled = true;
  try {
    const r = await api(hide ? '/api/hide' : '/api/unhide', { method: 'POST', body: { ids } });
    if (!r.ok) { banner(`Не получилось (${r.status})`, null, null, true); btn.disabled = false; return; }
    const place = keepPlace(new Set(ids));
    selEnd();
    await loadLibrary();
    if (HID) await loadMarks();                               // вернули в галерею — пометка снята
    banner(hide ? `Скрыто: ${n}` : `Возвращено в галерею: ${n}`);
    restorePlace(place);
    setTimeout(() => { if (/^(Скрыто|Возвращено)/.test($('banner-text').textContent)) banner(null); }, 3000);
  } catch (_) { btn.disabled = false; }
}
$('sel-hide').addEventListener('click', () => selApply(true));
$('sel-show').addEventListener('click', () => selApply(false));
$('sel-star').addEventListener('click', () => selStar(true));
$('sel-del').addEventListener('click', () => selMarkDelete(true));
$('sel-group').addEventListener('click', () => selGroup(true));
$('sel-ungroup').addEventListener('click', () => selGroup(false));
const GROUP_SVG = $('sel-group').querySelector('svg');
async function selGroup(make) {
  const ids = selIds();                                     // по порядку в ленте: первое — обложка
  if (make && ids.length < 2) return;
  const btn = make ? $('sel-group') : $('sel-ungroup'); btn.disabled = true;
  try {
    const r = await api(make ? '/api/group' : '/api/ungroup', { method: 'POST', body: { ids } });
    if (!r.ok) { const j = await r.json().catch(() => ({})); banner(j.error || `Не получилось (${r.status})`, null, null, true); btn.disabled = false; return; }
    const place = keepPlace(make ? new Set(ids.slice(1)) : null);   // обложка (первое) остаётся
    selEnd(); await loadLibrary();
    banner(make ? `Сгруппировано: ${ids.length}` : 'Группа разобрана');
    restorePlace(place);
    setTimeout(() => { if (/^(Сгруппировано|Группа разобрана)/.test($('banner-text').textContent)) banner(null); }, 3000);
  } catch (_) { btn.disabled = false; }
}
$('sel-undel').addEventListener('click', () => selMarkDelete(false));

// ================================================================== «удалить окончательно» (на /hidden)
// Пока только пометка в базе: удалять с компьютера будет отдельный клиент на ПК, он и решает.
// Помеченные — с красной корзиной и бледнее; «Не удалять» или «вернуть в галерею» снимает пометку.
const MARK = { ids: new Set() };
const TRASH_SVG = $('sel-del').querySelector('svg');
function markBadge() { const s = el('span', 'dbadge'); s.append(TRASH_SVG.cloneNode(true)); s.title = 'Помечено на удаление'; return s; }
async function loadMarks() {
  try { const j = await (await api('/api/marks')).json(); MARK.ids = new Set(j.ids || []); paintMarks(); } catch (_) {}
}
function paintMarks() {
  for (const t of $('grid').querySelectorAll('.tile')) {
    const ph = st.list[+t.dataset.i]; if (!ph) continue;
    const on = MARK.ids.has(ph[0]), b = t.querySelector('.dbadge');
    t.classList.toggle('marked', on);
    if (on && !b) t.append(markBadge()); else if (!on && b) b.remove();
  }
}
async function selMarkDelete(on) {
  const ids = selIds(); if (!ids.length) return;
  const n = ids.length.toLocaleString('ru');
  if (on && !confirm(`Пометить ${n} фото на окончательное удаление?\n\nОни пропадут и из скрытых. Удалять файлы с компьютера будет отдельная программа на ПК.`)) return;
  const btn = on ? $('sel-del') : $('sel-undel'); btn.disabled = true;
  try {
    const r = await api('/api/marks', { method: 'POST', body: { ids, on } });
    if (!r.ok) { const j = await r.json().catch(() => ({})); banner(j.error || `Не получилось (${r.status})`, null, null, true); btn.disabled = false; return; }
    const place = keepPlace(on ? new Set(ids) : null);
    selEnd(); await loadMarks(); await loadLibrary();       // помеченные из скрытых пропадают
    banner(on ? `Помечено на удаление: ${n}` : `Пометка снята: ${n}`);
    restorePlace(place);
    setTimeout(() => { if (/^(Помечено|Пометка)/.test($('banner-text').textContent)) banner(null); }, 3000);
  } catch (_) { btn.disabled = false; }
}
$('sel-unstar').addEventListener('click', () => selStar(false));

// ================================================================== избранное
// У каждого пользователя своё: сервер хранит пути его избранных файлов. Здесь — id для
// звёздочек на плитках и в просмотре; /starred — та же галерея только с избранным.
const STAR = { ids: new Set(), dirty: false };
async function loadStars() {
  try { const j = await (await api('/api/starred')).json(); STAR.ids = new Set(j.ids || []); paintStars(); } catch (_) {}
}
function paintStars() {
  for (const t of $('grid').querySelectorAll('.tile')) {
    const ph = st.list[+t.dataset.i]; if (!ph) continue;
    const on = STAR.ids.has(ph[0]), b = t.querySelector('.sbadge');
    if (on && !b) t.append(el('span', 'sbadge', '★')); else if (!on && b) b.remove();
  }
  if (!$('viewer').hidden) starBtn();
}
function starBtn() {
  const ph = st.list[V.i], on = !!ph && STAR.ids.has(ph[0]);
  $('v-star').classList.toggle('on', on);
  $('v-star').title = $('v-star').ariaLabel = on ? 'Убрать из избранного' : 'В избранное';
}
async function setStar(ids, on) {
  const r = await api('/api/star', { method: 'POST', body: { ids, on } });
  if (!r.ok) { banner(`Не получилось (${r.status})`, null, null, true); return false; }
  for (const id of ids) { if (on) STAR.ids.add(id); else STAR.ids.delete(id); }
  paintStars();
  return true;
}
async function selStar(on) {
  const ids = selIds(); if (!ids.length) return;
  const btn = on ? $('sel-star') : $('sel-unstar'); btn.disabled = true;
  try {
    if (!(await setStar(ids, on))) { btn.disabled = false; return; }
    const n = ids.length.toLocaleString('ru');
    const place = STARRED && !on ? keepPlace(new Set(ids)) : null;
    selEnd();
    if (STARRED) await loadLibrary();                       // убранные из избранного уходят со страницы
    banner(on ? `В избранном: +${n}` : `Убрано из избранного: ${n}`);
    restorePlace(place);
    setTimeout(() => { if (/избранн/.test($('banner-text').textContent)) banner(null); }, 3000);
  } catch (_) { btn.disabled = false; }
}
$('v-star').addEventListener('click', async () => {
  const ph = st.list[V.i]; if (!ph) return;
  const on = !STAR.ids.has(ph[0]);
  if (await setStar([ph[0]], on).catch(() => false)) STAR.dirty = STAR.dirty || STARRED;
});

// --- палец: долгое нажатие и протягивание
function tileAt(cx, cy) {
  // плитка под точкой, только если точка в её середине (без 15 % у краёв): идя по диагонали
  // через угол, соседние плитки не цепляем
  const t = document.elementFromPoint(cx, cy); const tile = t && t.closest && t.closest('.tile');
  if (!tile || !$('grid').contains(tile)) return -1;
  const r = tile.getBoundingClientRect(), m = Math.min(r.width, r.height) * SEL_EDGE;
  return cx > r.left + m && cx < r.right - m && cy > r.top + m && cy < r.bottom - m ? +tile.dataset.i : -1;
}
function dragTo(cx, cy) {
  // путь пальца — в координатах страницы (с учётом прокрутки), шагами по 1/6 плитки
  const d = SEL.drag, px = cx, py = cy + window.scrollY;
  const dx = px - d.px, dy = py - d.py, len = Math.hypot(dx, dy);
  const steps = Math.max(1, Math.ceil(len / Math.max(4, L.tileH / 6)));
  for (let k = 1; k <= steps; k++) {
    const i = tileAt(d.px + dx * k / steps, d.py + dy * k / steps - window.scrollY);
    if (i >= 0 && i !== d.last) { selMark(i, d.add); d.last = i; }
  }
  d.px = px; d.py = py; d.cx = cx; d.cy = cy;
  selUpdate();
}
function autoScroll() {
  SEL.raf = 0;
  const d = SEL.drag; if (!d) return;
  const top = $('banner').getBoundingClientRect().bottom || 60, zone = 70;
  let v = 0;
  if (d.cy < top + zone) v = -Math.ceil((top + zone - d.cy) / 4);
  else if (d.cy > innerHeight - zone) v = Math.ceil((d.cy - innerHeight + zone) / 4);
  if (!v) return;
  window.scrollBy(0, clamp(v, -24, 24));
  dragTo(d.cx, d.cy);
  SEL.raf = requestAnimationFrame(autoScroll);
}
$('grid').addEventListener('touchstart', (e) => {
  if (e.touches.length !== 1 || !st.me) {
    clearTimeout(SEL.press && SEL.press.t); SEL.press = null;
    if (SEL.drag) { SEL.drag = null; cancelAnimationFrame(SEL.raf); SEL.raf = 0; }   // второй палец — щипок
    return;
  }
  const t0 = e.touches[0], tile = e.target.closest('.tile'); if (!tile) return;
  const i = +tile.dataset.i, x = t0.clientX, y = t0.clientY;
  clearTimeout(SEL.press && SEL.press.t);
  SEL.press = { x, y, t: setTimeout(() => {
    SEL.press = null;
    if (!gridActive() || Z.pinch) return;
    if (!SEL.on) selStart();
    const ph = st.list[i]; if (!ph) return;
    const add = !SEL.set.has(ph[0]);
    selMark(i, add); SEL.anchor = i; SEL.anchorOn = add;
    SEL.drag = { add, last: i, px: x, py: y + window.scrollY, cx: x, cy: y };
    if (navigator.vibrate) navigator.vibrate(20);
    selUpdate();
  }, LONG_PRESS) };
}, { passive: true });
$('grid').addEventListener('touchmove', (e) => {
  const t0 = e.touches[0];
  if (SEL.press && (e.touches.length > 1 || Math.hypot(t0.clientX - SEL.press.x, t0.clientY - SEL.press.y) > 10)) {
    clearTimeout(SEL.press.t); SEL.press = null;           // начали листать — это не долгое нажатие
  }
  if (!SEL.drag || e.touches.length !== 1) return;
  e.preventDefault();                                     // пока выбираем, лента сама не листается
  dragTo(t0.clientX, t0.clientY);
  if (!SEL.raf) SEL.raf = requestAnimationFrame(autoScroll);
}, { passive: false });
function touchDone(e) {
  if (SEL.press) { clearTimeout(SEL.press.t); SEL.press = null; }
  if (SEL.drag) {
    SEL.drag = null; cancelAnimationFrame(SEL.raf); SEL.raf = 0;
    // палец отпустили — это не касание (клик браузер шлёт сразу после touchend, если вообще шлёт)
    SEL.ignoreClick = Date.now() + 250;
    if (e.cancelable) e.preventDefault();
  }
}
$('grid').addEventListener('touchend', touchDone, { passive: false });
$('grid').addEventListener('touchcancel', touchDone, { passive: false });
// мышь: зажал левую кнопку на фото — то же, что долгое нажатие пальцем (выбор и протягивание)
$('grid').addEventListener('pointerdown', (e) => {
  if (e.pointerType !== 'mouse' || e.button !== 0 || !st.me) return;
  const tile = e.target.closest('.tile'); if (!tile) return;
  const i = +tile.dataset.i, x = e.clientX, y = e.clientY;
  clearTimeout(SEL.press && SEL.press.t);
  SEL.press = { x, y, mouse: true, t: setTimeout(() => {
    SEL.press = null;
    if (!gridActive()) return;
    if (!SEL.on) selStart();
    const ph = st.list[i]; if (!ph) return;
    const add = !SEL.set.has(ph[0]);
    selMark(i, add); SEL.anchor = i; SEL.anchorOn = add;
    SEL.drag = { add, last: i, px: x, py: y + window.scrollY, cx: x, cy: y, mouse: true };
    selUpdate();
  }, LONG_PRESS) };
});
document.addEventListener('pointermove', (e) => {
  if (e.pointerType !== 'mouse') return;
  if (SEL.press && SEL.press.mouse && Math.hypot(e.clientX - SEL.press.x, e.clientY - SEL.press.y) > 6) {
    clearTimeout(SEL.press.t); SEL.press = null;
  }
  if (!SEL.drag || !SEL.drag.mouse) return;
  e.preventDefault();
  dragTo(e.clientX, e.clientY);
  if (!SEL.raf) SEL.raf = requestAnimationFrame(autoScroll);
});
document.addEventListener('pointerup', (e) => {
  if (e.pointerType !== 'mouse') return;
  if (SEL.press && SEL.press.mouse) { clearTimeout(SEL.press.t); SEL.press = null; }
  if (SEL.drag && SEL.drag.mouse) {
    SEL.drag = null; cancelAnimationFrame(SEL.raf); SEL.raf = 0;
    SEL.ignoreClick = Date.now() + 250;                     // отпустили кнопку — это не клик
  }
});
document.addEventListener('selectstart', (e) => { if (SEL.drag) e.preventDefault(); });   // не выделять текст, пока ведём
$('grid').addEventListener('contextmenu', (e) => { if (e.target.closest('.tile') && (SEL.on || SEL.press)) e.preventDefault(); });

// плашка с текущим месяцем при прокрутке
let pillT = 0;
function pill(rowIdx) {
  if (st.sort === 'name' || !L.rows.length) { $('pill').hidden = true; return; }
  const r = L.rows[Math.min(rowIdx + 1, L.rows.length - 1)];
  if (!r || window.scrollY < gridTop() - 20) { $('pill').hidden = true; return; }
  $('pill').textContent = monthName(r.month); $('pill').hidden = false;
  clearTimeout(pillT); pillT = setTimeout(() => { $('pill').hidden = true; }, 1200);
}

// ================================================================== ползунок по датам

const scrubH = 44;
function scrubRange() {
  const top = $('banner').getBoundingClientRect().bottom || 60, bottom = window.innerHeight - 8;
  return { top, span: Math.max(1, bottom - top - scrubH) };
}
function maxScroll() { return Math.max(1, document.documentElement.scrollHeight - window.innerHeight); }
function updateScrub() {
  const long = L.height > window.innerHeight * 4 && !$('main').hidden;
  $('scrub').hidden = !long; if (!long) return;
  const { top, span } = scrubRange();
  $('scrub-handle').style.transform = `translateY(${top + span * (window.scrollY / maxScroll())}px)`;
}
(() => {
  const h = $('scrub-handle'); let drag = false;
  h.addEventListener('pointerdown', (e) => { drag = true; L.scrubbing = true; h.setPointerCapture(e.pointerId); h.classList.add('drag'); e.preventDefault(); });
  h.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const { top, span } = scrubRange();
    const p = clamp((e.clientY - top - scrubH / 2) / span, 0, 1);
    window.scrollTo(0, p * maxScroll());
    const ri = firstRowAt(Math.max(0, window.scrollY - gridTop()));
    const r = L.rows[ri];
    $('scrub-label').textContent = r && st.sort !== 'name' ? `${MONTHS_SHORT[r.month % 12]} ${Math.floor(r.month / 12)}` : '';
  });
  const end = () => { drag = false; L.scrubbing = false; h.classList.remove('drag'); $('scrub-label').textContent = ''; L.fast = false; loadVisible(true); };
  h.addEventListener('pointerup', end); h.addEventListener('pointercancel', end);
})();

// ================================================================== масштаб сетки
// Щипок (телефон), жест трекпада / Ctrl+колесо (комп), кнопки −/+ или клавиши -/+.

const maxCols = () => Math.max(2, Math.floor(gridW() / 40));
function initZoom() {
  const tile = +store('pc.tile') || (window.innerWidth < 700 ? 125 : 180);
  Z.cols = clamp(Math.round(gridW() / tile), 1, maxCols());
}

function setCols(n, cx, cy) {
  n = clamp(n, 1, maxCols());
  if (n === Z.cols || !st.lib) return;
  // фото под пальцами/курсором остаётся на месте
  const hit = document.elementFromPoint(cx, cy);
  const tile = hit && hit.closest && hit.closest('.tile');
  const idx = tile ? +tile.dataset.i : null;
  const before = tile ? tile.getBoundingClientRect().top : 0;
  Z.cols = n;
  store('pc.tile', String(Math.round(gridW() / n)));
  clearGrid(); layout();
  if (idx != null) { const r = L.rows[rowOfIndex(idx)]; window.scrollTo(0, gridTop() + r.top - before); }
  draw(true); updateScrub();
}

const gridActive = () => !$('main').hidden && $('viewer').hidden;
const dist = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);

document.addEventListener('touchstart', (e) => {
  if (e.touches.length === 2 && gridActive()) Z.pinch = { d0: dist(e.touches) || 1, c0: Z.cols };
}, { passive: true });
document.addEventListener('touchmove', (e) => {
  if (!Z.pinch || e.touches.length !== 2) return;
  if (!gridActive()) { Z.pinch = null; return; }     // открыли просмотр — щипок уже не про сетку
  e.preventDefault();
  const s = dist(e.touches) / Z.pinch.d0;
  setCols(Math.round(Z.pinch.c0 / s), (e.touches[0].clientX + e.touches[1].clientX) / 2, (e.touches[0].clientY + e.touches[1].clientY) / 2);
}, { passive: false });
document.addEventListener('touchend', (e) => { if (e.touches.length < 2) Z.pinch = null; });
document.addEventListener('touchcancel', () => { Z.pinch = null; });
for (const ev of ['gesturestart', 'gesturechange']) document.addEventListener(ev, (e) => { if (gridActive()) e.preventDefault(); }, { passive: false });

window.addEventListener('wheel', (e) => {
  if (!e.ctrlKey || !gridActive()) return;          // трекпад-щипок приходит как Ctrl+колесо
  e.preventDefault();
  Z.wheel += e.deltaY;
  const step = Math.abs(e.deltaY) >= 50 ? 1 : 30;
  if (Math.abs(Z.wheel) >= step) { setCols(Z.cols + Math.sign(Z.wheel), e.clientX, e.clientY); Z.wheel = 0; }
}, { passive: false });

$('zin').addEventListener('click', () => setCols(Z.cols - 1, innerWidth / 2, innerHeight / 2));
$('zout').addEventListener('click', () => setCols(Z.cols + 1, innerWidth / 2, innerHeight / 2));
// + / − и Ctrl(⌘) + / − / 0: вместо масштаба страницы браузером меняем размер плиток
const zoomKey = (e) => (e.key === '+' || e.key === '=' || e.code === 'NumpadAdd') ? 1
  : (e.key === '-' || e.key === '_' || e.code === 'NumpadSubtract') ? -1
  : (e.key === '0' || e.code === 'Numpad0') ? 0 : null;
document.addEventListener('keydown', (e) => {
  if (!gridActive() || e.altKey || /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) return;
  const k = zoomKey(e);
  if (k === null || (k === 0 && !(e.ctrlKey || e.metaKey))) return;
  e.preventDefault();
  if (k === 0) { store('pc.tile', null); initZoom(); relayout(true); return; }   // Ctrl+0 — размер по умолчанию
  setCols(Z.cols - k, innerWidth / 2, innerHeight / 2);
});
// На телефоне при прокрутке браузер прячет/показывает адресную строку — высота окна
// меняется, но сетка от высоты не зависит. Перестраиваем её только при смене ширины
// (поворот, окно на компе), иначе плитки пересоздавались бы и мигали.

// Ширина окна целиком (со скроллбаром): на компе скроллбар исчезает/появляется, когда
// открываешь фото или подгружается список, — сетку из-за этого перестраивать не надо.
// Перестраиваем только при настоящей смене ширины окна или повороте телефона.
const layoutW = () => window.innerWidth;
let resizeT = 0, lastW = layoutW();
window.addEventListener('resize', () => {
  clearTimeout(resizeT);
  resizeT = setTimeout(() => {
    if ($('main').hidden || !st.lib || !$('viewer').hidden) return;   // в просмотре — проверим при выходе
    if (layoutW() === lastW) { draw(false); updateScrub(); return; }
    lastW = layoutW();
    initZoom(); relayout(true);
  }, 150);
});

// высота шапки (для плашки месяца)
new ResizeObserver(() => {
  document.documentElement.style.setProperty('--header-h', document.querySelector('.top').offsetHeight + 'px');
}).observe(document.querySelector('.top'));

// ================================================================== просмотр

const V = { i: -1, token: 0, pushed: false, loads: [], ctl: null };
const fmt = new Intl.DateTimeFormat('ru', { dateStyle: 'long', timeStyle: 'short' });
const sizeStr = (kb) => (kb >= 1024 ? (kb / 1024).toFixed(1) + ' МБ' : kb + ' КБ');

function openViewer(i) {
  if (!$('viewer').hidden) { show(i); return; }
  $('viewer').hidden = false; document.body.style.overflow = 'hidden'; Z.pinch = null;
  document.documentElement.classList.add('viewing');
  clearTimeout(GP.t); if (GP.ctl) { GP.ctl.abort(); GP.ctl = null; }
  // недогруженные эскизы под просмотрщиком не нужны — отменяем, весь канал отдаём фото
  for (const [, node] of L.rendered) cancelImgs(node);
  history.pushState({ viewer: 1 }, ''); V.pushed = true;
  show(i);
}

// вышли из видео / живого фото: сервер сразу бросает перекодирование этого файла,
// и процессор с чтением с ПК достаются эскизам
function stopServer(id) {
  fetch(`/vid/${encodeURIComponent(id)}/stop`, { method: 'POST', keepalive: true, credentials: 'same-origin',
    headers: { 'X-Requested-With': 'photocloud' } }).catch(() => {});
}
function stopVideo() {
  $('v-note').hidden = true; $('v-origwrap').hidden = true;
  if (V.hls) { V.hls.destroy(); V.hls = null; }
  if (V.vidPid) { stopServer(V.vidPid); V.vidPid = null; }
  const v = $('v-video'); v.pause(); v.removeAttribute('src'); v.removeAttribute('poster'); v.load(); v.hidden = true;
  vzReset();
}

// HLS: Safari/iOS играют сами, остальным помогает hls.js (грузится только при первом видео)
let hlsLib = null;
function loadHls() {
  if (!hlsLib) hlsLib = new Promise((ok, fail) => {
    const s = document.createElement('script'); s.src = '/static/vendor/hls.light.min.js';
    s.onload = () => ok(window.Hls); s.onerror = fail; document.head.append(s);
  });
  return hlsLib;
}

async function playVideo(ph, tok, startAt) {
  const v = $('v-video');
  const canTranscode = st.me && st.me.transcode;
  const orig = !canTranscode || store('pc.vorig') === '1';
  $('v-origwrap').hidden = !canTranscode; $('v-origchk').checked = orig;
  $('v-note').hidden = !(orig && (ph[6] & F_NOPLAY));
  if (startAt) v.addEventListener('loadedmetadata', () => { v.currentTime = startAt; }, { once: true });
  if (orig) { v.src = origUrl(ph, false); return; }
  const url = `/vid/${encodeURIComponent(ph[0])}/eco/index.m3u8?v=${ph[4]}`;   // без сжатия — галочка «Оригинал»
  V.vidPid = ph[0];
  // Сначала hls.js (через MediaSource): новый Chrome на Android заявляет «родную»
  // поддержку HLS, но наш поток в ней не играет — шкала есть, видео нет. Родной HLS —
  // только там, где hls.js не работает (старые iPhone).
  try {
    const Hls = await loadHls();
    if (tok !== V.token) return;
    if (!Hls || !Hls.isSupported()) {
      v.src = v.canPlayType('application/vnd.apple.mpegurl') ? url : origUrl(ph, false);
      return;
    }
    V.hls = new Hls({ enableWorker: false, maxBufferLength: 20, backBufferLength: 30 });
    V.hls.on(Hls.Events.ERROR, (_e, d) => {
      if (!d.fatal || tok !== V.token) return;
      // перекодированный поток не пошёл — показываем оригинал, чтобы видео всё равно открылось
      if (V.hls) { V.hls.destroy(); V.hls = null; }
      v.src = origUrl(ph, false);
    });
    V.hls.loadSource(url); V.hls.attachMedia(v);
  } catch (_) { v.src = origUrl(ph, false); }
}

$('v-origchk').addEventListener('change', (e) => {
  store('pc.vorig', e.target.checked ? '1' : '0');
  const ph = st.list[V.i]; if (!ph) return;
  const v = $('v-video'), t = v.currentTime, playing = !v.paused;
  if (V.hls) { V.hls.destroy(); V.hls = null; }
  v.removeAttribute('src'); v.load();
  playVideo(ph, V.token, t).then(() => { if (playing) v.play().catch(() => {}); });
});

function show(i) {
  if (i < 0 || i >= st.list.length) return;
  V.i = i; const ph = st.list[i]; const tok = ++V.token;
  const isVideo = !!(ph[6] & F_VIDEO) && (!(ph[6] & F_NOPLAY) || (st.me && st.me.transcode));
  $('v-name').textContent = ph[2];
  starBtn();
  const fromMeta = ph[6] & F_TAKEN, fromName = ph[6] & F_NAME;
  let meta = (ph[6] & F_FOLDER)
    ? `${new Date(ph[3] * 1000).getFullYear()} год (по названию папки) · ${sizeStr(ph[5])}`
    : (fromMeta ? 'Снято ' : fromName ? 'Снято (по имени файла) ' : 'Дата файла ') + fmt.format(new Date(ph[3] * 1000)) + ' · ' + sizeStr(ph[5]);
  $('v-date').textContent = meta;
  $('v-orig').href = origUrl(ph, false);
  $('v-dl').href = origUrl(ph, true); $('v-dl').setAttribute('download', ph[2]);
  const low = $('v-low'), hi = $('v-img');
  stopVideo();
  resetZoom(false); VZ.shown = 0; VZ.want = ''; VZ.zoomedOnce = false;
  cancelLoads();
  const liveVid = setupLive(ph);
  $('v-note').hidden = !(ph[6] & F_NOPLAY);
  hi.classList.remove('ok'); hi.removeAttribute('src');
  if (shownBlob) { URL.revokeObjectURL(shownBlob); shownBlob = ''; }
  low.style.visibility = ''; low.src = imgUrl(thumbKind(), ph);     // уже в кэше браузера — мгновенно
  // ПК выключен — лучше эскиза ничего не придёт: показываем его чётким, без размытия и загрузки
  const pcOff = st.pc === 'down';
  low.classList.toggle('sharp', pcOff);
  if (isVideo) {
    const v = $('v-video'); v.hidden = false; v.poster = imgUrl('m', ph);
    low.style.visibility = 'hidden'; $('v-spin').hidden = true;
    playVideo(ph, tok, 0);
  } else {
    // Загрузка по ступеням, строго по очереди (на медленном канале параллельные
    // загрузки только мешают друг другу):
    //   1) быстрая сильно сжатая версия (~20–40 КБ) — фото видно почти сразу;
    //   2) у живого фото — ролик (он и так закрывает фото, пока играет);
    //   3) полная версия 2048 — сервер готовит её заранее вместе с быстрой, из того же декода;
    //   4) соседние фото (быстрые версии).
    // Начали увеличивать — всё недогруженное обрывается и сразу грузится оригинал (goOriginal).
    $('v-spin').hidden = pcOff;
    const full = previewKind();
    loadStep(ph, tok, 'q', `&n=${full}`).then(() => {
      if (tok !== V.token) return;
      // сразу за 2048 грузим оригинал (и на телефоне, и на компьютере) — не дожидаясь увеличения
      const rest = () => {
        if (VZ.zoomedOnce) return;
        loadStep(ph, tok, full, '')
          .then(() => { if (tok === V.token) prefetchInfo(ph, tok); })
          .then(() => (!VZ.zoomedOnce && tok === V.token && canOriginal(ph) ? (VZ.want = 'o', loadStep(ph, tok, 'o', '')) : null))
          .then(() => { if (tok === V.token && !VZ.zoomedOnce) prefetchNear(i, tok); });
      };
      if (liveVid) playLive(liveVid, tok, rest); else rest();
    });
  }
  $('v-prev').disabled = i === 0; $('v-next').disabled = i === st.list.length - 1;
  setSides();
  if (INFO.open) fillInfo();
}

const RANK = { q: 1, e: 2, p: 3, o: 4 };

function cancelLoads() {
  // фото пролистали / начали увеличивать — недогруженные версии и предзагрузка больше не
  // нужны. fetch + AbortController рвёт соединение надёжно (у new Image() — не всегда).
  for (const c of V.loads) c.abort();
  V.loads = [];
  if (V.ctl) { V.ctl.abort(); V.ctl = null; }
}

// одна ступень: грузим версию kind и показываем, если она подробнее уже показанной.
// Ждём (resolve) всегда: и при успехе, и при ошибке, и при обрыве — цепочка не зависает.
let shownBlob = '';
async function loadStep(ph, tok, kind, extra) {
  if (tok !== V.token) return false;
  const ctl = new AbortController();
  V.loads.push(ctl);
  const url = (kind === 'o' ? origUrl(ph, false) : imgUrl(kind, ph)) + extra;
  let blobUrl = '';
  try {
    const r = await fetch(url, { signal: ctl.signal, priority: 'high', credentials: 'same-origin' });
    if (!r.ok) throw new Error(String(r.status));
    blobUrl = URL.createObjectURL(await r.blob());
    const im = new Image(); im.src = blobUrl;
    await im.decode();                                   // показываем уже раскодированное — без мигания
    if (tok !== V.token || RANK[kind] <= VZ.shown) { URL.revokeObjectURL(blobUrl); return true; }
    const hi = $('v-img');
    hi.src = blobUrl; hi.classList.add('ok'); VZ.shown = RANK[kind];
    if (shownBlob) URL.revokeObjectURL(shownBlob);
    shownBlob = blobUrl;
    setLabel();
    if (kind === 'o') preloadOrigClip(ph, tok);
    $('v-spin').hidden = true;
    setTimeout(() => { if (tok === V.token) $('v-low').style.visibility = 'hidden'; }, 200);
    return true;
  } catch (_) {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    if (tok === V.token && kind !== 'q' && !ctl.signal.aborted) $('v-spin').hidden = true;
    return false;
  } finally {
    V.loads = V.loads.filter((c) => c !== ctl);
  }
}

// соседние фото: по одному и с низким приоритетом — открытое фото важнее
async function prefetchNear(i, tok) {
  const ctl = V.ctl = new AbortController();
  const full = previewKind();
  const urls = [];
  for (const j of [i + 1, i - 1]) {
    const n = st.list[j];
    if (n && !(n[6] & F_VIDEO)) urls.push(imgUrl('q', n) + `&n=${full}`);
  }
  for (const u of urls) {
    if (tok !== V.token || ctl.signal.aborted) return;
    try {
      // X-PF: сервер ставит это в очередь после фото, которое открыто сейчас
      const r = await fetch(u, { signal: ctl.signal, priority: 'low', headers: { 'X-PF': '1' }, credentials: 'same-origin' });
      await r.arrayBuffer();
      if (r.ok) { prefetched.add(u); if (prefetched.size > 2000) prefetched.clear(); setSides(); }
    } catch (_) { return; }
  }
}

// ---- подпись: «Превью •» пока показана быстрая версия (или играет превью-ролик),
// «Без сжатия •» — когда показан оригинал
function setLabel() {
  const ph = st.list[V.i]; if (!ph) return;
  let pre = '';
  if (V.clip && V.clip.el.classList.contains('on')) pre = V.clip.q === 'eco' ? 'Превью • ' : V.clip.q === 'orig' ? 'Без сжатия • ' : '';
  else if (VZ.shown === RANK.q) pre = 'Превью • ';
  else if (VZ.shown === RANK.o) pre = 'Без сжатия • ';
  $('v-name').textContent = pre + ph[2];
}

// ---- живые фото
// Три <video> друг над другом: лёгкий превью-ролик, хороший (до 1080p) и оригинал файла.
// Играет лучший из уже загруженных; как только догрузился лучший — подмена на том же
// кадре (если ролик сейчас играет) или просто он будет играть в следующий раз.
const liveEls = (() => {
  const a = $('v-live'), b = a.cloneNode(), c = a.cloneNode();
  b.id = 'v-live2'; c.id = 'v-live3'; a.after(b); b.after(c);
  return { eco: a, hq: b, orig: c };
})();
const CLIPQ = { eco: 1, hq: 2, orig: 3 };
function stopLive() {
  // ролик ещё не готов — значит, сервер его перекодирует: просим бросить
  const busy = new Set();
  for (const lv of Object.values(liveEls)) {
    const m = (lv.getAttribute('src') || '').match(/^\/vid\/([^/]+)\/live\.mp4/);
    if (m && lv.readyState < 4) busy.add(decodeURIComponent(m[1]));
  }
  for (const id of busy) stopServer(id);
  for (const lv of Object.values(liveEls)) {
    lv.oncanplay = lv.oncanplaythrough = lv.onended = lv.onerror = lv.onplaying = null;
    lv.classList.remove('on'); lv.pause(); lv.removeAttribute('src'); lv.load();
  }
  V.clip = null;
}
function setupLive(ph) {
  // -> id ролика, если его надо проиграть (сам запуск — после быстрой версии фото)
  stopLive();
  const vid = (ph[6] & F_LIVE) && st.lib.live[ph[0]];
  $('v-livewrap').hidden = !vid;
  if (!vid) return null;
  $('v-livechk').checked = liveOn();
  return $('v-livechk').checked ? vid : null;
}
// галочка Live: включена по умолчанию, выбор запоминается в браузере
const liveOn = () => store('pc.live') !== '0';
const liveUrl = (vid, q) => q === 'orig' ? `/img/o/${encodeURIComponent(vid)}` : `/vid/${encodeURIComponent(vid)}/live.mp4?q=${q}`;
const startEl = (el) => el.play().catch(() => { el.muted = true; return el.play(); });  // без звука, если браузер не дал

// ролик качества q готов: становится текущим, если он лучше; играет — подменяем на том же кадре
function useClip(q, tok) {
  if (tok !== V.token) return;
  const el = liveEls[q], cur = V.clip;
  if (cur && CLIPQ[cur.q] >= CLIPQ[q]) return;
  el.onended = () => { el.classList.remove('on'); setLabel(); };
  if (cur && cur.el.classList.contains('on') && !cur.el.ended && !cur.el.paused) {
    el.currentTime = cur.el.currentTime; el.muted = cur.el.muted;
    el.onplaying = () => {
      el.onplaying = null;
      if (tok !== V.token) return;
      el.classList.add('on'); cur.el.classList.remove('on'); cur.el.pause();
      V.clip = { el, q }; setLabel();
    };
    startEl(el).catch(() => {});
  } else V.clip = { el, q };
}
// загрузить ролик качества q (если ещё не грузится); ready/fail — по готовности/ошибке
function loadClip(vid, q, tok, ready, fail) {
  const el = liveEls[q];
  if (el.getAttribute('src')) return false;
  el.preload = 'auto';
  el.oncanplaythrough = () => { el.oncanplaythrough = null; if (tok === V.token) { useClip(q, tok); if (ready) ready(); } };
  el.onerror = () => { el.removeAttribute('src'); if (tok === V.token && fail) fail(); };
  el.src = liveUrl(vid, q); el.load();
  return true;
}
function playClip(el) {
  el.muted = false; el.currentTime = 0;
  startEl(el).then(() => { el.classList.add('on'); setLabel(); }).catch(() => {});
}

// при открытии: превью-ролик (сразу играет) -> хороший ролик -> after (фото 2048)
function playLive(vid, tok, after) {
  let done = false;
  const next = () => { if (done) return; done = true; if (after && tok === V.token) after(); };
  setTimeout(next, 8000);
  const eco = liveEls.eco;
  eco.oncanplay = () => {
    eco.oncanplay = null;
    if (tok !== V.token) return;
    if (!V.clip) V.clip = { el: eco, q: 'eco' };
    if (V.clip.el === eco && !Object.values(liveEls).some((x) => x.classList.contains('on'))) playClip(eco);
  };
  const hq = () => loadClip(vid, 'hq', tok, next, next) || next();
  if (!loadClip(vid, 'eco', tok, hq, hq)) hq();
}

// Показан оригинал фото — грузим оригинал ролика. Пока он грузится, касание играет
// то, что уже есть; оригинал подменит его, как догрузится. Если браузер оригинал не
// играет (HEVC в .mov на части телефонов) — остаётся хороший пережатый.
function preloadOrigClip(ph, tok) {
  const vid = (ph[6] & F_LIVE) && st.lib.live[ph[0]];
  if (!vid || tok !== V.token || !liveOn()) return;            // галочка Live снята — ролики не грузим
  loadClip(vid, 'orig', tok, null, () => loadClip(vid, 'hq', tok));
}

// Касание живого фото (без сдвига; и в увеличении тоже) — проиграть ролик заново, со звуком.
// На телефоне двойное касание — увеличить в этой точке или вернуть как было, поэтому одиночное
// касание срабатывает с задержкой DOUBLE_TAP (только оно и ждёт; мышь — сразу).
const DOUBLE_TAP = 300, DOUBLE_TAP_ZOOM = 2.5;
let tapAt = null, lastTap = null, tapTimer = 0;
$('v-stage').addEventListener('pointerdown', (e) => { tapAt = e.isPrimary ? [e.clientX, e.clientY] : null; });
$('v-stage').addEventListener('pointerup', (e) => {
  if (!tapAt || Math.hypot(e.clientX - tapAt[0], e.clientY - tapAt[1]) > 10) return;
  tapAt = null;
  if (e.pointerType !== 'touch' || e.target.tagName === 'VIDEO' || !zoomActive()) { replayLive(); return; }
  const now = Date.now();
  if (now - (VZ.multiAt || 0) < 400) { lastTap = null; return; }   // это конец щипка, а не касание
  if (lastTap && now - lastTap.t < DOUBLE_TAP && Math.hypot(e.clientX - lastTap.x, e.clientY - lastTap.y) < 40) {
    clearTimeout(tapTimer); lastTap = null;
    if (DR.busy) return;
    if (VZ.s > 1.02) resetZoom(true);
    else { const [fx, fy] = stagePoint(e.clientX, e.clientY); zoomAt(DOUBLE_TAP_ZOOM, fx, fy, true); }
    return;
  }
  lastTap = { t: now, x: e.clientX, y: e.clientY };
  clearTimeout(tapTimer); tapTimer = setTimeout(() => { lastTap = null; replayLive(); }, DOUBLE_TAP);
});
function replayLive() {
  const ph = st.list[V.i], vid = ph && (ph[6] & F_LIVE) && st.lib.live[ph[0]];
  if (!vid || !liveOn() || $('v-livewrap').hidden || $('viewer').hidden || DR.busy) return;
  if (V.clip) { for (const x of Object.values(liveEls)) if (x !== V.clip.el) { x.classList.remove('on'); x.pause(); } playClip(V.clip.el); return; }
  // ещё ничего не загружено: превью-ролик сыграет сам, как будет готов; лучшие подменят его
  playLive(vid, V.token, null);
  if (VZ.shown === RANK.o) preloadOrigClip(ph, V.token);
}
$('v-livechk').addEventListener('change', (e) => {
  store('pc.live', e.target.checked ? '1' : '0');
  const ph = st.list[V.i]; const vid = ph && st.lib.live[ph[0]];
  if (!vid) return;
  if (e.target.checked) { stopLive(); playLive(vid, V.token, null); if (VZ.shown === RANK.o) preloadOrigClip(ph, V.token); }
  else { stopLive(); setLabel(); }
});

// ================================================================== жесты в просмотре (как в Google Фото)
// Одним пальцем без увеличения: вбок — фото едет за пальцем, рядом следующее, отпустил —
// докатывается (или возвращается); вверх/вниз — фото уменьшается за пальцем, фон
// растворяется, отпустил дальше порога — фото улетает в свою плитку, иначе возвращается.
const pane = el('div', 'v-pane');
$('v-zoom').before(pane); pane.append($('v-zoom'));
const sidePrev = el('img', 'v-side prev'), sideNext = el('img', 'v-side next');
sidePrev.alt = sideNext.alt = ''; pane.append(sidePrev, sideNext);
const GAP = 24;
const DR = { axis: null, busy: false };
const EASE = 'cubic-bezier(.2,.8,.2,1)';

function setSides() {
  for (const [img, j] of [[sidePrev, V.i - 1], [sideNext, V.i + 1]]) {
    const n = st.list[j];
    if (!n) { img.removeAttribute('src'); continue; }
    // фото: быстрое превью, если уже в кэше браузера (соседей мы подгружаем), иначе эскиз из
    // сетки; видео — всегда эскиз (быстрое превью для видео — лишний кадр через ffmpeg)
    // (сами не запрашиваем: соседи грузятся после открытого фото, в prefetchNear)
    const q = imgUrl('q', n) + '&n=p';
    img.src = !(n[6] & F_VIDEO) && prefetched.has(q) ? q : imgUrl(thumbKind(), n);
  }
}
function paneTo(x, y, s, anim) {
  pane.style.transition = anim ? `transform .26s ${EASE}` : 'none';
  pane.style.transform = x || y || s !== 1 ? `translate(${x}px, ${y}px) scale(${s})` : '';
}
function backdrop(a, anim) {
  const t = anim ? `.26s ${EASE}` : '0s';
  $('viewer').style.transition = `background-color ${t}`;
  $('viewer').style.backgroundColor = a >= 1 ? '' : `rgba(0,0,0,${a})`;
  for (const n of [document.querySelector('.v-top'), $('v-prev'), $('v-next')]) {
    n.style.transition = `opacity ${t}`; n.style.opacity = a >= 1 ? '' : String(Math.max(0, a * 2 - 1));
  }
}
function sides(on) { sidePrev.style.visibility = sideNext.style.visibility = on ? '' : 'hidden'; }
function resetPane() { paneTo(0, 0, 1, false); backdrop(1, false); sides(true); DR.busy = false; }

function dragMove(dx, dy) {
  const W = stage.clientWidth, H = stage.clientHeight;
  if (DR.axis === 'x') {
    const edge = (dx > 0 && V.i === 0) || (dx < 0 && V.i === st.list.length - 1);
    paneTo(edge ? dx * 0.3 : dx, 0, 1, false);                 // у края — «резинка»
  } else if (dy < 0 || INFO.open) {
    // вверх — потянуть фото к панели «Подробнее»; при открытой панели вниз — к её закрытию
    sides(false);
    paneTo(0, dy * 0.25, 1, false);
  } else {
    sides(false);                                               // при выходе — только текущее фото
    const p = Math.min(1, Math.abs(dy) / H);
    paneTo(dx, dy, 1 - p * 0.4, false);
    backdrop(1 - Math.min(1, Math.abs(dy) / (H * 0.4)), false);
  }
  void W;
}

function dragEnd(dx, dy, dt) {
  const W = stage.clientWidth;
  if (DR.axis === 'x') {
    const dir = dx < 0 ? 1 : -1, target = V.i + dir;
    const fast = Math.abs(dx) / Math.max(dt, 1) > 0.6 && Math.abs(dx) > 40;
    if ((Math.abs(dx) > W * 0.3 || fast) && st.list[target]) {
      DR.busy = true;
      paneTo(-dir * (W + GAP), 0, 1, true);
      setTimeout(() => { resetPane(); show(target); }, 260);
    } else paneTo(0, 0, 1, true);
  } else {
    const fast = Math.abs(dy) / Math.max(dt, 1) > 0.6 && Math.abs(dy) > 40;
    if (dy < 0 || INFO.open) {
      // вверх — открыть «Подробнее» (фото не закрывается); вниз при открытой панели — закрыть её
      if (dy < -50 || (fast && dy < 0)) openInfo();
      else if (INFO.open && (dy > 50 || fast)) closeInfo();
      paneTo(0, 0, 1, true); setTimeout(() => sides(true), 270);
    } else if (Math.abs(dy) > 90 || fast) dismiss(dx, dy);
    else { paneTo(0, 0, 1, true); backdrop(1, true); setTimeout(() => { if (!DR.axis) sides(true); }, 270); }
  }
  DR.axis = null;
}

// фото улетает в свою плитку; сетка становится доступна только после полного выхода
function dismiss() {
  DR.busy = true;
  stopLive();
  let tile = document.querySelector(`.tile[data-i="${V.i}"]`);
  let t = tile && tile.getBoundingClientRect();
  if (!t || t.bottom < 0 || t.top > window.innerHeight) {
    scrollToIndex(V.i, window.innerHeight / 3); draw(true);
    tile = document.querySelector(`.tile[data-i="${V.i}"]`); t = tile && tile.getBoundingClientRect();
  }
  const sb = stage.getBoundingClientRect(), r = imgRect();
  if (t && r.w && r.h) {
    const k = Math.max(t.width / r.w, t.height / r.h);
    const ox = sb.width / 2, oy = sb.height / 2;                 // pane масштабируется от центра
    const cx = r.x + r.w / 2, cy = r.y + r.h / 2;
    const tx = (t.left + t.width / 2 - sb.left) - (ox + (cx - ox) * k);
    const ty = (t.top + t.height / 2 - sb.top) - (oy + (cy - oy) * k);
    pane.style.clipPath = '';
    paneTo(tx, ty, k, true);
  } else {
    paneTo(0, 0, 0.6, true); pane.style.transition += ', opacity .26s'; pane.style.opacity = '0';
  }
  backdrop(0, true);
  setTimeout(() => { closeViewer(); resetPane(); pane.style.opacity = ''; }, 270);
}

// ================================================================== «Подробнее»: дата, файл, камера, место
// Смахнуть фото вверх (или кнопка ⓘ) — снизу выезжает панель; вниз или ✕ на панели — скрыть.
const INFO = { open: false, map: null, seq: 0 };
function openInfo() {
  if ($('viewer').hidden || INFO.open) return;
  INFO.open = true;
  const el = $('v-info'); el.hidden = false; el.scrollTop = 0;
  requestAnimationFrame(() => { el.classList.add('open'); liftPhoto(); });
  fillInfo();
}
// фото уезжает вверх — в свободную над панелью часть экрана (на телефоне; на компе панель сбоку)
function liftPhoto() {
  const st2 = $('v-stage'), el = $('v-info');
  const narrow = window.innerWidth < 700;
  const h = INFO.open && narrow ? Math.min(el.offsetHeight, window.innerHeight * 0.58) : 0;
  st2.style.transition = 'transform .25s cubic-bezier(.2,.8,.2,1)';
  st2.style.transform = h ? `translateY(${-h / 2}px)` : '';
}
function closeInfo(now) {
  if (!INFO.open && $('v-info').hidden) return;
  INFO.open = false; INFO.seq++;
  const el = $('v-info'); el.classList.remove('open'); liftPhoto();
  if (INFO.map) { INFO.map.remove(); INFO.map = null; }
  if (now) el.hidden = true; else setTimeout(() => { if (!INFO.open) el.hidden = true; }, 260);
}
$('v-infobtn').addEventListener('click', () => (INFO.open ? closeInfo() : openInfo()));

let leaflet = null;
function loadLeaflet() {
  if (leaflet) return leaflet;
  leaflet = new Promise((ok, fail) => {
    const css = document.createElement('link'); css.rel = 'stylesheet'; css.href = '/static/vendor/leaflet.css';
    document.head.append(css);
    const sc = document.createElement('script'); sc.src = '/static/vendor/leaflet.js';
    sc.onload = () => ok(window.L); sc.onerror = () => { leaflet = null; fail(new Error('leaflet')); };
    document.head.append(sc);
  });
  return leaflet;
}

// подробности снимка: один запрос на фото за сеанс (сервер и сам хранит их в базе)
const infoCache = new Map();
function getInfo(ph) {
  let pr = infoCache.get(ph[0]);
  if (!pr) {
    pr = fetch(`/api/info/${encodeURIComponent(ph[0])}`, { credentials: 'same-origin', priority: 'low' })
      .then((r) => (r.ok ? r.json() : {})).catch(() => ({}))
      .then((j) => { if (!Object.keys(j).length) infoCache.delete(ph[0]); return j; });
    infoCache.set(ph[0], pr);
    if (infoCache.size > 500) infoCache.delete(infoCache.keys().next().value);
  }
  return pr;
}
// заранее (после фото 2048): к смахиванию вверх всё уже готово, при GPS — и карта
function prefetchInfo(ph, tok) {
  if (ph[6] & F_VIDEO) return;
  getInfo(ph).then((j) => { if (tok === V.token && j && j.lat != null) loadLeaflet().catch(() => {}); });
}

function infoRows(rows) {
  const dl = el('dl', 'kv');
  for (const [k, v] of rows) if (v) dl.append(el('dt', null, k), el('dd', null, v));
  return dl;
}

async function fillInfo() {
  const ph = st.list[V.i]; if (!ph) return;
  const seq = ++INFO.seq;
  if (INFO.map) { INFO.map.remove(); INFO.map = null; }
  const body = $('v-info-body');
  const src = (ph[6] & F_TAKEN) ? 'из метаданных' : (ph[6] & F_NAME) ? 'по имени файла' : (ph[6] & F_FOLDER) ? 'по названию папки' : 'дата файла, дата съёмки неизвестна';
  const when = (ph[6] & F_FOLDER) ? `${new Date(ph[3] * 1000).getFullYear()} год` : fmt.format(new Date(ph[3] * 1000));
  const folder = st.lib.folders[ph[1]] || 'корень';
  const extra = el('div'); extra.append(el('div', 'dim', 'Загружаю подробности…'));
  body.replaceChildren(el('h3', null, 'Подробнее'),
    infoRows([['Дата', `${when} (${src})`], ['Файл', ph[2]], ['Папка', folder], ['Размер', sizeStr(ph[5])],
    ]), extra);
  const info = await getInfo(ph);
  if (seq !== INFO.seq || !INFO.open) return;
  extra.replaceChildren();
  const mp = info.width && info.height ? `${info.width} × ${info.height} (${(info.width * info.height / 1e6).toFixed(1)} Мп)` : '';
  if (mp || info.camera) extra.append(infoRows([['Разрешение', mp], ['Камера', info.camera]]));
  // админу — кто и когда скрыл (видит скрытые всех); остальным — когда скрыли сами
  if (info.hidden_by) extra.append(infoRows([['Скрыто', info.hidden_by.map((h) => `${h.user}, ${fmt.format(new Date(h.at * 1000))}`).join('; ')]]));
  else if (info.hidden_at) extra.append(infoRows([['Скрыто', fmt.format(new Date(info.hidden_at * 1000))]]));
  if (info.delete_by) extra.append(infoRows([['На удаление', `${info.delete_by}, ${fmt.format(new Date(info.delete_at * 1000))}`]]));
  if (info.lat == null) {
    extra.append(el('h3', null, 'Местоположение'), el('div', 'dim', 'В файле нет координат.'));
    return;
  }
  const lat = info.lat, lon = info.lon;
  const coords = `${lat.toFixed(5)}, ${lon.toFixed(5)}`;
  const map = el('div', 'map'), addr = el('div', 'addr', info.address || coords);
  if (!info.address_known) {
    // адрес ещё не известен — карта показывается сразу, адрес подставится, как придёт
    addr.textContent = coords + ' · ищу адрес…';
    fetch(`/api/info/${encodeURIComponent(ph[0])}/address`, { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : {})).catch(() => ({}))
      .then((j) => {
        if (seq !== INFO.seq) return;
        addr.textContent = j.address || coords;
        if (j.address) { info.address = j.address; info.address_known = true; }   // в кэше сеанса
      });
  }
  const links = el('div', 'links');
  const ya = el('a', null, 'Яндекс Карты'); ya.href = `https://yandex.ru/maps/?pt=${lon},${lat}&z=16&l=map`;
  const gm = el('a', null, 'Google Карты'); gm.href = `https://www.google.com/maps?q=${lat},${lon}`;
  for (const a of [ya, gm]) { a.target = '_blank'; a.rel = 'noopener noreferrer'; links.append(a); }
  extra.append(el('h3', null, 'Местоположение'), map, addr, links);
  try {
    const L = await loadLeaflet();
    if (seq !== INFO.seq || !INFO.open) return;
    const m = L.map(map, { zoomControl: true, attributionControl: true }).setView([lat, lon], 15);
    m.attributionControl.setPrefix(false);
    // OpenStreetMap просит Referer — отдаём только адрес сайта, без пути
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',
      { maxZoom: 19, attribution: '© OpenStreetMap', referrerPolicy: 'origin' }).addTo(m);
    const pin = document.createElement('div'); pin.className = 'map-pin';
    const im = document.createElement('img'); im.alt = ''; im.src = imgUrl('s', ph); pin.append(im);
    L.marker([lat, lon], { icon: L.divIcon({ html: pin, className: '', iconSize: [52, 52], iconAnchor: [26, 52] }) }).addTo(m);
    INFO.map = m;
    setTimeout(() => m.invalidateSize(), 280);      // панель доехала — пересчитать размер карты
  } catch (_) {
    map.replaceWith(el('div', 'dim', 'Карта не загрузилась.'));
  }
}

// панель: потянуть вниз от верха — закрыть
(() => {
  const p = $('v-info'); let y0 = null;
  p.addEventListener('touchstart', (e) => { y0 = p.scrollTop <= 0 && e.touches.length === 1 && !e.target.closest('.map') ? e.touches[0].clientY : null; }, { passive: true });
  p.addEventListener('touchmove', (e) => {
    if (y0 == null) return;
    const dy = e.touches[0].clientY - y0;
    if (dy > 0) p.style.transform = `translateY(${dy}px)`;
  }, { passive: true });
  p.addEventListener('touchend', (e) => {
    if (y0 == null) return;
    const dy = e.changedTouches[0].clientY - y0; y0 = null; p.style.transform = '';
    if (dy > 80) closeInfo();
  }, { passive: true });
})();

function closeViewer(silent) {
  if ($('viewer').hidden) return;
  closeInfo(true);
  stopVideo(); stopLive(); resetZoom(false); cancelLoads();
  $('viewer').hidden = true; document.body.style.overflow = ''; resetPane(); pane.style.opacity = '';
  document.documentElement.classList.remove('viewing');
  $('v-img').removeAttribute('src'); $('v-low').removeAttribute('src'); V.token++;
  if (shownBlob) { URL.revokeObjectURL(shownBlob); shownBlob = ''; }
  if (V.pushed && !silent) { V.pushed = false; history.back(); }
  V.pushed = false;
  // если пролистали далеко — возвращаем сетку к последнему просмотренному
  const t = document.querySelector(`.tile[data-i="${V.i}"]`);
  const r = t && t.getBoundingClientRect();
  if (!r || r.bottom < 0 || r.top > window.innerHeight) { scrollToIndex(V.i, window.innerHeight / 3); draw(true); }
  loadVisible(true);      // догружаем эскизы, отменённые при открытии
  gridPrefetchSoon();
  if (layoutW() !== lastW) { lastW = layoutW(); initZoom(); relayout(true); }   // повернули телефон в просмотре
  L.calmUntil = Date.now() + 2000;          // после выхода сетка пару секунд не перестраивается сама
  // на странице избранного: пока смотрели, сняли звёздочки — обновляем список при выходе
  if (STAR.dirty) { STAR.dirty = false; loadLibrary(); }
}

window.addEventListener('popstate', () => { if (!$('viewer').hidden) { V.pushed = false; closeViewer(true); } });
$('v-close').addEventListener('click', () => closeViewer());
$('v-prev').addEventListener('click', () => show(V.i - 1));
$('v-next').addEventListener('click', () => show(V.i + 1));
// ================================================================== масштаб в просмотре
// Щипок / растяжение, двойное касание (телефон), колесо мыши, Ctrl+колесо (жест трекпада), перетаскивание.
// Свайпы влево/вправо/вниз работают только при обычном масштабе.

const VZ = { s: 1, tx: 0, ty: 0, pinch: null, pan: null, moved: false, shown: 0, want: '' };
const MAX_ZOOM = 8;
const stage = $('v-stage'), zoomEl = $('v-zoom');

function zoomActive() { return !$('viewer').hidden && $('v-video').hidden; }

function imgRect() {
  // где лежит картинка внутри экрана при масштабе 1 (object-fit: contain)
  const W = stage.clientWidth, H = stage.clientHeight;
  const im = $('v-img').naturalWidth ? $('v-img') : $('v-low');
  const iw = im.naturalWidth || W, ih = im.naturalHeight || H;
  const k = Math.min(W / iw, H / ih);
  const w = iw * k, h = ih * k;
  return { x: (W - w) / 2, y: (H - h) / 2, w, h, W, H };
}

function clampPan() {
  const r = imgRect(), s = VZ.s;
  const fit = (t, pos, len, view) => {
    const size = len * s;
    if (size <= view) return (view - size) / 2 - pos * s;              // меньше экрана — по центру
    return clamp(t, view - (pos + len) * s, -pos * s);                  // больше — без пустых полей
  };
  VZ.tx = fit(VZ.tx, r.x, r.w, r.W);
  VZ.ty = fit(VZ.ty, r.y, r.h, r.H);
}

function applyZoom(anim) {
  if (VZ.s > 1.02 && !VZ.zoomedOnce && !$('viewer').hidden) goOriginal();
  zoomEl.classList.toggle('anim', !!anim);
  zoomEl.style.transform = VZ.s === 1 ? '' : `translate(${VZ.tx}px, ${VZ.ty}px) scale(${VZ.s})`;
  stage.classList.toggle('zoomed', VZ.s > 1);
}

function resetZoom(anim) { VZ.s = 1; VZ.tx = 0; VZ.ty = 0; applyZoom(anim); }

function zoomAt(s, fx, fy, anim) {
  // fx, fy — точка в координатах stage, которая остаётся под пальцем/курсором
  s = clamp(s, 1, MAX_ZOOM);
  VZ.tx = fx - (fx - VZ.tx) * (s / VZ.s);
  VZ.ty = fy - (fy - VZ.ty) * (s / VZ.s);
  VZ.s = s;
  if (s <= 1.01) { resetZoom(anim); return; }
  clampPan(); applyZoom(anim);
}

function stagePoint(cx, cy) { const b = stage.getBoundingClientRect(); return [cx - b.left, cy - b.top]; }

// Начали увеличивать: недогруженные картинки (версии фото, соседи) обрываем — браузер
// закрывает соединения, сервер снимает их запросы из очереди — и сразу грузим оригинал (ролик живого фото не трогаем).
// Если браузер не покажет оригинал (HEIC и т.п.) или он больше 25 МБ — версию 2048.
// оригинал, который браузер покажет сам (не HEIC и т.п.) и не больше 25 МБ
function canOriginal(ph) {
  const ext = ph[2].slice(ph[2].lastIndexOf('.')).toLowerCase();
  return ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext) && ph[5] < 25 * 1024;
}
function goOriginal() {
  const ph = st.list[V.i];
  if (!ph || VZ.zoomedOnce || (ph[6] & F_VIDEO)) return;
  VZ.zoomedOnce = true;
  const want = canOriginal(ph) ? 'o' : 'p';
  if (VZ.want === want) return;                  // уже грузится (на компьютере оригинал идёт сразу)
  cancelLoads(); setLabel();
  if (RANK[want] > VZ.shown) { VZ.want = want; loadStep(ph, V.token, want, ''); }
}

const tdist = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
const tmid = (t) => stagePoint((t[0].clientX + t[1].clientX) / 2, (t[0].clientY + t[1].clientY) / 2);

stage.addEventListener('touchstart', (e) => {
  VZ.lastTouch = Date.now();
  if (e.target.tagName === 'VIDEO') return;
  if (e.touches.length >= 2) VZ.multiAt = Date.now();          // щипок — не касание (двойное касание)
  if (e.touches.length === 2 && zoomActive()) {
    const [mx, my] = tmid(e.touches);
    VZ.pinch = { d0: tdist(e.touches) || 1, s0: VZ.s, mx, my, tx0: VZ.tx, ty0: VZ.ty };
    VZ.pan = null; VZ.moved = true;
    if (DR.axis) { DR.axis = null; paneTo(0, 0, 1, true); backdrop(1, true); sides(true); }   // второй палец — это щипок
  } else if (e.touches.length === 1) {
    const t = e.touches[0];
    VZ.pan = { x: t.clientX, y: t.clientY, tx0: VZ.tx, ty0: VZ.ty, t: Date.now() };
    VZ.moved = false; DR.axis = null;
  }
}, { passive: true });

stage.addEventListener('touchmove', (e) => {
  if (e.target.tagName === 'VIDEO') return;
  if (VZ.pinch && e.touches.length === 2) {
    e.preventDefault();
    const p = VZ.pinch, s = clamp(p.s0 * tdist(e.touches) / p.d0, 0.8, MAX_ZOOM);
    const [mx, my] = tmid(e.touches);
    // точка, бывшая под пальцами, остаётся под ними (и двигается вместе с ними)
    VZ.tx = mx - (p.mx - p.tx0) * (s / p.s0);
    VZ.ty = my - (p.my - p.ty0) * (s / p.s0);
    VZ.s = s; applyZoom(false);
  } else if (VZ.pan && e.touches.length === 1) {
    const t = e.touches[0], dx = t.clientX - VZ.pan.x, dy = t.clientY - VZ.pan.y;
    if (Math.abs(dx) + Math.abs(dy) > 8) VZ.moved = true;
    if (VZ.s > 1) { e.preventDefault(); VZ.tx = VZ.pan.tx0 + dx; VZ.ty = VZ.pan.ty0 + dy; clampPan(); applyZoom(false); }
    else if (!DR.busy) {
      // направление выбираем один раз: вбок — листание, вверх/вниз — выход
      if (!DR.axis && Math.abs(dx) + Math.abs(dy) > 10) DR.axis = Math.abs(dx) > Math.abs(dy) ? 'x' : 'y';
      if (DR.axis) { e.preventDefault(); dragMove(dx, dy); }
    }
  }
}, { passive: false });

stage.addEventListener('touchend', (e) => {
  if (e.target.tagName === 'VIDEO') return;
  if (VZ.pinch) {
    if (e.touches.length < 2) {
      VZ.pinch = null;
      if (VZ.s < 1.05) resetZoom(true); else { clampPan(); applyZoom(true); }
      // оставшийся палец продолжает двигать картинку, а не листать
      if (e.touches.length === 1) { const t = e.touches[0]; VZ.pan = { x: t.clientX, y: t.clientY, tx0: VZ.tx, ty0: VZ.ty, t: Date.now() }; VZ.moved = true; }
    }
    return;
  }
  if (!VZ.pan || e.touches.length) return;
  const t = e.changedTouches[0], dx = t.clientX - VZ.pan.x, dy = t.clientY - VZ.pan.y;
  const t0 = VZ.pan.t, quick = Date.now() - t0 < 300;
  VZ.pan = null;
  if (!VZ.moved && quick) return;                           // касание — его обрабатывает pointerup (живое фото)
  if (VZ.s > 1 || !DR.axis) { DR.axis = null; return; }   // при увеличении свайпы не листают
  dragEnd(dx, dy, Date.now() - t0);
}, { passive: true });

// ---- видео: щипок увеличивает, двумя пальцами — двигать; увеличенное — одним пальцем двигать,
// касание — пауза/воспроизведение. Пока увеличено, системные кнопки плеера спрятаны (иначе
// они увеличились бы вместе с кадром); вернул масштаб — кнопки на месте.
const VV = { s: 1, tx: 0, ty: 0, pinch: null, pan: null };
const vEl = $('v-video');
function vzApply() {
  const z = VV.s > 1.01;
  vEl.style.transformOrigin = '0 0';
  vEl.style.transform = z ? `translate(${VV.tx}px, ${VV.ty}px) scale(${VV.s})` : '';
  if (vEl.controls === z) vEl.controls = !z;
}
function vzReset() { VV.s = 1; VV.tx = 0; VV.ty = 0; VV.pinch = VV.pan = null; vzApply(); }
function vzClamp() {
  const W = vEl.clientWidth, H = vEl.clientHeight;
  VV.tx = clamp(VV.tx, W * (1 - VV.s), 0); VV.ty = clamp(VV.ty, H * (1 - VV.s), 0);
}
vEl.addEventListener('touchstart', (e) => {
  if (e.touches.length === 2) {
    e.preventDefault();
    const [mx, my] = tmid(e.touches);
    VV.pinch = { d0: tdist(e.touches) || 1, s0: VV.s, mx, my, tx0: VV.tx, ty0: VV.ty }; VV.pan = null;
  } else if (e.touches.length === 1 && VV.s > 1.01) {
    const t = e.touches[0]; VV.pan = { x: t.clientX, y: t.clientY, tx0: VV.tx, ty0: VV.ty, moved: false };
  }
}, { passive: false });
vEl.addEventListener('touchmove', (e) => {
  if (VV.pinch && e.touches.length === 2) {
    e.preventDefault();
    const p = VV.pinch, s = clamp(p.s0 * tdist(e.touches) / p.d0, 1, MAX_ZOOM);
    const [mx, my] = tmid(e.touches);
    VV.tx = mx - (p.mx - p.tx0) * (s / p.s0); VV.ty = my - (p.my - p.ty0) * (s / p.s0); VV.s = s;
    vzClamp(); vzApply();
  } else if (VV.pan && e.touches.length === 1) {
    e.preventDefault();
    const t = e.touches[0], dx = t.clientX - VV.pan.x, dy = t.clientY - VV.pan.y;
    if (Math.abs(dx) + Math.abs(dy) > 8) VV.pan.moved = true;
    VV.tx = VV.pan.tx0 + dx; VV.ty = VV.pan.ty0 + dy; vzClamp(); vzApply();
  }
}, { passive: false });
vEl.addEventListener('touchend', (e) => {
  if (VV.pinch && e.touches.length < 2) {
    VV.pinch = null;
    if (VV.s < 1.05) vzReset();
    if (e.touches.length === 1 && VV.s > 1.01) { const t = e.touches[0]; VV.pan = { x: t.clientX, y: t.clientY, tx0: VV.tx, ty0: VV.ty, moved: true }; }
    return;
  }
  if (VV.pan && !e.touches.length) {
    if (!VV.pan.moved) { if (vEl.paused) vEl.play().catch(() => {}); else vEl.pause(); }   // касание — пауза/пуск
    VV.pan = null;
  }
}, { passive: true });
vEl.addEventListener('dblclick', (e) => { if (VV.s > 1.01) { e.preventDefault(); vzReset(); } });

// мышь / трекпад
stage.addEventListener('wheel', (e) => {
  if (!zoomActive()) return;
  e.preventDefault();
  const [fx, fy] = stagePoint(e.clientX, e.clientY);
  // колесо мыши — щелчками по ~100 (или строками); тачпад — мелкими шагами и со сдвигом вбок
  const mouseWheel = e.deltaMode === 1 || (Math.abs(e.deltaY) >= 40 && e.deltaX === 0);
  if (e.ctrlKey) {                                          // щипок трекпада / Ctrl+колесо
    zoomAt(VZ.s * Math.exp(-e.deltaY * 0.01), fx, fy, false);
  } else if (mouseWheel) {
    // колесо мыши: вверх — увеличить (к курсору); вниз — уменьшить, а без увеличения —
    // открыть «Подробнее»; вверх при открытой панели — закрыть её
    if (e.deltaY < 0) { if (INFO.open) closeInfo(); else zoomAt(VZ.s * 1.25, fx, fy, true); }
    else if (VZ.s > 1.02) zoomAt(VZ.s * 0.8, fx, fy, true);
    else openInfo();
  } else if (VZ.s > 1) {                                    // прокрутка тачпадом двигает увеличенную картинку
    VZ.tx -= e.deltaX; VZ.ty -= e.deltaY; clampPan(); applyZoom(false);
  } else {
    // тачпад без увеличения: прокрутка вниз — открыть «Подробнее», вверх — закрыть
    wheelInfo(e.deltaY);
  }
}, { passive: false });

// накапливаем мелкие шаги тачпада: один жест — одно действие
let wheelAcc = 0, wheelT = 0, wheelLock = 0;
function wheelInfo(dy) {
  if (Date.now() < wheelLock) return;
  clearTimeout(wheelT); wheelT = setTimeout(() => { wheelAcc = 0; }, 250);
  wheelAcc += dy;
  if (wheelAcc > 60 && !INFO.open) { openInfo(); wheelAcc = 0; wheelLock = Date.now() + 500; }
  else if (wheelAcc < -60 && INFO.open) { closeInfo(); wheelAcc = 0; wheelLock = Date.now() + 500; }
}
// на самой панели: прокрутка вверх, когда она уже в самом верху, — закрыть
$('v-info').addEventListener('wheel', (e) => {
  if (e.deltaY < 0 && $('v-info').scrollTop <= 0 && !e.target.closest('.map')) {
    e.preventDefault();
    if (e.deltaMode === 1 || Math.abs(e.deltaY) >= 40) { if (Date.now() >= wheelLock) { closeInfo(); wheelLock = Date.now() + 500; } }
    else wheelInfo(e.deltaY);
  }
}, { passive: false });
stage.addEventListener('pointerdown', (e) => {
  if (e.pointerType !== 'mouse' || VZ.s <= 1 || e.button !== 0) return;
  VZ.drag = { x: e.clientX, y: e.clientY, tx0: VZ.tx, ty0: VZ.ty };
  stage.setPointerCapture(e.pointerId); stage.classList.add('drag');
});
stage.addEventListener('pointermove', (e) => {
  if (!VZ.drag) return;
  VZ.tx = VZ.drag.tx0 + e.clientX - VZ.drag.x; VZ.ty = VZ.drag.ty0 + e.clientY - VZ.drag.y; clampPan(); applyZoom(false);
});
const endDrag = () => { VZ.drag = null; stage.classList.remove('drag'); };
stage.addEventListener('pointerup', endDrag); stage.addEventListener('pointercancel', endDrag);
// Safari: свои жесты зума страницы в просмотрщике не нужны
for (const ev of ['gesturestart', 'gesturechange']) document.addEventListener(ev, (e) => { if (!$('viewer').hidden) e.preventDefault(); }, { passive: false });
window.addEventListener('resize', () => { if (VZ.s > 1) { clampPan(); applyZoom(false); } });

document.addEventListener('keydown', (e) => {
  if ($('viewer').hidden) return;
  const cx = stage.clientWidth / 2, cy = stage.clientHeight / 2;
  if (e.key === 'Escape') { if (VZ.s > 1) resetZoom(true); else closeViewer(); }
  else if (e.key === 'ArrowLeft' && VZ.s === 1) show(V.i - 1);
  else if (e.key === 'ArrowRight' && VZ.s === 1) show(V.i + 1);
  else if (zoomKey(e) !== null && zoomActive()) {
    e.preventDefault();                          // Ctrl + / − / 0 — масштаб фото, а не страницы
    const k = zoomKey(e);
    if (k === 1) zoomAt(VZ.s * 1.5, cx, cy, true);
    else if (k === -1) zoomAt(VZ.s / 1.5, cx, cy, true);
    else resetZoom(true);
  }
});

document.addEventListener('visibilitychange', () => { if (!document.hidden && !$('main').hidden) poll(); });

enter().catch(() => showLogin());
