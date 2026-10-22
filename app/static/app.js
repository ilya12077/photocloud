'use strict';
// Photocloud UI. Данные с сервера попадают в DOM только через textContent / атрибуты —
// никакого innerHTML с данными.

const $ = (id) => document.getElementById(id);
const MONTHS = ['Январь','Февраль','Март','Апрель','Май','Июнь','Июль','Август','Сентябрь','Октябрь','Ноябрь','Декабрь'];
const MONTHS_SHORT = ['янв','фев','мар','апр','май','июн','июл','авг','сен','окт','ноя','дек'];
const HEAD_H = 46;          // высота заголовка месяца, px
const BUFFER = 1.2;         // сколько экранов рендерим сверху/снизу
const F_VIDEO = 1, F_TAKEN = 2, F_NAME = 4, F_NOPLAY = 8, F_LIVE = 16, F_FOLDER = 32;

const st = {
  me: null,
  lib: null,          // {v, folders, photos:[[id, fidx, name, date, mtime, sizeKB, flags]]}
  children: null, totals: null, cover: null, folderIdx: null, parent: null,
  folder: '', sort: 'new', rec: true,
  list: [],           // текущий отсортированный список
  pc: 'unknown', pollTimer: 0, newVersion: null,
};
const Z = { cols: 3, pinch: null, wheel: 0, sizes: { s: 240, t: 400, m: 900 } };
const L = { rows: [], height: 0, tileH: 0, gap: 3, rendered: new Map(), lastY: 0, idleT: 0, fast: false };

function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (_) { return null; } }
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

async function api(path, opts = {}) {
  const init = { credentials: 'same-origin', cache: opts.cache || 'no-store', headers: {} };
  if (opts.timeout && window.AbortSignal && AbortSignal.timeout) init.signal = AbortSignal.timeout(opts.timeout);
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
  'locked': 'Слишком много попыток входа, подожди 15 минут',
};

async function showLogin(msg) {
  stopPoll(); closeViewer(true);
  $('main').hidden = true; $('login').hidden = false;
  $('lerr').textContent = msg || '';
  try { const r = await fetch('/api/auth/providers', { cache: 'no-store' }); const p = await r.json(); $('lgoogle').hidden = !p.google; } catch (_) {}
  setTimeout(() => $('lu').focus(), 0);
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('lbtn'); btn.disabled = true; $('lerr').textContent = '';
  try {
    const r = await api('/api/login', { method: 'POST', body: { u: $('lu').value.trim(), p: $('lp').value }, allow401: true });
    if (r.ok) { $('lp').value = ''; await enter(); return; }
    if (r.status === 429) {
      const j = await r.json().catch(() => ({}));
      $('lerr').textContent = `Слишком много попыток. Подожди ${Math.ceil((j.retry || 900) / 60)} мин.`;
    } else if (r.status === 401) $('lerr').textContent = 'Неверный логин или пароль';
    else $('lerr').textContent = 'Ошибка входа (' + r.status + ')';
  } catch (_) { $('lerr').textContent = 'Сервер недоступен'; }
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
  st.libPromise = fetch('/api/library', { credentials: 'same-origin', cache: 'no-cache' }).catch(() => null);
  const r = await api('/api/me', { allow401: true });
  if (r.status === 401) { st.libPromise = null; showLogin(err); return; }
  const me = await r.json(); st.me = me;
  if (me.name) { $('title').textContent = me.name; document.title = me.name; }
  if (me.sizes) Z.sizes = me.sizes;
  $('admin-link').hidden = me.role !== 'admin';
  $('login').hidden = true; $('main').hidden = false;
  readRoute(); initZoom();
  try { localStorage.removeItem('pc.eco'); } catch (_) {}
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
  if (btnText) { btn.hidden = false; btn.textContent = btnText; btn.onclick = onClick; } else btn.hidden = true;
}

async function wake() {
  banner('Отправляю команду включения…');
  try {
    const r = await api('/api/wake', { method: 'POST' });
    if (!r.ok) banner('Home Assistant не ответил на команду включения', 'Повторить', wake, true);
  } catch (_) {}
  poll(1500);
}

async function poll(delay) {
  stopPoll();
  if (delay) { st.pollTimer = setTimeout(() => poll(), delay); return; }
  let s;
  try { s = await (await api('/api/status', { timeout: 15000 })).json(); }
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
    banner((s.wake_failed ? 'Компьютер так и не включился' : 'Компьютер выключен') +
      (ix.count ? ' — показываю последний список, новые превью не загрузятся' : ''),
      s.wake_failed ? 'Попробовать ещё раз' : 'Запустить компьютер', wake, true);
    next = 10000;
  } else if (s.pc === 'waking') {
    banner(`Компьютер просыпается… (ещё до ${s.wake_left} с)`); next = 2000;
  } else if (ix.state === 'building') {
    banner(ix.count ? `Обновляю список… (${ix.progress})` : `Сканирую папки… найдено ${ix.progress}`); next = 1500;
  } else if (ix.state === 'error') {
    banner('Не удалось прочитать папку на компьютере (проверь доступ)', 'Повторить', reindex, true); next = 15000;
  } else if (metaBusy) {
    banner(`Читаю даты съёмки: ${ix.meta[0].toLocaleString('ru')} из ${ix.meta[1].toLocaleString('ru')}`); next = 3000;
  } else if (st.newVersion && st.lib) {
    banner('Список файлов обновился', 'Показать', () => { st.newVersion = null; loadLibrary(); });
  } else banner(null);

  if (ix.v && !st.lib && !st.libPromise) await loadLibrary();
  else if (ix.v && st.lib && ix.v !== st.lib.v && ix.state !== 'building') {
    // молча обновляем, только если пользователь ещё не начал листать
    if (window.scrollY < 50 && $('viewer').hidden) await loadLibrary();
    else if (!st.newVersion) { st.newVersion = ix.v; next = 100; }
  }
  if (prevPc !== 'up' && s.pc === 'up') retryBroken();
  if (!st.lib && ix.state !== 'error' && s.pc === 'up') next = Math.min(next, 1500);
  st.pollTimer = setTimeout(() => poll(), next);
}

async function reindex() {
  hideMenu();
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
  return { v: j.v, folders: j.folders, photos: out, live: j.live || {} };
}

async function loadLibrary(pre) {
  if (st.libLoading) return;
  st.libLoading = true;
  try { await loadLibraryInner(pre); } finally { st.libLoading = false; }
}
async function loadLibraryInner(pre) {
  if (!st.lib) banner('Загружаю список файлов…');
  // cache:'no-cache' — браузер хранит копию и спрашивает сервер по ETag (304 = 0 байт)
  const r = pre || await api('/api/library', { cache: 'no-cache' });
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
// экономия трафика всегда: на весь экран — 1280; 2048 и оригинал — только при увеличении
const previewKind = () => 'e';

// ================================================================== отрисовка: шапка, папки

function render() {
  const lib = st.lib; if (!lib) return;
  const fi = st.folderIdx.get(st.folder) ?? 0;

  const crumbs = [el('a', null, 'Все фото')]; crumbs[0].href = '#/';
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
  for (const c of st.children[fi]) {
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
  st.list = list;

  const videos = list.reduce((n, p) => n + (p[6] & F_VIDEO ? 1 : 0), 0);
  $('summary').textContent = list.length ? count(list.length) + (videos ? `, из них видео: ${videos.toLocaleString('ru')}` : '') + (st.rec && st.children[fi].length ? ' — с подпапками' : '') : '';
  $('empty').hidden = list.length > 0 || st.children[fi].length > 0;
  $('empty').textContent = 'Здесь пусто';

  relayout(false);
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
  const rowH = L.tileH + L.gap;
  const rows = []; let y = 0;
  const byMonth = st.sort !== 'name';
  const list = st.list;
  let i = 0;
  while (i < list.length) {
    let end = list.length, month = -1;
    if (byMonth) {
      month = monthKey(list[i][3]);
      end = i + 1;
      while (end < list.length && monthKey(list[end][3]) === month) end++;
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

function draw(force) {
  if ($('main').hidden || !st.lib) return;
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
    h.style.transform = `translateY(${r.top}px)`;
    return h;
  }
  const row = el('div', 'trow');
  row.style.transform = `translateY(${r.top}px)`; row.style.height = L.tileH + 'px'; row.style.gap = L.gap + 'px';
  const kind = thumbKind();
  for (let i = r.start; i < r.end; i++) {
    const ph = st.list[i];
    const b = el('button', 'tile'); b.type = 'button'; b.dataset.i = i; b.title = ph[2];
    const img = el('img'); img.alt = ''; img.decoding = 'async'; img.dataset.src = imgUrl(kind, ph);
    img.onload = () => { img.classList.add('ok'); img.dataset.loaded = '1'; b.classList.remove('broken'); };
    img.onerror = () => { if (img.getAttribute('src')) thumbFailed(img); };
    b.append(img);
    if (ph[6] & F_VIDEO) b.append(el('span', 'vbadge', '▶'));
    else if (ph[6] & F_LIVE) b.append(el('span', 'lbadge'));
    row.append(b);
  }
  return row;
}

function loadVisible(withBuffer) {
  if (L.fast) return;
  // во время прокрутки запрашиваем только то, что на экране; запас сверху/снизу — когда
  // прокрутка замрёт на 200 мс. Иначе сервер тратит время на то, мимо чего уже пролистали.
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
window.addEventListener('scroll', () => {
  if (rafPending) return; rafPending = true;
  requestAnimationFrame(() => { rafPending = false; draw(false); updateScrub(); });
}, { passive: true });

$('grid').addEventListener('click', (e) => { const t = e.target.closest('.tile'); if (t) openViewer(+t.dataset.i); });

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
document.addEventListener('keydown', (e) => {
  if (!gridActive() || e.ctrlKey || e.metaKey || e.altKey || /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) return;
  if (e.key === '+' || e.key === '=') setCols(Z.cols - 1, innerWidth / 2, innerHeight / 2);
  else if (e.key === '-') setCols(Z.cols + 1, innerWidth / 2, innerHeight / 2);
});
// На телефоне при прокрутке браузер прячет/показывает адресную строку — высота окна
// меняется, но сетка от высоты не зависит. Перестраиваем её только при смене ширины
// (поворот, окно на компе), иначе плитки пересоздавались бы и мигали.
// ширина макета, а не видимой области: щипок-увеличение в браузере её не меняет
const layoutW = () => document.documentElement.clientWidth;
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
  // недогруженные эскизы под просмотрщиком не нужны — отменяем, весь канал отдаём фото
  for (const [, node] of L.rendered) cancelImgs(node);
  history.pushState({ viewer: 1 }, ''); V.pushed = true;
  show(i);
}

function stopVideo() {
  $('v-note').hidden = true; $('v-origwrap').hidden = true;
  if (V.hls) { V.hls.destroy(); V.hls = null; }
  const v = $('v-video'); v.pause(); v.removeAttribute('src'); v.removeAttribute('poster'); v.load(); v.hidden = true;
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
  if (v.canPlayType('application/vnd.apple.mpegurl')) { v.src = url; return; }
  try {
    const Hls = await loadHls();
    if (tok !== V.token) return;
    if (!Hls || !Hls.isSupported()) { v.src = origUrl(ph, false); return; }
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
  const fromMeta = ph[6] & F_TAKEN, fromName = ph[6] & F_NAME;
  let meta = (ph[6] & F_FOLDER)
    ? `${new Date(ph[3] * 1000).getFullYear()} год (по названию папки) · ${sizeStr(ph[5])}`
    : (fromMeta ? 'Снято ' : fromName ? 'Снято (по имени файла) ' : 'Изменён ') + fmt.format(new Date(ph[3] * 1000)) + ' · ' + sizeStr(ph[5]);
  if (ph[6] & F_FOLDER) meta += ' · файл изменён ' + fmt.format(new Date(ph[4] * 1000));
  if ((fromMeta || fromName) && Math.abs(ph[4] - ph[3]) > 86400) meta += ' · файл изменён ' + fmt.format(new Date(ph[4] * 1000));
  $('v-date').textContent = meta;
  $('v-orig').href = origUrl(ph, false);
  $('v-dl').href = origUrl(ph, true); $('v-dl').setAttribute('download', ph[2]);
  const low = $('v-low'), hi = $('v-img');
  stopVideo();
  resetZoom(false); VZ.shown = 0; VZ.want = ''; VZ.tap = null;
  cancelLoads();
  const liveVid = setupLive(ph);
  $('v-note').hidden = !(ph[6] & F_NOPLAY);
  hi.classList.remove('ok'); hi.removeAttribute('src');
  low.style.visibility = ''; low.src = imgUrl(thumbKind(), ph);     // уже в кэше браузера — мгновенно
  if (isVideo) {
    const v = $('v-video'); v.hidden = false; v.poster = imgUrl('m', ph);
    low.style.visibility = 'hidden'; $('v-spin').hidden = true;
    playVideo(ph, tok, 0);
  } else {
    // Загрузка по ступеням, строго по очереди (на медленном канале параллельные
    // загрузки только мешают друг другу):
    //   1) быстрая сильно сжатая версия (~20–40 КБ) — фото видно почти сразу;
    //   2) у живого фото — ролик (он и так закрывает фото, пока играет);
    //   3) полная версия: 1280 при экономии, 2048 без неё; сервер готовит её
    //      заранее вместе с быстрой, из того же декода;
    //   4) соседние фото (быстрые версии, без экономии — и полная следующего).
    // При увеличении — версия подробнее / оригинал (upgradeQuality).
    $('v-spin').hidden = false;
    const full = previewKind();
    loadStep(ph, tok, 'q', `&n=${full}`).then(() => {
      if (tok !== V.token) return;
      const rest = () => loadStep(ph, tok, full, '').then(() => { if (tok === V.token) prefetchNear(i, tok); });
      if (liveVid) playLive(liveVid, tok, rest); else rest();
    });
  }
  $('v-prev').disabled = i === 0; $('v-next').disabled = i === st.list.length - 1;
}

const RANK = { q: 1, e: 2, p: 3, o: 4 };

function cancelLoads() {
  // фото пролистали — его недогруженные версии и предзагрузка больше не нужны
  for (const im of V.loads) im.removeAttribute('src');
  V.loads = [];
  if (V.ctl) { V.ctl.abort(); V.ctl = null; }
}

// одна ступень: грузим версию kind и показываем, если она подробнее уже показанной
function loadStep(ph, tok, kind, extra) {
  return new Promise((resolve) => {
    if (tok !== V.token) { resolve(false); return; }
    const pre = new Image(); pre.fetchPriority = 'high'; pre.decoding = 'async';
    V.loads.push(pre);
    const url = (kind === 'o' ? origUrl(ph, false) : imgUrl(kind, ph)) + extra;
    pre.onload = () => {
      if (tok === V.token && RANK[kind] > VZ.shown) {
        const hi = $('v-img');
        hi.src = url; hi.classList.add('ok'); VZ.shown = RANK[kind];
        if (kind === 'o') $('v-name').textContent = 'Без сжатия • ' + ph[2];
        $('v-spin').hidden = true;
        setTimeout(() => { if (tok === V.token) $('v-low').style.visibility = 'hidden'; }, 200);
      }
      resolve(true);
    };
    pre.onerror = () => { if (tok === V.token && kind !== 'q') $('v-spin').hidden = true; resolve(false); };
    pre.src = url;
  });
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
    } catch (_) { return; }
  }
}

// ---- живые фото
function stopLive() {
  const lv = $('v-live'); lv.classList.remove('on'); lv.pause(); lv.removeAttribute('src'); lv.load();
}
function setupLive(ph) {
  // -> id ролика, если его надо проиграть (сам запуск — после быстрой версии фото)
  stopLive();
  const vid = (ph[6] & F_LIVE) && st.lib.live[ph[0]];
  $('v-livewrap').hidden = !vid;
  if (!vid) return null;
  $('v-livechk').checked = store('pc.live') === '1';
  return $('v-livechk').checked ? vid : null;
}
function playLive(vid, tok, after) {
  // after — что грузить следом (полное фото): когда ролик загрузился, не смог или 5 с прошло
  const lv = $('v-live');
  let done = false;
  const next = () => { if (done) return; done = true; if (after && tok === V.token) after(); };
  setTimeout(next, 5000);
  lv.oncanplaythrough = next;
  lv.onended = () => lv.classList.remove('on');             // доиграл — снова фото
  lv.muted = false;
  lv.oncanplay = () => {
    if (tok !== V.token) return;
    lv.play().then(() => lv.classList.add('on')).catch(() => {
      // браузер не дал играть со звуком без нажатия — играем без звука
      lv.muted = true;
      lv.play().then(() => lv.classList.add('on')).catch(() => {});
    });
  };
  lv.onerror = () => { lv.classList.remove('on'); next(); };
  lv.src = `/vid/${encodeURIComponent(vid)}/live.mp4?q=eco`;
  lv.load();
}
// если браузер не разрешил звук без нажатия — первое касание фото включает звук и переигрывает
$('v-stage').addEventListener('pointerup', () => {
  const lv = $('v-live');
  if (lv.muted && lv.getAttribute('src') && !$('v-livewrap').hidden) {
    lv.muted = false; lv.currentTime = 0; lv.play().then(() => lv.classList.add('on')).catch(() => { lv.muted = true; });
  }
});
$('v-livechk').addEventListener('change', (e) => {
  store('pc.live', e.target.checked ? '1' : '0');
  const ph = st.list[V.i]; const vid = ph && st.lib.live[ph[0]];
  if (!vid) return;
  if (e.target.checked) { stopLive(); playLive(vid, V.token); } else stopLive();
});

function closeViewer(silent) {
  if ($('viewer').hidden) return;
  stopVideo(); stopLive(); resetZoom(false); cancelLoads();
  $('viewer').hidden = true; document.body.style.overflow = '';
  $('v-img').removeAttribute('src'); $('v-low').removeAttribute('src'); V.token++;
  if (V.pushed && !silent) { V.pushed = false; history.back(); }
  V.pushed = false;
  // если пролистали далеко — возвращаем сетку к последнему просмотренному
  const t = document.querySelector(`.tile[data-i="${V.i}"]`);
  const r = t && t.getBoundingClientRect();
  if (!r || r.bottom < 0 || r.top > window.innerHeight) { scrollToIndex(V.i, -window.innerHeight / 3); draw(true); }
  loadVisible(true);      // догружаем эскизы, отменённые при открытии
  if (layoutW() !== lastW) { lastW = layoutW(); initZoom(); relayout(true); }   // повернули телефон в просмотре
}

window.addEventListener('popstate', () => { if (!$('viewer').hidden) { V.pushed = false; closeViewer(true); } });
$('v-close').addEventListener('click', () => closeViewer());
$('v-prev').addEventListener('click', () => show(V.i - 1));
$('v-next').addEventListener('click', () => show(V.i + 1));
// ================================================================== масштаб в просмотре
// Щипок / растяжение, двойной тап или двойной клик, Ctrl+колесо (жест трекпада), перетаскивание.
// Свайпы влево/вправо/вниз работают только при обычном масштабе.

const VZ = { s: 1, tx: 0, ty: 0, pinch: null, pan: null, tap: null, moved: false, shown: 0, want: '' };
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

function toggleZoom(cx, cy) {
  const [fx, fy] = stagePoint(cx, cy);
  if (VZ.s > 1) resetZoom(true); else zoomAt(2.5, fx, fy, true);
  upgradeQuality();
}

// при сильном увеличении подгружаем картинку подробнее
function upgradeQuality() {
  const ph = st.list[V.i]; if (!ph || VZ.s < 1.6) return;
  const ext = ph[2].slice(ph[2].lastIndexOf('.')).toLowerCase();
  const browserCan = ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext);
  const have = Math.max(VZ.shown, RANK[VZ.want] || 0);
  let want = have < RANK.p ? 'p' : '';
  if (VZ.s >= 2.5 && browserCan && ph[5] < 25 * 1024) want = 'o';   // оригинал до 25 МБ
  if (!want || RANK[want] <= have) return;
  VZ.want = want;                                // помечаем сразу, чтобы не запрашивать повторно
  loadStep(ph, V.token, want, '');
}

const tdist = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
const tmid = (t) => stagePoint((t[0].clientX + t[1].clientX) / 2, (t[0].clientY + t[1].clientY) / 2);

stage.addEventListener('touchstart', (e) => {
  VZ.lastTouch = Date.now();
  if (e.target.tagName === 'VIDEO') return;
  if (e.touches.length === 2 && zoomActive()) {
    const [mx, my] = tmid(e.touches);
    VZ.pinch = { d0: tdist(e.touches) || 1, s0: VZ.s, mx, my, tx0: VZ.tx, ty0: VZ.ty };
    VZ.pan = null; VZ.moved = true;
  } else if (e.touches.length === 1) {
    const t = e.touches[0];
    VZ.pan = { x: t.clientX, y: t.clientY, tx0: VZ.tx, ty0: VZ.ty, t: Date.now() };
    VZ.moved = false;
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
  }
}, { passive: false });

stage.addEventListener('touchend', (e) => {
  if (e.target.tagName === 'VIDEO') return;
  if (VZ.pinch) {
    if (e.touches.length < 2) {
      VZ.pinch = null;
      if (VZ.s < 1.05) resetZoom(true); else { clampPan(); applyZoom(true); upgradeQuality(); }
      // оставшийся палец продолжает двигать картинку, а не листать
      if (e.touches.length === 1) { const t = e.touches[0]; VZ.pan = { x: t.clientX, y: t.clientY, tx0: VZ.tx, ty0: VZ.ty, t: Date.now() }; VZ.moved = true; }
    }
    return;
  }
  if (!VZ.pan || e.touches.length) return;
  const t = e.changedTouches[0], dx = t.clientX - VZ.pan.x, dy = t.clientY - VZ.pan.y;
  const quick = Date.now() - VZ.pan.t < 300;
  VZ.pan = null;
  if (!VZ.moved && quick && zoomActive()) {
    // двойной тап: второе касание рядом с первым в течение 300 мс
    const now = Date.now();
    if (VZ.tap && now - VZ.tap.t < 300 && Math.hypot(t.clientX - VZ.tap.x, t.clientY - VZ.tap.y) < 40) {
      VZ.tap = null; toggleZoom(t.clientX, t.clientY); return;
    }
    VZ.tap = { t: now, x: t.clientX, y: t.clientY };
    return;
  }
  if (VZ.s > 1) return;                                     // при увеличении свайпы не листают
  if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) show(V.i + (dx < 0 ? 1 : -1));
  else if (dy > 90 && Math.abs(dy) > Math.abs(dx) * 1.5) closeViewer();
}, { passive: true });

// мышь / трекпад
stage.addEventListener('dblclick', (e) => {
  // на тач-экранах браузер сам шлёт dblclick после двойного тапа — его уже обработали выше
  if (Date.now() - (VZ.lastTouch || 0) < 1000) return;
  if (zoomActive() && e.target.tagName !== 'VIDEO') toggleZoom(e.clientX, e.clientY);
});
stage.addEventListener('wheel', (e) => {
  if (!zoomActive()) return;
  e.preventDefault();
  const [fx, fy] = stagePoint(e.clientX, e.clientY);
  if (e.ctrlKey) {                                          // щипок трекпада / Ctrl+колесо
    zoomAt(VZ.s * Math.exp(-e.deltaY * 0.01), fx, fy, false);
    clearTimeout(VZ.wt); VZ.wt = setTimeout(upgradeQuality, 200);
  } else if (VZ.s > 1) {                                    // прокрутка двигает увеличенную картинку
    VZ.tx -= e.deltaX; VZ.ty -= e.deltaY; clampPan(); applyZoom(false);
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
  else if ((e.key === '+' || e.key === '=') && zoomActive()) { zoomAt(VZ.s * 1.5, cx, cy, true); upgradeQuality(); }
  else if (e.key === '-' && zoomActive()) zoomAt(VZ.s / 1.5, cx, cy, true);
  else if (e.key === '0' && zoomActive()) resetZoom(true);
});

document.addEventListener('visibilitychange', () => { if (!document.hidden && !$('main').hidden) poll(); });

enter().catch(() => showLogin());
