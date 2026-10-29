(function () {
  'use strict';

  /* =====================================================================
     공통 도구
     ===================================================================== */

  /* ---------- 토큰 보관 (localStorage) ---------- */
  const TOKEN_KEY = 'shop_token';

  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
  }
  function setToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
  }
  function clearToken() {
    try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* 무시 */ }
  }
  function go(url) {
    window.location.href = url;
  }

  /* ---------- API 호출: 토큰이 있으면 헤더에 자동으로 붙인다 ---------- */
  async function api(path, options) {
    options = options || {};
    const headers = {};
    const init = { method: options.method || 'GET', headers: headers };
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    const token = getToken();
    if (token) { headers['Authorization'] = 'Bearer ' + token; }

    const res = await fetch(path, init);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }

    if (!res.ok) {
      const err = new Error((data && data.detail) || '요청에 실패했습니다 (' + res.status + ')');
      err.status = res.status;
      throw err;
    }
    return data;
  }

  /* ---------- 화면 그리기 도구 ----------
     서버에서 받은 값은 전부 textContent 로만 넣는다 (innerHTML 금지).
     그래야 상품 이름 등에 악성 스크립트가 섞여 있어도 실행되지 않는다. */
  function el(tag, props, children) {
    const node = document.createElement(tag);
    Object.keys(props || {}).forEach(function (k) {
      if (k === 'text') { node.textContent = props[k]; } else { node.setAttribute(k, props[k]); }
    });
    (children || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) { return; }
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }
  function byId(id) {
    return document.getElementById(id);
  }
  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }
  function won(n) {
    return Number(n).toLocaleString('ko-KR') + '원';
  }
  function showMsg(node, text, kind) {
    node.textContent = text || '';
    node.className = 'msg' + (kind ? ' ' + kind : '');
  }
  function isDigits(v) {
    return /^[0-9]+$/.test(v || '');
  }
  function query() {
    return new URLSearchParams(window.location.search);
  }
  function pick(map, key) {
    return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
  }
  /* "2026-10-23 14:18:11" → "2026.10.23" / "2026.10.23 14:18" */
  function fmtDate(s) {
    return String(s || '').slice(0, 10).replace(/-/g, '.');
  }
  function fmtDateTime(s) {
    return fmtDate(s) + ' ' + String(s || '').slice(11, 16);
  }

  /* 401 이면 토큰을 지우고 로그인 화면으로 보낸다. 처리했으면 true */
  function handleAuthError(err, msgNode) {
    if (err.status === 401) {
      clearToken();
      go('/login.php?expired=1');
      return true;
    }
    showMsg(msgNode, err.message, 'error');
    return false;
  }
  function requireLogin() {
    if (!getToken()) { go('/login.php'); return false; }
    return true;
  }

  /* ---------- 아이콘 (선으로 그린 SVG, 외부 파일 없음) ---------- */
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const ICONS = {
    x: [['path', { d: 'M6 6 L18 18' }], ['path', { d: 'M18 6 L6 18' }]],
    check: [['path', { d: 'M5 12 L10 17 L19 7' }]],
    chevronRight: [['path', { d: 'M9 6 L15 12 L9 18' }]],
    truck: [['path', { d: 'M3 7 H14 V16 H3 Z' }], ['path', { d: 'M14 10 H18 L21 13 V16 H14' }],
            ['circle', { cx: '7', cy: '18', r: '1.6' }], ['circle', { cx: '17', cy: '18', r: '1.6' }]],
    home: [['path', { d: 'M4 10 L12 4 L20 10 V20 H4 Z' }], ['path', { d: 'M10 20 V14 H14 V20' }]],
    lock: [['rect', { x: '5', y: '11', width: '14', height: '10', rx: '2' }], ['path', { d: 'M8 11 V8 A4 4 0 0 1 16 8 V11' }]],
    alert: [['circle', { cx: '12', cy: '12', r: '9' }], ['path', { d: 'M12 7.5 V13' }], ['path', { d: 'M12 16.5 V16.6' }]],
    box: [['path', { d: 'M4 8 L12 4 L20 8 V16 L12 20 L4 16 Z' }], ['path', { d: 'M4 8 L12 12 L20 8' }], ['path', { d: 'M12 12 V20' }]],
    cart: [['path', { d: 'M3 4 H6 L8 15 H18 L20 7 H7' }], ['circle', { cx: '9', cy: '19', r: '1.5' }], ['circle', { cx: '17', cy: '19', r: '1.5' }]],
    cloth: [['path', { d: 'M8.5 4 L4 6.5 L5.5 10 L7.5 9.2 L7.5 20 L16.5 20 L16.5 9.2 L18.5 10 L20 6.5 L15.5 4 C14.8 5.8 9.2 5.8 8.5 4 Z' }]],
    tech: [['path', { d: 'M4 15 V12 A8 8 0 0 1 20 12 V15' }], ['rect', { x: '3', y: '14', width: '4', height: '6', rx: '1.5' }],
           ['rect', { x: '17', y: '14', width: '4', height: '6', rx: '1.5' }]],
    living: [['path', { d: 'M7 4 H17 L16 20 H8 Z' }], ['path', { d: 'M7.3 8 H16.7' }]],
    food: [['ellipse', { cx: '12', cy: '12', rx: '6', ry: '8' }], ['path', { d: 'M12 4 C9 9 15 15 12 20' }]],
    book: [['path', { d: 'M5 5 A2 2 0 0 1 7 3 H19 V17 H7 A2 2 0 0 0 5 19 Z' }], ['path', { d: 'M5 19 A2 2 0 0 0 7 21 H19 V17' }]]
  };

  function icon(name, size, strokeWidth) {
    const s = document.createElementNS(SVG_NS, 'svg');
    const attrs = {
      viewBox: '0 0 24 24', width: String(size), height: String(size), fill: 'none', stroke: 'currentColor',
      'stroke-width': String(strokeWidth || 2), 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true'
    };
    Object.keys(attrs).forEach(function (k) { s.setAttribute(k, attrs[k]); });
    (ICONS[name] || []).forEach(function (part) {
      const n = document.createElementNS(SVG_NS, part[0]);
      Object.keys(part[1]).forEach(function (k) { n.setAttribute(k, part[1][k]); });
      s.appendChild(n);
    });
    return s;
  }

  /* ---------- 상품 이미지 ----------
     서버에 사진 파일이 없으므로 분류별 색과 선 아이콘으로 이미지를 그린다.
     외부 주소로 나가는 요청이 없고 저작권 문제도 없다. */
  const CATEGORIES = ['의류', '전자기기', '생활용품', '식품', '도서'];
  /* 색감 B-2: 배경은 회색 하나, 분류는 아이콘 색으로만 구분한다 */
  const THUMB_BG = '#f5f6f8';
  const CATEGORY_STYLE = {
    '의류':     { tint: THUMB_BG, fg: '#be185d', icon: 'cloth' },
    '전자기기': { tint: THUMB_BG, fg: '#4338ca', icon: 'tech' },
    '생활용품': { tint: THUMB_BG, fg: '#0f766e', icon: 'living' },
    '식품':     { tint: THUMB_BG, fg: '#c2410c', icon: 'food' },
    '도서':     { tint: THUMB_BG, fg: '#6d28d9', icon: 'book' }
  };
  const DEFAULT_STYLE = { tint: THUMB_BG, fg: '#6b7280', icon: 'box' };

  function badgeOf(name) {
    const s = String(name);
    if (s.endsWith(' 프리미엄')) { return '프리미엄'; }
    if (s.endsWith(' 한정판')) { return '한정판'; }
    return '';
  }

  /* sizeClass: '' (목록 카드), 'thumb-lg' (상품 상세), 'thumb-sm' (장바구니),
                'thumb-md' (내 주문 카드), 'thumb-xs' (주문 상세의 상품 줄) */
  const ICON_SIZE = { '': 72, 'thumb-lg': 160, 'thumb-sm': 44, 'thumb-md': 36, 'thumb-xs': 30 };
  function thumbnail(p, sizeClass) {
    const st = pick(CATEGORY_STYLE, p.category) || DEFAULT_STYLE;
    const soldout = typeof p.stock === 'number' && p.stock < 1;
    const box = el('div', { class: 'thumb' + (sizeClass ? ' ' + sizeClass : '') + (soldout ? ' soldout' : '') });
    box.style.background = st.tint;
    box.style.color = st.fg;
    box.appendChild(icon(st.icon, pick(ICON_SIZE, sizeClass || '') || 72, 1.4));
    // 작은 썸네일에는 프리미엄·한정판 글자를 넣지 않는다 (공간 부족)
    const badge = (sizeClass === '' || sizeClass === 'thumb-lg') ? badgeOf(p.name) : '';
    if (badge) { box.appendChild(el('span', { class: 'badge', text: badge })); }
    return box;
  }

  function stockNode(p) {
    if (p.stock < 1) { return el('span', { class: 'stock out', text: '품절' }); }
    if (p.stock <= 10) { return el('span', { class: 'stock low', text: '재고 ' + p.stock + '개 남음' }); }
    return null;
  }

  function productCard(p) {
    return el('a', { class: 'pcard', href: '/product.php?id=' + encodeURIComponent(String(p.id)) }, [
      thumbnail(p, ''),
      el('div', { class: 'pbody' }, [
        el('span', { class: 'pcat', text: p.category || '-' }),
        el('span', { class: 'pname', text: p.name }),
        el('div', { class: 'prow' }, [el('span', { class: 'pprice', text: won(p.price) }), stockNode(p)])
      ])
    ]);
  }

  /* ---------- 수량 − / + ---------- */
  function qtyStepper(value, onChange) {
    const minus = el('button', { type: 'button', 'aria-label': '수량 줄이기', text: '−' });
    const plus = el('button', { type: 'button', 'aria-label': '수량 늘리기', text: '+' });
    const shown = el('span', { text: String(value), 'aria-live': 'polite' });
    minus.disabled = value <= 1;
    plus.disabled = value >= 99;
    minus.addEventListener('click', function () { onChange(value - 1, [minus, plus]); });
    plus.addEventListener('click', function () { onChange(value + 1, [minus, plus]); });
    return el('div', { class: 'qty' }, [minus, shown, plus]);
  }

  /* ---------- 주문 상태 ---------- */
  const STATUS_CLASS = { '결제완료': 's-paid', '배송중': 's-ship', '배송완료': 's-done', '취소': 's-cancel' };
  const STEPS = [
    { label: '결제완료', icon: 'check' },
    { label: '배송중', icon: 'truck' },
    { label: '배송완료', icon: 'home' }
  ];

  function statusBadge(status, big) {
    return el('span', {
      class: 'status-badge ' + (pick(STATUS_CLASS, status) || 's-cancel') + (big ? ' big' : ''),
      text: String(status)
    });
  }

  /* 결제완료 → 배송중 → 배송완료. 취소면 단계 대신 안내 문구 */
  function stepper(status, big, orderDate) {
    if (status === '취소') {
      return el('p', { class: 'stepper-cancel', text: '주문이 취소되었어요.' });
    }
    let reached = STEPS.findIndex(function (s) { return s.label === status; });
    if (reached < 0) { reached = 0; }
    const box = el('div', { class: 'stepper' + (big ? ' big' : ''), role: 'list', 'aria-label': '주문 진행 단계' });
    STEPS.forEach(function (s, i) {
      const done = i <= reached;
      const dot = el('span', { class: 'dot' }, [big ? icon(done ? 'check' : s.icon, 18, done ? 2.6 : 2) : null]);
      const sub = big ? el('span', { class: 'sub', text: i === 0 ? fmtDateTime(orderDate).slice(5) : (done ? '완료' : '대기') }) : null;
      box.appendChild(el('div', {
        class: 'step' + (done ? ' done' : '') + (i === reached ? ' current' : ''),
        role: 'listitem',
        'aria-current': i === reached ? 'step' : 'false'
      }, [dot, el('span', { class: 'label', text: s.label }), sub]));
    });
    return box;
  }

  /* ---------- 메뉴 + 장바구니 배지 ---------- */
  const NAV_ACTIVE = { products: 'products', product: 'products', cart: 'cart', orders: 'orders', order: 'orders', me: 'me' };
  let cartBadge = null;

  function setCartBadge(n) {
    if (!cartBadge) { return; }
    cartBadge.textContent = String(n);
    cartBadge.hidden = n === 0;
  }
  async function refreshCartBadge() {
    try {
      const c = await api('/api/v2/cart');
      setCartBadge(c.items.length);
    } catch (e) { /* 배지는 보조 정보라 실패해도 무시 */ }
  }

  function renderNav() {
    const nav = byId('nav');
    if (!nav) { return; }
    clear(nav);
    const page = document.body.getAttribute('data-page');
    const active = pick(NAV_ACTIVE, page);

    function link(key, href, text, extra) {
      const a = el('a', { href: href }, [text, extra || null]);
      if (key === active) {
        a.className = 'active';
        a.setAttribute('aria-current', 'page');
      }
      nav.appendChild(a);
    }

    link('products', '/products.php', '상품');
    if (getToken()) {
      cartBadge = el('span', { class: 'nav-badge', 'aria-label': '담긴 상품 종류 수' });
      cartBadge.hidden = true;
      link('cart', '/cart.php', '장바구니', cartBadge);
      link('orders', '/orders.php', '내 주문');
      link('me', '/me.php', '내 정보');
      const out = el('button', { type: 'button', class: 'logout', text: '로그아웃' });
      out.addEventListener('click', function () { clearToken(); go('/login.php'); });
      nav.appendChild(out);
      if (page !== 'cart') { refreshCartBadge(); }   // 장바구니 화면은 자기가 그리면서 배지를 맞춘다
    } else {
      link('login', '/login.php', '로그인');
      link('signup', '/signup.php', '회원가입');
    }
  }

  function renderPager(container, state, count, reload) {
    clear(container);
    // 첫 페이지에 다 들어오면 이전·다음 버튼이 필요 없다
    if (state.offset === 0 && count < state.limit) { return; }
    const prev = el('button', { type: 'button', text: '이전' });
    const next = el('button', { type: 'button', text: '다음' });
    prev.disabled = state.offset === 0;
    next.disabled = count < state.limit;
    prev.addEventListener('click', function () {
      state.offset = Math.max(0, state.offset - state.limit);
      reload();
    });
    next.addEventListener('click', function () {
      state.offset += state.limit;
      reload();
    });
    const label = count === 0 ? '결과 없음' : (state.offset + 1) + '–' + (state.offset + count) + '번째';
    container.appendChild(prev);
    container.appendChild(el('span', { text: label }));
    container.appendChild(next);
  }

  /* 전화번호 앞자리: 서버 UserValidator::PHONE_PREFIXES 와 같은 목록이어야 한다 */
  const PHONE_PREFIXES = [
    '010', '011', '016', '017', '018', '019',
    '02', '031', '032', '033',
    '041', '042', '043', '044',
    '051', '052', '053', '054', '055',
    '061', '062', '063', '064',
    '070'
  ];

  /* "051-123-4567" → { prefix, mid, last }. 형식이 안 맞으면 null */
  function splitPhone(phone) {
    const m = /^(\d{2,3})-(\d{3,4})-(\d{4})$/.exec(phone || '');
    if (!m || PHONE_PREFIXES.indexOf(m[1]) === -1) { return null; }
    return { prefix: m[1], mid: m[2], last: m[3] };
  }

  /* =====================================================================
     화면별 동작 (body 의 data-page 값으로 고른다)
     ===================================================================== */
  const pages = {};

  /* ---------- 로그인 ---------- */
  pages.login = function () {
    const form = byId('login-form');
    const msg = byId('msg');
    const q = query();
    if (q.get('joined')) { showMsg(msg, '가입이 완료되었습니다. 로그인해 주세요.', 'ok'); }
    if (q.get('expired')) { showMsg(msg, '로그인이 만료되었습니다. 다시 로그인해 주세요.', 'error'); }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      const button = form.querySelector('button');
      button.disabled = true;
      showMsg(msg, '');
      try {
        const data = await api('/api/v2/login', {
          method: 'POST',
          body: { email: form.elements['email'].value, password: form.elements['password'].value }
        });
        setToken(data.access_token);
        go('/products.php');
      } catch (err) {
        showMsg(msg, err.message, 'error');
        button.disabled = false;
      }
    });
  };

  /* ---------- 회원가입 ---------- */
  pages.signup = function () {
    const form = byId('signup-form');
    const msg = byId('msg');

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      const button = form.querySelector('button');
      button.disabled = true;
      showMsg(msg, '');
      const body = {
        name: form.elements['name'].value,
        email: form.elements['email'].value,
        password: form.elements['password'].value
      };
      if (form.elements['phone'].value) { body.phone = form.elements['phone'].value; }
      if (form.elements['address'].value) { body.address = form.elements['address'].value; }
      try {
        await api('/api/v2/signup', { method: 'POST', body: body });
        go('/login.php?joined=1');
      } catch (err) {
        showMsg(msg, err.message, 'error');
        button.disabled = false;
      }
    });
  };

  /* ---------- 상품 목록 + 검색 ---------- */
  pages.products = function () {
    const form = byId('search-form');
    const input = byId('q');
    const clearButton = byId('search-clear');
    const info = byId('search-info');
    const infoText = byId('search-info-text');
    const resetButton = byId('search-reset');
    const chipBox = byId('chips');
    const limitSelect = byId('limit');
    const list = byId('list');
    const pager = byId('pager');
    const msg = byId('msg');
    const SORT_LABEL = { default: '기본순', newest: '최신순', price_asc: '낮은 가격순', price_desc: '높은 가격순', name: '이름순' };
    const state = { limit: 20, offset: 0, category: '', q: '', sort: 'default' };

    /* 검색어가 있을 때만 X 버튼을 보인다 */
    function syncClearButton() {
      clearButton.hidden = input.value === '';
    }

    /* "‘키보드’ 검색 결과 · 낮은 가격순" 안내 줄 */
    function renderInfo() {
      if (!state.q && state.sort === 'default') {
        info.hidden = true;
        return;
      }
      info.hidden = false;
      clear(infoText);
      if (state.q) {
        infoText.appendChild(el('strong', { class: 'accent', text: '‘' + state.q + '’' }));
        infoText.appendChild(document.createTextNode(' 검색 결과'));
      } else {
        infoText.appendChild(document.createTextNode('전체 상품'));
      }
      infoText.appendChild(document.createTextNode(' · ' + SORT_LABEL[state.sort]));
    }

    function renderChips() {
      clear(chipBox);
      [['', '전체']].concat(CATEGORIES.map(function (c) { return [c, c]; })).forEach(function (pair) {
        const chip = el('button', {
          type: 'button',
          class: 'chip' + (state.category === pair[0] ? ' active' : ''),
          'aria-pressed': state.category === pair[0] ? 'true' : 'false',
          text: pair[1]
        });
        // 분류 칩은 분류만 바꾼다 (검색어는 그대로 둔다)
        chip.addEventListener('click', function () {
          state.category = pair[0];
          state.offset = 0;
          renderChips();
          load();
        });
        chipBox.appendChild(chip);
      });
    }

    function renderGrid(items) {
      clear(list);
      if (items.length === 0) {
        const reset = state.q ? el('button', { type: 'button', class: 'btn btn-plain', text: '검색 해제하고 전체 보기' }) : null;
        if (reset) { reset.addEventListener('click', resetSearch); }
        list.appendChild(el('div', { class: 'empty card' }, [
          icon('box', 40, 1.6),
          el('p', { text: state.q ? '‘' + state.q + '’에 맞는 상품이 없어요.' : '상품이 없어요.' }),
          reset
        ]));
        return;
      }
      items.forEach(function (p) { list.appendChild(productCard(p)); });
    }

    /* 검색어나 정렬이 있으면 검색 API, 없으면 기존 목록 API 를 부른다 */
    async function load() {
      showMsg(msg, '');
      renderInfo();
      const params = new URLSearchParams({ limit: String(state.limit), offset: String(state.offset) });
      if (state.category) { params.set('category', state.category); }
      const searching = state.q !== '' || state.sort !== 'default';
      if (state.q) { params.set('q', state.q); }
      if (state.sort !== 'default') { params.set('sort', state.sort); }
      try {
        const items = await api((searching ? '/api/v2/products/search?' : '/api/v2/products?') + params.toString());
        renderGrid(items);
        renderPager(pager, state, items.length, load);
      } catch (err) {
        showMsg(msg, err.message, 'error');
      }
    }

    /* X 버튼: 검색어만 지운다 (정렬·분류는 그대로) */
    function clearKeyword() {
      input.value = '';
      syncClearButton();
      state.q = '';
      state.offset = 0;
      load();
      input.focus();
    }

    /* "검색 해제하고 전체 보기": 검색어와 정렬을 모두 처음으로 */
    function resetSearch() {
      input.value = '';
      form.elements['sort'].value = 'default';
      syncClearButton();
      state.q = '';
      state.sort = 'default';
      state.offset = 0;
      load();
    }

    input.addEventListener('input', syncClearButton);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && input.value !== '') {
        e.preventDefault();
        clearKeyword();
      }
    });
    clearButton.addEventListener('click', clearKeyword);
    resetButton.addEventListener('click', resetSearch);

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      const q = input.value.trim();
      if (q.length > 50) {
        showMsg(msg, '검색어는 50자 이하로 입력해 주세요.', 'error');
        return;
      }
      input.value = q;
      syncClearButton();
      state.q = q;
      state.sort = form.elements['sort'].value;
      state.offset = 0;
      load();
    });

    limitSelect.addEventListener('change', function () {
      state.limit = parseInt(limitSelect.value, 10);
      state.offset = 0;
      load();
    });

    syncClearButton();
    renderChips();
    load();
  };

  /* ---------- 상품 상세 ---------- */
  pages.product = function () {
    const box = byId('product');
    const msg = byId('msg');
    const id = query().get('id');
    if (!isDigits(id)) {
      clear(box);
      showMsg(msg, '잘못된 상품 번호입니다.', 'error');
      return;
    }

    function stockLine(p) {
      if (p.stock < 1) { return el('p', { class: 'stock out', text: '품절' }); }
      if (p.stock <= 10) { return el('p', { class: 'stock low', text: '재고 ' + p.stock + '개 남음' }); }
      return el('p', { class: 'stock', text: '재고 ' + p.stock + '개' });
    }

    function buyBox(p) {
      const wrap = el('div', { class: 'buy card' });
      if (!getToken()) {
        wrap.appendChild(el('p', {}, ['주문하려면 ', el('a', { href: '/login.php', text: '로그인' }), '해 주세요.']));
        return wrap;
      }
      if (p.stock < 1) {
        wrap.appendChild(el('p', { class: 'stock out', text: '품절된 상품이에요.' }));
        return wrap;
      }

      let qty = 1;
      const total = el('strong', { text: won(p.price) });
      const qtyBox = el('div');
      function drawQty() {
        clear(qtyBox);
        qtyBox.appendChild(qtyStepper(qty, function (n) {
          qty = Math.min(99, Math.max(1, n));
          total.textContent = won(p.price * qty);
          drawQty();
        }));
      }
      drawQty();

      const orderButton = el('button', { type: 'submit', class: 'btn btn-primary btn-lg', text: '바로 주문하기' });
      const cartButton = el('button', { type: 'button', class: 'btn btn-outline btn-lg', text: '장바구니 담기' });

      const form = el('form', {}, [
        el('div', { class: 'qtyrow' }, [el('span', { text: '수량' }), qtyBox]),
        el('div', { class: 'total-row' }, [el('span', { text: '합계' }), total]),
        el('div', { class: 'actions' }, [cartButton, orderButton])
      ]);
      form.style.display = 'flex';
      form.style.flexDirection = 'column';
      form.style.gap = '14px';

      form.addEventListener('submit', async function (e) {
        e.preventDefault();
        orderButton.disabled = true;
        showMsg(msg, '');
        try {
          const r = await api('/api/v2/orders', {
            method: 'POST',
            body: { items: [{ product_id: Number(id), quantity: qty }] }
          });
          showMsg(msg, '주문이 완료되었습니다. 주문번호 ' + r.order_id + ', 합계 ' + won(r.total_price), 'ok');
          msg.appendChild(document.createTextNode(' '));
          msg.appendChild(el('a', { href: '/order.php?id=' + encodeURIComponent(String(r.order_id)), text: '주문 상세 보기' }));
          await load();
        } catch (err) {
          handleAuthError(err, msg);
        } finally {
          orderButton.disabled = false;
        }
      });

      cartButton.addEventListener('click', async function () {
        cartButton.disabled = true;
        showMsg(msg, '');
        try {
          const c = await api('/api/v2/cart', { method: 'POST', body: { product_id: Number(id), quantity: qty } });
          setCartBadge(c.items.length);
          showMsg(msg, '장바구니에 담았습니다.', 'ok');
          msg.appendChild(document.createTextNode(' '));
          msg.appendChild(el('a', { href: '/cart.php', text: '장바구니 보기' }));
        } catch (err) {
          handleAuthError(err, msg);
        } finally {
          cartButton.disabled = false;
        }
      });

      wrap.appendChild(form);
      return wrap;
    }

    async function load() {
      try {
        const p = await api('/api/v2/products/' + id);
        document.title = p.name + ' - SHOP';
        clear(box);
        box.appendChild(thumbnail(p, 'thumb-lg'));
        box.appendChild(el('div', { class: 'detail-info' }, [
          el('p', { class: 'crumb', text: p.category || '-' }),
          el('h1', { text: p.name }),
          el('div', { class: 'dprice', text: won(p.price) }),
          stockLine(p),
          el('pre', { class: 'desc', text: p.description || '-' }),
          buyBox(p)
        ]));
      } catch (err) {
        clear(box);
        showMsg(msg, err.message, 'error');
      }
    }
    load();
  };

  /* ---------- 장바구니 ---------- */
  pages.cart = function () {
    if (!requireLogin()) { return; }
    const box = byId('cart');
    const countEl = byId('cart-count');
    const msg = byId('msg');
    const MAX_ORDER_ITEMS = 10;   // 주문 API 규칙 (OrderValidator::MAX_ITEMS)

    function warnOf(it) {
      if (it.stock < 1) { return el('span', { class: 'warn bad', text: '품절된 상품이에요. 빼고 주문해 주세요.' }); }
      if (it.quantity > it.stock) { return el('span', { class: 'warn bad', text: '재고가 ' + it.stock + '개뿐이에요.' }); }
      if (it.stock <= 10) { return el('span', { class: 'warn', text: '재고가 얼마 남지 않았어요.' }); }
      return null;
    }

    function render(cart) {
      setCartBadge(cart.items.length);
      clear(box);

      if (cart.items.length === 0) {
        countEl.textContent = '';
        box.appendChild(el('div', { class: 'empty card' }, [
          icon('cart', 44, 1.6),
          el('p', { text: '장바구니가 비어 있어요.' }),
          el('a', { class: 'btn btn-primary', href: '/products.php', text: '쇼핑하러 가기' })
        ]));
        return;
      }

      let totalQty = 0;
      cart.items.forEach(function (it) { totalQty += it.quantity; });
      countEl.textContent = '상품 ' + cart.items.length + '종류';

      const listCard = el('section', { class: 'card cart-list', 'aria-label': '담은 상품' });
      const clearButton = el('button', { type: 'button', class: 'link-btn', text: '전체 비우기' });
      listCard.appendChild(el('div', { class: 'cart-head' }, [el('span', { text: '담은 상품' }), clearButton]));

      cart.items.forEach(function (it) {
        const removeButton = el('button', { type: 'button', class: 'icon-btn', 'aria-label': it.name + ' 빼기' }, [icon('x', 20, 2)]);
        removeButton.addEventListener('click', async function () {
          removeButton.disabled = true;
          try {
            render(await api('/api/v2/cart/' + encodeURIComponent(String(it.product_id)), { method: 'DELETE' }));
          } catch (err) {
            handleAuthError(err, msg);
            removeButton.disabled = false;
          }
        });

        const stepperNode = qtyStepper(it.quantity, async function (n, buttons) {
          buttons.forEach(function (b) { b.disabled = true; });
          showMsg(msg, '');
          try {
            render(await api('/api/v2/cart/' + encodeURIComponent(String(it.product_id)), {
              method: 'PATCH', body: { quantity: n }
            }));
          } catch (err) {
            handleAuthError(err, msg);
            buttons.forEach(function (b) { b.disabled = false; });
          }
        });

        listCard.appendChild(el('div', { class: 'cart-row' }, [
          thumbnail({ id: it.product_id, name: it.name, category: it.category, stock: it.stock }, 'thumb-sm'),
          el('div', { class: 'cart-info' }, [
            el('span', { class: 'pcat', text: it.category || '-' }),
            el('a', { href: '/product.php?id=' + encodeURIComponent(String(it.product_id)), text: it.name }),
            el('span', { class: 'muted', text: '개당 ' + won(it.price) }),
            warnOf(it)
          ]),
          stepperNode,
          el('span', { class: 'cart-sub', text: won(it.subtotal) }),
          removeButton
        ]));
      });
      listCard.appendChild(el('p', { class: 'note', text: '가격은 지금 상품 가격 기준이며, 재고는 주문할 때 다시 확인합니다.' }));

      const orderButton = el('button', { type: 'button', class: 'btn btn-primary btn-lg btn-block', text: '전체 주문하기' });
      const summary = el('aside', { class: 'card summary', 'aria-label': '주문 요약' }, [
        el('h2', { text: '주문 요약' }),
        el('div', { class: 'sum-row' }, [el('span', { text: '상품 수' }), el('span', { text: cart.items.length + '종류 · ' + totalQty + '개' })]),
        el('div', { class: 'sum-row' }, [el('span', { text: '상품 금액' }), el('span', { text: won(cart.total_price) })]),
        el('div', { class: 'divider' }),
        el('div', { class: 'sum-total' }, [el('span', { text: '총 결제 금액' }), el('strong', { text: won(cart.total_price) })]),
        orderButton,
        el('a', { class: 'btn btn-plain btn-block', href: '/products.php', text: '쇼핑 계속하기' }),
        el('p', { class: 'small-note', text: '한 번에 최대 ' + MAX_ORDER_ITEMS + '종류까지 주문할 수 있어요.' })
      ]);

      orderButton.addEventListener('click', async function () {
        if (cart.items.length > MAX_ORDER_ITEMS) {
          showMsg(msg, '한 번에 최대 ' + MAX_ORDER_ITEMS + '종류까지 주문할 수 있어요. 일부를 빼고 주문해 주세요.', 'error');
          return;
        }
        orderButton.disabled = true;
        showMsg(msg, '');
        try {
          // 주문은 기존 주문 API 로 한다 (가격은 서버가 DB 값으로 다시 계산)
          const r = await api('/api/v2/orders', {
            method: 'POST',
            body: { items: cart.items.map(function (it) { return { product_id: it.product_id, quantity: it.quantity }; }) }
          });
          await api('/api/v2/cart', { method: 'DELETE' });
          await load();
          showMsg(msg, '주문이 완료되었습니다. 주문번호 ' + r.order_id + ', 합계 ' + won(r.total_price), 'ok');
          msg.appendChild(document.createTextNode(' '));
          msg.appendChild(el('a', { href: '/order.php?id=' + encodeURIComponent(String(r.order_id)), text: '주문 상세 보기' }));
        } catch (err) {
          handleAuthError(err, msg);
          orderButton.disabled = false;
        }
      });

      clearButton.addEventListener('click', async function () {
        if (!window.confirm('장바구니를 비울까요?')) { return; }
        clearButton.disabled = true;
        try {
          await api('/api/v2/cart', { method: 'DELETE' });
          await load();
        } catch (err) {
          handleAuthError(err, msg);
          clearButton.disabled = false;
        }
      });

      box.appendChild(el('div', { class: 'cart-layout' }, [listCard, summary]));
    }

    async function load() {
      try {
        render(await api('/api/v2/cart'));
      } catch (err) {
        clear(box);
        handleAuthError(err, msg);
      }
    }
    load();
  };

  /* ---------- 내 주문 ---------- */
  pages.orders = function () {
    if (!requireLogin()) { return; }
    const tabs = byId('tabs');
    const list = byId('list');
    const pager = byId('pager');
    const msg = byId('msg');
    const state = { limit: 10, offset: 0, status: '' };
    const TABS = [['', '전체'], ['결제완료', '결제완료'], ['배송중', '배송중'], ['배송완료', '배송완료'], ['취소', '취소']];

    function renderTabs() {
      clear(tabs);
      TABS.forEach(function (t) {
        const selected = state.status === t[0];
        const b = el('button', {
          type: 'button', role: 'tab', class: 'tab' + (selected ? ' active' : ''),
          'aria-selected': selected ? 'true' : 'false', text: t[1]
        });
        b.addEventListener('click', function () {
          state.status = t[0];
          state.offset = 0;
          renderTabs();
          load();
        });
        tabs.appendChild(b);
      });
    }

    function titleOf(o) {
      if (o.items.length === 0) { return '상품 정보 없음'; }
      const first = o.items[0];
      return o.items.length > 1 ? first.name + ' 외 ' + (o.items.length - 1) + '건' : first.name + ' ' + first.quantity + '개';
    }

    function orderCard(o) {
      const href = '/order.php?id=' + encodeURIComponent(String(o.id));
      return el('article', { class: 'card order-card' }, [
        el('div', { class: 'order-top' }, [
          el('div', { class: 'when' }, [
            el('strong', { text: fmtDate(o.order_date) }),
            el('span', { class: 'muted', text: '주문번호 ' + o.id })
          ]),
          el('a', { class: 'link-more', href: href }, ['주문 상세', icon('chevronRight', 16, 2.2)])
        ]),
        el('div', { class: 'order-body' }, [
          o.items.length > 0
            ? thumbnail({ id: o.items[0].product_id, name: o.items[0].name, category: o.items[0].category }, 'thumb-md')
            : el('div', { class: 'order-thumb' }, [icon('box', 32, 1.6)]),
          el('div', { class: 'order-main' }, [
            statusBadge(o.status, false),
            el('span', { class: 'title', text: titleOf(o) }),
            el('span', { class: 'price', text: won(o.total_price) })
          ]),
          stepper(o.status, false, o.order_date)
        ])
      ]);
    }

    async function load() {
      showMsg(msg, '');
      const params = new URLSearchParams({ limit: String(state.limit), offset: String(state.offset) });
      if (state.status) { params.set('status', state.status); }
      try {
        const orders = await api('/api/v2/orders/me?' + params.toString());
        clear(list);
        if (orders.length === 0) {
          list.appendChild(el('div', { class: 'empty card' }, [
            icon('box', 40, 1.6),
            el('p', { text: state.status ? state.status + ' 상태의 주문이 없어요.' : '주문 내역이 없어요.' })
          ]));
        }
        orders.forEach(function (o) { list.appendChild(orderCard(o)); });
        renderPager(pager, state, orders.length, load);
      } catch (err) {
        handleAuthError(err, msg);
      }
    }

    renderTabs();
    load();
  };

  /* ---------- 주문 상세 + 취소 ---------- */
  pages.order = function () {
    if (!requireLogin()) { return; }
    const box = byId('order');
    const msg = byId('msg');
    const id = query().get('id');
    if (!isDigits(id)) {
      clear(box);
      showMsg(msg, '잘못된 주문 번호입니다.', 'error');
      return;
    }
    const STATUS_NOTE = {
      '배송중': '배송이 시작되어 취소할 수 없어요.',
      '배송완료': '배송이 완료된 주문이에요.',
      '취소': '취소된 주문이에요. 재고는 이미 돌아갔어요.'
    };

    function render(o) {
      clear(box);
      document.title = '주문번호 ' + o.id + ' - SHOP';

      const itemsCard = el('section', { class: 'card items', 'aria-label': '주문 상품' }, [
        el('h2', { text: '주문 상품 ' + o.items.length + '종류' })
      ]);
      o.items.forEach(function (it) {
        itemsCard.appendChild(el('div', { class: 'item-row' }, [
          thumbnail({ id: it.product_id, name: it.name, category: it.category }, 'thumb-xs'),
          el('div', { class: 'grow' }, [
            el('a', { href: '/product.php?id=' + encodeURIComponent(String(it.product_id)), text: it.name }),
            el('span', { class: 'muted', text: won(it.price) + ' · ' + it.quantity + '개' })
          ]),
          el('strong', { text: won(it.price * it.quantity) })
        ]));
      });
      itemsCard.appendChild(el('p', { class: 'note', text: '가격은 주문 당시 가격입니다.' }));

      const payCard = el('section', { class: 'card side-card', 'aria-label': '결제 정보' }, [
        el('h2', { text: '결제 정보' }),
        el('div', { class: 'sum-row' }, [el('span', { text: '상품 금액' }), el('span', { text: won(o.total_price) })]),
        el('div', { class: 'divider' }),
        el('div', { class: 'sum-total' }, [el('span', { text: '총 결제 금액' }), el('strong', { text: won(o.total_price) })])
      ]);

      const cancelCard = el('section', { class: 'card side-card', 'aria-label': '주문 취소' });
      if (o.status === '결제완료') {
        const cancelButton = el('button', { type: 'button', class: 'btn btn-danger-outline btn-block', text: '주문 취소' });
        cancelButton.addEventListener('click', async function () {
          if (!window.confirm('주문번호 ' + o.id + '을(를) 취소할까요?')) { return; }
          cancelButton.disabled = true;
          try {
            await api('/api/v2/orders/' + id + '/cancel', { method: 'POST' });
            await load();
            showMsg(msg, '주문이 취소되었습니다.', 'ok');
          } catch (err) {
            handleAuthError(err, msg);
            cancelButton.disabled = false;
          }
        });
        cancelCard.appendChild(el('p', {}, [
          '배송이 시작되기 전, ', el('strong', { text: '결제완료' }), ' 상태에서만 취소할 수 있어요. 취소하면 재고가 바로 돌아갑니다.'
        ]));
        cancelCard.appendChild(cancelButton);
      } else {
        cancelCard.appendChild(el('p', { text: pick(STATUS_NOTE, o.status) || '' }));
      }

      box.appendChild(el('div', { class: 'detail-head' }, [
        el('div', {}, [
          el('h1', { text: '주문번호 ' + o.id }),
          el('span', { class: 'muted', text: fmtDateTime(o.order_date) + ' 주문' })
        ]),
        statusBadge(o.status, true)
      ]));
      box.appendChild(el('section', { class: 'card progress', 'aria-label': '진행 상태' }, [stepper(o.status, true, o.order_date)]));
      box.appendChild(el('div', { class: 'two-col' }, [itemsCard, el('aside', { class: 'side-col' }, [payCard, cancelCard])]));
    }

    async function load() {
      try {
        render(await api('/api/v2/orders/' + id));
      } catch (err) {
        clear(box);
        handleAuthError(err, msg);
      }
    }
    box.style.display = 'flex';
    box.style.flexDirection = 'column';
    box.style.gap = '20px';
    load();
  };

  /* ---------- 내 정보: 보기 + 수정 (이름·전화번호·주소만) ---------- */
  pages.me = async function () {
    if (!requireLogin()) { return; }
    const side = byId('side');
    const box = byId('me');
    const title = byId('me-title');
    const msg = byId('msg');
    let user = null;

    function renderSide() {
      clear(side);
      side.appendChild(el('section', { class: 'card profile-card' }, [
        el('div', { class: 'avatar', 'aria-hidden': 'true', text: Array.from(String(user.name))[0] || '?' }),
        el('strong', { text: user.name + ' 님' }),
        el('span', { text: user.email })
      ]));
      side.appendChild(el('nav', { class: 'card side-menu', 'aria-label': '마이페이지 메뉴' }, [
        el('a', { href: '/me.php', class: 'active', 'aria-current': 'page', text: '내 정보' }),
        el('a', { href: '/orders.php', text: '주문 내역' }),
        el('a', { href: '/cart.php', text: '장바구니' })
      ]));
    }

    function row(label, value) {
      return el('div', {}, [el('dt', { text: label }), el('dd', { text: value })]);
    }

    function renderView() {
      title.textContent = '내 정보';
      clear(box);
      const editButton = el('button', { type: 'button', class: 'btn btn-primary', text: '정보 수정' });
      editButton.addEventListener('click', renderForm);
      box.appendChild(el('section', { class: 'card info-card' }, [
        el('dl', { class: 'info-list' }, [
          row('이름', user.name),
          row('이메일', user.email),
          row('전화번호', user.phone || '-'),
          row('주소', user.address || '-'),
          row('회원번호', String(user.id))
        ]),
        el('div', { class: 'actions' }, [editButton])
      ]));
    }

    function renderForm() {
      showMsg(msg, '');
      title.textContent = '내 정보 수정';
      clear(box);

      // 이메일·비밀번호는 입력칸을 만들지 않는다 (표시만)
      const name = el('input', { type: 'text', id: 'f-name', maxlength: '50', required: 'required', autocomplete: 'name' });
      name.value = user.name;

      const parts = splitPhone(user.phone) || { prefix: '010', mid: '', last: '' };
      const prefix = el('select', { 'aria-label': '전화번호 앞자리' });
      PHONE_PREFIXES.forEach(function (p) { prefix.appendChild(el('option', { value: p, text: p })); });
      prefix.value = parts.prefix;
      const mid = el('input', { type: 'text', inputmode: 'numeric', maxlength: '4', 'aria-label': '전화번호 가운데 3~4자리' });
      mid.value = parts.mid;
      const last = el('input', { type: 'text', inputmode: 'numeric', maxlength: '4', 'aria-label': '전화번호 끝 4자리' });
      last.value = parts.last;
      const phoneError = el('p', { class: 'field-error', role: 'alert' });
      const phoneHint = el('p', {
        class: 'hint',
        text: (user.phone && !splitPhone(user.phone))
          ? '현재 번호: ' + user.phone + ' · 새로 입력하면 바뀝니다.'
          : '바꾸지 않으려면 그대로 두세요.'
      });

      const address = el('input', { type: 'text', id: 'f-address', maxlength: '255', autocomplete: 'street-address' });
      address.value = user.address || '';

      function setPhoneError(text) {
        clear(phoneError);
        if (text) {
          phoneError.appendChild(icon('alert', 16, 2.2));
          phoneError.appendChild(document.createTextNode(text));
        }
      }

      /* 숫자 외 글자가 들어오면 바로 에러를 보여준다 */
      function checkDigits() {
        let ok = true;
        [mid, last].forEach(function (input) {
          const bad = !/^[0-9]*$/.test(input.value);
          input.classList.toggle('invalid', bad);
          input.setAttribute('aria-invalid', bad ? 'true' : 'false');
          if (bad) { ok = false; }
        });
        setPhoneError(ok ? '' : '전화번호는 숫자만 입력할 수 있어요.');
        return ok;
      }
      mid.addEventListener('input', checkDigits);
      last.addEventListener('input', checkDigits);

      const saveButton = el('button', { type: 'submit', class: 'btn btn-primary', text: '저장하기' });
      const cancelButton = el('button', { type: 'button', class: 'btn btn-plain', text: '취소' });
      cancelButton.addEventListener('click', function () { showMsg(msg, ''); renderView(); });

      const form = el('form', { class: 'card form-card', novalidate: 'novalidate' }, [
        el('div', { class: 'form-field' }, [
          el('span', { class: 'label', text: '이메일 (로그인 아이디)' }),
          el('div', { class: 'locked' }, [
            el('span', { text: user.email }),
            el('span', { class: 'lock-note' }, [icon('lock', 16, 2), '변경할 수 없어요'])
          ])
        ]),
        el('div', { class: 'form-field' }, [el('label', { for: 'f-name', text: '이름' }), name]),
        el('fieldset', { class: 'form-field' }, [
          el('legend', { text: '전화번호' }),
          el('div', { class: 'phone-row' }, [
            prefix, el('span', { class: 'dash', 'aria-hidden': 'true', text: '–' }),
            mid, el('span', { class: 'dash', 'aria-hidden': 'true', text: '–' }),
            last
          ]),
          phoneError,
          phoneHint
        ]),
        el('div', { class: 'form-field' }, [el('label', { for: 'f-address', text: '주소' }), address]),
        el('div', { class: 'form-actions' }, [cancelButton, saveButton])
      ]);

      form.addEventListener('submit', async function (e) {
        e.preventDefault();
        if (!checkDigits()) { return; }

        // 바뀐 항목만 보낸다
        const body = {};
        const newName = name.value.trim();
        if (newName === '') {
          showMsg(msg, '이름을 입력해 주세요.', 'error');
          name.focus();
          return;
        }
        if (newName !== user.name) { body.name = newName; }

        if (mid.value !== '' || last.value !== '') {
          if (mid.value.length < 3 || last.value.length !== 4) {
            setPhoneError('가운데는 3~4자리, 끝은 4자리를 입력해 주세요.');
            return;
          }
          const phone = prefix.value + '-' + mid.value + '-' + last.value;
          if (phone !== user.phone) { body.phone = phone; }
        }

        const newAddress = address.value.trim();
        if (newAddress !== (user.address || '')) { body.address = newAddress; }

        if (Object.keys(body).length === 0) {
          showMsg(msg, '변경된 내용이 없습니다.', 'error');
          return;
        }

        saveButton.disabled = true;
        showMsg(msg, '');
        try {
          user = await api('/api/v2/users/me', { method: 'PATCH', body: body });
          renderSide();
          renderView();
          showMsg(msg, '저장되었습니다.', 'ok');
        } catch (err) {
          handleAuthError(err, msg);
          saveButton.disabled = false;
        }
      });

      box.appendChild(form);
      name.focus();
    }

    try {
      user = await api('/api/v2/users/me');
      renderSide();
      renderView();
    } catch (err) {
      clear(box);
      handleAuthError(err, msg);
    }
  };

  document.addEventListener('DOMContentLoaded', function () {
    renderNav();
    const page = document.body.getAttribute('data-page');
    if (pages[page]) { pages[page](); }
  });
})();
