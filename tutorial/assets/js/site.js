/* SRP VPN Connect documentation: builds the header, sidebar, table of contents, search,
   theme switch and code copy buttons around each page's <main>. Pages stay plain HTML;
   the navigation lives in nav.js. */
(function () {
  'use strict';

  var script = document.currentScript;
  var root = script.src.replace(/assets\/js\/site\.js(\?.*)?$/, '');
  var nav = window.SITE_NAV || [];
  var main = document.querySelector('main');
  if (!main) return;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === 'text') node.textContent = attrs[key];
      else node.setAttribute(key, attrs[key]);
    });
    (children || []).forEach(function (child) { if (child) node.appendChild(child); });
    return node;
  }

  // Pages in reading order, for the current-page mark, previous/next links and search
  var pages = [];
  (function flatten(items) {
    items.forEach(function (item) {
      if (item.href) pages.push(item);
      if (item.children) flatten(item.children);
    });
  })(nav);

  var here = location.href.split('#')[0].split('?')[0];
  if (/\/$/.test(here)) here += 'index.html';
  function isCurrent(href) { return here === new URL(href, root).href; }

  // Theme: an explicit choice wins over the system setting
  function storedTheme() { try { return localStorage.getItem('theme'); } catch (e) { return null; } }
  function applyTheme(theme) {
    if (theme) document.documentElement.setAttribute('data-theme', theme);
    else document.documentElement.removeAttribute('data-theme');
  }
  applyTheme(storedTheme());
  function currentTheme() {
    var set = document.documentElement.getAttribute('data-theme');
    if (set) return set;
    return window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  // Header
  var menuButton = el('button', { 'class': 'icon-button menu-button', type: 'button', 'aria-label': 'Open navigation', 'aria-expanded': 'false', text: '☰' });
  var themeButton = el('button', { 'class': 'icon-button', type: 'button', 'aria-label': 'Switch light or dark theme' });
  function labelTheme() { themeButton.textContent = currentTheme() === 'dark' ? '☀ Light' : '☾ Dark'; }
  labelTheme();
  var searchInput = el('input', { type: 'search', placeholder: 'Search the docs', 'aria-label': 'Search the documentation', autocomplete: 'off' });
  var searchResults = el('ul', { 'class': 'search-results', hidden: '', role: 'listbox' });
  var header = el('header', { 'class': 'site-header' }, [
    menuButton,
    el('a', { 'class': 'site-title', href: root + 'index.html' }, [
      document.createTextNode('SRP VPN Connect '), el('span', { text: 'Docs' })
    ]),
    el('div', { 'class': 'header-spacer' }),
    el('div', { 'class': 'search', role: 'search' }, [searchInput, searchResults]),
    themeButton
  ]);

  // Sidebar
  function navList(items) {
    var ul = el('ul');
    items.forEach(function (item) {
      var li = el('li');
      if (item.children && !item.href) {
        var open = item.children.some(function containsCurrent(child) {
          return (child.href && isCurrent(child.href)) || (child.children && child.children.some(containsCurrent));
        }) || item.open;
        var details = el('details', open ? { open: '' } : {}, [el('summary', { text: item.title }), navList(item.children)]);
        li.appendChild(details);
      } else {
        var a = el('a', { href: root + item.href, text: item.title });
        if (isCurrent(item.href)) a.setAttribute('aria-current', 'page');
        li.appendChild(a);
        if (item.children) li.appendChild(navList(item.children));
      }
      ul.appendChild(li);
    });
    return ul;
  }
  var sidebar = el('nav', { 'class': 'sidebar', id: 'sidebar', 'aria-label': 'Documentation' }, [navList(nav)]);

  // Table of contents from the page's h2/h3 headings
  var toc = el('aside', { 'class': 'toc', 'aria-label': 'On this page' });
  var headings = main.querySelectorAll('h2, h3');
  if (headings.length > 1) {
    var tocList = el('ul');
    Array.prototype.forEach.call(headings, function (h) {
      if (!h.id) h.id = h.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      tocList.appendChild(el('li', { 'class': h.tagName.toLowerCase() }, [el('a', { href: '#' + h.id, text: h.textContent })]));
    });
    toc.appendChild(el('h2', { text: 'On this page' }));
    toc.appendChild(tocList);
  }

  // Previous / next page
  var index = -1;
  pages.forEach(function (page, i) { if (isCurrent(page.href)) index = i; });
  if (index >= 0) {
    var pageNav = el('nav', { 'class': 'page-nav', 'aria-label': 'Previous and next page' });
    pageNav.appendChild(index > 0 ? el('a', { href: root + pages[index - 1].href, text: '← ' + pages[index - 1].title }) : el('span'));
    if (index < pages.length - 1) pageNav.appendChild(el('a', { href: root + pages[index + 1].href, text: pages[index + 1].title + ' →' }));
    main.appendChild(pageNav);
  }

  // Assemble the page
  main.id = main.id || 'content';
  main.classList.add('doc');
  var layout = el('div', { 'class': 'layout' }, [sidebar, main.parentNode.removeChild(main), toc]);
  document.body.insertBefore(layout, document.body.firstChild);
  document.body.insertBefore(header, layout);
  document.body.insertBefore(el('a', { 'class': 'skip-link', href: '#' + main.id, text: 'Skip to content' }), header);

  menuButton.addEventListener('click', function () {
    var open = document.body.classList.toggle('nav-open');
    menuButton.setAttribute('aria-expanded', String(open));
  });
  sidebar.addEventListener('click', function (event) {
    if (event.target.tagName === 'A') document.body.classList.remove('nav-open');
  });
  themeButton.addEventListener('click', function () {
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem('theme', next); } catch (e) { /* the page still switches */ }
    labelTheme();
  });

  // Code: light syntax colouring for the languages the docs use, plus a copy button
  function escapeHtml(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  var rules = {
    json: [
      [/"(?:[^"\\]|\\.)*"(?=\s*:)/g, 'tok-key'],
      [/"(?:[^"\\]|\\.)*"/g, 'tok-str'],
      [/\b-?\d+(?:\.\d+)?\b/g, 'tok-num'],
      [/\b(?:true|false|null)\b/g, 'tok-kw']
    ],
    bash: [
      [/(^|\s)#.*$/gm, 'tok-com'],
      [/"(?:[^"\\]|\\.)*"|'[^']*'/g, 'tok-str'],
      [/(^|\s)--?[a-zA-Z][\w-]*/g, 'tok-key']
    ]
  };
  rules.shell = rules.bash;
  function highlight(code, lang) {
    var list = rules[lang];
    var text = code.textContent;
    if (!list) return;
    // One pass over the text: at each position take the earliest rule match
    var out = '';
    var pos = 0;
    while (pos < text.length) {
      var best = null;
      list.forEach(function (rule) {
        rule[0].lastIndex = pos;
        var m = rule[0].exec(text);
        if (m && (!best || m.index < best.index)) best = { index: m.index, text: m[0], cls: rule[1] };
      });
      if (!best || !best.text.length) { out += escapeHtml(text.slice(pos)); break; }
      out += escapeHtml(text.slice(pos, best.index));
      var lead = best.text.match(/^\s*/)[0];
      out += escapeHtml(lead) + '<span class="' + best.cls + '">' + escapeHtml(best.text.slice(lead.length)) + '</span>';
      pos = best.index + best.text.length;
    }
    code.innerHTML = out;
  }
  Array.prototype.forEach.call(main.querySelectorAll('pre > code'), function (code) {
    var pre = code.parentNode;
    var lang = (code.className.match(/language-(\w+)/) || [])[1];
    highlight(code, lang);
    var wrapper = el('div', { 'class': 'code-block' });
    pre.parentNode.insertBefore(wrapper, pre);
    if (pre.dataset.label) wrapper.appendChild(el('span', { 'class': 'code-label', text: pre.dataset.label }));
    wrapper.appendChild(pre);
    var copy = el('button', { 'class': 'copy', type: 'button', text: 'Copy', 'aria-label': 'Copy this code' });
    copy.addEventListener('click', function () {
      var done = function () { copy.textContent = 'Copied'; setTimeout(function () { copy.textContent = 'Copy'; }, 1600); };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(code.textContent).then(done, function () { copy.textContent = 'Select and copy'; });
      } else {
        var range = document.createRange();
        range.selectNodeContents(code);
        var selection = getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        try { document.execCommand('copy'); done(); } catch (e) { copy.textContent = 'Press Cmd/Ctrl+C'; }
      }
    });
    wrapper.appendChild(copy);
  });

  // Search: every page in nav.js is fetched once and searched in the browser
  var searchIndex = null;
  function buildIndex() {
    if (searchIndex) return searchIndex;
    searchIndex = Promise.all(pages.map(function (page) {
      return fetch(root + page.href).then(function (response) { return response.ok ? response.text() : ''; }).then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var body = doc.querySelector('main');
        // Table cells and list items carry no whitespace between them; add one so words do not run together
        if (body) Array.prototype.forEach.call(body.querySelectorAll('td, th, li, p, dt, dd, h1, h2, h3, pre'), function (n) { n.append(' '); });
        return { title: page.title, href: page.href, text: body ? body.textContent.replace(/\s+/g, ' ') : '' };
      }, function () { return { title: page.title, href: page.href, text: '' }; });
    }));
    return searchIndex;
  }
  function showResults(items, query) {
    searchResults.innerHTML = '';
    if (!items.length) {
      searchResults.appendChild(el('li', { 'class': 'empty', text: 'No page matches "' + query + '".' }));
    }
    items.slice(0, 12).forEach(function (item) {
      var at = item.text.toLowerCase().indexOf(query.split(' ')[0]);
      var snippet = at >= 0 ? item.text.slice(Math.max(0, at - 50), at + 90).trim() : item.text.slice(0, 120);
      searchResults.appendChild(el('li', {}, [el('a', { href: root + item.href }, [
        document.createTextNode(item.title), el('small', { text: '…' + snippet + '…' })
      ])]));
    });
    searchResults.hidden = false;
  }
  searchInput.addEventListener('focus', buildIndex);
  searchInput.addEventListener('input', function () {
    var query = searchInput.value.trim().toLowerCase();
    if (query.length < 2) { searchResults.hidden = true; return; }
    if (location.protocol === 'file:') {
      searchResults.innerHTML = '';
      searchResults.appendChild(el('li', { 'class': 'empty', text: 'Search works when the site is served over HTTP (GitHub Pages or a local web server).' }));
      searchResults.hidden = false;
      return;
    }
    var words = query.split(/\s+/);
    buildIndex().then(function (index) {
      var hits = index.map(function (item) {
        var title = item.title.toLowerCase();
        var text = item.text.toLowerCase();
        if (!words.every(function (w) { return title.indexOf(w) >= 0 || text.indexOf(w) >= 0; })) return null;
        return { item: item, score: words.reduce(function (s, w) { return s + (title.indexOf(w) >= 0 ? 10 : 0) + (text.split(w).length - 1); }, 0) };
      }).filter(Boolean).sort(function (a, b) { return b.score - a.score; });
      showResults(hits.map(function (h) { return h.item; }), query);
    });
  });
  searchInput.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { searchResults.hidden = true; searchInput.blur(); }
    if (event.key === 'ArrowDown') { var first = searchResults.querySelector('a'); if (first) { event.preventDefault(); first.focus(); } }
  });
  document.addEventListener('click', function (event) {
    if (!event.target.closest('.search')) searchResults.hidden = true;
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === '/' && document.activeElement !== searchInput && !/input|textarea/i.test(document.activeElement.tagName)) {
      event.preventDefault();
      searchInput.focus();
    }
  });
})();
