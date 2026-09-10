(() => {
  'use strict';

  const G = '__kcdNvidiaProbe';
  const OLD = '__kcdCombinedProbe';
  const UI = '__kcdNvidiaProbeUI';
  const VER = '1.3.0';

  const MAX_NETWORK = 1000;
  const MAX_FILES = 4000;
  const MAX_CRAWL = 180;
  const MAX_QUEUE = 1200;
  const MAX_TEXT = 300000;
  const MAX_STORE_TEXT = 180000;
  const CRAWL_DELAY_MS = 250;

  const SENSITIVE = /(authorization|cookie|token|secret|password|passwd|api.?key|session|credential|bearer|csrf|xsrf|saml|oidc|sid)/i;
  const BLOCKED_PATH = /(\/login|\/logout|\/signout|\/signin|\/account|\/profile|\/settings|\/billing|\/checkout|\/oauth|\/auth(?:\/|$)|\/token|\/session|\/admin|\/password|\/verify)/i;
  const TRACKING_PARAM = /^(utm_|gclid$|fbclid$|msclkid$|_rsc$|ref$|source$|campaign$)/i;
  const TEXT_EXT = /\.(?:html?|json|ya?ml|md|txt|xml|js|mjs|css)(?:$|\?)/i;
  const DOC_EXT = /\.(?:json|ya?ml|md|txt|xml)(?:$|\?)/i;
  const MEDIA_EXT = /\.(?:mp4|webm|mov|m4v|m3u8|mp3|wav|ogg|flac|jpg|jpeg|png|webp|gif|svg|avif)(?:$|\?)/i;
  const STATIC_EXT = /\.(?:woff2?|ttf|otf|ico|wasm|map)(?:$|\?)/i;

  try { window[G]?.stop?.(); } catch {}
  try { window[OLD]?.stop?.(); } catch {}

  const originals = {
    fetch: window.fetch,
    xhrOpen: XMLHttpRequest.prototype.open,
    xhrSend: XMLHttpRequest.prototype.send
  };

  const state = {
    name: 'KCD NVIDIA Public Site Inventory Probe',
    version: VER,
    startedAt: new Date().toISOString(),
    stoppedAt: null,
    active: true,
    mode: 'passive-plus-public-crawl',
    page: {},
    files: [],
    tables: [],
    panels: [],
    layout: {},
    network: [],
    crawl: {
      running: false,
      scanned: 0,
      queued: 0,
      max: MAX_CRAWL,
      results: [],
      errors: []
    },
    inventory: {
      routes: [],
      apis: [],
      catalogItems: [],
      models: [],
      skills: [],
      blueprints: [],
      scripts: [],
      styles: [],
      media: [],
      contentFiles: [],
      staticFiles: [],
      externalHosts: []
    },
    mutations: { childList: 0, attributes: 0 },
    errors: [],
    policy: {
      automaticClicks: false,
      formSubmission: false,
      sameOriginCrawlerOnly: true,
      crawlerCredentials: 'omit',
      requestHeadersCaptured: false,
      responseHeadersCaptured: false,
      cookiesCaptured: false,
      browserStorageCaptured: false,
      typedInputValuesCaptured: false,
      blockedPrivateLikePaths: true,
      authLikeValuesRedacted: true
    }
  };

  const invMaps = Object.fromEntries(Object.keys(state.inventory).map(k => [k, new Map()]));
  const seenCrawl = new Set();
  const queuedCrawl = new Set();
  const queue = [];
  let observer = null;
  let timer = null;
  let box = null;
  let crawlController = null;
  let crawlerPromise = null;

  const now = () => new Date().toISOString();
  const clean = (v, n = 500) => String(v ?? '').replace(/\s+/g, ' ').trim().slice(0, n);

  function hash(value) {
    let text;
    try { text = typeof value === 'string' ? value : JSON.stringify(value); }
    catch { text = String(value); }
    let h = 2166136261;
    for (let i = 0; i < text.length; i += 1) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(16).padStart(8, '0');
  }

  function cut(value, max = MAX_TEXT) {
    const text = String(value ?? '');
    return text.length > max ? `${text.slice(0, max)}\n...[AFGEKAPT ${text.length - max} chars]` : text;
  }

  function scrub(value) {
    let text = cut(value);
    text = text.replace(/Bearer\s+[A-Za-z0-9._~+\/=-]+/gi, 'Bearer [REDACTED]');
    text = text.replace(
      /((?:authorization|auth|token|session(?:id)?|sid|csrf|api[-_]?key|secret|password|credential)\s*["']?\s*[:=]\s*["']?)([^&\s,"'<>}]+)/gi,
      '$1[REDACTED]'
    );
    return text;
  }

  function redact(value, depth = 0) {
    if (depth > 10) return '[MAX_DEPTH]';
    if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'string') return scrub(value);
    if (Array.isArray(value)) return value.slice(0, 1500).map(x => redact(x, depth + 1));
    if (typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value).slice(0, 2500)) {
        out[k] = SENSITIVE.test(k) ? '[REDACTED]' : redact(v, depth + 1);
      }
      return out;
    }
    return String(value);
  }

  function safeBody(body) {
    if (body == null) return null;
    if (typeof body === 'string') {
      try { return redact(JSON.parse(body)); }
      catch { return scrub(body); }
    }
    if (body instanceof URLSearchParams) {
      const out = {};
      for (const [k, v] of body.entries()) out[k] = SENSITIVE.test(k) ? '[REDACTED]' : scrub(v);
      return out;
    }
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      const out = {};
      for (const [k, v] of body.entries()) {
        out[k] = SENSITIVE.test(k) ? '[REDACTED]' : (typeof v === 'string' ? scrub(v) : '[FILE]');
      }
      return out;
    }
    if (body instanceof ArrayBuffer) return `[ArrayBuffer ${body.byteLength}]`;
    try { return redact(body); } catch { return scrub(String(body)); }
  }

  function safeUrl(raw, { canonical = false } = {}) {
    try {
      const url = new URL(String(raw || ''), location.href);
      url.hash = '';
      for (const key of [...url.searchParams.keys()]) {
        if (SENSITIVE.test(key)) url.searchParams.set(key, '[REDACTED]');
        else if (canonical && TRACKING_PARAM.test(key)) url.searchParams.delete(key);
      }
      if (canonical) {
        for (const key of [...url.searchParams.keys()]) {
          if (!/^(q|query|page|limit|offset|category|tag|sort)$/i.test(key)) url.searchParams.delete(key);
        }
      }
      return url.href;
    } catch {
      return clean(raw, 2000);
    }
  }

  function sameOrigin(raw) {
    try { return new URL(String(raw || ''), location.href).origin === location.origin; }
    catch { return false; }
  }

  function blocked(raw) {
    try {
      const u = new URL(String(raw || ''), location.href);
      return BLOCKED_PATH.test(u.pathname);
    } catch {
      return true;
    }
  }

  function nameFromUrl(raw) {
    try {
      const u = new URL(raw, location.href);
      return decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || u.hostname);
    } catch {
      return clean(raw, 200);
    }
  }

  function extKind(raw) {
    const u = safeUrl(raw).toLowerCase();
    if (/\.(?:js|mjs)(?:$|\?)/.test(u)) return 'script';
    if (/\.css(?:$|\?)/.test(u)) return 'style';
    if (DOC_EXT.test(u)) return 'content';
    if (MEDIA_EXT.test(u)) return 'media';
    if (STATIC_EXT.test(u)) return 'static';
    return 'route';
  }

  function pushInventory(bucket, url, meta = {}) {
    if (!invMaps[bucket]) return;
    const safe = safeUrl(url);
    if (!safe || SENSITIVE.test(safe) || blocked(safe)) return;
    const key = safe;
    const current = invMaps[bucket].get(key) || { url: safe };
    invMaps[bucket].set(key, { ...current, ...meta, url: safe });
    state.inventory[bucket] = [...invMaps[bucket].values()].slice(0, 5000);
  }

  function classify(url, source = 'unknown', text = '') {
    const safe = safeUrl(url);
    if (!safe || blocked(safe)) return;
    let u;
    try { u = new URL(safe, location.href); } catch { return; }

    if (u.origin !== location.origin) {
      pushInventory('externalHosts', `${u.protocol}//${u.host}/`, { host: u.host, source });
      return;
    }

    const p = u.pathname;
    const meta = { source, name: nameFromUrl(safe), text: clean(text, 300) || null };
    const kind = extKind(safe);

    if (kind === 'script') pushInventory('scripts', safe, meta);
    else if (kind === 'style') pushInventory('styles', safe, meta);
    else if (kind === 'media') pushInventory('media', safe, meta);
    else if (kind === 'content') pushInventory('contentFiles', safe, meta);
    else if (kind === 'static') pushInventory('staticFiles', safe, meta);
    else pushInventory('routes', safe, meta);

    if (/\/api(?:\/|$)/i.test(p)) pushInventory('apis', safe, meta);
    if (/\/skills?(?:\/|$)/i.test(p)) pushInventory('skills', safe, meta);
    if (/\/blueprints?(?:\/|$)/i.test(p)) pushInventory('blueprints', safe, meta);
    if (/\/models?(?:\/|$)/i.test(p)) pushInventory('models', safe, meta);

    const seg = p.split('/').filter(Boolean);
    if (seg.length === 2 && !['api', 'explore', 'skills', 'models', 'blueprints'].includes(seg[0].toLowerCase())) {
      pushInventory('catalogItems', safe, { ...meta, publisher: seg[0], slug: seg[1] });
    }
  }

  function shouldCrawl(raw) {
    if (!sameOrigin(raw) || blocked(raw)) return false;
    const u = safeUrl(raw, { canonical: true });
    if (!u) return false;
    if (MEDIA_EXT.test(u) || STATIC_EXT.test(u)) return false;
    if (/\.(?:zip|gz|tgz|tar|pdf|bin|exe|dmg)(?:$|\?)/i.test(u)) return false;
    return TEXT_EXT.test(u) || !/\.[a-z0-9]{2,5}(?:$|\?)/i.test(u);
  }

  function enqueue(raw, depth = 0, source = 'discover') {
    if (!state.active || queue.length >= MAX_QUEUE) return;
    const url = safeUrl(raw, { canonical: true });
    if (!url || !shouldCrawl(url)) return;
    if (seenCrawl.has(url) || queuedCrawl.has(url)) return;
    queuedCrawl.add(url);
    queue.push({ url, depth, source });
    state.crawl.queued = queue.length;
  }

  function extractCandidates(text, baseUrl, source = 'text', depth = 0) {
    if (!text) return;
    const sample = String(text).slice(0, MAX_TEXT);
    const found = new Set();

    const fullUrl = /https?:\/\/[a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+/gi;
    const routeLike = /["'`](\/(?:api|models?|skills?|blueprints?|explore|nvidia|meta|docs|reference|agents?|workflows?|playground|runtime|content)[^"'`\s<>]*)["'`]/gi;
    const fileLike = /["'`](\/[^"'`\s<>]+\.(?:json|ya?ml|md|txt|xml|js|mjs|css|mp4|webm|m3u8|png|jpe?g|webp|svg))["'`]/gi;
    const markdown = /\[[^\]]*\]\(([^)\s]+)\)/g;

    for (const m of sample.matchAll(fullUrl)) found.add(m[0]);
    for (const m of sample.matchAll(routeLike)) found.add(m[1]);
    for (const m of sample.matchAll(fileLike)) found.add(m[1]);
    for (const m of sample.matchAll(markdown)) found.add(m[1]);

    for (const raw of [...found].slice(0, 1000)) {
      let url;
      try { url = new URL(raw, baseUrl || location.href).href; } catch { continue; }
      classify(url, source);
      if (depth < 2) enqueue(url, depth + 1, source);
    }
  }

  function discoverDocument(doc, baseUrl, source = 'dom', depth = 0) {
    const add = (raw, type, text = '') => {
      if (!raw) return;
      let url;
      try { url = new URL(raw, baseUrl || location.href).href; } catch { return; }
      classify(url, source, text);
      if (type === 'route' && depth < 2) enqueue(url, depth + 1, source);
    };

    for (const a of doc.querySelectorAll?.('a[href]') || []) add(a.getAttribute('href'), 'route', a.textContent);
    for (const s of doc.querySelectorAll?.('script[src]') || []) add(s.getAttribute('src'), 'asset');
    for (const l of doc.querySelectorAll?.('link[href]') || []) add(l.getAttribute('href'), 'asset', l.getAttribute('rel'));
    for (const i of doc.querySelectorAll?.('img[src]') || []) add(i.getAttribute('src'), 'asset', i.getAttribute('alt'));
    for (const i of doc.querySelectorAll?.('img[srcset],source[srcset]') || []) {
      const raw = i.getAttribute('srcset') || '';
      for (const part of raw.split(',')) add(part.trim().split(/\s+/)[0], 'asset');
    }
    for (const m of doc.querySelectorAll?.('video[src],video[poster],audio[src],source[src],iframe[src]') || []) {
      add(m.getAttribute('src') || m.getAttribute('poster'), 'asset');
    }
    for (const m of doc.querySelectorAll?.('meta[property^="og:"],meta[name^="twitter:"]') || []) {
      const c = m.getAttribute('content') || '';
      if (/^(https?:|\/)/i.test(c)) add(c, 'asset', m.getAttribute('property') || m.getAttribute('name'));
    }
    for (const el of doc.querySelectorAll?.('[data-src],[data-url]') || []) {
      add(el.getAttribute('data-src') || el.getAttribute('data-url'), 'asset');
    }

    for (const s of [...(doc.querySelectorAll?.('script:not([src])') || [])].slice(0, 100)) {
      extractCandidates(s.textContent || '', baseUrl, `${source}:inline-script`, depth);
    }
  }

  function collectFiles() {
    const map = new Map();
    const add = (url, type, source) => {
      if (!url) return;
      const safe = safeUrl(url);
      if (!safe || blocked(safe)) return;
      const key = `${type}|${safe}`;
      if (map.has(key)) return;
      map.set(key, { name: nameFromUrl(safe), type, source, url: safe });
      classify(safe, source);
    };

    for (const item of document.scripts) if (item.src) add(item.src, 'script', 'dom');
    for (const item of document.querySelectorAll('link[href]')) add(item.href, clean(item.rel, 60) || 'link', 'dom');
    for (const item of document.querySelectorAll('img[src]')) add(item.src, 'image', 'dom');
    for (const item of document.querySelectorAll('video[src],audio[src],source[src]')) add(item.src, 'media', 'dom');
    for (const item of document.querySelectorAll('video[poster]')) add(item.poster, 'poster', 'dom');
    for (const item of document.querySelectorAll('iframe[src]')) add(item.src, 'iframe', 'dom');

    try {
      for (const entry of performance.getEntriesByType('resource')) {
        add(entry.name, clean(entry.initiatorType, 60) || 'resource', 'performance');
      }
    } catch {}

    state.files = [...map.values()].slice(0, MAX_FILES);
  }

  function collectTables() {
    state.tables = [...document.querySelectorAll('table')].slice(0, 150).map(table => {
      const headers = [...table.querySelectorAll('thead th')].map(cell => clean(cell.innerText || cell.textContent, 250));
      const rows = [...table.querySelectorAll('tbody tr')].slice(0, 750).map(row =>
        [...row.querySelectorAll('th,td')].map(cell => clean(cell.innerText || cell.textContent, 600))
      ).filter(row => row.length);
      return { headers, rows, fingerprint: hash({ headers, rows }) };
    });
  }

  function collectPanels() {
    const out = [];
    const seen = new Set();
    const candidates = document.querySelectorAll('.embPanel,[data-test-subj*=embeddablePanel],section,article,[role=tabpanel],[role=dialog]');

    for (const el of candidates) {
      if (isUiNode(el)) continue;
      const title = clean(
        el.querySelector?.('[data-test-subj=embeddablePanelTitleInner]')?.innerText ||
        el.querySelector?.('h1,h2,h3,h4,header')?.innerText ||
        el.getAttribute?.('aria-label') || el.id,
        240
      );
      const text = clean(el.innerText, 16000);
      if (!title && text.length < 20) continue;
      const key = hash({ title, text: text.slice(0, 1500) });
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ title: title || '(zonder titel)', text, fingerprint: hash(text) });
      if (out.length >= 160) break;
    }
    state.panels = out;
  }

  function isUiNode(node) {
    const el = node?.nodeType === Node.ELEMENT_NODE ? node : node?.parentElement;
    return Boolean(el?.closest?.(`#${UI}`));
  }

  function collectLayout() {
    const roleCounts = {};
    const tagCounts = {};
    const classes = new Map();
    for (const el of document.querySelectorAll('nav,main,header,footer,section,article,aside,form,dialog,[role]')) {
      if (isUiNode(el)) continue;
      const tag = (el.tagName || '').toLowerCase();
      const role = el.getAttribute?.('role') || '';
      tagCounts[tag] = (tagCounts[tag] || 0) + 1;
      if (role) roleCounts[role] = (roleCounts[role] || 0) + 1;
      const cls = clean(typeof el.className === 'string' ? el.className : '', 300);
      if (cls) classes.set(cls, (classes.get(cls) || 0) + 1);
    }
    state.layout = {
      title: document.title,
      headings: [...document.querySelectorAll('h1,h2,h3')].slice(0, 200).map(h => ({
        level: h.tagName.toLowerCase(),
        text: clean(h.innerText || h.textContent, 400)
      })),
      roleCounts,
      tagCounts,
      topClassSignatures: [...classes.entries()].sort((a,b) => b[1] - a[1]).slice(0, 100).map(([className,count]) => ({ className, count })),
      buttons: document.querySelectorAll('button,[role=button]').length,
      links: document.querySelectorAll('a[href]').length,
      tabs: document.querySelectorAll('[role=tab]').length,
      dialogs: document.querySelectorAll('[role=dialog],dialog').length,
      grids: document.querySelectorAll('[role=grid],[role=table],table').length
    };
  }

  function seedDiscovery() {
    discoverDocument(document, location.href, 'dom', 0);
    classify(location.href, 'current-page');
    enqueue(location.href, 0, 'current-page');

    const seeds = [
      '/', '/models', '/skills', '/explore/discover', '/blueprints',
      '/llms.txt', '/robots.txt', '/sitemap.xml'
    ];
    for (const seed of seeds) enqueue(new URL(seed, location.origin).href, 0, 'seed');
  }

  function storeCrawlResult(result) {
    state.crawl.results.push(result);
    if (state.crawl.results.length > MAX_CRAWL) state.crawl.results.shift();
  }

  async function crawlOne(item) {
    if (!state.active) return;
    const { url, depth, source } = item;
    seenCrawl.add(url);
    queuedCrawl.delete(url);

    const result = {
      at: now(),
      url,
      depth,
      source,
      status: null,
      kind: extKind(url),
      size: 0,
      hash: null,
      title: null,
      textPreview: null,
      extracted: 0,
      error: null
    };

    try {
      crawlController = new AbortController();
      const response = await originals.fetch.call(window, url, {
        method: 'GET',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'follow',
        signal: crawlController.signal
      });
      result.status = response.status;
      const finalUrl = safeUrl(response.url || url, { canonical: true });
      classify(finalUrl, 'crawler');

      if (!response.ok) {
        storeCrawlResult(result);
        return;
      }

      let text = await response.text();
      result.size = text.length;
      result.hash = hash(text);
      text = scrub(text.slice(0, MAX_TEXT));

      const lowerPath = (() => { try { return new URL(finalUrl).pathname.toLowerCase(); } catch { return ''; }})();
      const looksHtml = /^\s*<!doctype html|^\s*<html[\s>]/i.test(text) || (!TEXT_EXT.test(lowerPath) && /<head[\s>]|<body[\s>]/i.test(text));
      const looksJson = /^\s*[\[{]/.test(text) && /\.(?:json)(?:$|\?)/i.test(finalUrl);
      const looksDoc = DOC_EXT.test(finalUrl);

      if (looksHtml) {
        const doc = new DOMParser().parseFromString(text, 'text/html');
        result.title = clean(doc.title, 500) || null;
        result.textPreview = clean(doc.body?.innerText || '', 20000) || null;
        const before = queue.length;
        discoverDocument(doc, finalUrl, 'crawler-html', depth);
        result.extracted = Math.max(0, queue.length - before);
      } else if (looksJson) {
        try {
          const parsed = redact(JSON.parse(text));
          result.textPreview = cut(JSON.stringify(parsed), MAX_STORE_TEXT);
        } catch {
          result.textPreview = cut(text, MAX_STORE_TEXT);
        }
        const before = queue.length;
        extractCandidates(text, finalUrl, 'crawler-json', depth);
        result.extracted = Math.max(0, queue.length - before);
      } else {
        if (looksDoc) result.textPreview = cut(text, MAX_STORE_TEXT);
        const before = queue.length;
        extractCandidates(text, finalUrl, result.kind === 'script' ? 'crawler-js' : 'crawler-text', depth);
        result.extracted = Math.max(0, queue.length - before);
      }
    } catch (error) {
      if (String(error?.name) !== 'AbortError') {
        result.error = String(error?.message || error);
        state.crawl.errors.push({ at: now(), url, error: result.error });
      }
    } finally {
      storeCrawlResult(result);
      state.crawl.scanned = seenCrawl.size;
      state.crawl.queued = queue.length;
      crawlController = null;
      render();
    }
  }

  async function crawlLoop() {
    if (state.crawl.running) return crawlerPromise;
    state.crawl.running = true;
    render();

    crawlerPromise = (async () => {
      try {
        while (state.active && seenCrawl.size < MAX_CRAWL) {
          const item = queue.shift();
          state.crawl.queued = queue.length;
          if (!item) {
            await new Promise(r => setTimeout(r, 500));
            if (!queue.length) break;
            continue;
          }
          if (seenCrawl.has(item.url)) continue;
          await crawlOne(item);
          if (!state.active) break;
          await new Promise(r => setTimeout(r, CRAWL_DELAY_MS));
        }
      } finally {
        state.crawl.running = false;
        render();
      }
    })();

    return crawlerPromise;
  }

  function captureableNetworkUrl(raw) {
    if (!sameOrigin(raw) || blocked(raw)) return false;
    try {
      const p = new URL(raw, location.href).pathname;
      return /\/api(?:\/|$)/i.test(p) || DOC_EXT.test(p) || /\/(?:models?|skills?|blueprints?|explore|nvidia)\//i.test(p);
    } catch {
      return false;
    }
  }

  async function captureFetchBody(url, response) {
    if (!captureableNetworkUrl(url)) return null;
    try {
      return scrub((await response.clone().text()).slice(0, MAX_STORE_TEXT));
    } catch (error) {
      return `[response unavailable: ${String(error?.message || error)}]`;
    }
  }

  function installNetworkHooks() {
    const xhrMeta = new WeakMap();

    XMLHttpRequest.prototype.open = function probeOpen(method, url, ...rest) {
      xhrMeta.set(this, {
        kind: 'xhr',
        method: String(method || 'GET').toUpperCase(),
        url: safeUrl(url),
        startedAt: now()
      });
      return originals.xhrOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function probeSend(body) {
      const meta = xhrMeta.get(this) || { kind: 'xhr', method: 'UNKNOWN', url: '', startedAt: now() };
      meta.requestBody = safeBody(body);
      this.addEventListener('loadend', () => {
        try {
          if (state.network.length >= MAX_NETWORK) return;
          meta.completedAt = now();
          meta.status = Number(this.status || 0);
          meta.responseUrl = safeUrl(this.responseURL || meta.url);
          classify(meta.responseUrl, 'xhr');
          if (captureableNetworkUrl(meta.responseUrl)) {
            try {
              if (!this.responseType || this.responseType === 'text') meta.responseBody = scrub((this.responseText || '').slice(0, MAX_STORE_TEXT));
              else if (this.responseType === 'json') meta.responseBody = redact(this.response);
            } catch {}
          }
          state.network.push(meta);
          refresh();
        } catch (error) {
          state.errors.push({ at: now(), area: 'xhr', error: String(error?.message || error) });
        }
      }, { once: true });
      return originals.xhrSend.call(this, body);
    };

    if (originals.fetch) {
      window.fetch = function probeFetch(input, init = {}) {
        const req = typeof Request !== 'undefined' && input instanceof Request ? input : null;
        const meta = {
          kind: 'fetch',
          method: String(init.method || req?.method || 'GET').toUpperCase(),
          url: safeUrl(req?.url || input || ''),
          requestBody: safeBody(init.body),
          startedAt: now()
        };
        const promise = originals.fetch.call(this, input, init);
        promise.then(async response => {
          if (state.network.length >= MAX_NETWORK) return;
          meta.completedAt = now();
          meta.status = Number(response.status || 0);
          meta.responseUrl = safeUrl(response.url || meta.url);
          classify(meta.responseUrl, 'fetch');
          meta.responseBody = await captureFetchBody(meta.responseUrl, response);
          state.network.push(meta);
          refresh();
        }).catch(error => {
          if (state.network.length >= MAX_NETWORK) return;
          meta.completedAt = now();
          meta.error = String(error?.message || error);
          state.network.push(meta);
          render();
        });
        return promise;
      };
    }
  }

  function refresh() {
    if (!state.active) return;
    collectFiles();
    collectTables();
    collectPanels();
    collectLayout();
    discoverDocument(document, location.href, 'dom-refresh', 0);
    state.page = {
      at: now(),
      href: safeUrl(location.href),
      title: document.title,
      readyState: document.readyState,
      files: state.files.length,
      network: state.network.length,
      tables: state.tables.length,
      panels: state.panels.length,
      routes: state.inventory.routes.length
    };
    state.crawl.queued = queue.length;
    render();
  }

  function download() {
    collectFiles();
    collectTables();
    collectPanels();
    collectLayout();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `KCD-NVIDIA-Inventory-Probe-v${VER}-${stamp}.json`;
    const blob = new Blob([JSON.stringify(state, null, 2) + '\n'], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    return fileName;
  }

  function stop() {
    if (!state.active) return { ok: true, alreadyStopped: true };
    state.active = false;
    state.stoppedAt = now();
    try { crawlController?.abort(); } catch {}
    try { observer?.disconnect(); } catch {}
    try { clearInterval(timer); } catch {}
    try { XMLHttpRequest.prototype.open = originals.xhrOpen; } catch {}
    try { XMLHttpRequest.prototype.send = originals.xhrSend; } catch {}
    try { if (originals.fetch) window.fetch = originals.fetch; } catch {}
    render();
    return { ok: true, stoppedAt: state.stoppedAt, dataReady: true };
  }

  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
  }

  function createUi() {
    document.getElementById(UI)?.remove();
    const el = document.createElement('div');
    el.id = UI;
    Object.assign(el.style, {
      position: 'fixed',
      top: '12px',
      right: '12px',
      width: '470px',
      maxHeight: '84vh',
      overflow: 'hidden',
      zIndex: '2147483647',
      background: 'rgba(14,14,17,.97)',
      color: '#fff',
      border: '1px solid #555',
      borderRadius: '10px',
      boxShadow: '0 8px 24px rgba(0,0,0,.5)',
      font: '12px/1.4 Consolas,ui-monospace,monospace'
    });

    el.innerHTML = `
      <div class="head" style="padding:10px 12px;border-bottom:1px solid #444;cursor:move;font-weight:700">
        KCD NVIDIA Inventory Probe v${VER}
      </div>
      <div style="padding:10px 12px">
        <div class="status" style="margin-bottom:8px"></div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">
          <button class="refresh">VERVERS</button>
          <button class="download">DOWNLOAD JSON</button>
          <button class="stop">STOP</button>
        </div>
        <div style="font-weight:700;margin-bottom:4px">Inventory</div>
        <div class="counts" style="display:grid;grid-template-columns:1fr 1fr;gap:2px 10px;margin-bottom:8px"></div>
        <div style="font-weight:700;margin-bottom:4px">Nieuwste gevonden resources</div>
        <div class="files" style="max-height:34vh;overflow:auto;border:1px solid #333;border-radius:6px;padding:6px;background:#09090b"></div>
      </div>
    `;

    document.documentElement.appendChild(el);
    box = el;

    for (const b of el.querySelectorAll('button')) {
      Object.assign(b.style, {
        padding: '6px 8px',
        border: '1px solid #666',
        borderRadius: '5px',
        background: '#222',
        color: '#fff',
        cursor: 'pointer',
        font: 'inherit'
      });
    }

    el.querySelector('.refresh').onclick = refresh;
    el.querySelector('.download').onclick = download;
    el.querySelector('.stop').onclick = stop;

    const head = el.querySelector('.head');
    let drag = null;
    head.addEventListener('pointerdown', e => {
      const r = el.getBoundingClientRect();
      drag = { dx: e.clientX - r.left, dy: e.clientY - r.top };
      head.setPointerCapture?.(e.pointerId);
    });
    head.addEventListener('pointermove', e => {
      if (!drag) return;
      el.style.left = `${Math.max(0, Math.min(innerWidth - el.offsetWidth, e.clientX - drag.dx))}px`;
      el.style.top = `${Math.max(0, Math.min(innerHeight - 40, e.clientY - drag.dy))}px`;
      el.style.right = 'auto';
    });
    head.addEventListener('pointerup', () => { drag = null; });

    render();
  }

  function render() {
    if (!box?.isConnected) return;
    const st = box.querySelector('.status');
    const counts = box.querySelector('.counts');
    const files = box.querySelector('.files');
    const stopBtn = box.querySelector('.stop');

    if (st) {
      st.innerHTML = `
        Status: <b>${state.active ? (state.crawl.running ? 'ACTIEF + DIEPE PUBLIEKE SCAN' : 'ACTIEF') : 'GESTOPT'}</b><br>
        Crawl: ${state.crawl.scanned}/${state.crawl.max} gescand · ${queue.length} in wachtrij<br>
        Netwerk: ${state.network.length} · Tabellen: ${state.tables.length} · Panelen: ${state.panels.length} · Fouten: ${state.errors.length + state.crawl.errors.length}
      `;
    }

    if (counts) {
      const i = state.inventory;
      counts.innerHTML = [
        ['Routes', i.routes.length],
        ['API endpoints', i.apis.length],
        ['Catalog items', i.catalogItems.length],
        ['Models', i.models.length],
        ['Skills', i.skills.length],
        ['Blueprints', i.blueprints.length],
        ['Scripts', i.scripts.length],
        ['Styles', i.styles.length],
        ['Media', i.media.length],
        ['JSON/YAML/MD/TXT', i.contentFiles.length],
        ['Static', i.staticFiles.length],
        ['External hosts', i.externalHosts.length]
      ].map(([k,v]) => `<div>${esc(k)}: <b>${v}</b></div>`).join('');
    }

    if (files) {
      const combined = [
        ...state.inventory.contentFiles.map(x => ({...x, k:'content'})),
        ...state.inventory.media.map(x => ({...x, k:'media'})),
        ...state.inventory.apis.map(x => ({...x, k:'api'})),
        ...state.inventory.catalogItems.map(x => ({...x, k:'catalog'})),
        ...state.inventory.scripts.map(x => ({...x, k:'js'})),
        ...state.inventory.styles.map(x => ({...x, k:'css'}))
      ];
      const seen = new Set();
      const rows = [];
      for (let n = combined.length - 1; n >= 0 && rows.length < 160; n -= 1) {
        const item = combined[n];
        if (seen.has(item.url)) continue;
        seen.add(item.url);
        rows.push(`<div style="padding:3px 0;border-bottom:1px solid #202026"><span style="opacity:.6">[${esc(item.k)}]</span> <span title="${esc(item.url)}">${esc(item.name || nameFromUrl(item.url))}</span></div>`);
      }
      files.innerHTML = rows.join('') || '<span style="opacity:.6">Nog niets gevonden.</span>';
    }

    if (stopBtn) {
      stopBtn.disabled = !state.active;
      stopBtn.style.opacity = stopBtn.disabled ? '.45' : '1';
    }
  }

  installNetworkHooks();

  observer = new MutationObserver(items => {
    let changed = false;
    for (const m of items) {
      if (isUiNode(m.target)) continue;
      if (m.type === 'childList') state.mutations.childList += 1;
      else if (m.type === 'attributes') state.mutations.attributes += 1;
      changed = true;
    }
    if (changed) {
      collectFiles();
      discoverDocument(document, location.href, 'mutation', 0);
      render();
    }
  });

  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    characterData: false
  });

  createUi();
  refresh();
  seedDiscovery();

  timer = setInterval(() => {
    if (!state.active) return;
    refresh();
    if (!state.crawl.running && queue.length && seenCrawl.size < MAX_CRAWL) void crawlLoop();
  }, 3000);

  setTimeout(() => {
    if (state.active) void crawlLoop();
  }, 700);

  window[G] = Object.freeze({
    version: VER,
    status: () => ({
      active: state.active,
      crawlRunning: state.crawl.running,
      crawlScanned: state.crawl.scanned,
      crawlQueued: queue.length,
      files: state.files.length,
      network: state.network.length,
      routes: state.inventory.routes.length,
      apis: state.inventory.apis.length,
      catalogItems: state.inventory.catalogItems.length,
      models: state.inventory.models.length,
      skills: state.inventory.skills.length,
      blueprints: state.inventory.blueprints.length,
      scripts: state.inventory.scripts.length,
      styles: state.inventory.styles.length,
      media: state.inventory.media.length,
      contentFiles: state.inventory.contentFiles.length,
      errors: state.errors.length + state.crawl.errors.length
    }),
    data: () => state,
    refresh,
    download,
    stop,
    resumeCrawl: () => { if (state.active) return crawlLoop(); },
    show: createUi,
    hide: () => document.getElementById(UI)?.remove()
  });

  console.log(`[KCD NVIDIA Inventory Probe v${VER}] actief. Geen automatische clicks; publieke same-origin crawl draait zonder cookies.`);
})();