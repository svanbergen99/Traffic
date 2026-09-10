(() => {
  'use strict';

  const G = '__kcdCombinedProbe';
  const UI = '__kcdCombinedProbeUI';
  const VER = '1.2.0';
  const MAX_NETWORK = 500;
  const MAX_FILES = 1500;
  const MAX_BODY = 2 * 1024 * 1024;
  const SENSITIVE = /(authorization|cookie|token|secret|password|passwd|api.?key|session|credential|bearer|csrf|xsrf|saml|oidc|sid)/i;
  const BLOCKED_URL = /(\/login|\/logout|\/signout|\/internal\/security\/|\/api\/security\/|telemetry|user_profile|\/internal\/session)/i;
  const DATA_ENDPOINT = /(\/internal\/bsearch(?:\?|$)|\/internal\/metrics\/vis\/data(?:\?|$)|\/api\/.*(?:traffic|rooster|schedule|queue|collector))/i;

  try { window[G]?.stop?.(); } catch {}

  const originals = {
    fetch: window.fetch,
    xhrOpen: XMLHttpRequest.prototype.open,
    xhrSend: XMLHttpRequest.prototype.send
  };

  const state = {
    name: 'KCD Passive Data Probe',
    version: VER,
    startedAt: new Date().toISOString(),
    stoppedAt: null,
    active: true,
    mode: 'passive-only',
    files: [],
    tables: [],
    panels: [],
    network: [],
    decodedData: [],
    mutations: { childList: 0, attributes: 0 },
    errors: [],
    policy: {
      passiveOnly: true,
      automaticClicks: false,
      requestHeadersCaptured: false,
      responseHeadersCaptured: false,
      cookiesCaptured: false,
      browserStorageCaptured: false,
      typedInputValuesCaptured: false,
      authLikeValuesRedacted: true
    }
  };

  let observer = null;
  let timer = null;
  let box = null;

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

  function cut(value, max = MAX_BODY) {
    const text = String(value ?? '');
    return text.length > max ? `${text.slice(0, max)}\n...[AFGEKAPT]` : text;
  }

  function sanitizeUrl(raw) {
    try {
      const url = new URL(String(raw || ''), location.href);
      for (const key of [...url.searchParams.keys()]) {
        if (SENSITIVE.test(key)) url.searchParams.set(key, '[REDACTED]');
      }
      return url.href;
    } catch {
      return clean(raw, 2000);
    }
  }

  function sanitizeText(value) {
    let text = cut(value);
    text = text.replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]');
    text = text.replace(
      /((?:authorization|auth|token|session(?:id)?|sid|csrf|api[-_]?key|secret|password|credential)\s*["']?\s*[:=]\s*["']?)([^&\s,"'<>}]+)/gi,
      '$1[REDACTED]'
    );
    return text;
  }

  function redact(value, depth = 0) {
    if (depth > 10) return '[MAX_DEPTH]';
    if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'string') return sanitizeText(value);
    if (Array.isArray(value)) return value.slice(0, 1500).map((item) => redact(item, depth + 1));
    if (typeof value === 'object') {
      const out = {};
      for (const [key, item] of Object.entries(value).slice(0, 2500)) {
        out[key] = SENSITIVE.test(key) ? '[REDACTED]' : redact(item, depth + 1);
      }
      return out;
    }
    return String(value);
  }

  function safeBody(body) {
    if (body == null) return null;
    if (typeof body === 'string') {
      try { return redact(JSON.parse(body)); }
      catch { return sanitizeText(body); }
    }
    if (body instanceof URLSearchParams) {
      const out = {};
      for (const [key, value] of body.entries()) {
        out[key] = SENSITIVE.test(key) ? '[REDACTED]' : sanitizeText(value);
      }
      return out;
    }
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      const out = {};
      for (const [key, value] of body.entries()) {
        out[key] = SENSITIVE.test(key)
          ? '[REDACTED]'
          : typeof value === 'string' ? sanitizeText(value) : '[FILE]';
      }
      return out;
    }
    if (body instanceof ArrayBuffer) return `[ArrayBuffer ${body.byteLength}]`;
    try { return redact(body); } catch { return sanitizeText(String(body)); }
  }

  function sameOrigin(raw) {
    try { return new URL(String(raw || ''), location.href).origin === location.origin; }
    catch { return false; }
  }

  function isUiNode(node) {
    const el = node?.nodeType === Node.ELEMENT_NODE ? node : node?.parentElement;
    return Boolean(el?.closest?.(`#${UI}`));
  }

  function visible(el) {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth;
  }

  function collectFiles() {
    const map = new Map();
    const add = (url, type, source) => {
      if (!url) return;
      const safe = sanitizeUrl(url);
      if (BLOCKED_URL.test(safe)) return;
      const key = `${type}|${safe}`;
      if (map.has(key)) return;
      let name = safe;
      try {
        const parsed = new URL(safe, location.href);
        name = decodeURIComponent(parsed.pathname.split('/').filter(Boolean).pop() || parsed.hostname);
      } catch {}
      map.set(key, { name, type, source, url: safe });
    };

    for (const item of document.scripts) add(item.src, 'script', 'dom');
    for (const item of document.querySelectorAll('link[href]')) add(item.href, clean(item.rel, 60) || 'link', 'dom');
    for (const item of document.querySelectorAll('img[src]')) add(item.src, 'image', 'dom');
    for (const item of document.querySelectorAll('a[href$=".json"],a[href$=".js"],a[href$=".css"],a[href$=".map"],a[href$=".wasm"],a[href$=".csv"],a[href$=".yaml"],a[href$=".yml"]')) {
      add(item.href, 'linked-file', 'dom');
    }

    try {
      for (const entry of performance.getEntriesByType('resource')) {
        add(entry.name, clean(entry.initiatorType, 60) || 'resource', 'performance');
      }
    } catch {}

    state.files = [...map.values()].slice(0, MAX_FILES);
  }

  function collectTables() {
    state.tables = [...document.querySelectorAll('table')].slice(0, 100).map((table) => {
      const headers = [...table.querySelectorAll('thead th')].map((cell) => clean(cell.innerText || cell.textContent, 250));
      const rows = [...table.querySelectorAll('tbody tr')].slice(0, 500).map((row) =>
        [...row.querySelectorAll('th,td')].map((cell) => clean(cell.innerText || cell.textContent, 500))
      ).filter((row) => row.length);
      return { headers, rows, fingerprint: hash({ headers, rows }) };
    });
  }

  function collectPanels() {
    const out = [];
    const seen = new Set();
    const candidates = document.querySelectorAll('.embPanel,[data-test-subj*=embeddablePanel],section,article');

    for (const el of candidates) {
      if (!visible(el) || isUiNode(el)) continue;
      const title = clean(
        el.querySelector?.('[data-test-subj=embeddablePanelTitleInner]')?.innerText ||
        el.querySelector?.('h1,h2,h3,h4,header')?.innerText ||
        el.getAttribute?.('aria-label') || el.id,
        220
      );
      const text = clean(el.innerText, 12000);
      if (!title && text.length < 20) continue;
      const key = hash({ title, text: text.slice(0, 1000) });
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ title: title || '(zonder titel)', text, fingerprint: hash(text) });
      if (out.length >= 100) break;
    }

    state.panels = out;
  }

  async function decodeBsearch(text) {
    const raw = String(text || '').trim();
    if (!raw) return [];
    const out = [];
    const chunks = raw.split(/\s+/).filter(Boolean).slice(0, 200);

    for (let index = 0; index < chunks.length; index += 1) {
      const chunk = chunks[index];
      try {
        if (chunk.startsWith('{') || chunk.startsWith('[')) {
          out.push({ index, decoder: 'raw-json', value: redact(JSON.parse(chunk)) });
          continue;
        }
        if (typeof DecompressionStream === 'undefined') continue;
        const normalized = chunk.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
        const decodedText = await new Response(stream).text();
        out.push({ index, decoder: 'deflate-base64', value: redact(JSON.parse(decodedText)) });
      } catch (error) {
        state.errors.push({ at: now(), area: 'bsearch-decode', index, error: String(error?.message || error) });
      }
    }

    return out;
  }

  async function captureFetchBody(url, response) {
    if (!sameOrigin(url) || BLOCKED_URL.test(url) || !DATA_ENDPOINT.test(url)) return null;
    try {
      const text = sanitizeText(await response.clone().text());
      if (/\/internal\/bsearch/i.test(url)) {
        const decoded = await decodeBsearch(text);
        if (decoded.length) state.decodedData.push({ at: now(), url, decoded });
      }
      return text;
    } catch (error) {
      return `[response unavailable: ${String(error?.message || error)}]`;
    }
  }

  function installNetworkHooks() {
    const xhrMeta = new WeakMap();

    XMLHttpRequest.prototype.open = function passiveProbeOpen(method, url, ...rest) {
      xhrMeta.set(this, {
        kind: 'xhr',
        method: String(method || 'GET').toUpperCase(),
        url: sanitizeUrl(url),
        startedAt: now()
      });
      return originals.xhrOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function passiveProbeSend(body) {
      const meta = xhrMeta.get(this) || { kind: 'xhr', method: 'UNKNOWN', url: '', startedAt: now() };
      meta.requestBody = safeBody(body);
      this.addEventListener('loadend', () => {
        try {
          if (state.network.length >= MAX_NETWORK) return;
          meta.completedAt = now();
          meta.status = Number(this.status || 0);
          meta.responseUrl = sanitizeUrl(this.responseURL || meta.url);
          if (sameOrigin(meta.responseUrl) && DATA_ENDPOINT.test(meta.responseUrl) && !BLOCKED_URL.test(meta.responseUrl)) {
            try {
              if (!this.responseType || this.responseType === 'text') meta.responseBody = sanitizeText(this.responseText || '');
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
      window.fetch = function passiveProbeFetch(input, init = {}) {
        const req = typeof Request !== 'undefined' && input instanceof Request ? input : null;
        const meta = {
          kind: 'fetch',
          method: String(init.method || req?.method || 'GET').toUpperCase(),
          url: sanitizeUrl(req?.url || input || ''),
          requestBody: safeBody(init.body),
          startedAt: now()
        };
        const promise = originals.fetch.call(this, input, init);
        promise.then(async (response) => {
          if (state.network.length >= MAX_NETWORK) return;
          meta.completedAt = now();
          meta.status = Number(response.status || 0);
          meta.responseUrl = sanitizeUrl(response.url || meta.url);
          meta.responseBody = await captureFetchBody(meta.responseUrl, response);
          state.network.push(meta);
          refresh();
        }).catch((error) => {
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
    state.page = {
      at: now(),
      href: sanitizeUrl(location.href),
      title: document.title,
      readyState: document.readyState,
      files: state.files.length,
      network: state.network.length,
      tables: state.tables.length,
      panels: state.panels.length,
      decodedData: state.decodedData.length
    };
    render();
  }

  function download() {
    collectFiles();
    collectTables();
    collectPanels();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `KCD-Passive-Data-Probe-v${VER}-${stamp}.json`;
    const blob = new Blob([JSON.stringify(state, null, 2) + '\n'], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    return fileName;
  }

  function stop() {
    if (!state.active) return { ok: true, alreadyStopped: true };
    state.active = false;
    state.stoppedAt = now();
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

  function render() {
    if (!box?.isConnected) return;
    const status = box.querySelector('.status');
    const files = box.querySelector('.files');
    const stopButton = box.querySelector('.stop');

    if (status) {
      status.innerHTML = `Status: <b>${state.active ? 'PASSIEF ACTIEF' : 'GESTOPT'}</b><br>` +
        `Bestanden: ${state.files.length} · Netwerk: ${state.network.length} · Gedecodeerde data: ${state.decodedData.length}<br>` +
        `Tabellen: ${state.tables.length} · Panelen: ${state.panels.length}<br>` +
        `DOM-mutaties: ${state.mutations.childList + state.mutations.attributes} · Fouten: ${state.errors.length}<br>` +
        `<span style="opacity:.7">Klikfunctionaliteit: UIT</span>`;
    }

    if (files) {
      files.innerHTML = state.files.slice(-150).reverse().map((file) =>
        `<div style="padding:3px 0;border-bottom:1px solid #222">` +
        `<span style="opacity:.6">[${esc(file.type)}]</span> ` +
        `<span title="${esc(file.url)}">${esc(file.name)}</span></div>`
      ).join('') || '<span style="opacity:.6">Nog geen resources gevonden</span>';
    }

    if (stopButton) {
      stopButton.disabled = !state.active;
      stopButton.style.opacity = state.active ? '1' : '.45';
    }
  }

  function makeUi() {
    document.getElementById(UI)?.remove();
    box = document.createElement('div');
    box.id = UI;
    Object.assign(box.style, {
      position: 'fixed', top: '12px', right: '12px', width: '430px', maxHeight: '82vh',
      overflow: 'hidden', zIndex: '2147483647', background: 'rgba(14,14,17,.97)', color: '#fff',
      border: '1px solid #555', borderRadius: '10px', boxShadow: '0 8px 24px #0008',
      font: '12px/1.4 Consolas,monospace'
    });

    box.innerHTML = `<div class="head" style="padding:10px 12px;border-bottom:1px solid #444;cursor:move;font-weight:700">` +
      `KCD Passive Data Probe v${VER}</div>` +
      `<div style="padding:10px 12px"><div class="status" style="margin-bottom:8px"></div>` +
      `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">` +
      `<button class="refresh">VERVERS</button><button class="download">DOWNLOAD JSON</button><button class="stop">STOP</button></div>` +
      `<b>Gevonden bestanden/resources</b>` +
      `<div class="files" style="margin-top:5px;max-height:47vh;overflow:auto;border:1px solid #333;border-radius:6px;padding:6px;background:#09090b"></div></div>`;

    document.documentElement.appendChild(box);

    for (const button of box.querySelectorAll('button')) {
      Object.assign(button.style, {
        padding: '6px 8px', border: '1px solid #666', borderRadius: '5px',
        background: '#222', color: '#fff', cursor: 'pointer', font: 'inherit'
      });
    }

    box.querySelector('.refresh').onclick = refresh;
    box.querySelector('.download').onclick = download;
    box.querySelector('.stop').onclick = stop;

    const head = box.querySelector('.head');
    let drag = null;
    head.addEventListener('pointerdown', (event) => {
      const rect = box.getBoundingClientRect();
      drag = { dx: event.clientX - rect.left, dy: event.clientY - rect.top };
      head.setPointerCapture?.(event.pointerId);
    });
    head.addEventListener('pointermove', (event) => {
      if (!drag) return;
      box.style.left = `${Math.max(0, Math.min(innerWidth - box.offsetWidth, event.clientX - drag.dx))}px`;
      box.style.top = `${Math.max(0, Math.min(innerHeight - 40, event.clientY - drag.dy))}px`;
      box.style.right = 'auto';
    });
    head.addEventListener('pointerup', () => { drag = null; });

    render();
  }

  installNetworkHooks();

  observer = new MutationObserver((items) => {
    let changed = false;
    for (const mutation of items) {
      if (isUiNode(mutation.target)) continue;
      if (mutation.type === 'childList') state.mutations.childList += 1;
      else if (mutation.type === 'attributes') state.mutations.attributes += 1;
      changed = true;
    }
    if (changed) {
      collectFiles();
      render();
    }
  });

  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    characterData: false
  });

  makeUi();
  refresh();
  timer = setInterval(refresh, 3000);

  window[G] = Object.freeze({
    name: state.name,
    version: VER,
    status: () => ({
      active: state.active,
      mode: state.mode,
      files: state.files.length,
      network: state.network.length,
      decodedData: state.decodedData.length,
      tables: state.tables.length,
      panels: state.panels.length,
      errors: state.errors.length
    }),
    data: () => state,
    refresh,
    download,
    stop,
    show: makeUi,
    hide: () => document.getElementById(UI)?.remove()
  });

  console.log(`[KCD Passive Data Probe v${VER}] actief; klikfunctionaliteit is uitgeschakeld.`);
})();