'use strict';
(() => {
  const byId = id => document.getElementById(id);
  const ownedUrls = [];
  let busy = false;
  const decode64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const say = (text, error = false) => { byId('status').textContent = text; byId('status').classList.toggle('error', error); };
  const blobUrl = (bytes, type) => { const url = URL.createObjectURL(new Blob([bytes], {type})); ownedUrls.push(url); return url; };
  const clearUrls = () => { ownedUrls.splice(0).forEach(url => URL.revokeObjectURL(url)); };

  async function fetchChecked(url) {
    const response = await fetch(url, {cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer'});
    if (!response.ok) throw new Error('network');
    return response;
  }

  function prepareDocument(bundle) {
    if (bundle.version !== 1 || typeof bundle.html !== 'string' || !Array.isArray(bundle.files)) throw new Error('format');
    const urls = new Map();
    for (const file of bundle.files) {
      if (typeof file.path !== 'string' || file.path.startsWith('/') || file.path.split('/').includes('..')) throw new Error('format');
      urls.set(file.path, blobUrl(decode64(file.data), file.type));
    }
    const mainPattern = /(<script type="application\/json" id="patientData">)([\s\S]*?)(<\/script>)/;
    const match = bundle.html.match(mainPattern);
    if (!match) throw new Error('format');
    const original = JSON.parse(match[2]);
    const oldMarkdown = original.markdown;
    const mapped = value => {
      if (Array.isArray(value)) return value.map(mapped);
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,mapped(v)]));
      if (typeof value !== 'string') return value;
      if (value === oldMarkdown) return urls.get(bundle.markdown) || value;
      let decoded;
      try { decoded = decodeURIComponent(value); } catch { return value; }
      return urls.get(decoded) || value;
    };
    const data = mapped(original);
    for (const report of data.reports) for (const file of report.files) {
      if (!file.url.startsWith('blob:')) throw new Error('missing-attachment');
    }
    let html = bundle.html.replace(mainPattern, (_, start, json, end) => start + JSON.stringify(data).replace(/</g, '\\u003c') + end);
    html = html.replace("img-src 'self' file: data:", "img-src 'self' data: blob:");
    // Referrers contain no document metadata when an external reference is opened.
    html = html.replace('<head>', '<head><meta name="referrer" content="no-referrer">');
    return blobUrl(html, 'text/html;charset=utf-8');
  }

  byId('unlockForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    if (!window.isSecureContext || !crypto.subtle || !window.DecompressionStream) {
      say('请使用较新版本的 Safari 或 Chrome，通过 HTTPS 链接打开。', true); return;
    }
    busy = true; byId('openButton').disabled = true;
    let password = byId('password').value.trim();
    let phase = 'network';
    try {
      say('正在验证密码…');
      const config = await (await fetchChecked('vault.json')).json();
      if (config.version !== 1 || config.iterations !== 600000 || !/^payload-[a-f0-9]{16}\.bin$/.test(config.payload)) throw new Error('format');
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
      password = ''; byId('password').value = '';
      const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode64(config.salt),iterations:config.iterations,hash:'SHA-256'}, material, {name:'AES-GCM',length:256}, false, ['decrypt']);
      phase = 'password';
      await crypto.subtle.decrypt({name:'AES-GCM',iv:decode64(config.checkIv),additionalData:new TextEncoder().encode('private-document-check-v1')}, key, decode64(config.check));
      say('密码正确，正在打开资料与附件…');
      phase = 'network';
      const ciphertext = await (await fetchChecked(config.payload)).arrayBuffer();
      phase = 'payload';
      const compressed = await crypto.subtle.decrypt({name:'AES-GCM',iv:decode64(config.iv),additionalData:new TextEncoder().encode('private-document-bundle-v1')}, key, ciphertext);
      const json = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
      const bundle = JSON.parse(json);
      const documentUrl = prepareDocument(bundle);
      byId('report').src = documentUrl;
      byId('viewer').hidden = false; byId('gate').hidden = true;
      say('');
    } catch (error) {
      clearUrls();
      say(phase === 'password' ? '密码不正确，请重新输入。' : phase === 'network' ? '暂时未能加载，请检查网络后重试。' : '资料未能完整打开，请刷新后重试。', true);
    } finally {
      password = ''; byId('password').value = ''; busy = false; byId('openButton').disabled = false;
    }
  });

  byId('lockButton').addEventListener('click', () => {
    byId('report').removeAttribute('src'); clearUrls();
    byId('viewer').hidden = true; byId('gate').hidden = false;
    byId('password').value = ''; say('已锁定。'); byId('password').focus();
  });
  // Returning through browser history must not restore an unlocked page from bfcache.
  window.addEventListener('pagehide', () => { byId('report').removeAttribute('src'); clearUrls(); byId('viewer').hidden=true; byId('gate').hidden=false; });
})();
