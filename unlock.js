'use strict';
(() => {
  const byId = id => document.getElementById(id);
  const ownedUrls = [];
  let busy = false, sessionKey=null, sessionGeneration=0;
  const deferredFiles=new Map(), deferredLoads=new Map();
  const decode64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const say = (text, error = false) => { byId('status').textContent = text; byId('status').classList.toggle('error', error); };
  const blobUrl = (bytes, type) => { const url = URL.createObjectURL(new Blob([bytes], {type})); ownedUrls.push(url); return url; };
  const clearUrls = () => { sessionKey=null;sessionGeneration++;deferredFiles.clear();deferredLoads.clear(); ownedUrls.splice(0).forEach(url => URL.revokeObjectURL(url)); };

  async function fetchChecked(url) {
    const response = await fetch(url, {cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer'});
    if (!response.ok) throw new Error('network');
    return response;
  }

  function validPayload(value,prefix) {
    const names=Array.isArray(value)?value:[value];
    return names.length>0&&names.length<=64&&names.every(n=>typeof n==='string'&&new RegExp('^'+prefix+'-[a-f0-9]{16}(?:-[0-9]{2})?\\.bin$').test(n));
  }
  async function fetchCipher(value) {
    const names=Array.isArray(value)?value:[value], parts=new Array(names.length);let next=0;
    await Promise.all(Array.from({length:Math.min(4,names.length)},async()=>{while(next<names.length){const i=next++;parts[i]=new Uint8Array(await(await fetchChecked(names[i])).arrayBuffer());}}));
    const all=new Uint8Array(parts.reduce((n,b)=>n+b.length,0));let offset=0;for(const part of parts){all.set(part,offset);offset+=part.length;}return all;
  }

  function preparePortal(bundle) {
    if(typeof bundle.html !== 'string' || !Array.isArray(bundle.files)) throw new Error('format');
    const urls = new Map(), documents = [];
    for(const file of bundle.files) {
      if(typeof file.path !== 'string' || file.path.startsWith('/') || file.path.split('/').includes('..') || urls.has(file.path)) throw new Error('format');
      if(file.deferred){if(!validPayload(file.payload,'asset'))throw new Error('format');deferredFiles.set(file.path,file);urls.set(file.path,'deferred:'+file.path);}
      else if(file.type.startsWith('text/html')) documents.push(file);
      else urls.set(file.path, blobUrl(decode64(file.data), file.type));
    }
    const resolve = html => html.replace(/asset:\/\/([A-Za-z0-9_.!~*'()%+-]+)/g, (_, encoded) => {
      const url = urls.get(decodeURIComponent(encoded));
      if(!url) throw new Error('missing-attachment');
      return url;
    });
    const htmlDocuments={};
    for(const file of documents){const html=resolve(new TextDecoder().decode(decode64(file.data)));htmlDocuments[file.path]=html;urls.set(file.path,blobUrl(html,file.type));}
    const html=resolve(bundle.html).replace('<script>window.PORTAL_FILES=',()=>'<script>window.PORTAL_DOCUMENTS='+JSON.stringify(htmlDocuments).replace(/</g,'\\u003c')+';window.PORTAL_FILES=');
    return {html};
  }

  function prepareDocument(bundle) {
    if (bundle.version === 2) return preparePortal(bundle);
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

  window.addEventListener('message', async event => {
    if(event.source!==byId('report').contentWindow || event.data?.type!=='portal-asset' || !sessionKey) return;
    const {name,requestId}=event.data, file=deferredFiles.get(name), generation=sessionGeneration;
    if(!file || typeof requestId!=='string')return;
    try {
      if(!deferredLoads.has(name))deferredLoads.set(name,(async()=>{
        const key=sessionKey;
        const bytes=await fetchCipher(file.payload);
        const packed=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode64(file.iv),additionalData:new TextEncoder().encode(file.aad)},key,bytes);
        const raw=await new Response(new Blob([packed]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
        if(generation!==sessionGeneration)throw new Error('locked');
        return blobUrl(raw,file.type);
      })());
      const url=await deferredLoads.get(name);
      if(generation===sessionGeneration)event.source.postMessage({type:'portal-asset-result',requestId,url},'*');
    }catch{deferredLoads.delete(name);if(generation===sessionGeneration)event.source.postMessage({type:'portal-asset-result',requestId,error:true},'*');}
  });

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
      if (config.version !== 1 || config.iterations !== 600000 || !validPayload(config.payload,'payload')) throw new Error('format');
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
      password = ''; byId('password').value = '';
      const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode64(config.salt),iterations:config.iterations,hash:'SHA-256'}, material, {name:'AES-GCM',length:256}, false, ['decrypt']);
      phase = 'password';
      await crypto.subtle.decrypt({name:'AES-GCM',iv:decode64(config.checkIv),additionalData:new TextEncoder().encode('private-document-check-v1')}, key, decode64(config.check));
      say('密码正确，正在打开资料与附件…');
      phase = 'network';
      const ciphertext = await fetchCipher(config.payload);
      phase = 'payload';
      const compressed = await crypto.subtle.decrypt({name:'AES-GCM',iv:decode64(config.iv),additionalData:new TextEncoder().encode('private-document-bundle-v1')}, key, ciphertext);
      const json = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
      const bundle = JSON.parse(json);
      const documentUrl = prepareDocument(bundle);sessionKey=key;
      if(documentUrl.html)byId('report').srcdoc=documentUrl.html;else byId('report').src = documentUrl;
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
    byId('report').removeAttribute('srcdoc');byId('report').removeAttribute('src'); clearUrls();
    byId('viewer').hidden = true; byId('gate').hidden = false;
    byId('password').value = ''; say('已锁定。'); byId('password').focus();
  });
  // Returning through browser history must not restore an unlocked page from bfcache.
  window.addEventListener('pagehide', () => { byId('report').removeAttribute('srcdoc');byId('report').removeAttribute('src'); clearUrls(); byId('viewer').hidden=true; byId('gate').hidden=false; });
})();
