(() => {
  'use strict';

  const G='__kcdHyperrealExplorer';
  const OLD=['__kcdAdaptiveProbe','__kcdNvidiaProbe','__kcdCombinedProbe','__kcdHyperrealProbe'];
  const UI='__kcdHyperrealExplorerUI';
  const VER='1.6.0';

  const C={
    minDelayMs:50,
    maxDelayMs:2000,
    concurrency:6,
    maxCrawl:5000,
    maxQueue:25000,
    maxFindings:12000,
    maxFiles:12000,
    maxNetwork:2500,
    maxJsCssCrawl:700,
    maxScrollSteps:600,
    scrollStepRatio:0.85,
    scrollDelayMs:100,
    bottomSettleMs:650,
    maxSafeClicks:80,
    refreshMs:800,
    maxResponseChars:500000,
    maxStoredSnippetChars:5000
  };

  const TOPICS={
    video:/\b(video|text[- ]?to[- ]?video|image[- ]?to[- ]?video|video[- ]?to[- ]?video|frame interpolation|temporal|motion control|camera motion|fps|frame rate|seedance|kling|wan|veo|sora|minimax|hailuo|runway|luma|pika|ray2|ray3)\b/i,
    rendering:/\b(render|rendering|renderer|ray ?trac|path ?trac|raster|denois|sampling|samples per pixel|spp|anti[- ]?alias|supersampl|upscal|super[- ]?resolution|dlss|fsr|optix|cycles|eevee|arnold|redshift|octane|v[- ]?ray)\b/i,
    shading:/\b(shader|shading|material|materials|texture|texturing|pbr|physically based|roughness|metallic|normal map|height map|displacement|bump map|albedo|base color|specular|subsurface|sss|transmission|ior|anisotrop|clearcoat|emission|uv|procedural texture)\b/i,
    lighting:/\b(light|lighting|hdr|hdri|global illumination|gi\b|indirect light|volumetric|caustic|area light|key light|fill light|rim light|softbox|environment map|exposure|white balance)\b/i,
    realism:/\b(hyperreal|hyper-real|photoreal|photo-real|realistic|cinematic|film look|skin detail|skin texture|pores|microdetail|micro-detail|physically accurate|real-world scale|depth of field|bokeh|lens|focal length|aperture|shutter|iso\b)\b/i,
    post:/\b(composit|compositor|color grad|colour grad|lut\b|tone map|tonemap|post[- ]?process|postprocess|motion blur|chromatic aberration|film grain|bloom|glare|vfx|alpha|masking|rotoscop|keying|depth pass|normal pass|aov|render pass)\b/i,
    workflow:/\b(comfyui|workflow|node graph|pipeline|controlnet|lora|vae|checkpoint|diffusion|sampler|scheduler|prompt|negative prompt|guidance|cfg\b|steps\b|seed\b|inference|latent|img2img|txt2img|inpaint|outpaint|reference image|style reference|pose control|depth control)\b/i,
    geometry:/\b(mesh|geometry|topology|retopo|retopology|subdivision|sculpt|3d\b|point cloud|gaussian splat|nerf|photogrammetry|rigging|animation|simulation|cloth|hair|fur|particle|fluid|smoke|fire)\b/i
  };
  const ANY=new RegExp(Object.values(TOPICS).map(r=>r.source).join('|'),'i');

  const SENSITIVE=/(authorization|cookie|token|secret|password|passwd|api.?key|session|credential|bearer|csrf|xsrf|saml|oidc|sid)/i;
  const BLOCK_PATH=/(\/login|\/logout|\/signout|\/signin|\/account|\/profile|\/settings|\/billing|\/checkout|\/oauth|\/auth(?:\/|$)|\/token|\/session|\/admin|\/password|\/verify|\/invite|\/purchase|\/payment)/i;
  const BLOCK_HOST=/(doubleclick|googlesyndication|googleadservices|googletagmanager|clarity\.ms|bing\.com|bing\.net|facebook\.com|facebook\.net|segment\.|amplitude\.|cookielaw|snapchat|licdn\.com|hotjar|contentsquare)/i;
  const BLOCK_BINARY=/\.(?:safetensors|bin|pt|pth|ckpt|onnx|gguf|h5|npz|npy|zip|tar|gz|bz2|xz|7z|rar|exe|dmg|iso)(?:$|\?)/i;
  const TEXT_EXT=/\.(?:html?|json|ya?ml|md|txt|xml|csv|js|mjs|css)(?:$|\?)/i;
  const MEDIA_EXT=/\.(?:mp4|webm|mov|m4v|m3u8|jpg|jpeg|png|webp|gif|svg|avif)(?:$|\?)/i;
  const RELEVANT_PATH=/(video|image|render|shader|material|texture|light|cinematic|photo|real|prompt|workflow|comfy|model|effect|3d|motion|camera|upscal|denois|diffusion|controlnet|lora|vae|inference|gallery|example|template|tool)/i;
  const SAFE_CLICK_TEXT=/\b(show more|load more|view more|more examples|examples|gallery|preview|details|model card|technical details|expand|see more|read more|show details)\b/i;
  const DANGEROUS_CLICK=/\b(generate|create|start|run|submit|send|save|download|upload|buy|purchase|subscribe|checkout|login|sign in|sign up|delete|remove|edit|update|publish|share|apply|install|deploy|try now|use model)\b/i;

  for(const k of [G,...OLD]){try{window[k]?.stop?.()}catch{}}

  const nativeFetch=typeof window.fetch==='function'?window.fetch.bind(window):null;
  const origFetch=window.fetch;
  const origXOpen=XMLHttpRequest.prototype.open;
  const origXSend=XMLHttpRequest.prototype.send;
  const origPush=history.pushState;
  const origReplace=history.replaceState;

  const st={
    name:'KCD Hyperreal Explorer Probe',
    version:VER,
    startedAt:new Date().toISOString(),
    stoppedAt:null,
    active:true,
    crawling:false,
    autoScroll:true,
    safeClicks:true,
    currentOrigin:location.origin,
    currentDelayMs:C.minDelayMs,
    visitedOrigins:[],
    findings:[],
    files:[],
    routes:[],
    media:[],
    network:[],
    crawl:[],
    viewport:[],
    scroll:{running:false,steps:0,bottomRounds:0,maxY:0,lastHeight:0},
    clicks:[],
    errors:[],
    stats:{},
    policy:{
      hyperrealMediaOnly:true,
      publicGetOnly:true,
      sameOriginCrawl:true,
      credentialsOmitted:true,
      requestHeadersCaptured:false,
      responseHeadersCaptured:false,
      cookiesCaptured:false,
      browserStorageCaptured:false,
      typedInputValuesCaptured:false,
      accountAndAuthPathsBlocked:true,
      largeModelBinariesBlocked:true,
      trackerHostsIgnored:true,
      safeUiExpansionOnly:true,
      destructiveAndGenerationActionsBlocked:true,
      adaptiveBackoff:true
    }
  };

  const M={
    findings:new Map(), files:new Map(), routes:new Map(), media:new Map(),
    crawled:new Set(), queued:new Set(), origins:new Set(), clicked:new Set()
  };
  let q=[],workers=0,stopCrawl=false,scrollStop=false,obs,refreshTimer,navTimer,jsCssCount=0;
  let throttleChain=Promise.resolve(),nextRequestAt=0,lastLocation=location.href;

  const now=()=>new Date().toISOString();
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const clean=(v,n=500)=>String(v??'').replace(/\s+/g,' ').trim().slice(0,n);

  function hash(v){
    let s; try{s=typeof v==='string'?v:JSON.stringify(v)}catch{s=String(v)}
    let h=2166136261; for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}
    return (h>>>0).toString(16).padStart(8,'0');
  }

  function safeUrl(raw,base=location.href){
    try{
      const u=new URL(String(raw||''),base);
      if(!/^https?:$/.test(u.protocol))return null;
      for(const k of [...u.searchParams.keys()]){
        if(SENSITIVE.test(k))u.searchParams.set(k,'[REDACTED]');
        if(/^(utm_|gclid$|fbclid$|msclkid$|_rsc$|ref$|source$|campaign$)/i.test(k))u.searchParams.delete(k);
      }
      u.hash='';
      return u.href;
    }catch{return null}
  }

  function blocked(url){
    try{
      const u=new URL(url);
      return BLOCK_PATH.test(u.pathname)||BLOCK_BINARY.test(u.pathname)||BLOCK_HOST.test(u.hostname);
    }catch{return true}
  }

  function categories(text){
    const out=[]; const s=String(text||'');
    for(const [k,r] of Object.entries(TOPICS))if(r.test(s))out.push(k);
    return out;
  }

  function relevance(text){
    const cats=categories(text);
    let score=cats.length*3;
    const s=String(text||'');
    if(/\b(hyperreal|photoreal|cinematic|render|shader|shading|pbr|ray ?trac|path ?trac|lighting|video|comfyui|controlnet)\b/i.test(s))score+=3;
    if(/\b(example|workflow|settings|parameters|prompt|guide|tutorial|model|technical|documentation)\b/i.test(s))score+=1;
    return {score,categories:cats};
  }

  function addFinding(kind,url,text,source='discovery',extra={}){
    const snippet=clean(text,C.maxStoredSnippetChars);
    const rel=relevance(`${url||''} ${snippet}`);
    if(!rel.categories.length)return;
    const u=url?safeUrl(url)||url:null;
    const key=hash({kind,u,snippet:snippet.slice(0,1400)});
    if(M.findings.has(key))return;
    M.findings.set(key,{kind,url:u,source,categories:rel.categories,score:rel.score,text:snippet,...extra});
    if(M.findings.size>C.maxFindings){
      const first=M.findings.keys().next().value;
      M.findings.delete(first);
    }
  }

  function addRoute(url,source='discovery',label=''){
    const u=safeUrl(url); if(!u||blocked(u))return;
    const rel=relevance(`${u} ${label}`);
    if(rel.categories.length&&!M.routes.has(u)){
      M.routes.set(u,{url:u,source,label:clean(label,300),categories:rel.categories,score:rel.score});
      addFinding('route',u,label||u,source);
    }
  }

  function addFile(url,type='resource',source='dom',context=''){
    const u=safeUrl(url); if(!u||blocked(u))return;
    const name=(()=>{try{return decodeURIComponent(new URL(u).pathname.split('/').filter(Boolean).pop()||new URL(u).hostname)}catch{return u}})();
    const rel=relevance(`${u} ${name} ${context}`);
    if(!rel.categories.length)return;
    const key=`${type}|${u}`;
    if(!M.files.has(key))M.files.set(key,{name,type,source,url:u,categories:rel.categories,score:rel.score,context:clean(context,500)});
    if(MEDIA_EXT.test(new URL(u).pathname)&&!M.media.has(u))M.media.set(u,{url:u,type,source,categories:rel.categories,context:clean(context,500)});
  }

  function sync(){
    st.findings=[...M.findings.values()].sort((a,b)=>b.score-a.score).slice(0,C.maxFindings);
    st.files=[...M.files.values()].slice(0,C.maxFiles);
    st.routes=[...M.routes.values()];
    st.media=[...M.media.values()];
    st.visitedOrigins=[...M.origins];
    const catCounts={};
    for(const k of Object.keys(TOPICS))catCounts[k]=st.findings.filter(x=>x.categories.includes(k)).length;
    st.stats={
      origin:st.currentOrigin,
      queue:q.length,workers,crawled:M.crawled.size,
      findings:st.findings.length,files:st.files.length,routes:st.routes.length,media:st.media.length,
      network:st.network.length,delayMs:Math.round(st.currentDelayMs),
      scrollSteps:st.scroll.steps,autoScroll:st.autoScroll,safeClicks:st.safeClicks,clicks:st.clicks.length,
      errors:st.errors.length,categories:catCounts
    };
  }

  function shouldQueue(url,context=''){
    const u=safeUrl(url); if(!u||blocked(u))return false;
    const p=new URL(u);
    if(p.origin!==st.currentOrigin)return false;
    if(M.crawled.has(u)||M.queued.has(u))return false;
    if(M.crawled.size+q.length>=C.maxQueue)return false;
    if(/\/(?:robots\.txt|sitemap(?:[^/]*)\.xml|llms\.txt)$/i.test(p.pathname))return true;
    if(/\.m?js$|\.css$/i.test(p.pathname))return jsCssCount<C.maxJsCssCrawl;
    return RELEVANT_PATH.test(`${p.pathname} ${p.search} ${context}`)||ANY.test(context);
  }

  function queue(url,source='crawl',context=''){
    if(!st.active||M.crawled.size>=C.maxCrawl)return;
    const u=safeUrl(url); if(!u||!shouldQueue(u,context))return;
    const p=new URL(u);
    if(/\.m?js$|\.css$/i.test(p.pathname))jsCssCount++;
    M.queued.add(u);
    q.push({url:u,source,context:clean(context,400)});
    addRoute(u,source,context);
  }

  function scanDom(root=document,base=location.href,source='dom'){
    const els=root.querySelectorAll?.('a[href],link[href],script[src],img[src],source[src],video[src],figure,article,section,[role=tabpanel],[role=dialog]')||[];
    for(const el of els){
      const context=clean(
        el.getAttribute?.('alt')||el.getAttribute?.('aria-label')||el.getAttribute?.('title')||
        el.closest?.('article,section,figure,[class*=card],[class*=model],[class*=video],[class*=gallery]')?.innerText||
        el.textContent||'',1000
      );
      const raw=el.getAttribute?.('href')||el.getAttribute?.('src');
      if(raw){
        const u=safeUrl(raw,base);
        if(u){
          addFile(u,el.tagName?.toLowerCase()||'resource',source,context);
          addRoute(u,source,context);
          queue(u,source,context);
        }
      }
      if(context&&ANY.test(context))addFinding('dom',base,context,source,{tag:el.tagName?.toLowerCase()||null});
    }
  }

  function scanViewport(){
    if(!st.active)return;
    const seen=new Set(),hits=[];
    const cols=6,rows=5;
    for(let yi=0;yi<rows;yi++)for(let xi=0;xi<cols;xi++){
      const x=Math.min(innerWidth-1,Math.round((xi+.5)*innerWidth/cols));
      const y=Math.min(innerHeight-1,Math.round((yi+.5)*innerHeight/rows));
      for(const el of document.elementsFromPoint(x,y).slice(0,8)){
        if(!el||el.closest?.('#'+UI))continue;
        const target=el.closest?.('article,section,figure,[role=tabpanel],[class*=card],[class*=model],[class*=video],[class*=gallery],div')||el;
        if(seen.has(target))continue; seen.add(target);
        const text=clean(
          `${target.getAttribute?.('aria-label')||''} ${target.getAttribute?.('title')||''} ${target.innerText||target.textContent||''}`,
          1800
        );
        const rel=relevance(text);
        if(!rel.categories.length)continue;
        const media=[...target.querySelectorAll?.('img[src],video[src],source[src]')||[]].slice(0,12).map(m=>safeUrl(m.getAttribute('src'))).filter(Boolean);
        const rec={at:now(),x,y,categories:rel.categories,score:rel.score,text:clean(text,1200),media};
        hits.push(rec);
        addFinding('viewport',location.href,text,'viewport',{media});
        for(const u of media)addFile(u,'visible-media','viewport',text);
      }
    }
    if(hits.length)st.viewport.push(...hits);
    if(st.viewport.length>1000)st.viewport=st.viewport.slice(-1000);
    sync(); render();
  }

  function extractTextRoutes(body,base,source='crawl-text'){
    const text=String(body||'').slice(0,C.maxResponseChars);
    const urlRe=/(https?:\/\/[^\s"'`<>\\)]+|\/(?:api|models?|model|video|image|tools?|prompts?|effects?|explore|gallery|examples?|workflows?|render|shader|materials?|textures?|lighting|docs?)[A-Za-z0-9_./?&=%+:#~-]*)/gi;
    let m,n=0;
    while((m=urlRe.exec(text))&&n++<2500){
      const u=safeUrl(m[1],base); if(!u)continue;
      const around=text.slice(Math.max(0,m.index-180),Math.min(text.length,m.index+m[1].length+240));
      if(!ANY.test(`${u} ${around}`)&&!RELEVANT_PATH.test(u))continue;
      addRoute(u,source,around);
      addFile(u,'discovered',source,around);
      queue(u,source,around);
    }
    if(ANY.test(text)){
      const relSnippet=(text.match(/.{0,300}(?:video|render|shader|shading|material|texture|lighting|photoreal|hyperreal|cinematic|comfyui|controlnet|workflow|motion control).{0,700}/is)||[])[0];
      if(relSnippet)addFinding('content',base,relSnippet,source);
    }
  }

  function parseHtml(raw,base){
    try{
      const d=new DOMParser().parseFromString(raw,'text/html');
      scanDom(d,base,'crawl-html');
      const title=clean(d.title,300);
      const body=clean(d.body?.innerText||'',10000);
      if(ANY.test(`${title} ${body}`))addFinding('page',base,`${title}\n${body}`,'crawl-html');
    }catch{}
    extractTextRoutes(raw,base,'crawl-html-source');
  }

  function parseSitemap(raw,base){
    try{
      const d=new DOMParser().parseFromString(raw,'application/xml');
      for(const loc of d.querySelectorAll('loc')){
        const u=safeUrl(loc.textContent,base);
        if(u&&shouldQueue(u,loc.textContent))queue(u,'sitemap',loc.textContent);
      }
    }catch{}
  }

  async function throttle(){
    const job=async()=>{
      const wait=Math.max(0,nextRequestAt-Date.now());
      if(wait)await sleep(wait);
      nextRequestAt=Date.now()+Math.max(C.minDelayMs,st.currentDelayMs);
    };
    throttleChain=throttleChain.then(job,job);
    return throttleChain;
  }

  async function crawlOne(item){
    if(!st.active||stopCrawl||M.crawled.size>=C.maxCrawl||!nativeFetch)return;
    const url=item.url;
    M.crawled.add(url);
    M.queued.delete(url);
    await throttle();

    const t=performance.now();
    const rec={at:now(),url,source:item.source,status:null,contentType:null,durationMs:null,relevant:false,error:null};

    try{
      const r=await nativeFetch(url,{
        method:'GET',
        credentials:'omit',
        redirect:'follow',
        cache:'no-store',
        headers:{Accept:'text/html,application/json,text/plain,application/xml,text/css,application/javascript;q=0.9,*/*;q=0.3'}
      });
      rec.status=r.status;
      rec.contentType=r.headers.get('content-type')||'';
      rec.finalUrl=safeUrl(r.url||url)||url;

      if(r.status===429||r.status===503){
        st.currentDelayMs=Math.min(C.maxDelayMs,Math.max(200,st.currentDelayMs*2));
      }else if(r.status===403){
        st.currentDelayMs=Math.min(C.maxDelayMs,Math.max(250,st.currentDelayMs*1.5));
      }else if(r.ok&&st.currentDelayMs>C.minDelayMs){
        st.currentDelayMs=Math.max(C.minDelayMs,Math.round(st.currentDelayMs*.90));
      }

      const ct=rec.contentType.toLowerCase();
      const path=new URL(rec.finalUrl).pathname;
      const textish=ct.includes('text')||ct.includes('json')||ct.includes('xml')||ct.includes('javascript')||ct.includes('css')||TEXT_EXT.test(path)||!ct;

      if(textish&&!BLOCK_BINARY.test(path)){
        const raw=(await r.text()).slice(0,C.maxResponseChars);
        rec.relevant=ANY.test(`${rec.finalUrl} ${raw}`)||RELEVANT_PATH.test(rec.finalUrl);

        if(/sitemap.*\.xml$/i.test(path)||ct.includes('xml'))parseSitemap(raw,rec.finalUrl);
        if(ct.includes('html')||/\.html?$/i.test(path)||/<html[\s>]/i.test(raw))parseHtml(raw,rec.finalUrl);
        else extractTextRoutes(raw,rec.finalUrl,'crawl-text');

        if(rec.relevant){
          const snippet=(raw.match(/.{0,350}(?:video|render|shader|shading|material|texture|lighting|photoreal|hyperreal|cinematic|workflow|comfyui|controlnet|motion control).{0,1200}/is)||[])[0]||raw.slice(0,1500);
          addFinding('crawl',rec.finalUrl,snippet,'crawl',{status:r.status,contentType:rec.contentType});
        }
      }
    }catch(e){
      rec.error=String(e?.message||e);
      st.errors.push({at:now(),area:'crawl',url,error:rec.error});
      if(st.errors.length>1000)st.errors=st.errors.slice(-1000);
      st.currentDelayMs=Math.min(C.maxDelayMs,Math.max(100,st.currentDelayMs*1.2));
    }finally{
      rec.durationMs=Math.round(performance.now()-t);
      st.crawl.push(rec);
      if(st.crawl.length>C.maxCrawl)st.crawl=st.crawl.slice(-C.maxCrawl);
      sync(); render();
    }
  }

  async function worker(){
    workers++;
    try{
      while(st.active&&!stopCrawl&&M.crawled.size<C.maxCrawl){
        const item=q.shift();
        if(!item)break;
        await crawlOne(item);
      }
    }finally{
      workers--;
      sync(); render();
    }
  }

  function startCrawl(){
    if(!st.active)return;
    stopCrawl=false; st.crawling=true;
    const jobs=[];
    for(let i=0;i<C.concurrency;i++)jobs.push(worker());
    Promise.all(jobs).finally(()=>{
      st.crawling=false;
      sync(); render();
      if(st.active&&!stopCrawl&&q.length&&M.crawled.size<C.maxCrawl)setTimeout(startCrawl,50);
    });
  }

  function seed(){
    st.currentOrigin=location.origin;
    M.origins.add(st.currentOrigin);
    q=[]; M.queued.clear(); M.crawled.clear(); jsCssCount=0;
    const seeds=[location.href,'/robots.txt','/sitemap.xml','/llms.txt'];
    const h=location.hostname.toLowerCase();

    if(h==='domer.io'||h.endsWith('.domer.io')){
      seeds.push('/ai-video-generator','/text-to-video','/image-to-video','/ai-video','/models','/tools','/prompts/media/video','/prompts/categories/photography','/prompts/categories/illustration-and-3d','/effects');
    }else if(h==='toolkit.artlist.io'){
      seeds.push('/new?mode=video','/image-video-generator?mode=video');
    }else if(h==='build.nvidia.com'){
      seeds.push('/models','/skills','/explore/discover','/blueprints');
    }else if(h==='huggingface.co'){
      seeds.push('/models?pipeline_tag=text-to-video','/models?pipeline_tag=image-to-video','/spaces?sort=trending');
    }

    for(const u of seeds)queue(u,'seed',u);
    scanDom(document,location.href,'dom');
    for(const s of document.scripts){
      const u=safeUrl(s.src);
      if(u&&new URL(u).origin===st.currentOrigin&&jsCssCount<C.maxJsCssCrawl){
        M.queued.delete(u);
        queue(u,'loaded-script','render video image workflow model');
      }
    }
    sync(); render();
    if(q.length)startCrawl();
    if(st.autoScroll)startAutoScroll();
  }

  async function safeExpandVisible(){
    if(!st.active||!st.safeClicks||st.clicks.length>=C.maxSafeClicks)return;
    const candidates=[...document.querySelectorAll('button,[role=button],[role=tab],summary')].filter(el=>{
      if(!el.isConnected||el.disabled||el.closest?.('#'+UI))return false;
      const r=el.getBoundingClientRect();
      if(r.width<2||r.height<2||r.bottom<0||r.top>innerHeight)return false;
      const own=clean(`${el.innerText||el.textContent||''} ${el.getAttribute('aria-label')||''} ${el.getAttribute('title')||''}`,300);
      if(!SAFE_CLICK_TEXT.test(own)||DANGEROUS_CLICK.test(own))return false;
      const ctx=clean(el.closest?.('article,section,[class*=card],[class*=model],[class*=video],[class*=gallery]')?.innerText||own,1200);
      return ANY.test(ctx);
    });

    for(const el of candidates.slice(0,8)){
      if(st.clicks.length>=C.maxSafeClicks)break;
      const key=hash({text:clean(el.innerText||el.textContent,300),aria:el.getAttribute('aria-label'),title:el.getAttribute('title'),path:location.pathname});
      if(M.clicked.has(key))continue;
      M.clicked.add(key);
      const label=clean(`${el.innerText||el.textContent||''} ${el.getAttribute('aria-label')||''}`,300);
      try{
        el.click();
        st.clicks.push({at:now(),label,key,path:location.pathname});
        await sleep(250);
        scanViewport(); scanDom(document,location.href,'safe-click');
      }catch(e){
        st.errors.push({at:now(),area:'safe-click',label,error:String(e?.message||e)});
      }
    }
  }

  async function startAutoScroll(){
    if(!st.active||!st.autoScroll||st.scroll.running)return;
    scrollStop=false; st.scroll.running=true; st.scroll.bottomRounds=0;
    try{
      while(st.active&&st.autoScroll&&!scrollStop&&st.scroll.steps<C.maxScrollSteps){
        scanViewport();
        await safeExpandVisible();

        const beforeY=scrollY;
        const beforeH=Math.max(document.documentElement.scrollHeight,document.body?.scrollHeight||0);
        const step=Math.max(420,Math.round(innerHeight*C.scrollStepRatio));
        window.scrollBy({top:step,left:0,behavior:'auto'});
        st.scroll.steps++;
        st.scroll.maxY=Math.max(st.scroll.maxY,scrollY);
        await sleep(C.scrollDelayMs);

        const afterH=Math.max(document.documentElement.scrollHeight,document.body?.scrollHeight||0);
        const atBottom=scrollY+innerHeight>=afterH-8 || scrollY===beforeY;

        if(atBottom){
          await sleep(C.bottomSettleMs);
          scanViewport(); scanDom(document,location.href,'scroll-bottom');
          const settledH=Math.max(document.documentElement.scrollHeight,document.body?.scrollHeight||0);
          if(settledH<=afterH+4)st.scroll.bottomRounds++;
          else st.scroll.bottomRounds=0;
          if(st.scroll.bottomRounds>=4)break;
        }else{
          st.scroll.bottomRounds=0;
        }
        st.scroll.lastHeight=afterH;
        sync(); render();
      }
    }finally{
      st.scroll.running=false;
      sync(); render();
    }
  }

  function installNetworkHooks(){
    const xm=new WeakMap();

    XMLHttpRequest.prototype.open=function(method,url,...rest){
      xm.set(this,{kind:'xhr',method:String(method||'GET').toUpperCase(),url:safeUrl(url),startedAt:now()});
      return origXOpen.call(this,method,url,...rest);
    };
    XMLHttpRequest.prototype.send=function(body){
      const meta=xm.get(this)||{kind:'xhr',method:'UNKNOWN',url:null,startedAt:now()};
      this.addEventListener('loadend',()=>{
        if(!st.active||st.network.length>=C.maxNetwork)return;
        const u=safeUrl(this.responseURL||meta.url);
        const desc=`${meta.method} ${u||''}`;
        if(u&&!blocked(u)&&ANY.test(desc)){
          st.network.push({...meta,responseUrl:u,status:Number(this.status||0),completedAt:now(),categories:categories(desc)});
          addFinding('network',u,desc,'xhr');
          sync(); render();
        }
      },{once:true});
      return origXSend.call(this,body);
    };

    if(origFetch){
      window.fetch=function(input,init={}){
        const req=(typeof Request!=='undefined'&&input instanceof Request)?input:null;
        const u=safeUrl(req?.url||input||'');
        const method=String(init.method||req?.method||'GET').toUpperCase();
        const p=Reflect.apply(origFetch,window,[input,init]);
        p.then(r=>{
          if(!st.active||st.network.length>=C.maxNetwork)return;
          const ru=safeUrl(r.url||u);
          const desc=`${method} ${ru||''} ${r.headers?.get?.('content-type')||''}`;
          if(ru&&!blocked(ru)&&ANY.test(desc)){
            st.network.push({kind:'fetch',method,url:u,responseUrl:ru,status:r.status,contentType:r.headers?.get?.('content-type')||'',at:now(),categories:categories(desc)});
            addFinding('network',ru,desc,'fetch');
            sync(); render();
          }
        }).catch(()=>{});
        return p;
      };
    }
  }

  function onNavigation(){
    if(location.href===lastLocation)return;
    lastLocation=location.href;
    if(location.origin!==st.currentOrigin){
      stopCrawl=true; scrollStop=true;
      setTimeout(()=>{if(st.active){st.currentOrigin=location.origin;seed()}},400);
    }else{
      setTimeout(()=>{if(st.active){scanDom(document,location.href,'navigation');scanViewport();if(st.autoScroll)startAutoScroll();sync();render()}},250);
    }
  }

  function installNavHooks(){
    history.pushState=function(...a){const r=origPush.apply(this,a);setTimeout(onNavigation,0);return r};
    history.replaceState=function(...a){const r=origReplace.apply(this,a);setTimeout(onNavigation,0);return r};
    addEventListener('popstate',onNavigation);
    addEventListener('hashchange',onNavigation);
    navTimer=setInterval(onNavigation,500);
  }

  function download(){
    sync();
    const name=`KCD-Hyperreal-Explorer-v${VER}-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
    const blob=new Blob([JSON.stringify(st,null,2)+'\n'],{type:'application/json'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download=name;a.style.display='none';
    document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);
    return name;
  }

  function stop(){
    if(!st.active)return {ok:true,alreadyStopped:true};
    st.active=false; st.stoppedAt=now(); stopCrawl=true; scrollStop=true; st.autoScroll=false;
    try{obs?.disconnect()}catch{}
    try{clearInterval(refreshTimer)}catch{}
    try{clearInterval(navTimer)}catch{}
    try{window.fetch=origFetch}catch{}
    try{XMLHttpRequest.prototype.open=origXOpen;XMLHttpRequest.prototype.send=origXSend}catch{}
    try{history.pushState=origPush;history.replaceState=origReplace}catch{}
    sync(); render();
    return {ok:true,stoppedAt:st.stoppedAt};
  }

  function toggleScroll(){
    st.autoScroll=!st.autoScroll;
    scrollStop=!st.autoScroll;
    if(st.autoScroll)startAutoScroll();
    sync();render();
  }

  function toggleClicks(){st.safeClicks=!st.safeClicks;sync();render()}

  function render(){
    const box=document.getElementById(UI); if(!box)return;
    const s=st.stats||{},c=s.categories||{};
    box.querySelector('.status').innerHTML=`
      <div><b>KCD Hyperreal Explorer v${VER}</b> — ${st.active?'ACTIEF':'GESTOPT'}</div>
      <div>Crawl: ${s.crawled||0}/${C.maxCrawl} · Queue: ${s.queue||0} · Workers: ${s.workers||0} · ${s.delayMs||0}ms</div>
      <div>Findings: ${s.findings||0} · Files: ${s.files||0} · Routes: ${s.routes||0} · Media: ${s.media||0}</div>
      <div>Scroll: ${s.scrollSteps||0} stappen · clicks: ${s.clicks||0} · errors: ${s.errors||0}</div>
      <div>Video ${c.video||0} · Render ${c.rendering||0} · Shading ${c.shading||0} · Licht ${c.lighting||0}</div>
      <div>Realism ${c.realism||0} · Post ${c.post||0} · Workflow ${c.workflow||0} · 3D ${c.geometry||0}</div>`;
    const list=box.querySelector('.list');
    list.innerHTML=st.findings.slice(0,80).map(x=>`<div style="padding:3px 0;border-bottom:1px solid #202026"><span style="opacity:.55">[${x.categories.join(',')}]</span> ${esc(x.text||x.url||'')}</div>`).join('')||'<div style="opacity:.6">Nog geen relevante findings.</div>';
    const sb=box.querySelector('.scroll'); if(sb)sb.textContent=`SCROLL ${st.autoScroll?'AAN':'UIT'}`;
    const cb=box.querySelector('.clicks'); if(cb)cb.textContent=`SAFE CLICKS ${st.safeClicks?'AAN':'UIT'}`;
  }

  function esc(v){return String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;')}

  function ui(){
    document.getElementById(UI)?.remove();
    const box=document.createElement('div');box.id=UI;
    Object.assign(box.style,{position:'fixed',top:'10px',right:'10px',width:'470px',maxHeight:'84vh',overflow:'hidden',zIndex:'2147483647',background:'rgba(12,12,15,.97)',color:'#fff',border:'1px solid #555',borderRadius:'10px',boxShadow:'0 8px 28px rgba(0,0,0,.4)',font:'12px/1.4 ui-monospace,Consolas,monospace'});
    box.innerHTML=`<div style="padding:10px 12px;border-bottom:1px solid #444;font-weight:700">Hyperreal Explorer</div><div style="padding:10px 12px"><div class="status"></div><div style="display:flex;gap:5px;flex-wrap:wrap;margin:9px 0"><button class="scroll"></button><button class="clicks"></button><button class="crawl">CRAWL</button><button class="download">DOWNLOAD JSON</button><button class="stop">STOP</button></div><div class="list" style="max-height:48vh;overflow:auto;background:#08080a;border:1px solid #333;border-radius:6px;padding:6px"></div></div>`;
    document.documentElement.appendChild(box);
    for(const b of box.querySelectorAll('button'))Object.assign(b.style,{padding:'6px 8px',border:'1px solid #666',borderRadius:'5px',background:'#222',color:'#fff',cursor:'pointer',font:'inherit'});
    box.querySelector('.scroll').onclick=toggleScroll;
    box.querySelector('.clicks').onclick=toggleClicks;
    box.querySelector('.crawl').onclick=()=>{stopCrawl=false;if(!st.crawling&&q.length)startCrawl()};
    box.querySelector('.download').onclick=download;
    box.querySelector('.stop').onclick=stop;
    render();
  }

  installNetworkHooks();
  installNavHooks();

  obs=new MutationObserver(items=>{
    if(!st.active)return;
    if(items.some(x=>!x.target?.closest?.('#'+UI))){
      scanDom(document,location.href,'mutation');
      scanViewport();
      sync();render();
    }
  });
  obs.observe(document.documentElement,{subtree:true,childList:true,attributes:false});

  ui();
  seed();
  scanViewport();

  refreshTimer=setInterval(()=>{
    if(!st.active)return;
    scanDom(document,location.href,'refresh');
    scanViewport();
    if(!st.crawling&&q.length&&M.crawled.size<C.maxCrawl)startCrawl();
    if(st.autoScroll&&!st.scroll.running)startAutoScroll();
    sync();render();
  },C.refreshMs);

  window[G]=Object.freeze({
    version:VER,
    config:{...C},
    status:()=>({...st.stats,active:st.active,crawling:st.crawling}),
    data:()=>st,
    startCrawl,
    startAutoScroll,
    toggleScroll,
    toggleClicks,
    download,
    stop,
    show:ui,
    hide:()=>document.getElementById(UI)?.remove()
  });

  console.log(`[KCD Hyperreal Explorer v${VER}] actief — 50ms globale throttle, max ${C.maxCrawl} crawl, auto-scroll en veilige relevantie-clicks.`);
})();