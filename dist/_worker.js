// dist/_worker.js (SP-Proxy-Pages Enterprise Edition v1.0.0 beta)
"use strict";

const MAX_REWRITE_SIZE = 5 * 1024 * 1024; 
const SECRET_PREFIX = "";
const BOT_REGEX = /bot|spider|crawler|python|curl|wget|postman|scanner|shodan|masscan|nmap/i;
const IGNORE_URL_REGEX = /^(data:|blob:|javascript:|mailto:|tel:|#)/i;
const PROTOCOL_REGEX = /^(https?):\/+/;
const CSS_URL_REGEX = /url\((['"]?)([^)'"\n]+)\1\)/gi; 
const JS_LOC_REPLACE_REGEX = /(?<!\w|\.)location\.(pathname|href|origin|host|hostname|port|protocol|assign|replace|search|hash|reload)\b/g;
const JS_LOC_ASSIGN_REGEX = /(?<!\w|\.)location(\s*=)/g; 
const UP_COOKIE_REGEX = /^__UP_(.+?)__(.*)$/;

const PRIVATE_IP_REGEX = /^(localhost|0\.0\.0\.0|\[::\]|\[::1\]|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d+\.\d+|\[::ffff:(127|10|192\.168|172\.(1[6-9]|2\d|3[0-1]))\..*\]|::1|fd[0-9a-fA-F]{2}:.*|0x[0-9a-fA-F]+(\.[0-9a-fA-F]+){0,3}|0[0-7]+(\.[0-7]+){0,3})/i;
const CF_PORTS = new Set([80, 443, 8080, 8443, 8880, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096]);

const STRIP_REQ_HEADERS = new Set(['cf-worker', 'cf-ray', 'cf-ew-via', 'cdn-loop', 'cf-connecting-o2o', 'cf-connecting-ip', 'cf-connecting-ipv6', 'cf-ipcountry', 'cf-visitor', 'forwarded', 'via', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip', 'true-client-ip', 'x-proxyuser-ip', 'accept-encoding', 'x-amzn-trace-id', 'x-datadog-trace-id', 'x-datadog-parent-id', 'b3', 'traceparent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-full-version-list']);
const STRIP_RES_HEADERS = new Set(["content-security-policy", "content-security-policy-report-only", "x-frame-options", "clear-site-data", "cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "speculation-rules", "link", "permissions-policy", "document-policy"]);
const ATTR_LIST =["src", "href", "action", "formaction", "data-url", "data-pjax-url", "data-src", "data-hydro-click-payload"];
const CSS_ATTR_SELECTORS = ATTR_LIST.map(a => `[${a}]`).join(",");

const safeDecode = (str) => { try { return decodeURIComponent(str); } catch { return str; } };
const esc = (s) => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

class FastLRUCache {
    constructor(maxSize) { this.maxSize = maxSize; this.cache = new Map(); }
    get(key) {
        let val = this.cache.get(key);
        if (val !== undefined) { this.cache.delete(key); this.cache.set(key, val); }
        return val;
    }
    set(key, val) {
        if (this.cache.has(key)) this.cache.delete(key);
        else if (this.cache.size >= this.maxSize) this.cache.delete(this.cache.keys().next().value);
        this.cache.set(key, val);
    }
}

const REGEX_CACHE = new FastLRUCache(200);
const PAYLOAD_CACHE = new FastLRUCache(50);
const RULES_CACHE = new Map(); 
let globalCryptoKeys = null;
let cryptoKeysPromise = null;

const getCryptoCacheName = (env) => `up-crypto-v2-${env.CRYPTO_SALT || "default"}`;

function getCryptoKeys(env) {
    if (globalCryptoKeys) return globalCryptoKeys;
    if (cryptoKeysPromise) return cryptoKeysPromise;
    return cryptoKeysPromise = (async () => {
        let workerKeyPair, workerPubKeyJWK;
        try {
            const cacheName = getCryptoCacheName(env);
            const cache = await caches.open(cacheName);
            const req = new Request(`https://proxy.local/_up_pub_key_internal?salt=${env.CRYPTO_SALT || "default"}`);
            let res = await cache.match(req);
            let privJwk, pubJwk;
            if (res) try { const data = await res.json(); privJwk = data.priv; pubJwk = data.pub; } catch(e) {}
            
            if (!privJwk) {
                const pair = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true,["encrypt", "decrypt"]);
                privJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
                pubJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
                await cache.put(req, new Response(JSON.stringify({priv: privJwk, pub: pubJwk}), { headers: { "Cache-Control": "public, max-age=31536000", "Content-Type": "application/json" } })).catch(()=>{});
            }
            workerKeyPair = {
                privateKey: await crypto.subtle.importKey("jwk", privJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true,["decrypt"]),
                publicKey: await crypto.subtle.importKey("jwk", pubJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true,["encrypt"])
            };
            workerPubKeyJWK = pubJwk;
        } catch(err) {
            const pair = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true,["encrypt", "decrypt"]);
            workerKeyPair = pair;
            workerPubKeyJWK = await crypto.subtle.exportKey("jwk", pair.publicKey);
        }
        return globalCryptoKeys = { workerKeyPair, workerPubKeyJWK };
    })();
}

const DOM_SANDBOX_JS = `<script>!function(){if(window.__UP_DOM_HOOKED)return;window.__UP_DOM_HOOKED=!0;const P=__ProxyOrigin,T=__TargetOrigin;window.__UP_TARGET=T;function getTH(){let u=window.location.href;let rx=new RegExp('^'+P.replace(/[.*+?^$\\{\\}()|[\\]\\\\]/g,'\\\\$&')+'\\\\/+(https?(?::\\\\/\\\\/|%3A%2F%2F).*)','i');let m=u.match(rx);if(m){let tUrl=m[1];try{let qIdx=tUrl.indexOf('?'),hIdx=tUrl.indexOf('#'),splitIdx=qIdx!==-1?(hIdx!==-1?Math.min(qIdx,hIdx):qIdx):(hIdx!==-1?hIdx:-1),pP=splitIdx!==-1?tUrl.substring(0,splitIdx):tUrl,qP=splitIdx!==-1?tUrl.substring(splitIdx):'';if(pP.includes('%2Fhttps%3A')||pP.includes('%3A%2F%2F'))pP=decodeURIComponent(pP);return pP+qP;}catch(e){return tUrl;}}return T;}const TH=getTH();window.__up_crypto=function(){let p=null,sk=null,ek=null;async function g(){if(p)return p;let j=sessionStorage.getItem('__up_jwk');if(!j){let r=await fetch('/_up_pub_key');j=await r.text();sessionStorage.setItem('__up_jwk',j)}return p=await crypto.subtle.importKey("jwk",JSON.parse(j),{name:"RSA-OAEP",hash:"SHA-256"},!1,["encrypt"])}function b(f){let u=new Uint8Array(f),s='',c=8192;for(let i=0;i<u.length;i+=c)s+=String.fromCharCode.apply(null,u.subarray(i,i+c));return btoa(s)}return{async e(t){if(!sk){sk=await crypto.subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt"]);let k=await g(),r=await crypto.subtle.exportKey("raw",sk);ek=b(await crypto.subtle.encrypt({name:"RSA-OAEP"},k,r))}let i=crypto.getRandomValues(new Uint8Array(12)),d=await crypto.subtle.encrypt({name:"AES-GCM",iv:i},sk,new TextEncoder().encode(t));let ts=Date.now(),nonce=b(crypto.getRandomValues(new Uint8Array(12)));return btoa(JSON.stringify({r:ek,i:b(i),d:b(d),t:ts,n:nonce}))}}}();function toP(u){if(!u)return u;let s=String(u).trim();if(/^(data:|blob:|javascript:|mailto:|tel:|#)/i.test(s))return s;if(s.startsWith(P+'/http'))return s;if(s.includes(P+'/http'))return s.substring(s.indexOf(P+'/http'));if(s.match(/^\\/https?:\\/\\//i))return P+s;try{let pu=new URL(s,getTH()).href,em=pu.match(/^(https?:\\/\\/[^\\/]+)\\/*\\1\\/(.*)/i);if(em)pu=em[1]+'/'+em[2];return P+'/'+pu;}catch(e){return s;}}function unP(u){if(!u)return u;let s=String(u),rx=new RegExp('^'+P.replace(/[.*+?^$\\{\\}()|[\\]\\\\]/g,'\\\\$&')+'\\\\/+(https?(?::\\\\/\\\\/|%3A%2F%2F).*)','i'),m=s.match(rx);if(m){let p=m[1];try{if(p.includes('%2Fhttps%3A')||p.includes('%3A%2F%2F'))p=decodeURIComponent(p);}catch(e){}return p;}return s;}const _loc=new URL(window.location.href),_up_proxy_obj=new Proxy(_loc,{get(t,p){let th=getTH();if(p===Symbol.toPrimitive||p==='toString'||p==='valueOf')return ()=>th;if(p==='href')return th;if(['pathname','origin','host','hostname','port','protocol','search','hash'].includes(p)){try{return new URL(th)[p];}catch(e){return '';}}if(p==='assign')return u=>window.location.assign(toP(u));if(p==='replace')return u=>window.location.replace(toP(u));if(p==='reload')return f=>window.location.reload(f);let v=window.location[p];return typeof v==='function'?v.bind(window.location):v;},set(t,p,v){if(['href','pathname','search','hash','protocol','host','hostname','port'].includes(p)){try{let u=new URL(getTH());u[p]=v;window.location.href=toP(u.href);}catch(e){window.location[p]=toP(v);}return !0;}window.location[p]=v;return !0;}});Object.defineProperty(window,'__up_loc',{get:()=>_up_proxy_obj,set:v=>{_up_proxy_obj.href=v;},configurable:!0});try{Object.defineProperty(document,'location',{get:()=>_up_proxy_obj,set:v=>{_up_proxy_obj.href=v;},configurable:!0});}catch(e){}try{function df(p){Object.defineProperty(Document.prototype,p,{get:()=>getTH(),configurable:!0});}df('URL');df('documentURI');df('baseURI');}catch(e){}try{Object.defineProperty(MessageEvent.prototype,'origin',{get:()=>T});}catch(e){}const _Req=window.Request;if(_Req)window.Request=function(i,o){let r=i&&typeof i==='object'&&i.url,u=r?i.url:i;try{if(typeof u==='string')u=toP(u);}catch(e){}return new _Req(u,o||(r?i:undefined));};const _f=window.fetch;window.fetch=async function(i,o){let r=i&&typeof i==='object'&&i.url,u=r?i.url:i;let _ou=String(u);try{u=toP(u);}catch(e){}let m=o?.method||(r?i.method:'GET'),b=o?.body;let isLg=/login|sign-?in|auth/i.test(_ou);if(isLg&&b&&m&&['POST','PUT','PATCH'].includes(m.toUpperCase())){let strBody=null;if(typeof b==='string')strBody=b;else if(b instanceof URLSearchParams)strBody=b.toString();else if(b instanceof FormData){let hasFile=!1;if(b.values){for(let val of b.values()){if(val instanceof File||val instanceof Blob)hasFile=!0;}}if(!hasFile)strBody=new URLSearchParams(b).toString();}if(strBody!==null&&strBody.length<500000){try{let c=await window.__up_crypto.e(strBody),h=new Headers(o?.headers||(r?i.headers:{}));h.set('X-Up-Enc','1');if(!h.has('content-type')&&!h.has('Content-Type'))h.set('Content-Type','application/x-www-form-urlencoded');let nO=Object.assign({},o,{body:'__UP_ENC__'+c,headers:h});return r?_f(new Request(u,i),nO):_f(u,nO);}catch(e){}}}if(r)try{return _f(new Request(u,i),o);}catch(e){return _f(u,o||i);}return _f(u,o);};const _o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u,...r){this.__up_u=String(u);try{u=toP(u);}catch(e){}return _o.call(this,m,u,...r);};const _s=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(b){let _ou=this.__up_u||'';let isLg=/login|sign-?in|auth/i.test(_ou);if(isLg&&b){let strBody=null;if(typeof b==='string')strBody=b;else if(b instanceof URLSearchParams)strBody=b.toString();else if(b instanceof FormData){let hasFile=!1;if(b.values){for(let val of b.values()){if(val instanceof File||val instanceof Blob)hasFile=!0;}}if(!hasFile)strBody=new URLSearchParams(b).toString();}if(strBody!==null&&strBody.length<500000){let t=this;window.__up_crypto.e(strBody).then(c=>{t.setRequestHeader('X-Up-Enc','1');if(b instanceof FormData||b instanceof URLSearchParams)t.setRequestHeader('Content-Type','application/x-www-form-urlencoded');_s.call(t,'__UP_ENC__'+c)}).catch(()=>{_s.call(t,b)});return}} _s.call(this,b)};const _wo=window.open;window.open=function(u,n,f){try{u=toP(u);}catch(e){}return _wo.call(this,u,n,f);};if(navigator.sendBeacon){const _sb=navigator.sendBeacon;navigator.sendBeacon=function(u,d){try{u=toP(u);}catch(e){}return _sb.call(this,u,d);};}const _Wk=window.Worker;if(_Wk)window.Worker=function(s,o){try{s=toP(s);}catch(e){}return new _Wk(s,o);};const _SWk=window.SharedWorker;if(_SWk)window.SharedWorker=function(s,o){try{s=toP(s);}catch(e){}return new _SWk(s,o);};const _ES=window.EventSource;if(_ES)window.EventSource=function(s,o){try{s=toP(s);}catch(e){}return new _ES(s,o);};const _W=window.WebSocket;if(_W)window.WebSocket=function(u,p){try{let w=new URL(String(u),getTH());if(w.protocol==='ws:'||w.protocol==='wss:'){let t=(w.protocol==='ws:'?'http:':'https:')+'//'+w.host+w.pathname+w.search;u=P.replace('http','ws')+'/'+t;}}catch(e){}return p?new _W(u,p):new _W(u);};const _pm=Window.prototype.postMessage;Window.prototype.postMessage=function(d,o,t){if(typeof o==='string'&&o!=='/'&&o!=='*')o='*';if(arguments.length<3)return _pm.call(this,d,o);return _pm.call(this,d,o,t);};const _fs=HTMLFormElement.prototype.submit;async function encF(f,btn){let a=String(f.action||getTH());let isLg=/login|sign-?in|auth/i.test(a);if(isLg&&f.method&&f.method.toUpperCase()==='POST'&&!f.hasAttribute('data-up-enc')&&f.enctype!=='multipart/form-data'&&!f.querySelector('input[type="file"]')){try{let fd=new FormData(f);if(btn&&btn.name)fd.append(btn.name,btn.value||'');else{let sBtn=f.querySelector('button[type="submit"][name], input[type="submit"][name]');if(sBtn&&sBtn.name)fd.append(sBtn.name,sBtn.value||'');}if(isLg&&!fd.has('loginsubmit')){fd.append('loginsubmit','yes');}if(!fd.has('formhash')){let fh=document.querySelector('input[name="formhash"]');if(fh)fd.append('formhash',fh.value);}let d=new URLSearchParams(fd).toString(),c=await window.__up_crypto.e(d);f.setAttribute('data-up-enc','1');let i=document.createElement('input');i.type='hidden';i.name='__UP_ENC__';i.value=c;i.className='__up_e_i';f.appendChild(i);f.action=toP(f.action||getTH());const nx=document.createElement('input');nx.type='hidden';nx.name='__UP_ENCH__';nx.value='1';f.appendChild(nx);_fs.call(f);setTimeout(()=>{f.removeAttribute('data-up-enc');f.querySelectorAll('.__up_e_i, input[name="__UP_ENCH__"]').forEach(el=>el.remove());},100);return !0;}catch(x){}}return !1;}HTMLFormElement.prototype.submit=function(){let f=this;encF(f,null).then(r=>{if(!r)_fs.call(f)});};window.addEventListener('submit',e=>{if(e.defaultPrevented)return;let f=e.target;if(f.method&&f.method.toUpperCase()==='POST'&&!f.hasAttribute('data-up-enc')&&f.enctype!=='multipart/form-data'&&!f.querySelector('input[type="file"]')){e.preventDefault();encF(f,e.submitter).then(r=>{if(!r)_fs.call(f)});}},!1);function hk(C,N,S){if(!C||!C.prototype)return;const d=Object.getOwnPropertyDescriptor(C.prototype,N);if(d&&d.set){const s_fn=d.set,g_fn=d.get;try{Object.defineProperty(C.prototype,N,{set:function(v){if(S)return;try{if(!this.hasAttribute('data-up-orig-'+N.toLowerCase()))this.setAttribute('data-up-orig-'+N.toLowerCase(),v);v=toP(v);}catch(e){}s_fn.call(this,v);},get:function(){let v=g_fn.call(this);return(N==='href'||N==='src'||N==='action')?unP(v):v;}});}catch(e){}}}try{hk(HTMLScriptElement,'src',0);hk(HTMLLinkElement,'href',0);hk(HTMLImageElement,'src',0);hk(HTMLIFrameElement,'src',0);hk(HTMLAnchorElement,'href',0);hk(HTMLFormElement,'action',0);hk(HTMLButtonElement,'formAction',0);hk(HTMLVideoElement,'src',0);hk(HTMLAudioElement,'src',0);hk(HTMLMediaElement,'src',0);hk(HTMLSourceElement,'src',0);hk(HTMLTrackElement,'src',0);hk(HTMLScriptElement,'integrity',1);hk(HTMLLinkElement,'integrity',1);hk(HTMLScriptElement,'nonce',1);hk(HTMLElement,'nonce',1);}catch(e){}['pathname','search','hash','host','hostname','port','protocol','origin'].forEach(p=>{const d=Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype,p);if(d&&d.get){const s_fn=d.set,g_fn=d.get;try{Object.defineProperty(HTMLAnchorElement.prototype,p,{get:function(){let h=unP(this.href);try{return new URL(h)[p];}catch(e){return g_fn.call(this);}},set:function(v){if(s_fn){let h=unP(this.href);try{let u=new URL(h);u[p]=v;this.href=u.href;}catch(e){s_fn.call(this,v);}}}});}catch(e){}}});const _ga=Element.prototype.getAttribute;Element.prototype.getAttribute=function(n){let v=_ga.call(this,n);if(v&&typeof v==='string'&&['href','src','action','data-url'].includes(n.toLowerCase())){let orig=_ga.call(this,'data-up-orig-'+n.toLowerCase());if(orig)return orig;return unP(v);}return v;};const _sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){const l=n.toLowerCase();if(['integrity','crossorigin','nonce'].includes(l))return;if(['src','href','action','formaction','data-url','data-pjax-url','data-src','data-hydro-click-payload'].includes(l)&&v){try{if(!this.hasAttribute('data-up-orig-'+l))_sa.call(this,'data-up-orig-'+l,v);v=toP(v);}catch(e){}}return _sa.call(this,n,v);};const _hp=History.prototype.pushState,_np=function(s,t,u){if(u)u=toP(u);return _hp.call(this,s,t,u);};History.prototype.pushState=_np;if(window.history)window.history.pushState=_np;const _hr=History.prototype.replaceState,_nr=function(s,t,u){if(u)u=toP(u);return _hr.call(this,s,t,u);};History.prototype.replaceState=_nr;if(window.history)window.history.replaceState=_nr;if(navigator.serviceWorker&&navigator.serviceWorker.register){navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(()=>{});navigator.serviceWorker.register=()=>Promise.reject(new Error("SW disabled by proxy."));}try{const _cd=Object.getOwnPropertyDescriptor(Document.prototype,'cookie')||Object.getOwnPropertyDescriptor(HTMLDocument.prototype,'cookie');if(_cd&&_cd.configurable){Object.defineProperty(document,'cookie',{get:function(){let th_h=new URL(getTH()).hostname,a=_cd.get.call(this)||"",ps=a.split(';'),r=[];for(let i=0;i<ps.length;i++){let p=ps[i].trim(),eq=p.indexOf('='),n=eq===-1?p:p.substring(0,eq),v=eq===-1?'':p.substring(eq),m=n.match(/^__UP_(.+?)__(.*)$/);if(m){let d=m[1],cn=m[2];if(th_h===d||th_h.endsWith('.'+d))r.push(cn+v);}}return r.join('; ');},set:function(vl){let th_h=new URL(getTH()).hostname,ps=vl.toString().split(';'),nv=ps[0],eq=nv.indexOf('='),n=eq===-1?nv.trim():nv.substring(0,eq).trim(),cv=eq===-1?'':nv.substring(eq),d=th_h,o=[];for(let i=1;i<ps.length;i++){let p=ps[i].trim(),pl=p.toLowerCase();if(pl.startsWith('domain='))d=p.substring(7).trim().replace(/^\\./,'');else if(!pl.startsWith('path=')&&!pl.startsWith('samesite')&&!pl.startsWith('secure'))o.push(p);}let ut='__UP_'+d+'__'+n+cv+'; Path=/; SameSite=None; Secure';if(o.length)ut+='; '+o.join('; ');_cd.set.call(this,ut);}});}Object.defineProperty(document,'domain',{get:()=>new URL(getTH()).hostname,set:function(){}});}catch(e){}function arYT(){try{let t=new URL(getTH());if(t.hostname==='youtube.com'||t.hostname==='www.youtube.com')return;if(!window.__up_yt_locked){window.__up_yt_locked=!0;try{let _vp=HTMLMediaElement.prototype.play;HTMLMediaElement.prototype.play=function(){let u=new URL(getTH());if(u.hostname==='m.youtube.com'&&u.pathname.startsWith('/watch')){try{this.muted=!0;this.volume=0}catch(e){}}return _vp.call(this)};let oV=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'volume');if(oV){Object.defineProperty(HTMLMediaElement.prototype,'volume',{get:function(){let u=new URL(getTH());return(u.hostname==='m.youtube.com'&&u.pathname.startsWith('/watch'))?0:oV.get.call(this)},set:function(v){let u=new URL(getTH());if(!(u.hostname==='m.youtube.com'&&u.pathname.startsWith('/watch')))oV.set.call(this,v)},configurable:!0})}let oM=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'muted');if(oM){Object.defineProperty(HTMLMediaElement.prototype,'muted',{get:function(){let u=new URL(getTH());return(u.hostname==='m.youtube.com'&&u.pathname.startsWith('/watch'))?!0:oM.get.call(this)},set:function(v){let u=new URL(getTH());if(!(u.hostname==='m.youtube.com'&&u.pathname.startsWith('/watch')))oM.set.call(this,v)},configurable:!0})}}catch(e){}}if(t.hostname==='m.youtube.com'){if(t.pathname.startsWith('/watch')){let v=t.searchParams.get('v');if(v){let p=document.querySelector('.html5-video-player, #player, #movie_player, .player-container');if(p){let vds=p.querySelectorAll('video');for(let i=0;i<vds.length;i++){let n=vds[i];n.muted=!0;n.volume=0;n.pause();try{if(n.hasAttribute('src')||n.src){n.removeAttribute('src');n.src='';n.load()}if(n.srcObject)n.srcObject=null}catch(err){}n.style.opacity='0';n.style.pointerEvents='none'}let ols=p.querySelectorAll('.ytp-chrome-top, .ytp-chrome-bottom, .ytp-spinner, .ytp-error, .ytp-ad-module, .html5-video-info-panel, .ytp-gradient-top, .ytp-gradient-bottom, ytm-custom-control, .player-controls');for(let k=0;k<ols.length;k++){ols[k].style.opacity='0';ols[k].style.pointerEvents='none'}let e=document.getElementById('up-yt-iframe-container');if(e){if(e.dataset.vid!==v){e.querySelector('iframe').src=toP('https://www.youtube.com/embed/'+v+'?autoplay=1&playsinline=1');e.dataset.vid=v}}else{let c=document.createElement('div');c.id='up-yt-iframe-container';c.dataset.vid=v;c.style.cssText="position:absolute;top:0;left:0;width:100%;height:100%;z-index:2147483647;background:#000;";let f=document.createElement('iframe');f.width="100%";f.height="100%";f.src=toP('https://www.youtube.com/embed/'+v+'?autoplay=1&playsinline=1');f.title="YouTube proxy player";f.setAttribute("frameborder","0");f.setAttribute("allow","accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share");f.setAttribute("sandbox","allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-presentation");f.setAttribute("referrerpolicy","strict-origin-when-cross-origin");f.setAttribute("allowfullscreen","");f.style.cssText="width:100%;height:100%;border:none;";c.appendChild(f);p.appendChild(c)}}}}else{let e=document.getElementById('up-yt-iframe-container');if(e)e.remove();let vds=document.querySelectorAll('video');for(let i=0;i<vds.length;i++){let n=vds[i];if(n.style.opacity==='0'){n.style.opacity='1';n.style.pointerEvents='auto'}}let ols=document.querySelectorAll('.ytp-chrome-top, .ytp-chrome-bottom, .ytp-spinner, .ytp-error, .ytp-ad-module, .html5-video-info-panel, .ytp-gradient-top, .ytp-gradient-bottom, ytm-custom-control, .player-controls');for(let k=0;k<ols.length;k++){if(ols[k].style.opacity==='0'){ols[k].style.opacity='1';ols[k].style.pointerEvents='auto'}}}}}catch(x){}try{const r=new RegExp('(?:youtube\\\\.com\\\\/(?:[^\\\\/]+\\\\/.+\\\\/|(?:v|e(?:mbed)?)\\\\/|.*[?&]v=)|youtu\\\\.be\\\\/)([^"&?\\\\/\\\\s]{11})','i');let l=document.querySelectorAll('a:not([data-yt-replaced])');for(let i=0;i<l.length;i++){let a=l[i];a.setAttribute('data-yt-replaced','1');let h=a.getAttribute('data-up-orig-href')||a.href||'';let m=h.match(r);if(m&&m[1]){let t=a.textContent.trim();if(t.includes('youtube.com')||t.includes('youtu.be')){let c=document.createElement('div');c.style.cssText="position:relative;width:100%;padding-bottom:56.25%;height:0;overflow:hidden;background:#000;border-radius:8px;margin:10px 0;";let f=document.createElement('iframe');f.src=toP('https://www.youtube.com/embed/'+m[1]+'?autoplay=0&playsinline=1');f.title="YouTube proxy player";f.setAttribute("frameborder","0");f.setAttribute("allow","accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share");f.setAttribute("sandbox","allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-presentation");f.setAttribute("referrerpolicy","strict-origin-when-cross-origin");f.setAttribute("allowfullscreen","");f.style.cssText="position:absolute;top:0;left:0;width:100%;height:100%;border:none;";c.appendChild(f);a.parentNode.replaceChild(c,a)}}}}catch(x){}}setInterval(arYT,1000);new MutationObserver(ms=>{for(let i=0;i<ms.length;i++){const m=ms[i];for(let j=0;j<m.addedNodes.length;j++){const n=m.addedNodes[j];if(n.nodeType===1){if(n.removeAttribute){n.removeAttribute('integrity');n.removeAttribute('crossorigin');n.removeAttribute('nonce');}if(n.nodeName==='SCRIPT'&&n.textContent){let t=n.textContent,r=t.replace(/\\bwindow\\.location\\b/g,"window.__up_loc").replace(/\\bdocument\\.location\\b/g,"window.__up_loc").replace(/\\btop\\.location\\b/g,"top.__up_loc").replace(/\\bparent\\.location\\b/g,"parent.__up_loc").replace(/\\bself\\.location\\b/g,"self.__up_loc");if(t!==r)try{n.textContent=r}catch(e){}}if(n.querySelectorAll){const els=n.querySelectorAll('[integrity],[crossorigin],[nonce]');for(let k=0;k<els.length;k++){els[k].removeAttribute('integrity');els[k].removeAttribute('crossorigin');els[k].removeAttribute('nonce');}const urls=n.querySelectorAll('[src],[href],[action],[data-url],[data-pjax-url],[data-src],[data-hydro-click-payload]');for(let k=0;k<urls.length;k++){let el=urls[k];['src','href','action','data-url','data-pjax-url','data-src','data-hydro-click-payload'].forEach(attr=>{if(el.hasAttribute(attr)){let v=el.getAttribute(attr);if(v&&!v.startsWith(P+'/http')&&!/^(data:|blob:|javascript:|mailto:|tel:|#)/i.test(v)){try{if(!el.hasAttribute('data-up-orig-'+attr))el.setAttribute('data-up-orig-'+attr,v);el.setAttribute(attr,toP(v));}catch(e){}}}});}}['src','href','action','data-url','data-pjax-url','data-src','data-hydro-click-payload'].forEach(attr=>{if(n.hasAttribute&&n.hasAttribute(attr)){let v=n.getAttribute(attr);if(v&&!v.startsWith(P+'/http')&&!/^(data:|blob:|javascript:|mailto:|tel:|#)/i.test(v)){try{if(!n.hasAttribute('data-up-orig-'+attr))n.setAttribute('data-up-orig-'+attr,v);n.setAttribute(attr,toP(v));}catch(e){}}}});}}}}).observe(document.documentElement,{childList:!0,subtree:!0});}();</script>`;

function getCachedPayload(p, t) {
    const key = `${p}|${t}`;
    let cached = PAYLOAD_CACHE.get(key);
    if (!cached) PAYLOAD_CACHE.set(key, cached = { sandbox: DOM_SANDBOX_JS.replaceAll('__ProxyOrigin', `"${p}"`).replaceAll('__TargetOrigin', `"${t}"`) });
    return cached;
}

let cachedBlockRulesStr = null;
let compiledBlockRules =[];
let cachedAllowRulesStr = null;
let compiledAllowRules =[];

function safeMakeRegExp(str, flags) {
    const cacheKey = `${str}|${flags || ''}`;
    if (RULES_CACHE.has(cacheKey)) return RULES_CACHE.get(cacheKey);
    try { 
        const re = new RegExp(str, flags); 
        RULES_CACHE.set(cacheKey, re);
        return re;
    } catch (e) { return null; }
}

function compileRulesOnce(env) {
    const blockStr = env.BLOCK_RULES ?? "chatgpt.com, openai.com, claude.ai, gemini.google.com, grok.com, copilot.microsoft.com, perplexity.ai, poe.com, ";
    if (blockStr !== cachedBlockRulesStr) {
        compiledBlockRules = blockStr.split(/[\n,]+/).map(r => r.trim()).filter(Boolean)
            .map(rule => rule.startsWith('/') && rule.endsWith('/') ? safeMakeRegExp(rule.slice(1, -1)) : safeMakeRegExp(`(^|\\.)${rule.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i'))
            .filter(Boolean);
        cachedBlockRulesStr = blockStr;
    }
    const allowStr = env.ALLOW_RULES ?? "";
    if (allowStr !== cachedAllowRulesStr) {
        compiledAllowRules = allowStr.split(/[\n,]+/).map(r => r.trim()).filter(Boolean)
            .map(rule => rule.startsWith('/') && rule.endsWith('/') ? safeMakeRegExp(rule.slice(1, -1)) : safeMakeRegExp(`(^|\\.)${rule.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i'))
            .filter(Boolean);
        cachedAllowRulesStr = allowStr;
    }
}

function isPermitted(hostname, env) {
    compileRulesOnce(env);
    if (compiledBlockRules.length > 0 && compiledBlockRules.some(r => r.test(hostname))) return false;
    if (compiledAllowRules.length > 0) return compiledAllowRules.some(r => r.test(hostname));
    return true;
}

function getOriginRegex(origin, isHTML) {
    const key = (isHTML ? 'h_' : 't_') + origin;
    let regex = REGEX_CACHE.get(key);
    if (!regex) REGEX_CACHE.set(key, regex = new RegExp((isHTML ? origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + "(?![:a-zA-Z0-9.-])" : origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'g'));
    return regex;
}

export default {
    async fetch(request, env) {
        try { return await handleRequest(request, env); } 
        catch (err) { 
            return buildUIResponse("💥 网关致命异常", "System Error", "系统处理请求时遭遇未预期的异常错误。出于安全策略保护，异常堆栈与内部详情已被静默处理并锁死。", 502); 
        }
    }
};

async function handleRequest(request, env) {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || '';

    if (BOT_REGEX.test(userAgent)) return buildUIResponse("🚫 访问被拒绝", "Access Denied", "您的请求似乎来源于自动化脚本或扫描器。", 403);
    if (request.headers.get('X-UP-Proxy-Loop') === '1') return buildUIResponse("🔁 代理死循环", "Proxy Loop", "检测到请求在节点内自我循环，已切断。", 508);

    const authSecret = env.AUTH_SECRET;
    if (authSecret) {
        if (url.searchParams.get('auth') === authSecret) {
            url.searchParams.delete('auth');
            return new Response(null, { status: 302, headers: { 'Location': url.toString() || '/', 'Set-Cookie': `__UP_AUTH__=${encodeURIComponent(authSecret)}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=2592000` } });
        }
        const isAuthed = (request.headers.get('cookie') || '').includes(`__UP_AUTH__=${encodeURIComponent(authSecret)}`);
        if (!isAuthed && !url.pathname.endsWith('manifest.json') && !url.pathname.endsWith('.webmanifest')) {
            return buildUIResponse("🛡️ Zero Trust 访问受限", "Private Node", "该节点已启用零信任私有化策略。首次访问请在 URL 后追加验证参数（例如：<code>/?auth=您的密语</code>）以进行身份授权。<br><br>⚠️ 未经授权的自动化扫描请求将被持续边缘拦截。", 401);
        }
    }

    let rawPath = url.pathname.replace(/^\/+/, "");
    if (rawPath === "_up_pub_key") {
        const keys = await getCryptoKeys(env);
        return new Response(JSON.stringify(keys.workerPubKeyJWK), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=3600" } });
    }

    if (rawPath === "sw.js" || rawPath === "favicon.ico") {
        if (env.ASSETS) try { const assetRes = await env.ASSETS.fetch(request); if (assetRes?.status === 200) return assetRes; } catch(e) {}
        if (rawPath === "sw.js") return new Response("self.addEventListener('fetch', (e) => {});", { headers: { "Content-Type": "application/javascript" } });
        return new Response(null, { status: 404 });
    }

    let pathAndQuery = request.url.slice(url.origin.length);
    if (SECRET_PREFIX) {
        if (!pathAndQuery.startsWith(SECRET_PREFIX)) return new Response('Not Found', { status: 404 });
        pathAndQuery = pathAndQuery.slice(SECRET_PREFIX.length) || "/";
    }

    let clean = pathAndQuery.replace(/^\/+/, "");
    if (clean.length > 8192) return buildUIResponse("❌ 无效的 URL", "Invalid URL", "目标地址格式错误或级联超限，无法构建访问。", 400);

    if (clean.includes('%2Fhttps%3A') || clean.includes('%3A%2F%2F')) {
        let qIdx = clean.indexOf('?');
        let pathPart = qIdx !== -1 ? clean.substring(0, qIdx) : clean;
        clean = safeDecode(pathPart) + (qIdx !== -1 ? clean.substring(qIdx) : "");
    }

    const proxyHost = url.host;
    const safeHost = proxyHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    clean = clean.replace(new RegExp(`^(?:https?:\\/\\/${safeHost}\\/+)+`, 'i'), '');
    clean = clean.replace(/^(?:https?:\/\/[^\/]+\/+)+?(?=https?:\/\/)/i, '');

    if (!clean) return buildHomepage(url);
    if (clean === "robots.txt") return new Response("User-agent: *\nDisallow: /\n", { headers: { "Content-Type": "text/plain" } });

    clean = clean.replace(PROTOCOL_REGEX, "$1://");
    
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
        let redirectTarget = null;
        const ref = request.headers.get("Referer");
        if (ref) {
            try {
                let refPath = new URL(ref).pathname.slice(1).replace(SECRET_PREFIX ? SECRET_PREFIX.slice(1) : "", "").replace(/^\/+/, "");
                if (refPath.includes('%2Fhttps%3A')) refPath = safeDecode(refPath);
                let em = refPath.match(/^(https?:\/\/[^\/]+)\/+(https?:\/\/.*)/i);
                if (em) refPath = em[2];
                if (refPath.startsWith("http")) redirectTarget = new URL(refPath).origin;
            } catch(e) {}
        }
        if (!redirectTarget) {
            const match = (request.headers.get('cookie') || "").match(/__UP_LAST_TARGET__=([^;]+)/);
            if (match) redirectTarget = safeDecode(match[1]);
        }
        if (redirectTarget) return Response.redirect(`${url.origin}${SECRET_PREFIX}/${redirectTarget}/${clean}`, 307); 
        
        if (/^([a-zA-Z0-9.-]+)(:\d+)?([/?#].*)?$/.test(clean)) clean = "https://" + clean;
        else return buildUIResponse("❓ 上下文丢失", "Context Lost", "无法正确解析目标地址，Worker 裸请求溯源失败。", 400);
    }

    let target;
    try { 
        target = new URL(clean); 
    } catch { return buildUIResponse("❌ 无效的 URL", "Invalid URL", "目标地址格式错误或解析失败，无法构建访问。", 400); }

    if (PRIVATE_IP_REGEX.test(target.hostname)) return buildUIResponse("🚨 安全策略拦截 (SSRF)", "Security Policy Enforced", `系统禁止通过代理访问私有网络、云元数据或特殊回环地址 (<b>${esc(target.hostname)}</b>) 以防范服务器请求伪造攻击。`, 403);
    if (!isPermitted(target.hostname, env)) return buildUIResponse("🛑 域名访问受限", "Domain Access Restricted", `根据安全访问策略，目标域名 <b>${esc(target.hostname)}</b> 无法通过此代理访问。`, 403);
    if (target.port && !CF_PORTS.has(Number(target.port))) return buildUIResponse("🔒 端口受限", "Port Blocked", "指定的网络端口非安全端口，请求已被网关拒绝。", 502);

    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Expose-Headers": "*", 
                "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "*",
                "Access-Control-Max-Age": "86400",
                "Access-Control-Allow-Credentials": "true"
            }
        });
    }

    const headers = new Headers(request.headers);
    const realIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || '127.0.0.1';
    let ipHash = 0;
    for (let i = 0; i < realIp.length; i++) {
        ipHash = ((ipHash << 5) - ipHash) + realIp.charCodeAt(i);
        ipHash |= 0;
    }
    ipHash = Math.abs(ipHash);
    const pseudoIp = `11.${(ipHash >> 16) & 255}.${(ipHash >> 8) & 255}.${ipHash & 255}`;

    headers.set("Host", target.host);
    STRIP_REQ_HEADERS.forEach(h => headers.delete(h));
    headers.set('X-UP-Proxy-Loop', '1'); 
    headers.set('X-Forwarded-For', pseudoIp);
    headers.set('X-Real-IP', pseudoIp);
    headers.set('CF-Connecting-IP', pseudoIp);

    // Cookie 垃圾回收 (GC) 机制：防止作用域污染导致的 400 异常
    let cookiesToClear =[];
    const reqCookies = headers.get('cookie');
    if (reqCookies) {
        let isolatedCookies = [];
        let allUpCookies =[];
        for (let pair of reqCookies.split(';')) {
            const trimmed = pair.trim(), eqIdx = trimmed.indexOf('='), name = eqIdx === -1 ? trimmed : trimmed.substring(0, eqIdx);
            if (name === '__UP_AUTH__' || name === '__UP_LAST_TARGET__') continue;
            const m = name.match(UP_COOKIE_REGEX);
            if (m) {
                allUpCookies.push({ name: name, domain: m[1] });
                if (target.hostname === m[1] || target.hostname.endsWith('.'+m[1])) {
                    isolatedCookies.push(`${m[2]}${eqIdx === -1 ? '' : trimmed.substring(eqIdx)}`);
                }
            }
        }
        
        // 当 Cookie 长度逼近 3KB 或键数超过 40 时，触发垃圾回收保护
        if (reqCookies.length > 3072 || allUpCookies.length > 40) {
            for (let c of allUpCookies) {
                // 仅剥离与当前正在访问目标毫不相干的旧域名 Cookie
                if (!(target.hostname === c.domain || target.hostname.endsWith('.'+c.domain))) {
                    cookiesToClear.push(c.name);
                }
            }
        }

        headers.delete('cookie');
        if (isolatedCookies.length > 0) headers.set('cookie', isolatedCookies.join('; '));
    }

    let finalReferer = "", reqOrigin = target.origin;
    const clientReferer = request.headers.get("Referer");
    if (clientReferer) {
        try {
            let refPath = clientReferer.slice(new URL(clientReferer).origin.length).replace(/^\/+/, "").replace(PROTOCOL_REGEX, "$1://");
            if (SECRET_PREFIX && refPath.startsWith(SECRET_PREFIX.slice(1))) refPath = refPath.replace(SECRET_PREFIX.slice(1), '').replace(/^\/+/, "");
            if (refPath.includes('%2Fhttps%3A')) refPath = safeDecode(refPath);
            let em = refPath.match(/^(https?:\/\/[^\/]+)\/+(https?:\/\/.*)/i);
            if (em) refPath = em[2];
            if (refPath.startsWith("http")) { finalReferer = refPath; reqOrigin = new URL(finalReferer).origin; }
        } catch (e) {}
    }

    headers.set("Referer", finalReferer || (target.origin + "/")); 
    if (request.method !== "GET" || request.headers.has("Origin") || request.headers.get("Upgrade") === "websocket") headers.set("Origin", reqOrigin);

    const fetchOpts = { method: request.method, headers, redirect: "manual" };
    
    if (request.body && !["GET", "HEAD"].includes(request.method)) { 
        let finalBody = request.body;
        const needsDecryption = headers.get("X-Up-Enc") === "1" || (headers.get("content-type") || "").includes("application/x-www-form-urlencoded");
        if (needsDecryption) {
            try {
                const text = await request.text();
                finalBody = text;
                let encPayload = null;
                const searchParamMatch = text.match(/__UP_ENC__=([^&]+)/);
                if (searchParamMatch) encPayload = safeDecode(searchParamMatch[1]);
                else if (text.startsWith("__UP_ENC__")) encPayload = text.substring(10);
                
                if (encPayload) {
                    let decryptSuccess = false;
                    try {
                        const keys = await getCryptoKeys(env);
                        const parsed = JSON.parse(atob(encPayload));

                        if (parsed.t) {
                            const age = Date.now() - parsed.t;
                            const maxAge = parseInt(env.REPLAY_WINDOW_MS) || 86400000;
                            if (age > maxAge || age < -86400000) {
                                return buildUIResponse("🚫 安全时间戳异常", "Time Sync Error", "您的设备时间偏差过大或请求已过期，已被安全策略自动拦截。", 403);
                            }
                        }

                        const aesKeyRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, keys.workerKeyPair.privateKey, Uint8Array.from(atob(parsed.r), c => c.charCodeAt(0)));
                        const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]);
                        const decryptedBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Uint8Array.from(atob(parsed.i), c => c.charCodeAt(0)) }, aesKey, Uint8Array.from(atob(parsed.d), c => c.charCodeAt(0)));
                        finalBody = new TextDecoder().decode(decryptedBuf);
                        headers.set("content-length", new Blob([finalBody]).size.toString());
                        decryptSuccess = true;
                    } catch (decErr) {
                        let isForm = text.includes('__UP_ENC__=');
                        if (isForm) {
                            try {
                                let sp = new URLSearchParams(text);
                                sp.delete('__UP_ENC__');
                                sp.delete('__UP_ENCH__');
                                finalBody = sp.toString();
                                headers.set("content-length", new Blob([finalBody]).size.toString());
                            } catch (ex) {
                                finalBody = text;
                            }
                        } else {
                            return new Response('<script>sessionStorage.removeItem("__up_jwk");alert("安全隧道密钥已自动轮换，请刷新页面后重试操作。\\nSecurity key rotated, please refresh and retry.");location.reload();</script>', { status: 409, headers: { "Content-Type": "text/html;charset=utf-8" } });
                        }
                    }
                }
            } catch (e) {} 
        }
        headers.delete("X-Up-Enc");
        if (headers.get("content-type")?.includes("multipart/form-data") || !needsDecryption) {
            fetchOpts.body = request.body; fetchOpts.duplex = "half"; 
        } else fetchOpts.body = finalBody;
    }

    if (request.headers.get("Upgrade") === "websocket") {
        target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
        return fetch(target.toString(), fetchOpts);
    }

    let response;
    try { response = await fetch(target, fetchOpts); } 
    catch (err) { return buildUIResponse("⌛ 网关请求超时", "Upstream Gateway Timeout", "上游目标服务器未能及时响应您的请求，请稍后重试。", 504); }

    const newHeaders = new Headers(response.headers);

    // 下发 Cookie 清理指令 (GC 执行段)
    if (cookiesToClear.length > 0) {
        // 单次请求最多下发 20 条删除指令，平滑卸载避免并发头超限
        const clearLimit = Math.min(cookiesToClear.length, 20);
        for (let i = 0; i < clearLimit; i++) {
            newHeaders.append("set-cookie", `${cookiesToClear[i]}=; Domain=${proxyHost}; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=None; Secure`);
        }
    }

    const contentType = (newHeaders.get("content-type") || "").toLowerCase();
    const contentLength = Number(newHeaders.get("content-length") || 0);

    const isHTML = contentType.includes("html");
    const isM3U8 = !isHTML && (contentType.includes("mpegurl") || contentType.includes("application/vnd.apple.mpegurl") || target.pathname.toLowerCase().endsWith(".m3u8"));
    
    if (!isM3U8 && (response.status === 206 || request.headers.has("range") || contentType.includes("video/") || contentType.includes("audio/") || contentType.includes("event-stream") || contentType.includes("application/octet-stream"))) {
        const o = request.headers.get("Origin") || "*";
        newHeaders.set("Access-Control-Allow-Origin", o);
        if (o !== "*") newHeaders.set("Access-Control-Allow-Credentials", "true");
        newHeaders.set("Access-Control-Expose-Headers", Array.from(newHeaders.keys()).join(', ')); 
        newHeaders.set("Cache-Control", "no-transform"); 
        newHeaders.delete("content-security-policy"); 
        return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
    }

    const isCSS = !isHTML && contentType.includes("css");
    const isXML = !isHTML && !isM3U8 && (contentType.includes("xml") || target.pathname.toLowerCase().endsWith(".xml"));
    const isJS = !isHTML && !isM3U8 && (contentType.includes("javascript") || contentType.includes("json") || target.pathname.toLowerCase().endsWith(".js"));
    const shouldRewriteBody = (isHTML || isCSS || isXML || isJS || isM3U8) && contentLength < MAX_REWRITE_SIZE;

    STRIP_RES_HEADERS.forEach(h => newHeaders.delete(h));
    newHeaders.set("X-Content-Type-Options", "nosniff");
    newHeaders.set("X-XSS-Protection", "1; mode=block");
    newHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

    if (shouldRewriteBody) { newHeaders.delete("content-encoding"); newHeaders.delete("content-length"); }
    
    newHeaders.set("Cache-Control", "no-transform");
    const currentOrigin = request.headers.get("Origin") || "*";
    newHeaders.set("Access-Control-Allow-Origin", currentOrigin);
    newHeaders.set("Access-Control-Expose-Headers", Array.from(newHeaders.keys()).join(', '));
    if (currentOrigin !== "*") newHeaders.set("Access-Control-Allow-Credentials", "true");

    newHeaders.append("set-cookie", `__UP_LAST_TARGET__=${encodeURIComponent(target.origin)}; Path=/; SameSite=None; Secure`);

    const loc = newHeaders.get("location");
    const baseProxyOrigin = url.origin + (SECRET_PREFIX || "");
    if (loc) {
        try {
            const absLoc = new URL(loc, target).href;
            if (!absLoc.startsWith(baseProxyOrigin)) newHeaders.set("location", baseProxyOrigin + "/" + absLoc);
        } catch {}
    }

    if (typeof newHeaders.getSetCookie === 'function') {
        const cookies = newHeaders.getSetCookie();
        if (cookies.length) {
            newHeaders.delete("set-cookie");
            for (let cookie of cookies) {
                let parts = cookie.split(';'), nameVal = parts[0].trim(), eqIdx = nameVal.indexOf('=');
                let name = eqIdx === -1 ? nameVal : nameVal.substring(0, eqIdx), val = eqIdx === -1 ? '' : nameVal.substring(eqIdx);
                if (name === '__UP_LAST_TARGET__') { newHeaders.append("set-cookie", cookie); continue; }

                let origDomain = target.hostname, extraParts =[];
                for (let i = 1; i < parts.length; i++) {
                    let p = parts[i].trim(), pl = p.toLowerCase();
                    if (pl.startsWith('domain=')) origDomain = p.substring(7).trim().replace(/^\./, '');
                    else if (!pl.startsWith('path=') && !pl.startsWith('samesite') && !pl.startsWith('secure')) extraParts.push(p);
                }
                newHeaders.append("set-cookie", `__UP_${origDomain}__${name}${val}; Domain=${proxyHost}; Path=/; SameSite=None; Secure${extraParts.length ? '; ' + extraParts.join('; ') : ''}`);
            }
        }
    }

    if (!shouldRewriteBody) return new Response(response.body, { status: response.status, headers: newHeaders });

    if (isHTML) return rewriteHTML(response, newHeaders, baseProxyOrigin, target);
    if (isM3U8) return rewriteM3U8Response(response, newHeaders, baseProxyOrigin, target);
    if (isXML) return rewriteTextResource(response, newHeaders, baseProxyOrigin, target, false);
    if (isCSS) return rewriteCSSResponse(response, newHeaders, baseProxyOrigin, target);
    if (isJS) return rewriteJSResponse(response, newHeaders, baseProxyOrigin, target);

    return new Response(response.body, { status: response.status, headers: newHeaders });
}

async function getDecodedText(res, ct) {
    let charset = 'utf-8';
    const match = ct.match(/charset=([^;]+)/i);
    if (match) charset = match[1].replace(/['"]/g, '').trim().toLowerCase();
    if (charset === 'utf-8' || charset === 'utf8' || !match) return await res.text();
    try { return new TextDecoder(charset).decode(await res.arrayBuffer()); } catch { return await res.text(); }
}

async function rewriteM3U8Response(res, headers, proxyOrigin, target) {
    const text = await res.text();
    const rewritten = text.replace(/(URI=")([^"]+)(")|(^[^#\s].*)/gm, (match, prefix, uri, suffix, nakedUrl) => {
        try {
            if (nakedUrl) return `${proxyOrigin}/${new URL(nakedUrl.trim(), target).href}`;
            return `${prefix}${proxyOrigin}/${new URL(uri, target).href}${suffix}`;
        } catch { return match; }
    });
    return new Response(rewritten, { status: res.status, headers });
}

async function rewriteTextResource(res, headers, proxyOrigin, target, isHTML) {
    const ct = headers.get("content-type") || "";
    const text = await getDecodedText(res, ct);
    if (ct.includes("charset=")) headers.set("content-type", ct.replace(/charset=[^;]+/gi, "charset=utf-8"));
    else if (ct) headers.set("content-type", ct + "; charset=utf-8");
    return new Response(text.replace(getOriginRegex(target.origin, isHTML), proxyOrigin + "/" + target.origin), { status: res.status, headers });
}

async function rewriteCSSResponse(res, headers, proxyOrigin, target) {
    const ct = headers.get("content-type") || "";
    let css = await getDecodedText(res, ct);
    if (ct.includes("charset=")) headers.set("content-type", ct.replace(/charset=[^;]+/gi, "charset=utf-8"));
    css = css.replace(CSS_URL_REGEX, (m, quote, p) => {
        let u = p.trim();
        if (IGNORE_URL_REGEX.test(u) || u.startsWith(proxyOrigin + '/http')) return m;
        try { return `url('${proxyOrigin}/${new URL(u, target).href}')`; } catch { return m; }
    });
    return new Response(css, { status: res.status, headers });
}

async function rewriteJSResponse(res, headers, proxyOrigin, target) {
    const ct = headers.get("content-type") || "";
    let js = await getDecodedText(res, ct);
    if (ct.includes("charset=")) headers.set("content-type", ct.replace(/charset=[^;]+/gi, "charset=utf-8"));
    js = js.replace(/\bwindow\.location\b/g, "window.__up_loc").replace(/\bdocument\.location\b/g, "window.__up_loc").replace(/\btop\.location\b/g, "top.__up_loc").replace(/\bparent\.location\b/g, "parent.__up_loc").replace(/\bself\.location\b/g, "self.__up_loc");
    if (!target.hostname.includes('youtube.com')) {
        js = js.replace(JS_LOC_REPLACE_REGEX, "window.__up_loc.$1").replace(JS_LOC_ASSIGN_REGEX, "window.__up_loc$1");
    }
    return new Response(js, { status: res.status, headers });
}

function safeRewriteAttr(el, attr, proxyOrigin, target) {
    let val = el.getAttribute(attr);
    if (val && !val.startsWith('#') && !IGNORE_URL_REGEX.test(val.trim()) && !val.startsWith(proxyOrigin + '/http')) {
        try { 
            if (!el.hasAttribute('data-up-orig-' + attr)) el.setAttribute('data-up-orig-' + attr, val);
            el.setAttribute(attr, proxyOrigin + "/" + new URL(val, target).href); 
        } catch {}
    }
}

async function rewriteHTML(res, headers, proxyOrigin, target) {
    const ct = headers.get("content-type") || "";
    let htmlText = await getDecodedText(res, ct);
    htmlText = htmlText.replace(getOriginRegex(target.origin, true), proxyOrigin + "/" + target.origin);
    
    htmlText = htmlText.replace(/<script([^>]*)>([\s\S]*?)<\/script>/gi, (match, attrs, content) => {
        if (!content || content.trim() === '') return match;
        if (attrs && /type=['"]?(application\/json|text\/template|text\/x-template|importmap)['"]?/i.test(attrs)) return match;
        let rewritten = content.replace(/\bwindow\.location\b/g, "window.__up_loc").replace(/\bdocument\.location\b/g, "window.__up_loc").replace(/\btop\.location\b/g, "top.__up_loc").replace(/\bparent\.location\b/g, "parent.__up_loc").replace(/\bself\.location\b/g, "self.__up_loc");
        if (!target.hostname.includes('youtube.com')) {
            rewritten = rewritten.replace(JS_LOC_REPLACE_REGEX, "window.__up_loc.$1").replace(JS_LOC_ASSIGN_REGEX, "window.__up_loc$1");
        }
        return `<script${attrs}>${rewritten}</script>`;
    });

    if (ct.includes("charset=")) headers.set("content-type", ct.replace(/charset=[^;]+/gi, "charset=utf-8"));
    const payloads = getCachedPayload(proxyOrigin, target.origin);
    let injected = false;

    return new HTMLRewriter()
        .on("head, body", { element(el) { 
            if (!injected) { el.before(`<base data-up-base="1" href="${proxyOrigin}/${target.origin}/"><meta name="referrer" content="unsafe-url">${payloads.sandbox}`, { html: true }); injected = true; }
        }})
        .on("base", { element(el) { if (!el.hasAttribute("data-up-base")) el.remove(); }})
        .on("meta", { element(el) {
            if (el.hasAttribute("charset")) el.setAttribute("charset", "utf-8");
            let he = (el.getAttribute("http-equiv") || "").toLowerCase();
            if (['content-security-policy', 'content-security-policy-report-only', 'x-frame-options'].includes(he)) return el.remove();
            if (he === 'refresh') {
                let c = el.getAttribute("content");
                if (c) {
                    const m = c.match(/(url\s*=\s*)(['"]?)(.+?)(\2|;|$)/i);
                    if (m && !IGNORE_URL_REGEX.test(m[3].trim()) && !m[3].trim().startsWith(proxyOrigin + '/http')) {
                        try { el.setAttribute("content", c.replace(m[0], m[1] + m[2] + (proxyOrigin + "/" + new URL(m[3].trim(), target).href) + m[4])); } catch {}
                    }
                }
            } else if (he === 'content-type') {
                let c = el.getAttribute("content");
                if (c) el.setAttribute("content", c.replace(/charset=[^;]+/gi, "charset=utf-8"));
            }
        }})
        .on("[integrity],[crossorigin], [nonce]", { element(el) { el.removeAttribute("integrity"); el.removeAttribute("crossorigin"); el.removeAttribute("nonce"); }})
        .on("iframe", { element(el) { el.removeAttribute("sandbox"); }})
        .on("include-fragment, turbo-frame", { element(el) { safeRewriteAttr(el, "src", proxyOrigin, target); }})
        .on("use", { element(el) { safeRewriteAttr(el, "href", proxyOrigin, target); }})
        .on("link[rel='manifest']", { element(el) { el.setAttribute("crossorigin", "use-credentials"); safeRewriteAttr(el, "href", proxyOrigin, target); }})
        .on(CSS_ATTR_SELECTORS, { element(el) { ATTR_LIST.forEach(attr => { if(el.hasAttribute(attr)) safeRewriteAttr(el, attr, proxyOrigin, target); }); }})
        .on("[style]", { element(el) {
            let style = el.getAttribute("style");
            if (style && style.toLowerCase().includes("url(")) {
                el.setAttribute("style", style.replace(CSS_URL_REGEX, (m, quote, p) => {
                    let u = p.trim(); if (IGNORE_URL_REGEX.test(u) || u.startsWith(proxyOrigin + '/http')) return m;
                    try { return `url('${proxyOrigin}/${new URL(u, target).href}')`; } catch { return m; }
                }));
            }
        }})
        .on("img[srcset], source[srcset]", { element(el) {
            let val = el.getAttribute("srcset");
            if (!val) return;
            el.setAttribute("srcset", val.split(",").map(p => {
                let[url, size] = p.trim().split(/\s+/);
                if(url.startsWith(proxyOrigin + '/http')) return p;
                try { return proxyOrigin + "/" + new URL(url, target).href + (size ? " " + size : ""); } catch { return p; }
            }).join(", "));
        }})
        .transform(new Response(htmlText, { status: res.status, headers }));
}

const UI_CSS = `:root{--bg:#f3f4f6;--card:rgba(255,255,255,0.9);--text:#1f2937;--sub:#6b7280;--primary:#3b82f6;--hover:#2563eb;--border:rgba(229,231,235,0.5);--shadow:rgba(0,0,0,0.05);--error:#ef4444;--error-bg:#fef2f2}@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--card:rgba(30,41,59,0.85);--text:#f1f5f9;--sub:#94a3b8;--primary:#3b82f6;--hover:#60a5fa;--border:rgba(51,65,85,0.5);--shadow:rgba(0,0,0,0.3);--error:#f87171;--error-bg:rgba(127,29,29,0.3)}}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;transition:background-color .3s}.box{background:var(--card);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);padding:2.5rem 2.2rem;border-radius:20px;box-shadow:0 10px 40px var(--shadow);text-align:center;width:88%;max-width:440px;border:1px solid var(--border);animation:popIn .4s cubic-bezier(0.175,0.885,0.32,1.275) forwards;opacity:0;transform:translateY(20px)}@keyframes popIn{to{opacity:1;transform:translateY(0)}}h2{margin:0 0 .5rem;display:flex;align-items:center;justify-content:center;gap:10px;font-weight:700}.badge{color:#fff;font-size:11px;padding:4px 10px;border-radius:20px;vertical-align:middle;font-weight:600;letter-spacing:0.5px}.desc{color:var(--sub);font-size:14px;margin-bottom:2rem;line-height:1.6}#searchForm{display:flex;flex-direction:column;gap:16px}.input-group{position:relative}input{width:100%;padding:14px 20px;font-size:15px;background:var(--bg);color:var(--text);border:1px solid transparent;border-radius:12px;box-sizing:border-box;outline:none;transition:all .25s ease;box-shadow:inset 0 2px 4px rgba(0,0,0,0.02)}input:focus{border-color:var(--primary);background:var(--card);box-shadow:0 0 0 4px rgba(59,130,246,0.15),0 4px 12px rgba(0,0,0,0.05);transform:translateY(-1px)}.engine-select{display:flex;align-items:center;justify-content:space-between;background:transparent;padding:0 4px;font-size:14px;color:var(--sub)}select{background:transparent;color:var(--primary);border:none;font-weight:600;cursor:pointer;outline:none;font-size:14px;transition:color .2s}select:hover{color:var(--hover)}button{background:var(--primary);color:white;border:none;padding:14px;font-size:16px;font-weight:600;border-radius:12px;cursor:pointer;transition:all .2s cubic-bezier(0.4,0,0.2,1);display:flex;justify-content:center;align-items:center;gap:8px;position:relative;overflow:hidden}button::after{content:"";position:absolute;top:50%;left:50%;width:100%;height:100%;background:rgba(255,255,255,0.2);transform:translate(-50%,-50%) scale(0);border-radius:50%;opacity:0;transition:transform .4s,opacity .4s}button:active::after{transform:translate(-50%,-50%) scale(2);opacity:1;transition:0s}button:hover{background:var(--hover);transform:translateY(-2px);box-shadow:0 6px 16px rgba(59,130,246,0.3)}button:active{transform:translateY(1px);box-shadow:0 2px 8px rgba(59,130,246,0.3)}.err-box{background:var(--error-bg);padding:1.2rem;border-radius:12px;margin-bottom:1.5rem;color:var(--error);font-weight:500;font-size:14px;text-align:left;border:1px solid rgba(239,68,68,0.2);line-height:1.5}.spinner{width:18px;height:18px;border:2px solid #fff;border-bottom-color:transparent;border-radius:50%;display:inline-block;animation:rotation 1s linear infinite}@keyframes rotation{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}code{background:rgba(0,0,0,0.05);padding:2px 6px;border-radius:4px;font-family:monospace;color:var(--text)}`;
const UI_JS = `if('serviceWorker' in navigator)window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(()=>{}));const form=document.getElementById('searchForm');const queryInput=document.getElementById('query');if(queryInput)queryInput.addEventListener('focus',function(){this.select()});if(form)form.addEventListener('submit',e=>{e.preventDefault();let q=queryInput.value.trim(),engine=document.getElementById('engine').value,target='';if(!q)return;const btn=document.getElementById('submitBtn');btn.innerHTML='<span class="spinner"></span><span>建立连接中...</span>';btn.style.pointerEvents='none';const isUrl=/^(https?:\\/\\/)?(([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}|localhost)(:\\d+)?(\\/.*)?$/.test(q);if(engine==='direct'||(isUrl&&!q.includes(' '))){if(!q.startsWith('http'))q='https://'+q;target=q}else{target=(engine==='bing'?'https://www.bing.com/search?q=':'https://duckduckgo.com/?q=')+encodeURIComponent(q)}setTimeout(()=>{let p=window.location.pathname;if(!p.endsWith('/'))p+='/';window.location.href=window.location.origin+p+target},150)});`;

function buildUIResponse(title, subtitle, content, status = 200, isHome = false) {
    const color = isHome ? 'var(--primary)' : 'var(--error)';
    const homePath = SECRET_PREFIX ? SECRET_PREFIX + "/" : "/";
    const uiHtml = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>${title}</title><style>${UI_CSS}</style></head><body><div class="box"><h2 style="color:${color}">${title}<span class="badge" style="background:${color}">${isHome ? 'v1.0.0 beta' : subtitle}</span></h2><p class="desc">${isHome ? '简易的无端代理（Web Proxy），支持一些简单站点的浏览。非自部署，严禁进行任何登录动作！' : '系统主动干预，当前网络请求已被安全策略拦截。'}</p>${isHome ? `<form id="searchForm"><div class="engine-select"><span>搜索引擎 / 直达 URL</span><select id="engine"><option value="ddg">DuckDuckGo</option><option value="bing">Bing</option><option value="direct">直接访问</option></select></div><div class="input-group"><input type="text" id="query" placeholder="完整网址或关键词... (按 Enter 出发)" required autocomplete="off" autofocus></div><button type="submit" id="submitBtn"><span>立即前往</span></button></form>` : `<div class="err-box">${content}</div>${status === 401 ? '' : `<button onclick="try{top.location.href='${homePath}'}catch(e){window.location.href='${homePath}'}" style="width:100%">返回系统主页</button>`}`}<script>${UI_JS}</script></div></body></html>`;
    return new Response(uiHtml, { status, headers: { "content-type": "text/html;charset=utf-8", "x-content-type-options": "nosniff", "content-security-policy": "frame-ancestors 'self';" } });
}

function buildHomepage(url) {
    return buildUIResponse("🚀 极简代理", "", "", 200, true);
}
