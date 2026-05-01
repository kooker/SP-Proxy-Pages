// dist/sw.js (SP-Proxy Service Worker - Enterprise Edition v1.0.0)
"use strict";

const VERSION = "v1.0.0-202604212037";
const CACHE_PREFIX = "sp-proxy-cache-";
const DYNAMIC_CACHE = `${CACHE_PREFIX}dynamic-${VERSION}`;
const MAX_DYNAMIC_ITEMS = 150;
const MAX_CACHE_SIZE_BYTES = 5 * 1024 * 1024; 

const REGEX_PROXY_REQ = /^\/https?:\/\//i;
const REGEX_PROTOCOL = /^(https?):\/+/;
const REGEX_STREAM_EXT = /\.(m4s|mp4|ts|flv|webm|m3u8)$/i;

self.addEventListener("install", (event) => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        Promise.all([
            self.clients.claim(),
            caches.keys().then(keys => Promise.all(
                keys.filter(k => k.startsWith(CACHE_PREFIX) && k !== DYNAMIC_CACHE).map(k => caches.delete(k))
            ))
        ])
    );
});

const isProxyRequest = (url) => REGEX_PROXY_REQ.test(url.pathname);

function getTargetOrigin(url) {
    try {
        let clean = url.pathname.slice(1).replace(REGEX_PROTOCOL, "$1://");
        return new URL(clean.startsWith("http") ? clean : "https://" + clean).origin;
    } catch { return ""; }
}

function getTargetOriginFromReferrer(request) {
    const ref = request.referrer;
    if (!ref || !ref.includes('http')) return null;
    try {
        const refUrl = new URL(ref);
        return isProxyRequest(refUrl) ? getTargetOrigin(refUrl) : null;
    } catch { return null; }
}

async function getTargetOriginFromClient(clientId) {
    if (!clientId) return null;
    try {
        const client = await self.clients.get(clientId).catch(() => null);
        return (client && client.url && isProxyRequest(new URL(client.url))) ? getTargetOrigin(new URL(client.url)) : null;
    } catch { return null; }
}

async function getTargetOriginFromCookie(request) {
    try {
        const cookies = request.headers.get('cookie');
        if (cookies) {
            const match = cookies.match(/__UP_LAST_TARGET__=([^;]+)/);
            if (match) return decodeURIComponent(match[1]);
        }
    } catch(e) {}
    return null;
}

self.addEventListener("fetch", (event) => {
    const req = event.request;
    const url = new URL(req.url);
    const origin = self.location.origin;

    if (url.origin === origin && !isProxyRequest(url)) {
        const p = url.pathname;
        if (p === '/' || p === '/sw.js' || p === '/favicon.ico' || p === '/_up_pub_key' || p.startsWith('/_assets/')) return;

        event.respondWith((async () => {
            let targetOrigin = getTargetOriginFromReferrer(req) || await getTargetOriginFromClient(req.clientId) || await getTargetOriginFromCookie(req);
            
            if (targetOrigin) {
                const correctUrl = `${origin}/${targetOrigin}${url.pathname}${url.search}`;
                if (req.mode === 'navigate' && !req.headers.has('range') && req.method === 'GET') {
                    return Response.redirect(correctUrl, 307);
                }
                return routeFetch(req, correctUrl, url);
            }
            return fetch(req);
        })());
        return;
    } 
    
    if (!isProxyRequest(url) && url.origin !== origin) {
        const correctUrl = `${origin}/${url.href}`;
        if (req.mode === 'navigate' && !req.headers.has('range') && req.method === 'GET') {
            event.respondWith(Response.redirect(correctUrl, 307));
            return;
        }
        event.respondWith(routeFetch(req, correctUrl, url));
        return;
    }

    event.respondWith(routeFetch(req, req.url, url));
});

function routeFetch(req, targetUrl, parsedOriginalUrl) {
    const acceptHeader = req.headers.get('accept') || '';
    const isStreamChunk = req.destination === 'video' || 
                          req.destination === 'audio' || 
                          req.headers.has('range') || 
                          acceptHeader.includes('turbo-stream') || 
                          acceptHeader.includes('text/event-stream') || 
                          acceptHeader.includes('application/octet-stream') || 
                          parsedOriginalUrl.hostname.includes('googlevideo.com') || 
                          REGEX_STREAM_EXT.test(parsedOriginalUrl.pathname) || 
                          parsedOriginalUrl.pathname.includes('videoplayback');

    const isApiOrNoCache = req.method !== 'GET' || 
                           req.headers.has('authorization') || 
                           parsedOriginalUrl.pathname.match(/\/(api|graphql|trpc|rpc|v1|v2|v3)\//i);

    if (isStreamChunk || isApiOrNoCache) {
        return proxyNetworkFetch(req, targetUrl, isStreamChunk); 
    }

    if (req.destination === "document" || req.mode === "navigate" || parsedOriginalUrl.pathname.endsWith(".xml")) {
        return handleDocumentRequest(req, targetUrl);
    }
    return handleStaticResource(req, targetUrl);
}

async function proxyNetworkFetch(req, targetUrl, isLongConnection = false) {
    const headers = new Headers(req.headers);
    if (req.referrer && !headers.has('Referer')) headers.set('Referer', req.referrer);

    const fetchOpts = {
        method: req.method,
        headers: headers,
        redirect: req.redirect || "follow", 
        credentials: req.credentials,
        referrer: req.referrer
    };

    let timeoutId = null;
    if (!isLongConnection) {
        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), 30000);
        fetchOpts.signal = controller.signal;
    }

    if (req.body && req.method !== 'GET' && req.method !== 'HEAD') {
        const cl = Number(headers.get('content-length') || 0);
        if (cl > 0 && cl < 15 * 1024 * 1024) {
            try { fetchOpts.body = await req.clone().arrayBuffer(); } 
            catch { fetchOpts.body = req.body; fetchOpts.duplex = 'half'; }
        } else {
            fetchOpts.body = req.body;
            fetchOpts.duplex = 'half';
        }
    }

    try {
        const res = await fetch(targetUrl, fetchOpts);
        if (timeoutId) clearTimeout(timeoutId);
        return res;
    } catch (err) { 
        if (timeoutId) clearTimeout(timeoutId);
        if (err.name === 'AbortError') return new Response("Proxy Service Worker Timeout", { status: 504 });
        throw err;
    }
}

async function handleDocumentRequest(req, correctUrl) {
    try {
        const res = await proxyNetworkFetch(req, correctUrl, false);
        if (res && res.ok && res.status === 200) {
            const resToCache = res.clone();
            caches.open(DYNAMIC_CACHE)
                .then(c => c.put(req, resToCache))
                .then(triggerCacheTrim)
                .catch((e) => { console.warn('SW Cache write failed/Quota exceeded:', e.name); });
        }
        return res;
    } catch (err) {
        const cached = await caches.match(req);
        if (cached) return cached;
        return new Response("Service Worker: Offline or Gateway Unreachable.", { status: 503 });
    }
}

async function handleStaticResource(req, correctUrl) {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const cachedRes = await cache.match(req);
        if (cachedRes) return cachedRes;

        const res = await proxyNetworkFetch(req, correctUrl, false);
        if (res && res.ok && res.status === 200) {
            const cacheControl = res.headers.get("cache-control") || "";
            if (!cacheControl.includes("no-store") && !cacheControl.includes("no-cache")) {
                const size = Number(res.headers.get("content-length") || 0);
                if (size > 0 && size < MAX_CACHE_SIZE_BYTES) {
                    const resToCache = res.clone();
                    cache.put(req, resToCache).then(triggerCacheTrim).catch(() => {});
                }
            }
        }
        return res;
    } catch (err) { 
        return new Response("Service Worker: Resource Unavailable.", { status: 503 }); 
    }
}

let isTrimming = false;
function triggerCacheTrim() {
    if (isTrimming || Math.random() >= 0.1) return;
    isTrimming = true;
    trimCache().finally(() => { isTrimming = false; });
}

async function trimCache() {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const keys = await cache.keys();
        if (keys.length > MAX_DYNAMIC_ITEMS) {
            const keysToDelete = keys.slice(0, keys.length - MAX_DYNAMIC_ITEMS);
            await Promise.all(keysToDelete.map(r => cache.delete(r)));
        }
    } catch {}
}
