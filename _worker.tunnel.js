/**
 * tunnel-only · _ref 精简版 Worker
 * ---------------------------------------------------------------
 * 仅保留 VLESS-over-WebSocket 主链 + 可配置出口（直连 / PROXYIP / SOCKS5）。
 * 出口档案存于 KV（键名 env.EGRESS_KEY || 'egress.json'），见 EGRESS_CONTRACT.md。
 * ?egress=<name> 强制出口；/sub?egress=<a,b> 动态生成订阅。
 * 移除了原版 admin 面板、subconverter 订阅转换、TURN/SSTP/gRPC 等重型链路。
 */
import { connect } from 'cloudflare:sockets';

const EDT_VERSION = String.fromCharCode(116,117,110,110,101,108,45,111,110,108,121,45,49,46,48,46,48);
const K_EGRESS = null; // 运行时解析：env.EGRESS_KEY || 'egress.json'

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- 字节工具 ----
function _a(data) {
 if (data instanceof Uint8Array) return data;
 if (data instanceof ArrayBuffer) return new Uint8Array(data);
 if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
 return new Uint8Array(data || 0);
}
function _b(...chunks) {
 const cs = chunks.map(toU8);
 const total = cs.reduce((s, c) => s + c.byteLength, 0);
 const out = new Uint8Array(total);
 let off = 0;
 for (const c of cs) { out.set(c, off); off += c.byteLength; }
 return out;
}
function _c(data, offset, uuidStr) {
 const hex = uuidStr.replace(/-/g, '');
 for (let i = 0; i < 16; i++) {
 const b = (parseInt(hex[i * 2], 16) << 4) | parseInt(hex[i * 2 + 1], 16);
 if (data[offset + i] !== b) return false;
 }
 return true;
}

/**
 * 解析 VLESS 请求头（与上游逐字节对齐）。
 * 返回 { hasError, addressType, port, hostname, isUDP, rawClientData, version }
 */
function _d(chunk, uuid) {
 const data = _a(chunk);
 const length = data.byteLength;
 if (length < 24) return { hasError: true, message: 'Invalid data' };
 const version = data[0];
 if (!_c(data, 1, uuid)) return { hasError: true, message: 'Invalid uuid' };
 const optLen = data[17];
 const cmdIndex = 18 + optLen;
 if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };
 const cmd = data[cmdIndex];
 let isUDP = false;
 if (cmd === 1) { /* TCP */ } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
 const portIdx = cmdIndex + 1;
 const port = (data[portIdx] << 8) | data[portIdx + 1];
 let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
 const addressType = data[portIdx + 2];
 switch (addressType) {
 case 1:
 addrLen = 4;
 if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 length' };
 hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
 break;
 case 2:
 if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
 addrLen = data[addrValIdx]; addrValIdx += 1;
 if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
 hostname = dec.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
 break;
 case 3:
 addrLen = 16;
 if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 length' };
 const ipv6 = [];
 for (let i = 0; i < 8; i++) { const b = addrValIdx + i * 2; ipv6.push(((data[b] << 8) | data[b + 1]).toString(16)); }
 hostname = ipv6.join(':');
 break;
 default:
 return { hasError: true, message: `Invalid address type: ${addressType}` };
 }
 if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
 const rawIndex = addrValIdx + addrLen;
 return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

// ---- SOCKS5 握手（与上游逐字节对齐） ----
async function _e(targetHost, targetPort, initialData, connect, parsed) {
 const { username, password, hostname, port } = parsed || {};
 const socket = connect({ hostname, port });
 const writer = socket.writable.getWriter();
 const reader = socket.readable.getReader();
 try {
 const methods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
 await writer.write(methods);
 let resp = await reader.read();
 if (resp.done || resp.value.byteLength < 2) throw new Error('S5 method selection failed');
 const method = new Uint8Array(resp.value)[1];
 if (method === 0x02) {
 if (!username || !password) throw new Error('S5 requires auth');
 const u = enc.encode(username), p = enc.encode(password);
 await writer.write(new Uint8Array([0x01, u.length, ...u, p.length, ...p]));
 resp = await reader.read();
 if (resp.done || new Uint8Array(resp.value)[1] !== 0x00) throw new Error('S5 auth failed');
 } else if (method !== 0x00) throw new Error(`S5 unsupported method: ${method}`);
 const hostBytes = enc.encode(targetHost);
 await writer.write(new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]));
 resp = await reader.read();
 if (resp.done || new Uint8Array(resp.value)[1] !== 0x00) throw new Error('S5 connection failed');
 if (initialData && initialData.byteLength > 0) await writer.write(initialData);
 writer.releaseLock(); reader.releaseLock();
 return socket;
 } catch (e) {
 try { writer.releaseLock(); } catch (_) { }
 try { reader.releaseLock(); } catch (_) { }
 try { socket.close(); } catch (_) { }
 throw e;
 }
}

// 解析 SOCKS5 账号串：user:pass@host:port 或 host:port
function _f(value) {
 let user = '', pass = '', rest = value;
 const at = value.indexOf('@');
 if (at > -1) { const cred = value.slice(0, at); rest = value.slice(at + 1); const c = cred.indexOf(':'); if (c > -1) { user = cred.slice(0, c); pass = cred.slice(c + 1); } else { user = cred; } }
 const idx = rest.lastIndexOf(':');
 const hostname = idx > -1 ? rest.slice(0, idx) : rest;
 const port = idx > -1 ? parseInt(rest.slice(idx + 1), 10) : 1080;
 return { username: user, password: pass, hostname, port };
}

// 出口拨号：根据档案类型返回一个已连接（含首包）的 socket
async function _g(egress, targetHost, targetPort, initialData, connect) {
 if (egress.type === 'socks5') {
 const parsed = _f(egress.value);
 return await _e(targetHost, targetPort, initialData, connect, parsed);
 }
 if (egress.type === 'proxy') {
 // 反代：连接到 proxy host:port（通常是 CDN / PROXYIP），首包直接写入
 const idx = egress.value.lastIndexOf(':');
 const hostname = idx > -1 ? egress.value.slice(0, idx) : egress.value;
 const port = idx > -1 ? (parseInt(egress.value.slice(idx + 1), 10) || 443) : 443;
 const socket = connect({ hostname, port });
 const writer = socket.writable.getWriter();
 if (initialData && initialData.byteLength > 0) await writer.write(initialData);
 writer.releaseLock();
 return socket;
 }
 // 直连（默认/回退）
 const socket = connect({ hostname: targetHost, port: targetPort });
 const writer = socket.writable.getWriter();
 if (initialData && initialData.byteLength > 0) await writer.write(initialData);
 writer.releaseLock();
 return socket;
}

// ---- 出口档案：读取 + 选择 ----
let egressCache = { key: null, data: null, ts: 0 };
async function _h(env) {
 const key = env.EGRESS_KEY || 'egress.json';
 const now = Date.now();
 if (egressCache.key === key && now - egressCache.ts < 30000 && egressCache.data) return egressCache.data;
 let raw = null;
 try { if (env.KV && typeof env.KV.get === 'function') raw = await env.KV.get(key); } catch (e) { }
 let data = { version: 1, default: null, egress: [], prefs: [] };
 if (raw) { try { const j = JSON.parse(raw); data = { ...data, ...j }; } catch (e) { } }
 egressCache = { key, data, ts: now };
 return data;
}
function _i(cfg) { return (cfg.egress || []).filter(e => e && e.enabled !== false && e.name); }
function _j(cfg, name) {
 const list = _i(cfg);
 if (name) {
 const hit = list.find(e => e.name === name);
 if (hit) return hit;
 }
 if (cfg.default) { const d = list.find(e => e.name === cfg.default); if (d) return d; }
 return list[0] || null; // 可能为 null → 调用方回退直连
}

// ---- VLESS-over-WebSocket 主链（闭包内完成双向转发） ----
async function _k(request, userID, egress) {
 const pair = new WebSocketPair();
 const [client, server] = Object.values(pair);
 server.accept();

 let remoteSocket = null;
 let closed = false;
 const earlyData = request.headers.get('sec-websocket-protocol') || '';
 const readable = _l(server, earlyData);

 // 下行：remote → client，在 remoteSocket 就绪后启动
 const pumpDownlink = async () => {
 if (!remoteSocket) return;
 const reader = remoteSocket.readable.getReader();
 try {
 while (true) {
 const { done, value } = await reader.read();
 if (done) break;
 if (server.readyState !== 1) break; // WebSocket.OPEN
 server.send(value);
 }
 } catch (e) { } finally { try { reader.releaseLock(); } catch (e) { } cleanup(); }
 };

 const cleanup = () => { if (closed) return; closed = true; try { if (remoteSocket) remoteSocket.close(); } catch (e) { } try { server.close(); } catch (e) { } };

 // 上行：client → remote
 readable.pipeTo(new WritableStream({
 async write(chunk) {
 if (remoteSocket) {
 const w = remoteSocket.writable.getWriter();
 await w.write(chunk); w.releaseLock();
 return;
 }
 // 首包：解析 VLESS 头并建连
 const parsed = _d(chunk, userID);
 if (parsed.hasError) throw new Error(parsed.message || 'parse error');
 if (parsed.isUDP) throw new Error('UDP not supported in tunnel-only');
 const respHeader = new Uint8Array([parsed.version, 0]);
 const initialData = _b(respHeader, parsed.rawClientData);
 remoteSocket = await _g(egress, parsed.hostname, parsed.port, initialData, (opts) => connect(opts));
 pumpDownlink();
 },
 close() { cleanup(); },
 abort() { cleanup(); },
 })).catch(() => cleanup());

 return new Response(null, { status: 101, webSocket: client });
}

// 可读 WS 流（支持 sec-websocket-protocol 携带的首包 base64）
function _l(webSocketServer, earlyDataHeader, log) {
 let readableStreamCancel = false;
 const stream = new ReadableStream({
 start(controller) {
 webSocketServer.addEventListener('message', (event) => {
 if (readableStreamCancel) return;
 const msg = event.data;
 controller.enqueue(msg);
 });
 webSocketServer.addEventListener('close', () => { try { if (!readableStreamCancel) controller.close(); } catch (e) { } _n(webSocketServer); });
 webSocketServer.addEventListener('error', (err) => { try { controller.error(err); } catch (e) { } _n(webSocketServer); });
 const { earlyData, error } = _m(earlyDataHeader);
 if (error) controller.error(error);
 else if (earlyData) controller.enqueue(earlyData);
 },
 pull() { },
 cancel(reason) { readableStreamCancel = true; _n(webSocketServer); },
 });
 return stream;
}
function _m(base64Str) {
 if (!base64Str) return { earlyData: null, error: null };
 try { const earlyData = Uint8Array.from(atob(base64Str), (x) => x.charCodeAt(0)).buffer; return { earlyData: new Uint8Array(earlyData), error: null }; }
 catch (error) { return { earlyData: null, error }; }
}
function _n(ws) { try { ws.close(); } catch (e) { } }

// ---- XHTTP（叉HTTP）传输 ----
function machineId(uuid) { return [uuid.slice(1, 7), '_' + uuid.slice(25, 31)]; }
const HPACK_HUFFMAN_LEN = [13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,20,24,20,21,22,21,21,23,22,21,22,25,25,24,24,26,23,26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,30];
function huffmanBytes(str) { const b = enc.encode(str); let bits = 0; for (let i = 0; i < b.length; i++) bits += HPACK_HUFFMAN_LEN[b[i]]; return Math.ceil(bits / 8); }
function xhttpPaddingValue(request, idHeader, idKey) {
 const h = request.headers.get(idHeader);
 if (h) { try { const u = new URL(h, 'https://x.invalid'); const q = u.searchParams.get(idKey); if (q) return q; } catch (e) { } return h; }
 const u = new URL(request.url); return u.searchParams.get(idKey) || '';
}
function checkXhttpPadding(request, idHeader, idKey) {
 const v = xhttpPaddingValue(request, idHeader, idKey);
 if (!v) return true;
 const len = huffmanBytes(v);
 return len >= 98 && len <= 1002;
}
const XHTTP_B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function genXhttpPadding(n) { let s = ''; for (let i = 0; i < n; i++) s += XHTTP_B62[Math.floor(Math.random() * XHTTP_B62.length)]; return s; }

// 跨 chunk 累积读取并解析首包（VLESS only；tunnel-only 不支持 Trojan）
async function readXhttpFirstPacket(reader, uuid) {
 let buffer = new Uint8Array(1024), offset = 0;
 const tryVless = (data) => {
 const len = data.byteLength;
 if (len < 18) return { s: 'more' };
 if (!_c(data, 1, uuid)) return { s: 'invalid' };
 const optLen = data[17], cmdIndex = 18 + optLen;
 if (len < cmdIndex + 1) return { s: 'more' };
 const cmd = data[cmdIndex];
 if (cmd !== 1 && cmd !== 2) return { s: 'invalid' };
 const portIndex = cmdIndex + 1;
 if (len < portIndex + 3) return { s: 'more' };
 const port = (data[portIndex] << 8) | data[portIndex + 1];
 const at = data[portIndex + 2], addrIndex = portIndex + 3;
 let headerLen = -1, hostname = '';
 if (at === 1) { if (len < addrIndex + 4) return { s: 'more' }; hostname = `${data[addrIndex]}.${data[addrIndex+1]}.${data[addrIndex+2]}.${data[addrIndex+3]}`; headerLen = addrIndex + 4; }
 else if (at === 2) { if (len < addrIndex + 1) return { s: 'more' }; const dl = data[addrIndex]; if (len < addrIndex + 1 + dl) return { s: 'more' }; hostname = dec.decode(data.subarray(addrIndex + 1, addrIndex + 1 + dl)); headerLen = addrIndex + 1 + dl; }
 else if (at === 3) { if (len < addrIndex + 16) return { s: 'more' }; const ip = []; for (let i = 0; i < 8; i++) { const b = addrIndex + i * 2; ip.push(((data[b] << 8) | data[b + 1]).toString(16)); } hostname = ip.join(':'); headerLen = addrIndex + 16; }
 else return { s: 'invalid' };
 if (!hostname) return { s: 'invalid' };
 return { s: 'ok', r: { hostname, port, isUDP: cmd === 2, rawData: data.subarray(headerLen), respHeader: new Uint8Array([data[0], 0]) } };
 };
 while (true) {
 const { value, done } = await reader.read();
 if (done) { if (offset === 0) return null; break; }
 const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
 if (offset + chunk.byteLength > buffer.byteLength) { const nb = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength)); nb.set(buffer.subarray(0, offset)); buffer = nb; }
 buffer.set(chunk, offset); offset += chunk.byteLength;
 const res = tryVless(buffer.subarray(0, offset));
 if (res.s === 'ok') return { ...res.r, reader };
 if (res.s === 'invalid') return null;
 }
 const res = tryVless(buffer.subarray(0, offset));
 return res.s === 'ok' ? { ...res.r, reader } : null;
}

async function handleXhttp(request, userID, egress) {
 if (!request.body) return new Response('Bad Request', { status: 400 });
 const [idHeader, idKey] = machineId(userID);
 if (!checkXhttpPadding(request, idHeader, idKey)) return new Response('Bad Request', { status: 400 });

 const reader = request.body.getReader();
 const first = await readXhttpFirstPacket(reader, userID);
 if (!first) { try { reader.releaseLock(); } catch (e) { } return new Response('Invalid request', { status: 400 }); }
 if (first.isUDP) { try { reader.releaseLock(); } catch (e) { } return new Response('UDP is not supported', { status: 400 }); }
 try { reader.releaseLock(); } catch (e) { }

 const headers = new Headers({ 'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });
 try { const u = new URL('https://x.invalid/'); u.searchParams.set(idKey, genXhttpPadding(100 + Math.floor(Math.random() * 901))); headers.set(idHeader, u.toString()); } catch (e) { }

 let socket;
 try {
 const initialData = _b(first.respHeader, first.rawData);
 socket = await _g(egress, first.hostname, first.port, initialData, (opts) => connect(opts));
 } catch (err) {
 return new Response('bad gateway', { status: 502 });
 }

 const abort = new AbortController();
 abort.signal.addEventListener('abort', () => { try { socket.close(); } catch (e) { } });

 // 上行：client body → socket
 (async () => {
 const up = request.body.getReader();
 try { while (true) { const { done, value } = await up.read(); if (done) break; if (value && value.byteLength) { const w = socket.writable.getWriter(); await w.write(value); w.releaseLock(); } } }
 catch (e) { } finally { try { up.releaseLock(); } catch (e) { } abort.abort(); }
 })();

 // 下行：socket → response
 const down = new IdentityTransformStream();
 (async () => {
 try { await socket.readable.pipeTo(down.writable, { signal: abort.signal }); }
 catch (e) { try { await down.writable.abort(e); } catch (_) { } }
 })();

 return new Response(down.readable, { status: 200, headers });
}

// ---- 动态订阅生成 ----
async function _o(cfg, names, userID, url, host) {
 const list = _i(cfg);
 const prefs = cfg.prefs || [];
 let targets = list;
 if (names && names.length) targets = list.filter(e => names.includes(e.name));
 if (!targets.length && cfg.default) { const d = list.find(e => e.name === cfg.default); targets = d ? [d] : list; }

 const lines = [];
 const path = cfg.path || '/';
 for (const e of targets) {
 const tag = e.name;
 if (e.type === 'proxy') {
 const idx = e.value.lastIndexOf(':');
 const h = idx > -1 ? e.value.slice(0, idx) : e.value;
 const p = idx > -1 ? (parseInt(e.value.slice(idx + 1), 10) || 443) : 443;
 lines.push(`vless://${userID}@${h}:${p}?path=${encodeURIComponent(path + '?egress=' + encodeURIComponent(tag))}&security=tls&type=ws&encryption=none#${encodeURIComponent(tag)}`);
 } else {
 // socks5：客户端连优选入口；无 prefs 时用占位域名
 const edges = prefs.length ? prefs : [{ ip: host, port: 443 }];
 for (const pf of edges) {
 lines.push(`vless://${userID}@${pf.ip}:${pf.port}?path=${encodeURIComponent(path + '?egress=' + encodeURIComponent(tag))}&security=tls&type=ws&encryption=none#${encodeURIComponent(tag + '·' + pf.ip)}`);
 }
 }
 }
 return lines.join('\n');
}

// ---- 伪装页兜底 ----
function _p(host) {
 return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title><style>body{width:60em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;background:#fff;color:#222}h1{font-size:2.4em}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p><p><em>${host}</em></p></body></html>`;
}

// ---- 测活探针（/probe）----
// 通用探活，两种模式：
// direct：直连 host:port，发 HTTP /cdn-cgi/trace 读 ip/loc（测非 CF 的反代域名/服务器）
// socks5 ：通过 SOCKS5 代理访问 cloudflare.com，读出口 ip/loc（测 SOCKS5 出口真实落地）
// 返回 {ok, latency, ip, loc, error}。注意：CF Workers 禁止出站到 Cloudflare IP 段，
// 故 CF 边缘 IP 类反代节点无法在此测活（需 VPS/smart-vpngate）。
async function _r(socket, sni, timeoutMs) {
 const writer = socket.writable.getWriter();
 const reader = socket.readable.getReader();
 const req = `GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
 const readGuard = new Promise((_, rej) => setTimeout(() => rej(new Error('read-timeout')), timeoutMs));
 try {
 await writer.write(new TextEncoder().encode(req));
 let buf = new Uint8Array(0);
 const max = 64 * 1024;
 while (buf.length < max) {
 const { value, done } = await Promise.race([reader.read(), readGuard]);
 if (done) break;
 if (value && value.byteLength) { const nb = new Uint8Array(buf.length + value.byteLength); nb.set(buf); nb.set(value, buf.length); buf = nb; }
 if (new TextDecoder().decode(buf).includes('\r\n\r\n')) break;
 }
 const text = new TextDecoder().decode(buf);
 const ip = (text.match(/(?:^|\n)ip=(.*)/) || [])[1];
 const loc = (text.match(/(?:^|\n)loc=(.*)/) || [])[1];
 return { ip: ip ? ip.trim() : undefined, loc: loc ? loc.trim() : undefined };
 } finally {
 try { writer.releaseLock(); } catch (e) { }
 try { reader.releaseLock(); } catch (e) { }
 try { socket.close(); } catch (e) { }
 }
}

async function _s(spec) {
 const start = Date.now();
 const timeoutMs = Math.min(8000, Math.max(1000, Number(spec.timeout) || 5000));
 const traceHost = spec.traceHost || 'cloudflare.com';
 const tracePort = spec.tracePort || 80;
 let socket = null;
 try {
 if (spec.type === 'socks5') {
 const parsed = _f(spec.value);
 socket = await _e(traceHost, tracePort, new Uint8Array(0), (o) => connect(o), parsed);
 } else {
 // direct：直连被探测 host:port（用于反代域名/服务器）
 const idx = String(spec.value).lastIndexOf(':');
 const hostname = idx > -1 ? String(spec.value).slice(0, idx) : spec.value;
 const port = idx > -1 ? (parseInt(String(spec.value).slice(idx + 1), 10) || 443) : 443;
 const guard = new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), timeoutMs));
 socket = await Promise.race([connect({ hostname, port }), guard]);
 }
 const latency = Date.now() - start;
 const info = await _r(socket, traceHost, timeoutMs);
 return { ok: true, latency, ...info };
 } catch (e) {
 try { if (socket) socket.close(); } catch (_) { }
 return { ok: false, latency: Date.now() - start, error: e.message || String(e) };
 }
}

async function _q(env) {
 if (env.UUID && UUID_RE.test(env.UUID)) return env.UUID.toLowerCase();
 const seed = (env.KEY || env.ADMIN || '_ref') + '|tunnel-only';
 // 简单确定性哈希生成 16 字节
 let h1 = 0x811c9dc5, h2 = 0x01000193;
 for (let i = 0; i < seed.length; i++) { const c = seed.charCodeAt(i); h1 = (h1 ^ c) * 16777619 >>> 0; h2 = (h2 + c * (i + 7)) >>> 0; }
 const bytes = [];
 for (let i = 0; i < 16; i++) { const v = ((i % 2 ? h1 : h2) >>> ((i % 8) * 4)) & 0xff; bytes.push(v); }
 // 设 version 4 + variant 位
 bytes[6] = (bytes[6] & 0x0f) | 0x40; bytes[8] = (bytes[8] & 0x3f) | 0x80;
 const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
 return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ---- 主入口 ----
export default {
 async fetch(request, env, ctx) {
 const url = new URL(request.url);
 const host = url.hostname;
 const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();
 const cfg = await _h(env);
 const userID = await _q(env);

 // 版本查询
 if (url.pathname.slice(1).toLowerCase() === 'version') {
 return new Response(JSON.stringify({ Version: EDT_VERSION }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
 }

 // 测活探针 /probe（前端「测」按钮后端）
 // 用法：?egress=名称 从 KV 档案测活该出口（socks5 走代理、proxy 直连域名）
 // 或 ?type=socks5&value=账号:密码@host:port / ?type=direct&value=host:port
 // 可选 ?key= 鉴权（设置 env.PROBE_KEY 时启用）
 if (url.pathname.slice(1).toLowerCase() === 'probe') {
 if (env.PROBE_KEY) {
 const k = url.searchParams.get('key');
 if (k !== env.PROBE_KEY) return new Response(JSON.stringify({ ok: false, error: 'forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
 }
 let spec = { type: url.searchParams.get('type') || 'direct', value: url.searchParams.get('value') || '', timeout: url.searchParams.get('timeout') };
 const egName = url.searchParams.get('egress');
 if (egName) {
 const eg = _j(cfg, egName);
 if (!eg) return new Response(JSON.stringify({ ok: false, error: 'egress not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
 spec = { type: eg.type === 'socks5' ? 'socks5' : 'direct', value: eg.value, timeout: url.searchParams.get('timeout') };
 }
 if (!spec.value) return new Response(JSON.stringify({ ok: false, error: 'missing value' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
 const result = await _s(spec);
 return new Response(JSON.stringify(result), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } });
 }

 // 动态订阅
 if (url.pathname.slice(1).toLowerCase() === 'sub') {
 const key = env.SUB_KEY;
 if (key) {
 const tok = url.searchParams.get('token') || url.searchParams.get('key');
 if (tok !== key) return new Response('Forbidden', { status: 403 });
 }
 const egParam = url.searchParams.get('egress');
 const names = egParam ? egParam.split(',').map(s => s.trim()).filter(Boolean) : [];
 const body = await _o(cfg, names, userID, url, host);
 const ua = (request.headers.get('User-Agent') || '').toLowerCase();
 const headers = { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Update-Interval': '12', 'Cache-Control': 'no-store' };
 if (!ua.includes('mozilla')) headers['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent('tunnel-only')}`;
 return new Response(body, { status: 200, headers });
 }

 // WebSocket 主链
 if (upgrade === 'websocket') {
 const egName = url.searchParams.get('egress');
 const egress = _j(cfg, egName) || { name: 'direct', type: 'direct', value: '' };
 try {
 const resp = await _k(request, userID, egress);
 resp.headers.set('X-Egress', egress.name || 'direct');
 return resp;
 } catch (e) {
 return new Response('WS error: ' + e.message, { status: 500 });
 }
 }

 // XHTTP（叉HTTP）主链：POST 且非 sub/version
 if (request.method === 'POST') {
 const egName = url.searchParams.get('egress');
 const egress = _j(cfg, egName) || { name: 'direct', type: 'direct', value: '' };
 try {
 const resp = await handleXhttp(request, userID, egress);
 resp.headers.set('X-Egress', egress.name || 'direct');
 return resp;
 } catch (e) {
 return new Response('XHTTP error: ' + e.message, { status: 500 });
 }
 }

 // 其余一律伪装页兜底（防探活）
 return new Response(_p(host), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
 },
};

