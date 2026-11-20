import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import zlib from 'node:zlib';
import { URL } from 'node:url';
import sharp from 'sharp';
import archiver from 'archiver';
import {
  compressImageBufferV2 as compressImageBuffer,
  compressAndSliceForBundleV2 as compressAndSliceForBundle,
  detectCjpegliBinary,
} from './pipeline.js';

const PORT = Number(process.env.PORT || 7860);
const PROXY_KEY = (process.env.PROXY_KEY || '').trim();
const MAX_DOWNLOAD_BYTES = Number(process.env.MAX_DOWNLOAD_BYTES || 35 * 1024 * 1024); // 35 MB cap
const MAX_FETCH_BYTES = Number(process.env.MAX_FETCH_BYTES || 15 * 1024 * 1024); // 15 MB cap for HTML/JSON bridge
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 15000);
const MAX_REDIRECTS = 5;
const DEFAULT_UA =
  'Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';

// Prevent libvips from blowing RAM on constrained free hosts
sharp.concurrency(2);
sharp.cache({ memory: 64, files: 0, items: 50 });

const serverStats = {
  startedAt: Date.now(),
  requestsTotal: 0,
  requestsSuccess: 0,
  requestsFailed: 0,
  bytesOriginalTotal: 0,
  bytesCompressedTotal: 0,
};

/**
 * Checks whether an IPv4 or IPv6 address belongs to a private, loopback,
 * link-local, CGNAT, multicast, or unspecified range (SSRF defense).
 */
export function isPrivateOrReservedIp(rawIp) {
  if (!rawIp) return true;
  let ip = rawIp.trim().toLowerCase();

  // Strip IPv6 zone ID if present (e.g. fe80::1%eth0)
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) ip = ip.slice(0, zoneIdx);

  // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (ip.startsWith('::ffff:')) {
    const rest = ip.slice(7);
    if (net.isIPv4(rest)) {
      return isPrivateOrReservedIp(rest);
    }
    // Hex form like ::ffff:7f00:0001
    const hexParts = rest.split(':');
    if (hexParts.length === 2) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
        const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isPrivateOrReservedIp(v4);
      }
    }
    return true;
  }

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / IMDS
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
    if (a === 192 && b === 0 && parts[2] === 2) return true; // TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
    if (a === 198 && b === 51 && parts[2] === 100) return true; // TEST-NET-2
    if (a === 203 && b === 0 && parts[2] === 113) return true; // TEST-NET-3
    if (a >= 224) return true; // Multicast / reserved
    return false;
  }

  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // fc00::/7 ULA
    if (ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb')) return true; // fe80::/10
    if (ip.startsWith('ff')) return true; // multicast
    if (ip.startsWith('2001:db8:')) return true; // documentation
    return false;
  }

  return true;
}

/**
 * Resolves a hostname and returns a verified public IP address, preventing DNS rebinding.
 */
async function resolveAndValidateHost(hostname) {
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new HttpError(403, 'Blocked private or reserved IP address');
    }
    return { address: hostname, family: net.isIPv6(hostname) ? 6 : 4 };
  }

  const results = await dns.promises.lookup(hostname, { all: true });
  if (!results || results.length === 0) {
    throw new HttpError(404, 'Origin hostname could not be resolved');
  }
  for (const entry of results) {
    if (isPrivateOrReservedIp(entry.address)) {
      throw new HttpError(403, 'Origin resolved to a private or reserved IP address');
    }
  }
  return results[0];
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function validateTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new HttpError(400, 'Invalid target URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new HttpError(400, 'Only HTTP and HTTPS protocols are allowed');
  }
  const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
  if (port !== 80 && port !== 443) {
    throw new HttpError(403, 'Only ports 80 and 443 are allowed');
  }
  return parsed;
}

function sanitizeReferer(rawRef) {
  if (!rawRef) return undefined;
  try {
    const u = new URL(rawRef);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u.toString();
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Detects image type from binary magic bytes (rejects HTML/JSON/SVG/unknown).
 */
export function detectImageMagic(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;

  // JPEG: FF D8 FF
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpeg';
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'png';
  // GIF: GIF87a / GIF89a
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return 'gif';
  // WEBP: RIFF....WEBP
  if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  // BMP: BM
  if (buf[0] === 0x42 && buf[1] === 0x4d) return 'bmp';
  // AVIF / HEIF: ....ftypavif / heic / mif1
  if (buf.toString('ascii', 4, 8) === 'ftyp') {
    const brand = buf.toString('ascii', 8, 12);
    if (brand === 'avif' || brand === 'avis') return 'avif';
    if (brand === 'heic' || brand === 'heix' || brand === 'mif1') return 'heif';
  }
  return null;
}

/**
 * Performs an SSRF-safe HTTP(S) GET with pinned DNS IP and manual redirect validation.
 */
async function safeFetchImageBuffer(targetUrl, { referer, userAgent } = {}, redirectDepth = 0) {
  if (redirectDepth > MAX_REDIRECTS) {
    throw new HttpError(502, 'Too many redirects');
  }

  const parsed = validateTargetUrl(targetUrl);
  const resolved = await resolveAndValidateHost(parsed.hostname);
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;

  const safeRef = sanitizeReferer(referer);
  const safeUa = (userAgent || DEFAULT_UA).replace(/[\r\n]/g, ' ').slice(0, 300);

  const reqHeaders = {
    'User-Agent': safeUa,
    Accept: 'image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8,*/*;q=0.5',
    'Accept-Encoding': 'identity', // keep byte count predictable and avoid double work
  };
  if (safeRef) {
    reqHeaders['Referer'] = safeRef;
    try {
      reqHeaders['Origin'] = new URL(safeRef).origin;
    } catch {
      // ignore invalid origin
    }
  }

  return new Promise((resolve, reject) => {
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: `${parsed.pathname}${parsed.search}`,
      method: 'GET',
      headers: reqHeaders,
      timeout: FETCH_TIMEOUT_MS,
      // Pin socket to already-validated IP so DNS cannot rebind between check and connect
      lookup: (_host, _opts, cb) => cb(null, resolved.address, resolved.family),
    };

    const req = transport.request(options, (res) => {
      const status = res.statusCode || 0;

      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        let nextUrl;
        try {
          nextUrl = new URL(res.headers.location, parsed).toString();
        } catch {
          return reject(new HttpError(502, 'Invalid redirect location'));
        }
        // Only preserve Referer on same-origin redirects
        const sameOrigin = new URL(nextUrl).origin === parsed.origin;
        safeFetchImageBuffer(
          nextUrl,
          { referer: sameOrigin ? safeRef : undefined, userAgent: safeUa },
          redirectDepth + 1,
        )
          .then(resolve)
          .catch(reject);
        return;
      }

      if (status < 200 || status >= 300) {
        res.resume();
        return reject(new HttpError(status === 403 || status === 429 ? status : 502, `Upstream returned HTTP ${status}`));
      }

      const contentLen = Number(res.headers['content-length'] || 0);
      if (contentLen > MAX_DOWNLOAD_BYTES) {
        res.destroy();
        return reject(new HttpError(413, 'Upstream image exceeds max size cap'));
      }

      const chunks = [];
      let totalBytes = 0;

      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_DOWNLOAD_BYTES) {
          res.destroy();
          return reject(new HttpError(413, 'Upstream image exceeded max download size'));
        }
        chunks.push(chunk);
      });

      res.on('end', () => {
        const buffer = Buffer.concat(chunks);
        const magic = detectImageMagic(buffer);
        if (!magic) {
          return reject(new HttpError(502, 'Upstream response is not a valid raster image (possible HTML/CF challenge)'));
        }
        resolve({ buffer, magic, upstreamStatus: status });
      });

      res.on('error', (err) => reject(new HttpError(502, err.message)));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new HttpError(504, 'Upstream fetch timed out'));
    });
    req.on('error', (err) => reject(new HttpError(502, err.message)));
    req.end();
  });
}

function checkAuth(req, parsedUrl) {
  if (!PROXY_KEY) return true;
  const headerKey = (req.headers['x-proxy-key'] || '').toString().trim();
  const queryKey = (parsedUrl.searchParams.get('key') || '').trim();
  return headerKey === PROXY_KEY || queryKey === PROXY_KEY;
}

const BLOCKED_FORWARD_HEADERS = new Set([
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
  'accept-encoding',
  'keep-alive',
  'upgrade',
  'proxy-authorization',
  'proxy-connection',
]);

/**
 * Decodes Base64-encoded JSON header map from X-Target-Headers, filtering out hop-by-hop headers.
 */
export function parseForwardedHeaders(encodedHeader, fallbackRef, fallbackUa) {
  const clean = {
    'User-Agent': (fallbackUa || DEFAULT_UA).replace(/[\r\n]/g, ' ').slice(0, 300),
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
  };
  const safeRef = sanitizeReferer(fallbackRef);
  if (safeRef) {
    clean['Referer'] = safeRef;
  }

  if (encodedHeader) {
    try {
      const jsonStr = Buffer.from(String(encodedHeader), 'base64').toString('utf8');
      const parsed = JSON.parse(jsonStr);
      if (parsed && typeof parsed === 'object') {
        for (const [rawKey, rawVal] of Object.entries(parsed)) {
          const k = String(rawKey).trim();
          const lower = k.toLowerCase();
          if (
            !k ||
            BLOCKED_FORWARD_HEADERS.has(lower) ||
            lower.startsWith('x-proxy-') ||
            lower.startsWith('x-target-') ||
            lower.startsWith('x-forwarded-') ||
            lower.startsWith('cf-')
          ) {
            continue;
          }
          const val = String(rawVal ?? '').replace(/[\r\n]/g, ' ').slice(0, 4096);
          if (val) clean[k] = val;
        }
      }
    } catch {
      // ignore malformed X-Target-Headers and use defaults
    }
  }
  return clean;
}

function decompressUpstreamBody(buffer, contentEncoding) {
  const enc = String(contentEncoding || '').toLowerCase().trim();
  if (!enc || buffer.length === 0) return buffer;
  try {
    if (enc.includes('br')) return zlib.brotliDecompressSync(buffer);
    if (enc.includes('gzip')) return zlib.gunzipSync(buffer);
    if (enc.includes('deflate')) return zlib.inflateSync(buffer);
  } catch {
    return buffer;
  }
  return buffer;
}

function readRawBody(req, maxBytes = 2 * 1024 * 1024) {
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
  if (typeof req.body === 'string') return Promise.resolve(Buffer.from(req.body, 'utf8'));
  return new Promise((resolve, reject) => {
    const chunks = [];
    let len = 0;
    req.on('data', (c) => {
      len += c.length;
      if (len > maxBytes) {
        req.destroy();
        return reject(new HttpError(413, 'Request body too large'));
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', (e) => reject(new HttpError(400, e.message)));
  });
}

/**
 * SSRF-hardened Zero-VPN source fetch bridge for HTML/JSON/AJAX catalog & chapter requests.
 */
async function safeFetchUpstreamBridge(
  targetUrl,
  { method = 'GET', headers = {}, body = null, collectedCookies = [] } = {},
  redirectDepth = 0,
) {
  if (redirectDepth > MAX_REDIRECTS) {
    throw new HttpError(502, 'Too many redirects');
  }

  const parsed = validateTargetUrl(targetUrl);
  const resolved = await resolveAndValidateHost(parsed.hostname);
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;
  const upperMethod = ['GET', 'POST', 'HEAD', 'OPTIONS'].includes(String(method).toUpperCase())
    ? String(method).toUpperCase()
    : 'GET';

  const reqHeaders = { ...headers };
  if (body && body.length > 0 && upperMethod === 'POST') {
    reqHeaders['Content-Length'] = String(body.length);
  } else {
    delete reqHeaders['Content-Length'];
  }

  return new Promise((resolve, reject) => {
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: `${parsed.pathname}${parsed.search}`,
      method: upperMethod,
      headers: reqHeaders,
      timeout: FETCH_TIMEOUT_MS,
      lookup: (_host, _opts, cb) => cb(null, resolved.address, resolved.family),
    };

    const req = transport.request(options, (res) => {
      const status = res.statusCode || 502;
      const rawSetCookie = res.headers['set-cookie'];
      if (Array.isArray(rawSetCookie)) {
        collectedCookies.push(...rawSetCookie);
      } else if (typeof rawSetCookie === 'string') {
        collectedCookies.push(rawSetCookie);
      }

      if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
        res.resume();
        let nextUrl;
        try {
          nextUrl = new URL(res.headers.location, parsed).toString();
        } catch {
          return reject(new HttpError(502, 'Invalid redirect location'));
        }
        const convertToGet = status === 301 || status === 302 || status === 303;
        const nextHeaders = { ...reqHeaders };
        if (convertToGet) {
          delete nextHeaders['Content-Type'];
          delete nextHeaders['content-type'];
          delete nextHeaders['Content-Length'];
        }
        safeFetchUpstreamBridge(
          nextUrl,
          {
            method: convertToGet ? 'GET' : upperMethod,
            headers: nextHeaders,
            body: convertToGet ? null : body,
            collectedCookies,
          },
          redirectDepth + 1,
        )
          .then(resolve)
          .catch(reject);
        return;
      }

      const chunks = [];
      let totalBytes = 0;

      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_FETCH_BYTES) {
          res.destroy();
          return reject(new HttpError(413, 'Upstream response exceeded max bridge size'));
        }
        chunks.push(chunk);
      });

      res.on('end', () => {
        const rawBuf = Buffer.concat(chunks);
        const decompressed = decompressUpstreamBody(rawBuf, res.headers['content-encoding']);
        resolve({
          status,
          contentType: res.headers['content-type'] || 'text/html; charset=utf-8',
          body: decompressed,
          finalUrl: parsed.toString(),
          setCookies: collectedCookies,
        });
      });

      res.on('error', (err) => reject(new HttpError(502, err.message)));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new HttpError(504, 'Upstream bridge fetch timed out'));
    });
    req.on('error', (err) => reject(new HttpError(502, err.message)));
    if (body && body.length > 0 && upperMethod === 'POST') {
      req.write(body);
    }
    req.end();
  });
}

function readJsonBody(req, maxBytes = 1024 * 1024) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return Promise.resolve(req.body);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let len = 0;
    req.on('data', (c) => {
      len += c.length;
      if (len > maxBytes) {
        req.destroy();
        return reject(new HttpError(413, 'Request JSON too large'));
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'Invalid JSON body'));
      }
    });
    req.on('error', (e) => reject(new HttpError(400, e.message)));
  });
}

async function runWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  async function next() {
    while (cursor < items.length) {
      const idx = cursor++;
      results[idx] = await worker(items[idx], idx);
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, () => next());
  await Promise.all(workers);
  return results;
}

export async function handleRequest(req, res) {
  const parsedUrl = new URL(req.url || '/', `http://localhost:${PORT}`);
  const path = parsedUrl.pathname;

  if (req.method === 'GET' && path === '/health') {
    const wantsAuthVerify =
      parsedUrl.searchParams.get('verify') === '1' || Boolean(req.headers['x-proxy-key']);
    if (wantsAuthVerify && !checkAuth(req, parsedUrl)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid proxy key' }));
      return;
    }

    const mem = process.memoryUsage();
    const hasCjpegli = Boolean(await detectCjpegliBinary());
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'ok',
        service: 'komikku-smart-proxy',
        version: '2.1.0',
        engine: hasCjpegli ? 'sharp/libvips + google/jpegli' : 'sharp/libvips',
        features: [
          'avif-auto',
          'webp-sharp-yuv',
          hasCjpegli ? 'google-jpegli' : 'mozjpeg-444',
          'smart-gutter-trim',
          'oled-bw-noise-snap',
          'auto-bw-detect',
          'hazy-scan-leveling',
          'adaptive-complexity',
          'seam-aware-slicing',
          'referer-forward',
          'tall-fallback',
          'chapter-bundle-cbz',
          'zero-vpn-bridge',
        ],
        authRequired: Boolean(PROXY_KEY),
        uptimeSec: Math.round((Date.now() - serverStats.startedAt) / 1000),
        memoryMb: Math.round(mem.rss / (1024 * 1024)),
        stats: serverStats,
      }),
    );
    return;
  }

  if (!checkAuth(req, parsedUrl)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized: invalid or missing proxy key' }));
    return;
  }

  // Zero-VPN Source Bridge endpoint for browsing blocked manga/manhwa sources without VPN
  if ((req.method === 'POST' || req.method === 'GET') && path === '/fetch') {
    serverStats.requestsTotal++;
    const targetUrl = (req.headers['x-target-url'] || parsedUrl.searchParams.get('url') || '').toString().trim();
    if (!targetUrl) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing target URL (X-Target-Url header or url param)' }));
      return;
    }

    try {
      const targetMethod = (req.headers['x-target-method'] || parsedUrl.searchParams.get('method') || 'GET')
        .toString()
        .toUpperCase();
      const forwardHeaders = parseForwardedHeaders(
        req.headers['x-target-headers'],
        parsedUrl.searchParams.get('ref') || req.headers['x-target-referer'],
        parsedUrl.searchParams.get('ua') || req.headers['user-agent'],
      );
      const reqBody = req.method === 'POST' ? await readRawBody(req) : null;

      const upstream = await safeFetchUpstreamBridge(targetUrl, {
        method: targetMethod,
        headers: forwardHeaders,
        body: reqBody,
      });

      const clientAcceptsGzip = String(req.headers['accept-encoding'] || '').includes('gzip');
      const shouldGzip = clientAcceptsGzip && upstream.body.length > 512;
      const outBody = shouldGzip ? zlib.gzipSync(upstream.body) : upstream.body;

      serverStats.requestsSuccess++;
      const resHeaders = {
        'Content-Type': upstream.contentType,
        'Content-Length': outBody.length,
        'X-Final-Url': upstream.finalUrl,
        'X-Upstream-Status': String(upstream.status),
        'X-Proxy-Bridge': 'komikku-v2',
      };
      if (shouldGzip) {
        resHeaders['Content-Encoding'] = 'gzip';
      }
      if (upstream.setCookies.length > 0) {
        resHeaders['X-Upstream-Set-Cookie'] = Buffer.from(
          JSON.stringify(upstream.setCookies),
          'utf8',
        ).toString('base64');
      }

      res.writeHead(upstream.status, resHeaders);
      res.end(outBody);
    } catch (err) {
      serverStats.requestsFailed++;
      const status = err instanceof HttpError ? err.status : 502;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message || 'Zero-VPN bridge fetch failed' }));
    }
    return;
  }

  // Single-image smart compression endpoint (compatible with Bandwidth Hero & Komikku Smart Proxy)
  if (req.method === 'GET' && (path === '/' || path === '/compress')) {
    serverStats.requestsTotal++;
    const targetUrl = parsedUrl.searchParams.get('url');
    if (!targetUrl) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing required "url" query parameter' }));
      return;
    }

    try {
      const referer = parsedUrl.searchParams.get('ref') || req.headers['x-target-referer'];
      const userAgent = parsedUrl.searchParams.get('ua') || req.headers['user-agent'];

      const { buffer: origBuf, magic } = await safeFetchImageBuffer(targetUrl, { referer, userAgent });
      const result = await compressImageBuffer(origBuf, magic, {
        w: parsedUrl.searchParams.get('w'),
        q: parsedUrl.searchParams.get('q') ?? parsedUrl.searchParams.get('l'),
        jpg: parsedUrl.searchParams.get('jpg'),
        bw: parsedUrl.searchParams.get('bw'),
        fmt: parsedUrl.searchParams.get('fmt'),
        trim: parsedUrl.searchParams.get('trim'),
        autobw: parsedUrl.searchParams.get('autobw'),
        adaptive: parsedUrl.searchParams.get('adaptive'),
      });

      const saved = Math.max(0, origBuf.length - result.buffer.length);
      serverStats.requestsSuccess++;
      serverStats.bytesOriginalTotal += origBuf.length;
      serverStats.bytesCompressedTotal += result.buffer.length;

      const headers = {
        'Content-Type': result.contentType,
        'Content-Length': result.buffer.length,
        'X-Content-Type-Options': 'nosniff',
        'X-Original-Size': String(origBuf.length),
        'X-Compressed-Size': String(result.buffer.length),
        'X-Saved-Bytes': String(saved),
        'X-Proxy-Tier': result.tierLabel,
        'X-Format': result.formatName || result.ext,
        'Cache-Control': 'private, max-age=86400',
      };
      if (result.trimmedPx > 0) {
        headers['X-Trimmed-Height'] = String(result.trimmedPx);
      }
      if (result.autoBw) {
        headers['X-Auto-BW'] = '1';
      }
      if (result.bypassed) {
        headers['X-Proxy-Bypass'] = result.tierLabel;
      }

      res.writeHead(200, headers);
      res.end(result.buffer);
    } catch (err) {
      serverStats.requestsFailed++;
      const status = err instanceof HttpError ? err.status : 502;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message || 'Proxy compression failed' }));
    }
    return;
  }

  // Turbo-CBZ chapter bundler endpoint
  if (req.method === 'POST' && path === '/chapter-bundle') {
    serverStats.requestsTotal++;
    try {
      const body = await readJsonBody(req);
      const pages = Array.isArray(body?.pages) ? body.pages : [];
      if (pages.length === 0 || pages.length > 300) {
        throw new HttpError(400, 'pages array must contain between 1 and 300 entries');
      }

      const digitCount = Math.max(3, String(pages.length).length);
      let origTotal = 0;
      let compTotal = 0;
      const failedPages = [];
      const filesToPack = [];

      const processed = await runWithConcurrency(pages, 5, async (p) => {
        const idx = Number(p.index);
        if (!Number.isInteger(idx) || idx < 0 || !p.url) {
          return { ok: false, index: p.index, url: p.url, error: 'Invalid page descriptor' };
        }
        const prefix = String(idx).padStart(digitCount, '0');
        try {
          const { buffer: origBuf, magic } = await safeFetchImageBuffer(p.url, {
            referer: p.referer,
            userAgent: p.userAgent,
          });
          const slices = await compressAndSliceForBundle(origBuf, magic, prefix, body);
          const sliceBytes = slices.reduce((sum, s) => sum + s.buffer.length, 0);
          return { ok: true, index: idx, origBytes: origBuf.length, compBytes: sliceBytes, slices };
        } catch (err) {
          return { ok: false, index: idx, url: p.url, error: err.message || 'Fetch failed' };
        }
      });

      for (const item of processed) {
        if (item.ok) {
          origTotal += item.origBytes;
          compTotal += item.compBytes;
          filesToPack.push(...item.slices);
        } else {
          failedPages.push({ index: item.index, url: item.url, error: item.error });
        }
      }

      if (filesToPack.length === 0) {
        throw new HttpError(502, 'All pages in chapter bundle failed upstream');
      }

      serverStats.requestsSuccess++;
      serverStats.bytesOriginalTotal += origTotal;
      serverStats.bytesCompressedTotal += compTotal;

      // Build ZIP STORE (.cbz) in memory so we can send accurate Content-Length & telemetry headers
      const zipBuffer = await new Promise((resolve, reject) => {
        const chunks = [];
        const archive = archiver('zip', { store: true });
        archive.on('data', (chunk) => chunks.push(chunk));
        archive.on('end', () => resolve(Buffer.concat(chunks)));
        archive.on('error', reject);

        for (const f of filesToPack) {
          archive.append(f.buffer, { name: f.filename });
        }
        archive.append(
          JSON.stringify({
            originalBytes: origTotal,
            compressedBytes: compTotal,
            savedBytes: Math.max(0, origTotal - compTotal),
            succeededCount: filesToPack.length,
            failedPages,
          }),
          { name: '_bundle_meta.json' },
        );
        archive.finalize();
      });

      if (process.env.VERCEL && zipBuffer.length > 4_200_000) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bundle exceeds serverless 4.2MB limit; use per-page fallback' }));
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Length': zipBuffer.length,
        'X-Original-Size': String(origTotal),
        'X-Compressed-Size': String(compTotal),
        'X-Saved-Bytes': String(Math.max(0, origTotal - compTotal)),
        'X-Pages-Succeeded': String(processed.filter((x) => x.ok).length),
        'X-Pages-Failed': String(failedPages.length),
      });
      res.end(zipBuffer);
    } catch (err) {
      serverStats.requestsFailed++;
      const status = err instanceof HttpError ? err.status : 502;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message || 'Chapter bundle failed' }));
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

const server = http.createServer(handleRequest);

import { pathToFileURL } from 'node:url';

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain && process.env.NODE_ENV !== 'test') {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`komikku-smart-proxy listening on port ${PORT}`);
  });
}

export { server, compressImageBuffer, compressAndSliceForBundle };
