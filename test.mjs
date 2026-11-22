import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { PassThrough, Readable } from 'node:stream';
import sharp from 'sharp';
import {
  isPrivateOrReservedIp,
  detectImageMagic,
  compressImageBuffer,
  compressAndSliceForBundle,
  parseForwardedHeaders,
  createPinnedLookup,
  stripSensitiveCrossOriginHeaders,
  sanitizeKorotomiReleases,
  ByteLruCache,
  PerOriginPoliteLimiter,
  extractPaginatedNextUrls,
  handleRequest,
} from './server.js';
import {
  analyzePageContent,
  trimVerticalGutters,
  findSeamAwareCuts,
  mapQualityToAvif,
} from './pipeline.js';

function makeNoisyColorBuffer(width, height) {
  const raw = Buffer.alloc(width * height * 3);
  let seed = 1337;
  for (let i = 0; i < raw.length; i += 3) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const v = (seed >>> 24) & 0xff;
    raw[i] = v;
    raw[i + 1] = (v + ((i / 3) % 128)) & 0xff;
    raw[i + 2] = (255 - v) & 0xff;
  }
  return raw;
}

describe('SSRF IP validation', () => {
  it('blocks private, loopback, IMDS, and IPv4-mapped IPv6 addresses', () => {
    for (const ip of [
      '127.0.0.1',
      '10.0.0.1',
      '172.16.5.4',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '::1',
      'fc00::1',
      'fe80::1%eth0',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
    ]) {
      assert.equal(isPrivateOrReservedIp(ip), true, `Expected ${ip} to be blocked`);
    }
  });

  it('allows public IPv4 and IPv6 addresses', () => {
    for (const ip of ['1.1.1.1', '8.8.8.8', '104.16.132.229', '2606:4700:4700::1111']) {
      assert.equal(isPrivateOrReservedIp(ip), false, `Expected ${ip} to be allowed`);
    }
  });
});

describe('Magic-byte image detection', () => {
  it('rejects HTML/JSON/SVG payloads', () => {
    assert.equal(detectImageMagic(Buffer.from('<html><body>Cloudflare</body></html>')), null);
    assert.equal(detectImageMagic(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>')), null);
    assert.equal(detectImageMagic(Buffer.from('{"error":"blocked"}')), null);
  });

  it('recognizes PNG and JPEG magic bytes', async () => {
    const png = await sharp({
      create: { width: 100, height: 100, channels: 3, background: { r: 10, g: 20, b: 30 } },
    })
      .png()
      .toBuffer();
    assert.equal(detectImageMagic(png), 'png');
  });
});

describe('V2 Content Analysis, Gutter Trimming & Seam-Aware Slicing', () => {
  it('detects B&W manga saved as 24-bit RGB vs full-color manhwa', async () => {
    // 24-bit RGB image with neutral gray + minor scanner tint
    const bwRaw = Buffer.alloc(200 * 200 * 3);
    for (let i = 0; i < bwRaw.length; i += 3) {
      const g = ((i / 3) % 2 === 0) ? 238 : 30;
      bwRaw[i] = g;
      bwRaw[i + 1] = g;
      bwRaw[i + 2] = Math.min(255, g + 2);
    }
    const bwPng = await sharp(bwRaw, { raw: { width: 200, height: 200, channels: 3 } }).png().toBuffer();
    const bwStats = await analyzePageContent(bwPng);
    assert.equal(bwStats.isGrayscale, true);
    assert.equal(bwStats.isHazyScan, true);

    const colorPng = await sharp(makeNoisyColorBuffer(200, 200), {
      raw: { width: 200, height: 200, channels: 3 },
    })
      .png()
      .toBuffer();
    const colorStats = await analyzePageContent(colorPng);
    assert.equal(colorStats.isGrayscale, false);
  });

  it('collapses long solid vertical voids while preserving drawn panels', () => {
    const width = 400;
    const height = 3000;
    const raw = Buffer.alloc(width * height * 3, 255); // solid white background
    // Panel 1: rows 100..600 (noisy art)
    const art1 = makeNoisyColorBuffer(width, 500);
    art1.copy(raw, 100 * width * 3);
    // Huge 1200px white void: rows 600..1800
    // Panel 2: rows 1800..2800 (noisy art)
    const art2 = makeNoisyColorBuffer(width, 1000);
    art2.copy(raw, 1800 * width * 3);

    const res = trimVerticalGutters(raw, { width, height, channels: 3 });
    assert.ok(res.trimmedPx >= 900, `Expected >= 900px trimmed, got ${res.trimmedPx}`);
    assert.equal(res.info.height, height - res.trimmedPx);
    assert.ok(res.savedHeightPct >= 30);
  });

  it('chooses clean white gutter instead of cutting through noisy panel art', () => {
    const width = 400;
    const height = 7000;
    // Fill entire image with high-variance noise
    const raw = makeNoisyColorBuffer(width, height);
    // Insert a clean 120px solid white gutter at y = 3300..3420 (near target 3500)
    raw.fill(255, 3300 * width * 3, 3420 * width * 3);

    const slices = findSeamAwareCuts(raw, { width, height, channels: 3 }, 3800);
    assert.equal(slices.length, 2);
    const cutY = slices[1].top;
    assert.ok(
      cutY >= 3300 && cutY <= 3420,
      `Expected seam-aware cut inside gutter [3300..3420], got ${cutY}`,
    );
  });

  it('maps WebP quality to calibrated AVIF quality cleanly', () => {
    assert.ok(mapQualityToAvif(82) >= 48 && mapQualityToAvif(82) <= 55);
    assert.ok(mapQualityToAvif(65) >= 38 && mapQualityToAvif(65) <= 45);
  });

  it('parses Base64 X-Target-Headers safely and strips hop-by-hop headers', () => {
    const rawHeaders = {
      Referer: 'https://mangalek.org/manga/test',
      Cookie: 'session_id=abc123',
      'X-Requested-With': 'XMLHttpRequest',
      Host: 'evil.internal',
      'X-Proxy-Key': 'leaked',
      'CF-Connecting-IP': '1.2.3.4',
    };
    const b64 = Buffer.from(JSON.stringify(rawHeaders), 'utf8').toString('base64');
    const clean = parseForwardedHeaders(b64);
    assert.equal(clean['Referer'], 'https://mangalek.org/manga/test');
    assert.equal(clean['Cookie'], 'session_id=abc123');
    assert.equal(clean['X-Requested-With'], 'XMLHttpRequest');
    assert.equal(clean['Host'], undefined);
    assert.equal(clean['X-Proxy-Key'], undefined);
    assert.equal(clean['CF-Connecting-IP'], undefined);
  });

  it('evicts oldest entries cleanly in ByteLruCache without exceeding byte cap', () => {
    const cache = new ByteLruCache(100);
    cache.set('a', 'valA', 20, 60_000);
    cache.set('b', 'valB', 20, 60_000);
    cache.set('c', 'valC', 20, 60_000);
    cache.set('d', 'valD', 20, 60_000);
    cache.set('e', 'valE', 20, 60_000);
    // Access 'a' so 'b' becomes oldest
    assert.equal(cache.get('a'), 'valA');
    cache.set('f', 'valF', 20, 60_000);
    assert.equal(cache.get('b'), null);
    assert.equal(cache.get('a'), 'valA');
    assert.equal(cache.get('f'), 'valF');
    assert.ok(cache.totalBytes <= 100);
  });

  it('enforces max concurrency per origin in PerOriginPoliteLimiter', async () => {
    const limiter = new PerOriginPoliteLimiter(2, 10);
    let active = 0;
    let maxSeen = 0;
    const tasks = Array.from({ length: 6 }, () =>
      limiter.run('olympustaff.com', async () => {
        active++;
        maxSeen = Math.max(maxSeen, active);
        await new Promise((r) => setTimeout(r, 30));
        active--;
      }),
    );
    await Promise.all(tasks);
    assert.ok(maxSeen <= 2, `Expected maxSeen <= 2, got ${maxSeen}`);
  });
});

describe('V2 Image Compression & Smart Codec Routing', () => {
  it('routes normal-height PNG (<=4000px) to AVIF in auto mode and WebP when fmt=webp', async () => {
    const png = await sharp(makeNoisyColorBuffer(1200, 1800), {
      raw: { width: 1200, height: 1800, channels: 3 },
    })
      .png()
      .toBuffer();

    const avifOut = await compressImageBuffer(png, 'png', { w: '800', q: '65', jpg: '0', bw: '0' });
    assert.equal(avifOut.ext, 'avif');
    assert.equal(avifOut.bypassed, false);
    assert.ok(avifOut.buffer.length < png.length);

    const webpOut = await compressImageBuffer(png, 'png', { w: '800', q: '65', fmt: 'webp' });
    assert.equal(webpOut.ext, 'webp');
    assert.equal(webpOut.bypassed, false);
    assert.ok(webpOut.buffer.length < png.length);

    const meta = await sharp(avifOut.buffer).metadata();
    assert.equal(meta.width, 800);
  });

  it('routes tall un-sliced strip (4001..16383px) to WebP for lag-free Korotomi scrolling', async () => {
    const raw = makeNoisyColorBuffer(600, 6000);
    const png = await sharp(raw, { raw: { width: 600, height: 6000, channels: 3 } }).png().toBuffer();

    const out = await compressImageBuffer(png, 'png', { w: '600', q: '65', jpg: '0', trim: '0' });
    assert.equal(out.ext, 'webp');
    assert.equal(out.bypassed, false);
  });

  it('automatically switches to MozJPEG/Jpegli when resized height exceeds WebP 16383px limit', async () => {
    const tallPng = await sharp({
      create: { width: 800, height: 17000, channels: 3, background: { r: 220, g: 220, b: 220 } },
    })
      .png()
      .toBuffer();

    const out = await compressImageBuffer(tallPng, 'png', { w: '800', q: '65', jpg: '0', trim: '0' });
    assert.equal(out.ext, 'jpg');
    assert.match(out.tierLabel, /(jpeg-tall-fallback|jpegli-tall)/);
  });

  it('slices ultra-tall strips into <=3800px lag-free AVIF segments for chapter bundle', async () => {
    const raw = makeNoisyColorBuffer(800, 10000);
    const tallPng = await sharp(raw, { raw: { width: 800, height: 10000, channels: 3 } }).png().toBuffer();

    const slices = await compressAndSliceForBundle(tallPng, 'png', '000', {
      w: '800',
      q: '65',
      maxSliceHeight: '3800',
      trim: '0',
    });
    assert.ok(slices.length >= 3, `Expected >= 3 slices, got ${slices.length}`);
    assert.equal(slices[0].filename, '000__001.avif');
    assert.equal(slices[1].filename, '000__002.avif');
  });
});

describe('Tier 0 Hardening: Node 20+ Pinned Lookup, Cross-Origin Redirects, Streaming Bundle', () => {
  it('createPinnedLookup satisfies both Node 20+ autoSelectFamily (opts.all=true) and legacy lookup', async () => {
    const lookup = createPinnedLookup({ address: '127.0.0.1', family: 4 });

    const allRes = await new Promise((resolve, reject) => {
      lookup('example.test', { all: true }, (err, list) => (err ? reject(err) : resolve(list)));
    });
    assert.deepEqual(allRes, [{ address: '127.0.0.1', family: 4 }]);

    const singleRes = await new Promise((resolve, reject) => {
      lookup('example.test', { family: 0 }, (err, addr, fam) => (err ? reject(err) : resolve({ addr, fam })));
    });
    assert.deepEqual(singleRes, { addr: '127.0.0.1', fam: 4 });

    // Real Node 20+ socket test with http.request using createPinnedLookup
    const localServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok-pinned');
    });
    await new Promise((resolve) => localServer.listen(0, '127.0.0.1', resolve));
    const { port } = localServer.address();
    try {
      const body = await new Promise((resolve, reject) => {
        const req = http.request(
          {
            hostname: 'pinned.invalid',
            port,
            path: '/',
            method: 'GET',
            lookup: createPinnedLookup({ address: '127.0.0.1', family: 4 }),
          },
          (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
          },
        );
        req.on('error', reject);
        req.end();
      });
      assert.equal(body, 'ok-pinned');
    } finally {
      await new Promise((resolve) => localServer.close(resolve));
    }
  });

  it('stripSensitiveCrossOriginHeaders removes Cookie, Authorization, Proxy-Authorization, Referer, Origin', () => {
    const stripped = stripSensitiveCrossOriginHeaders({
      Cookie: 'sid=secret',
      Authorization: 'Bearer tok',
      'Proxy-Authorization': 'Basic abc',
      Referer: 'https://source-a.example/ch1',
      Origin: 'https://source-a.example',
      'User-Agent': 'Korotomi/1.0',
      Accept: '*/*',
    });
    assert.equal(stripped.Cookie, undefined);
    assert.equal(stripped.Authorization, undefined);
    assert.equal(stripped['Proxy-Authorization'], undefined);
    assert.equal(stripped.Referer, undefined);
    assert.equal(stripped.Origin, undefined);
    assert.equal(stripped['User-Agent'], 'Korotomi/1.0');
    assert.equal(stripped.Accept, '*/*');
  });

  it('extracts same-origin next page URLs from paginated chapter HTML and ignores cross-origin or non-page-1', () => {
    const html = `
      <nav>
        <a href="https://olympustaff.com/series/solo?page=2">2</a>
        <a href="?page=3">3</a>
        <a href="?page=4">4</a>
        <a href="?page=5">5</a>
        <a href="https://evil.example.com/series/solo?page=2">Evil</a>
      </nav>
    `;
    const urls = extractPaginatedNextUrls('https://olympustaff.com/series/solo', html, 3);
    assert.deepEqual(urls, [
      'https://olympustaff.com/series/solo?page=2',
      'https://olympustaff.com/series/solo?page=3',
      'https://olympustaff.com/series/solo?page=4',
    ]);

    // Already on page 2 -> do not prefetch again
    assert.deepEqual(
      extractPaginatedNextUrls('https://olympustaff.com/series/solo?page=2', html, 3),
      [],
    );
  });

  it('extracts next page URLs from JSON last_page responses', () => {
    const json = JSON.stringify({ data: [], current_page: 1, last_page: 4 });
    const urls = extractPaginatedNextUrls('https://api.example.org/chapters?page=1', json, 3);
    assert.deepEqual(urls, [
      'https://api.example.org/chapters?page=2',
      'https://api.example.org/chapters?page=3',
      'https://api.example.org/chapters?page=4',
    ]);
  });

  it('streams /chapter-bundle ZIP with _bundle_meta.json, enforces limits & SSRF blocking, and removes /fetch-batch', async () => {
    const invoke = async (urlPath, payload) => {
      const req = Readable.from([Buffer.from(JSON.stringify(payload), 'utf8')]);
      req.method = 'POST';
      req.url = urlPath;
      req.headers = { 'content-type': 'application/json' };
      let statusCode = 0;
      let headers = {};
      const res = new PassThrough();
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.writeHead = (code, hdrs) => {
        statusCode = code;
        headers = hdrs || {};
      };
      await handleRequest(req, res);
      return { statusCode, headers, raw: Buffer.concat(chunks) };
    };

    // Dead /fetch-batch endpoint should return 404
    const deadBatch = await invoke('/fetch-batch', { items: [{ url: 'https://example.com' }] });
    assert.equal(deadBatch.statusCode, 404);

    // Empty pages array should return 400
    const emptyBundle = await invoke('/chapter-bundle', { pages: [] });
    assert.equal(emptyBundle.statusCode, 400);

    // SSRF pages should stream a valid ZIP (PK\x03\x04) containing _bundle_meta.json with failedPages
    const ssrfBundle = await invoke('/chapter-bundle', {
      pages: [
        { index: 0, url: 'http://127.0.0.1/secret.png' },
        { index: 1, url: 'http://169.254.169.254/latest/meta-data/' },
      ],
    });
    assert.equal(ssrfBundle.statusCode, 200);
    assert.equal(ssrfBundle.headers['X-Bundle-Mode'], 'streaming-v2');
    // ZIP magic bytes PK\x03\x04
    assert.equal(ssrfBundle.raw[0], 0x50);
    assert.equal(ssrfBundle.raw[1], 0x4b);
    const zipAscii = ssrfBundle.raw.toString('utf8');
    assert.ok(zipAscii.includes('_bundle_meta.json'));
    assert.ok(zipAscii.includes('"succeededPages":0'));
  });

  it('protects /korotomi-update/* with dedicated app key and rewrites private assets without leaking repo URL', async () => {
    const req = Readable.from([]);
    req.method = 'GET';
    req.url = '/korotomi-update/releases';
    req.headers = {};
    let statusCode = 0;
    const chunks = [];
    const res = {
      writeHead(code) {
        statusCode = code;
      },
      end(buf) {
        if (buf) chunks.push(Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf)));
      },
    };
    await handleRequest(req, res);
    assert.equal(statusCode, 401);

    const sanitized = sanitizeKorotomiReleases(
      [
        {
          tag_name: 'v1.14.2',
          body: 'Tier 1 fixes',
          html_url: 'https://github.com/Koros1Sama/korotomi/releases/tag/v1.14.2',
          prerelease: false,
          draft: false,
          assets: [
            { id: 12345, name: 'Korotomi-arm64-v8a-v1.14.2.apk', browser_download_url: 'https://private.example/a' },
            { id: 99999, name: 'checksums.txt', browser_download_url: 'https://private.example/b' },
          ],
        },
        { tag_name: 'v1.14.3-draft', draft: true, assets: [{ id: 1, name: 'x.apk' }] },
      ],
      'https://komikku-smart-proxy.onrender.com',
      'secret_key',
    );
    assert.equal(sanitized.length, 1);
    assert.equal(sanitized[0].html_url, 'https://t.me/korossama');
    assert.equal(sanitized[0].assets.length, 1);
    assert.equal(
      sanitized[0].assets[0].browser_download_url,
      'https://komikku-smart-proxy.onrender.com/korotomi-update/asset/12345?k=secret_key',
    );
  });
});
