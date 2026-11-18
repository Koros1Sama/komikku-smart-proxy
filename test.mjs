import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sharp from 'sharp';
import {
  isPrivateOrReservedIp,
  detectImageMagic,
  compressImageBuffer,
  compressAndSliceForBundle,
} from './server.js';

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

describe('Image compression & tall-strip handling', () => {
  it('downscales and compresses a wide PNG manhwa panel to smaller WebP', async () => {
    // Realistic manhwa-like image with 32-bit LCG noise + gradients so PNG is large
    const width = 1400;
    const height = 2000;
    const raw = Buffer.alloc(width * height * 3);
    let seed = 1337;
    for (let i = 0; i < raw.length; i += 3) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      const v = (seed >>> 24) & 0xff;
      raw[i] = v;
      raw[i + 1] = (v + ((i / 3) % 128)) & 0xff;
      raw[i + 2] = (255 - v) & 0xff;
    }
    const png = await sharp(raw, { raw: { width, height, channels: 3 } }).png().toBuffer();

    const out = await compressImageBuffer(png, 'png', { w: '800', q: '65', jpg: '0', bw: '0' });
    assert.equal(out.ext, 'webp');
    assert.equal(out.bypassed, false);
    assert.ok(out.buffer.length < png.length, `Expected ${out.buffer.length} < ${png.length}`);

    const meta = await sharp(out.buffer).metadata();
    assert.equal(meta.width, 800);
  });

  it('automatically switches to MozJPEG when resized height exceeds WebP 16383px limit', async () => {
    const tallPng = await sharp({
      create: { width: 800, height: 17000, channels: 3, background: { r: 220, g: 220, b: 220 } },
    })
      .png()
      .toBuffer();

    const out = await compressImageBuffer(tallPng, 'png', { w: '800', q: '65', jpg: '0' });
    assert.equal(out.ext, 'jpg');
    assert.match(out.tierLabel, /jpeg-tall-fallback/);
  });

  it('slices ultra-tall strips into <=4500px WebP segments for chapter bundle', async () => {
    const tallPng = await sharp({
      create: { width: 1000, height: 12000, channels: 3, background: { r: 100, g: 150, b: 200 } },
    })
      .png()
      .toBuffer();

    const slices = await compressAndSliceForBundle(tallPng, 'png', '000', {
      w: '800',
      q: '65',
      maxSliceHeight: '4000',
    });
    assert.ok(slices.length >= 2, `Expected multiple slices, got ${slices.length}`);
    assert.equal(slices[0].filename, '000__001.webp');
    assert.equal(slices[1].filename, '000__002.webp');
  });
});
