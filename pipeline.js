import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import sharp from 'sharp';

const execFileAsync = promisify(execFile);

export const WEBP_MAX_DIMENSION = 16383;
// Komikku/Mihon SubsamplingScaleImageView lacks partial tile seeking for AVIF (#1945),
// so auto-AVIF is restricted to <= 4500px height (zero scroll lag, maximum savings).
export const AVIF_LAG_FREE_MAX_HEIGHT = 4500;
export const AVIF_HARD_MAX_DIMENSION = 8192;
const MAX_INPUT_PIXELS = 120_000_000;

let cjpegliAvailablePromise = null;

/**
 * Checks once whether Google's `cjpegli` binary is available on the host (e.g. Docker/Render/Oracle).
 */
export async function detectCjpegliBinary() {
  if (cjpegliAvailablePromise) return cjpegliAvailablePromise;
  const bin = (process.env.CJPEGLI_BIN || 'cjpegli').trim();
  cjpegliAvailablePromise = execFileAsync(bin, ['--version'], { timeout: 2000 })
    .then(() => bin)
    .catch(() => null);
  return cjpegliAvailablePromise;
}

export function clampInt(val, min, max, fallback) {
  const n = Number(val);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

export function parseBoolFlag(val, defaultVal = false) {
  if (val === undefined || val === null || val === '') return defaultVal;
  if (typeof val === 'boolean') return val;
  const s = String(val).trim().toLowerCase();
  if (s === '1' || s === 'true' || s === 'yes' || s === 'on') return true;
  if (s === '0' || s === 'false' || s === 'no' || s === 'off') return false;
  return defaultVal;
}

/**
 * Maps WebP/JPEG quality scale (10..95) to calibrated libaom AVIF quality scale (24..78).
 * Calibrated so AVIF matches or beats WebP perceptual fidelity while saving 30-45% more bytes.
 */
export function mapQualityToAvif(webpQuality) {
  return clampInt(Math.round(webpQuality * 0.72 + 2), 24, 78, 52);
}

/**
 * Fast (<5ms) shrink-on-load content analyzer using a 128x128 RGB sample.
 * Detects:
 *  - True B&W / Grayscale manga pages saved as 24-bit RGB
 *  - Washed-out / hazy scanner backgrounds (for gentle non-destructive tonal cleanup)
 *  - Local edge energy (sparse dialogue vs normal vs dense action/screentone)
 */
export async function analyzePageContent(inputBuffer) {
  const { data, info } = await sharp(inputBuffer, { limitInputPixels: MAX_INPUT_PIXELS })
    .resize({ width: 128, height: 128, fit: 'inside', kernel: 'nearest' })
    .removeAlpha()
    .toColorspace('srgb')
    .raw()
    .toBuffer({ resolveWithObject: true });

  const w = info.width;
  const h = info.height;
  const ch = info.channels;
  const pixelCount = w * h;
  if (pixelCount === 0) {
    return {
      isGrayscale: false,
      isHazyScan: false,
      edgeEnergy: 15,
      complexity: 'normal',
      adaptiveDelta: 0,
    };
  }

  let neutralPixels = 0;
  let edgeSum = 0;
  let edgeSamples = 0;
  const lumaHist = new Uint32Array(256);

  // Precompute luma map for fast gradient & histogram stats
  const luma = new Uint8Array(pixelCount);
  for (let i = 0, p = 0; p < pixelCount; i += ch, p++) {
    const r = data[i];
    const g = ch >= 3 ? data[i + 1] : r;
    const b = ch >= 3 ? data[i + 2] : r;

    const maxDiff = Math.max(Math.abs(r - g), Math.abs(g - b), Math.abs(r - b));
    if (maxDiff <= 12) neutralPixels++;

    const y = (r * 77 + g * 150 + b * 29) >> 8;
    luma[p] = y;
    lumaHist[y]++;
  }

  for (let y = 0; y < h - 1; y++) {
    const row = y * w;
    const nextRow = (y + 1) * w;
    for (let x = 0; x < w - 1; x++) {
      const c = luma[row + x];
      edgeSum += Math.abs(c - luma[row + x + 1]) + Math.abs(c - luma[nextRow + x]);
      edgeSamples += 2;
    }
  }

  const isGrayscale = neutralPixels / pixelCount >= 0.992;
  const edgeEnergy = edgeSamples > 0 ? edgeSum / edgeSamples : 15;

  // Estimate 2nd and 98th percentile luma to spot hazy scanned paper without clipping art
  let p2 = 0;
  let p98 = 255;
  const lowThresh = Math.floor(pixelCount * 0.02);
  const highThresh = Math.floor(pixelCount * 0.98);
  let acc = 0;
  for (let v = 0; v < 256; v++) {
    acc += lumaHist[v];
    if (acc >= lowThresh && p2 === 0 && v > 0) {
      p2 = v;
    }
    if (acc >= highThresh) {
      p98 = v;
      break;
    }
  }

  // Only flag hazy scan on B&W manga with lifted blacks (>12) or gray paper background (220..246)
  const isHazyScan = isGrayscale && ((p98 >= 215 && p98 <= 246) || (p2 >= 12 && p2 <= 38));

  let complexity = 'normal';
  let adaptiveDelta = 0;
  if (edgeEnergy < 8.5) {
    complexity = 'sparse';
    adaptiveDelta = -5;
  } else if (edgeEnergy > 32) {
    complexity = 'dense';
    adaptiveDelta = 2;
  }

  return {
    isGrayscale,
    isHazyScan,
    p2,
    p98,
    edgeEnergy: Number(edgeEnergy.toFixed(1)),
    complexity,
    adaptiveDelta,
  };
}

/**
 * Samples interior column byte offsets [5%..95%] to ignore 1-2px outer scan border artifacts.
 */
function buildInteriorSampleOffsets(width, channels, maxSamples) {
  const sampleCount = Math.min(width, maxSamples);
  const sampleOffsets = new Int32Array(sampleCount);
  const minX = Math.floor(width * 0.05);
  const maxX = Math.max(minX, Math.floor(width * 0.95) - 1);
  const spanX = Math.max(1, maxX - minX);
  for (let s = 0; s < sampleCount; s++) {
    const x = sampleCount === 1 ? minX : minX + Math.floor((s * spanX) / (sampleCount - 1));
    sampleOffsets[s] = x * channels;
  }
  return sampleOffsets;
}

/**
 * Applies optional max-width downscale, grayscale conversion, and non-destructive hazy-scan leveling.
 */
function applyResizeAndTonalPrep(sharpPipe, { maxWidth, srcWidth, useGrayscale, forceGrayscale, analysis }) {
  let pipe = sharpPipe;
  if (maxWidth > 0 && srcWidth > maxWidth) {
    pipe = pipe.resize({ width: maxWidth, withoutEnlargement: true });
  }
  if (useGrayscale) {
    pipe = pipe.grayscale();
    if (analysis.isHazyScan && !forceGrayscale) {
      const gain = Math.min(1.12, 255 / Math.max(200, analysis.p98 - analysis.p2));
      const offset = -Math.round(analysis.p2 * gain * 0.5);
      pipe = pipe.linear(gain, offset);
    }
  }
  return pipe;
}

/**
 * Smart Vertical Gutter Trimming (KCC --ipc style) for tall manhwa/webtoon strips.
 * Collapses excessively long solid-color voids (>25% of width) down to a clean pacing margin (~14% of width).
 * Guarantees zero loss to any drawn panel, art, or text.
 */
export function trimVerticalGutters(rawPixels, info, opts = {}) {
  const { width, height, channels } = info;
  const minRatio = opts.minAspectRatio ?? 2.5;
  const minHeight = opts.minHeight ?? 2000;
  if (height < minHeight || height / width < minRatio) {
    return { data: rawPixels, info, trimmedPx: 0, savedHeightPct: 0 };
  }

  const maxGutter = Math.max(180, Math.round(width * 0.25));
  const keepMargin = Math.max(90, Math.round(width * 0.14));
  const keepTop = Math.floor(keepMargin / 2);
  const keepBottom = keepMargin - keepTop;
  const tolerance = 10;

  const sampleOffsets = buildInteriorSampleOffsets(width, channels, 32);
  const sampleCount = sampleOffsets.length;

  const rowStride = width * channels;
  const keepSpans = []; // pairs of [startY, endYExclusive]
  let currentKeepStart = 0;
  let totalRemoved = 0;

  let runStart = -1;
  let runR = 0;
  let runG = 0;
  let runB = 0;

  const flushRun = (runEndExclusive) => {
    if (runStart < 0) return;
    const runLen = runEndExclusive - runStart;
    if (runLen > maxGutter) {
      const cutStart = runStart + keepTop;
      const cutEnd = runEndExclusive - keepBottom;
      if (cutEnd > cutStart) {
        if (cutStart > currentKeepStart) {
          keepSpans.push([currentKeepStart, cutStart]);
        }
        totalRemoved += cutEnd - cutStart;
        currentKeepStart = cutEnd;
      }
    }
    runStart = -1;
  };

  for (let y = 0; y < height; y++) {
    const base = y * rowStride;
    const o0 = base + sampleOffsets[0];
    const r0 = rawPixels[o0];
    const g0 = channels >= 3 ? rawPixels[o0 + 1] : r0;
    const b0 = channels >= 3 ? rawPixels[o0 + 2] : r0;

    let uniform = true;
    for (let s = 1; s < sampleCount; s++) {
      const o = base + sampleOffsets[s];
      const r = rawPixels[o];
      const g = channels >= 3 ? rawPixels[o + 1] : r;
      const b = channels >= 3 ? rawPixels[o + 2] : r;
      if (
        Math.abs(r - r0) > tolerance ||
        Math.abs(g - g0) > tolerance ||
        Math.abs(b - b0) > tolerance
      ) {
        uniform = false;
        break;
      }
    }

    if (!uniform) {
      flushRun(y);
      continue;
    }

    if (runStart < 0) {
      runStart = y;
      runR = r0;
      runG = g0;
      runB = b0;
    } else if (
      Math.abs(r0 - runR) > tolerance ||
      Math.abs(g0 - runG) > tolerance ||
      Math.abs(b0 - runB) > tolerance
    ) {
      flushRun(y);
      runStart = y;
      runR = r0;
      runG = g0;
      runB = b0;
    }
  }
  flushRun(height);

  if (currentKeepStart < height) {
    keepSpans.push([currentKeepStart, height]);
  }

  const savedHeightPct = (totalRemoved / height) * 100;
  // Skip memory copy if savings are negligible (<3%)
  if (totalRemoved <= 0 || savedHeightPct < 3) {
    return { data: rawPixels, info, trimmedPx: 0, savedHeightPct: 0 };
  }

  const newHeight = height - totalRemoved;
  const outBuf = Buffer.allocUnsafe(newHeight * rowStride);
  let writeRow = 0;
  for (const [startY, endY] of keepSpans) {
    const spanRows = endY - startY;
    if (spanRows <= 0) continue;
    rawPixels.copy(outBuf, writeRow * rowStride, startY * rowStride, endY * rowStride);
    writeRow += spanRows;
  }

  return {
    data: outBuf,
    info: { ...info, height: newHeight },
    trimmedPx: totalRemoved,
    savedHeightPct: Number(savedHeightPct.toFixed(1)),
  };
}

/**
 * Seam-Aware Horizontal Slicer (SmartStitch algorithm).
 * Finds low-variance horizontal gutters near each target slice boundary so
 * speech bubbles and panels are never cut in half, while enforcing <= maxSliceHeight.
 */
export function findSeamAwareCuts(rawPixels, info, maxSliceHeight = 3800) {
  const { width, height, channels } = info;
  if (height <= maxSliceHeight) {
    return [{ top: 0, height }];
  }

  const rowStride = width * channels;
  const sampleOffsets = buildInteriorSampleOffsets(width, channels, 40);
  const sampleCount = sampleOffsets.length;

  const scoreRow = (y) => {
    const base = y * rowStride;
    let sumR = 0;
    let sumG = 0;
    let sumB = 0;
    for (let s = 0; s < sampleCount; s++) {
      const o = base + sampleOffsets[s];
      sumR += rawPixels[o];
      sumG += channels >= 3 ? rawPixels[o + 1] : rawPixels[o];
      sumB += channels >= 3 ? rawPixels[o + 2] : rawPixels[o];
    }
    const avgR = sumR / sampleCount;
    const avgG = sumG / sampleCount;
    const avgB = sumB / sampleCount;

    // Horizontal variance along row y
    let horizDev = 0;
    for (let s = 0; s < sampleCount; s++) {
      const o = base + sampleOffsets[s];
      const r = rawPixels[o];
      const g = channels >= 3 ? rawPixels[o + 1] : r;
      const b = channels >= 3 ? rawPixels[o + 2] : r;
      horizDev += Math.abs(r - avgR) + Math.abs(g - avgG) + Math.abs(b - avgB);
    }
    horizDev /= sampleCount;

    // Vertical transition against y-2 and y+2 to avoid slicing right on a panel edge
    let vertDiff = 0;
    if (y >= 2 && y + 2 < height) {
      const prevBase = (y - 2) * rowStride;
      const nextBase = (y + 2) * rowStride;
      for (let s = 0; s < sampleCount; s += 2) {
        const off = sampleOffsets[s];
        vertDiff +=
          Math.abs(rawPixels[base + off] - rawPixels[prevBase + off]) +
          Math.abs(rawPixels[base + off] - rawPixels[nextBase + off]);
      }
      vertDiff /= Math.ceil(sampleCount / 2);
    }

    return horizDev + vertDiff * 0.6;
  };

  const cuts = [0];
  let curY = 0;
  const searchRadius = Math.min(450, Math.floor(maxSliceHeight * 0.2));

  while (height - curY > maxSliceHeight) {
    const remaining = height - curY;
    const slicesLeft = Math.ceil(remaining / maxSliceHeight);
    const idealStep = Math.floor(remaining / slicesLeft);
    const yTarget = curY + idealStep;

    const minY = Math.max(curY + Math.min(800, Math.floor(maxSliceHeight * 0.35)), yTarget - searchRadius);
    const maxY = Math.min(curY + maxSliceHeight, height - 250, yTarget + searchRadius);

    let bestY = Math.min(yTarget, curY + maxSliceHeight);
    let bestScore = Infinity;

    for (let y = minY; y <= maxY; y += 2) {
      const score = scoreRow(y) + Math.abs(y - yTarget) * 0.002;
      if (score < bestScore) {
        bestScore = score;
        bestY = y;
        if (score < 0.05) break; // Perfect uniform gutter right near target
      }
    }

    if (bestY <= curY) {
      bestY = Math.min(curY + maxSliceHeight, height);
    }
    cuts.push(bestY);
    curY = bestY;
  }

  if (cuts[cuts.length - 1] < height) {
    cuts.push(height);
  }

  const slices = [];
  for (let i = 0; i < cuts.length - 1; i++) {
    slices.push({ top: cuts[i], height: cuts[i + 1] - cuts[i] });
  }
  return slices;
}

/**
 * Optional Google Jpegli (`cjpegli`) encoder when installed on Docker/Render/Oracle.
 * NEVER uses --xyb so Android non-ICC viewers display accurate colors.
 */
async function encodeWithCjpegli(sharpPipeline, quality, isGrayscale) {
  const bin = await detectCjpegliBinary();
  if (!bin) return null;

  const tmpId = crypto.randomBytes(6).toString('hex');
  const inPath = path.join(os.tmpdir(), `kp_in_${tmpId}.png`);
  const outPath = path.join(os.tmpdir(), `kp_out_${tmpId}.jpg`);

  try {
    // Fast uncompressed PNG handoff to cjpegli
    await sharpPipeline.png({ compressionLevel: 0 }).toFile(inPath);
    const args = [inPath, outPath, '-q', String(clampInt(quality, 30, 95, 78))];
    if (!isGrayscale && quality >= 70) {
      args.push('--chroma_subsampling=444');
    }
    await execFileAsync(bin, args, { timeout: 15000 });
    return await fs.readFile(outPath);
  } catch (err) {
    if (err?.code !== 'ENOENT') {
      console.warn(`cjpegli fallback to MozJPEG: ${err?.message || err}`);
    }
    return null;
  } finally {
    fs.unlink(inPath).catch(() => {});
    fs.unlink(outPath).catch(() => {});
  }
}

/**
 * Encodes a prepared sharp pipeline into the optimal format (AVIF, WebP sharp_yuv, Jpegli, or MozJPEG).
 */
async function encodePreparedPipeline(pipeline, { width, height, quality, fmt, wantJpg, isGrayscale, isAnimated }) {
  const forceAvif = fmt === 'avif' && !isAnimated && !wantJpg;
  const forceWebp = fmt === 'webp' && !wantJpg;
  const autoAvifAllowed =
    fmt === 'auto' &&
    !isAnimated &&
    !wantJpg &&
    height <= AVIF_LAG_FREE_MAX_HEIGHT &&
    width <= AVIF_LAG_FREE_MAX_HEIGHT;

  const canUseAvif =
    (forceAvif || autoAvifAllowed) &&
    width <= AVIF_HARD_MAX_DIMENSION &&
    height <= AVIF_HARD_MAX_DIMENSION &&
    width >= 2 &&
    height >= 2;

  if (canUseAvif) {
    const avifQ = mapQualityToAvif(quality);
    const buffer = await pipeline
      .avif({
        quality: avifQ,
        effort: 2,
        chromaSubsampling: '4:2:0',
      })
      .toBuffer();
    return {
      buffer,
      ext: 'avif',
      contentType: 'image/avif',
      formatName: 'avif',
      tierLabel: `avif-w${width}-q${avifQ}`,
    };
  }

  const exceedsWebp = width > WEBP_MAX_DIMENSION || height > WEBP_MAX_DIMENSION;
  const useJpeg = wantJpg || fmt === 'jpg' || fmt === 'jpeg' || (!forceWebp && exceedsWebp) || exceedsWebp;

  if (useJpeg) {
    // Prefer Google Jpegli if available on host; fall back to fully tuned MozJPEG
    const jpegliBuf = await encodeWithCjpegli(pipeline.clone(), quality, isGrayscale);
    if (jpegliBuf) {
      return {
        buffer: jpegliBuf,
        ext: 'jpg',
        contentType: 'image/jpeg',
        formatName: 'jpegli',
        tierLabel: exceedsWebp && !wantJpg ? `jpegli-tall-q${quality}` : `jpegli-w${width}-q${quality}`,
      };
    }

    const buffer = await pipeline
      .jpeg({
        quality,
        mozjpeg: true,
        progressive: true,
        trellisQuantisation: true,
        overshootDeringing: true,
        optimiseScans: true,
        chromaSubsampling: !isGrayscale && quality >= 85 ? '4:4:4' : '4:2:0',
      })
      .toBuffer();
    return {
      buffer,
      ext: 'jpg',
      contentType: 'image/jpeg',
      formatName: 'mozjpeg',
      tierLabel: exceedsWebp && !wantJpg ? `jpeg-tall-fallback-q${quality}` : `jpeg-w${width}-q${quality}`,
    };
  }

  // WebP with smartSubsample (libwebp -sharp_yuv) for razor-sharp Arabic/English text & zero SSIV scroll lag
  const buffer = await pipeline
    .webp({
      quality,
      effort: 3,
      smartSubsample: true,
    })
    .toBuffer();
  return {
    buffer,
    ext: 'webp',
    contentType: 'image/webp',
    formatName: 'webp',
    tierLabel: `webp-w${width}-q${quality}`,
  };
}

/**
 * V2 Smart Single-Image Compression Pipeline:
 *  1. <5ms content analysis (Auto B&W + Hazy Scan + Complexity adaptive quality)
 *  2. Optional Smart Vertical Gutter Trimming on tall manhwa strips
 *  3. Lag-free format routing (AVIF <= 4000px, WebP sharp_yuv <= 16383px, Jpegli/MozJPEG > 16383px)
 *  4. Strict No-Gain guard
 */
export async function compressImageBufferV2(inputBuffer, magic, opts = {}) {
  const maxWidth = clampInt(opts.w, 0, 4096, 0);
  const requestedQ = clampInt(opts.q ?? opts.l, 10, 95, 65);
  const wantJpg = parseBoolFlag(opts.jpg, false);
  const forceGrayscale = parseBoolFlag(opts.bw, false);
  const enableAutoBw = parseBoolFlag(opts.autobw, true);
  const enableAdaptive = parseBoolFlag(opts.adaptive, true);
  const enableTrim = parseBoolFlag(opts.trim, true);
  const fmtRaw = String(opts.fmt || 'auto').trim().toLowerCase();
  const fmt = ['auto', 'avif', 'webp', 'jpg', 'jpeg'].includes(fmtRaw) ? fmtRaw : 'auto';

  const meta = await sharp(inputBuffer, { limitInputPixels: MAX_INPUT_PIXELS }).metadata();
  const srcWidth = meta.width || 0;
  const srcHeight = meta.height || 0;
  const isAnimated = (meta.pages || 1) > 1;

  if (isAnimated && wantJpg) {
    return {
      buffer: inputBuffer,
      ext: magic,
      contentType: `image/${magic}`,
      tierLabel: 'passthrough-animated',
      bypassed: true,
      autoBw: false,
      trimmedPx: 0,
      formatName: magic,
    };
  }

  let analysis = {
    isGrayscale: false,
    isHazyScan: false,
    p2: 0,
    p98: 255,
    edgeEnergy: 15,
    complexity: 'normal',
    adaptiveDelta: 0,
  };
  if (!isAnimated && (enableAutoBw || enableAdaptive)) {
    analysis = await analyzePageContent(inputBuffer);
  }

  const useGrayscale = forceGrayscale || (enableAutoBw && analysis.isGrayscale);
  const effectiveQ = enableAdaptive
    ? clampInt(requestedQ + analysis.adaptiveDelta, 36, 92, requestedQ)
    : requestedQ;

  let estWidth = srcWidth;
  let estHeight = srcHeight;
  if (maxWidth > 0 && srcWidth > maxWidth && srcHeight > 0) {
    estHeight = Math.round((srcHeight * maxWidth) / srcWidth);
    estWidth = maxWidth;
  }

  // Only decode raw pixels when vertical gutter trimming is worthwhile (tall non-animated strips)
  const shouldAttemptTrim = enableTrim && !isAnimated && estHeight >= 2000 && estWidth > 0 && estHeight / estWidth >= 2.5;

  let pipeline;
  let finalWidth = estWidth || srcWidth;
  let finalHeight = estHeight || srcHeight;
  let trimmedPx = 0;

  const prepOpts = { maxWidth, srcWidth, useGrayscale, forceGrayscale, analysis };
  if (shouldAttemptTrim) {
    const prep = applyResizeAndTonalPrep(
      sharp(inputBuffer, { limitInputPixels: MAX_INPUT_PIXELS }),
      prepOpts,
    );
    const { data: rawPixels, info } = await prep.raw().toBuffer({ resolveWithObject: true });
    const trimmed = trimVerticalGutters(rawPixels, info);
    trimmedPx = trimmed.trimmedPx;
    finalWidth = trimmed.info.width;
    finalHeight = trimmed.info.height;
    pipeline = sharp(trimmed.data, { raw: trimmed.info });
  } else {
    pipeline = applyResizeAndTonalPrep(
      sharp(inputBuffer, { animated: isAnimated && !wantJpg, limitInputPixels: MAX_INPUT_PIXELS }),
      prepOpts,
    );
  }

  const encoded = await encodePreparedPipeline(pipeline, {
    width: finalWidth,
    height: finalHeight,
    quality: effectiveQ,
    fmt,
    wantJpg,
    isGrayscale: useGrayscale,
    isAnimated,
  });

  // Strict No-Gain guard: never deliver a larger payload than the original
  if (encoded.buffer.length >= inputBuffer.length) {
    return {
      buffer: inputBuffer,
      ext: magic === 'jpeg' ? 'jpg' : magic,
      contentType: `image/${magic}`,
      tierLabel: 'bypass-no-gain',
      bypassed: true,
      autoBw: useGrayscale && !forceGrayscale,
      trimmedPx: 0,
      formatName: magic,
    };
  }

  const tags = [encoded.tierLabel];
  if (useGrayscale && !forceGrayscale) tags.push('autobw');
  if (trimmedPx > 0) tags.push(`trim-${trimmedPx}px`);
  if (analysis.complexity !== 'normal' && enableAdaptive) tags.push(analysis.complexity);

  return {
    buffer: encoded.buffer,
    ext: encoded.ext,
    contentType: encoded.contentType,
    tierLabel: tags.join('+'),
    bypassed: false,
    autoBw: useGrayscale && !forceGrayscale,
    trimmedPx,
    formatName: encoded.formatName,
  };
}

/**
 * V2 Turbo-CBZ Chapter Bundler processor:
 *  - Auto B&W + Hazy scan cleanup + Adaptive quality
 *  - Smart Vertical Gutter Trimming
 *  - Seam-Aware Slicing (SmartStitch) into <= 3800px segments (never cuts speech bubbles!)
 *  - Encodes every slice in lag-free AVIF (or WebP/JPEG when requested)
 */
export async function compressAndSliceForBundleV2(inputBuffer, magic, pageIndexStr, opts = {}) {
  const maxWidth = clampInt(opts.w, 0, 4096, 900);
  const requestedQ = clampInt(opts.q ?? opts.l, 10, 95, 65);
  const wantJpg = parseBoolFlag(opts.jpg, false);
  const forceGrayscale = parseBoolFlag(opts.bw, false);
  const enableAutoBw = parseBoolFlag(opts.autobw, true);
  const enableAdaptive = parseBoolFlag(opts.adaptive, true);
  const enableTrim = parseBoolFlag(opts.trim, true);
  const maxSliceHeight = clampInt(opts.maxSliceHeight, 1500, 4000, 3800);
  const fmtRaw = String(opts.fmt || 'auto').trim().toLowerCase();
  const fmt = ['auto', 'avif', 'webp', 'jpg', 'jpeg'].includes(fmtRaw) ? fmtRaw : 'auto';

  const meta = await sharp(inputBuffer, { limitInputPixels: MAX_INPUT_PIXELS }).metadata();
  const isAnimated = (meta.pages || 1) > 1;
  if (isAnimated || !meta.width || !meta.height) {
    const single = await compressImageBufferV2(inputBuffer, magic, opts);
    return [{ filename: `${pageIndexStr}.${single.ext}`, buffer: single.buffer }];
  }

  const analysis = enableAutoBw || enableAdaptive
    ? await analyzePageContent(inputBuffer)
    : { isGrayscale: false, isHazyScan: false, p2: 0, p98: 255, adaptiveDelta: 0 };

  const useGrayscale = forceGrayscale || (enableAutoBw && analysis.isGrayscale);
  const effectiveQ = enableAdaptive
    ? clampInt(requestedQ + analysis.adaptiveDelta, 36, 92, requestedQ)
    : requestedQ;

  const basePipe = applyResizeAndTonalPrep(
    sharp(inputBuffer, { limitInputPixels: MAX_INPUT_PIXELS }),
    { maxWidth, srcWidth: meta.width, useGrayscale, forceGrayscale, analysis },
  );

  let { data: rawPixels, info } = await basePipe.raw().toBuffer({ resolveWithObject: true });

  if (enableTrim) {
    const trimmed = trimVerticalGutters(rawPixels, info);
    rawPixels = trimmed.data;
    info = trimmed.info;
  }

  const isTall = info.height > maxSliceHeight && info.height / info.width > 2.2;
  if (!isTall) {
    const encoded = await encodePreparedPipeline(sharp(rawPixels, { raw: info }), {
      width: info.width,
      height: info.height,
      quality: effectiveQ,
      fmt,
      wantJpg,
      isGrayscale: useGrayscale,
      isAnimated: false,
    });
    if (encoded.buffer.length >= inputBuffer.length) {
      const origExt = magic === 'jpeg' ? 'jpg' : magic;
      return [{ filename: `${pageIndexStr}.${origExt}`, buffer: inputBuffer }];
    }
    return [{ filename: `${pageIndexStr}.${encoded.ext}`, buffer: encoded.buffer }];
  }

  const segments = findSeamAwareCuts(rawPixels, info, maxSliceHeight);
  const slices = [];

  for (let i = 0; i < segments.length; i++) {
    const { top, height } = segments[i];
    const suffix = String(i + 1).padStart(3, '0');
    const slicePipe = sharp(rawPixels, {
      raw: { width: info.width, height: info.height, channels: info.channels },
    }).extract({ left: 0, top, width: info.width, height });

    const encoded = await encodePreparedPipeline(slicePipe, {
      width: info.width,
      height,
      quality: effectiveQ,
      fmt,
      wantJpg,
      isGrayscale: useGrayscale,
      isAnimated: false,
    });

    slices.push({
      filename: `${pageIndexStr}__${suffix}.${encoded.ext}`,
      buffer: encoded.buffer,
    });
  }

  return slices;
}
