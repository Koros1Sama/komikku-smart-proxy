# Komikku Smart Proxy V2 (Korotomi)

SSRF-hardened perceptual image compression & Turbo-CBZ chapter bundler designed for **Korotomi / Komikku Smart Data Saver**.

## What's New in V2.0
- **Ultra-Fast Page Content Analyzer (`< 5 ms`)**:
  - **Auto B&W Manga Detection (`autobw=1`)**: strips wasted 24-bit RGB channels on grayscale manga pages & gently levels hazy scanner backgrounds.
  - **Perceptual Adaptive Quality (`adaptive=1`)**: tightens quality on sparse dialogue pages (imperceptible) and preserves detail on dense action/screentone pages.
- **Smart Vertical Gutter Trimming (`trim=1`)**:
  - Collapses excessively tall solid white/black webtoon voids while keeping natural pacing margins — zero loss on drawn art or text.
- **Lag-Free Android Codec Router (`fmt=auto|avif|webp|jpg`)**:
  - `<= 4000 px` pages & chapter slices -> **AVIF** (`libaom` effort=2, calibrated perceptual quality).
  - `4001 – 16,383 px` tall strips -> **WebP** (`smartSubsample: true` / `-sharp_yuv`) for crisp Arabic/English text & zero `SSIV` scroll lag.
  - `> 16,383 px` ultra-tall strips -> **Google Jpegli (`cjpegli` 4:4:4)** when installed on Docker/VPS, or tuned **MozJPEG** (`trellisQuantisation + overshootDeringing`).
- **Seam-Aware Slicing (`SmartStitch`) in `POST /chapter-bundle`**:
  - Cuts tall strips strictly along low-variance horizontal gutters (`<= 3800 px`) so speech bubbles and panels are never split, packed into `ZIP_STORED` (level 0) `.cbz`.
- **Full Security & Telemetry**:
  - DNS-pinned SSRF protection, magic-byte validation, safe `Referer`/`User-Agent` forwarding, strict No-Gain guard, optional `PROXY_KEY` lock, and headers `X-Original-Size`, `X-Compressed-Size`, `X-Saved-Bytes`, `X-Proxy-Tier`, `X-Format`, `X-Trimmed-Height`, `X-Auto-BW`.

## Deployment Options (Free Tier — Personal Use)
- **Vercel Hobby (Fluid Compute)** via GitHub Actions CI/CD: 100 GB/mo bandwidth, zero cold sleep, ideal for single-page live reading (`api/index.js` + `vercel.json`).
- **Render Free (No Credit Card)** via `render.yaml` / `Dockerfile`: 5 GB/mo bandwidth, supports both single-page and large `/chapter-bundle` `.cbz` responses.
- **Oracle Cloud Always Free / Any Docker Host**: 24/7 Docker with optional `cjpegli` binary (`CJPEGLI_BIN`).
- **Security**: Always set `PROXY_KEY=<your-secret>` in environment variables and enter the same key in Korotomi Data Saver settings.
