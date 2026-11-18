---
title: Komikku Smart Proxy
emoji: 📚
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# Komikku Smart Proxy

SSRF-hardened image compression & Turbo-CBZ chapter bundler designed for **Komikku Smart Data Saver**.

## Features
- **Single-Image Proxy (`GET /`)**:
  - WebP / MozJPEG conversion via `sharp` (`libvips`)
  - Max-width downscaling (`w=720|800|900|1080`) without upscaling
  - Safe `Referer` & `User-Agent` forwarding (strips cookies/auth)
  - Automatic `16,383 px` WebP tall-strip fallback to MozJPEG
  - No-Gain guard (never returns larger file than origin)
  - Telemetry headers: `X-Original-Size`, `X-Compressed-Size`, `X-Saved-Bytes`, `X-Proxy-Tier`
- **Turbo-CBZ Chapter Bundle (`POST /chapter-bundle`)**:
  - Fetches & compresses up to 5 pages concurrently
  - Auto-slices tall manhwa strips (`__001.webp`, `__002.webp`, ...)
  - Packs into a single `.cbz` (ZIP STORE) stream with `_bundle_meta.json`
- **Health Endpoint (`GET /health`)**: Live status & compression statistics

## Deploy Free (Zero Risk to Vercel Main Account)
- **Hugging Face Spaces (Recommended, No Credit Card)**: Create a Docker Space -> push this directory -> runs on port `7860` (`2 vCPU / 16 GB RAM`).
- **Koyeb / Render / Any Docker Host**: Build with included `Dockerfile` (`PORT` env automatically respected).
- **Security**: Set `PROXY_KEY=<your-secret>` in Space/container Secrets to lock access to your Komikku app only.
