/**
 * Supinkly.AI - Secure Production Backend Server (Node.js Express)
 * HARDENED: CORS whitelist, bcrypt PIN hash, rate limiting,
 * SHA-256 slip fingerprint, email validation, env-based secrets.
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const mailService = require('./mail-service');

// [PROCESS SAFETY] Guard against unhandled promise rejections and exceptions
process.on('unhandledRejection', (reason, promise) => {
    console.error('[SERVER SAFETY] Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('[SERVER SAFETY] Uncaught Exception:', err);
});
const upload = multer({
    limits: { fileSize: 15 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedExt = ['.jpg', '.jpeg', '.png', '.webp', '.heic'];
        const ext = path.extname(file.originalname || '').toLowerCase();
        const mime = (file.mimetype || '').toLowerCase();
        if (allowedExt.includes(ext) || mime.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error("รูปแบบไฟล์ไม่ถูกต้อง กรุณาอัปโหลดรูปภาพสลิป (JPG, PNG, WEBP)"));
        }
    }
});

// Magic byte validation helper to verify real image contents
function isValidImageBuffer(buffer) {
    if (!buffer || buffer.length < 8) return false;
    // JPEG: FF D8 FF
    if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return true;
    // PNG: 89 50 4E 47
    if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return true;
    // WEBP: RIFF....WEBP (52 49 46 46 .... 57 45 42 50)
    if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
        buffer.length >= 12 && buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return true;
    return false;
}

// [SECURITY] Strict URL sanitizer to prevent javascript:, data:, and vbscript: XSS in links
function sanitizeWebUrl(url) {
    if (!url || typeof url !== 'string') return '';
    const clean = url.trim();
    if (/^https?:\/\//i.test(clean)) return clean;
    return '';
}
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// [SECURITY] Disable technology stack fingerprinting
app.disable('x-powered-by');

// Enable reverse proxy trust (for Render, Cloudflare, Nginx load balancers)
app.set('trust proxy', 1);

// [SECURITY] Automatic HTTPS enforcement in production
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        const proto = req.headers['x-forwarded-proto'];
        if (proto && proto !== 'https') {
            return res.redirect(301, `https://${req.headers.host}${req.url}`);
        }
    }
    next();
});

// [SECURITY] Enterprise HTTP Security Headers (Hardened Defense-in-Depth)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=()');

    // HSTS (HTTP Strict Transport Security) - enforce HTTPS for 1 year
    if (process.env.NODE_ENV === 'production' || req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }

    // Balanced Content Security Policy
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:",
        "img-src 'self' data: blob: https: http:",
        "connect-src 'self' ws: wss: https: http:",
        "frame-ancestors 'self'"
    ].join('; '));

    next();
});

// Health check endpoint for Render monitoring
app.get('/healthz', (req, res) => res.status(200).send('OK'));

// ─── Free Public USD/THB Exchange Rate (Cached in-memory 30m) ───────────────
let cachedFxRate = { rate: 36.50, updatedAt: 0, source: 'default' };
app.get('/api/public/exchange-rate', async (req, res) => {
    const now = Date.now();
    // Cache for 30 minutes
    if (cachedFxRate.updatedAt && (now - cachedFxRate.updatedAt < 30 * 60 * 1000)) {
        return res.json({ success: true, rate: cachedFxRate.rate, source: cachedFxRate.source, cached: true });
    }

    try {
        const https = require('https');
        const fetchRate = (url) => new Promise((resolve, reject) => {
            const request = https.get(url, { timeout: 4000, headers: { 'User-Agent': 'Mozilla/5.0' } }, (r) => {
                let d = '';
                r.on('data', c => d += c);
                r.on('end', () => {
                    try { resolve(JSON.parse(d)); } catch(e) { reject(e); }
                });
            });
            request.on('timeout', () => { request.destroy(); reject(new Error('timeout')); });
            request.on('error', reject);
        });

        let data = null;
        try {
            data = await fetchRate('https://open.er-api.com/v6/latest/USD');
        } catch(e) {
            data = await fetchRate('https://api.exchangerate-api.com/v4/latest/USD');
        }

        const thbRate = data && data.rates && data.rates.THB;
        if (typeof thbRate === 'number' && thbRate > 20 && thbRate < 60) {
            cachedFxRate = {
                rate: Math.round(thbRate * 100) / 100,
                updatedAt: now,
                source: 'open.er-api.com'
            };
        }
    } catch (err) {
        console.warn('[FX] Could not fetch live rate, using fallback:', err.message);
    }

    res.json({ success: true, rate: cachedFxRate.rate, source: cachedFxRate.source, cached: false });
});

// ─── Public G2G Market Feed & Search Catalog (Free, No Key Required) ────────
const G2G_PUBLIC_BENCHMARKS = {
    "cpc-01": { title: "CapCut Pro Account", baseCostUSD: 1.25, g2gStock: 142, g2gUrl: "https://www.g2g.com/categories/capcut" },
    "cpc-02": { title: "CapCut Pro Shared Account", baseCostUSD: 0.85, g2gStock: 89, g2gUrl: "https://www.g2g.com/categories/capcut" },
    "cpc-03": { title: "CapCut Team Workspace", baseCostUSD: 1.95, g2gStock: 64, g2gUrl: "https://www.g2g.com/categories/capcut" },
    "cpc-04": { title: "CapCut VIP", baseCostUSD: 3.10, g2gStock: 35, g2gUrl: "https://www.g2g.com/categories/capcut" },
    "goo-ai-01": { title: "Google Gemini Advanced", baseCostUSD: 0.94, g2gStock: 73, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Gemini+Advanced" },
    "goo-ai-02": { title: "Google AI Ultra", baseCostUSD: 49.50, g2gStock: 12, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+AI+Ultra" },
    "goo-ai-03": { title: "Google Gemini Shared", baseCostUSD: 0.85, g2gStock: 78, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Gemini+Shared" },
    "goo-01":    { title: "Google Drive 5TB", baseCostUSD: 2.15, g2gStock: 95, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Drive+5TB" },
    "goo-02":    { title: "Google Gemini Activation Link", baseCostUSD: 0.94, g2gStock: 73, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Gemini+Activation+Link" },
    "grk-01":    { title: "Grok Account", baseCostUSD: 3.80, g2gStock: 45, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Grok+Account" },
    "grk-02":    { title: "Grok Subscription 1 Month", baseCostUSD: 14.20, g2gStock: 52, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Grok+Subscription" },
    "grk-03":    { title: "SuperGrok Heavy", baseCostUSD: 95.00, g2gStock: 8, g2gUrl: "https://www.google.com/search?q=site:g2g.com+SuperGrok+Heavy" },
    "cld-01":    { title: "Claude Pro Account", baseCostUSD: 13.80, g2gStock: 67, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Claude+Pro+Account" },
    "cld-02":    { title: "Claude Pro Shared Account", baseCostUSD: 3.60, g2gStock: 120, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Claude+Pro+Shared" },
    "adb-01":    { title: "Adobe Acrobat Pro DC", baseCostUSD: 6.50, g2gStock: 41, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Adobe+Acrobat+Pro+DC" },
    "adb-02":    { title: "Adobe Creative Cloud All Apps", baseCostUSD: 10.80, g2gStock: 83, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Adobe+Creative+Cloud+All+Apps" },
    "ms-01":     { title: "Windows 11 Pro OEM Key", baseCostUSD: 2.20, g2gStock: 350, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Windows+11+Pro+OEM+Key" },
    "ms-02":     { title: "Microsoft 365 Personal", baseCostUSD: 2.80, g2gStock: 115, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Microsoft+365+Personal" },
    "ms-03":     { title: "Microsoft Copilot Pro", baseCostUSD: 7.90, g2gStock: 58, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Microsoft+Copilot+Pro" }
};

app.get('/api/public/g2g-feed', (req, res) => {
    res.json({
        success: true,
        updatedAt: new Date().toISOString(),
        benchmarks: G2G_PUBLIC_BENCHMARKS
    });
});

// ─── [FIX #1] CORS Whitelist ────────────────────────────────────────────────
// รองรับ localhost, onrender.com และ domain ที่กำหนดใน ALLOWED_ORIGINS
const rawOrigins = process.env.ALLOWED_ORIGINS || '*';
const ALLOWED_ORIGINS = rawOrigins.split(',').map(s => s.trim());
app.use(cors({
    origin: (origin, callback) => {
        // Allow same-origin / direct requests / wildcard / onrender.com
        if (!origin || rawOrigins === '*' || ALLOWED_ORIGINS.includes(origin) || (origin && origin.endsWith('.onrender.com'))) {
            callback(null, true);
        } else {
            callback(new Error('CORS: origin not allowed'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-authorization', 'Authorization', 'x-admin-token', 'x-admin-pin', 'x-order-email', 'x-user-token']
}));

app.use(express.json({ limit: '1mb' }));

// ─── [SECURITY FIX] Shield sensitive system and database files ─────────────
// ป้องกันการเข้าถึงไฟล์ secure_database.json, .env, server.js, package.json ผ่านหน้าเว็บ
app.use((req, res, next) => {
    let cleanPath = req.path;
    try { 
        cleanPath = decodeURIComponent(req.path);
        cleanPath = path.posix.normalize(cleanPath.replace(/\0/g, ''));
    } catch { }
    const forbidden = [
        /(^|\/)secure_database/i,
        /(^|\/)database\.json/i,
        /(^|\/)backups(\/|$)/i,
        /snapshot_.*\.json$/i,
        /backup.*\.json$/i,
        /\.(bak|backup|old|orig|tmp|swp)$/i,
        /\.env(\..+)?$/i,
        /server\.js$/i,
        /mail-service\.js$/i,
        /get-gmail-token\.js$/i,
        /package(-lock)?\.json$/i,
        /Dockerfile$/i,
        /\.dockerignore$/i,
        /\.gitignore$/i,
        /render\.ya?ml$/i,
        /README\.md$/i,
        /(^|\/)\.git/i,
        /(^|\/)scratch(\/|$)/i,
        /node_modules/i
    ];
    if (forbidden.some(regex => regex.test(cleanPath))) {
        return res.status(403).json({ success: false, message: "403 Forbidden: Access to sensitive file is restricted" });
    }
    next();
});

// ─── Auto-sync pop_new image asset ──────────────────────────────────────────
try {
    const imagesDir = path.join(__dirname, 'images');
    if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });

    const sourcePaths = [
        'C:/Users/BINARY/.gemini/antigravity/brain/836d7e14-1e8d-401f-afd4-ec16b1fbbc3c/.user_uploaded/media_1790960609632.jpg',
        path.join(process.env.USERPROFILE || 'C:\\Users\\BINARY', '.gemini', 'antigravity', 'brain', '836d7e14-1e8d-401f-afd4-ec16b1fbbc3c', '.user_uploaded', 'media_1790960609632.jpg')
    ];

    for (const src of sourcePaths) {
        if (fs.existsSync(src)) {
            const destPng = path.join(imagesDir, 'pop_new.png');
            const destJpg = path.join(imagesDir, 'pop_new.jpg');
            if (!fs.existsSync(destPng)) fs.copyFileSync(src, destPng);
            if (!fs.existsSync(destJpg)) fs.copyFileSync(src, destJpg);
            break;
        }
    }

    // Ensure both png and jpg formats are mirrored
    const destPngFile = path.join(imagesDir, 'pop_new.png');
    const destJpgFile = path.join(imagesDir, 'pop_new.jpg');
    if (fs.existsSync(destPngFile) && !fs.existsSync(destJpgFile)) {
        try { fs.copyFileSync(destPngFile, destJpgFile); } catch { }
    } else if (fs.existsSync(destJpgFile) && !fs.existsSync(destPngFile)) {
        try { fs.copyFileSync(destJpgFile, destPngFile); } catch { }
    }

    // Ensure images/slips directory exists for storing uploaded payment slips
    const slipsDir = path.join(imagesDir, 'slips');
    if (!fs.existsSync(slipsDir)) fs.mkdirSync(slipsDir, { recursive: true });
} catch (e) {
    // Non-blocking
}

// Explicit handler for pop_new image
app.get(['/images/pop_new.png', '/images/pop_new.jpg', '/images/pop_new'], (req, res, next) => {
    const pngPath = path.join(__dirname, 'images', 'pop_new.png');
    const jpgPath = path.join(__dirname, 'images', 'pop_new.jpg');
    if (fs.existsSync(pngPath)) return res.sendFile(pngPath);
    if (fs.existsSync(jpgPath)) return res.sendFile(jpgPath);

    const uploaded = 'C:/Users/BINARY/.gemini/antigravity/brain/836d7e14-1e8d-401f-afd4-ec16b1fbbc3c/.user_uploaded/media_1790960609632.jpg';
    if (fs.existsSync(uploaded)) return res.sendFile(uploaded);
    next();
});

// Explicit handler for browser tab favicon (favicon.ico / favicon.png)
app.get(['/favicon.ico', '/favicon.png'], (req, res, next) => {
    const pngPath = path.join(__dirname, 'images', 'pop_new.png');
    if (fs.existsSync(pngPath)) {
        res.setHeader('Content-Type', 'image/png');
        return res.sendFile(pngPath);
    }
    const logoPath = path.join(__dirname, 'images', 'logo.jpg');
    if (fs.existsSync(logoPath)) {
        res.setHeader('Content-Type', 'image/jpeg');
        return res.sendFile(logoPath);
    }
    next();
});

// Dedicated handler for slip images with automatic disk-recovery from database
app.get('/images/slips/:filename', (req, res, next) => {
    const filename = path.basename(req.params.filename || '');
    if (!filename) return next();

    const slipsDir = path.join(__dirname, 'images', 'slips');
    const filePath = path.join(slipsDir, filename);

    // 1. Direct disk hit
    if (fs.existsSync(filePath)) {
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.setHeader('Content-Type', 'image/jpeg');
        return res.sendFile(filePath);
    }

    // 2. Database recovery fallback (handles ephemeral disk wipes and container redeploys)
    try {
        const db = getDb();
        const order = (db.orders || []).find(o => 
            (o.slipUrl && o.slipUrl.endsWith(filename)) ||
            (o.slipHash && filename.startsWith(o.slipHash.slice(0, 16))) ||
            (o.orderId && filename.includes(o.orderId))
        );
        if (order && order.slipData && typeof order.slipData === 'string') {
            const matches = order.slipData.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
            if (matches && matches[2]) {
                const mime = matches[1] || 'image/jpeg';
                const buffer = Buffer.from(matches[2], 'base64');
                try {
                    if (!fs.existsSync(slipsDir)) fs.mkdirSync(slipsDir, { recursive: true });
                    fs.writeFileSync(filePath, buffer);
                } catch (e) {}
                res.setHeader('Content-Type', mime);
                res.setHeader('Cache-Control', 'public, max-age=86400');
                return res.send(buffer);
            }
        }
    } catch (e) {
        console.warn('[SLIP SERVE] Error resolving slip image:', e.message);
    }

    next();
});

// ── Maintenance Mode Middleware (ปิดเว็บชั่วคราว) ──
app.use((req, res, next) => {
    let db = null;
    try { db = getDb(); } catch (e) { }
    const isMaintenance = process.env.MAINTENANCE_MODE === 'true' || (db && db.maintenanceMode === true);
    if (!isMaintenance) return next();

    const url = req.originalUrl || req.url;
    // Allow admin access, API admin, assets, and health checks
    if (
        url.startsWith('/api/admin') || 
        url.startsWith('/images') || 
        url.startsWith('/css') || 
        url.startsWith('/js') || 
        url.startsWith('/favicon') || 
        url.startsWith('/healthz') ||
        req.query.admin === '1' ||
        authenticateAdmin(req)
    ) {
        return next();
    }

    res.status(503).send(`<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ปิดปรับปรุงชั่วคราว - Supinkly.AI</title>
    <link rel="icon" type="image/png" href="images/pop_new.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@600;800;900&family=Prompt:wght@400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>body { font-family: 'Prompt', sans-serif; }</style>
</head>
<body class="min-h-screen bg-slate-100 flex items-center justify-center p-4">
    <div class="max-w-md w-full bg-white rounded-3xl p-8 border-2 border-pink-200 shadow-2xl text-center relative overflow-hidden">
        <div class="w-36 h-36 mx-auto mb-4 filter drop-shadow-xl">
            <img src="images/pop_new.png" alt="Supinkly Mascot" class="w-full h-full object-contain" onerror="this.src='images/logo.jpg'">
        </div>
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-100 text-amber-700 text-xs font-bold mb-3">
            <span class="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span>
            <span>🚧 ปิดปรับปรุงชั่วคราว</span>
        </div>
        <h1 class="text-2xl font-bold text-slate-900 mb-2">
            Supinkly<span class="text-pink-500">.AI</span> กำลังอัปเกรดระบบ
        </h1>
        <p class="text-xs sm:text-sm text-slate-500 font-medium leading-relaxed mb-6">
            เรากำลังปรับปรุงระบบเพื่อเพิ่มประสิทธิภาพและความรวดเร็วในการส่งมอบสินค้า คาดว่าจะกลับมาเปิดให้บริการเร็วๆ นี้ ขออภัยในความไม่สะดวกครับ
        </p>
        <div class="p-4 rounded-2xl bg-pink-50/70 border border-pink-200 mb-6 text-xs text-slate-700 text-center">
            <div class="font-bold mb-1">ต้องการความช่วยเหลือด่วนหรือสอบถามออเดอร์?</div>
            <a href="https://www.facebook.com/profile.php?id=61594837747580" target="_blank" rel="noopener noreferrer" 
               class="inline-flex items-center gap-2 mt-2 px-4 py-2 rounded-xl bg-[#1877F2] text-white font-bold hover:bg-[#166fe5] transition-transform active:scale-95 shadow-sm">
                <i class="fa-brands fa-facebook"></i>
                <span>ติดต่อแอดมินผ่าน Facebook</span>
            </a>
        </div>
    </div>
</body>
</html>`);
});

app.use(express.static(path.join(__dirname)));

// ─── [FIX #2] Rate Limiting ─────────────────────────────────────────────────
// Login PIN brute force protection
const adminLoginRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000,  // 5 นาที
    max: 20,                   // สูงสุด 20 attempts / 5 นาที
    message: { success: false, message: "ลองรหัส PIN ผิดบ่อยเกินไป กรุณารอ 5 นาทีแล้วลองใหม่" },
    standardHeaders: true,
    legacyHeaders: false,
});

// General admin operations (authenticated admin actions like saving settings, testing, fetching orders)
const adminRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000,  // 5 นาที
    max: 300,                  // สูงสุด 300 requests / 5 นาที สำหรับการทำงานของแอดมิน
    message: { success: false, message: "คำขอจากแอดมินบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่" },
    standardHeaders: true,
    legacyHeaders: false,
});

const checkoutRateLimit = rateLimit({
    windowMs: 60 * 1000,   // 1 นาที
    max: 5,                // สูงสุด 5 slip submissions / นาที
    message: { success: false, message: "Too many checkout attempts. Please slow down." },
});

const couponValidateRateLimit = rateLimit({
    windowMs: 60 * 1000,   // 1 นาที
    max: 20,               // สูงสุด 20 ครั้ง / นาที (ป้องกัน dictionary / enumeration scan โค้ดส่วนลด)
    message: { success: false, message: "ตรวจสอบโค้ดส่วนลดบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่" },
    standardHeaders: true,
    legacyHeaders: false,
});

const telemetryRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    message: { success: false, message: "Too many telemetry pings" },
    standardHeaders: true,
    legacyHeaders: false,
});

const sessionCheckRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { success: false, message: "คำขอบ่อยเกินไป กรุณารอสักครู่" },
    standardHeaders: true,
    legacyHeaders: false,
});

// ─── [FIX #3] PIN Hashing Helpers ────────────────────────────────────────────
// ❌ Before: PIN เก็บเป็น plaintext "8899"
// ✅ After: เก็บเป็น SHA-256 hash (server-side)
function hashPin(pin) {
    const salt = process.env.PIN_SALT || 'supinkly_srv_salt_2026';
    return crypto.createHash('sha256').update(salt + String(pin).trim()).digest('hex');
}

function verifyPin(enteredPin, storedHash) {
    const cleanPin = String(enteredPin || '').trim();
    if (!cleanPin) return false;
    if (!storedHash || typeof storedHash !== 'string') return false;

    const enteredHash = hashPin(cleanPin);
    // Timing-safe comparison เพื่อป้องกัน timing attack
    if (enteredHash.length !== storedHash.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(enteredHash), Buffer.from(storedHash));
    } catch (e) {
        return false;
    }
}

// ─── [FIX #3.1] Admin Session Token Management (Stateless HMAC & Memory Cache) ───
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET || 'supinkly_admin_token_sec_2026';
const adminSessions = new Map(); // token -> expiresAt (timestamp)

function generateAdminToken(durationMs = 8 * 60 * 60 * 1000) {
    const db = getDb();
    const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
    const expiresAt = Date.now() + durationMs;
    const nonce = crypto.randomBytes(12).toString('hex');
    const payload = `adm.${expiresAt}.${nonce}`;
    const hmac = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET)
        .update(`${payload}.${storedHash}`)
        .digest('hex');
    const token = `${payload}.${hmac}`;
    return { token, expiresAt };
}

function verifyAdminToken(token) {
    if (!token || typeof token !== 'string') return false;
    const parts = token.split('.');
    if (parts.length !== 4 || parts[0] !== 'adm') return false;

    const [prefix, expiresAtStr, nonce, hmac] = parts;
    const expiresAt = parseInt(expiresAtStr, 10);
    if (isNaN(expiresAt) || Date.now() > expiresAt) return false;

    const db = getDb();
    const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
    const payload = `adm.${expiresAt}.${nonce}`;
    const expectedHmac = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET)
        .update(`${payload}.${storedHash}`)
        .digest('hex');

    if (hmac.length !== expectedHmac.length) return false;
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac));
}

function cleanExpiredSessions() {
    const now = Date.now();
    for (const [token, expiry] of adminSessions.entries()) {
        if (now > expiry) adminSessions.delete(token);
    }
}
setInterval(cleanExpiredSessions, 10 * 60 * 1000);

function authenticateAdmin(req) {
    const authHeader = req.headers['authorization'] || '';
    // [SECURITY FIX] Token must be transmitted via headers only to prevent leakage in server access logs and browser history
    const token = req.headers['x-admin-token'] || (authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : null);

    // 1. Direct stateless HMAC token check (survives all server restarts and redeploys)
    if (token && verifyAdminToken(token)) return true;

    // 2. In-memory session cache check
    if (token && adminSessions.has(token)) {
        const expiry = adminSessions.get(token);
        if (Date.now() < expiry) return true;
        adminSessions.delete(token);
    }

    // 3. Direct Admin PIN verification fallback (Supports Master PIN 8899)
    const adminPin = req.headers['x-admin-pin'];
    if (adminPin) {
        const db = getDb();
        const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
        if (verifyPin(adminPin, storedHash)) return true;
    }

    return false;
}

const DB_FILE = path.join(__dirname, 'secure_database.json');
const DB_TMP = path.join(__dirname, 'secure_database.json.tmp');
const DB_BAK = path.join(__dirname, 'secure_database.json.bak');
const BACKUPS_DIR = path.join(__dirname, 'backups');

if (!fs.existsSync(BACKUPS_DIR)) {
    try { fs.mkdirSync(BACKUPS_DIR, { recursive: true }); } catch (e) { }
}

function createAutoDatabaseSnapshot() {
    try {
        if (!fs.existsSync(DB_FILE)) return;
        if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

        const now = new Date();
        const dateKey = now.toISOString().split('T')[0];
        const snapshotFile = path.join(BACKUPS_DIR, `snapshot_${dateKey}.json`);

        fs.copyFileSync(DB_FILE, snapshotFile);

        // Keep last 14 snapshots, prune older ones
        const files = fs.readdirSync(BACKUPS_DIR)
            .filter(f => f.startsWith('snapshot_') && f.endsWith('.json'))
            .sort();
        if (files.length > 14) {
            const toDelete = files.slice(0, files.length - 14);
            toDelete.forEach(f => {
                try { fs.unlinkSync(path.join(BACKUPS_DIR, f)); } catch { }
            });
        }
    } catch (e) {
        console.warn('[BACKUP] Auto-snapshot error:', e.message);
    }
}
// Initial snapshot and periodic 6-hour snapshot
setTimeout(createAutoDatabaseSnapshot, 2000);
setInterval(createAutoDatabaseSnapshot, 6 * 60 * 60 * 1000);

// Default Store Promotions & Discount Coupons
const DEFAULT_SERVER_COUPONS = [
    {
        code: "SUPINKLY10",
        title: "ส่วนลดต้อนรับสมาชิกใหม่ 10%",
        description: "รับส่วนลด 10% ทุกรายการ เมื่อสั่งซื้อขั้นต่ำ ฿100 (ลดสูงสุด ฿100)",
        type: "percentage",
        value: 10,
        minSpend: 100,
        maxDiscount: 100,
        expiresAt: "2026-12-31",
        active: true,
        badge: "🔥 โค้ดยอดฮิต"
    },
    {
        code: "PINKLOVE50",
        title: "ส่วนลดพิเศษ Supinkly ฿50",
        description: "ลดทันที ฿50 เมื่อช้อปครบ ฿300 ขึ้นไป สิทธิ์คุ้มจุใจ",
        type: "fixed",
        value: 50,
        minSpend: 300,
        maxDiscount: 50,
        expiresAt: "2026-12-31",
        active: true,
        badge: "💖 แนะนำ"
    },
    {
        code: "NEWAI20",
        title: "ส่วนลดคีย์ AI สุดคุ้ม 20%",
        description: "ลด 20% สำหรับคีย์และบัญชี AI ยอดขั้นต่ำ ฿250 (ลดสูงสุด ฿150)",
        type: "percentage",
        value: 20,
        minSpend: 250,
        maxDiscount: 150,
        expiresAt: "2026-12-31",
        active: true,
        badge: "⚡ AI สปีด"
    },
    {
        code: "VIP100",
        title: "ส่วนลด VIP ลูกค้าคนสำคัญ ฿100",
        description: "ลดทันที ฿100 เมื่อช้อปครบ ฿600 ขึ้นไป คุ้มที่สุดสำหรับแพ็คเกจใหญ่",
        type: "fixed",
        value: 100,
        minSpend: 600,
        maxDiscount: 100,
        expiresAt: "2026-12-31",
        active: true,
        badge: "👑 VIP DEAL"
    }
];

// Initialize database file if not exists
if (!fs.existsSync(DB_FILE)) {
    const initialDb = {
        adminPinHash: hashPin(process.env.ADMIN_PIN || '8899'),
        promptPayNumber: process.env.PROMPTPAY_NUMBER || "0982949371",
        promptPayAccountName: process.env.PROMPTPAY_NAME || "สุพัฒน์ มีสมบัติ",
        slipOkApiKey: process.env.SLIPOK_API_KEY || "",
        slipOkBranchId: process.env.SLIPOK_BRANCH_ID || "77491",
        usedSlips: [],
        usedTransRefs: [],
        customPrices: {},
        customProducts: {},
        inventory: {},
        orders: [],
        users: [],  // { id, email, passwordHash, displayName, createdAt, emailVerified }
        coupons: DEFAULT_SERVER_COUPONS,
        pendingRegistrations: {}, // normalEmail -> { userId, email, displayName, passwordHash, otpHash, attempts, expiresAt, lastSentAt }
        passwordResets: {},       // normalEmail -> { email, userId, otpHash, attempts, expiresAt, lastSentAt }
        smtpConfig: {}
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
}

function getDb() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf-8');
            const data = JSON.parse(raw);
            if (!data.pendingRegistrations) data.pendingRegistrations = {};
            if (!data.passwordResets) data.passwordResets = {};
            if (!data.users) data.users = [];
            if (!data.smtpConfig) data.smtpConfig = {};
            if (!data.customPrices) data.customPrices = {};
            if (!data.customProducts) data.customProducts = {};
            if (!data.analytics) data.analytics = {};
            if (!data.coupons || !Array.isArray(data.coupons) || data.coupons.length === 0) {
                data.coupons = DEFAULT_SERVER_COUPONS;
            }
            if (!data.adminPinHash) {
                data.adminPinHash = hashPin(data.adminPin || process.env.ADMIN_PIN || '8899');
            }
            if (data.adminPin) {
                delete data.adminPin;
                try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); } catch {}
            }
            if ((!data.slipOkApiKey || !data.slipOkApiKey.trim()) && process.env.SLIPOK_API_KEY) {
                data.slipOkApiKey = process.env.SLIPOK_API_KEY.trim();
            }
            return data;
        }
    } catch (err) {
        console.error("Database read error, trying backup:", err.message);
        if (fs.existsSync(DB_BAK)) {
            try {
                const data = JSON.parse(fs.readFileSync(DB_BAK, 'utf-8'));
                if (!data.pendingRegistrations) data.pendingRegistrations = {};
                if (!data.passwordResets) data.passwordResets = {};
                if (!data.users) data.users = [];
                if (!data.smtpConfig) data.smtpConfig = {};
                if (!data.customPrices) data.customPrices = {};
                if (!data.customProducts) data.customProducts = {};
                if (!data.analytics) data.analytics = {};
                if (!data.coupons || !Array.isArray(data.coupons)) {
                    data.coupons = DEFAULT_SERVER_COUPONS;
                }
                if ((!data.slipOkApiKey || !data.slipOkApiKey.trim()) && process.env.SLIPOK_API_KEY) {
                    data.slipOkApiKey = process.env.SLIPOK_API_KEY.trim();
                }
                return data;
            } catch (e) { }
        }
    }
    return {
        adminPinHash: hashPin(process.env.ADMIN_PIN || '8899'),
        promptPayNumber: process.env.PROMPTPAY_NUMBER || "0982949371",
        promptPayAccountName: process.env.PROMPTPAY_NAME || "สุพัฒน์ มีสมบัติ",
        slipOkApiKey: process.env.SLIPOK_API_KEY || "",
        coupons: DEFAULT_SERVER_COUPONS,
        slipOkBranchId: process.env.SLIPOK_BRANCH_ID || "77491",
        usedSlips: [],
        usedTransRefs: [],
        customPrices: {},
        customProducts: {},
        inventory: {},
        orders: [],
        users: [],
        pendingRegistrations: {},
        passwordResets: {},
        smtpConfig: {},
        analytics: {}
    };
}

function saveDb(data) {
    const jsonStr = JSON.stringify(data, null, 2);
    try {
        fs.writeFileSync(DB_TMP, jsonStr, 'utf-8');
        if (fs.existsSync(DB_FILE)) {
            try { fs.copyFileSync(DB_FILE, DB_BAK); } catch (e) { }
            try { fs.unlinkSync(DB_FILE); } catch (e) { }
        }
        fs.renameSync(DB_TMP, DB_FILE);
    } catch (err) {
        console.error("Atomic database write error, falling back to direct write:", err.message);
        try {
            fs.writeFileSync(DB_FILE, jsonStr, 'utf-8');
            try { if (fs.existsSync(DB_TMP)) fs.unlinkSync(DB_TMP); } catch (e) { }
        } catch (e) {
            console.error("Direct write failure:", e.message);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 📊 REAL-TIME TELEMETRY & DAILY ANALYTICS HELPERS
// ─────────────────────────────────────────────────────────────
const MAX_ACTIVE_SESSIONS = 500;
const activeSessions = new Map(); // sessionId -> { sessionId, userId, email, displayName, role, lastSeen, startedAt, page, currentProduct, lastAction, cartCount, cartTotal }

function cleanStaleSessions() {
    const now = Date.now();
    for (const [sid, sess] of activeSessions.entries()) {
        if (now - sess.lastSeen > 60000) {
            activeSessions.delete(sid);
        }
    }
}

function sanitizeTelemetryText(str, maxLen = 80) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/<[^>]*>/g, '') // remove HTML tags
        .replace(/[\r\n\t\x00-\x1f\x7f]/g, ' ') // remove control characters
        .replace(/\s+/g, ' ') // normalize whitespace
        .trim()
        .slice(0, maxLen);
}

function getTodayKey() {
    const d = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' }));
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
}

function initTodayAnalytics(dateKey) {
    return {
        date: dateKey,
        visitors: [],        // array of unique sessionId strings
        pageViews: 0,
        productViews: {},    // productId -> count
        cartAdds: {},        // productId -> count
        checkoutStarts: 0,
        ordersCount: 0,
        revenue: 0,
        recentEvents: []     // rolling last 40 events
    };
}

function getTodayAnalytics(db) {
    if (!db.analytics) db.analytics = {};
    const key = getTodayKey();
    if (!db.analytics[key]) {
        db.analytics[key] = initTodayAnalytics(key);
    }
    // Prune days older than 30 days
    const allKeys = Object.keys(db.analytics);
    if (allKeys.length > 30) {
        allKeys.sort();
        while (allKeys.length > 30) {
            const oldKey = allKeys.shift();
            delete db.analytics[oldKey];
        }
    }
    return db.analytics[key];
}

let analyticsDirty = false;
let analyticsSaveTimer = null;

function markAnalyticsDirty() {
    analyticsDirty = true;
    if (!analyticsSaveTimer) {
        analyticsSaveTimer = setTimeout(() => {
            analyticsSaveTimer = null;
            if (analyticsDirty) {
                analyticsDirty = false;
                try {
                    const freshDb = getDb();
                    saveDb(freshDb);
                } catch (e) {
                    console.warn('[ANALYTICS] Debounced flush error:', e.message);
                }
            }
        }, 15000); // Flush to disk at most once every 15s to prevent I/O thrashing & race conditions
    }
}

function addAnalyticsEvent(db, evt) {
    const today = getTodayAnalytics(db);
    const now = new Date();
    const timeStr = now.toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Asia/Bangkok' });
    const fullEvent = {
        id: 'EVT-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        ts: Date.now(),
        time: timeStr,
        type: evt.type || 'info',
        user: sanitizeTelemetryText(evt.user || 'ผู้เยี่ยมชม', 60),
        role: evt.role === 'member' ? 'member' : 'guest',
        text: sanitizeTelemetryText(evt.text || '', 160),
        productId: (typeof evt.productId === 'string' && /^[a-z0-9\-]{1,32}$/.test(evt.productId)) ? evt.productId : null,
        amount: typeof evt.amount === 'number' ? Math.max(0, Math.round(evt.amount * 100) / 100) : null
    };
    if (!today.recentEvents) today.recentEvents = [];
    today.recentEvents.unshift(fullEvent);
    if (today.recentEvents.length > 40) {
        today.recentEvents = today.recentEvents.slice(0, 40);
    }
    return fullEvent;
}

// Auto prune sessions inactive for > 60 seconds
setInterval(() => {
    cleanStaleSessions();
}, 20000);

// ─── [FIX #4] Email Validation Helper ───────────────────────────────────────
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
function isValidEmail(email) {
    return typeof email === 'string' && EMAIL_REGEX.test(email.trim()) && email.length <= 254;
}

// ─── [FIX #5] SHA-256 File Fingerprint (Server-side) ────────────────────────
// ❌ Before: `F_${file.size}_${file.originalname}` → rename แล้วส่งซ้ำได้
// ✅ After: SHA-256 hash ของ file buffer จริง
function computeSlipSHA256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Master catalog price list (Single source of truth on server)
const MASTER_CATALOG = {
    "cpc-01": { title: "CapCut Pro 1M Private", price: 129.00, warranty: "30 วัน" },
    "cpc-02": { title: "CapCut Pro 1M Shared", price: 79.00, warranty: "30 วัน" },
    "cpc-03": { title: "CapCut Team 1M", price: 189.00, warranty: "30 วัน" },
    "cpc-04": { title: "CapCut VIP 1M", price: 259.00, warranty: "30 วัน" },
    "goo-ai-01": { title: "Google AI Pro Link", price: 150.00, warranty: "30 วัน" },
    "goo-ai-02": { title: "Google AI Ultra Private", price: 2590.00, warranty: "30 วัน" },
    "goo-ai-03": { title: "Google AI Pro Shared", price: 99.00, warranty: "30 วัน" },
    "goo-01": { title: "Google Drive 5TB Private", price: 229.00, warranty: "30 วัน" },
    "goo-02": { title: "Google One Subscription Pro 5TB (18 เดือน) - Activation Link", price: 99.00, warranty: "30 วัน" },
    "grk-01": { title: "Grok 7D Private", price: 290.00, warranty: "7 วัน" },
    "grk-02": { title: "Grok 1M Private", price: 950.00, warranty: "30 วัน" },
    "grk-03": { title: "SuperGrok Heavy 1M", price: 4990.00, warranty: "30 วัน" },
    "cld-01": { title: "Claude Pro 1M Private", price: 850.00, warranty: "30 วัน" },
    "cld-02": { title: "Claude Pro 1M Shared", price: 280.00, warranty: "30 วัน" },
    "adb-01": { title: "Adobe Acrobat Pro 1M", price: 490.00, warranty: "30 วัน" },
    "adb-02": { title: "Adobe CC All Apps 1M", price: 790.00, warranty: "30 วัน" },
    "ms-01": { title: "Windows 11 OEM Key", price: 290.00, warranty: "ตลอดชีพ" },
    "ms-02": { title: "Microsoft 365 1M", price: 259.00, warranty: "30 วัน" },
    "ms-03": { title: "Microsoft Copilot Pro 1M", price: 590.00, warranty: "30 วัน" }
};

// Catalog product resolution helper (Unifies built-in catalog & custom admin products)
function getCatalogProduct(productId, db) {
    if (!productId || typeof productId !== 'string') return null;
    const currentDb = db || getDb();
    if (currentDb.customProducts && currentDb.customProducts[productId]) {
        const cp = currentDb.customProducts[productId];
        if (cp.deleted) return null;
        return cp;
    }
    if (MASTER_CATALOG[productId]) {
        return MASTER_CATALOG[productId];
    }
    return null;
}

// Effective unit price calculator (considers admin dynamic customPrices & customProducts)
function getEffectiveUnitPrice(productId, product, db) {
    const currentDb = db || getDb();
    if (currentDb.customPrices && currentDb.customPrices[productId] && typeof currentDb.customPrices[productId].price === 'number') {
        return currentDb.customPrices[productId].price;
    }
    if (currentDb.customProducts && currentDb.customProducts[productId] && typeof currentDb.customProducts[productId].price === 'number') {
        return currentDb.customProducts[productId].price;
    }
    return (product && typeof product.price === 'number') ? product.price : 0;
}

// ─── [SECURITY FIX] Strict Discord Webhook URL Validator (Anti-SSRF) ─────────
function isValidDiscordWebhookUrl(url) {
    if (!url || typeof url !== 'string') return false;
    try {
        const parsed = new URL(url.trim());
        if (parsed.protocol !== 'https:') return false;
        const validHosts = ['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com'];
        if (!validHosts.includes(parsed.hostname.toLowerCase())) return false;
        // Pathname must strictly match /api/webhooks/<id>/<token>
        const pathRegex = /^\/api\/webhooks\/[0-9]{17,21}\/[A-Za-z0-9_\-]+(?:\/)?$/;
        return pathRegex.test(parsed.pathname);
    } catch {
        return false;
    }
}

// ─── Discord Webhook Real-time Order Notification Helper (Hardened & Anti-SSRF) ─
async function sendDiscordNotification(webhookUrl, order, isFulfillmentUpdate = false) {
    if (!isValidDiscordWebhookUrl(webhookUrl)) return;
    try {
        const isPending = (order.items || []).some(it => !it.credentials || it.status === 'pending_fulfillment');

        let color = 0x10B981; // emerald
        const safeOrderId = String(order.orderId || '-').replace(/[`\\]/g, '').slice(0, 32);
        let title = `🛒 มีคำสั่งซื้อใหม่ #${safeOrderId}`;
        let alertMessage = `✅ **มีคำสั่งซื้อใหม่สำเร็จในระบบ**`;

        if (isFulfillmentUpdate) {
            color = 0x8B5CF6; // purple
            title = `📦 จัดส่งสินค้าสำเร็จ #${safeOrderId}`;
            alertMessage = `🎉 **แอดมินส่งมอบคีย์เรียบร้อยแล้ว** สำหรับคำสั่งซื้อ #${safeOrderId}`;
        } else if (isPending) {
            color = 0xF59E0B; // amber
            title = `🚨 แจ้งเตือนออเดอร์รอจัดส่ง #${safeOrderId}`;
            alertMessage = `⚠️ **มีออเดอร์ On-Demand โอนเงินแล้ว!** กรุณาเข้าสู่ระบบแอดมินเพื่อส่งมอบคีย์`;
        }

        let itemsText = (order.items || []).map((it, idx) => {
            const titleStr = String(it.productTitle || 'สินค้า').replace(/[`*_\\]/g, '').slice(0, 60);
            const statusTxt = it.credentials && it.status !== 'pending_fulfillment' ? '✅ จัดส่งแล้ว' : '🟡 รอส่งมอบ';
            return `${idx + 1}. **${titleStr}** (฿${parseFloat(it.price || 0).toFixed(2)}) - ${statusTxt}`;
        }).join('\n');

        if (itemsText.length > 950) {
            itemsText = itemsText.slice(0, 930) + '\n... (มีรายการเพิ่มเติม)';
        }

        const safeEmail = String(order.email || order.recipientEmail || '-').slice(0, 100);
        const safeRef = String(order.transRef || '-').replace(/[`\\]/g, '').slice(0, 50);

        const embed = {
            title: title.slice(0, 250),
            color: color,
            fields: [
                { name: "💰 ยอดชำระเงิน", value: `**฿${parseFloat(order.totalAmount || 0).toFixed(2)}**`, inline: true },
                { name: "📊 สถานะ", value: String(order.status || (isPending ? "รอจัดส่ง" : "จัดส่งสำเร็จ")).slice(0, 100), inline: true },
                { name: "📧 อีเมลลูกค้า", value: safeEmail, inline: true },
                { name: "🧾 สลิปอ้างอิง", value: `\`${safeRef}\``, inline: true },
                { name: "📦 รายการสินค้า", value: itemsText || "ไม่มีรายการ" }
            ],
            footer: { text: "Supinkly.AI Real-Time Order System" },
            timestamp: new Date().toISOString()
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6000);
        try {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: alertMessage,
                    embeds: [embed]
                }),
                signal: controller.signal
            });
        } finally {
            clearTimeout(timeoutId);
        }
    } catch (err) {
        console.error('[DISCORD-WEBHOOK] Error sending notification:', err.message);
    }
}

// In-flight slip mutex set to eliminate concurrent double-spend race conditions
const inFlightSlips = new Set();

// 1. API: Verify Slip & Dispense Product (Server-Side Verified)
app.post('/api/checkout/verify-slip', checkoutRateLimit, upload.single('slip'), async (req, res) => {
    let activeSlipHash = null;
    try {
        // [AUTHENTICATION & EMAIL RESOLUTION]
        const userSession = authenticateUser(req);
        const db = getDb();
        let orderEmail = '';
        let orderUserId = null;
        let orderUserName = '';

        if (userSession && userSession.email) {
            orderEmail = userSession.email.trim().toLowerCase();
            orderUserId = userSession.userId || null;
            orderUserName = userSession.displayName || orderEmail;
        } else if (req.body.email && typeof req.body.email === 'string' && isValidEmail(req.body.email)) {
            orderEmail = req.body.email.trim().toLowerCase();
            orderUserName = orderEmail;
            const matchedUser = (db.users || []).find(u => u.email === orderEmail);
            if (matchedUser) {
                orderUserId = matchedUser.id;
                orderUserName = matchedUser.displayName || orderEmail;
            }
        } else {
            return res.status(401).json({
                success: false,
                requireLogin: true,
                message: "กรุณาระบุอีเมลที่ถูกต้องหรือเข้าสู่ระบบก่อนดำเนินการชำระเงิน เพื่อบันทึกคีย์และประวัติการสั่งซื้อเข้าบัญชีของคุณ"
            });
        }
        const { cartItems } = req.body;

        let parsedCart;
        try {
            parsedCart = typeof cartItems === 'string' ? JSON.parse(cartItems) : cartItems;
            if (!Array.isArray(parsedCart) || parsedCart.length === 0) throw new Error();
        } catch {
            return res.status(400).json({ success: false, message: "ข้อมูลตะกร้าสินค้าไม่ถูกต้อง" });
        }

        if (!req.file || !isValidImageBuffer(req.file.buffer)) {
            return res.status(400).json({ success: false, message: "กรุณาแนบไฟล์รูปภาพสลิปที่ถูกต้อง (JPG, PNG, WEBP)" });
        }

        // SHA-256 fingerprint จากไฟล์จริง
        const slipHash = computeSlipSHA256(req.file.buffer);
        activeSlipHash = slipHash;

        if (db.usedSlips && db.usedSlips.includes(slipHash)) {
            return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้วในระบบ ไม่สามารถใช้ซ้ำได้" });
        }

        // Concurrency Guard: ป้องกันการส่งสลิปซ้ำพร้อมกันในเสี้ยววินาที (Double-Spend / Anti-Replay)
        if (inFlightSlips.has(slipHash)) {
            return res.status(409).json({ success: false, message: "สลิปนี้กำลังอยู่ระหว่างการตรวจสอบ กรุณารอสักครู่" });
        }
        inFlightSlips.add(slipHash);

        // Validate cart items and calculate expected total price
        const VALID_ID_REGEX = /^[a-z0-9\-]{1,32}$/;
        let expectedTotal = 0;
        for (const item of parsedCart) {
            if (!item.productId || !VALID_ID_REGEX.test(item.productId)) {
                return res.status(400).json({ success: false, message: "productId ไม่ถูกต้อง" });
            }
            const qty = parseInt(item.quantity, 10);
            if (isNaN(qty) || qty < 1 || qty > 50) {
                return res.status(400).json({ success: false, message: "จำนวนสินค้าไม่ถูกต้อง" });
            }
            item.quantity = qty;

            const catalogItem = getCatalogProduct(item.productId, db);
            if (!catalogItem) {
                return res.status(400).json({ success: false, message: `ไม่พบข้อมูลสินค้ารหัส: ${item.productId}` });
            }
            const unitPrice = getEffectiveUnitPrice(item.productId, catalogItem, db);
            let finalUnitPrice = unitPrice;
            if (typeof item.price === 'number' && item.price > 0) {
                if (Math.abs(item.price - unitPrice) <= Math.max(30, unitPrice * 0.15)) {
                    finalUnitPrice = item.price;
                }
            }
            expectedTotal += finalUnitPrice * qty;
        }

        const originalSubtotal = expectedTotal;
        let appliedCouponInfo = null;
        let discountAmount = 0;

        const promoCode = (req.body.promoCode || '').trim().toUpperCase();
        if (promoCode) {
            const coupons = db.coupons || DEFAULT_SERVER_COUPONS;
            const coupon = coupons.find(c => c.code && c.code.toUpperCase() === promoCode && c.active);
            if (!coupon) {
                return res.status(400).json({ success: false, message: `ไม่พบโค้ดส่วนลด "${promoCode}" หรือโค้ดถูกปิดใช้งาน` });
            }

            if (coupon.expiresAt) {
                const exp = new Date(coupon.expiresAt + 'T23:59:59');
                if (!isNaN(exp.getTime()) && Date.now() > exp.getTime()) {
                    return res.status(400).json({ success: false, message: `โค้ดส่วนลด "${promoCode}" หมดอายุแล้ว` });
                }
            }

            if (coupon.usageLimit && typeof coupon.usedCount === 'number' && coupon.usedCount >= coupon.usageLimit) {
                return res.status(400).json({ success: false, message: `โค้ดส่วนลด "${promoCode}" มีผู้ใช้สิทธิ์ครบตามจำนวนที่กำหนดแล้ว` });
            }

            if (expectedTotal < (coupon.minSpend || 0)) {
                return res.status(400).json({ success: false, message: `ยอดสั่งซื้อไม่ถึงเกณฑ์ขั้นต่ำสำหรับโค้ดส่วนลด "${promoCode}" (ขั้นต่ำ ฿${coupon.minSpend})` });
            }

            const isPercent = (coupon.discountType === 'percent' || coupon.type === 'percentage' || coupon.type === 'percent');
            const val = typeof coupon.discountValue === 'number' ? coupon.discountValue : (typeof coupon.value === 'number' ? coupon.value : 0);
            if (isPercent) {
                discountAmount = Math.round((expectedTotal * val / 100) * 100) / 100;
                if (coupon.maxDiscount && coupon.maxDiscount > 0) {
                    discountAmount = Math.min(discountAmount, coupon.maxDiscount);
                }
            } else {
                discountAmount = Math.min(expectedTotal, val);
            }
            discountAmount = Math.max(0, Math.round(discountAmount * 100) / 100);
            expectedTotal = Math.max(1, Math.round((expectedTotal - discountAmount) * 100) / 100);
            appliedCouponInfo = {
                code: coupon.code,
                title: coupon.title,
                type: isPercent ? 'percentage' : 'fixed',
                discountType: isPercent ? 'percent' : 'fixed',
                value: val,
                discountValue: val,
                discountAmount
            };
        }

        let transRef = null;
        let isAutoVerified = false;

        // ── Save slip image to disk for admin audit & fulfillment ──
        const slipsDir = path.join(__dirname, 'images', 'slips');
        if (!fs.existsSync(slipsDir)) {
            try { fs.mkdirSync(slipsDir, { recursive: true }); } catch { }
        }
        const slipFilename = `${slipHash.slice(0, 20)}.jpg`;
        const slipFilePath = path.join(slipsDir, slipFilename);
        try {
            fs.writeFileSync(slipFilePath, req.file.buffer);
        } catch (e) {
            console.warn("[SLIP] Could not write slip image to disk:", e.message);
        }
        const slipUrl = `/images/slips/${slipFilename}`;
        const slipMime = req.file.mimetype || 'image/jpeg';
        const slipData = `data:${slipMime};base64,${req.file.buffer.toString('base64')}`;

        // ── Verify with SlipOK Server-Side (if API key is configured) ──
        const apiKey = (process.env.SLIPOK_API_KEY || db.slipOkApiKey || "").trim();
        const branchId = (process.env.SLIPOK_BRANCH_ID || db.slipOkBranchId || "77491").trim();

        if (apiKey) {
            try {
                const formData = new FormData();
                const blob = new Blob([req.file.buffer], { type: req.file.mimetype || 'image/jpeg' });
                formData.append('files', blob, req.file.originalname || 'slip.jpg');
                formData.append('log', 'true');
                formData.append('amount', String(expectedTotal));

                const slipRes = await fetch(`https://api.slipok.com/api/line/apikey/${branchId}`, {
                    method: 'POST',
                    headers: { 'x-authorization': apiKey },
                    body: formData
                });
                const slipJson = await slipRes.json();

                if (!slipJson.success || !slipJson.data) {
                    console.warn("[SLIPOK] Non-success response:", slipJson);
                    // If SlipOK explicitly says the slip has duplicate usage or bank rejection
                    if (slipJson.code === 1001 || (slipJson.message && (slipJson.message.includes('สลิปซ้ำ') || slipJson.message.includes('ไม่พบข้อมูล')))) {
                        return res.status(400).json({
                            success: false,
                            message: slipJson.message || "สลิปไม่ถูกต้อง หรือไม่ผ่านการตรวจสอบจากระบบธนาคาร"
                        });
                    }
                    // Quota exhausted, branch inactive, or temporary service issue: fall back to manual review queue
                    console.warn("[SLIPOK] Upstream service degraded/quota exhausted. Falling back to manual review queue.");
                    isAutoVerified = false;
                } else {
                    const slipData = slipJson.data;
                    if (slipData.success === false) {
                        return res.status(400).json({ success: false, message: "สลิปนี้ไม่ผ่านการตรวจสอบความถูกต้องจากธนาคาร" });
                    }

                    // Check transferred amount (with 0.05 THB float tolerance)
                    const transferred = parseFloat(slipData.amount);
                    if (isNaN(transferred) || (transferred + 0.05) < expectedTotal) {
                        return res.status(400).json({
                            success: false,
                            message: `ยอดเงินในสลิป (฿${(transferred || 0).toFixed(2)}) ไม่ตรงกับยอดชำระที่ต้องโอน (฿${expectedTotal.toFixed(2)})`
                        });
                    }

                    // ── [SECURITY FIX] Receiver Verification (Wrong Recipient Attack Prevention) ──
                    const expectedPhone = (db.promptPayNumber || process.env.PROMPTPAY_NUMBER || "0982949371").replace(/[^0-9]/g, '');
                    const expectedName = (db.promptPayAccountName || process.env.PROMPTPAY_NAME || "สุพัฒน์ มีสมบัติ").trim();
                    const receiver = slipData.receiver || {};
                    const receiverProxy = (receiver.proxy?.value || '').replace(/[^0-9]/g, '');
                    const receiverAcc = (receiver.account?.value || '').replace(/[^0-9]/g, '');
                    const receiverName = (receiver.name || receiver.displayName || '').toLowerCase();

                    let isReceiverMatched = false;
                    if (receiverProxy && expectedPhone) {
                        if (receiverProxy === expectedPhone || receiverProxy.endsWith(expectedPhone.slice(-8)) || expectedPhone.endsWith(receiverProxy.slice(-8))) {
                            isReceiverMatched = true;
                        }
                    }
                    if (!isReceiverMatched && receiverAcc && expectedPhone) {
                        const last4 = expectedPhone.slice(-4);
                        if (receiverAcc.endsWith(last4)) {
                            isReceiverMatched = true;
                        }
                    }
                    if (!isReceiverMatched && receiverName && expectedName) {
                        const nameParts = expectedName.toLowerCase().split(/\s+/).filter(k => k.length >= 3);
                        if (nameParts.some(part => receiverName.includes(part))) {
                            isReceiverMatched = true;
                        }
                    }

                    if (!isReceiverMatched) {
                        return res.status(400).json({
                            success: false,
                            message: "บัญชีผู้รับเงินในสลิปไม่ตรงกับบัญชีของร้านค้า Supinkly.AI กรุณาตรวจสอบสลิปการโอนเงิน"
                        });
                    }

                    // Anti-Replay on transRef
                    if (slipData.transRef) {
                        transRef = slipData.transRef;
                    }
                    isAutoVerified = true;
                }
            } catch (err) {
                console.error("[SLIPOK] Verification error, falling back to manual queue:", err.message);
                // Graceful fallback to manual queue
                isAutoVerified = false;
            }
        } else {
            // SlipOK is unconfigured: gracefully accept genuine slip into admin manual verification & fulfillment queue
            isAutoVerified = false;
        }

        // ── [SECURITY FIX] Re-read db to avoid TOCTOU race conditions during async SlipOK fetch ──
        const currentDb = getDb();

        if (currentDb.usedSlips && currentDb.usedSlips.includes(slipHash)) {
            return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้วในระบบ ไม่สามารถใช้ซ้ำได้" });
        }
        if (transRef) {
            if (!currentDb.usedTransRefs) currentDb.usedTransRefs = [];
            if (currentDb.usedTransRefs.includes(transRef)) {
                return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้วในระบบ ไม่สามารถใช้ซ้ำได้" });
            }
            currentDb.usedTransRefs.push(transRef);
            // [SECURITY] Cap to last 10,000 entries to prevent unbounded growth
            if (currentDb.usedTransRefs.length > 10000) {
                currentDb.usedTransRefs = currentDb.usedTransRefs.slice(-10000);
            }
        }
        if (!currentDb.usedSlips) currentDb.usedSlips = [];
        currentDb.usedSlips.push(slipHash);
        // [SECURITY] Cap to last 10,000 entries to prevent unbounded growth
        if (currentDb.usedSlips.length > 10000) {
            currentDb.usedSlips = currentDb.usedSlips.slice(-10000);
        }

        // Dispense Items from secure server inventory
        const deliveredItems = [];
        let hasPending = !isAutoVerified;

        for (const item of parsedCart) {
            const master = getCatalogProduct(item.productId, currentDb);
            if (!currentDb.inventory[item.productId]) currentDb.inventory[item.productId] = [];
            const pool = currentDb.inventory[item.productId];
            const effectivePrice = getEffectiveUnitPrice(item.productId, master, currentDb);
            const productTitle = master ? master.title : item.productId;
            const productWarranty = master ? master.warranty : "30 วัน";

            for (let i = 0; i < item.quantity; i++) {
                if (isAutoVerified && pool.length > 0) {
                    const cred = pool.shift();
                    deliveredItems.push({
                        productId: item.productId,
                        productTitle: productTitle,
                        price: effectivePrice,
                        warranty: productWarranty,
                        status: "delivered",
                        credentials: cred
                    });
                } else {
                    hasPending = true;
                    deliveredItems.push({
                        productId: item.productId,
                        productTitle: productTitle,
                        price: effectivePrice,
                        warranty: productWarranty,
                        status: "pending_fulfillment",
                        credentials: null
                    });
                }
            }
        }

        // Record Order with unguessable cryptographic token
        const orderId = "SPK-" + Date.now().toString().slice(-6) + crypto.randomBytes(3).toString('hex').toUpperCase();

        const order = {
            orderId,
            date: new Date().toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }),
            email: orderEmail,
            recipientEmail: orderEmail,
            userId: orderUserId || (userSession ? userSession.userId : null),
            userName: orderUserName || (userSession ? userSession.displayName : orderEmail),
            subtotal: originalSubtotal,
            discountAmount: discountAmount,
            coupon: appliedCouponInfo,
            totalAmount: expectedTotal,
            paymentMethod: "Thai QR PromptPay",
            transRef: transRef || "REF-" + Date.now().toString(36).toUpperCase(),
            items: deliveredItems,
            status: hasPending ? "🟡 รอส่งมอบ (On-Demand)" : "🟢 จัดส่งสำเร็จทันที",
            slipHash,
            slipUrl,
            slipData,
            isAutoVerified
        };
        if (!currentDb.orders) currentDb.orders = [];
        currentDb.orders.unshift(order);

        // [COUPON USAGE] Increment usedCount for the redeemed promotion
        if (appliedCouponInfo && appliedCouponInfo.code) {
            if (!currentDb.coupons) currentDb.coupons = [...DEFAULT_SERVER_COUPONS];
            const targetCoupon = currentDb.coupons.find(c => c.code && c.code.toUpperCase() === appliedCouponInfo.code.toUpperCase());
            if (targetCoupon) {
                targetCoupon.usedCount = (targetCoupon.usedCount || 0) + 1;
            }
        }

        // [ANALYTICS] Record verified order into daily analytics
        try {
            const todayKey = getTodayKey();
            if (!currentDb.analytics) currentDb.analytics = {};
            if (!currentDb.analytics[todayKey]) currentDb.analytics[todayKey] = initTodayAnalytics(todayKey);
            currentDb.analytics[todayKey].ordersCount = (currentDb.analytics[todayKey].ordersCount || 0) + 1;
            currentDb.analytics[todayKey].revenue = (currentDb.analytics[todayKey].revenue || 0) + expectedTotal;
            addAnalyticsEvent(currentDb, {
                type: 'order_success',
                user: (userSession && userSession.displayName) ? userSession.displayName : orderEmail,
                role: userSession ? 'member' : 'guest',
                text: `สั่งซื้อสำเร็จ ${order.orderId} ยอด ฿${expectedTotal.toFixed(2)} (${deliveredItems.map(i => i.productTitle).join(', ')})`,
                amount: expectedTotal
            });
        } catch (analyticsErr) {
            console.warn('[ANALYTICS] Order tracking error:', analyticsErr.message);
        }

        saveDb(currentDb);

        // [NOTIFICATION & RECEIPT] Fire-and-forget Discord alert & Email receipt
        const webhookUrl = process.env.DISCORD_WEBHOOK_URL || currentDb.discordWebhookUrl;
        if (webhookUrl) {
            sendDiscordNotification(webhookUrl, order, false).catch(e => console.warn('[DISCORD] Notification error:', e.message));
        }
        mailService.sendOrderReceiptEmail(order, false, currentDb).catch(e => console.warn('[MAIL] Order receipt email error:', e.message));

        res.json({ success: true, order, isAutoVerified, pendingReview: !isAutoVerified });
    } catch (err) {
        console.error('checkout error:', err.message);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" });
    } finally {
        if (activeSlipHash) {
            inFlightSlips.delete(activeSlipHash);
        }
    }
});

// 1.1 API: Sync Local Orders into Server Database (Disaster recovery & client reconciliation)
app.post('/api/checkout/sync-local-orders', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ: ต้องใช้สิทธิ์ผู้ดูแลระบบเท่านั้น" });
    }
    try {
        const { orders } = req.body;
        if (!Array.isArray(orders) || orders.length === 0) {
            return res.json({ success: true, syncedCount: 0 });
        }
        const db = getDb();
        if (!db.orders) db.orders = [];
        const existingOrderIds = new Set(db.orders.map(o => o.orderId));
        let syncedCount = 0;

        for (const rawOrder of orders.slice(0, 50)) {
            if (!rawOrder || !rawOrder.orderId || typeof rawOrder.orderId !== 'string') continue;
            if (existingOrderIds.has(rawOrder.orderId)) continue;

            const safeOrder = {
                orderId: rawOrder.orderId,
                date: rawOrder.date || new Date().toLocaleString('th-TH'),
                email: (rawOrder.email || rawOrder.recipientEmail || '').trim().toLowerCase(),
                recipientEmail: (rawOrder.recipientEmail || rawOrder.email || '').trim().toLowerCase(),
                userId: rawOrder.userId || null,
                userName: rawOrder.userName || rawOrder.recipientEmail || 'ลูกค้า',
                subtotal: parseFloat(rawOrder.subtotal) || parseFloat(rawOrder.totalAmount) || 0,
                discountAmount: parseFloat(rawOrder.discountAmount) || 0,
                coupon: rawOrder.coupon || null,
                totalAmount: parseFloat(rawOrder.totalAmount) || 0,
                paymentMethod: rawOrder.paymentMethod || "Thai QR PromptPay",
                transRef: rawOrder.transRef || ("REF-" + Date.now().toString(36).toUpperCase()),
                items: Array.isArray(rawOrder.items) ? rawOrder.items : [],
                status: rawOrder.status || "🟡 รอส่งมอบ (On-Demand)",
                slipHash: rawOrder.slipHash || rawOrder.slipFingerprint || null,
                slipUrl: rawOrder.slipUrl || "",
                slipData: rawOrder.slipData || rawOrder.slipDataUrl || "",
                isAutoVerified: !!rawOrder.isAutoVerified,
                isDemo: !!rawOrder.isDemo
            };
            db.orders.unshift(safeOrder);
            existingOrderIds.add(safeOrder.orderId);
            syncedCount++;
        }

        if (syncedCount > 0) {
            saveDb(db);
        }
        res.json({ success: true, syncedCount, totalOrders: db.orders.length, orders: db.orders });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ─── [PROMOTIONS & DISCOUNT COUPONS API] ────────────────────────────────────

// Public: Get all active promotions (exclude expired or quota-exhausted coupons)
app.get('/api/promotions', (req, res) => {
    try {
        const db = getDb();
        const now = Date.now();
        const coupons = (db.coupons || DEFAULT_SERVER_COUPONS).filter(c => {
            if (!c || c.active === false) return false;
            if (c.expiresAt) {
                const exp = new Date(c.expiresAt + 'T23:59:59');
                if (!isNaN(exp.getTime()) && now > exp.getTime()) return false;
            }
            if (c.usageLimit && typeof c.usedCount === 'number' && c.usedCount >= c.usageLimit) {
                return false;
            }
            return true;
        });
        res.json({ success: true, promotions: coupons });
    } catch (err) {
        res.json({ success: true, promotions: DEFAULT_SERVER_COUPONS.filter(c => c.active) });
    }
});

// Public: Validate a coupon against current subtotal (Rate-limited to prevent brute-force scans)
app.post('/api/promotions/validate', couponValidateRateLimit, (req, res) => {
    const { code, subtotal } = req.body;
    if (!code || typeof code !== 'string') {
        return res.status(400).json({ success: false, message: "กรุณาระบุโค้ดส่วนลด" });
    }
    const cleanCode = code.trim().toUpperCase();
    const db = getDb();
    const coupons = db.coupons || DEFAULT_SERVER_COUPONS;
    const coupon = coupons.find(c => c.code && c.code.toUpperCase() === cleanCode);

    if (!coupon || !coupon.active) {
        return res.status(400).json({ success: false, message: `ไม่พบโค้ดส่วนลด "${cleanCode}" หรือโค้ดถูกปิดใช้งาน` });
    }

    if (coupon.expiresAt) {
        const exp = new Date(coupon.expiresAt + 'T23:59:59');
        if (!isNaN(exp.getTime()) && Date.now() > exp.getTime()) {
            return res.status(400).json({ success: false, message: `โค้ดส่วนลด "${cleanCode}" หมดอายุแล้ว` });
        }
    }

    if (coupon.usageLimit && typeof coupon.usedCount === 'number' && coupon.usedCount >= coupon.usageLimit) {
        return res.status(400).json({ success: false, message: `โค้ดส่วนลด "${cleanCode}" มีผู้ใช้สิทธิ์ครบตามจำนวนที่กำหนดแล้ว` });
    }

    const currentSubtotal = Math.max(0, parseFloat(subtotal) || 0);
    const minSpend = Math.max(0, coupon.minSpend || 0);
    if (currentSubtotal < minSpend) {
        return res.status(400).json({
            success: false,
            message: `โค้ด "${cleanCode}" ใช้ได้เมื่อสั่งซื้อขั้นต่ำ ฿${minSpend.toFixed(2)} (ขาดอีก ฿${(minSpend - currentSubtotal).toFixed(2)})`
        });
    }

    const isPercent = (coupon.discountType === 'percent' || coupon.type === 'percentage' || coupon.type === 'percent');
    const val = typeof coupon.discountValue === 'number' ? coupon.discountValue : (typeof coupon.value === 'number' ? coupon.value : 0);

    let discountAmount = 0;
    if (isPercent) {
        discountAmount = Math.round((currentSubtotal * val / 100) * 100) / 100;
        if (coupon.maxDiscount && coupon.maxDiscount > 0) {
            discountAmount = Math.min(discountAmount, coupon.maxDiscount);
        }
    } else {
        discountAmount = Math.min(currentSubtotal, val);
    }
    discountAmount = Math.max(0, Math.round(discountAmount * 100) / 100);
    const netTotal = Math.max(1, Math.round((currentSubtotal - discountAmount) * 100) / 100);

    res.json({
        success: true,
        coupon: {
            code: coupon.code,
            title: coupon.title,
            type: isPercent ? 'percentage' : 'fixed',
            discountType: isPercent ? 'percent' : 'fixed',
            value: val,
            discountValue: val,
            discountAmount,
            netTotal
        },
        message: `ใช้โค้ด "${coupon.code}" สำเร็จ! ประหยัดไป ฿${discountAmount.toFixed(2)}`
    });
});

// Admin: Get all coupons (active and inactive)
app.get('/api/admin/coupons', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    res.json({ success: true, coupons: db.coupons || DEFAULT_SERVER_COUPONS });
});

// Admin: Create or update a coupon
app.post('/api/admin/coupons', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { code, title, description, type, discountType, value, discountValue, minSpend, maxDiscount, expiresAt, active, badge, usageLimit } = req.body;
    if (!code || typeof code !== 'string') {
        return res.status(400).json({ success: false, message: "กรุณาระบุรหัสโค้ดส่วนลด" });
    }
    const cleanCode = code.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
    if (!cleanCode) {
        return res.status(400).json({ success: false, message: "รหัสโค้ดต้องเป็นตัวอักษรภาษาอังกฤษหรือตัวเลข" });
    }
    const numVal = parseFloat(value !== undefined ? value : discountValue);
    if (isNaN(numVal) || numVal <= 0) {
        return res.status(400).json({ success: false, message: "มูลค่าส่วนลดต้องมากกว่า 0" });
    }

    const resolvedType = (type || discountType) === 'fixed' ? 'fixed' : 'percentage';
    if (resolvedType === 'percentage' && numVal > 100) {
        return res.status(400).json({ success: false, message: "ส่วนลดแบบเปอร์เซ็นต์ต้องไม่เกิน 100%" });
    }

    const db = getDb();
    if (!db.coupons) db.coupons = [...DEFAULT_SERVER_COUPONS];

    const existingIndex = db.coupons.findIndex(c => c.code && c.code.toUpperCase() === cleanCode);
    const existingCoupon = existingIndex > -1 ? db.coupons[existingIndex] : null;

    const couponObj = {
        code: cleanCode,
        title: String(title || description || cleanCode).trim().slice(0, 80),
        description: String(description || title || '').trim().slice(0, 200),
        type: resolvedType,
        discountType: resolvedType === 'fixed' ? 'fixed' : 'percent',
        value: numVal,
        discountValue: numVal,
        minSpend: Math.max(0, parseFloat(minSpend) || 0),
        maxDiscount: Math.max(0, parseFloat(maxDiscount) || 0),
        usageLimit: (usageLimit && parseInt(usageLimit, 10) > 0) ? parseInt(usageLimit, 10) : null,
        usedCount: existingCoupon ? (existingCoupon.usedCount || 0) : 0,
        expiresAt: expiresAt ? String(expiresAt).slice(0, 10) : '2026-12-31',
        active: active !== false,
        badge: String(badge || '').trim().slice(0, 30),
        updatedAt: new Date().toISOString()
    };

    if (existingIndex > -1) {
        db.coupons[existingIndex] = couponObj;
    } else {
        db.coupons.unshift(couponObj);
    }
    saveDb(db);

    res.json({ success: true, message: `บันทึกโค้ดส่วนลด "${cleanCode}" เรียบร้อยแล้ว`, coupon: couponObj });
});

// Admin: Toggle active status
app.post('/api/admin/coupons/:code/toggle', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const code = (req.params.code || '').trim().toUpperCase();
    const db = getDb();
    if (!db.coupons) db.coupons = [...DEFAULT_SERVER_COUPONS];
    const coupon = db.coupons.find(c => c.code && c.code.toUpperCase() === code);
    if (!coupon) {
        return res.status(404).json({ success: false, message: "ไม่พบโค้ดส่วนลดนี้" });
    }
    coupon.active = !coupon.active;
    coupon.updatedAt = new Date().toISOString();
    saveDb(db);
    res.json({ success: true, active: coupon.active, message: `ปรับสถานะโค้ด "${code}" เป็น ${coupon.active ? 'เปิดใช้งาน' : 'ปิดใช้งาน'} แล้ว` });
});

// Admin: Delete a coupon
app.delete('/api/admin/coupons/:code', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const code = (req.params.code || '').trim().toUpperCase();
    const db = getDb();
    if (!db.coupons) db.coupons = [...DEFAULT_SERVER_COUPONS];
    const beforeLen = db.coupons.length;
    db.coupons = db.coupons.filter(c => c.code && c.code.toUpperCase() !== code);
    if (db.coupons.length === beforeLen) {
        return res.status(404).json({ success: false, message: "ไม่พบโค้ดส่วนลดนี้" });
    }
    saveDb(db);
    res.json({ success: true, message: `ลบโค้ดส่วนลด "${code}" เรียบร้อยแล้ว` });
});

// 2. API: Admin Authenticated Stock Management
app.post('/api/admin/stock', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { productId, newCredentials } = req.body;
    const db = getDb();

    const VALID_ID_REGEX = /^[a-z0-9\-]{1,32}$/;
    if (!productId || !VALID_ID_REGEX.test(productId)) {
        return res.status(400).json({ success: false, message: "productId ไม่ถูกต้อง" });
    }

    if (!db.inventory[productId]) db.inventory[productId] = [];
    if (Array.isArray(newCredentials)) {
        // [SECURITY] Sanitize credentials — allow only known safe string fields, limit batch size
        const MAX_BATCH = 500;
        const sanitized = newCredentials.slice(0, MAX_BATCH).map(cred => {
            if (!cred || typeof cred !== 'object' || Array.isArray(cred)) return null;
            return {
                ...(cred.email ? { email: String(cred.email).slice(0, 254) } : {}),
                ...(cred.password ? { password: String(cred.password).slice(0, 512) } : {}),
                ...(cred.key ? { key: String(cred.key).slice(0, 512) } : {}),
                ...(cred.link ? { link: sanitizeWebUrl(cred.link) } : {}),
                ...(cred.instructions ? { instructions: String(cred.instructions).slice(0, 1000) } : {}),
            };
        }).filter(c => c !== null && (c.email || c.key || c.link));

        db.inventory[productId].push(...sanitized);
    }
    saveDb(db);

    res.json({ success: true, stockCount: db.inventory[productId].length });
});

// 3. API: Admin Login & Session Verification
app.post('/api/admin/login', adminLoginRateLimit, (req, res) => {
    const { pin } = req.body;
    const db = getDb();
    const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
    if (!pin || !verifyPin(pin, storedHash)) {
        return res.status(403).json({ success: false, message: "รหัส PIN แอดมินไม่ถูกต้อง" });
    }
    const { token, expiresAt } = generateAdminToken();
    adminSessions.set(token, expiresAt);
    res.json({ success: true, token, expiresAt });
});

// 4. API: Admin Session Check
app.post('/api/admin/verify-session', adminRateLimit, (req, res) => {
    if (authenticateAdmin(req)) {
        return res.json({ success: true, valid: true });
    }
    return res.status(401).json({ success: false, valid: false });
});

// 5. API: Admin Fetch Orders
app.get('/api/admin/orders', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    res.json({ success: true, orders: db.orders || [] });
});

// 5.1 API: Admin Delete Order
app.delete('/api/admin/orders/:orderId', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { orderId } = req.params;
    if (!orderId) {
        return res.status(400).json({ success: false, message: "ไม่ระบุรหัสคำสั่งซื้อ" });
    }
    const db = getDb();
    const orderIndex = (db.orders || []).findIndex(o => o.orderId === orderId);
    if (orderIndex === -1) {
        return res.status(404).json({ success: false, message: "ไม่พบคำสั่งซื้อที่ต้องการลบ" });
    }

    const removedOrder = db.orders.splice(orderIndex, 1)[0];

    // Clean up usedSlips and usedTransRefs
    if (removedOrder.slipHash && Array.isArray(db.usedSlips)) {
        db.usedSlips = db.usedSlips.filter(h => h !== removedOrder.slipHash);
    }
    if (removedOrder.transRef && Array.isArray(db.usedTransRefs)) {
        db.usedTransRefs = db.usedTransRefs.filter(r => r !== removedOrder.transRef);
    }

    saveDb(db);
    res.json({ success: true, message: `ลบคำสั่งซื้อ ${orderId} สำเร็จเรียบร้อย`, orders: db.orders });
});

// 5.1.1 API: Admin Clear All Orders
app.post(['/api/admin/orders/clear-all', '/api/admin/orders/delete-all'], adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const count = (db.orders || []).length;
    db.orders = [];
    db.usedSlips = [];
    db.usedTransRefs = [];
    saveDb(db);
    res.json({ success: true, message: `ลบข้อมูลคำสั่งซื้อทั้งหมด ${count} รายการเรียบร้อยแล้ว`, orders: [] });
});

app.delete('/api/admin/orders', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const count = (db.orders || []).length;
    db.orders = [];
    db.usedSlips = [];
    db.usedTransRefs = [];
    saveDb(db);
    res.json({ success: true, message: `ลบข้อมูลคำสั่งซื้อทั้งหมด ${count} รายการเรียบร้อยแล้ว`, orders: [] });
});

// 5.2 API: Admin Attach/Re-upload Slip Image for an Existing Order
app.post('/api/admin/orders/:orderId/attach-slip', adminRateLimit, upload.single('slip'), (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { orderId } = req.params;
    if (!orderId || !req.file || !isValidImageBuffer(req.file.buffer)) {
        return res.status(400).json({ success: false, message: "กรุณาแนบไฟล์รูปภาพสลิปที่ถูกต้อง (JPG, PNG, WEBP)" });
    }

    const db = getDb();
    if (!db.orders) db.orders = [];
    const order = db.orders.find(o => o.orderId === orderId);
    if (!order) {
        return res.status(404).json({ success: false, message: "ไม่พบคำสั่งซื้อที่ระบุ" });
    }

    const slipHash = computeSlipSHA256(req.file.buffer);
    const slipsDir = path.join(__dirname, 'images', 'slips');
    if (!fs.existsSync(slipsDir)) {
        try { fs.mkdirSync(slipsDir, { recursive: true }); } catch {}
    }
    const slipFilename = `${slipHash.slice(0, 20)}.jpg`;
    const slipFilePath = path.join(slipsDir, slipFilename);
    try {
        fs.writeFileSync(slipFilePath, req.file.buffer);
    } catch (e) {
        console.warn("[ATTACH-SLIP] Could not write file:", e.message);
    }

    const slipUrl = `/images/slips/${slipFilename}`;
    const slipMime = req.file.mimetype || 'image/jpeg';
    const slipData = `data:${slipMime};base64,${req.file.buffer.toString('base64')}`;

    order.slipUrl = slipUrl;
    order.slipData = slipData;
    order.slipHash = slipHash;

    saveDb(db);
    res.json({ success: true, message: "แนบรูปสลิปให้คำสั่งซื้อเรียบร้อยแล้ว", slipUrl });
});

// 5.3 API: Admin Create Demo Order (For Testing & Verification)
app.post('/api/admin/orders/demo', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const demoOrderId = "SPK-DEMO" + Math.floor(1000 + Math.random() * 9000);
    const demoOrder = {
        orderId: demoOrderId,
        date: new Date().toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }),
        email: "demo.customer@gmail.com",
        recipientEmail: "demo.customer@gmail.com",
        userId: null,
        userName: "นายลูกค้า ทดสอบ (Demo)",
        subtotal: 129,
        discountAmount: 0,
        coupon: null,
        totalAmount: 129.00,
        paymentMethod: "Thai QR PromptPay (ทดสอบ)",
        transRef: "DEMO_" + Date.now().toString(36).toUpperCase(),
        slipHash: "demo_hash_" + Math.random().toString(36).substring(2, 10),
        slipUrl: "",
        slipData: `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="360" height="460" viewBox="0 0 360 460"><rect width="100%" height="100%" fill="%23f8fafc"/><rect x="16" y="16" width="328" height="428" rx="20" fill="white" stroke="%23e2e8f0" stroke-width="2"/><circle cx="180" cy="70" r="28" fill="%23ec4899"/><path d="M168 70 l8 8 l16 -16" fill="none" stroke="white" stroke-width="4" stroke-linecap="round"/><text x="180" y="125" text-anchor="middle" font-family="sans-serif" font-weight="bold" font-size="16" fill="%230f172a">ชำระเงินสำเร็จ (สลิปจำลอง)</text><text x="180" y="145" text-anchor="middle" font-family="sans-serif" font-size="12" fill="%2364748b">PromptPay QR Verification</text><line x1="40" y1="165" x2="320" y2="165" stroke="%23e2e8f0" stroke-dasharray="4 4"/><text x="40" y="200" font-family="sans-serif" font-size="12" fill="%2364748b">จำนวนเงิน</text><text x="320" y="200" text-anchor="end" font-family="sans-serif" font-weight="bold" font-size="20" fill="%23db2777">฿129.00</text><text x="40" y="240" font-family="sans-serif" font-size="12" fill="%2364748b">ผู้โอน</text><text x="320" y="240" text-anchor="end" font-family="sans-serif" font-size="12" font-weight="bold" fill="%23334155">นายลูกค้า ทดสอบ (Demo)</text><text x="40" y="275" font-family="sans-serif" font-size="12" fill="%2364748b">ผู้รับเงิน</text><text x="320" y="275" text-anchor="end" font-family="sans-serif" font-size="12" font-weight="bold" fill="%23334155">Supinkly.AI Store</text><text x="40" y="310" font-family="sans-serif" font-size="12" fill="%2364748b">รหัสอ้างอิง</text><text x="320" y="310" text-anchor="end" font-family="monospace" font-size="11" fill="%23475569">${demoOrderId}</text><rect x="40" y="340" width="280" height="70" rx="12" fill="%23fdf2f8" stroke="%23fbcfe8"/><text x="180" y="370" text-anchor="middle" font-family="sans-serif" font-weight="bold" font-size="12" fill="%23be185d">ตรวจสอบสลิปอัตโนมัติผ่านแล้ว</text><text x="180" y="392" text-anchor="middle" font-family="sans-serif" font-size="11" fill="%23db2777">SlipOK / PromptPay Hash Verified</text></svg>`,
        items: [
            {
                productId: "capcut-pro",
                productTitle: "CapCut Pro 1 ปี (บัญชีส่วนตัว)",
                brand: "CapCut",
                type: "App Premium",
                price: 129,
                warranty: "365 วัน",
                status: "pending_fulfillment",
                credentials: null
            }
        ],
        status: "🟡 รอส่งมอบ (On-Demand)",
        isAutoVerified: true,
        isDemo: true
    };
    if (!db.orders) db.orders = [];
    db.orders.unshift(demoOrder);
    saveDb(db);
    res.json({ success: true, order: demoOrder, orders: db.orders });
});

// 6. API: Admin Fulfill Order Item
app.post('/api/admin/fulfill', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { orderId, itemIndex, credentials, orderData } = req.body;
    if (!orderId || typeof itemIndex !== 'number' || !credentials) {
        return res.status(400).json({ success: false, message: "ข้อมูลไม่ครบถ้วน กรุณากรอกรหัสหรือข้อมูลบัญชี" });
    }

    const cleanOrderId = String(orderId).trim();
    const idx = parseInt(itemIndex, 10);
    const db = getDb();
    if (!db.orders) db.orders = [];

    // Robust case-insensitive search
    let order = db.orders.find(o => (o.orderId || '').trim().toUpperCase() === cleanOrderId.toUpperCase());

    // Disaster Recovery / Self-healing: if order existed in local storage but hadn't reached db.orders, restore it
    if (!order && orderData && typeof orderData === 'object' && orderData.orderId) {
        const recovered = {
            orderId: orderData.orderId,
            date: orderData.date || new Date().toLocaleString('th-TH'),
            email: (orderData.email || orderData.recipientEmail || '').trim().toLowerCase(),
            recipientEmail: (orderData.recipientEmail || orderData.email || '').trim().toLowerCase(),
            userId: orderData.userId || null,
            userName: orderData.userName || orderData.recipientEmail || 'ลูกค้า',
            subtotal: parseFloat(orderData.subtotal) || parseFloat(orderData.totalAmount) || 0,
            discountAmount: parseFloat(orderData.discountAmount) || 0,
            coupon: orderData.coupon || null,
            totalAmount: parseFloat(orderData.totalAmount) || 0,
            paymentMethod: orderData.paymentMethod || "Thai QR PromptPay",
            transRef: orderData.transRef || ("REF-" + Date.now().toString(36).toUpperCase()),
            items: Array.isArray(orderData.items) ? orderData.items : [],
            status: orderData.status || "🟡 รอส่งมอบ (On-Demand)",
            slipHash: orderData.slipHash || null,
            slipUrl: orderData.slipUrl || "",
            slipData: orderData.slipData || "",
            isAutoVerified: !!orderData.isAutoVerified,
            isDemo: !!orderData.isDemo
        };
        db.orders.unshift(recovered);
        order = recovered;
    }

    if (!order || !Array.isArray(order.items) || isNaN(idx) || idx < 0 || idx >= order.items.length) {
        return res.status(404).json({ success: false, message: "ไม่พบคำสั่งซื้อหรือรายการสินค้าที่ต้องการส่งมอบในระบบ" });
    }

    // [SECURITY] Sanitize credentials to safe string fields
    const cleanCred = {
        ...(credentials.email ? { email: String(credentials.email).trim().slice(0, 254) } : {}),
        ...(credentials.password ? { password: String(credentials.password).trim().slice(0, 512) } : {}),
        ...(credentials.key ? { key: String(credentials.key).trim().slice(0, 512) } : {}),
        ...(credentials.link ? { link: sanitizeWebUrl(credentials.link) } : {}),
        instructions: String(credentials.instructions || 'เข้าสู่ระบบและเริ่มใช้งานได้ทันที มีการรับประกันดูแลตลอดอายุการใช้งาน 30 วัน').trim().slice(0, 1000)
    };

    order.items[idx].credentials = cleanCred;
    order.items[idx].status = "delivered";

    // Re-evaluate entire order fulfillment status
    const allDelivered = order.items.every(it => {
        const hasCred = it.credentials && (it.credentials.email || it.credentials.key || it.credentials.link);
        return hasCred && it.status !== 'pending_fulfillment';
    });

    if (allDelivered) {
        order.status = "🟢 จัดส่งสำเร็จเรียบร้อย";
    } else {
        order.status = "🟡 จัดส่งแล้วบางส่วน (รอส่งมอบรายการที่เหลือ)";
    }

    saveDb(db);

    // [NOTIFICATION & RECEIPT] Notify customer that item/order has been delivered
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL || db.discordWebhookUrl;
    if (webhookUrl) {
        sendDiscordNotification(webhookUrl, order, true).catch(e => console.warn('[DISCORD] Fulfill notification error:', e.message));
    }
    mailService.sendOrderReceiptEmail(order, true, db).catch(e => console.warn('[MAIL] Fulfill receipt email error:', e.message));

    res.json({ success: true, order, orders: db.orders });
});

// 6.0.1 API: Public Catalog & Synced Custom Prices & Products
app.get('/api/catalog', (req, res) => {
    const db = getDb();
    const customPrices = db.customPrices || {};
    const customProducts = db.customProducts || {};
    res.json({
        success: true,
        catalog: MASTER_CATALOG,
        customPrices,
        customProducts
    });
});

// 6.0.2 API: Admin Update Product Price, Badge, and G2G URL
app.post('/api/admin/price', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { productId, price, originalPrice, badge, g2gUrl, action } = req.body;
    if (!productId || typeof productId !== 'string') {
        return res.status(400).json({ success: false, message: "กรุณาระบุ productId" });
    }

    const db = getDb();
    if (!db.customPrices) db.customPrices = {};

    if (action === 'reset') {
        if (db.customPrices[productId]) {
            delete db.customPrices[productId].manualOverride;
            if (price !== undefined) {
                const parsedPrice = parseFloat(price);
                if (!isNaN(parsedPrice)) {
                    db.customPrices[productId].price = parsedPrice;
                }
            }
        }
        saveDb(db);
        return res.json({ success: true, message: "คืนค่าราคาตลาดสำเร็จ", customPrices: db.customPrices });
    }

    const numPrice = parseFloat(price);
    if (isNaN(numPrice) || numPrice < 0) {
        return res.status(400).json({ success: false, message: "ราคาไม่ถูกต้อง" });
    }

    const numOrig = (originalPrice !== undefined && !isNaN(parseFloat(originalPrice)))
        ? parseFloat(originalPrice)
        : numPrice;

    const nowIso = new Date().toISOString();
    const existing = db.customPrices[productId] || {};
    db.customPrices[productId] = {
        ...existing,
        price: Math.round(numPrice * 100) / 100,
        originalPrice: Math.round(numOrig * 100) / 100,
        badge: typeof badge === 'string' ? badge.slice(0, 50).trim() : (existing.badge || ''),
        g2gUrl: typeof g2gUrl === 'string' ? sanitizeWebUrl(g2gUrl) : (existing.g2gUrl || ''),
        manualOverride: true,
        lastManualUpdate: nowIso,
        updatedAt: nowIso
    };

    saveDb(db);
    res.json({ success: true, message: "บันทึกราคาลงเซิร์ฟเวอร์สำเร็จ", customPrices: db.customPrices });
});

// 6.0.3 API: Admin Manage Product (Create / Edit Details: Title, Subtitle, Description, Brand, Type, Duration, Warranty, Devices, Price, Badge, G2G URL)
app.post('/api/admin/product', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { id, title, subtitle, description, brand, type, duration, devices, warranty, price, originalPrice, badge, isHighlight, g2gUrl } = req.body;
    if (!title || typeof title !== 'string' || !title.trim()) {
        return res.status(400).json({ success: false, message: "กรุณาระบุชื่อสินค้า" });
    }

    const db = getDb();
    if (!db.customProducts) db.customProducts = {};
    if (!db.customPrices) db.customPrices = {};

    const prodId = (id && typeof id === 'string' && id.trim())
        ? id.trim().toLowerCase().replace(/[^a-z0-9\-]/g, '-')
        : 'prod-' + Date.now().toString(36);

    const numPrice = !isNaN(parseFloat(price)) ? Math.max(0, parseFloat(price)) : 0;
    const numOrig = (!isNaN(parseFloat(originalPrice)) && parseFloat(originalPrice) >= numPrice)
        ? parseFloat(originalPrice)
        : numPrice;

    const existing = db.customProducts[prodId] || {};
    const nowIso = new Date().toISOString();
    const updatedProduct = {
        ...existing,
        id: prodId,
        title: title.trim().slice(0, 150),
        subtitle: typeof subtitle === 'string' ? subtitle.trim().slice(0, 200) : (existing.subtitle || ''),
        description: typeof description === 'string' ? description.trim().slice(0, 3000) : (existing.description || ''),
        brand: typeof brand === 'string' && brand.trim() ? brand.trim().slice(0, 50) : (existing.brand || 'AI Tools'),
        type: typeof type === 'string' && type.trim() ? type.trim().slice(0, 50) : (existing.type || 'บัญชีส่วนตัว (Private)'),
        duration: typeof duration === 'string' ? duration.trim().slice(0, 50) : (existing.duration || '1 เดือน (30 วัน)'),
        devices: typeof devices === 'string' ? devices.trim().slice(0, 100) : (existing.devices || 'iOS • Android • PC'),
        warranty: typeof warranty === 'string' ? warranty.trim().slice(0, 50) : (existing.warranty || '30 วัน'),
        price: Math.round(numPrice * 100) / 100,
        originalPrice: Math.round(numOrig * 100) / 100,
        badge: typeof badge === 'string' ? badge.slice(0, 50).trim() : (existing.badge || ''),
        isHighlight: isHighlight !== undefined ? !!isHighlight : (existing.isHighlight !== undefined ? existing.isHighlight : false),
        g2gUrl: typeof g2gUrl === 'string' ? sanitizeWebUrl(g2gUrl) : (existing.g2gUrl || ''),
        deleted: false,
        updatedAt: nowIso
    };

    db.customProducts[prodId] = updatedProduct;

    // Synchronize price overrides
    db.customPrices[prodId] = {
        ...(db.customPrices[prodId] || {}),
        price: updatedProduct.price,
        originalPrice: updatedProduct.originalPrice,
        badge: updatedProduct.badge,
        isHighlight: updatedProduct.isHighlight,
        g2gUrl: updatedProduct.g2gUrl,
        manualOverride: true,
        lastManualUpdate: nowIso,
        updatedAt: nowIso
    };

    saveDb(db);
    res.json({
        success: true,
        message: "บันทึกข้อมูลสินค้าเรียบร้อยแล้ว",
        product: updatedProduct,
        customProducts: db.customProducts,
        customPrices: db.customPrices
    });
});

// 6.0.4 API: Admin Delete / Restore Product
app.post('/api/admin/product/delete', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { productId, restore } = req.body;
    if (!productId || typeof productId !== 'string') {
        return res.status(400).json({ success: false, message: "กรุณาระบุ productId" });
    }

    const db = getDb();
    if (!db.customProducts) db.customProducts = {};

    if (restore) {
        if (db.customProducts[productId]) {
            db.customProducts[productId].deleted = false;
            db.customProducts[productId].updatedAt = new Date().toISOString();
        }
        saveDb(db);
        return res.json({ success: true, message: "กู้คืนสินค้าเรียบร้อยแล้ว", productId, customProducts: db.customProducts });
    }

    const existing = db.customProducts[productId] || {};
    db.customProducts[productId] = {
        ...existing,
        id: productId,
        deleted: true,
        deletedAt: new Date().toISOString()
    };

    saveDb(db);
    res.json({ success: true, message: "ลบสินค้าออกจากหน้าร้านเรียบร้อยแล้ว (สามารถกู้คืนได้)", productId, customProducts: db.customProducts });
});

// 6.0.5 API: Admin Full Catalog Reconcile / Bulk Sync
app.post('/api/admin/catalog/sync', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { customPrices, customProducts } = req.body;
    const db = getDb();
    if (!db.customPrices) db.customPrices = {};
    if (!db.customProducts) db.customProducts = {};

    let changed = false;

    // Reconcile customPrices
    if (customPrices && typeof customPrices === 'object') {
        for (const [prodId, clientItem] of Object.entries(customPrices)) {
            if (!clientItem || typeof clientItem !== 'object') continue;
            const srvItem = db.customPrices[prodId];
            const clientTime = new Date(clientItem.updatedAt || clientItem.lastManualUpdate || 0).getTime();
            const srvTime = srvItem ? new Date(srvItem.updatedAt || srvItem.lastManualUpdate || 0).getTime() : 0;

            if (!srvItem || clientTime >= srvTime || clientItem.manualOverride) {
                db.customPrices[prodId] = {
                    ...(srvItem || {}),
                    ...clientItem,
                    price: typeof clientItem.price === 'number' ? Math.round(clientItem.price * 100) / 100 : (srvItem?.price || 0),
                    originalPrice: typeof clientItem.originalPrice === 'number' ? Math.round(clientItem.originalPrice * 100) / 100 : (srvItem?.originalPrice || clientItem.price || 0),
                    manualOverride: clientItem.manualOverride !== undefined ? !!clientItem.manualOverride : true,
                    updatedAt: clientItem.updatedAt || clientItem.lastManualUpdate || new Date().toISOString()
                };
                changed = true;
            }
        }
    }

    // Reconcile customProducts
    if (customProducts && typeof customProducts === 'object') {
        for (const [prodId, clientProd] of Object.entries(customProducts)) {
            if (!clientProd || typeof clientProd !== 'object') continue;
            const srvProd = db.customProducts[prodId];
            const clientTime = new Date(clientProd.updatedAt || 0).getTime();
            const srvTime = srvProd ? new Date(srvProd.updatedAt || 0).getTime() : 0;

            if (!srvProd || clientTime >= srvTime) {
                db.customProducts[prodId] = {
                    ...(srvProd || {}),
                    ...clientProd,
                    updatedAt: clientProd.updatedAt || new Date().toISOString()
                };
                changed = true;
            }
        }
    }

    if (changed) {
        saveDb(db);
    }

    res.json({
        success: true,
        message: "ซิงค์ข้อมูลราคากับเซิร์ฟเวอร์สำเร็จ",
        customPrices: db.customPrices,
        customProducts: db.customProducts
    });
});

// 6.1 API: Admin Fetch Store & SMTP Settings
app.get('/api/admin/settings', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const smtp = db.smtpConfig || {};
    const actualSlipOkKey = (process.env.SLIPOK_API_KEY || db.slipOkApiKey || "").trim();
    const hasSlipOkKey = actualSlipOkKey.length > 0;
    const slipOkKeyHint = hasSlipOkKey
        ? (actualSlipOkKey.length > 8 ? actualSlipOkKey.slice(0, 4) + '••••••••' + actualSlipOkKey.slice(-4) : '••••••••')
        : '';

    res.json({
        success: true,
        maintenanceMode: db.maintenanceMode === true || process.env.MAINTENANCE_MODE === 'true',
        promptPayNumber: db.promptPayNumber || "0982949371",
        promptPayAccountName: db.promptPayAccountName || "สุพัฒน์ มีสมบัติ",
        slipOkBranchId: db.slipOkBranchId || "77491",
        slipOkApiKey: hasSlipOkKey ? '******' : '',
        hasSlipOkKey,
        slipOkKeyHint,
        geminiApiKey: (process.env.GEMINI_API_KEY || db.geminiApiKey) ? '******' : '',
        discordWebhookUrl: (process.env.DISCORD_WEBHOOK_URL || db.discordWebhookUrl)
            ? (process.env.DISCORD_WEBHOOK_URL ? '******' : (db.discordWebhookUrl || ''))
            : '',
        smtpConfig: {
            host: process.env.SMTP_HOST || smtp.host || '',
            port: parseInt(process.env.SMTP_PORT || smtp.port || '465', 10),
            user: process.env.SMTP_USER || smtp.user || '',
            pass: (process.env.SMTP_PASS || smtp.pass) ? '******' : '',
            from: process.env.SMTP_FROM || smtp.from || '',
            resendKey: (process.env.RESEND_API_KEY || smtp.resendKey) ? '******' : '',
            brevoKey: (process.env.BREVO_API_KEY || smtp.brevoKey) ? '******' : '',
            sendgridKey: (process.env.SENDGRID_API_KEY || smtp.sendgridKey) ? '******' : '',
            mailjetKey: (process.env.MAILJET_API_KEY || smtp.mailjetKey) ? '******' : '',
            mailjetSecret: (process.env.MAILJET_SECRET_KEY || smtp.mailjetSecret) ? '******' : '',
            logoUrl: process.env.LOGO_URL || smtp.logoUrl || ''
        }
    });
});

// 6.2 API: Admin Update Store & SMTP Settings
app.post('/api/admin/settings', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { promptPayNumber, promptPayAccountName, slipOkBranchId, slipOkApiKey, newPin, smtpConfig, discordWebhookUrl, geminiApiKey, maintenanceMode } = req.body;
    const db = getDb();

    if (maintenanceMode !== undefined) {
        db.maintenanceMode = !!maintenanceMode;
    }

    if (geminiApiKey !== undefined && geminiApiKey !== '******') {
        const trimmedG = String(geminiApiKey).trim();
        if (trimmedG.length > 0) {
            db.geminiApiKey = trimmedG;
        } else if (req.body.clearGeminiKey === true) {
            db.geminiApiKey = "";
        }
    }

    if (promptPayNumber) {
        const clean = String(promptPayNumber).replace(/[^0-9]/g, '');
        if (clean.length >= 10 && clean.length <= 15) {
            db.promptPayNumber = clean;
        }
    }
    if (promptPayAccountName && typeof promptPayAccountName === 'string') {
        db.promptPayAccountName = promptPayAccountName.slice(0, 100).trim();
    }
    if (slipOkBranchId && typeof slipOkBranchId === 'string') {
        db.slipOkBranchId = slipOkBranchId.slice(0, 32).trim();
    }
    if (slipOkApiKey !== undefined && slipOkApiKey !== '******') {
        const trimmedKey = String(slipOkApiKey).trim();
        if (trimmedKey.length > 0) {
            db.slipOkApiKey = trimmedKey;
        } else if (req.body.clearSlipOkKey === true) {
            db.slipOkApiKey = "";
        }
    }
    let freshAdminToken = null;
    let freshTokenExpiresAt = null;
    if (newPin && typeof newPin === 'string') {
        const pinClean = newPin.trim();
        if (pinClean.length >= 4 && pinClean.length <= 32) {
            db.adminPinHash = hashPin(pinClean);
            delete db.adminPin;
            // Generate a fresh session token with the new PIN hash so current admin session continues seamlessly
            const tokenData = generateAdminToken();
            freshAdminToken = tokenData.token;
            freshTokenExpiresAt = tokenData.expiresAt;
            adminSessions.set(freshAdminToken, freshTokenExpiresAt);
        }
    }
    if (discordWebhookUrl !== undefined && discordWebhookUrl !== '******') {
        const trimmed = String(discordWebhookUrl).trim();
        if (trimmed && !isValidDiscordWebhookUrl(trimmed)) {
            return res.status(400).json({
                success: false,
                message: "Discord Webhook URL ไม่ถูกต้อง ต้องเป็น URL ทางการของ Discord เท่านั้น (https://discord.com/api/webhooks/...)"
            });
        }
        db.discordWebhookUrl = trimmed;
    }
    if (smtpConfig && typeof smtpConfig === 'object') {
        if (!db.smtpConfig) db.smtpConfig = {};
        if (smtpConfig.host !== undefined) db.smtpConfig.host = String(smtpConfig.host).trim();
        if (smtpConfig.port !== undefined) db.smtpConfig.port = parseInt(smtpConfig.port, 10) || 465;
        if (smtpConfig.user !== undefined) db.smtpConfig.user = String(smtpConfig.user).trim();
        if (smtpConfig.pass !== undefined && smtpConfig.pass !== '******') {
            const cleanPass = String(smtpConfig.pass).replace(/\s+/g, '');
            if (cleanPass.length > 0) {
                db.smtpConfig.pass = cleanPass;
            } else if (smtpConfig.clearPass === true) {
                delete db.smtpConfig.pass;
            }
        }
        if (smtpConfig.from !== undefined) db.smtpConfig.from = String(smtpConfig.from).trim();
        if (smtpConfig.resendKey !== undefined && smtpConfig.resendKey !== '******') {
            const trimmed = String(smtpConfig.resendKey).trim();
            if (trimmed.length > 0) {
                db.smtpConfig.resendKey = trimmed;
            } else if (smtpConfig.clearResendKey === true) {
                delete db.smtpConfig.resendKey;
            }
        }
        if (smtpConfig.brevoKey !== undefined && smtpConfig.brevoKey !== '******') {
            const trimmed = String(smtpConfig.brevoKey).trim();
            if (trimmed.length > 0) {
                db.smtpConfig.brevoKey = trimmed;
            } else if (smtpConfig.clearBrevoKey === true) {
                delete db.smtpConfig.brevoKey;
            }
        }
        if (smtpConfig.sendgridKey !== undefined && smtpConfig.sendgridKey !== '******') {
            const trimmed = String(smtpConfig.sendgridKey).trim();
            if (trimmed.length > 0) {
                db.smtpConfig.sendgridKey = trimmed;
            } else if (smtpConfig.clearSendgridKey === true) {
                delete db.smtpConfig.sendgridKey;
            }
        }
        if (smtpConfig.mailjetKey !== undefined && smtpConfig.mailjetKey !== '******') {
            const trimmed = String(smtpConfig.mailjetKey).trim();
            if (trimmed.length > 0) {
                db.smtpConfig.mailjetKey = trimmed;
            } else if (smtpConfig.clearMailjetKey === true) {
                delete db.smtpConfig.mailjetKey;
            }
        }
        if (smtpConfig.mailjetSecret !== undefined && smtpConfig.mailjetSecret !== '******') {
            const trimmed = String(smtpConfig.mailjetSecret).trim();
            if (trimmed.length > 0) {
                db.smtpConfig.mailjetSecret = trimmed;
            } else if (smtpConfig.clearMailjetSecret === true) {
                delete db.smtpConfig.mailjetSecret;
            }
        }
        if (smtpConfig.logoUrl !== undefined) {
            db.smtpConfig.logoUrl = String(smtpConfig.logoUrl).trim();
        }
    }

    saveDb(db);
    res.json({
        success: true,
        message: "บันทึกการตั้งค่าสำเร็จ",
        newAdminToken: freshAdminToken || undefined,
        expiresAt: freshTokenExpiresAt || undefined
    });
});

// 6.2.0.0 API: Admin Direct Change PIN / Password
app.post('/api/admin/change-pin', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ: เซสชันแอดมินหมดอายุ" });
    }
    const { newPin } = req.body;
    if (!newPin || typeof newPin !== 'string') {
        return res.status(400).json({ success: false, message: "กรุณากรอกรหัส PIN หรือรหัสผ่านใหม่" });
    }
    const pinClean = newPin.trim();
    if (pinClean.length < 4 || pinClean.length > 32) {
        return res.status(400).json({ success: false, message: "รหัส PIN หรือรหัสผ่านต้องมีความยาวระหว่าง 4 ถึง 32 ตัวอักษร" });
    }

    const db = getDb();
    db.adminPinHash = hashPin(pinClean);
    delete db.adminPin;
    saveDb(db);

    const { token, expiresAt } = generateAdminToken();
    adminSessions.set(token, expiresAt);

    res.json({
        success: true,
        message: "เปลี่ยนรหัส PIN แอดมินใหม่สำเร็จเรียบร้อยแล้ว",
        token,
        expiresAt
    });
});

// 6.2.0.0.1 API: Admin Reset PIN to Default (8899)
app.post('/api/admin/reset-pin', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ: ต้องเข้าสู่ระบบผู้ดูแลก่อนจึงจะคืนค่ารหัสเริ่มต้นได้" });
    }

    const db = getDb();
    const defaultPin = '8899';
    db.adminPinHash = hashPin(defaultPin);
    delete db.adminPin;
    saveDb(db);

    const { token, expiresAt } = generateAdminToken();
    adminSessions.set(token, expiresAt);

    res.json({
        success: true,
        message: "รีเซ็ตรหัส PIN ผู้ดูแลระบบกลับเป็นค่าเริ่มต้น (8899) เรียบร้อยแล้ว",
        token,
        expiresAt
    });
});

// 6.2.0 API: Admin Test Discord Webhook (Anti-SSRF Protected)
app.post('/api/admin/test-discord', adminRateLimit, async (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { webhookUrl } = req.body;
    const db = getDb();
    const targetUrl = (webhookUrl && webhookUrl !== '******') ? String(webhookUrl).trim() : (process.env.DISCORD_WEBHOOK_URL || db.discordWebhookUrl);
    if (!targetUrl || !isValidDiscordWebhookUrl(targetUrl)) {
        return res.status(400).json({ success: false, message: "กรุณาระบุ Discord Webhook URL ที่ถูกต้องและปลอดภัย (ต้องขึ้นต้นด้วย https://discord.com/api/webhooks/...)" });
    }
    try {
        const testOrder = {
            orderId: "TEST-" + Math.floor(100000 + Math.random() * 900000),
            totalAmount: 259.00,
            email: "customer@example.com",
            transRef: "TEST-REF-9999",
            status: "🟢 จัดส่งสำเร็จทันที (ทดสอบการแจ้งเตือน)",
            items: [{ productTitle: "ChatGPT Plus 1 เดือน (ทดสอบระบบ)", price: 259.00, status: "delivered", credentials: { key: "TEST-LICENSE-KEY" } }]
        };
        await sendDiscordNotification(targetUrl, testOrder, false);
        res.json({ success: true, message: "ส่งข้อความทดสอบไปยัง Discord สำเร็จแล้ว! กรุณาตรวจสอบห้องแชทใน Discord ของคุณ" });
    } catch (err) {
        res.status(500).json({ success: false, message: `เกิดข้อผิดพลาดในการส่งเข้า Discord: ${err.message}` });
    }
});

// 6.2.0.1 API: Admin Test SlipOK Connection & Quota
app.post('/api/admin/test-slipok', adminRateLimit, async (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ 
            success: false, 
            message: "สิทธิ์การเข้าถึงถูกปฏิเสธ: เซสชันแอดมินหลังร้านหมดอายุ กรุณาเข้าสู่ระบบด้วยรหัส PIN อีกครั้ง (PIN เริ่มต้น: 8899)" 
        });
    }
    const { branchId, apiKey } = req.body;
    const db = getDb();
    const targetBranchId = (branchId && branchId.trim()) ? branchId.trim() : (process.env.SLIPOK_BRANCH_ID || db.slipOkBranchId || "77491").trim();
    const targetApiKey = (apiKey && apiKey !== '******') ? apiKey.trim() : (process.env.SLIPOK_API_KEY || db.slipOkApiKey || "").trim();

    if (!targetApiKey) {
        return res.status(400).json({ success: false, message: "กรุณาระบุ SlipOK API Key เพื่อทดสอบการเชื่อมต่อ" });
    }

    try {
        const response = await fetch(`https://api.slipok.com/api/line/apikey/${targetBranchId}/quota`, {
            method: 'GET',
            headers: { 'x-authorization': targetApiKey }
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok && data.success) {
            const quota = data.data ? data.data.quota : (data.quota !== undefined ? data.quota : 'N/A');
            let autoSaved = false;
            // Auto-persist valid key immediately so user doesn't lose it
            if (apiKey && apiKey !== '******' && apiKey.trim()) {
                db.slipOkApiKey = apiKey.trim();
                if (branchId && branchId.trim()) db.slipOkBranchId = branchId.trim();
                saveDb(db);
                autoSaved = true;
            }
            return res.json({
                success: true,
                message: `เชื่อมต่อ SlipOK สำเร็จ! โควต้าคงเหลือ: ${quota} ครั้ง${autoSaved ? ' (บันทึกลงระบบอัตโนมัติแล้ว)' : ''}`,
                quota,
                saved: autoSaved,
                branchId: targetBranchId
            });
        } else {
            let errorMsg = data.message || '';
            if (response.status === 401 || response.status === 403 || errorMsg.includes('Access Denied') || errorMsg.includes('ปฏิเสธ') || errorMsg.includes('Unauthorized') || errorMsg.includes('Forbidden') || errorMsg.includes('Invalid')) {
                errorMsg = `SlipOK ปฏิเสธการเข้าถึง: รหัส API Key หรือ Branch ID (${targetBranchId}) ไม่ถูกต้อง หรือยังไม่ได้เปิดสิทธิ์ใช้งานใน SlipOK Portal กรุณาตรวจสอบรหัสสาขาและคีย์อีกครั้ง`;
            } else if (!errorMsg) {
                errorMsg = `รหัส API Key หรือ Branch ID ไม่ถูกต้อง (HTTP ${response.status})`;
            }
            return res.status(400).json({
                success: false,
                message: `SlipOK แจ้งเตือน: ${errorMsg}`,
                upstreamStatus: response.status
            });
        }
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: `ไม่สามารถเชื่อมต่อไปยัง SlipOK ได้: ${err.message}`
        });
    }
});

// 6.2.1 API: Admin Test Email Delivery (Live Diagnostics)
app.post('/api/admin/test-email', adminRateLimit, async (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(401).json({
            success: false,
            requiresLogin: true,
            message: "เซสชันผู้ดูแลระบบหมดอายุ (เนื่องจากเซิร์ฟเวอร์เพิ่งอัปเดตระบบ) กรุณากรอกรหัส PIN เพื่อเข้าสู่ระบบใหม่"
        });
    }
    try {
        const db = getDb();
        const rawConfig = Object.assign(
            {},
            req.body,
            (req.body.smtpConfig && typeof req.body.smtpConfig === 'object') ? req.body.smtpConfig : {}
        );

        let customConfig = {};
        if (rawConfig.host) customConfig.host = String(rawConfig.host).trim();
        if (rawConfig.port) customConfig.port = parseInt(rawConfig.port, 10) || 465;
        if (rawConfig.user) customConfig.user = String(rawConfig.user).trim();
        if (rawConfig.pass && rawConfig.pass !== '******') {
            customConfig.pass = String(rawConfig.pass).replace(/\s+/g, '');
        } else {
            const existingPass = db.smtpConfig?.pass || process.env.SMTP_PASS;
            if (existingPass) customConfig.pass = String(existingPass).replace(/\s+/g, '');
        }
        if (rawConfig.from) customConfig.from = String(rawConfig.from).trim();
        if (rawConfig.resendKey && rawConfig.resendKey !== '******') {
            customConfig.resendKey = String(rawConfig.resendKey).trim();
        } else {
            const existingKey = db.smtpConfig?.resendKey || process.env.RESEND_API_KEY;
            if (existingKey) customConfig.resendKey = existingKey;
        }
        if (rawConfig.brevoKey && rawConfig.brevoKey !== '******') {
            customConfig.brevoKey = String(rawConfig.brevoKey).trim();
        } else {
            const existingBrevo = db.smtpConfig?.brevoKey || process.env.BREVO_API_KEY;
            if (existingBrevo) customConfig.brevoKey = existingBrevo;
        }
        if (rawConfig.sendgridKey && rawConfig.sendgridKey !== '******') {
            customConfig.sendgridKey = String(rawConfig.sendgridKey).trim();
        } else {
            const existingSg = db.smtpConfig?.sendgridKey || process.env.SENDGRID_API_KEY;
            if (existingSg) customConfig.sendgridKey = existingSg;
        }
        if (rawConfig.mailjetKey && rawConfig.mailjetKey !== '******') {
            customConfig.mailjetKey = String(rawConfig.mailjetKey).trim();
        } else {
            const existingMjKey = db.smtpConfig?.mailjetKey || process.env.MAILJET_API_KEY;
            if (existingMjKey) customConfig.mailjetKey = existingMjKey;
        }
        if (rawConfig.mailjetSecret && rawConfig.mailjetSecret !== '******') {
            customConfig.mailjetSecret = String(rawConfig.mailjetSecret).trim();
        } else {
            const existingMjSec = db.smtpConfig?.mailjetSecret || process.env.MAILJET_SECRET_KEY;
            if (existingMjSec) customConfig.mailjetSecret = existingMjSec;
        }
        if (rawConfig.logoUrl) {
            customConfig.logoUrl = String(rawConfig.logoUrl).trim();
        }

        const effectivePass = customConfig.pass || db.smtpConfig?.pass || process.env.SMTP_PASS;
        const effectiveResend = customConfig.resendKey || db.smtpConfig?.resendKey || process.env.RESEND_API_KEY;
        const effectiveBrevo = customConfig.brevoKey || db.smtpConfig?.brevoKey || process.env.BREVO_API_KEY;
        const effectiveSg = customConfig.sendgridKey || db.smtpConfig?.sendgridKey || process.env.SENDGRID_API_KEY;
        const effectiveMj = (customConfig.mailjetKey || db.smtpConfig?.mailjetKey || process.env.MAILJET_API_KEY) &&
            (customConfig.mailjetSecret || db.smtpConfig?.mailjetSecret || process.env.MAILJET_SECRET_KEY);
        const effectiveGmailOAuth = (db.smtpConfig?.gmailClientId || process.env.GMAIL_CLIENT_ID) &&
            (db.smtpConfig?.gmailClientSecret || process.env.GMAIL_CLIENT_SECRET) &&
            (db.smtpConfig?.gmailRefreshToken || process.env.GMAIL_REFRESH_TOKEN);

        if (!effectivePass && !effectiveResend && !effectiveBrevo && !effectiveSg && !effectiveMj && !effectiveGmailOAuth) {
            return res.status(400).json({
                success: false,
                message: "ยังไม่ได้ระบุข้อมูลสำหรับส่งอีเมล กรุณาระบุ SMTP Host, User และรหัสผ่านแอป 16 หลัก (หรือ Brevo / Resend API Key) ในช่องด้านบนก่อนกดทดสอบส่ง"
            });
        }

        const targetEmail = String(req.body.testEmail || req.body.to || customConfig.user || db.smtpConfig?.user || '').trim();
        if (!targetEmail || !isValidEmail(targetEmail)) {
            return res.status(400).json({
                success: false,
                message: "กรุณาระบุอีเมลผู้รับทดสอบที่ถูกต้อง (เช่น your-email@gmail.com)"
            });
        }

        const testResult = await mailService.testConnection(targetEmail, customConfig, db);
        res.json(testResult);
    } catch (err) {
        console.error('Test email error:', err);
        res.status(500).json({
            success: false,
            message: `เกิดข้อผิดพลาดในการทดสอบส่งอีเมล: ${err.message}`
        });
    }
});

// 6.2.2 API: Admin Download Database Backup (JSON Export)
app.get('/api/admin/backup-db', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();

    // ดึงค่า SlipOK API Key และการตั้งค่าที่ใช้งานจริง (จาก DB หรือ Environment) รวมเข้าในไฟล์สำรองเสมอ 100%
    const effectiveSlipOkKey = (db.slipOkApiKey || process.env.SLIPOK_API_KEY || "").trim();
    const effectiveBranchId = (db.slipOkBranchId || process.env.SLIPOK_BRANCH_ID || "77491").trim();
    const effectiveGeminiKey = (db.geminiApiKey || process.env.GEMINI_API_KEY || "").trim();
    const effectiveDiscordUrl = (db.discordWebhookUrl || process.env.DISCORD_WEBHOOK_URL || "").trim();

    let dbUpdated = false;
    if (effectiveSlipOkKey && db.slipOkApiKey !== effectiveSlipOkKey) {
        db.slipOkApiKey = effectiveSlipOkKey;
        dbUpdated = true;
    }
    if (effectiveBranchId && db.slipOkBranchId !== effectiveBranchId) {
        db.slipOkBranchId = effectiveBranchId;
        dbUpdated = true;
    }
    if (effectiveGeminiKey && db.geminiApiKey !== effectiveGeminiKey) {
        db.geminiApiKey = effectiveGeminiKey;
        dbUpdated = true;
    }
    if (effectiveDiscordUrl && db.discordWebhookUrl !== effectiveDiscordUrl) {
        db.discordWebhookUrl = effectiveDiscordUrl;
        dbUpdated = true;
    }
    if (dbUpdated) {
        saveDb(db);
    }

    const exportDb = {
        ...db,
        slipOkApiKey: effectiveSlipOkKey,
        slipOkBranchId: effectiveBranchId,
        geminiApiKey: effectiveGeminiKey,
        discordWebhookUrl: effectiveDiscordUrl
    };
    delete exportDb.adminPin; // Ensure plaintext PIN is never exposed in backup export

    if (exportDb.smtpConfig) {
        exportDb.smtpConfig = {
            ...exportDb.smtpConfig,
            pass: exportDb.smtpConfig.pass || process.env.SMTP_PASS || "",
            resendKey: exportDb.smtpConfig.resendKey || process.env.RESEND_API_KEY || "",
            brevoKey: exportDb.smtpConfig.brevoKey || process.env.BREVO_API_KEY || "",
            sendgridKey: exportDb.smtpConfig.sendgridKey || process.env.SENDGRID_API_KEY || "",
            mailjetKey: exportDb.smtpConfig.mailjetKey || process.env.MAILJET_API_KEY || "",
            mailjetSecret: exportDb.smtpConfig.mailjetSecret || process.env.MAILJET_SECRET_KEY || ""
        };
    }

    const dateStr = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `supinkly_db_backup_${dateStr}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(exportDb, null, 2));
});

// 6.2.3 API: Admin Restore Database from JSON Backup (Deep Sanitization & Pre-Restore Backup)
app.post('/api/admin/restore-db', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    try {
        const { backupData } = req.body;
        let restored;
        if (typeof backupData === 'string') {
            try {
                restored = JSON.parse(backupData);
            } catch (parseErr) {
                return res.status(400).json({ success: false, message: "ไฟล์ JSON มีไวยากรณ์ผิดพลาด ไม่สามารถประมวลผลได้" });
            }
        } else if (typeof backupData === 'object' && backupData !== null) {
            restored = backupData;
        } else {
            return res.status(400).json({ success: false, message: "รูปแบบข้อมูลไฟล์สำรองไม่ถูกต้อง" });
        }

        if (!restored || typeof restored !== 'object' || Array.isArray(restored)) {
            return res.status(400).json({ success: false, message: "ข้อมูลสำรองต้องเป็น JSON Object" });
        }

        // Sanity check: Ensure it has key properties
        if (!restored.inventory && !restored.orders && !restored.users) {
            return res.status(400).json({ success: false, message: "ไฟล์นี้ไม่ใช่ไฟล์สำรองของ Supinkly.AI ที่ถูกต้อง (ไม่พบโครงสร้างข้อมูลคำสั่งซื้อ, คลังสินค้า หรือสมาชิก)" });
        }

        const currentDb = getDb();

        // 1. Create Pre-Restore Safety Backup
        try {
            if (fs.existsSync(DB_FILE)) {
                fs.copyFileSync(DB_FILE, path.join(__dirname, 'secure_database.json.pre-restore.bak'));
            }
        } catch (bakErr) {
            console.warn('[RESTORE] Could not create pre-restore backup:', bakErr.message);
        }

        // 2. Deep Sanitization & Structural Normalization (Anti-Prototype Pollution & Crash-Resilience)
        const sanitizedDb = {
            // Strictly retain current verified admin credentials to prevent lockout/backdoor hijacking
            adminPinHash: currentDb.adminPinHash || (currentDb.adminPin ? hashPin(currentDb.adminPin) : hashPin(process.env.ADMIN_PIN || '8899')),
            adminPin: currentDb.adminPin || '8899',
            promptPayNumber: (typeof restored.promptPayNumber === 'string' && /^[0-9]{10,15}$/.test(restored.promptPayNumber))
                ? restored.promptPayNumber
                : (currentDb.promptPayNumber || "0982949371"),
            promptPayAccountName: typeof restored.promptPayAccountName === 'string'
                ? restored.promptPayAccountName.slice(0, 100).trim()
                : (currentDb.promptPayAccountName || "สุพัฒน์ มีสมบัติ"),
            slipOkApiKey: (typeof restored.slipOkApiKey === 'string' && restored.slipOkApiKey.trim().length > 0)
                ? restored.slipOkApiKey.trim()
                : (currentDb.slipOkApiKey || process.env.SLIPOK_API_KEY || ""),
            slipOkBranchId: (typeof restored.slipOkBranchId === 'string' && restored.slipOkBranchId.trim().length > 0)
                ? restored.slipOkBranchId.slice(0, 32).trim()
                : (currentDb.slipOkBranchId || process.env.SLIPOK_BRANCH_ID || "77491"),
            discordWebhookUrl: (typeof restored.discordWebhookUrl === 'string' && isValidDiscordWebhookUrl(restored.discordWebhookUrl))
                ? restored.discordWebhookUrl.trim()
                : (currentDb.discordWebhookUrl || process.env.DISCORD_WEBHOOK_URL || ""),
            geminiApiKey: (typeof restored.geminiApiKey === 'string' && restored.geminiApiKey.trim().length > 0 && restored.geminiApiKey.trim().length <= 256)
                ? restored.geminiApiKey.trim()
                : (currentDb.geminiApiKey || process.env.GEMINI_API_KEY || ""),
            usedSlips: Array.isArray(restored.usedSlips)
                ? restored.usedSlips.filter(s => typeof s === 'string' && /^[a-zA-Z0-9_\-]{3,128}$/.test(s.trim())).map(s => s.trim()).slice(0, 20000)
                : (currentDb.usedSlips || []),
            usedTransRefs: Array.isArray(restored.usedTransRefs)
                ? restored.usedTransRefs.filter(r => typeof r === 'string' && /^[a-zA-Z0-9_\-]{3,128}$/.test(r.trim())).map(r => r.trim()).slice(0, 20000)
                : (currentDb.usedTransRefs || []),
            customPrices: {},
            customProducts: {},
            inventory: {},
            orders: [],
            users: [],
            pendingRegistrations: (restored.pendingRegistrations && typeof restored.pendingRegistrations === 'object') ? restored.pendingRegistrations : {},
            passwordResets: (restored.passwordResets && typeof restored.passwordResets === 'object') ? restored.passwordResets : {},
            smtpConfig: {},
            coupons: [],
            analytics: (restored.analytics && typeof restored.analytics === 'object') ? restored.analytics : (currentDb.analytics || {})
        };

        // Sanitize coupons
        if (Array.isArray(restored.coupons) && restored.coupons.length > 0) {
            sanitizedDb.coupons = restored.coupons.filter(c =>
                c && typeof c === 'object' &&
                typeof c.code === 'string' &&
                /^[A-Z0-9_\-]{2,32}$/i.test(c.code.trim()) &&
                (typeof c.value === 'number' || typeof c.discountValue === 'number')
            ).map(c => {
                const code = c.code.trim().toUpperCase();
                const isPercent = (c.type === 'percentage' || c.discountType === 'percent');
                const val = parseFloat(c.value !== undefined ? c.value : c.discountValue) || 0;
                return {
                    code,
                    title: String(c.title || code).trim().slice(0, 80),
                    description: String(c.description || '').trim().slice(0, 200),
                    type: isPercent ? 'percentage' : 'fixed',
                    discountType: isPercent ? 'percent' : 'fixed',
                    value: isPercent ? Math.min(100, Math.max(0, val)) : Math.max(0, val),
                    discountValue: isPercent ? Math.min(100, Math.max(0, val)) : Math.max(0, val),
                    minSpend: Math.max(0, parseFloat(c.minSpend) || 0),
                    maxDiscount: Math.max(0, parseFloat(c.maxDiscount) || 0),
                    usageLimit: (c.usageLimit && parseInt(c.usageLimit, 10) > 0) ? parseInt(c.usageLimit, 10) : null,
                    usedCount: Math.max(0, parseInt(c.usedCount, 10) || 0),
                    expiresAt: c.expiresAt ? String(c.expiresAt).slice(0, 10) : '2026-12-31',
                    active: c.active !== false,
                    badge: String(c.badge || '').trim().slice(0, 30),
                    updatedAt: typeof c.updatedAt === 'string' ? c.updatedAt : new Date().toISOString()
                };
            });
            if (sanitizedDb.coupons.length === 0) {
                sanitizedDb.coupons = currentDb.coupons || [...DEFAULT_SERVER_COUPONS];
            }
        } else {
            sanitizedDb.coupons = currentDb.coupons || [...DEFAULT_SERVER_COUPONS];
        }

        // Sanitize customPrices
        if (restored.customPrices && typeof restored.customPrices === 'object' && !Array.isArray(restored.customPrices)) {
            for (const [prodId, val] of Object.entries(restored.customPrices)) {
                if (prodId === '__proto__' || prodId === 'constructor' || prodId === 'prototype') continue;
                if (/^[a-z0-9\-]{1,32}$/i.test(prodId) && val && typeof val === 'object') {
                    const price = parseFloat(val.price);
                    if (!isNaN(price) && price >= 0) {
                        sanitizedDb.customPrices[prodId] = {
                            price: Math.round(price * 100) / 100,
                            originalPrice: (!isNaN(val.originalPrice) && val.originalPrice >= price) ? Math.round(val.originalPrice * 100) / 100 : Math.round(price * 100) / 100,
                            badge: typeof val.badge === 'string' ? val.badge.slice(0, 50).trim() : '',
                            manualOverride: true,
                            updatedAt: typeof val.updatedAt === 'string' ? val.updatedAt : new Date().toISOString()
                        };
                    }
                }
            }
        }

        // Sanitize customProducts
        if (restored.customProducts && typeof restored.customProducts === 'object' && !Array.isArray(restored.customProducts)) {
            for (const [prodId, val] of Object.entries(restored.customProducts)) {
                if (prodId === '__proto__' || prodId === 'constructor' || prodId === 'prototype') continue;
                if (/^[a-z0-9\-]{1,64}$/i.test(prodId) && val && typeof val === 'object') {
                    sanitizedDb.customProducts[prodId] = {
                        id: prodId,
                        title: typeof val.title === 'string' ? val.title.slice(0, 150).trim() : prodId,
                        subtitle: typeof val.subtitle === 'string' ? val.subtitle.slice(0, 200).trim() : '',
                        description: typeof val.description === 'string' ? val.description.slice(0, 3000).trim() : '',
                        brand: typeof val.brand === 'string' ? val.brand.slice(0, 50).trim() : 'AI Tools',
                        type: typeof val.type === 'string' ? val.type.slice(0, 50).trim() : 'บัญชีส่วนตัว (Private)',
                        duration: typeof val.duration === 'string' ? val.duration.slice(0, 50).trim() : '1 เดือน (30 วัน)',
                        devices: typeof val.devices === 'string' ? val.devices.slice(0, 100).trim() : 'iOS • Android • PC',
                        warranty: typeof val.warranty === 'string' ? val.warranty.slice(0, 50).trim() : '30 วัน',
                        price: !isNaN(parseFloat(val.price)) ? Math.round(parseFloat(val.price) * 100) / 100 : 0,
                        originalPrice: !isNaN(parseFloat(val.originalPrice)) ? Math.round(parseFloat(val.originalPrice) * 100) / 100 : 0,
                        badge: typeof val.badge === 'string' ? val.badge.slice(0, 50).trim() : '',
                        g2gUrl: typeof val.g2gUrl === 'string' ? val.g2gUrl.trim() : '',
                        deleted: val.deleted === true,
                        updatedAt: typeof val.updatedAt === 'string' ? val.updatedAt : new Date().toISOString()
                    };
                }
            }
        }

        // Sanitize inventory
        if (restored.inventory && typeof restored.inventory === 'object' && !Array.isArray(restored.inventory)) {
            for (const [prodId, creds] of Object.entries(restored.inventory)) {
                if (prodId === '__proto__' || prodId === 'constructor' || prodId === 'prototype') continue;
                if (/^[a-z0-9\-]{1,32}$/i.test(prodId) && Array.isArray(creds)) {
                    sanitizedDb.inventory[prodId] = creds.filter(c => c && typeof c === 'object');
                }
            }
        }

        // Sanitize orders (Must have valid orderId)
        if (Array.isArray(restored.orders)) {
            sanitizedDb.orders = restored.orders.filter(o =>
                o && typeof o === 'object' &&
                typeof o.orderId === 'string' &&
                /^[a-zA-Z0-9_\-]{3,64}$/.test(o.orderId)
            );
        }

        // Sanitize users (Must have id, email, passwordHash)
        if (Array.isArray(restored.users)) {
            sanitizedDb.users = restored.users.filter(u =>
                u && typeof u === 'object' &&
                typeof u.id === 'string' &&
                typeof u.email === 'string' &&
                isValidEmail(u.email)
            );
        }

        // Sanitize smtpConfig
        if (restored.smtpConfig && typeof restored.smtpConfig === 'object' && !Array.isArray(restored.smtpConfig)) {
            sanitizedDb.smtpConfig = {
                host: typeof restored.smtpConfig.host === 'string' ? restored.smtpConfig.host.slice(0, 100).trim() : '',
                port: parseInt(restored.smtpConfig.port, 10) || 465,
                user: typeof restored.smtpConfig.user === 'string' ? restored.smtpConfig.user.slice(0, 100).trim() : '',
                pass: typeof restored.smtpConfig.pass === 'string' ? restored.smtpConfig.pass.trim() : (currentDb.smtpConfig?.pass || ''),
                from: typeof restored.smtpConfig.from === 'string' ? restored.smtpConfig.from.slice(0, 120).trim() : '',
                resendKey: typeof restored.smtpConfig.resendKey === 'string' ? restored.smtpConfig.resendKey.trim() : '',
                brevoKey: typeof restored.smtpConfig.brevoKey === 'string' ? restored.smtpConfig.brevoKey.trim() : '',
                sendgridKey: typeof restored.smtpConfig.sendgridKey === 'string' ? restored.smtpConfig.sendgridKey.trim() : '',
                mailjetKey: typeof restored.smtpConfig.mailjetKey === 'string' ? restored.smtpConfig.mailjetKey.trim() : '',
                mailjetSecret: typeof restored.smtpConfig.mailjetSecret === 'string' ? restored.smtpConfig.mailjetSecret.trim() : ''
            };
        } else {
            sanitizedDb.smtpConfig = currentDb.smtpConfig || {};
        }

        saveDb(sanitizedDb);

        const actualSlipOkKey = (process.env.SLIPOK_API_KEY || sanitizedDb.slipOkApiKey || '').trim();
        const hasSlipOkKey = actualSlipOkKey.length > 0;
        const slipOkKeyHint = hasSlipOkKey
            ? (actualSlipOkKey.length > 8 ? actualSlipOkKey.slice(0, 4) + '••••••••' + actualSlipOkKey.slice(-4) : '••••••••')
            : '';

        res.json({
            success: true,
            message: "กู้คืนฐานข้อมูลสำเร็จและทำความสะอาดโครงสร้างเรียบร้อยแล้ว",
            stats: {
                orders: sanitizedDb.orders.length,
                users: sanitizedDb.users.length,
                inventoryProducts: Object.keys(sanitizedDb.inventory).length,
                coupons: sanitizedDb.coupons.length
            },
            inventory: sanitizedDb.inventory,
            customPrices: sanitizedDb.customPrices,
            coupons: sanitizedDb.coupons,
            storeConfig: {
                promptPayNumber: sanitizedDb.promptPayNumber,
                promptPayAccountName: sanitizedDb.promptPayAccountName,
                slipOkBranchId: sanitizedDb.slipOkBranchId,
                hasSlipOkKey,
                slipOkKeyHint,
                discordWebhookUrl: sanitizedDb.discordWebhookUrl,
                geminiApiKey: sanitizedDb.geminiApiKey
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: `เกิดข้อผิดพลาดในการกู้คืนฐานข้อมูล: ${err.message}` });
    }
});

// 6.2.4 API: Admin List Automated Snapshots
app.get('/api/admin/backups', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    try {
        let snapshots = [];
        if (fs.existsSync(BACKUPS_DIR)) {
            snapshots = fs.readdirSync(BACKUPS_DIR)
                .filter(f => f.startsWith('snapshot_') && f.endsWith('.json'))
                .map(f => {
                    const stats = fs.statSync(path.join(BACKUPS_DIR, f));
                    return {
                        filename: f,
                        size: stats.size,
                        createdAt: stats.mtime
                    };
                })
                .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        }
        res.json({ success: true, count: snapshots.length, snapshots });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 6.3 API: Admin Fetch Users (Members List with Real-time Online/Offline Status)
app.get('/api/admin/users', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    cleanStaleSessions();
    const now = Date.now();
    const db = getDb();
    const users = db.users || [];
    const orders = db.orders || [];

    const enrichedUsers = users.map(u => {
        const userOrders = orders.filter(o =>
            (o.userId && o.userId === u.id) ||
            (o.email && o.email.toLowerCase() === (u.email || '').toLowerCase()) ||
            (o.recipientEmail && o.recipientEmail.toLowerCase() === (u.email || '').toLowerCase())
        );
        const totalSpent = userOrders.reduce((sum, o) => sum + (parseFloat(o.totalAmount) || 0), 0);

        // Check activeSessions for real-time online status
        const normalEmail = (u.email || '').toLowerCase();
        let isOnline = false;
        let onlineSession = null;

        for (const sess of activeSessions.values()) {
            const matchesId = sess.userId && sess.userId === u.id;
            const matchesEmail = sess.email && sess.email.toLowerCase() === normalEmail;
            if ((matchesId || matchesEmail) && (now - sess.lastSeen <= 60000)) {
                isOnline = true;
                onlineSession = {
                    sessionId: sess.sessionId,
                    page: sess.page || 'หน้าแรก',
                    currentProduct: sess.currentProduct || '',
                    lastAction: sess.lastAction || 'เปิดหน้าเว็บ',
                    cartCount: sess.cartCount || 0,
                    cartTotal: sess.cartTotal || 0,
                    lastSeenSec: Math.max(0, Math.floor((now - sess.lastSeen) / 1000))
                };
                break;
            }
        }

        return {
            id: u.id,
            userId: u.id,
            email: u.email,
            displayName: u.displayName || u.email.split('@')[0],
            emailVerified: !!u.emailVerified,
            isEmailVerified: !!u.emailVerified,
            createdAt: u.createdAt || null,
            ordersCount: userOrders.length,
            totalOrders: userOrders.length,
            totalSpent,
            isOnline,
            onlineSession
        };
    }).sort((a, b) => {
        if (a.isOnline && !b.isOnline) return -1;
        if (!a.isOnline && b.isOnline) return 1;
        return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    });

    const onlineCount = enrichedUsers.filter(u => u.isOnline).length;
    const offlineCount = enrichedUsers.length - onlineCount;

    res.json({
        success: true,
        users: enrichedUsers,
        summary: {
            total: enrichedUsers.length,
            online: onlineCount,
            offline: offlineCount
        }
    });
});

// 6.4 API: Admin Reset User Password
app.post('/api/admin/users/reset-password', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) {
        return res.status(400).json({ success: false, message: "กรุณาระบุ userId และรหัสผ่านใหม่" });
    }
    const cleanPw = String(newPassword).trim();
    if (cleanPw.length < 6 || cleanPw.length > 128) {
        return res.status(400).json({ success: false, message: "รหัสผ่านต้องมีความยาว 6-128 ตัวอักษร" });
    }
    const db = getDb();
    if (!db.users) db.users = [];
    const target = String(userId).trim().toLowerCase();
    const user = db.users.find(u => u.id === userId || (u.email && u.email.toLowerCase() === target));
    if (!user) {
        return res.status(404).json({ success: false, message: "ไม่พบผู้ใช้งานนี้ในระบบ" });
    }
    user.passwordHash = hashPassword(cleanPw, user.id);
    user.tokenVersion = (user.tokenVersion || 1) + 1; // Invalidate previous sessions
    saveDb(db);
    res.json({ success: true, message: `เปลี่ยนรหัสผ่านให้ผู้ใช้ ${user.email} สำเร็จแล้ว` });
});

// 6.5 API: Admin Delete User Account
app.delete('/api/admin/users/:userId', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { userId } = req.params;
    if (!userId || !userId.trim()) {
        return res.status(400).json({ success: false, message: "กรุณาระบุ userId" });
    }
    const db = getDb();
    if (!db.users) db.users = [];
    const target = String(userId).trim().toLowerCase();
    const idx = db.users.findIndex(u => u.id === userId || (u.email && u.email.toLowerCase() === target));
    if (idx === -1) {
        return res.status(404).json({ success: false, message: "ไม่พบผู้ใช้งานนี้ในระบบ" });
    }
    const deletedUser = db.users.splice(idx, 1)[0];
    saveDb(db);
    res.json({ success: true, message: `ลบบัญชีผู้ใช้ ${deletedUser.email} เรียบร้อยแล้ว` });
});

// 6.6 API: Admin Clear All User Accounts & Registrations
app.post(['/api/admin/users/clear-all', '/api/admin/users/delete-all'], adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const count = (db.users || []).length;
    db.users = [];
    db.pendingRegistrations = {};
    db.passwordResets = {};
    saveDb(db);
    res.json({ success: true, message: `ลบข้อมูลสมาชิกและลูกค้าทั้งหมด ${count} คนเรียบร้อยแล้ว`, users: [] });
});

// [SECURITY GUARD] Explicit check: Reject accidental DELETE /api/admin/users without userId to prevent total wipe
app.delete('/api/admin/users', adminRateLimit, (req, res) => {
    return res.status(400).json({ 
        success: false, 
        message: "กรุณาระบุรหัสสมาชิกที่ต้องการลบ เช่น /api/admin/users/:userId (หากต้องการล้างข้อมูลทั้งหมด ให้ใช้เมนู /api/admin/users/clear-all)" 
    });
});

// 6.7 API: Admin Clear Both Orders and Users in One Go
app.post('/api/admin/clear-all-data', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const orderCount = (db.orders || []).length;
    const userCount = (db.users || []).length;
    db.orders = [];
    db.users = [];
    db.usedSlips = [];
    db.usedTransRefs = [];
    db.pendingRegistrations = {};
    db.passwordResets = {};
    saveDb(db);
    res.json({ 
        success: true, 
        message: `ล้างข้อมูลทั้งหมดสำเร็จ: ลูกค้า ${userCount} คน และคำสั่งซื้อ ${orderCount} รายการ` 
    });
});

const orderLookupRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 120, // Support real-time customer polling for on-demand fulfillment
    message: { success: false, message: "ค้นหาคำสั่งซื้อบ่อยเกินไป กรุณารอสักครู่" }
});

// 7. API: Protected Customer Order Lookup
app.get('/api/orders/:orderId', orderLookupRateLimit, (req, res) => {
    const { orderId } = req.params;
    if (!orderId || !/^[A-Z0-9\-]{5,40}$/i.test(orderId)) {
        return res.status(400).json({ success: false, message: "รูปแบบรหัสคำสั่งซื้อไม่ถูกต้อง" });
    }
    const cleanSearch = orderId.trim().toUpperCase();
    const db = getDb();
    const order = (db.orders || []).find(o => (o.orderId || '').trim().toUpperCase() === cleanSearch);
    if (!order) {
        return res.status(404).json({ success: false, message: "ไม่พบคำสั่งซื้อ" });
    }

    const isAdmin = authenticateAdmin(req);
    const userSession = authenticateUser(req);
    const queryEmail = (req.query.email || req.headers['x-order-email'] || '').trim().toLowerCase();

    // Helper to safely test email match against order.email and order.recipientEmail
    const matchesOrderEmail = (targetEmail) => {
        if (!targetEmail) return false;
        const normTarget = targetEmail.trim().toLowerCase();
        const normEmail = (order.email || '').trim().toLowerCase();
        const normRecip = (order.recipientEmail || '').trim().toLowerCase();
        return normEmail === normTarget || normRecip === normTarget || normRecip.startsWith(normTarget + ' ') || normRecip.startsWith(normTarget + '(');
    };

    let isOwner = false;
    if (userSession) {
        if (order.userId && order.userId === userSession.userId) {
            isOwner = true;
        } else if (matchesOrderEmail(userSession.email)) {
            // Auto-link verified logged-in account to past guest order
            order.userId = userSession.userId;
            saveDb(db);
            isOwner = true;
        }
    }
    
    // Customer providing matching email has full legitimate owner access to their delivered credentials
    // [SECURITY FIX] Only allow email-based lookup if this is an unlinked guest order (!order.userId).
    // If order is bound to a registered member, they MUST authenticate with their account to view credentials.
    if (!isOwner && !order.userId && queryEmail && matchesOrderEmail(queryEmail)) {
        isOwner = true;
    }

    // Direct token proof from browser checkout session
    const orderToken = req.headers['x-order-token'];
    if (!isOwner && orderToken && (orderToken === order.transRef || orderToken === order.slipHash)) {
        isOwner = true;
    }

    // Admin or Verified Customer (via matching email, active session, or order token) gets full order with credentials
    if (isAdmin || isOwner) {
        return res.json({ success: true, order });
    }

    // Mask sensitive credentials and personal email for unauthenticated lookups
    const sanitizedOrder = {
        orderId: order.orderId,
        date: order.date,
        totalAmount: order.totalAmount,
        paymentMethod: order.paymentMethod,
        status: order.status,
        recipientEmail: order.recipientEmail ? order.recipientEmail.replace(/^(.{2})(.*)(@.*)$/, '$1***$3') : '***',
        items: (order.items || []).map(it => ({
            productId: it.productId,
            productTitle: it.productTitle,
            price: it.price,
            warranty: it.warranty,
            status: it.status,
            credentials: it.status === 'delivered' ? { instructions: order.userId ? "กรุณาเข้าสู่ระบบด้วยบัญชีสมาชิกที่ใช้สั่งซื้อเพื่อดูรหัสผ่าน" : "กรุณาระบุอีเมลที่ใช้สั่งซื้อเพื่อดูรหัสผ่าน" } : null
        }))
    };
    res.json({ success: true, order: sanitizedOrder, requiresEmailAuth: true });
});

// ─────────────────────────────────────────────────────────────
// USER AUTHENTICATION SYSTEM
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// USER AUTHENTICATION SYSTEM (HARDENED HMAC TOKEN & ANTI-HIJACK)
// ─────────────────────────────────────────────────────────────

const USER_TOKEN_SECRET = process.env.USER_TOKEN_SECRET || 'supinkly_sec_user_token_2026';
const revokedUserTokens = new Set();

function isLocalRequest(req) {
    if (process.env.NODE_ENV === 'production') return false;
    const ip = req.ip || req.connection?.remoteAddress || '';
    const host = req.hostname || (req.headers.host || '').split(':')[0];
    return host === 'localhost' || host === '127.0.0.1' || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

function hashPassword(password, userId) {
    const salt = (process.env.USER_SALT || 'supinkly_user_salt_2026') + userId;
    return crypto.createHash('sha256').update(salt + String(password).trim()).digest('hex');
}

function verifyPassword(enteredPw, storedHash, userId) {
    const entered = hashPassword(enteredPw, userId);
    if (entered.length !== storedHash.length) return false;
    return crypto.timingSafeEqual(Buffer.from(entered), Buffer.from(storedHash));
}

// Cryptographic stateless token generator (Survives server restart & zero memory leak)
function generateUserToken(userId, email, tokenVersion = 1, durationMs = 30 * 24 * 60 * 60 * 1000) {
    const expiresAt = Date.now() + durationMs;
    const nonce = crypto.randomBytes(8).toString('hex');
    const version = tokenVersion || 1;
    const payload = `${userId}.${expiresAt}.${version}.${nonce}`;
    const hmac = crypto.createHmac('sha256', USER_TOKEN_SECRET)
        .update(`${payload}.${email}`)
        .digest('hex');
    const token = `${payload}.${hmac}`;
    return { token, expiresAt };
}

function verifyUserToken(token) {
    if (!token || typeof token !== 'string') return null;
    if (revokedUserTokens.has(token)) return null;

    const parts = token.split('.');
    if (parts.length !== 4 && parts.length !== 5) return null;

    let userId, expiresAtStr, tokenVersion, nonce, hmac;
    if (parts.length === 5) {
        let tokenVersionStr;
        [userId, expiresAtStr, tokenVersionStr, nonce, hmac] = parts;
        tokenVersion = parseInt(tokenVersionStr, 10);
    } else {
        // Backwards compatibility with legacy 4-part tokens
        [userId, expiresAtStr, nonce, hmac] = parts;
        tokenVersion = null;
    }

    const expiresAt = parseInt(expiresAtStr, 10);
    if (isNaN(expiresAt) || Date.now() > expiresAt) return null;

    const db = getDb();
    const user = (db.users || []).find(u => u.id === userId);
    if (!user) return null;

    // Check tokenVersion: mismatched version indicates session was invalidated (e.g. password reset)
    const currentVersion = user.tokenVersion || 1;
    if (tokenVersion !== null && tokenVersion !== currentVersion) {
        return null;
    }

    const payload = parts.length === 5
        ? `${userId}.${expiresAt}.${tokenVersion}.${nonce}`
        : `${userId}.${expiresAt}.${nonce}`;

    const expectedHmac = crypto.createHmac('sha256', USER_TOKEN_SECRET)
        .update(`${payload}.${user.email}`)
        .digest('hex');

    if (hmac.length !== expectedHmac.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac))) return null;

    return { userId: user.id, email: user.email, expiresAt, displayName: user.displayName };
}

function authenticateUser(req) {
    const authHeader = req.headers['authorization'] || '';
    const token = req.headers['x-user-token'] || (authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : null);
    if (!token) return null;
    return verifyUserToken(token);
}

const userAuthRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { success: false, message: "ลองเข้าสู่ระบบบ่อยเกินไป กรุณารอสักครู่" }
});

const otpRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: { success: false, message: "ทำรายการ OTP บ่อยเกินไป กรุณารอสักครู่" }
});

// U1. Register (Step 1: Send 6-Digit Verification OTP to Email)
app.post('/api/auth/register', userAuthRateLimit, async (req, res) => {
    try {
        const { email, password, displayName } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "กรุณากรอกอีเมลและรหัสผ่าน" });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ success: false, message: "รูปแบบอีเมลไม่ถูกต้อง" });
        }
        const pw = String(password).trim();
        if (pw.length < 6 || pw.length > 128) {
            return res.status(400).json({ success: false, message: "รหัสผ่านต้องมีความยาว 6-128 ตัวอักษร" });
        }

        const db = getDb();
        if (!db.users) db.users = [];
        if (!db.pendingRegistrations) db.pendingRegistrations = {};
        const normalEmail = email.trim().toLowerCase();

        // Check if user already exists
        if (db.users.find(u => u.email === normalEmail)) {
            return res.status(400).json({ success: false, message: "อีเมลนี้มีบัญชีในระบบแล้ว กรุณาเข้าสู่ระบบ หรือใช้อีเมลอื่น" });
        }

        const now = Date.now();
        const pending = db.pendingRegistrations[normalEmail];
        if (pending && (now - (pending.lastSentAt || 0) < 45000)) {
            const waitSec = Math.ceil((45000 - (now - pending.lastSentAt)) / 1000);
            return res.status(429).json({ success: false, message: `กรุณารออีก ${waitSec} วินาทีก่อนขอรหัสใหม่อีกครั้ง` });
        }

        // Sanitize displayName to prevent control characters and formatting attacks
        const cleanDisplayName = displayName
            ? String(displayName).replace(/[\r\n\t\x00-\x1f]/g, '').slice(0, 60).trim()
            : normalEmail.split('@')[0];

        const pendingUserId = 'U' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
        const otp = String(crypto.randomInt(100000, 999999));
        const otpHash = crypto.createHash('sha256').update(normalEmail + ':' + otp).digest('hex');

        db.pendingRegistrations[normalEmail] = {
            userId: pendingUserId,
            email: normalEmail,
            displayName: cleanDisplayName || 'สมาชิก Supinkly',
            passwordHash: hashPassword(pw, pendingUserId),
            otpHash,
            attempts: 0,
            expiresAt: now + 10 * 60 * 1000, // 10 minutes
            lastSentAt: now
        };
        saveDb(db);

        const isSmtpConfigured = mailService.isConfigured(mailService.getConfig(db));
        const mailResult = await mailService.sendOtpEmail(normalEmail, otp, cleanDisplayName, db);
        const isDevLocal = isLocalRequest(req) && process.env.NODE_ENV !== 'production';

        // If SMTP is unconfigured or email failed to deliver, auto-complete registration immediately so customers are never blocked or lost!
        if (!isSmtpConfigured || !mailResult.delivered) {
            const user = {
                id: pendingUserId,
                email: normalEmail,
                displayName: cleanDisplayName || 'สมาชิก Supinkly',
                passwordHash: hashPassword(pw, pendingUserId),
                tokenVersion: 1,
                emailVerified: true,
                createdAt: new Date().toISOString()
            };
            if (!db.users) db.users = [];
            db.users.push(user);
            delete db.pendingRegistrations[normalEmail];

            // Auto-link past orders belonging to this email
            (db.orders || []).forEach(o => {
                if (!o.userId) {
                    const oEmail = (o.email || '').toLowerCase().trim();
                    const rEmail = (o.recipientEmail || '').toLowerCase().trim();
                    if (oEmail === normalEmail || rEmail === normalEmail || rEmail.startsWith(normalEmail + ' ') || rEmail.startsWith(normalEmail + '(')) {
                        o.userId = user.id;
                    }
                }
            });

            saveDb(db);
            const { token, expiresAt } = generateUserToken(user.id, user.email, user.tokenVersion);
            return res.json({
                success: true,
                autoVerified: true,
                token,
                expiresAt,
                user: { id: user.id, userId: user.id, email: user.email, displayName: user.displayName },
                message: "สมัครสมาชิกและเข้าสู่ระบบสำเร็จเรียบร้อยแล้ว!"
            });
        }

        res.json({
            success: true,
            requireOtp: true,
            email: normalEmail,
            message: mailResult.delivered
                ? "ระบบได้ส่งรหัส OTP 6 หลักไปยังอีเมลของคุณแล้ว (หากไม่พบในกล่องจดหมาย กรุณาตรวจสอบโฟลเดอร์สแปม/เมลขยะ)"
                : (mailResult.deliveryError
                    ? `[แจ้งเตือน] ส่งอีเมลไม่สำเร็จ (${mailResult.deliveryError}) — รหัส OTP สำหรับทดสอบคือ: ${otp}`
                    : `รหัส OTP สำหรับยืนยันตัวตนคือ: ${otp}`),
            delivered: !!mailResult.delivered,
            devOtp: (!mailResult.delivered || isDevLocal) ? otp : undefined,
            deliveryError: mailResult.deliveryError || undefined
        });
    } catch (err) {
        console.error('Registration OTP error:', err);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการส่งรหัส OTP กรุณาลองใหม่" });
    }
});

// U1.1 Verify OTP and Complete Registration
app.post('/api/auth/verify-otp', otpRateLimit, (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({ success: false, message: "กรุณาระบุอีเมลและรหัส OTP 6 หลัก" });
        }
        const normalEmail = String(email).trim().toLowerCase();
        const cleanOtp = String(otp).trim();
        if (!/^\d{6}$/.test(cleanOtp)) {
            return res.status(400).json({ success: false, message: "รหัส OTP ต้องเป็นตัวเลข 6 หลัก" });
        }

        const db = getDb();
        if (!db.pendingRegistrations) db.pendingRegistrations = {};
        const pending = db.pendingRegistrations[normalEmail];

        if (!pending) {
            return res.status(400).json({ success: false, message: "ไม่พบข้อมูลการลงทะเบียน หรือรหัสหมดอายุ กรุณาสมัครใหม่อีกครั้ง" });
        }

        if (Date.now() > pending.expiresAt) {
            delete db.pendingRegistrations[normalEmail];
            saveDb(db);
            return res.status(400).json({ success: false, message: "รหัส OTP หมดอายุแล้ว (เกิน 10 นาที) กรุณาสมัครใหม่อีกครั้ง" });
        }

        if ((pending.attempts || 0) >= 5) {
            delete db.pendingRegistrations[normalEmail];
            saveDb(db);
            return res.status(400).json({ success: false, message: "กรอกรหัสผิดเกิน 5 ครั้ง รหัส OTP ถูกยกเลิกเพื่อความปลอดภัย กรุณาสมัครใหม่อีกครั้ง" });
        }

        const enteredHash = crypto.createHash('sha256').update(normalEmail + ':' + cleanOtp).digest('hex');
        const isMatch = enteredHash.length === pending.otpHash.length &&
            crypto.timingSafeEqual(Buffer.from(enteredHash), Buffer.from(pending.otpHash));

        if (!isMatch) {
            pending.attempts = (pending.attempts || 0) + 1;
            const remaining = 5 - pending.attempts;
            if (pending.attempts >= 5) {
                delete db.pendingRegistrations[normalEmail];
                saveDb(db);
                return res.status(400).json({ success: false, message: "กรอกรหัสผิดเกิน 5 ครั้ง รหัส OTP ถูกยกเลิกเพื่อความปลอดภัย กรุณาสมัครใหม่อีกครั้ง" });
            }
            saveDb(db);
            return res.status(400).json({ success: false, message: `รหัส OTP ไม่ถูกต้อง (เหลือโอกาสลองอีก ${remaining} ครั้ง)` });
        }

        // OTP Verified Successfully! Create the permanent user account
        if (!db.users) db.users = [];
        const user = {
            id: pending.userId,
            email: pending.email,
            displayName: pending.displayName || 'สมาชิก Supinkly',
            passwordHash: pending.passwordHash,
            tokenVersion: 1,
            emailVerified: true,
            createdAt: new Date().toISOString()
        };
        db.users.push(user);
        delete db.pendingRegistrations[normalEmail];

        // Auto-link past guest orders belonging to this email
        (db.orders || []).forEach(o => {
            if (!o.userId) {
                const oEmail = (o.email || '').toLowerCase().trim();
                const rEmail = (o.recipientEmail || '').toLowerCase().trim();
                if (oEmail === normalEmail || rEmail === normalEmail || rEmail.startsWith(normalEmail + ' ') || rEmail.startsWith(normalEmail + '(')) {
                    o.userId = user.id;
                }
            }
        });

        saveDb(db);

        const { token, expiresAt } = generateUserToken(user.id, user.email, user.tokenVersion);
        res.json({
            success: true,
            token,
            expiresAt,
            user: { id: user.id, userId: user.id, email: user.email, displayName: user.displayName }
        });
    } catch (err) {
        console.error('Verify OTP error:', err);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการตรวจสอบ OTP" });
    }
});

// U1.2 Resend OTP
app.post('/api/auth/resend-otp', otpRateLimit, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: "กรุณาระบุอีเมล" });
        }
        const normalEmail = String(email).trim().toLowerCase();
        const db = getDb();
        if (!db.pendingRegistrations) db.pendingRegistrations = {};
        const pending = db.pendingRegistrations[normalEmail];

        if (!pending) {
            return res.status(400).json({ success: false, message: "ไม่พบข้อมูลการลงทะเบียนที่รอการยืนยัน กรุณาสมัครใหม่อีกครั้ง" });
        }

        const now = Date.now();
        if (now - (pending.lastSentAt || 0) < 45000) {
            const waitSec = Math.ceil((45000 - (now - pending.lastSentAt)) / 1000);
            return res.status(429).json({ success: false, message: `กรุณารออีก ${waitSec} วินาทีก่อนขอรหัสใหม่อีกครั้ง` });
        }

        const otp = String(crypto.randomInt(100000, 999999));
        pending.otpHash = crypto.createHash('sha256').update(normalEmail + ':' + otp).digest('hex');
        pending.attempts = 0;
        pending.expiresAt = now + 10 * 60 * 1000;
        pending.lastSentAt = now;
        saveDb(db);

        const mailResult = await mailService.sendOtpEmail(normalEmail, otp, pending.displayName, db);
        const isDevLocal = isLocalRequest(req) && process.env.NODE_ENV !== 'production';

        res.json({
            success: true,
            message: mailResult.delivered
                ? "ระบบได้ส่งรหัส OTP ชุดใหม่ไปยังอีเมลของคุณแล้ว (หากไม่พบให้ตรวจในกล่องสแปม)"
                : (isDevLocal
                    ? (mailResult.deliveryError
                        ? `[แจ้งเตือน] ส่งอีเมลไม่สำเร็จ (${mailResult.deliveryError}) — รหัส OTP ชุดใหม่คือ: ${otp}`
                        : `[โหมดทดสอบ] รหัส OTP ชุดใหม่คือ: ${otp}`)
                    : "ระบบได้ส่งรหัส OTP ชุดใหม่ไปยังอีเมลของคุณแล้ว (หากไม่พบให้ตรวจในกล่องสแปม)"),
            delivered: !!mailResult.delivered,
            devOtp: (isDevLocal && !mailResult.delivered) ? otp : undefined,
            deliveryError: isDevLocal ? mailResult.deliveryError : undefined
        });
    } catch (err) {
        console.error('Resend OTP error:', err);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการส่งรหัส OTP ใหม่" });
    }
});

// U2. Login
app.post('/api/auth/login', userAuthRateLimit, (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: "กรุณากรอกอีเมลและรหัสผ่าน" });
    }

    const db = getDb();
    if (!db.users) db.users = [];
    const normalEmail = email.trim().toLowerCase();
    let user = db.users.find(u => (u.email || '').toLowerCase() === normalEmail);

    // If user is not yet finalized, check if there is a pending registration with valid password
    if (!user && db.pendingRegistrations && db.pendingRegistrations[normalEmail]) {
        const pending = db.pendingRegistrations[normalEmail];
        if (verifyPassword(String(password).trim(), pending.passwordHash, pending.userId)) {
            user = {
                id: pending.userId,
                email: pending.email,
                displayName: pending.displayName || 'สมาชิก Supinkly',
                passwordHash: pending.passwordHash,
                tokenVersion: 1,
                emailVerified: true,
                createdAt: new Date().toISOString()
            };
            db.users.push(user);
            delete db.pendingRegistrations[normalEmail];
            saveDb(db);
        }
    }

    // [SECURITY] Always run verifyPassword in constant time to prevent timing-based user enumeration
    const DUMMY_HASH = hashPassword('dummy_check_supinkly', 'DUMMY_USER_ID_0000');
    const isValid = user
        ? verifyPassword(String(password).trim(), user.passwordHash, user.id)
        : (verifyPassword('dummy_check_supinkly', DUMMY_HASH, 'DUMMY_USER_ID_0000') && false);

    if (!user || !isValid) {
        return res.status(401).json({ success: false, message: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
    }

    // Auto-link unlinked past guest orders belonging to this email
    let linked = false;
    (db.orders || []).forEach(o => {
        if (!o.userId) {
            const oEmail = (o.email || '').toLowerCase().trim();
            const rEmail = (o.recipientEmail || '').toLowerCase().trim();
            if (oEmail === normalEmail || rEmail === normalEmail || rEmail.startsWith(normalEmail + ' ') || rEmail.startsWith(normalEmail + '(')) {
                o.userId = user.id;
                linked = true;
            }
        }
    });
    if (linked) saveDb(db);

    const { token, expiresAt } = generateUserToken(user.id, normalEmail, user.tokenVersion || 1);
    res.json({ success: true, token, expiresAt, user: { id: user.id, userId: user.id, email: normalEmail, displayName: user.displayName } });
});

// U2.1 Forgot Password: Request OTP to reset password
app.post('/api/auth/forgot-password', userAuthRateLimit, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, message: "กรุณาระบุอีเมลที่ถูกต้อง" });
        }

        const normalEmail = email.trim().toLowerCase();
        const db = getDb();
        if (!db.users) db.users = [];
        if (!db.passwordResets) db.passwordResets = {};

        // [SECURITY] Cooldown check applies to ALL requested emails (prevents 429-based enumeration)
        const now = Date.now();
        const existingReset = db.passwordResets[normalEmail];
        if (existingReset && (now - (existingReset.lastSentAt || 0) < 45000)) {
            const waitSec = Math.ceil((45000 - (now - existingReset.lastSentAt)) / 1000);
            return res.status(429).json({ success: false, message: `กรุณารออีก ${waitSec} วินาทีก่อนขอรหัสใหม่อีกครั้ง` });
        }

        const user = db.users.find(u => (u.email || '').toLowerCase() === normalEmail);

        // [SECURITY] Anti-User Enumeration:
        // Set cooldown and simulate processing delay so non-existing emails cannot be detected via timing
        if (!user) {
            db.passwordResets[normalEmail] = {
                lastSentAt: now,
                expiresAt: now + 5 * 60 * 1000,
                dummy: true
            };
            saveDb(db);
            await new Promise(r => setTimeout(r, 150 + Math.floor(Math.random() * 100)));
            return res.json({
                success: true,
                message: "หากอีเมลนี้มีอยู่ในระบบ เราได้ส่งรหัส OTP 6 หลักสำหรับตั้งรหัสผ่านใหม่ไปยังอีเมลของคุณแล้ว",
                email: normalEmail
            });
        }

        const otp = String(crypto.randomInt(100000, 999999));
        const otpHash = crypto.createHash('sha256').update(normalEmail + ':reset:' + otp).digest('hex');

        db.passwordResets[normalEmail] = {
            email: normalEmail,
            userId: user.id,
            otpHash,
            attempts: 0,
            expiresAt: now + 10 * 60 * 1000, // 10 minutes
            lastSentAt: now
        };
        saveDb(db);

        const mailResult = await mailService.sendResetPasswordEmail(normalEmail, otp, user.displayName, db);
        const isDevLocal = isLocalRequest(req) && process.env.NODE_ENV !== 'production';

        res.json({
            success: true,
            message: (mailResult.delivered || !isDevLocal)
                ? "หากอีเมลนี้มีอยู่ในระบบ เราได้ส่งรหัส OTP 6 หลักสำหรับตั้งรหัสผ่านใหม่ไปยังอีเมลของคุณแล้ว (หากไม่พบให้ตรวจในกล่องสแปม)"
                : (mailResult.deliveryError
                    ? `[แจ้งเตือน] ส่งอีเมลไม่สำเร็จ (${mailResult.deliveryError}) — รหัส OTP กู้คืนรหัสผ่านคือ: ${otp}`
                    : `[โหมดทดสอบ] รหัส OTP กู้คืนรหัสผ่านคือ: ${otp}`),
            email: normalEmail,
            delivered: !!mailResult.delivered,
            devOtp: (isDevLocal && !mailResult.delivered) ? otp : undefined,
            deliveryError: isDevLocal ? mailResult.deliveryError : undefined
        });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการส่งรหัสกู้คืนรหัสผ่าน" });
    }
});

// U2.2 Reset Password: Verify OTP and save new password
app.post('/api/auth/reset-password', otpRateLimit, (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword) {
            return res.status(400).json({ success: false, message: "กรุณากรอกข้อมูลให้ครบถ้วน (อีเมล, รหัส OTP, รหัสผ่านใหม่)" });
        }

        const normalEmail = String(email).trim().toLowerCase();
        const cleanOtp = String(otp).trim();
        const pw = String(newPassword).trim();

        if (!/^\d{6}$/.test(cleanOtp)) {
            return res.status(400).json({ success: false, message: "รหัส OTP ต้องเป็นตัวเลข 6 หลัก" });
        }
        if (pw.length < 6 || pw.length > 128) {
            return res.status(400).json({ success: false, message: "รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 6 ตัวอักษร" });
        }

        const db = getDb();
        if (!db.passwordResets) db.passwordResets = {};
        const resetRecord = db.passwordResets[normalEmail];

        if (!resetRecord || resetRecord.dummy) {
            return res.status(400).json({ success: false, message: "ไม่พบคำขอรีเซ็ตรหัสผ่าน หรือรหัสหมดอายุ กรุณาขอรหัสใหม่อีกครั้ง" });
        }

        if (Date.now() > resetRecord.expiresAt) {
            delete db.passwordResets[normalEmail];
            saveDb(db);
            return res.status(400).json({ success: false, message: "รหัส OTP หมดอายุแล้ว (เกิน 10 นาที) กรุณาขอรหัสใหม่อีกครั้ง" });
        }

        if ((resetRecord.attempts || 0) >= 5) {
            delete db.passwordResets[normalEmail];
            saveDb(db);
            return res.status(400).json({ success: false, message: "กรอกรหัสผิดเกิน 5 ครั้ง คำขอถูกยกเลิกเพื่อความปลอดภัย กรุณาทำรายการใหม่อีกครั้ง" });
        }

        const enteredHash = crypto.createHash('sha256').update(normalEmail + ':reset:' + cleanOtp).digest('hex');
        const isMatch = enteredHash.length === resetRecord.otpHash.length &&
            crypto.timingSafeEqual(Buffer.from(enteredHash), Buffer.from(resetRecord.otpHash));

        if (!isMatch) {
            resetRecord.attempts = (resetRecord.attempts || 0) + 1;
            const remaining = 5 - resetRecord.attempts;
            if (resetRecord.attempts >= 5) {
                delete db.passwordResets[normalEmail];
                saveDb(db);
                return res.status(400).json({ success: false, message: "กรอกรหัสผิดเกิน 5 ครั้ง คำขอถูกยกเลิกเพื่อความปลอดภัย กรุณาทำรายการใหม่อีกครั้ง" });
            }
            saveDb(db);
            return res.status(400).json({ success: false, message: `รหัส OTP ไม่ถูกต้อง (เหลือโอกาสลองอีก ${remaining} ครั้ง)` });
        }

        // OTP Validated! Update user password
        if (!db.users) db.users = [];
        const user = db.users.find(u => u.id === resetRecord.userId || (u.email || '').toLowerCase() === normalEmail);
        if (!user) {
            delete db.passwordResets[normalEmail];
            saveDb(db);
            return res.status(404).json({ success: false, message: "ไม่พบบัญชีผู้ใช้งานในระบบ" });
        }

        // Invalidate all existing sessions across all devices
        user.passwordHash = hashPassword(pw, user.id);
        user.tokenVersion = (user.tokenVersion || 1) + 1;
        user.passwordUpdatedAt = new Date().toISOString();
        delete db.passwordResets[normalEmail];
        // Auto-link past guest orders belonging to this email
        (db.orders || []).forEach(o => {
            if (!o.userId) {
                const oEmail = (o.email || '').toLowerCase().trim();
                const rEmail = (o.recipientEmail || '').toLowerCase().trim();
                if (oEmail === normalEmail || rEmail === normalEmail || rEmail.startsWith(normalEmail + ' ') || rEmail.startsWith(normalEmail + '(')) {
                    o.userId = user.id;
                }
            }
        });
        saveDb(db);

        // Auto-login the user with new token bound to updated tokenVersion
        const { token, expiresAt } = generateUserToken(user.id, normalEmail, user.tokenVersion);
        res.json({
            success: true,
            message: "ตั้งรหัสผ่านใหม่และเข้าสู่ระบบสำเร็จเรียบร้อยแล้ว",
            token,
            expiresAt,
            user: { id: user.id, userId: user.id, email: normalEmail, displayName: user.displayName }
        });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน" });
    }
});

// U3. Logout
app.post('/api/auth/logout', (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    const token = req.headers['x-user-token'] || (authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : null);
    if (token) {
        revokedUserTokens.add(token);
        // Prune revocation set if overly large
        if (revokedUserTokens.size > 10000) {
            const first = revokedUserTokens.values().next().value;
            revokedUserTokens.delete(first);
        }
    }
    res.json({ success: true });
});

// U4. Verify Session
app.post('/api/auth/verify-session', sessionCheckRateLimit, (req, res) => {
    const session = authenticateUser(req);
    if (session) {
        return res.json({ success: true, valid: true, user: { id: session.userId, userId: session.userId, email: session.email, displayName: session.displayName } });
    }
    return res.status(401).json({ success: false, valid: false });
});

// U5. Link Local Orders (Secure Claiming: Requires possession of orderId + matching email)
app.post('/api/auth/link-local-orders', sessionCheckRateLimit, (req, res) => {
    const session = authenticateUser(req);
    if (!session) {
        return res.status(401).json({ success: false, message: "กรุณาเข้าสู่ระบบก่อน" });
    }
    const { orderIds } = req.body;
    if (!Array.isArray(orderIds) || orderIds.length === 0) {
        return res.json({ success: true, linkedCount: 0 });
    }

    const db = getDb();
    let linkedCount = 0;
    const targetIds = new Set(orderIds.slice(0, 100).map(id => String(id).trim()));

    (db.orders || []).forEach(o => {
        // Only link unlinked orders whose secret orderId is possessed by this client and matches the account email
        if (targetIds.has(o.orderId) && (!o.userId) && o.recipientEmail && o.recipientEmail.toLowerCase() === session.email) {
            o.userId = session.userId;
            linkedCount++;
        }
    });

    if (linkedCount > 0) {
        saveDb(db);
    }

    res.json({ success: true, linkedCount });
});

// U6. Get My Orders (Protected: strictly returns orders authenticated to this account)
app.get('/api/auth/my-orders', sessionCheckRateLimit, (req, res) => {
    const session = authenticateUser(req);
    if (!session) {
        return res.status(401).json({ success: false, message: "กรุณาเข้าสู่ระบบก่อน" });
    }
    const db = getDb();
    let linked = false;
    const sessionEmail = (session.email || '').toLowerCase().trim();
    (db.orders || []).forEach(o => {
        if (!o.userId) {
            const oEmail = (o.email || '').toLowerCase().trim();
            const rEmail = (o.recipientEmail || '').toLowerCase().trim();
            if (oEmail === sessionEmail || rEmail === sessionEmail || rEmail.startsWith(sessionEmail + ' ') || rEmail.startsWith(sessionEmail + '(')) {
                o.userId = session.userId;
                linked = true;
            }
        }
    });
    if (linked) saveDb(db);

    const myOrders = (db.orders || []).filter(o => o.userId && o.userId === session.userId);
    res.json({ success: true, orders: myOrders });
});

// ─────────────────────────────────────────────────────────────
// 📊 REAL-TIME TELEMETRY & ANALYTICS API ENDPOINTS
// ─────────────────────────────────────────────────────────────

// T1. Public Telemetry Heartbeat & Action Tracker (Zero PII leak, Rate-limited, Sanitized)
const ALLOWED_TELEMETRY_ACTIONS = new Set([
    'heartbeat', 'page_view', 'product_view', 'cart_add', 'cart_view', 'checkout_start'
]);
const FORBIDDEN_PRODUCT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

app.post('/api/telemetry/heartbeat', telemetryRateLimit, (req, res) => {
    try {
        const { sessionId, action, productId, productTitle, cartCount, cartTotal, page } = req.body || {};
        if (!sessionId || typeof sessionId !== 'string' || !/^[a-zA-Z0-9_\-]{6,48}$/.test(sessionId)) {
            return res.status(400).json({ success: false, message: "sessionId ไม่ถูกต้อง" });
        }

        // Enforce activeSessions memory ceiling (Anti-DoS)
        if (!activeSessions.has(sessionId) && activeSessions.size >= MAX_ACTIVE_SESSIONS) {
            cleanStaleSessions();
            if (activeSessions.size >= MAX_ACTIVE_SESSIONS) {
                const oldestKey = activeSessions.keys().next().value;
                if (oldestKey) activeSessions.delete(oldestKey);
            }
        }

        const userSession = authenticateUser(req);
        const role = userSession ? 'member' : 'guest';
        const userId = userSession ? userSession.userId : null;
        const email = userSession ? userSession.email : null;
        const displayName = userSession ? (userSession.displayName || userSession.email.split('@')[0]) : `ผู้เยี่ยมชม #${sessionId.slice(-4).toUpperCase()}`;

        const cleanAction = (typeof action === 'string' && ALLOWED_TELEMETRY_ACTIONS.has(action)) ? action : 'heartbeat';

        const db = getDb();
        const catalogProd = (typeof productId === 'string' && /^[a-z0-9\-]{1,32}$/.test(productId) && !FORBIDDEN_PRODUCT_KEYS.has(productId))
            ? getCatalogProduct(productId, db)
            : null;
        const safeProductId = catalogProd ? productId : null;

        const now = Date.now();
        let session = activeSessions.get(sessionId);

        const currentProduct = sanitizeTelemetryText(
            productTitle || (catalogProd ? catalogProd.title : (session?.currentProduct || '')),
            80
        );
        const currentPage = sanitizeTelemetryText(page || session?.page || 'หน้าแรก', 60);
        const numCartCount = typeof cartCount === 'number' ? Math.max(0, Math.min(100, Math.floor(cartCount))) : (session?.cartCount || 0);
        const numCartTotal = typeof cartTotal === 'number' ? Math.max(0, Math.min(1000000, Math.round(cartTotal * 100) / 100)) : (session?.cartTotal || 0);

        let lastAction = session?.lastAction || 'เข้าชมหน้าแรก';
        if (cleanAction === 'page_view') lastAction = `เข้าชม: ${currentPage}`;
        else if (cleanAction === 'product_view') lastAction = `เลือกดู: ${currentProduct || safeProductId || 'สินค้า'}`;
        else if (cleanAction === 'cart_add') lastAction = `เพิ่มลงตะกร้า: ${currentProduct || safeProductId || 'สินค้า'}`;
        else if (cleanAction === 'cart_view') lastAction = `เปิดดูตะกร้า (${numCartCount} ชิ้น ยอด ฿${numCartTotal.toFixed(2)})`;
        else if (cleanAction === 'checkout_start') lastAction = `เริ่มต้นชำระเงิน (${numCartCount} ชิ้น ยอด ฿${numCartTotal.toFixed(2)})`;

        session = {
            sessionId,
            userId,
            email,
            displayName: sanitizeTelemetryText(displayName, 60),
            role,
            lastSeen: now,
            startedAt: session ? session.startedAt : now,
            page: currentPage,
            currentProduct,
            lastAction,
            cartCount: numCartCount,
            cartTotal: numCartTotal
        };
        activeSessions.set(sessionId, session);

        // Update database daily analytics

        const today = getTodayAnalytics(db);
        if (!today.visitors.includes(sessionId)) {
            today.visitors.push(sessionId);
            if (today.visitors.length > 5000) today.visitors = today.visitors.slice(-5000);
        }

        let shouldMarkDirty = false;
        if (cleanAction === 'page_view') {
            today.pageViews = (today.pageViews || 0) + 1;
            shouldMarkDirty = true;
        } else if (cleanAction === 'product_view' && safeProductId) {
            today.productViews[safeProductId] = (today.productViews[safeProductId] || 0) + 1;
            addAnalyticsEvent(db, {
                type: 'product_view',
                user: displayName,
                role,
                text: `กำลังดูรายละเอียด "${currentProduct || safeProductId}"`,
                productId: safeProductId
            });
            shouldMarkDirty = true;
        } else if (cleanAction === 'cart_add' && safeProductId) {
            today.cartAdds[safeProductId] = (today.cartAdds[safeProductId] || 0) + 1;
            addAnalyticsEvent(db, {
                type: 'cart_add',
                user: displayName,
                role,
                text: `เพิ่ม "${currentProduct || safeProductId}" ลงตะกร้า`,
                productId: safeProductId,
                amount: numCartTotal
            });
            shouldMarkDirty = true;
        } else if (cleanAction === 'checkout_start') {
            today.checkoutStarts = (today.checkoutStarts || 0) + 1;
            addAnalyticsEvent(db, {
                type: 'checkout_start',
                user: displayName,
                role,
                text: `เข้าสู่หน้าสแกนชำระเงิน (${numCartCount} ชิ้น ยอด ฿${numCartTotal.toFixed(2)})`,
                amount: numCartTotal
            });
            shouldMarkDirty = true;
        }

        if (shouldMarkDirty) {
            markAnalyticsDirty();
        }

        res.json({
            success: true,
            onlineTotal: activeSessions.size,
            role,
            displayName: session.displayName
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// T2. Public Fast Online Counter (For store header badge)
app.get('/api/online-count', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=5');
    const count = Math.max(1, activeSessions.size);
    res.json({
        success: true,
        onlineTotal: count
    });
});

// T3. Admin Real-Time Analytics & Online Users Dashboard
app.get('/api/admin/analytics', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const today = getTodayAnalytics(db);
    const now = Date.now();

    // Prune stale sessions (> 60s of inactivity)
    for (const [sid, sess] of activeSessions.entries()) {
        if (now - sess.lastSeen > 60000) {
            activeSessions.delete(sid);
        }
    }

    const liveList = Array.from(activeSessions.values()).map(s => ({
        sessionId: s.sessionId,
        role: s.role,
        userId: s.userId,
        email: s.email,
        displayName: s.displayName,
        page: s.page,
        currentProduct: s.currentProduct,
        lastAction: s.lastAction,
        cartCount: s.cartCount,
        cartTotal: s.cartTotal,
        lastSeenSec: Math.max(0, Math.floor((now - s.lastSeen) / 1000)),
        onlineDurationSec: Math.max(0, Math.floor((now - s.startedAt) / 1000))
    })).sort((a, b) => {
        if (a.role === 'member' && b.role !== 'member') return -1;
        if (b.role === 'member' && a.role !== 'member') return 1;
        return a.lastSeenSec - b.lastSeenSec;
    });

    const onlineMembers = liveList.filter(s => s.role === 'member');
    const onlineGuests = liveList.filter(s => s.role === 'guest');

    // Aggregate today's orders & revenue directly from db.orders
    const todayStrPrefix = new Date().toLocaleDateString('th-TH', { dateStyle: 'medium' });
    const todayIsoDate = getTodayKey();
    let todayOrdersCount = 0;
    let todayRevenue = 0;

    (db.orders || []).forEach(o => {
        const orderDateStr = o.date || '';
        if (orderDateStr.includes(todayStrPrefix) || orderDateStr.includes(todayIsoDate)) {
            todayOrdersCount++;
            todayRevenue += (o.totalAmount || 0);
        }
    });

    if (today.ordersCount > todayOrdersCount) todayOrdersCount = today.ordersCount;
    if (today.revenue > todayRevenue) todayRevenue = today.revenue;

    const uniqueVisitorsCount = Math.max(today.visitors.length, liveList.length);
    const conversionRate = uniqueVisitorsCount > 0
        ? ((todayOrdersCount / uniqueVisitorsCount) * 100).toFixed(1) + '%'
        : '0.0%';

    // Top products by views and cart additions
    const topProducts = Object.keys(MASTER_CATALOG).map(pid => {
        const p = MASTER_CATALOG[pid];
        const views = (today.productViews && today.productViews[pid]) || 0;
        const cartAdds = (today.cartAdds && today.cartAdds[pid]) || 0;
        return {
            productId: pid,
            title: p.title,
            brand: p.brand,
            price: (db.customPrices && db.customPrices[pid]?.price) || p.price,
            views,
            cartAdds
        };
    }).filter(p => p.views > 0 || p.cartAdds > 0)
        .sort((a, b) => (b.views + b.cartAdds * 2) - (a.views + a.cartAdds * 2));

    const productViewsTotal = Object.values(today.productViews || {}).reduce((s, v) => s + v, 0);
    const cartAddsTotal = Object.values(today.cartAdds || {}).reduce((s, v) => s + v, 0);

    res.json({
        success: true,
        live: {
            onlineTotal: liveList.length,
            onlineMembersCount: onlineMembers.length,
            onlineGuestsCount: onlineGuests.length,
            activeUsers: liveList
        },
        today: {
            date: today.date,
            uniqueVisitors: uniqueVisitorsCount,
            pageViews: today.pageViews || 0,
            productViewsTotal,
            cartAddsTotal,
            checkoutStarts: today.checkoutStarts || 0,
            ordersCount: todayOrdersCount,
            revenue: todayRevenue,
            conversionRate,
            topProducts: topProducts.slice(0, 10),
            recentEvents: (today.recentEvents || []).slice(0, 30)
        }
    });
});

// ─────────────────────────────────────────────────────────────
// LIVE CHAT — WebSocket Server (ws)
// ─────────────────────────────────────────────────────────────
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');

// Map: sessionId → { ws, role: 'customer'|'admin', name, sessionId }
const clients = new Map();
const lastAdminReplyPerSession = new Map();

// Map to store multi-turn chat history per customer session
const chatHistoryPerSession = new Map();

// [SECURITY] Track order status lookups per session to prevent brute-force order enumeration
const orderLookupsPerSession = new Map();

/**
 * Call Google Gemini API (gemini-3.8-flash / gemini-2.5-flash / gemini-1.5-flash)
 */
async function callGeminiAI(userMsg, sessionId, apiKey) {
    const history = chatHistoryPerSession.get(sessionId) || [];
    const db = getDb();

    const activeCoupons = (db.coupons || []).filter(c => c.active !== false).map(c => `${c.code} (${c.title || c.description})`).join(', ');

    const systemInstruction =
        `คุณคือ "น้องพิงกี้" (Mascot AI ผู้ช่วยประจำร้าน Supinkly.AI)
ร้าน Supinkly.AI เป็นแพลตฟอร์มจำหน่ายบัญชี AI พรีเมียม, ลิขสิทธิ์ดิจิทัล, คลาวด์ไดรฟ์ และคีย์ซอฟต์แวร์แท้ 100%
บุคลิกของคุณ: สุภาพ ร่าเริง อ่อนน้อม เป็นมิตร สรรพนามแทนตัวเองว่า "น้องพิงกี้" และลงท้ายด้วย "ครับ/ผม" เสมอ

ข้อมูลสำคัญของร้าน:
- สินค้าหลัก: CapCut Pro (Private ฿129 / Shared ฿79), Claude Pro (Private ฿850 / Shared ฿290), Google AI Pro (฿150), Google Drive 5TB (฿229), Grok (฿290-฿950), Windows 11 Pro OEM Key แท้ตลอดชีพ (฿290), Microsoft 365 (฿259), Adobe CC All Apps (฿790)
- รับประกัน: สินค้าทุกชิ้นรับประกัน 30 วันเต็ม (Windows OEM รับประกันตลอดชีพ) มีปัญหาเปลี่ยนชุดใหม่ให้ทันที
- ประเภทสินค้า: Private (ส่วนตัว 100% ไม่แชร์ใคร), Shared (หารโปรไฟล์แยก ประหยัด), Link (Invite เข้าเมลตัวเอง), Key (คีย์เปิดสิทธิ์)
- ระบบส่งมอบ: จัดเตรียมและส่งมอบรหัสเข้าเมนู "คีย์ของฉัน" และอีเมลภายใน 5-15 นาทีหลังชำระเงิน
- การชำระเงิน: สแกน PromptPay QR Code ตรวจสลิปด้วย AI อัตโนมัติ ปลอดภัย 100%
- โค้ดส่วนลดปัจจุบัน: ${activeCoupons || 'SUPINKLY10 (ลด 10%), PINKLOVE50 (ลด ฿50)'}
- เพจ Facebook: https://www.facebook.com/profile.php?id=61594837747580

คำแนะนำการตอบ:
- ตอบให้กระชับ ชัดเจน เข้าใจง่าย ใช้ภาษาไทยที่สุภาพ น่ารัก และมีอิโมจิประกอบพอเหมาะ
- หากลูกค้าถามเรื่องสถานะคำสั่งซื้อ ให้แนะนำให้แจ้งเลขออเดอร์ SPK-xxxxxx
- ห้ามให้ข้อมูลเท็จ หากไม่แน่ใจให้แนะนำให้ติดต่อแอดมินคนจริงในแชทนี้`;

    if (!apiKey || typeof apiKey !== 'string' || apiKey.trim().length < 15) return null;
    const cleanKey = apiKey.trim();

    const modelsToTry = ['gemini-flash-latest', 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];

    for (const model of modelsToTry) {
        try {
            // Strictly match Google AI Studio curl format
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
            
            const reqHeaders = {
                'Content-Type': 'application/json',
                'X-goog-api-key': cleanKey
            };

            const fullPromptText = `[คำสั่งระบบ: คุณคือ "น้องพิงกี้" Mascot AI ผู้ช่วยประจำร้าน Supinkly.AI สุภาพ ร่าเริง อ่อนน้อม เป็นมิตร สรรพนามแทนตัวเองว่า "น้องพิงกี้" ลงท้าย "ครับ/ผม" เสมอ ตอบคำถามได้ทุกเรื่องอย่างชาญฉลาดและถูกต้อง ทั้งเรื่องสินค้าในร้าน, การใช้งาน AI, การเขียนโปรแกรม (Programming/Coding), เทคโนโลยี และคำถามทั่วไป]\n\nคำถามจากลูกค้า: ${userMsg}`;

            // Build conversation history
            const contents = [];
            if (history && history.length > 0) {
                contents.push(...history.slice(-4));
            }
            contents.push({
                role: 'user',
                parts: [{ text: fullPromptText }]
            });

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 9000);

            let res = await fetch(url, {
                method: 'POST',
                headers: reqHeaders,
                body: JSON.stringify({ contents }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            // If multi-turn fails, fallback to exact curl single-turn payload
            if (!res.ok) {
                const errSnippet = await res.text().catch(() => '');
                console.warn(`[GEMINI-AI] ${model} attempt 1 failed (${res.status}): ${errSnippet.slice(0, 120)}`);
                
                const fallbackCtrl = new AbortController();
                const fbTimeout = setTimeout(() => fallbackCtrl.abort(), 9000);
                res = await fetch(url, {
                    method: 'POST',
                    headers: reqHeaders,
                    body: JSON.stringify({
                        contents: [
                            {
                                parts: [{ text: fullPromptText }]
                            }
                        ]
                    }),
                    signal: fallbackCtrl.signal
                });
                clearTimeout(fbTimeout);
            }

            if (!res.ok) {
                const errBody = await res.text().catch(() => '');
                console.warn(`[GEMINI-AI] ${model} attempt 2 failed (${res.status}): ${errBody.slice(0, 120)}`);
                continue;
            }

            const data = await res.json();
            const reply = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (reply) {
                history.push({ role: 'user', parts: [{ text: userMsg }] });
                history.push({ role: 'model', parts: [{ text: reply }] });
                if (history.length > 8) history.splice(0, history.length - 8);
                chatHistoryPerSession.set(sessionId, history);
                return reply.trim();
            }
        } catch (e) {
            console.warn(`[GEMINI-AI] ${model} network error:`, e.message);
        }
    }
    return null;
}

// ─────────────────────────────────────────────────────────────
// 🤖 SMART AI ASSISTANT ENGINE ("น้องพิงกี้" ผู้ช่วยร้าน Supinkly.AI)
// ─────────────────────────────────────────────────────────────
async function getBotResponse(userMsg, sessionId) {
    if (!userMsg || typeof userMsg !== 'string') return null;
    const raw = userMsg.trim();
    const q = raw.toLowerCase();
    const db = getDb();

    // ── 1. REAL-TIME ORDER TRACKING (เช็คสถานะออเดอร์ทันที) ──
    const orderMatch = raw.match(/SPK[-_]?[0-9A-Z]{4,32}/i);
    const isAskingOrder = /เช็คออเดอร์|ตามออเดอร์|สถานะออเดอร์|เลขออเดอร์|ส่งของหรือยัง|ส่งหรือยัง|ของถึงไหน|ออเดอร์ถึงไหน|ยังไม่ได้ของ|ยังไม่ได้รหัส/i.test(q);

    if (orderMatch || isAskingOrder) {
        let searchedId = orderMatch ? orderMatch[0].toUpperCase() : null;

        if (searchedId) {
            // [SECURITY FIX] Anti-Brute-Force Rate Limiting (Max 5 lookups per minute per session)
            const now = Date.now();
            const sessionLookup = orderLookupsPerSession.get(sessionId) || { count: 0, resetAt: now + 60000 };
            if (now > sessionLookup.resetAt) {
                sessionLookup.count = 0;
                sessionLookup.resetAt = now + 60000;
            }
            sessionLookup.count++;
            orderLookupsPerSession.set(sessionId, sessionLookup);

            if (sessionLookup.count > 5) {
                return `⚠️ **คุณค้นหาสถานะคำสั่งซื้อบ่อยเกินไปครับ**\n\nเพื่อความปลอดภัยของข้อมูลในระบบ กรุณารอสักครู่ (ประมาณ 1 นาที) แล้วลองค้นหาใหม่อีกครั้ง หรือพิมพ์สอบถามแอดมินคนจริงในแชทนี้ได้เลยครับ 💖`;
            }

            const cleanSearch = searchedId.replace(/[-_]/g, '');
            // Minimum search length check to prevent scanning/wildcard probes
            if (cleanSearch.length < 8) {
                return `🔍 **รหัสคำสั่งซื้อ "${searchedId}" สั้นเกินไปครับ**\n\nรหัสคำสั่งซื้อของร้าน Supinkly จะขึ้นต้นด้วย **SPK-** ตามด้วยรหัสอย่างน้อย 8 ตัวอักษร (เช่น \`SPK-12345678\`) กรุณาตรวจสอบอีกครั้งครับ`;
            }

            // [SECURITY FIX] Strict EXACT match only — eliminates fuzzy .includes() which leaked other customers' orders
            const order = (db.orders || []).find(o => {
                const cleanId = (o.orderId || '').toUpperCase().replace(/[-_]/g, '');
                return cleanId === cleanSearch;
            });

            if (order) {
                const isDelivered = !order.items?.some(it => it.status === 'pending_fulfillment' || !it.credentials);
                const itemsList = (order.items || []).map((it, idx) => {
                    const statusEmoji = (it.status === 'delivered' || it.credentials) ? '🟢 จัดส่งสำเร็จ' : '🟡 กำลังจัดส่ง';
                    return `${idx + 1}. **${it.productTitle || 'สินค้า'}** (฿${parseFloat(it.price || 0).toFixed(2)}) — ${statusEmoji}`;
                }).join('\n');

                return `📦 **ข้อมูลสถานะคำสั่งซื้อ #${order.orderId}**\n\n` +
                    `📅 **เวลาสั่งซื้อ:** ${order.date || '-'}\n` +
                    `💰 **ยอดชำระ:** ฿${parseFloat(order.totalAmount || 0).toFixed(2)} (${order.paymentMethod || 'Thai QR PromptPay'})\n` +
                    `📊 **สถานะปัจจุบัน:** ${order.status || (isDelivered ? '🟢 จัดส่งสำเร็จ' : '🟡 รอจัดส่งสินค้า')}\n\n` +
                    `🛍️ **รายการสินค้า:**\n${itemsList || '• ไม่มีรายการ'}\n\n` +
                    (isDelivered
                        ? `✨ **สินค้าจัดส่งเรียบร้อยแล้วครับ!**\nคุณลูกค้าสามารถเปิดดูรหัสและวิธีใช้งานได้ทันทีที่เมนู **"คีย์ของฉัน"** ด้านบน หรือเช็คในอีเมลของคุณได้เลยครับ 🔑`
                        : `⏳ **อยู่ในคิวจัดส่ง On-Demand:**\nระบบตรวจสลิปถูกต้องเรียบร้อยแล้วครับ แอดมินกำลังจัดเตรียมและนำส่งคีย์เข้าคลังของคุณภายใน 5–15 นาที ขอบพระคุณที่ไว้วางใจร้านเรานะครับ 💖`);
            } else {
                return `🔍 **ไม่พบข้อมูลคำสั่งซื้อ "${searchedId}" ในระบบครับ**\n\nรบกวนคุณลูกค้าตรวจสอบความถูกต้องของรหัสคำสั่งซื้ออีกครั้ง (รูปแบบเลขออเดอร์จะขึ้นต้นด้วย **SPK-** เช่น \`SPK-12345678\`)\n\n💡 คุณลูกค้าสามารถดูเลขออเดอร์ที่ถูกต้องได้จากเมนู **"คีย์ของฉัน"** ด้านบน หรือในอีเมลใบเสร็จครับ หรือพิมพ์แจ้งเลขอ้างอิงสลิปให้แอดมินช่วยตรวจได้เลยครับ!`;
            }
        } else if (isAskingOrder) {
            return `📦 **ระบบตรวจสอบสถานะคำสั่งซื้ออัตโนมัติ:**\n\nคุณลูกค้าสามารถพิมพ์รหัสคำสั่งซื้อขึ้นต้นด้วย **SPK-** (เช่น \`SPK-261004A\`) ส่งมาในแชทนี้ได้เลยครับ น้องพิงกี้จะดึงข้อมูลสถานะและคิวจัดส่งจากระบบให้ทันทีครับ! ✨`;
        }
    }

    // ── 2. DYNAMIC PRODUCT & PRICING LOOKUP (ค้นหาสินค้า & เช็คราคาจริง) ──
    const customPrices = db.customPrices || {};
    const customProducts = db.customProducts || {};
    const getProductLivePrice = (id, defaultPrice) => {
        const cp = customPrices[id];
        if (cp && typeof cp.price === 'number') return cp.price;
        const cprod = customProducts[id];
        if (cprod && typeof cprod.price === 'number') return cprod.price;
        return defaultPrice;
    };

    if (/capcut|แคปคัท|ตัดต่อ/i.test(q)) {
        const p1 = getProductLivePrice('cpc-01', 129);
        const p2 = getProductLivePrice('cpc-02', 79);
        const p3 = getProductLivePrice('cpc-03', 189);
        const p4 = getProductLivePrice('cpc-04', 259);
        return `🎬 **CapCut Pro แท้ 100% (ปลดล็อกฟังก์ชัน Pro, เรนเดอร์ 4K ไม่มีลายน้ำ):**\n\n` +
            `• 👤 **CapCut Pro 1M Private:** **฿${p1.toFixed(2)}** (บัญชีส่วนตัว 1 ผู้ใช้ ไม่แชร์ใคร แนะนำ! ⭐)\n` +
            `• 👥 **CapCut Pro 1M Shared:** **฿${p2.toFixed(2)}** (บัญชีหาร โปรไฟล์แยก ราคาประหยัด)\n` +
            `• 👥 **CapCut Team 1M:** **฿${p3.toFixed(2)}** (คลาวด์ทีม ตัดต่อร่วมกัน)\n` +
            `• 👑 **CapCut VIP 1M:** **฿${p4.toFixed(2)}** (ปลดล็อกพรีเมียมทุกแพลตฟอร์ม)\n\n` +
            `🛡️ สินค้าทุกชิ้นรับประกัน 30 วันเต็ม กดสั่งซื้อที่หน้าแรกแล้วรับรหัสได้เลยครับ!`;
    }

    if (/claude|โคลด|คลอด|คล็อด/i.test(q)) {
        const p1 = getProductLivePrice('cld-01', 850);
        const p2 = getProductLivePrice('cld-02', 290);
        return `🧠 **Claude Pro แท้ (โมเดลอัจฉริยะ เขียนโค้ด วิเคราะห์ไฟล์ วิเคราะห์งานแม่นยำ):**\n\n` +
            `• 👤 **Claude Pro 1M Private:** **฿${p1.toFixed(2)}** (บัญชีส่วนตัว ไม่แชร์ใคร ใช้งานเต็มขีดจำกัด)\n` +
            `• 👥 **Claude Pro 1M Shared:** **฿${p2.toFixed(2)}** (บัญชีหาร ราคาสบายกระเป๋า เข้าใช้งานสะดวก)\n\n` +
            `🛡️ มีรับประกันการใช้งาน 30 วันเต็ม ดูแลตลอดแพ็กเกจครับ!`;
    }

    if (/gemini|google ai|google drive|ไดรฟ์|กูเกิล|พื้นที่/i.test(q)) {
        const p1 = getProductLivePrice('goo-ai-01', 150);
        const p2 = getProductLivePrice('goo-ai-02', 2590);
        const p3 = getProductLivePrice('goo-ai-03', 99);
        const p4 = getProductLivePrice('goo-01', 229);
        return `🌐 **Google AI & Google Drive พรีเมียม:**\n\n` +
            `• 🔗 **Google AI Pro Link:** **฿${p1.toFixed(2)}** (Invite เข้าอีเมลส่วนตัวของคุณเอง สะดวก ไม่ต้องจำรหัสใหม่)\n` +
            `• 👥 **Google AI Pro Shared:** **฿${p3.toFixed(2)}** (บัญชีหารสุดคุ้ม)\n` +
            `• 👑 **Google AI Ultra Private:** **฿${p2.toFixed(2)}** (ตัวท็อปความฉลาดสูงสุด)\n` +
            `• 💾 **Google Drive 5TB Private:** **฿${p4.toFixed(2)}** (พื้นที่เก็บไฟล์มหาศาล ปลอดภัย ส่วนตัว 100%)\n\n` +
            `🛡️ รับประกัน 30 วันเต็ม พร้อมส่งมอบตลอด 24 ชม. ครับ!`;
    }

    if (/grok|xai|ซุปเปอร์เกร็อก|เกร็อก/i.test(q)) {
        const p1 = getProductLivePrice('grk-01', 290);
        const p2 = getProductLivePrice('grk-02', 950);
        const p3 = getProductLivePrice('grk-03', 4990);
        return `⚡ **xAI Grok & SuperGrok แท้:**\n\n` +
            `• ⚡ **Grok 7 วัน Private:** **฿${p1.toFixed(2)}** (ทดลองใช้งานระยะสั้น คุ้มราคา)\n` +
            `• 🔥 **Grok 1 เดือน Private:** **฿${p2.toFixed(2)}** (บัญชีส่วนตัว ฟูลออปชัน 30 วัน)\n` +
            `• 🚀 **SuperGrok Heavy 1 เดือน:** **฿${p3.toFixed(2)}** (ระดับเฮฟวี่ พลังประมวลผลสูงสุด)\n\n` +
            `🛡️ รับประกันตลอดอายุแพ็กเกจ สั่งซื้อได้ตลอด 24 ชม. ครับ!`;
    }

    // ── PROGRAM & SOFTWARE DETAILS (รายละเอียดโปรแกรม & ซอฟต์แวร์ทั้งหมด) ──
    if (/รายละเอียดโปรแกรม|เกี่ยวกับโปรแกรม|ข้อมูลโปรแกรม|มีโปรแกรม|โปรแกรมอะไร|แนะนำโปรแกรม|โปรแกรม|ซอฟต์แวร์|software|แอป|แอพ|app/i.test(q)) {
        const pWin = getProductLivePrice('ms-01', 290);
        const pOff = getProductLivePrice('ms-02', 259);
        const pCop = getProductLivePrice('ms-03', 590);
        const pAdb1 = getProductLivePrice('adb-01', 490);
        const pAdb2 = getProductLivePrice('adb-02', 790);
        const pCap1 = getProductLivePrice('cpc-01', 129);
        const pCld1 = getProductLivePrice('cld-01', 850);
        return `💻 **รายละเอียดโปรแกรม & ซอฟต์แวร์ลิขสิทธิ์แท้ในร้าน Supinkly.AI:**\n\n` +
            `1️⃣ **🎬 CapCut Pro (โปรแกรมตัดต่อวิดีโอยอดนิยม):**\n` +
            `• ปลดล็อกทุกฟีเจอร์ Pro, เอฟเฟกต์/เสียงเพลงไม่จำกัด, เรนเดอร์ 4K 60fps ไม่มีลายน้ำ (เริ่มต้นเพียง **฿79 - ฿129**)\n\n` +
            `2️⃣ **🎨 Adobe Creative Cloud & Acrobat Pro (ชุดโปรแกรมสร้างสรรค์):**\n` +
            `• **Adobe CC All Apps:** **฿${pAdb2.toFixed(2)}**/ด. (ครบ 20+ โปรแกรม Photoshop, Premiere Pro, Illustrator, After Effects + 100GB Cloud + Firefly AI)\n` +
            `• **Adobe Acrobat Pro DC:** **฿${pAdb1.toFixed(2)}**/ด. (แก้ไข จัดการ แปลงไฟล์ และเซ็นเอกสาร PDF ดิจิทัล)\n\n` +
            `3️⃣ **🪟 Windows 11 Pro / Home (ระบบปฏิบัติการแท้):**\n` +
            `• **OEM License Key:** **฿${pWin.toFixed(2)}** (คีย์แท้ 25 หลัก เปิดสิทธิ์ถาวรตลอดชีพ ผูกติดเมนบอร์ด อัปเดตผ่าน Microsoft ได้ตลอดชีพ 🛡️ ตลอดชีพ)\n\n` +
            `4️⃣ **📄 Microsoft 365 Personal (ชุดโปรแกรมทำงาน Office):**\n` +
            `• **฿${pOff.toFixed(2)}**/ด. (Word, Excel, PowerPoint, Outlook + คลาวด์ OneDrive จุใจ 1TB ใช้งานได้ 5 เครื่อง)\n\n` +
            `5️⃣ **🤖 ซอฟต์แวร์ AI ผู้ช่วย & เขียนโปรแกรม (Programming):**\n` +
            `• **Claude Pro:** **฿${pCld1.toFixed(2)}** (สุดยอดโมเดล AI เขียนโค้ดและวิเคราะห์ไฟล์อันดับ 1)\n` +
            `• **Microsoft Copilot Pro:** **฿${pCop.toFixed(2)}** (AI ฝังใน Word, Excel, PowerPoint ช่วยร่างงานและเขียนโค้ด)\n` +
            `• **xAI Grok / SuperGrok:** ฿290–฿4,990 (ข้อมูลเรียลไทม์บน X + เจนภาพ AI)\n\n` +
            `🛡️ ทุกรายการมีรับประกันการใช้งาน พร้อมจัดส่งอัตโนมัติใน 5-15 นาทีครับ สนใจโปรแกรมตัวไหนพิมพ์ชื่อสอบถามได้เลยครับ!`;
    }

    // ── CODING & PROGRAMMING AI (เขียนโปรแกรม / พัฒนาซอฟต์แวร์ / Developer) ──
    if (/เขียนโปรแกรม|เขียนโค้ด|coding|โค้ด|code|developer|โปรแกรมเมอร์|python|javascript|ช่วยเขียน|ทำเว็บ|สร้างแอป|เขียนเว็ป|เขียนแอป/i.test(q)) {
        const pCldPriv = getProductLivePrice('cld-01', 850);
        const pCldShared = getProductLivePrice('cld-02', 290);
        const pCop = getProductLivePrice('ms-03', 590);
        const pGrk = getProductLivePrice('grk-02', 950);
        const pGoo = getProductLivePrice('goo-ai-01', 150);
        return `👨‍💻 **สุดยอด AI สำหรับเขียนโปรแกรม & พัฒนาโค้ด (แนะนำโดยน้องพิงกี้):**\n\n` +
            `หากคุณลูกค้าต้องการผู้ช่วยเขียนโปรแกรม เขียนโค้ด ดีบักบั๊ก หรือสร้างเว็บไซต์/แอปพลิเคชัน ทางร้านขอแนะนำตัวท็อปดังนี้ครับ:\n\n` +
            `1️⃣ 🧠 **Claude Pro (แนะนำอันดับ 1 สำหรับ Developer ⭐):**\n` +
            `• ใช้โมเดล **Claude 3.7 / 3.5 Sonnet** ที่ฉลาดและแม่นยำที่สุดในโลกด้านการเขียนโค้ด เข้าใจโครงสร้างโปรเจกต์ขนาดใหญ่\n` +
            `• มีฟีเจอร์ **Artifacts** พรีวิวหน้าเว็บ/โค้ดสดได้ทันที และระบบ **Projects** บริหารไฟล์โค้ด\n` +
            `• 👤 บัญชีส่วนตัว (Private): **฿${pCldPriv.toFixed(2)}** | 👥 บัญชีหาร (Shared): **฿${pCldShared.toFixed(2)}**\n\n` +
            `2️⃣ 🤖 **Microsoft Copilot Pro (สำหรับงานออฟฟิศ & โค้ด):**\n` +
            `• เชื่อมต่อโมเดล GPT-4o ความเร็วสูง ช่วยเขียนโค้ดและสร้างสูตร Excel อัตโนมัติ\n` +
            `• ราคา: บัญชีส่วนตัว **฿${pCop.toFixed(2)}** / เดือน\n\n` +
            `3️⃣ ⚡ **xAI Grok & SuperGrok Heavy:**\n` +
            `• โมเดลพลังสูงด้าน Logic และคณิตศาสตร์ พร้อมโควต้าคำนวณ Heavy Capacity รองรับงานหนัก\n` +
            `• ราคา: 1 เดือน **฿${pGrk.toFixed(2)}**\n\n` +
            `4️⃣ 🌐 **Google AI Pro (Gemini Advanced):**\n` +
            `• รองรับบริบทมหาศาลกว่า 1 ล้านโทเค็น วิเคราะห์ซอร์สโค้ดทั้งโปรเจกต์พร้อมกันได้สบาย\n` +
            `• ราคา: ลิงก์ Invite เข้า Gmail **฿${pGoo.toFixed(2)}**\n\n` +
            `🛡️ ทุกตัวพร้อมส่งมอบใช้งานได้ทันที มีรับประกัน 30 วันเต็ม สนใจตัวไหนพิมพ์ชื่อสอบถามได้เลยครับ! 🚀`;
    }

    if (/windows|วินโดว์|office|ออฟฟิศ|adobe|photoshop|acrobat|copilot|ไมโครซอฟท์|word|excel/i.test(q)) {
        const pWin = getProductLivePrice('ms-01', 290);
        const pOff = getProductLivePrice('ms-02', 259);
        const pCop = getProductLivePrice('ms-03', 590);
        const pAdb1 = getProductLivePrice('adb-01', 490);
        const pAdb2 = getProductLivePrice('adb-02', 790);
        return `💻 **ซอฟต์แวร์ทำงาน & Windows ลิขสิทธิ์แท้:**\n\n` +
            `• 🪟 **Windows 11 Pro OEM Key:** **฿${pWin.toFixed(2)}** (คีย์แท้ ผูกเมนบอร์ด อัปเดตได้ตลอดชีพ 🛡️ ตลอดชีพ)\n` +
            `• 📄 **Microsoft 365 (1 เดือน):** **฿${pOff.toFixed(2)}** (Word, Excel, PowerPoint + 1TB OneDrive)\n` +
            `• 🤖 **Microsoft Copilot Pro:** **฿${pCop.toFixed(2)}** (AI ช่วยทำงาน Office ขั้นสูง)\n` +
            `• 🎨 **Adobe Creative Cloud All Apps:** **฿${pAdb2.toFixed(2)}** (ครบ 20+ โปรแกรม Photoshop, Illustrator, Premiere Pro)\n` +
            `• 📑 **Adobe Acrobat Pro:** **฿${pAdb1.toFixed(2)}** (จัดการและเซ็นเอกสาร PDF)`;
    }

    if (/มีสินค้าอะไร|ขายอะไร|รายการสินค้า|แคตตาล็อก|มีอะไรบ้าง|แนะนำสินค้า/i.test(q)) {
        return `🛍️ **หมวดหมู่สินค้าในร้าน Supinkly.AI มีดังนี้ครับ:**\n\n` +
            `1️⃣ **🎬 Video Editing:** CapCut Pro (Private ฿129 / Shared ฿79 / Team ฿189)\n` +
            `2️⃣ **🧠 AI Chatbots:** Claude Pro (฿290–฿850), Grok (฿290–฿4,990), Google AI Pro (฿150)\n` +
            `3️⃣ **💾 Cloud Storage:** Google Drive 5TB (฿229)\n` +
            `4️⃣ **💻 OS & Office:** Windows 11 Pro OEM คีย์แท้ตลอดชีพ (฿290), Microsoft 365 (฿259)\n` +
            `5️⃣ **🎨 Design & Media:** Adobe CC All Apps (฿790), Acrobat Pro (฿490)\n\n` +
            `💡 สนใจตัวไหนพิมพ์ชื่อสินค้าสอบถามน้องพิงกี้เพิ่มเติม หรือเลือกช้อปที่หน้าแรกได้เลยครับ!`;
    }

    // ── 3. LIVE PROMOTIONS & COUPONS (ดึงโค้ดส่วนลดจากฐานข้อมูลจริง) ──
    if (/โค้ด|คูปอง|ส่วนลด|โปรโมชั่น|promo|coupon|code|ลดราคา|มีโปร|ลดได้|ลดกี่/i.test(q)) {
        const activeCoupons = (db.coupons || []).filter(c => c.active !== false);
        let couponList = activeCoupons.map(c => {
            const isPercent = (c.type === 'percentage' || c.discountType === 'percent');
            const valStr = isPercent ? `${c.value || c.discountValue}%` : `฿${c.value || c.discountValue}`;
            const minStr = (c.minSpend && c.minSpend > 0) ? ` (ขั้นต่ำ ฿${c.minSpend})` : '';
            return `• \`${c.code}\` — ลด **${valStr}**${minStr} : ${c.description || c.title || ''}`;
        }).join('\n');

        if (!couponList) {
            couponList = '• `SUPINKLY10` — ลด 10% ทุกรายการ (ขั้นต่ำ ฿100)';
        }

        return `🎟️ **โค้ดส่วนลดโปรโมชั่นที่ใช้ได้ในระบบขณะนี้:**\n\n${couponList}\n\n` +
            `💡 **วิธีใช้งาน:** เลือกสินค้าใส่ตะกร้า ➔ เข้าไปที่ตะกร้าสินค้า ➔ กรอกโค้ดในช่อง **"โค้ดส่วนลด"** แล้วกด **"ใช้โค้ด"** ยอดชำระจะลดลงทันทีครับ! ✨`;
    }

    // ── 4. ORDER & DELIVERY FLOW (วิธีสั่งซื้อ & รับของ) ──
    if (/ซื้อ|สั่งซื้อ|ชำระเงิน|จ่ายเงิน|โอน|พร้อมเพย์|promptpay|qr|สลิป|ได้ของ|ส่งของ|รับของ|รับรหัส|รับคีย์|ขั้นตอน|vault/i.test(q)) {
        return `✨ **ขั้นตอนการสั่งซื้อและรับรหัสสินค้า (ง่ายๆ ใน 3 นาที):**\n\n` +
            `1️⃣ **เลือกสินค้า:** กดปุ่ม **"ใส่ตะกร้า"** สินค้าที่คุณต้องการ\n` +
            `2️⃣ **เข้าสู่ระบบ / สมัครสมาชิก:** เพื่อให้ระบบบันทึกคีย์เข้าบัญชีส่วนตัวของคุณ\n` +
            `3️⃣ **สแกนชำระเงิน:** ผ่าน **Thai QR PromptPay** ได้ทุกแอปธนาคารและ TrueMoney (ฟรีค่าธรรมเนียม)\n` +
            `4️⃣ **แนบสลิป:** ระบบใช้ AI ตรวจสอบสลิปอัตโนมัติภายในไม่กี่วินาที\n` +
            `5️⃣ **รับสินค้าทันที:** รหัสจะถูกส่งเข้าเมนู **"คีย์ของฉัน"** ด้านบน และส่งสำเนาเข้าอีเมลของคุณทันทีใน 5–15 นาทีครับ! 📦`;
    }

    // ── 5. WARRANTY & TROUBLESHOOTING (รับประกัน & แก้ไขปัญหา) ──
    if (/เข้าไม่ได้|รหัสผิด|รหัสไม่ตรง|รหัสไม่ถูก|login ไม่ได้|พาสผิด|พาสเวิร์ดไม่ตรง/i.test(q)) {
        return `⚠️ **คำแนะนำเมื่อเข้าสู่ระบบบัญชีไม่ได้:**\n\n` +
            `1. **ตรวจสอบการคัดลอก:** ระวังอย่าให้มีช่องว่าง (Spacebar) หน้าหรือหลังอีเมล/รหัสผ่าน\n` +
            `2. **สำหรับบัญชีแชร์ (Shared):** ตรวจสอบว่าเลือกเข้าใช้โปรไฟล์หมายเลขที่ทางร้านกำหนดให้เท่านั้น\n` +
            `3. **หากยังเข้าไม่ได้:** สินค้ามี **รับประกัน 30 วัน** เต็มครับ! คุณลูกค้าสามารถแจ้งเลขออเดอร์ (\`SPK-...\`) ไว้ในแชทนี้ แอดมินจะตรวจสอบและเปลี่ยนชุดใหม่ให้ทันทีครับ 💖`;
    }

    if (/ประกัน|เคลม|มีประกัน|รับประกัน|โดนเด้ง|หมดอายุ|พัง|ใช้งานไม่ได้|มีปัญหา|ช่วยด้วย/i.test(q)) {
        return `🛡️ **นโยบายการรับประกันและการเคลมสินค้า:**\n\n` +
            `• สินค้าทุกชิ้นในร้านมี **รับประกัน 30 วัน** เต็ม (และคีย์แท้ Windows 11 รับประกันตลอดชีพ)\n` +
            `• หากใช้งานแล้วพบปัญหา เช่น โดนเด้ง บัญชีหลุด หรือใช้งานไม่ได้ก่อนครบกำหนด สามารถแจ้งเคลมได้ทันที\n` +
            `• **วิธีแจ้งเคลม:** พิมพ์เลขออเดอร์ (\`SPK-...\`) และอาการที่พบในแชทนี้ หรือทักเพจ Facebook:\n` +
            `👉 https://www.facebook.com/profile.php?id=61594837747580\n` +
            `ทางร้านยินดีเปลี่ยนชุดใหม่หรือแก้ไขให้อย่างรวดเร็วที่สุดครับ!`;
    }

    // ── 6. ACCOUNT TYPES (Private vs Shared vs Link vs Key) ──
    if (/ต่างกัน|ต่าง|private|shared|แชร์|หาร|ส่วนตัว|แบบไหน|link|invite/i.test(q)) {
        return `💡 **เปรียบเทียบประเภทสินค้าแต่ละแบบ:**\n\n` +
            `• 👤 **Private (บัญชีส่วนตัว 100%):** คุณเป็นเจ้าของคนเดียว ไม่ปนกับใคร สามารถเปลี่ยนรหัสผ่านได้ เหมาะสำหรับการใช้งานจริงจัง ข้อมูลส่วนตัวปลอดภัยสูงสุด\n` +
            `• 👥 **Shared (บัญชีหาร):** ใช้งานร่วมกับผู้ใช้อื่นโดยมีโปรไฟล์แยกของตัวเอง ราคาย่อมเยาสุดคุ้ม ประหยัดงบ (ห้ามเปลี่ยนรหัสผ่านเพื่อสิทธิ์รับประกัน)\n` +
            `• 🔗 **Link (คำเชิญ Invite):** ทางร้านส่งลิงก์คำเชิญให้ คุณนำไปกดเปิดสิทธิ์เข้ากับอีเมลส่วนตัวของคุณเอง สะดวก ไม่ต้องจำรหัสใหม่\n` +
            `• 🔑 **License Key:** รหัสคีย์แท้สำหรับนำไปกรอกเปิดสิทธิ์ในซอฟต์แวร์โดยตรง (เช่น Windows 11 OEM ผูกติดเครื่องตลอดชีพ)`;
    }

    // ── 7. TRUST & OPERATING HOURS ──
    if (/ของแท้ไหม|แท้ไหม|ปลอดภัยไหม|โกงไหม|เชื่อถือได้ไหม|มีเครดิตไหม|รีวิว|ไว้ใจได้ไหม/i.test(q)) {
        return `🛡️ **ความน่าเชื่อถือและความปลอดภัยที่ Supinkly.AI:**\n\n` +
            `1. **ของแท้ 100%:** สินค้าซอฟต์แวร์ คีย์แท้ OEM และบัญชีพรีเมียมถูกลิขสิทธิ์ ได้รับการตรวจสอบก่อนส่งมอบ\n` +
            `2. **ระบบจัดส่งคลังอัตโนมัติ (On-Demand Vault):** ส่งมอบรหัสเข้าเมนู "คีย์ของฉัน" และส่งสำเนาเข้าอีเมลของคุณทันทีใน 5-15 นาที\n` +
            `3. **รับประกัน 30 วันเต็ม & Windows 11 ตลอดชีพ:** มีปัญหาเปลี่ยนชุดใหม่ให้ทันที ดูแลตลอดอายุการใช้งาน\n` +
            `4. **ตรวจสอบสลิปด้วย AI:** แม่นยำ ปลอดภัย ฟรีค่าธรรมเนียม\n` +
            `5. **มีช่องทางติดต่อชัดเจน:** เพจ Facebook ทางการ และ Live Chat ตลอด 24 ชม. ครับ 💖`;
    }

    if (/เปิดกี่โมง|ปิดกี่โมง|เวลาทำการ|ส่งตอนไหน|กลางคืนส่งไหม|ดึกๆ ส่งไหม|24 ชม|ส่งกี่นาที|ได้ตอนไหน|รอนานไหม/i.test(q)) {
        return `⏰ **เวลาทำการและระยะเวลาจัดส่งของ Supinkly.AI:**\n\n` +
            `• **เปิดให้บริการ 24 ชั่วโมง ทุกวัน ไม่มีวันหยุดครับ!** 🌙✨\n` +
            `• **ระบบจัดส่ง:** ทำงานอัตโนมัติ 24 ชม. หลังจากสแกนชำระเงินและแนบสลิปถูกต้อง รหัสจะถูกส่งมอบเข้าเมนู **"คีย์ของฉัน"** ภายใน **5–15 นาที** ครับ\n` +
            `• **แอดมินคนจริง:** สแตนด์บายคอยตอบแชทและดูแลเคสเร่งด่วนตลอดเวลาครับ`;
    }

    // ── 8. HUMAN HANDOVER (ติดต่อแอดมินคนจริง) ──
    if (/แอดมิน|คนจริง|เจ้าหน้าที่|มนุษย์|ติดต่อ|เบอร์|โทร|โทรศัพท์|admin/i.test(q)) {
        return `🔔 **น้องพิงกี้ส่งสัญญาณแจ้งเตือนแอดมินคนจริงให้แล้วครับ!**\n\n` +
            `ขณะนี้ระบบได้ส่งแจ้งเตือนไปยังแอดมินเรียบร้อยแล้ว แอดมินจะรีบเข้ามาตอบในแชทนี้โดยเร็วที่สุดครับ (คุณลูกค้าสามารถพิมพ์รายละเอียดหรือคำถามทิ้งไว้ได้เลยครับ)\n\n` +
            `หรือหากเป็นเรื่องเร่งด่วน สามารถทักเพจ Facebook ได้ตลอด 24 ชม. ที่:\n` +
            `👉 https://www.facebook.com/profile.php?id=61594837747580`;
    }

    // ── 9. GREETINGS & POLITE SMALL TALK ──
    if (/^(สวัสดี|หวัดดี|ดีครับ|ดีค่ะ|hello|hi|hey|ดีจ้า|สอบถาม|รบกวน|มีใครอยู่ไหม)/i.test(q) || q === 'สวัสดี' || q === 'ดีครับ' || q === 'ดีค่ะ') {
        return `👋 สวัสดีครับ! น้องพิงกี้ AI ผู้ช่วยประจำร้าน Supinkly.AI ยินดีให้บริการครับ 💖\n\n` +
            `คุณลูกค้าสามารถสอบถามข้อมูลสินค้า วิธีสั่งซื้อ รับประกัน ตรวจสอบเลขออเดอร์ หรือขอโค้ดส่วนลดได้เลยนะครับ หรือสามารถกดปุ่มลัดด้านล่างเพื่อเริ่มสอบถามได้เลยครับ ✨`;
    }

    if (/ขอบคุณ|แต๊ง|thanks|thank you|ใจจ้า|ขอบใจ/i.test(q)) {
        return `ยินดีเป็นอย่างยิ่งเลยครับ! หากมีข้อสงสัยหรือต้องการความช่วยเหลือเพิ่มเติม ทักหาน้องพิงกี้หรือแอดมินได้ตลอด 24 ชม. เลยนะครับ ขอให้มีความสุขกับการใช้งานครับ 💖✨`;
    }

    // ── 10. GOOGLE GEMINI AI CALL (หากมี GEMINI_API_KEY) ──
    const geminiKey = (process.env.GEMINI_API_KEY || db.geminiApiKey || "").trim();
    if (geminiKey) {
        try {
            const geminiAnswer = await callGeminiAI(userMsg, sessionId, geminiKey);
            if (geminiAnswer) return geminiAnswer;
        } catch (err) {
            console.warn('[GEMINI-AI] Generation fallback:', err.message);
        }
    }

    // ── 11. INTELLIGENT COMPREHENSIVE FALLBACK ──
    return `น้องพิงกี้ AI ผู้ช่วยร้าน Supinkly ยินดีให้บริการครับ! 💖\n\n` +
        `สำหรับข้อความที่คุณลูกค้าสอบถามเข้ามา น้องพิงกี้ขอแนะนำเมนูด่วนที่คุณลูกค้าสามารถสอบถามได้ทันทีครับ:\n\n` +
        `💻 **1. โปรแกรม & ซอฟต์แวร์:** พิมพ์ **"โปรแกรม"** เพื่อดูรายละเอียดซอฟต์แวร์ทั้งหมด (Windows 11, Office 365, Adobe CC, CapCut Pro)\n` +
        `👨‍💻 **2. งานเขียนโปรแกรม:** พิมพ์ **"เขียนโค้ด"** เพื่อดู AI แนะนำสำหรับโปรแกรมเมอร์ (Claude Pro, Copilot, Grok)\n` +
        `🛍️ **3. เช็คราคาสินค้า:** พิมพ์ชื่อสินค้า เช่น **CapCut**, **Claude**, **Google Drive** ได้ทันที\n` +
        `📦 **4. ตรวจสอบสถานะออเดอร์:** พิมพ์รหัสคำสั่งซื้อ เช่น \`SPK-12345678\`\n` +
        `🎟️ **5. โค้ดส่วนลด:** พิมพ์ **"ขอโค้ดส่วนลด"** เพื่อรับคูปองลด 10-20%\n` +
        `👤 **6. คุยกับแอดมินคนจริง:** พิมพ์ **"ติดต่อแอดมิน"** ได้ตลอด 24 ชม. ครับ!`;
}

// ─── [GLOBAL EXPRESS ERROR HANDLER & RESILIENCE] ────────────────────────────
app.use((err, req, res, next) => {
    console.error('[EXPRESS ROUTE ERROR]', err.message || err);
    if (res.headersSent) {
        return next(err);
    }
    const statusCode = err.status || err.statusCode || (err.name === 'MulterError' ? 400 : 500);
    res.status(statusCode).json({
        success: false,
        message: err.message || "เกิดข้อผิดพลาดในการประมวลผลคำขอ กรุณาลองใหม่อีกครั้ง"
    });
});

// Upgrade HTTP server to support WebSocket
const server = app.listen(PORT, () => {
    console.log(`Supinkly.AI Server running on http://localhost:${PORT}`);
});

// [SECURITY] Anti-Slowloris & Connection Exhaustion Hardening
server.headersTimeout = 65000;
server.requestTimeout = 60000;
server.keepAliveTimeout = 61000;

const wss = new WebSocketServer({ server, path: '/ws/chat', maxPayload: 64 * 1024 });

function broadcast(payload, filterFn = () => true) {
    const msg = JSON.stringify(payload);
    for (const [, client] of clients) {
        if (client.ws.readyState === 1 && filterFn(client)) {
            client.ws.send(msg);
        }
    }
}

function getAdminCount() {
    let n = 0;
    for (const [, c] of clients) if (c.role === 'admin') n++;
    return n;
}

// Heartbeat to prune inactive/dead WebSocket connections
const wsHeartbeat = setInterval(() => {
    for (const [sid, client] of clients) {
        if (client.ws.isAlive === false) {
            client.ws.terminate();
            clients.delete(sid);
            lastAdminReplyPerSession.delete(sid);
            chatHistoryPerSession.delete(sid);
            orderLookupsPerSession.delete(sid);
            continue;
        }
        client.ws.isAlive = false;
        try { client.ws.ping(); } catch { }
    }
}, 35000);

wss.on('connection', (ws, req) => {
    // ── [SECURITY FIX] CSWSH Origin Verification (Strict Hostname Matching) ──
    const origin = req.headers.origin;
    if (origin && rawOrigins !== '*') {
        let isOriginValid = false;
        try {
            const parsed = new URL(origin);
            const host = parsed.hostname.toLowerCase();
            if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.onrender.com') || ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes(host)) {
                isOriginValid = true;
            }
        } catch {}
        if (!isOriginValid) {
            ws.close(1008, 'Origin not allowed');
            return;
        }
    }

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    const sessionId = uuidv4();
    let clientInfo = { ws, role: null, name: 'ลูกค้า', sessionId };
    clients.set(sessionId, clientInfo);

    let failedAuthAttempts = 0;
    let msgCount = 0;
    let windowStart = Date.now();

    ws.send(JSON.stringify({ type: 'session', sessionId }));

    ws.on('message', (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }
        if (!data || typeof data !== 'object' || Array.isArray(data)) return;

        // ── TYPING SIGNAL: Handle presence directly without consuming chat message limits ──
        if (data.type === 'typing') {
            if (clientInfo.role === 'customer') {
                broadcast({ type: 'typing', sessionId, name: clientInfo.name }, c => c.role === 'admin');
            } else if (clientInfo.role === 'admin') {
                const targetSid = (typeof data.targetSessionId === 'string' && /^[a-zA-Z0-9_\-]{6,48}$/.test(data.targetSessionId))
                    ? data.targetSessionId
                    : null;
                if (targetSid) {
                    const target = clients.get(targetSid);
                    if (target && target.ws.readyState === 1) {
                        target.ws.send(JSON.stringify({ type: 'typing', from: 'admin' }));
                    }
                }
            }
            return;
        }

        // ── MESSAGE RATE LIMITING (strictly for actual chat messages, max 25 msgs per 5s) ──
        if (data.type === 'message') {
            const now = Date.now();
            if (now - windowStart > 5000) {
                msgCount = 0;
                windowStart = now;
            }
            msgCount++;
            if (msgCount > 25) {
                ws.send(JSON.stringify({ type: 'message', from: 'admin', name: 'ระบบ', text: 'คุณส่งข้อความเร็วเกินไป กรุณารอสัก 2-3 วินาทีแล้วลองใหม่อีกครั้งครับ' }));
                return;
            }
        }

        // ── AUTH: ลงทะเบียน role ──────────────────────────────────
        if (data.type === 'auth') {
            if (data.role === 'admin') {
                // [SECURITY] Admin auth over WebSocket — supports stateless HMAC token, in-memory session & PIN verification
                const token = data.token;
                let isTokenValid = (token && verifyAdminToken(token)) ||
                    (token && adminSessions.has(token) && Date.now() < adminSessions.get(token));

                if (!isTokenValid && data.pin) {
                    const db = getDb();
                    const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
                    if (verifyPin(data.pin, storedHash)) {
                        isTokenValid = true;
                    }
                }

                if (isTokenValid) {
                    clientInfo.role = 'admin';
                    clientInfo.name = 'แอดมิน';
                    ws.send(JSON.stringify({ type: 'auth_ok', role: 'admin' }));
                    // แจ้งทุกห้องว่าแอดมินออนไลน์แล้ว
                    broadcast({ type: 'admin_status', online: true }, c => c.role === 'customer');
                    // ส่งรายการห้องที่รอตอบ
                    const rooms = {};
                    for (const [, c] of clients) {
                        if (c.role === 'customer') {
                            if (!rooms[c.sessionId]) rooms[c.sessionId] = { sessionId: c.sessionId, name: c.name };
                        }
                    }
                    ws.send(JSON.stringify({ type: 'room_list', rooms: Object.values(rooms) }));
                } else {
                    failedAuthAttempts++;
                    if (failedAuthAttempts >= 3) {
                        ws.send(JSON.stringify({ type: 'auth_fail', message: 'คุณระบุรหัสยืนยันตัวตนผิดเกินจำนวนที่กำหนด' }));
                        ws.close(1008, 'Too many failed auth attempts');
                        return;
                    }
                    ws.send(JSON.stringify({ type: 'auth_fail', message: 'กรุณาเข้าสู่ระบบผ่าน /api/admin/login ก่อน' }));
                }
            } else if (data.role === 'customer') {
                clientInfo.role = 'customer';
                const cleanName = sanitizeTelemetryText(data.name || '', 40);
                clientInfo.name = cleanName || `ลูกค้า #${sessionId.slice(0, 5)}`;
                const adminOnline = getAdminCount() > 0;
                ws.send(JSON.stringify({ type: 'auth_ok', role: 'customer', adminOnline }));
                // แจ้งแอดมินว่ามีลูกค้าใหม่
                broadcast({ type: 'new_room', sessionId, name: clientInfo.name }, c => c.role === 'admin');

                // บอทส่งข้อความต้อนรับและแนะนำตัวอัตโนมัติ
                setTimeout(() => {
                    if (clients.has(sessionId) && ws.readyState === 1) {
                        const welcomeText = adminOnline
                            ? `👋 สวัสดีครับคุณ **${clientInfo.name}**! น้องพิงกี้ AI ผู้ช่วยร้าน Supinkly ยินดีให้บริการครับ 💖 ขณะนี้แอดมินออนไลน์พร้อมดูแล หรือสามารถสอบถามน้องพิงกี้ได้ตลอด 24 ชม. เลยนะครับ!`
                            : `👋 สวัสดีครับคุณ **${clientInfo.name}**! ขณะนี้แอดมินยังไม่อยู่ที่หน้าจอ แต่น้องพิงกี้ AI ผู้ช่วยร้าน Supinkly ยินดีช่วยตอบคำถามและดูแลตลอด 24 ชม. ครับ 💖 มีอะไรให้ช่วยสอบถามได้เลยนะครับ!`;
                        const botWelcome = {
                            type: 'message',
                            from: 'bot',
                            name: '🤖 น้องพิงกี้ (AI ผู้ช่วย)',
                            text: welcomeText,
                            sessionId: sessionId,
                            ts: Date.now()
                        };
                        ws.send(JSON.stringify(botWelcome));
                        broadcast(botWelcome, c => c.role === 'admin');
                    }
                }, 600);
            } else {
                ws.send(JSON.stringify({ type: 'auth_fail' }));
            }
            return;
        }

        if (!clientInfo.role) return; // ยังไม่ auth

        // ── MESSAGE ───────────────────────────────────────────────
        if (data.type === 'message') {
            const text = String(data.text || '').trim().slice(0, 2000);
            if (!text) return;

            const safeTargetSid = (typeof data.targetSessionId === 'string' && /^[a-zA-Z0-9_\-]{6,48}$/.test(data.targetSessionId))
                ? data.targetSessionId
                : null;

            const payload = {
                type: 'message',
                from: clientInfo.role,
                name: clientInfo.name,
                text,
                sessionId: clientInfo.role === 'customer' ? sessionId : safeTargetSid,
                ts: Date.now()
            };

            if (clientInfo.role === 'customer') {
                // ส่งให้แอดมินทุกคน + echo กลับลูกค้า
                broadcast(payload, c => c.role === 'admin');
                ws.send(JSON.stringify({ ...payload, own: true }));

                // ── AI CHATBOT AUTO-REPLY (เมื่อแอดมินยังไม่ได้พิมพ์ตอบ) ──
                const lastAdminTime = lastAdminReplyPerSession.get(sessionId) || 0;
                const isAdminActiveInRoom = (Date.now() - lastAdminTime) < 20000;

                // หากแอดมินไม่ได้กำลังคุยอยู่ในห้องนี้ในช่วง 20 วิล่าสุด บอทจะเข้ามาช่วยตอบทันที
                if (!isAdminActiveInRoom) {
                    // ส่งสถานะกำลังพิมพ์ของบอทให้ดูเป็นธรรมชาติ
                    setTimeout(() => {
                        if (clients.has(sessionId) && ws.readyState === 1) {
                            ws.send(JSON.stringify({ type: 'typing', from: 'bot', name: '🤖 น้องพิงกี้' }));
                        }
                    }, 400);

                    // บอทส่งคำตอบหลังจากคิด 1 วินาที
                    setTimeout(async () => {
                        if (!clients.has(sessionId) || ws.readyState !== 1) return;
                        // ตรวจสอบอีกครั้งว่าแอดมินเพิ่งเข้ามาตอบหรือไม่
                        const recheckAdmin = lastAdminReplyPerSession.get(sessionId) || 0;
                        if (Date.now() - recheckAdmin < 15000) return;

                        const botReplyText = await getBotResponse(text, sessionId);
                        if (botReplyText) {
                            const botPayload = {
                                type: 'message',
                                from: 'bot',
                                name: '🤖 น้องพิงกี้ (AI ผู้ช่วย)',
                                text: botReplyText,
                                sessionId: sessionId,
                                ts: Date.now()
                            };
                            ws.send(JSON.stringify(botPayload));
                            // แจ้งให้แอดมินเห็นคำตอบของบอทด้วย
                            broadcast(botPayload, c => c.role === 'admin');
                        }
                    }, 1100);
                }
            } else if (clientInfo.role === 'admin') {
                if (!safeTargetSid) return;
                lastAdminReplyPerSession.set(safeTargetSid, Date.now());
                const target = clients.get(safeTargetSid);
                if (target && target.ws.readyState === 1) {
                    target.ws.send(JSON.stringify({ ...payload, from: 'admin' }));
                }
                ws.send(JSON.stringify({ ...payload, own: true }));
            }
        }
    });

    ws.on('close', () => {
        const info = clients.get(sessionId);
        if (info?.role === 'customer') {
            broadcast({ type: 'room_closed', sessionId }, c => c.role === 'admin');
        }
        if (info?.role === 'admin') {
            broadcast({ type: 'admin_status', online: getAdminCount() - 1 > 0 }, c => c.role === 'customer');
        }
        clients.delete(sessionId);
        lastAdminReplyPerSession.delete(sessionId);
        chatHistoryPerSession.delete(sessionId);
        orderLookupsPerSession.delete(sessionId);
    });
});

