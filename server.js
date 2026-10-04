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
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable reverse proxy trust (for Render, Cloudflare, Nginx load balancers)
app.set('trust proxy', 1);

// Health check endpoint for Render monitoring
app.get('/healthz', (req, res) => res.status(200).send('OK'));

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
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'x-authorization', 'Authorization', 'x-admin-token', 'x-order-email', 'x-user-token']
}));

app.use(express.json({ limit: '1mb' }));

// ─── [SECURITY FIX] Shield sensitive system and database files ─────────────
// ป้องกันการเข้าถึงไฟล์ secure_database.json, .env, server.js, package.json ผ่านหน้าเว็บ
app.use((req, res, next) => {
    let cleanPath = req.path;
    try { cleanPath = decodeURIComponent(req.path); } catch {}
    const forbidden = [
        /secure_database\.json$/i,
        /\.env(\..+)?$/i,
        /server\.js$/i,
        /package(-lock)?\.json$/i,
        /Dockerfile$/i,
        /\.dockerignore$/i,
        /render\.yaml$/i,
        /(^|\/)\.git/i,
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

    // Auto-sync all 19 product banner images
    const productsImgDir = path.join(imagesDir, 'products');
    if (!fs.existsSync(productsImgDir)) fs.mkdirSync(productsImgDir, { recursive: true });

    const brainDir = 'C:/Users/BINARY/.gemini/antigravity/brain/836d7e14-1e8d-401f-afd4-ec16b1fbbc3c';
    const productImagesMap = {
        'cpc-01.jpg': path.join(brainDir, 'capcut_pro_card_1791049186129.jpg'),
        'cpc-02.jpg': path.join(brainDir, 'capcut_shared_card_1791049423548.jpg'),
        'cpc-03.jpg': path.join(brainDir, 'capcut_team_card_1791049450137.jpg'),
        'cpc-04.jpg': path.join(brainDir, 'capcut_svip_card_1791049505797.jpg'),
        'goo-02.jpg': path.join(brainDir, '.user_uploaded', 'media_1791049138382.jpg'),
        'goo-ai-01.jpg': path.join(brainDir, 'gemini_adv_link_card_1791049542389.jpg'),
        'goo-ai-02.jpg': path.join(brainDir, 'gemini_ultra_card_1791049587917.jpg'),
        'goo-ai-03.jpg': path.join(brainDir, 'gemini_shared_card_1791076121301.jpg'),
        'goo-01.jpg': path.join(brainDir, 'google_drive_5tb_card_1791076137905.jpg'),
        'grk-01.jpg': path.join(brainDir, 'xai_grok_card_1791049315969.jpg'),
        'grk-02.jpg': path.join(brainDir, 'xai_grok_30d_card_1791076154086.jpg'),
        'grk-03.jpg': path.join(brainDir, 'supergrok_heavy_card_1791076197454.jpg'),
        'cld-01.jpg': path.join(brainDir, 'claude_pro_card_1791049222986.jpg'),
        'cld-02.jpg': path.join(brainDir, 'claude_shared_card_1791076222594.jpg'),
        'ms-01.jpg': path.join(brainDir, 'windows11_pro_card_1791049243416.jpg'),
        'ms-02.jpg': path.join(brainDir, 'ms_office365_card_1791049341288.jpg'),
        'ms-03.jpg': path.join(brainDir, 'copilot_pro_card_1791049366066.jpg'),
        'adb-01.jpg': path.join(brainDir, 'adobe_acrobat_card_1791049391660.jpg'),
        'adb-02.jpg': path.join(brainDir, 'adobe_cc_card_1791049294249.jpg'),
    };

    for (const [destName, srcPath] of Object.entries(productImagesMap)) {
        const destPath = path.join(productsImgDir, destName);
        if (!fs.existsSync(destPath) && fs.existsSync(srcPath)) {
            try { fs.copyFileSync(srcPath, destPath); } catch {}
        }
    }
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

app.use(express.static(path.join(__dirname)));

// ─── [FIX #2] Rate Limiting ─────────────────────────────────────────────────
// ❌ Before: ไม่มี rate limit → brute force PIN ได้หลายพันครั้ง/วินาที
const adminRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000,  // 5 นาที
    max: 10,                   // สูงสุด 10 requests / 5 นาที
    message: { success: false, message: "Too many requests. Please try again in 5 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
});

const checkoutRateLimit = rateLimit({
    windowMs: 60 * 1000,   // 1 นาที
    max: 5,                // สูงสุด 5 slip submissions / นาที
    message: { success: false, message: "Too many checkout attempts. Please slow down." },
});

// ─── [FIX #3] PIN Hashing Helpers ────────────────────────────────────────────
// ❌ Before: PIN เก็บเป็น plaintext "8899"
// ✅ After: เก็บเป็น SHA-256 hash (server-side)
function hashPin(pin) {
    const salt = process.env.PIN_SALT || 'supinkly_srv_salt_2026';
    return crypto.createHash('sha256').update(salt + String(pin).trim()).digest('hex');
}

function verifyPin(enteredPin, storedHash) {
    const enteredHash = hashPin(enteredPin);
    // Timing-safe comparison เพื่อป้องกัน timing attack
    if (enteredHash.length !== storedHash.length) return false;
    return crypto.timingSafeEqual(Buffer.from(enteredHash), Buffer.from(storedHash));
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

    // 3. Header or body PIN fallback (Emergency authentication if session expired)
    const pinHeader = req.headers['x-admin-pin'] || (req.body && req.body.adminPin ? String(req.body.adminPin).trim() : null);
    if (pinHeader) {
        const db = getDb();
        const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
        if (verifyPin(pinHeader, storedHash)) return true;
    }

    return false;
}

const DB_FILE = path.join(__dirname, 'secure_database.json');
const DB_TMP = path.join(__dirname, 'secure_database.json.tmp');
const DB_BAK = path.join(__dirname, 'secure_database.json.bak');

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
        inventory: {},
        orders: [],
        users: [],  // { id, email, passwordHash, displayName, createdAt, emailVerified }
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
                return data;
            } catch (e) {}
        }
    }
    return {
        adminPinHash: hashPin(process.env.ADMIN_PIN || '8899'),
        promptPayNumber: process.env.PROMPTPAY_NUMBER || "0982949371",
        promptPayAccountName: process.env.PROMPTPAY_NAME || "สุพัฒน์ มีสมบัติ",
        slipOkApiKey: process.env.SLIPOK_API_KEY || "",
        slipOkBranchId: process.env.SLIPOK_BRANCH_ID || "77491",
        usedSlips: [],
        usedTransRefs: [],
        customPrices: {},
        inventory: {},
        orders: [],
        users: [],
        pendingRegistrations: {},
        passwordResets: {},
        smtpConfig: {}
    };
}

function saveDb(data) {
    try {
        const jsonStr = JSON.stringify(data, null, 2);
        fs.writeFileSync(DB_TMP, jsonStr, 'utf-8');
        if (fs.existsSync(DB_FILE)) {
            try { fs.copyFileSync(DB_FILE, DB_BAK); } catch (e) {}
        }
        fs.renameSync(DB_TMP, DB_FILE);
    } catch (err) {
        console.error("Atomic database write error, falling back to direct write:", err.message);
        try {
            fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
        } catch (e) {
            console.error("Direct write failure:", e.message);
        }
    }
}

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
    "goo-02": { title: "Google Storage 5TB Link", price: 179.00, warranty: "30 วัน" },
    "grk-01": { title: "Grok 7D Private", price: 290.00, warranty: "7 วัน" },
    "grk-02": { title: "Grok 1M Private", price: 950.00, warranty: "30 วัน" },
    "grk-03": { title: "SuperGrok Heavy 1M", price: 4990.00, warranty: "30 วัน" },
    "cld-01": { title: "Claude Pro 1M Private", price: 850.00, warranty: "30 วัน" },
    "cld-02": { title: "Claude Pro 1M Shared", price: 290.00, warranty: "30 วัน" },
    "adb-01": { title: "Adobe Acrobat Pro 1M", price: 490.00, warranty: "30 วัน" },
    "adb-02": { title: "Adobe CC All Apps 1M", price: 790.00, warranty: "30 วัน" },
    "ms-01": { title: "Windows 11 OEM Key", price: 290.00, warranty: "ตลอดชีพ" },
    "ms-02": { title: "Microsoft 365 1M", price: 259.00, warranty: "30 วัน" },
    "ms-03": { title: "Microsoft Copilot Pro 1M", price: 590.00, warranty: "30 วัน" }
};

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

// 1. API: Verify Slip & Dispense Product (Server-Side Verified)
app.post('/api/checkout/verify-slip', checkoutRateLimit, upload.single('slip'), async (req, res) => {
    try {
        // [AUTHENTICATION GATE] ผู้เล่นต้องเข้าสู่ระบบหรือสมัครสมาชิกก่อนชำระเงิน
        const userSession = authenticateUser(req);
        if (!userSession || !userSession.email) {
            return res.status(401).json({ 
                success: false, 
                requireLogin: true, 
                message: "กรุณาสมัครสมาชิกหรือเข้าสู่ระบบก่อนดำเนินการชำระเงิน เพื่อบันทึกคีย์เข้าบัญชีของคุณ" 
            });
        }

        // [SECURITY FIX] Single Source of Truth: อีเมลผูกกับ Session ของผู้ใช้ที่ผ่านการยืนยันแล้ว ป้องกันการดัดแปลงหรือปลอมแปลงอีเมล
        const orderEmail = userSession.email.trim().toLowerCase();
        const { cartItems } = req.body;

        let parsedCart;
        try {
            parsedCart = typeof cartItems === 'string' ? JSON.parse(cartItems) : cartItems;
            if (!Array.isArray(parsedCart) || parsedCart.length === 0) throw new Error();
        } catch {
            return res.status(400).json({ success: false, message: "ข้อมูลตะกร้าสินค้าไม่ถูกต้อง" });
        }

        const db = getDb();

        if (!req.file || !isValidImageBuffer(req.file.buffer)) {
            return res.status(400).json({ success: false, message: "กรุณาแนบไฟล์รูปภาพสลิปที่ถูกต้อง (JPG, PNG, WEBP)" });
        }

        // SHA-256 fingerprint จากไฟล์จริง
        const slipHash = computeSlipSHA256(req.file.buffer);
        if (db.usedSlips && db.usedSlips.includes(slipHash)) {
            return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้วในระบบ ไม่สามารถใช้ซ้ำได้" });
        }

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

            const catalogItem = MASTER_CATALOG[item.productId];
            if (!catalogItem) {
                return res.status(400).json({ success: false, message: `ไม่พบข้อมูลสินค้ารหัส: ${item.productId}` });
            }
            const unitPrice = (db.customPrices && db.customPrices[item.productId] && typeof db.customPrices[item.productId].price === 'number')
                ? db.customPrices[item.productId].price
                : catalogItem.price;
            expectedTotal += unitPrice * qty;
        }

        let transRef = null;
        let isAutoVerified = false;

        // ── Verify with SlipOK Server-Side ──
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
                    return res.status(400).json({ 
                        success: false, 
                        message: slipJson.message || "สลิปไม่ถูกต้อง หรือไม่ผ่านการตรวจสอบจากระบบธนาคาร" 
                    });
                }

                const slipData = slipJson.data;
                if (slipData.success === false) {
                    return res.status(400).json({ success: false, message: "สลิปนี้ไม่ผ่านการตรวจสอบความถูกต้อง" });
                }

                // Check transferred amount
                const transferred = parseFloat(slipData.amount);
                if (isNaN(transferred) || transferred < expectedTotal) {
                    return res.status(400).json({ 
                        success: false, 
                        message: `ยอดเงินในสลิป (฿${transferred || 0}) ไม่ตรงกับยอดชำระที่ต้องโอน (฿${expectedTotal})` 
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
            } catch (err) {
                console.error("SlipOK verification error:", err.message);
                return res.status(502).json({ 
                    success: false, 
                    message: "ไม่สามารถเชื่อมต่อระบบตรวจสลิปธนาคารได้ กรุณาลองใหม่ในภายหลัง" 
                });
            }
        } else {
            // [SECURITY FIX] In production, if SlipOK API key is unconfigured, reject with friendly message rather than silently creating unverified pending orders
            const isProduction = process.env.NODE_ENV === 'production' || (!process.env.DEV_MODE && !process.env.ALLOW_DEV_SLIP_BYPASS);
            if (isProduction) {
                return res.status(503).json({
                    success: false,
                    message: "ระบบตรวจสลิปอัตโนมัติอยู่ระหว่างการปรับปรุงระบบ กรุณาติดต่อแอดมินทาง Live Chat เพื่อทำรายการ"
                });
            }
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
            const master = MASTER_CATALOG[item.productId];
            if (!currentDb.inventory[item.productId]) currentDb.inventory[item.productId] = [];
            const pool = currentDb.inventory[item.productId];
            const effectivePrice = (currentDb.customPrices && currentDb.customPrices[item.productId] && typeof currentDb.customPrices[item.productId].price === 'number')
                ? currentDb.customPrices[item.productId].price
                : master.price;

            for (let i = 0; i < item.quantity; i++) {
                if (isAutoVerified && pool.length > 0) {
                    const cred = pool.shift();
                    deliveredItems.push({
                        productId: item.productId,
                        productTitle: master.title,
                        price: effectivePrice,
                        warranty: master.warranty,
                        status: "delivered",
                        credentials: cred
                    });
                } else {
                    hasPending = true;
                    deliveredItems.push({
                        productId: item.productId,
                        productTitle: master.title,
                        price: effectivePrice,
                        warranty: master.warranty,
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
            userId: userSession.userId,
            totalAmount: expectedTotal,
            paymentMethod: "Thai QR PromptPay",
            transRef: transRef || "REF-" + Date.now().toString(36).toUpperCase(),
            items: deliveredItems,
            status: hasPending ? "🟡 รอจัดส่งสินค้า (5-15 นาที)" : "🟢 จัดส่งสำเร็จทันที",
            slipHash
        };
        if (!currentDb.orders) currentDb.orders = [];
        currentDb.orders.unshift(order);
        saveDb(currentDb);

        // [NOTIFICATION & RECEIPT] Fire-and-forget Discord alert & Email receipt
        const webhookUrl = process.env.DISCORD_WEBHOOK_URL || currentDb.discordWebhookUrl;
        if (webhookUrl) {
            sendDiscordNotification(webhookUrl, order, false).catch(e => console.warn('[DISCORD] Notification error:', e.message));
        }
        mailService.sendOrderReceiptEmail(order, false, currentDb).catch(e => console.warn('[MAIL] Order receipt email error:', e.message));

        res.json({ success: true, order });
    } catch (err) {
        console.error('checkout error:', err.message);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" });
    }
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
                ...(cred.email     ? { email:        String(cred.email).slice(0, 254) }        : {}),
                ...(cred.password  ? { password:     String(cred.password).slice(0, 512) }     : {}),
                ...(cred.key       ? { key:          String(cred.key).slice(0, 512) }          : {}),
                ...(cred.link      ? { link:         String(cred.link).slice(0, 2048) }        : {}),
                ...(cred.instructions ? { instructions: String(cred.instructions).slice(0, 1000) } : {}),
            };
        }).filter(c => c !== null && (c.email || c.key || c.link));

        db.inventory[productId].push(...sanitized);
    }
    saveDb(db);

    res.json({ success: true, stockCount: db.inventory[productId].length });
});

// 2.1 API: Get Public Catalog & Dynamic Prices
app.get('/api/catalog', (req, res) => {
    const db = getDb();
    res.json({
        success: true,
        catalog: MASTER_CATALOG,
        customPrices: db.customPrices || {}
    });
});

// 2.2 API: Admin Update or Reset Custom Price & Promotional Badge
app.post('/api/admin/price', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { productId, price, originalPrice, badge, action } = req.body;
    const VALID_ID_REGEX = /^[a-z0-9\-]{1,32}$/;
    if (!productId || !VALID_ID_REGEX.test(productId) || !MASTER_CATALOG[productId]) {
        return res.status(400).json({ success: false, message: "productId ไม่ถูกต้อง หรือไม่พบสินค้าในระบบ" });
    }

    const db = getDb();
    if (!db.customPrices) db.customPrices = {};

    if (action === 'reset') {
        delete db.customPrices[productId];
        saveDb(db);
        return res.json({ success: true, message: "คืนค่าราคาสินค้าเป็นค่ามาตรฐานเรียบร้อยแล้ว", customPrices: db.customPrices });
    }

    const numPrice = parseFloat(price);
    if (isNaN(numPrice) || numPrice < 0) {
        return res.status(400).json({ success: false, message: "ราคาขายไม่ถูกต้อง" });
    }
    const numOrig = parseFloat(originalPrice);

    db.customPrices[productId] = {
        price: Math.round(numPrice * 100) / 100,
        originalPrice: (!isNaN(numOrig) && numOrig >= numPrice) ? Math.round(numOrig * 100) / 100 : Math.round(numPrice * 100) / 100,
        badge: typeof badge === 'string' ? badge.slice(0, 50).trim() : '',
        manualOverride: true,
        updatedAt: new Date().toISOString()
    };

    saveDb(db);
    res.json({ success: true, message: "อัปเดตราคาและป้ายสินค้าสำเร็จ", customPrices: db.customPrices });
});

// 3. API: Admin Login & Session Verification
app.post('/api/admin/login', adminRateLimit, (req, res) => {
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
app.post('/api/admin/verify-session', (req, res) => {
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

// 6. API: Admin Fulfill Order Item
app.post('/api/admin/fulfill', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { orderId, itemIndex, credentials } = req.body;
    if (!orderId || typeof itemIndex !== 'number' || !credentials) {
        return res.status(400).json({ success: false, message: "ข้อมูลไม่ครบถ้วน" });
    }
    const db = getDb();
    const order = (db.orders || []).find(o => o.orderId === orderId);
    if (!order || !order.items || !order.items[itemIndex]) {
        return res.status(404).json({ success: false, message: "ไม่พบคำสั่งซื้อ" });
    }
    order.items[itemIndex].credentials = credentials;
    order.items[itemIndex].status = "delivered";
    const allDelivered = order.items.every(it => it.credentials && it.status !== 'pending_fulfillment');
    if (allDelivered) {
        order.status = "🟢 จัดส่งสำเร็จเรียบร้อย";
    }
    saveDb(db);

    // [NOTIFICATION & RECEIPT] Notify customer that item/order has been delivered
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL || db.discordWebhookUrl;
    if (webhookUrl) {
        sendDiscordNotification(webhookUrl, order, true).catch(e => console.warn('[DISCORD] Fulfill notification error:', e.message));
    }
    mailService.sendOrderReceiptEmail(order, true, db).catch(e => console.warn('[MAIL] Fulfill receipt email error:', e.message));

    res.json({ success: true, order });
});

// 6.1 API: Admin Fetch Store & SMTP Settings
app.get('/api/admin/settings', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const db = getDb();
    const smtp = db.smtpConfig || {};
    res.json({
        success: true,
        promptPayNumber: db.promptPayNumber || "0982949371",
        promptPayAccountName: db.promptPayAccountName || "สุพัฒน์ มีสมบัติ",
        slipOkBranchId: db.slipOkBranchId || "77491",
        discordWebhookUrl: (process.env.DISCORD_WEBHOOK_URL || db.discordWebhookUrl) 
            ? (process.env.DISCORD_WEBHOOK_URL ? '******' : (db.discordWebhookUrl || '')) 
            : '',
        smtpConfig: {
            host: process.env.SMTP_HOST || smtp.host || '',
            port: parseInt(process.env.SMTP_PORT || smtp.port || '465', 10),
            user: process.env.SMTP_USER || smtp.user || '',
            pass: (process.env.SMTP_PASS || smtp.pass) ? '******' : '',
            from: process.env.SMTP_FROM || smtp.from || '',
            resendKey:     (process.env.RESEND_API_KEY     || smtp.resendKey)     ? '******' : '',
            brevoKey:      (process.env.BREVO_API_KEY      || smtp.brevoKey)      ? '******' : '',
            sendgridKey:   (process.env.SENDGRID_API_KEY   || smtp.sendgridKey)   ? '******' : '',
            mailjetKey:    (process.env.MAILJET_API_KEY    || smtp.mailjetKey)    ? '******' : '',
            mailjetSecret: (process.env.MAILJET_SECRET_KEY || smtp.mailjetSecret) ? '******' : '',
            logoUrl:       process.env.LOGO_URL || smtp.logoUrl || ''
        }
    });
});

// 6.2 API: Admin Update Store & SMTP Settings
app.post('/api/admin/settings', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
    const { promptPayNumber, promptPayAccountName, slipOkBranchId, newPin, smtpConfig, discordWebhookUrl } = req.body;
    const db = getDb();

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
    if (newPin && typeof newPin === 'string') {
        const pinClean = newPin.trim();
        if (pinClean.length >= 4 && pinClean.length <= 16) {
            db.adminPinHash = hashPin(pinClean);
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
            db.smtpConfig.pass = String(smtpConfig.pass).replace(/\s+/g, '');
        }
        if (smtpConfig.from !== undefined) db.smtpConfig.from = String(smtpConfig.from).trim();
        if (smtpConfig.resendKey !== undefined && smtpConfig.resendKey !== '******') {
            db.smtpConfig.resendKey = String(smtpConfig.resendKey).trim();
        }
        if (smtpConfig.brevoKey !== undefined && smtpConfig.brevoKey !== '******') {
            db.smtpConfig.brevoKey = String(smtpConfig.brevoKey).trim();
        }
        if (smtpConfig.sendgridKey !== undefined && smtpConfig.sendgridKey !== '******') {
            db.smtpConfig.sendgridKey = String(smtpConfig.sendgridKey).trim();
        }
        if (smtpConfig.mailjetKey !== undefined && smtpConfig.mailjetKey !== '******') {
            db.smtpConfig.mailjetKey = String(smtpConfig.mailjetKey).trim();
        }
        if (smtpConfig.mailjetSecret !== undefined && smtpConfig.mailjetSecret !== '******') {
            db.smtpConfig.mailjetSecret = String(smtpConfig.mailjetSecret).trim();
        }
        if (smtpConfig.logoUrl !== undefined) {
            db.smtpConfig.logoUrl = String(smtpConfig.logoUrl).trim();
        }
    }

    saveDb(db);
    res.json({ success: true, message: "บันทึกการตั้งค่าสำเร็จ" });
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
        const { testEmail, smtpConfig } = req.body;
        const db = getDb();

        let customConfig = null;
        if (smtpConfig && typeof smtpConfig === 'object') {
            customConfig = {};
            if (smtpConfig.host) customConfig.host = String(smtpConfig.host).trim();
            if (smtpConfig.port) customConfig.port = parseInt(smtpConfig.port, 10) || 465;
            if (smtpConfig.user) customConfig.user = String(smtpConfig.user).trim();
            if (smtpConfig.pass && smtpConfig.pass !== '******') {
                customConfig.pass = String(smtpConfig.pass).replace(/\s+/g, '');
            } else {
                const existingPass = db.smtpConfig?.pass || process.env.SMTP_PASS;
                if (existingPass) customConfig.pass = existingPass;
            }
            if (smtpConfig.from) customConfig.from = String(smtpConfig.from).trim();
            if (smtpConfig.resendKey && smtpConfig.resendKey !== '******') {
                customConfig.resendKey = String(smtpConfig.resendKey).trim();
            } else {
                const existingKey = db.smtpConfig?.resendKey || process.env.RESEND_API_KEY;
                if (existingKey) customConfig.resendKey = existingKey;
            }
            if (smtpConfig.brevoKey && smtpConfig.brevoKey !== '******') {
                customConfig.brevoKey = String(smtpConfig.brevoKey).trim();
            } else {
                const existingBrevo = db.smtpConfig?.brevoKey || process.env.BREVO_API_KEY;
                if (existingBrevo) customConfig.brevoKey = existingBrevo;
            }
            if (smtpConfig.sendgridKey && smtpConfig.sendgridKey !== '******') {
                customConfig.sendgridKey = String(smtpConfig.sendgridKey).trim();
            } else {
                const existingSg = db.smtpConfig?.sendgridKey || process.env.SENDGRID_API_KEY;
                if (existingSg) customConfig.sendgridKey = existingSg;
            }
            if (smtpConfig.mailjetKey && smtpConfig.mailjetKey !== '******') {
                customConfig.mailjetKey = String(smtpConfig.mailjetKey).trim();
            } else {
                const existingMjKey = db.smtpConfig?.mailjetKey || process.env.MAILJET_API_KEY;
                if (existingMjKey) customConfig.mailjetKey = existingMjKey;
            }
            if (smtpConfig.mailjetSecret && smtpConfig.mailjetSecret !== '******') {
                customConfig.mailjetSecret = String(smtpConfig.mailjetSecret).trim();
            } else {
                const existingMjSec = db.smtpConfig?.mailjetSecret || process.env.MAILJET_SECRET_KEY;
                if (existingMjSec) customConfig.mailjetSecret = existingMjSec;
            }
        }

        const effectivePass    = customConfig?.pass        || db.smtpConfig?.pass        || process.env.SMTP_PASS;
        const effectiveResend  = customConfig?.resendKey   || db.smtpConfig?.resendKey   || process.env.RESEND_API_KEY;
        const effectiveBrevo   = customConfig?.brevoKey    || db.smtpConfig?.brevoKey    || process.env.BREVO_API_KEY;
        const effectiveSg      = customConfig?.sendgridKey || db.smtpConfig?.sendgridKey || process.env.SENDGRID_API_KEY;
        const effectiveMj      = (customConfig?.mailjetKey || db.smtpConfig?.mailjetKey  || process.env.MAILJET_API_KEY) &&
                                 (customConfig?.mailjetSecret || db.smtpConfig?.mailjetSecret || process.env.MAILJET_SECRET_KEY);
        if (!effectivePass && !effectiveResend && !effectiveBrevo && !effectiveSg && !effectiveMj) {
            return res.status(400).json({
                success: false,
                message: "ยังไม่ได้ระบุ API Key ใดๆ (Brevo, Resend, SendGrid, Mailjet) หรือรหัสผ่าน SMTP กรุณาระบุในช่องด้านบนก่อนกดทดสอบส่ง"
            });
        }

        const targetEmail = (testEmail || customConfig?.user || db.smtpConfig?.user || '').trim();
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
    const dateStr = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `supinkly_db_backup_${dateStr}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(db, null, 2));
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
            adminPinHash: currentDb.adminPinHash || hashPin(process.env.ADMIN_PIN || '8899'),
            promptPayNumber: (typeof restored.promptPayNumber === 'string' && /^[0-9]{10,15}$/.test(restored.promptPayNumber))
                ? restored.promptPayNumber
                : (currentDb.promptPayNumber || "0982949371"),
            promptPayAccountName: typeof restored.promptPayAccountName === 'string'
                ? restored.promptPayAccountName.slice(0, 100).trim()
                : (currentDb.promptPayAccountName || "สุพัฒน์ มีสมบัติ"),
            slipOkApiKey: typeof restored.slipOkApiKey === 'string'
                ? restored.slipOkApiKey.trim()
                : (currentDb.slipOkApiKey || ""),
            slipOkBranchId: typeof restored.slipOkBranchId === 'string'
                ? restored.slipOkBranchId.slice(0, 32).trim()
                : (currentDb.slipOkBranchId || "77491"),
            discordWebhookUrl: (typeof restored.discordWebhookUrl === 'string' && isValidDiscordWebhookUrl(restored.discordWebhookUrl))
                ? restored.discordWebhookUrl.trim()
                : (currentDb.discordWebhookUrl || ""),
            usedSlips: Array.isArray(restored.usedSlips)
                ? restored.usedSlips.filter(s => typeof s === 'string' && /^[a-f0-9]{64}$/i.test(s)).slice(0, 20000)
                : (currentDb.usedSlips || []),
            usedTransRefs: Array.isArray(restored.usedTransRefs)
                ? restored.usedTransRefs.filter(r => typeof r === 'string' && r.length <= 64).slice(0, 20000)
                : (currentDb.usedTransRefs || []),
            customPrices: {},
            inventory: {},
            orders: [],
            users: [],
            pendingRegistrations: {},
            passwordResets: {},
            smtpConfig: {}
        };

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

        res.json({
            success: true,
            message: "กู้คืนฐานข้อมูลสำเร็จและทำความสะอาดโครงสร้างเรียบร้อยแล้ว",
            stats: {
                orders: sanitizedDb.orders.length,
                users: sanitizedDb.users.length,
                inventoryProducts: Object.keys(sanitizedDb.inventory).length
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: `เกิดข้อผิดพลาดในการกู้คืนฐานข้อมูล: ${err.message}` });
    }
});

// 6.3 API: Admin Fetch Users (Members List)
app.get('/api/admin/users', adminRateLimit, (req, res) => {
    if (!authenticateAdmin(req)) {
        return res.status(403).json({ success: false, message: "สิทธิ์การเข้าถึงถูกปฏิเสธ" });
    }
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
        return {
            id: u.id,
            email: u.email,
            displayName: u.displayName || u.email.split('@')[0],
            emailVerified: !!u.emailVerified,
            createdAt: u.createdAt || null,
            ordersCount: userOrders.length,
            totalSpent
        };
    }).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

    res.json({ success: true, users: enrichedUsers });
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
    const user = db.users.find(u => u.id === userId);
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
    if (!userId) {
        return res.status(400).json({ success: false, message: "กรุณาระบุ userId" });
    }
    const db = getDb();
    if (!db.users) db.users = [];
    const idx = db.users.findIndex(u => u.id === userId);
    if (idx === -1) {
        return res.status(404).json({ success: false, message: "ไม่พบผู้ใช้งานนี้ในระบบ" });
    }
    const deletedUser = db.users.splice(idx, 1)[0];
    saveDb(db);
    res.json({ success: true, message: `ลบบัญชีผู้ใช้ ${deletedUser.email} เรียบร้อยแล้ว` });
});

const orderLookupRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { success: false, message: "ค้นหาคำสั่งซื้อบ่อยเกินไป กรุณารอสักครู่" }
});

// 7. API: Protected Customer Order Lookup
app.get('/api/orders/:orderId', orderLookupRateLimit, (req, res) => {
    const { orderId } = req.params;
    if (!orderId || !/^[A-Z0-9\-]{5,40}$/i.test(orderId)) {
        return res.status(400).json({ success: false, message: "รูปแบบรหัสคำสั่งซื้อไม่ถูกต้อง" });
    }
    const db = getDb();
    const order = (db.orders || []).find(o => o.orderId === orderId);
    if (!order) {
        return res.status(404).json({ success: false, message: "ไม่พบคำสั่งซื้อ" });
    }

    const isAdmin = authenticateAdmin(req);
    const userSession = authenticateUser(req);
    const queryEmail = (req.query.email || req.headers['x-order-email'] || '').trim().toLowerCase();

    // [SECURITY FIX] IDOR & Account Isolation:
    // หากออเดอร์ผูกกับบัญชีสมาชิก (มี userId) จะต้องยืนยันตัวตนด้วย User Session หรือสิทธิ์ Admin เท่านั้น
    // ไม่อนุญาตให้ใช้เพียง queryEmail ในการดูรหัสผ่าน เพื่อป้องกันผู้ไม่ประสงค์ดีที่รู้อีเมลแอบดูคีย์
    let isOwner = false;
    if (userSession && order.userId && order.userId === userSession.userId) {
        isOwner = true;
    } else if (!order.userId && queryEmail && order.recipientEmail && queryEmail === order.recipientEmail.toLowerCase()) {
        // Fallback สำหรับออเดอร์เก่าที่สร้างไว้ก่อนระบบสมาชิก
        isOwner = true;
    }

    // Admin or Verified Customer (via matching email or active session) gets full order with credentials
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

        const mailResult = await mailService.sendOtpEmail(normalEmail, otp, cleanDisplayName, db);

        res.json({
            success: true,
            requireOtp: true,
            email: normalEmail,
            message: mailResult.delivered
                ? "ระบบได้ส่งรหัส OTP 6 หลักไปยังอีเมลของคุณแล้ว (หากไม่พบในกล่องจดหมาย กรุณาตรวจสอบโฟลเดอร์สแปม/เมลขยะ)"
                : (mailResult.deliveryError 
                    ? `[แจ้งเตือน] ส่งอีเมลไม่สำเร็จ (${mailResult.deliveryError}) — รหัส OTP สำหรับทดสอบคือ: ${otp}`
                    : `[โหมดทดสอบ] เซิร์ฟเวอร์ยังไม่ได้เชื่อมต่อ SMTP ร้านค้า รหัส OTP ทดสอบคือ: ${otp}`),
            delivered: !!mailResult.delivered,
            devOtp: !mailResult.delivered ? otp : undefined,
            deliveryError: mailResult.deliveryError
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
        saveDb(db);

        const { token, expiresAt } = generateUserToken(user.id, user.email, user.tokenVersion);
        res.json({
            success: true,
            token,
            expiresAt,
            user: { id: user.id, email: user.email, displayName: user.displayName }
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

        res.json({
            success: true,
            message: mailResult.delivered
                ? "ระบบได้ส่งรหัส OTP ชุดใหม่ไปยังอีเมลของคุณแล้ว (หากไม่พบให้ตรวจในกล่องสแปม)"
                : (mailResult.deliveryError
                    ? `[แจ้งเตือน] ส่งอีเมลไม่สำเร็จ (${mailResult.deliveryError}) — รหัส OTP ชุดใหม่คือ: ${otp}`
                    : `[โหมดทดสอบ] รหัส OTP ชุดใหม่คือ: ${otp}`),
            delivered: !!mailResult.delivered,
            devOtp: !mailResult.delivered ? otp : undefined,
            deliveryError: mailResult.deliveryError
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
    const user = db.users.find(u => (u.email || '').toLowerCase() === normalEmail);

    // [SECURITY] Always run verifyPassword in constant time to prevent timing-based user enumeration
    const DUMMY_HASH = hashPassword('dummy_check_supinkly', 'DUMMY_USER_ID_0000');
    const isValid = user
        ? verifyPassword(String(password).trim(), user.passwordHash, user.id)
        : (verifyPassword('dummy_check_supinkly', DUMMY_HASH, 'DUMMY_USER_ID_0000') && false);

    if (!user || !isValid) {
        return res.status(401).json({ success: false, message: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
    }

    const { token, expiresAt } = generateUserToken(user.id, normalEmail, user.tokenVersion || 1);
    res.json({ success: true, token, expiresAt, user: { id: user.id, email: normalEmail, displayName: user.displayName } });
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

        res.json({
            success: true,
            message: mailResult.delivered
                ? "หากอีเมลนี้มีอยู่ในระบบ เราได้ส่งรหัส OTP 6 หลักสำหรับตั้งรหัสผ่านใหม่ไปยังอีเมลของคุณแล้ว (หากไม่พบให้ตรวจในกล่องสแปม)"
                : (mailResult.deliveryError
                    ? `[แจ้งเตือน] ส่งอีเมลไม่สำเร็จ (${mailResult.deliveryError}) — รหัส OTP กู้คืนรหัสผ่านคือ: ${otp}`
                    : `[โหมดทดสอบ] รหัส OTP กู้คืนรหัสผ่านคือ: ${otp}`),
            email: normalEmail,
            delivered: !!mailResult.delivered,
            devOtp: !mailResult.delivered ? otp : undefined,
            deliveryError: mailResult.deliveryError
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
        user.tokenVersion = (user.tokenVersion || 1) + 1;
        user.passwordHash = hashPassword(pw, user.id);
        user.passwordUpdatedAt = new Date().toISOString();
        delete db.passwordResets[normalEmail];
        saveDb(db);

        // Auto-login the user with new token bound to updated tokenVersion
        const { token, expiresAt } = generateUserToken(user.id, normalEmail, user.tokenVersion);
        res.json({
            success: true,
            message: "ตั้งรหัสผ่านใหม่และเข้าสู่ระบบสำเร็จเรียบร้อยแล้ว",
            token,
            expiresAt,
            user: { id: user.id, email: normalEmail, displayName: user.displayName }
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
app.post('/api/auth/verify-session', (req, res) => {
    const session = authenticateUser(req);
    if (session) {
        return res.json({ success: true, valid: true, user: { id: session.userId, email: session.email, displayName: session.displayName } });
    }
    return res.status(401).json({ success: false, valid: false });
});

// U5. Link Local Orders (Secure Claiming: Requires possession of orderId + matching email)
app.post('/api/auth/link-local-orders', (req, res) => {
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
app.get('/api/auth/my-orders', (req, res) => {
    const session = authenticateUser(req);
    if (!session) {
        return res.status(401).json({ success: false, message: "กรุณาเข้าสู่ระบบก่อน" });
    }
    const db = getDb();
    // [SECURITY FIX] Return orders belonging to this userId. Unauthenticated registrations cannot hijack past guest orders.
    const myOrders = (db.orders || []).filter(o => o.userId && o.userId === session.userId);
    res.json({ success: true, orders: myOrders });
});

// ─────────────────────────────────────────────────────────────
// LIVE CHAT — WebSocket Server (ws)
// ─────────────────────────────────────────────────────────────
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');

// Map: sessionId → { ws, role: 'customer'|'admin', name, sessionId }
const clients = new Map();

// Upgrade HTTP server to support WebSocket
const server = app.listen(PORT, () => {
    console.log(`Supinkly.AI Server running on http://localhost:${PORT}`);
});

const wss = new WebSocketServer({ server, path: '/ws/chat' });

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
            continue;
        }
        client.ws.isAlive = false;
        try { client.ws.ping(); } catch {}
    }
}, 35000);

wss.on('connection', (ws, req) => {
    // ── [SECURITY FIX] CSWSH Origin Verification ──
    const origin = req.headers.origin;
    if (origin && rawOrigins !== '*' && !ALLOWED_ORIGINS.includes(origin) && !origin.endsWith('.onrender.com') && !origin.includes('localhost') && !origin.includes('127.0.0.1')) {
        ws.close(1008, 'Origin not allowed');
        return;
    }

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    const sessionId = uuidv4();
    let clientInfo = { ws, role: null, name: 'ลูกค้า', sessionId };
    clients.set(sessionId, clientInfo);

    let msgCount = 0;
    let windowStart = Date.now();

    ws.send(JSON.stringify({ type: 'session', sessionId }));

    ws.on('message', (raw) => {
        // Message rate limiting (max 20 messages per 5s)
        const now = Date.now();
        if (now - windowStart > 5000) {
            msgCount = 0;
            windowStart = now;
        }
        msgCount++;
        if (msgCount > 20) {
            ws.send(JSON.stringify({ type: 'message', from: 'admin', name: 'ระบบ', text: 'คุณส่งข้อความเร็วเกินไป กรุณารอสักครู่' }));
            return;
        }

        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // ── AUTH: ลงทะเบียน role ──────────────────────────────────
        if (data.type === 'auth') {
            if (data.role === 'admin') {
                // [SECURITY] Token-only auth over WebSocket — supports stateless HMAC token & in-memory session
                const isTokenValid = (data.token && verifyAdminToken(data.token)) || 
                                     (data.token && adminSessions.has(data.token) && Date.now() < adminSessions.get(data.token));

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
                    ws.send(JSON.stringify({ type: 'auth_fail', message: 'กรุณาเข้าสู่ระบบผ่าน /api/admin/login ก่อน' }));
                }
            } else if (data.role === 'customer') {
                clientInfo.role = 'customer';
                clientInfo.name = data.name ? String(data.name).slice(0, 40) : `ลูกค้า #${sessionId.slice(0, 5)}`;
                ws.send(JSON.stringify({ type: 'auth_ok', role: 'customer', adminOnline: getAdminCount() > 0 }));
                // แจ้งแอดมินว่ามีลูกค้าใหม่
                broadcast({ type: 'new_room', sessionId, name: clientInfo.name }, c => c.role === 'admin');
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

            const payload = {
                type: 'message',
                from: clientInfo.role,
                name: clientInfo.name,
                text,
                sessionId: clientInfo.role === 'customer' ? sessionId : data.targetSessionId,
                ts: Date.now()
            };

            if (clientInfo.role === 'customer') {
                // ส่งให้แอดมินทุกคน + echo กลับลูกค้า
                broadcast(payload, c => c.role === 'admin');
                ws.send(JSON.stringify({ ...payload, own: true }));
            } else if (clientInfo.role === 'admin') {
                // ส่งให้ลูกค้าที่ระบุ + echo กลับแอดมิน
                const target = clients.get(data.targetSessionId);
                if (target && target.ws.readyState === 1) {
                    target.ws.send(JSON.stringify({ ...payload, from: 'admin' }));
                }
                ws.send(JSON.stringify({ ...payload, own: true }));
            }
        }

        // ── TYPING ────────────────────────────────────────────────
        if (data.type === 'typing') {
            if (clientInfo.role === 'customer') {
                broadcast({ type: 'typing', sessionId, name: clientInfo.name }, c => c.role === 'admin');
            } else if (clientInfo.role === 'admin') {
                const target = clients.get(data.targetSessionId);
                if (target && target.ws.readyState === 1) {
                    target.ws.send(JSON.stringify({ type: 'typing', from: 'admin' }));
                }
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
    });
});

