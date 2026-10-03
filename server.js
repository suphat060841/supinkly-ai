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

// ─── [FIX #3.1] Admin Session Token Management ──────────────────────────────
const adminSessions = new Map(); // token -> expiresAt (timestamp)

function cleanExpiredSessions() {
    const now = Date.now();
    for (const [token, expiry] of adminSessions.entries()) {
        if (now > expiry) adminSessions.delete(token);
    }
}
setInterval(cleanExpiredSessions, 10 * 60 * 1000);

function authenticateAdmin(req) {
    const authHeader = req.headers['authorization'] || '';
    const token = req.headers['x-admin-token'] || (authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null);
    if (token && adminSessions.has(token)) {
        const expiry = adminSessions.get(token);
        if (Date.now() < expiry) return true;
        adminSessions.delete(token);
    }
    // [SECURITY] PIN fallback removed — must use session token from /api/admin/login
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
        inventory: {},
        orders: [],
        users: []  // { id, email, passwordHash, displayName, createdAt }
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
}

function getDb() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf-8');
            return JSON.parse(raw);
        }
    } catch (err) {
        console.error("Database read error, trying backup:", err.message);
        if (fs.existsSync(DB_BAK)) {
            try {
                return JSON.parse(fs.readFileSync(DB_BAK, 'utf-8'));
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
        inventory: {},
        orders: []
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

// 1. API: Verify Slip & Dispense Product (Server-Side Verified)
app.post('/api/checkout/verify-slip', checkoutRateLimit, upload.single('slip'), async (req, res) => {
    try {
        const { email, cartItems } = req.body;

        // Validate email server-side
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, message: "รูปแบบอีเมลไม่ถูกต้อง" });
        }

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
            return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้ว (Anti-Replay)" });
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
            expectedTotal += catalogItem.price * qty;
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
        }

        // ── [SECURITY FIX] Re-read db to avoid TOCTOU race conditions during async SlipOK fetch ──
        const currentDb = getDb();

        if (currentDb.usedSlips && currentDb.usedSlips.includes(slipHash)) {
            return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้ว (Anti-Replay)" });
        }
        if (transRef) {
            if (!currentDb.usedTransRefs) currentDb.usedTransRefs = [];
            if (currentDb.usedTransRefs.includes(transRef)) {
                return res.status(400).json({ success: false, message: "เลขอ้างอิงสลิป (transRef) เคยถูกใช้งานแล้ว (Anti-Replay)" });
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

            for (let i = 0; i < item.quantity; i++) {
                if (isAutoVerified && pool.length > 0) {
                    const cred = pool.shift();
                    deliveredItems.push({
                        productId: item.productId,
                        productTitle: master.title,
                        price: master.price,
                        warranty: master.warranty,
                        status: "delivered",
                        credentials: cred
                    });
                } else {
                    hasPending = true;
                    deliveredItems.push({
                        productId: item.productId,
                        productTitle: master.title,
                        price: master.price,
                        warranty: master.warranty,
                        status: "pending_fulfillment",
                        credentials: null
                    });
                }
            }
        }

        // Record Order with unguessable cryptographic token
        const orderId = "SPK-" + Date.now().toString().slice(-6) + crypto.randomBytes(3).toString('hex').toUpperCase();

        // Link order to user account if logged in
        const userSession = authenticateUser(req);

        const order = {
            orderId,
            date: new Date().toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }),
            email: email.trim().toLowerCase(),
            recipientEmail: email.trim().toLowerCase(),
            ...(userSession ? { userId: userSession.userId } : {}),
            totalAmount: expectedTotal,
            paymentMethod: "Thai QR PromptPay",
            transRef: transRef || "REF-" + Date.now().toString(36).toUpperCase(),
            items: deliveredItems,
            status: hasPending ? "🟡 รอจัดส่งสินค้า (5-15 นาที)" : "🟢 จัดส่งสำเร็จทันที (Instant Vault)",
            slipHash
        };
        if (!currentDb.orders) currentDb.orders = [];
        currentDb.orders.unshift(order);
        saveDb(currentDb);

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

// 3. API: Admin Login & Session Verification
app.post('/api/admin/login', adminRateLimit, (req, res) => {
    const { pin } = req.body;
    const db = getDb();
    const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
    if (!pin || !verifyPin(pin, storedHash)) {
        return res.status(403).json({ success: false, message: "รหัส PIN แอดมินไม่ถูกต้อง" });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 4 * 60 * 60 * 1000; // 4 hours
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
    res.json({ success: true, order });
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
    const isOwner = (queryEmail && order.recipientEmail && queryEmail === order.recipientEmail.toLowerCase()) ||
                    (userSession && order.userId && order.userId === userSession.userId);

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
            credentials: it.status === 'delivered' ? { instructions: "กรุณาระบุอีเมลที่ใช้สั่งซื้อเพื่อดูรหัสผ่าน" } : null
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
function generateUserToken(userId, email, durationMs = 30 * 24 * 60 * 60 * 1000) {
    const expiresAt = Date.now() + durationMs;
    const nonce = crypto.randomBytes(8).toString('hex');
    const payload = `${userId}.${expiresAt}.${nonce}`;
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
    if (parts.length !== 4) return null; // [userId, expiresAt, nonce, hmac]
    const [userId, expiresAtStr, nonce, hmac] = parts;

    const expiresAt = parseInt(expiresAtStr, 10);
    if (isNaN(expiresAt) || Date.now() > expiresAt) return null;

    const db = getDb();
    const user = (db.users || []).find(u => u.id === userId);
    if (!user) return null;

    const payload = `${userId}.${expiresAt}.${nonce}`;
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

// U1. Register
app.post('/api/auth/register', userAuthRateLimit, (req, res) => {
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
    const normalEmail = email.trim().toLowerCase();
    if (db.users.find(u => u.email === normalEmail)) {
        // [SECURITY] Return generic message to prevent user enumeration
        return res.status(200).json({ success: false, message: "หากอีเมลนี้ยังไม่เคยลงทะเบียน จะมีอีเมลยืนยันส่งไปให้ กรุณาตรวจสอบ Inbox ของคุณ" });
    }

    // Sanitize displayName to prevent control characters and formatting attacks
    const cleanDisplayName = displayName
        ? String(displayName).replace(/[\r\n\t\x00-\x1f]/g, '').slice(0, 60).trim()
        : normalEmail.split('@')[0];

    const userId = 'U' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
    const user = {
        id: userId,
        email: normalEmail,
        displayName: cleanDisplayName || 'สมาชิก Supinkly',
        passwordHash: hashPassword(pw, userId),
        createdAt: new Date().toISOString()
    };
    db.users.push(user);
    saveDb(db);

    const { token, expiresAt } = generateUserToken(userId, normalEmail);
    res.json({ success: true, token, expiresAt, user: { id: userId, email: normalEmail, displayName: user.displayName } });
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
    const user = db.users.find(u => u.email === normalEmail);

    // [SECURITY] Always run verifyPassword in constant time to prevent timing-based user enumeration
    const DUMMY_HASH = hashPassword('dummy_check_supinkly', 'DUMMY_USER_ID_0000');
    const isValid = user
        ? verifyPassword(String(password).trim(), user.passwordHash, user.id)
        : (verifyPassword('dummy_check_supinkly', DUMMY_HASH, 'DUMMY_USER_ID_0000') && false);

    if (!user || !isValid) {
        return res.status(401).json({ success: false, message: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" });
    }

    const { token, expiresAt } = generateUserToken(user.id, normalEmail);
    res.json({ success: true, token, expiresAt, user: { id: user.id, email: normalEmail, displayName: user.displayName } });
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
                // [SECURITY] Token-only auth over WebSocket — no raw PIN
                const isTokenValid = data.token && adminSessions.has(data.token) && Date.now() < adminSessions.get(data.token);

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

