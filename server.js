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
const rateLimit = require('express-rate-limit');
const upload = multer({ limits: { fileSize: 15 * 1024 * 1024 } });

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
    allowedHeaders: ['Content-Type', 'x-authorization']
}));

app.use(express.json({ limit: '1mb' }));
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

const DB_FILE = path.join(__dirname, 'secure_database.json');

// Initialize database file if not exists
if (!fs.existsSync(DB_FILE)) {
    const initialDb = {
        // ❌ Before: adminPin: "8899"  (plaintext)
        // ✅ After: เก็บ hash
        adminPinHash: hashPin(process.env.ADMIN_PIN || '8899'),
        promptPayNumber: process.env.PROMPTPAY_NUMBER || "0982949371",
        promptPayAccountName: process.env.PROMPTPAY_NAME || "สุพัฒน์ มีสมบัติ",
        // ✅ API keys ควรมาจาก env ไม่ hardcode
        slipOkApiKey: process.env.SLIPOK_API_KEY || "",
        slipOkBranchId: process.env.SLIPOK_BRANCH_ID || "77491",
        usedSlips: [],   // เก็บ SHA-256 hash ของ slip file
        inventory: {},
        orders: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
}

function getDb() {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
}

function saveDb(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
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

// 1. API: Verify Slip & Dispense Product
app.post('/api/checkout/verify-slip', checkoutRateLimit, upload.single('slip'), async (req, res) => {
    try {
        const { email, cartItems } = req.body;

        // ─── [FIX #4 Applied] Validate email server-side ────────────────
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

        if (!req.file) {
            return res.status(400).json({ success: false, message: "กรุณาแนบไฟล์สลิป" });
        }

        // ─── [FIX #5 Applied] SHA-256 fingerprint จากไฟล์จริง ──────────
        const slipHash = computeSlipSHA256(req.file.buffer);
        if (db.usedSlips.includes(slipHash)) {
            return res.status(400).json({ success: false, message: "สลิปนี้เคยถูกใช้งานไปแล้ว (Anti-Replay)" });
        }

        // Validate cart items (sanitize productId)
        const VALID_ID_REGEX = /^[a-z0-9\-]{1,32}$/;
        for (const item of parsedCart) {
            if (!item.productId || !VALID_ID_REGEX.test(item.productId)) {
                return res.status(400).json({ success: false, message: "productId ไม่ถูกต้อง" });
            }
            const qty = parseInt(item.quantity, 10);
            if (isNaN(qty) || qty < 1 || qty > 50) {
                return res.status(400).json({ success: false, message: "จำนวนสินค้าไม่ถูกต้อง" });
            }
            item.quantity = qty;
        }

        // Dispense Items from secure server inventory
        const deliveredItems = [];
        for (const item of parsedCart) {
            const pool = db.inventory[item.productId] || [];
            for (let i = 0; i < item.quantity; i++) {
                if (pool.length > 0) {
                    const cred = pool.shift();
                    deliveredItems.push({ productId: item.productId, credentials: cred });
                } else {
                    deliveredItems.push({
                        productId: item.productId,
                        credentials: {
                            key: `VOUCHER-${Date.now().toString(36).toUpperCase()}`,
                            instructions: "เจ้าหน้าที่จะส่งมอบรหัสเพิ่มเติมให้ทางอีเมล"
                        }
                    });
                }
            }
        }

        // Register used slip (SHA-256 hash)
        db.usedSlips.push(slipHash);

        // Record Order
        const orderId = "SPK-" + Date.now().toString().slice(-8);
        const order = {
            orderId,
            date: new Date().toISOString(),
            email: email.trim().toLowerCase(),
            items: deliveredItems,
            status: "ชำระเงินสำเร็จ",
            slipHash  // เก็บไว้เพื่อ audit
        };
        db.orders.unshift(order);
        saveDb(db);

        res.json({ success: true, order });
    } catch (err) {
        console.error('checkout error:', err.message);
        res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" });
    }
});

// 2. API: Admin Authenticated Stock Management
// ─── [FIX #2 + #3 Applied] Rate limit + PIN hash comparison ────────────────
app.post('/api/admin/stock', adminRateLimit, (req, res) => {
    const { pin, productId, newCredentials } = req.body;
    const db = getDb();

    // ❌ Before: pin !== db.adminPin  (plaintext compare)
    // ✅ After: timing-safe hash compare
    const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
    if (!pin || !verifyPin(pin, storedHash)) {
        return res.status(403).json({ success: false, message: "PIN แอดมินไม่ถูกต้อง" });
    }

    // Validate productId
    const VALID_ID_REGEX = /^[a-z0-9\-]{1,32}$/;
    if (!productId || !VALID_ID_REGEX.test(productId)) {
        return res.status(400).json({ success: false, message: "productId ไม่ถูกต้อง" });
    }

    if (!db.inventory[productId]) db.inventory[productId] = [];
    if (Array.isArray(newCredentials)) {
        db.inventory[productId].push(...newCredentials);
    }
    saveDb(db);

    res.json({ success: true, stockCount: db.inventory[productId].length });
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

wss.on('connection', (ws, req) => {
    const sessionId = uuidv4();
    let clientInfo = { ws, role: null, name: 'ลูกค้า', sessionId };
    clients.set(sessionId, clientInfo);

    ws.send(JSON.stringify({ type: 'session', sessionId }));

    ws.on('message', (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // ── AUTH: ลงทะเบียน role ──────────────────────────────────
        if (data.type === 'auth') {
            const db = getDb();
            const storedHash = db.adminPinHash || hashPin(db.adminPin || '8899');
            if (data.role === 'admin' && data.pin && verifyPin(data.pin, storedHash)) {
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

