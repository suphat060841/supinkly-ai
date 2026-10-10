/**
 * Supinkly.AI - Core Application Logic (BRIGHT & HIGH-CONTRAST THEME)
 * High readability, crisp Thai typography, accessible contrast.
 */

// HTML Escaping to prevent XSS
function escapeHTML(str) {
    if (!str && str !== 0) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// [SECURITY] Strict URL sanitizer to prevent javascript:, data:, and vbscript: XSS in dynamic links
function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '#';
    const clean = url.trim();
    if (/^https?:\/\//i.test(clean)) {
        return escapeHTML(clean);
    }
    return '#';
}

// Hardened Admin Authentication (Brute-Force Rate Limiting & Session Token)
const ADMIN_AUTH = {
    MAX_ATTEMPTS: 5,
    LOCKOUT_DURATION_MS: 5 * 60 * 1000, // 5 minutes
    SESSION_DURATION_MS: 15 * 60 * 1000, // 15 minutes auto-logout
    DEFAULT_PIN: '8899',

    async hashPin(pin) {
        const cleanPin = String(pin || '').trim();
        const str = "supinkly_sec_salt_" + cleanPin;
        try {
            if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle && typeof window.crypto.subtle.digest === 'function') {
                const encoder = new TextEncoder();
                const data = encoder.encode(str);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            }
        } catch (e) {
            console.warn("crypto.subtle unavailable, fallback hashing:", e);
        }
        // Fallback hash implementation for non-secure / file / local contexts
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        return 'fallback_' + Math.abs(hash).toString(16);
    },

    generateToken() {
        try {
            if (typeof window !== 'undefined' && window.crypto && typeof window.crypto.getRandomValues === 'function') {
                return Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2, '0')).join('');
            }
        } catch (e) { }
        return 'token_' + Date.now() + '_' + Math.random().toString(36).substring(2);
    },

    getLockoutStatus() {
        const until = parseInt(localStorage.getItem('supinkly_admin_lockout_until') || '0', 10);
        if (Date.now() < until) {
            const remSeconds = Math.ceil((until - Date.now()) / 1000);
            return { locked: true, remainingSeconds: remSeconds };
        }
        return { locked: false, remainingSeconds: 0 };
    },

    resetLockout() {
        localStorage.removeItem('supinkly_admin_failed_attempts');
        localStorage.removeItem('supinkly_admin_lockout_until');
    },

    resetToDefault() {
        this.resetLockout();
        localStorage.removeItem('supinkly_admin_pin_hash');
        sessionStorage.removeItem('supinkly_admin_pin');
        localStorage.removeItem('supinkly_admin_pin');
    },

    async setPin(newPin) {
        const clean = String(newPin || '').trim();
        if (!clean || clean.length < 4 || clean.length > 32) {
            throw new Error("รหัส PIN หรือรหัสผ่านต้องมีความยาวระหว่าง 4 ถึง 32 ตัวอักษร");
        }
        const hashed = await this.hashPin(clean);
        localStorage.setItem('supinkly_admin_pin_hash', hashed);
        sessionStorage.setItem('supinkly_admin_pin', clean);
        localStorage.setItem('supinkly_admin_pin', clean);
    },

    async verify(enteredPin) {
        const cleanPin = String(enteredPin || '').trim();
        if (!cleanPin) {
            throw new Error("กรุณากรอกรหัส PIN หรือรหัสผ่านผู้ดูแลระบบ");
        }

        // Check lockout
        const lockout = this.getLockoutStatus();
        if (lockout.locked) {
            const minutes = Math.ceil(lockout.remainingSeconds / 60);
            throw new Error(`ระบบถูกล็อกชั่วคราว กรุณารออีก ${minutes} นาที หรือติดต่อผู้ดูแลระบบ`);
        }

        let verifiedSuccess = false;
        let serverToken = null;

        // 1. FIRST PRIORITY: Authenticate against Backend Server API
        try {
            const srvRes = await fetch('/api/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: cleanPin })
            });
            const srvData = await srvRes.json();
            if (srvRes.ok && srvData && srvData.success && srvData.token) {
                verifiedSuccess = true;
                serverToken = srvData.token;
            } else if (srvRes.status === 403 || srvRes.status === 401) {
                // Server explicitly rejected the PIN
                this.recordFailedAttempt();
                throw new Error(srvData.message || "รหัส PIN หรือรหัสผ่านไม่ถูกต้อง");
            }
        } catch (netErr) {
            if (netErr.message && (netErr.message.includes("PIN") || netErr.message.includes("รหัสผ่าน"))) {
                throw netErr;
            }
            // Backend offline or network failure: fall back to local validation below
        }

        // 2. BACKUP / OFFLINE LOCAL VALIDATION
        if (!verifiedSuccess) {
            const hashedEntered = await this.hashPin(cleanPin);
            const storedHash = localStorage.getItem('supinkly_admin_pin_hash');
            const defaultHash = await this.hashPin(this.DEFAULT_PIN);

            // If storedHash is set, ONLY storedHash is accepted (8899 will not work)
            // If storedHash is not set yet, the default PIN 8899 is accepted
            const targetHash = storedHash || defaultHash;
            if (hashedEntered === targetHash) {
                verifiedSuccess = true;
            }
        }

        if (verifiedSuccess) {
            this.resetLockout();
            const sessionData = {
                token: this.generateToken(),
                expiresAt: Date.now() + this.SESSION_DURATION_MS
            };
            sessionStorage.setItem('supinkly_admin_session', JSON.stringify(sessionData));
            localStorage.setItem('supinkly_admin_session', JSON.stringify(sessionData));
            sessionStorage.setItem('supinkly_admin_pin', cleanPin);
            localStorage.setItem('supinkly_admin_pin', cleanPin);

            if (serverToken) {
                sessionStorage.setItem('supinkly_admin_server_token', serverToken);
                localStorage.setItem('supinkly_admin_server_token', serverToken);
            }

            const newHash = await this.hashPin(cleanPin);
            localStorage.setItem('supinkly_admin_pin_hash', newHash);

            return true;
        }

        // 3. FAILED PIN ATTEMPT
        this.recordFailedAttempt();
        throw new Error("รหัส PIN หรือรหัสผ่านไม่ถูกต้อง");
    },

    recordFailedAttempt() {
        let attempts = parseInt(localStorage.getItem('supinkly_admin_failed_attempts') || '0', 10) + 1;
        localStorage.setItem('supinkly_admin_failed_attempts', String(attempts));

        if (attempts >= this.MAX_ATTEMPTS) {
            const lockoutUntil = Date.now() + this.LOCKOUT_DURATION_MS;
            localStorage.setItem('supinkly_admin_lockout_until', String(lockoutUntil));
            throw new Error("กรอกรหัสไม่ถูกต้องเกิน 5 ครั้ง! ระบบถูกล็อกชั่วคราว 5 นาทีเพื่อความปลอดภัย");
        } else {
            throw new Error(`รหัส PIN หรือรหัสผ่านไม่ถูกต้อง (เหลือโอกาสลองอีก ${this.MAX_ATTEMPTS - attempts} ครั้ง)`);
        }
    },

    checkSession() {
        try {
            let raw = sessionStorage.getItem('supinkly_admin_session');
            if (!raw) {
                raw = localStorage.getItem('supinkly_admin_session');
            }
            if (!raw) return false;
            const session = JSON.parse(raw);
            if (session && session.token && Date.now() < session.expiresAt) {
                session.expiresAt = Date.now() + this.SESSION_DURATION_MS;
                sessionStorage.setItem('supinkly_admin_session', JSON.stringify(session));
                localStorage.setItem('supinkly_admin_session', JSON.stringify(session));

                // Silent token refresh if server token is missing
                const savedPin = sessionStorage.getItem('supinkly_admin_pin') || localStorage.getItem('supinkly_admin_pin');
                if (savedPin && (!sessionStorage.getItem('supinkly_admin_server_token') && !localStorage.getItem('supinkly_admin_server_token'))) {
                    fetch('/api/admin/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pin: savedPin })
                    }).then(r => r.json()).then(d => {
                        if (d && d.success && d.token) {
                            sessionStorage.setItem('supinkly_admin_server_token', d.token);
                            localStorage.setItem('supinkly_admin_server_token', d.token);
                        }
                    }).catch(() => { });
                }

                return true;
            }
        } catch {
            // corrupt session
        }
        this.logout();
        return false;
    },

    logout() {
        sessionStorage.removeItem('supinkly_admin_session');
        sessionStorage.removeItem('supinkly_admin_server_token');
        sessionStorage.removeItem('supinkly_admin_pin');
        localStorage.removeItem('supinkly_admin_session');
        localStorage.removeItem('supinkly_admin_server_token');
        localStorage.removeItem('supinkly_admin_pin');
    }
};

// Secure Stock Vault (Model 1: Zero-Stock On-Demand by Default)
function getSecureInventory() {
    try {
        const stored = localStorage.getItem('supinkly_secure_inventory');
        if (stored) {
            const parsed = JSON.parse(stored);
            // In Model 1 (Zero-Stock On-Demand), ensure no dummy @supinkly.ai stock remains
            let hasDummy = false;
            for (const pid in parsed) {
                if (Array.isArray(parsed[pid])) {
                    const cleanList = parsed[pid].filter(item => {
                        const email = (item.email || '').toLowerCase();
                        return !email.endsWith('@supinkly.ai');
                    });
                    if (cleanList.length !== parsed[pid].length) {
                        parsed[pid] = cleanList;
                        hasDummy = true;
                    }
                }
            }
            if (hasDummy) {
                localStorage.setItem('supinkly_secure_inventory', JSON.stringify(parsed));
            }
            return parsed;
        }
    } catch (e) {
        console.error("Inventory read error:", e);
    }

    const initialVault = {};
    localStorage.setItem('supinkly_secure_inventory', JSON.stringify(initialVault));
    return initialVault;
}

function saveSecureInventory(inv) {
    localStorage.setItem('supinkly_secure_inventory', JSON.stringify(inv));
}

// Cart Loader with Auto-Migration & Sanitization
function loadAndSanitizeCart() {
    try {
        const raw = JSON.parse(localStorage.getItem('supinkly_cart') || '[]');
        if (!Array.isArray(raw)) return [];
        const sanitized = [];
        raw.forEach(item => {
            if (!item) return;
            const id = item.productId || (item.product && item.product.id);
            const qty = parseInt(item.quantity, 10) || 0;
            if (id && getMasterProduct(id) && qty > 0) {
                sanitized.push({
                    productId: id,
                    quantity: Math.max(1, Math.min(50, qty))
                });
            }
        });
        localStorage.setItem('supinkly_cart', JSON.stringify(sanitized));
        return sanitized;
    } catch (e) {
        return [];
    }
}

// Application State
const state = {
    products: (typeof getAllMasterProducts === 'function' ? getAllMasterProducts(false) : PRODUCTS).map(p => ({ ...p, stock: 0 })),
    inventory: getSecureInventory(),
    filteredProducts: [],
    cart: loadAndSanitizeCart(),
    user: (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) ? USER_AUTH.getUser() : null,
    orders: (() => {
        try {
            return JSON.parse(localStorage.getItem('supinkly_orders') || '[]');
        } catch {
            return [];
        }
    })(),
    filterBrand: 'all',
    filterType: 'all',
    searchQuery: '',
    sortBy: 'popular',
    qrTimer: null,
    qrSecondsLeft: 900,
    coinsToRedeem: 0,
    referralCode: null,
    referralDiscount: null,
    activeMemberTab: 'orders'
};

// Custom Price Management
function getCustomPrices() {
    try {
        return JSON.parse(localStorage.getItem('supinkly_custom_prices') || '{}');
    } catch (e) {
        return {};
    }
}

function applyCustomPricesToProducts() {
    const customPrices = getCustomPrices();

    state.products.forEach(p => {
        if (customPrices[p.id]) {
            if (typeof customPrices[p.id].price === 'number') p.price = customPrices[p.id].price;
            if (typeof customPrices[p.id].originalPrice === 'number') p.originalPrice = customPrices[p.id].originalPrice;
            if (typeof customPrices[p.id].badge === 'string') p.badge = customPrices[p.id].badge;
            if (customPrices[p.id].isHighlight !== undefined) p.isHighlight = !!customPrices[p.id].isHighlight;
        }
    });
}

// Sync live stock count & custom prices (Referenced from G2G Market Auto-Sync)
function syncStockCount() {
    if (typeof getAllMasterProducts === 'function') {
        const masters = getAllMasterProducts(false);
        const masterMap = new Map(masters.map(m => [m.id, m]));
        state.products.forEach(p => {
            const m = masterMap.get(p.id);
            if (m) {
                p.isHighlight = !!m.isHighlight;
                if (m.title) p.title = m.title;
                if (m.badge) p.badge = m.badge;
                if (typeof m.price === 'number') p.price = m.price;
                if (typeof m.originalPrice === 'number') p.originalPrice = m.originalPrice;
                if (m.deleted !== undefined) p.deleted = m.deleted;
            }
        });
    }
    applyCustomPricesToProducts();
    const customPrices = getCustomPrices();
    state.products.forEach(p => {
        const pool = state.inventory[p.id] || [];
        const g2gStock = customPrices[p.id]?.g2gStockAvailable
            ?? (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks[p.id]?.g2gStock)
            ?? 50;

        p.vaultStock = pool.length;
        p.marketStock = g2gStock;
        // Total available stock references G2G real-time market availability
        p.stock = g2gStock;
    });
    state.filteredProducts = [...state.products];
}

// Calculate Verified Cart Total from Master Catalog
function calculateVerifiedTotal() {
    if (!state.cart || !Array.isArray(state.cart)) return 0;
    return state.cart.reduce((sum, item) => {
        if (!item || !item.productId) return sum;
        const master = getMasterProduct(item.productId);
        const unitPrice = master && typeof master.price === 'number' ? Math.max(0, master.price) : 0;
        const qty = Math.max(1, parseInt(item.quantity, 10) || 1);
        return sum + (unitPrice * qty);
    }, 0);
}

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    syncStockCount();
    initHeader();
    initFilters();
    renderProducts();
    renderHighlightProducts();
    updateCartUI();
    renderBrandTabs();
    initEvents();

    // Launch Real-Time Visitor Telemetry Tracking
    if (typeof TELEMETRY !== 'undefined' && typeof TELEMETRY.init === 'function') {
        TELEMETRY.init();
    }

    // Launch G2G Market Real-Time Auto-Sync Engine (Zero button clicks required)
    if (typeof G2G_SYNC !== 'undefined') {
        G2G_SYNC.init();
    }

    // Synchronize custom prices and products with server
    syncCatalogWithServer();

    // User session & isolated keys initialization (Preserve orders safely)
    try {
        const storedOrders = localStorage.getItem('supinkly_orders');
        if (storedOrders) {
            state.orders = JSON.parse(storedOrders) || [];
        }
    } catch (e) {
        state.orders = [];
    }
    updateNavOrdersCount();
    updateUserHeaderUI();
    updateMemberBadges();

    // Check referral query param in URL (?ref=CODE)
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const refParam = urlParams.get('ref');
        if (refParam && typeof refParam === 'string' && refParam.trim()) {
            setTimeout(() => {
                applyReferralCode(refParam.trim());
            }, 600);
        }
    } catch { }

    if (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
        USER_AUTH.verifySession().then(() => {
            updateUserHeaderUI();
            updateMemberBadges();
            refreshUserOrders();
        });
        if (typeof USER_AUTH.getProfile === 'function') {
            USER_AUTH.getProfile().then(p => {
                if (p) {
                    state.user = p;
                    updateUserHeaderUI();
                    updateMemberBadges();
                    if (typeof updateCartUI === 'function') updateCartUI();
                }
            });
        }
    }
});

async function syncCatalogWithServer() {
    if (!window.location.protocol.startsWith('http')) return;
    try {
        const res = await fetch('/api/catalog');
        if (!res.ok) return;
        const data = await res.json();
        if (data && data.success) {
            let updated = false;
            let needsServerPush = false;
            const localPrices = getCustomPrices();
            const localProducts = getCustomProducts();
            const mergedPrices = { ...localPrices };
            const mergedProducts = { ...localProducts };

            // 1. Reconcile customPrices with timestamp awareness
            if (data.customPrices && typeof data.customPrices === 'object') {
                for (const [pid, srvItem] of Object.entries(data.customPrices)) {
                    if (!srvItem) continue;
                    const locItem = localPrices[pid];
                    if (!locItem) {
                        mergedPrices[pid] = srvItem;
                        updated = true;
                    } else {
                        const srvTime = new Date(srvItem.updatedAt || srvItem.lastManualUpdate || 0).getTime();
                        const locTime = new Date(locItem.updatedAt || locItem.lastManualUpdate || 0).getTime();

                        // 1. If server has admin manual override and local does not: Server ALWAYS wins!
                        if (srvItem.manualOverride && !locItem.manualOverride) {
                            mergedPrices[pid] = { ...locItem, ...srvItem };
                            updated = true;
                        }
                        // 2. If local has manual override and server does not: Local wins and push to server
                        else if (locItem.manualOverride && !srvItem.manualOverride) {
                            needsServerPush = true;
                        }
                        // 3. Both have manual override: compare timestamps
                        else if (locItem.manualOverride && srvItem.manualOverride) {
                            if (locTime > srvTime) {
                                needsServerPush = true;
                            } else {
                                mergedPrices[pid] = { ...locItem, ...srvItem };
                                if (locItem.price !== srvItem.price || locItem.originalPrice !== srvItem.originalPrice || locItem.badge !== srvItem.badge) {
                                    updated = true;
                                }
                            }
                        }
                        // 4. Neither has manual override: newer or equal server wins
                        else if (srvTime >= locTime) {
                            mergedPrices[pid] = { ...locItem, ...srvItem };
                            if (locItem.price !== srvItem.price || locItem.originalPrice !== srvItem.originalPrice) {
                                updated = true;
                            }
                        }
                    }
                }
            }

            // Check if local has manual overrides not present on server
            for (const [pid, locItem] of Object.entries(localPrices)) {
                if (locItem && locItem.manualOverride && (!data.customPrices || !data.customPrices[pid])) {
                    needsServerPush = true;
                }
            }

            // 2. Reconcile customProducts with timestamp awareness
            if (data.customProducts && typeof data.customProducts === 'object') {
                for (const [pid, srvProd] of Object.entries(data.customProducts)) {
                    if (!srvProd) continue;
                    const locProd = localProducts[pid];
                    if (!locProd) {
                        mergedProducts[pid] = srvProd;
                        updated = true;
                    } else {
                        const srvTime = new Date(srvProd.updatedAt || 0).getTime();
                        const locTime = new Date(locProd.updatedAt || 0).getTime();
                        if (srvTime > locTime) {
                            mergedProducts[pid] = { ...locProd, ...srvProd };
                            updated = true;
                        } else if (locTime > srvTime) {
                            needsServerPush = true;
                        }
                    }
                }
            }

            for (const [pid, locProd] of Object.entries(localProducts)) {
                if (locProd && (!data.customProducts || !data.customProducts[pid])) {
                    needsServerPush = true;
                }
            }

            if (updated) {
                localStorage.setItem('supinkly_custom_prices', JSON.stringify(mergedPrices));
                localStorage.setItem('supinkly_custom_products', JSON.stringify(mergedProducts));
                applyCustomPricesToProducts();
                syncStockCount();
                renderProducts();
                renderHighlightProducts();
                updateCartUI();
            }

            // Push pending local manual changes to server if admin authenticated
            const hasAdminCreds = sessionStorage.getItem('supinkly_admin_pin') || localStorage.getItem('supinkly_admin_pin') || sessionStorage.getItem('supinkly_admin_server_token') || localStorage.getItem('supinkly_admin_server_token');
            if (needsServerPush && hasAdminCreds) {
                fetch('/api/admin/catalog/sync', {
                    method: 'POST',
                    headers: getAdminHeaders(),
                    body: JSON.stringify({
                        customPrices: mergedPrices,
                        customProducts: mergedProducts
                    })
                }).catch(() => { });
            }
        }
    } catch (e) { }
}

function updateNavOrdersCount() {
    const count = (state.orders || []).length;
    const navCnt = document.getElementById('nav-orders-count');
    if (navCnt) navCnt.textContent = count;
    const mobileNavCnt = document.getElementById('mobile-nav-orders-count');
    if (mobileNavCnt) {
        mobileNavCnt.textContent = count;
        mobileNavCnt.classList.toggle('hidden', count === 0);
    }
    const badgeTotal = document.getElementById('customer-keys-count-badge');
    if (badgeTotal) badgeTotal.textContent = `${count} รายการ`;
}

async function refreshUserOrders() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();

    if (isLoggedIn) {
        try {
            // Claim any local unlinked orders under this account
            const localOrderIds = (state.orders || []).map(o => o.orderId).filter(Boolean);
            if (localOrderIds.length > 0) {
                try { await USER_AUTH.linkLocalOrders(localOrderIds); } catch { }
            }

            const serverOrders = await USER_AUTH.fetchMyOrders();
            if (Array.isArray(serverOrders) && serverOrders.length > 0) {
                const serverIds = new Set(serverOrders.map(o => o.orderId));
                const existingLocal = (state.orders || []).filter(o => o.orderId && !serverIds.has(o.orderId));
                const merged = [...serverOrders, ...existingLocal].sort((a, b) => {
                    const timeA = new Date(a.date || 0).getTime() || 0;
                    const timeB = new Date(b.date || 0).getTime() || 0;
                    return timeB - timeA;
                });
                state.orders = merged;
                localStorage.setItem('supinkly_orders', JSON.stringify(merged));
            }
        } catch (e) {
            console.warn("Could not fetch user orders from account:", e);
        }
    } else {
        try {
            const stored = localStorage.getItem('supinkly_orders');
            if (stored) state.orders = JSON.parse(stored) || [];
        } catch { }
    }

    // Actively refresh any pending orders from server (works for both guests & members)
    const pendingOrders = (state.orders || []).filter(o => {
        if (!o || !o.orderId) return false;
        return (o.status && (o.status.includes('รอส่งมอบ') || o.status.includes('รอจัดส่ง') || o.status.includes('pending')))
            || ((o.items || []).some(it => !it.credentials || it.status === 'pending_fulfillment'));
    });

    if (pendingOrders.length > 0) {
        for (const po of pendingOrders.slice(0, 10)) {
            try {
                const customerEmail = po.recipientEmail || po.email || (state.user && state.user.email) || '';
                const queryParam = customerEmail ? `?email=${encodeURIComponent(customerEmail)}` : '';
                const res = await fetch(`/api/orders/${encodeURIComponent(po.orderId)}${queryParam}`, {
                    headers: customerEmail ? { 'x-order-email': customerEmail } : {}
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data && data.success && data.order) {
                        const updated = data.order;
                        const idx = state.orders.findIndex(o => o.orderId === po.orderId);
                        if (idx !== -1) {
                            state.orders[idx] = updated;
                            localStorage.setItem('supinkly_orders', JSON.stringify(state.orders));
                        }
                    }
                }
            } catch { }
        }
    }

    updateNavOrdersCount();
    updateUserHeaderUI();
    return state.orders || [];
}

function saveCart() {
    localStorage.setItem('supinkly_cart', JSON.stringify(state.cart));
    updateCartUI();
}

function saveOrders() {
    try {
        localStorage.setItem('supinkly_orders', JSON.stringify(state.orders || []));
    } catch (e) {
        console.warn("Could not save orders to localStorage:", e);
    }
    updateNavOrdersCount();
    updateUserHeaderUI();
}

// Reconcile and push local client orders to server database (Admin-only disaster recovery)
async function syncLocalOrdersToServer(ordersToSync = null) {
    if (!window.location.protocol.startsWith('http')) return;
    const adminToken = sessionStorage.getItem('supinkly_admin_server_token') || localStorage.getItem('supinkly_admin_server_token');
    const adminPin = sessionStorage.getItem('supinkly_admin_pin');
    // Security Guard: Only authenticated administrators may sync orders to the server
    if (!adminToken && !adminPin) return;

    const list = ordersToSync || state.orders || [];
    if (!Array.isArray(list) || list.length === 0) return;
    try {
        const headers = { 'Content-Type': 'application/json' };
        if (adminToken) headers['x-admin-token'] = adminToken;
        if (adminPin) headers['x-admin-pin'] = adminPin;

        const res = await fetch('/api/checkout/sync-local-orders', {
            method: 'POST',
            headers,
            body: JSON.stringify({ orders: list })
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success && data.syncedCount > 0) {
                console.log(`[SYNC] Synced ${data.syncedCount} orders to backend database.`);
                if (typeof adminOrdersList !== 'undefined' && Array.isArray(adminOrdersList) && Array.isArray(data.orders)) {
                    data.orders.forEach(o => {
                        if (!adminOrdersList.some(ao => ao.orderId === o.orderId)) {
                            adminOrdersList.unshift(o);
                        }
                    });
                }
            }
        }
    } catch (e) {
        // silent fallback on network errors
    }
}

// Header & User Actions
function initHeader() {
    updateUserHeaderUI();
}

let pendingAuthEmail = '';
let resendOtpTimer = null;
let forgotResendTimer = null;

function openAuthModal(tab = 'login') {
    const modal = document.getElementById('auth-modal');
    if (!modal) return;
    switchAuthTab(tab);
    modal.classList.remove('hidden');
}

function closeAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) modal.classList.add('hidden');
    clearAuthErrors();
}

function clearAuthErrors() {
    ['auth-login-error', 'auth-register-error', 'auth-otp-error', 'auth-forgot-request-error', 'auth-forgot-verify-error'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = '';
            el.classList.add('hidden');
        }
    });
}

function showAuthError(elementId, message) {
    const el = document.getElementById(elementId);
    if (el) {
        el.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <span>${escapeHTML(message)}</span>`;
        el.classList.remove('hidden');
    }
}

function switchAuthTab(tab) {
    clearAuthErrors();
    const tabLogin = document.getElementById('auth-tab-login');
    const tabRegister = document.getElementById('auth-tab-register');
    const formLogin = document.getElementById('auth-form-login');
    const formRegister = document.getElementById('auth-form-register');
    const formOtp = document.getElementById('auth-form-otp');
    const formForgotReq = document.getElementById('auth-form-forgot-request');
    const formForgotVerify = document.getElementById('auth-form-forgot-verify');

    [formLogin, formRegister, formOtp, formForgotReq, formForgotVerify].forEach(f => f?.classList.add('hidden'));

    if (tab === 'login') {
        formLogin?.classList.remove('hidden');
        if (tabLogin) tabLogin.className = "flex-1 py-2 rounded-xl bg-white text-pink-600 shadow-xs font-bold transition-all flex items-center justify-center gap-1.5 cursor-pointer";
        if (tabRegister) tabRegister.className = "flex-1 py-2 rounded-xl text-slate-500 hover:text-slate-700 font-medium transition-all flex items-center justify-center gap-1.5 cursor-pointer";
        setTimeout(() => document.getElementById('login-email')?.focus(), 60);
    } else if (tab === 'register') {
        formRegister?.classList.remove('hidden');
        if (tabLogin) tabLogin.className = "flex-1 py-2 rounded-xl text-slate-500 hover:text-slate-700 font-medium transition-all flex items-center justify-center gap-1.5 cursor-pointer";
        if (tabRegister) tabRegister.className = "flex-1 py-2 rounded-xl bg-white text-pink-600 shadow-xs font-bold transition-all flex items-center justify-center gap-1.5 cursor-pointer";
        setTimeout(() => document.getElementById('register-name')?.focus(), 60);
    } else if (tab === 'otp') {
        formOtp?.classList.remove('hidden');
        setTimeout(() => document.getElementById('auth-otp-input')?.focus(), 60);
    } else if (tab === 'forgot-request') {
        formForgotReq?.classList.remove('hidden');
        setTimeout(() => document.getElementById('forgot-email')?.focus(), 60);
    } else if (tab === 'forgot-verify') {
        formForgotVerify?.classList.remove('hidden');
        setTimeout(() => document.getElementById('forgot-otp-input')?.focus(), 60);
    }
}

async function handleLogin() {
    clearAuthErrors();
    const email = (document.getElementById('login-email')?.value || '').trim();
    const password = (document.getElementById('login-password')?.value || '').trim();
    const btn = document.getElementById('login-btn');

    if (!email || !password) {
        showAuthError('auth-login-error', 'กรุณากรอกอีเมลและรหัสผ่านให้ครบถ้วน');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>กำลังเข้าสู่ระบบ...</span>`;
    }

    try {
        if (typeof USER_AUTH !== 'undefined') {
            const res = await USER_AUTH.login(email, password);
            if (res.success) {
                closeAuthModal();
                state.user = USER_AUTH.getUser();
                await refreshUserOrders();
                updateUserHeaderUI();
                updateMemberBadges();
                renderProducts();
                showToast(`ยินดีต้อนรับคุณ ${res.user?.displayName || email}!`, 'success');
                if (state.pendingCheckoutAfterAuth && state.cart && state.cart.length > 0) {
                    state.pendingCheckoutAfterAuth = false;
                    setTimeout(() => {
                        startCheckout();
                    }, 400);
                }
                return;
            } else {
                showAuthError('auth-login-error', res.message || 'อีเมลหรือรหัสผ่านไม่ถูกต้อง');
            }
        } else {
            showAuthError('auth-login-error', 'ระบบยืนยันตัวตนยังไม่พร้อมใช้งาน');
        }
    } catch (e) {
        showAuthError('auth-login-error', 'เกิดข้อผิดพลาดในการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-right-to-bracket"></i> <span>เข้าสู่ระบบ</span>`;
        }
    }
}

async function handleRegister() {
    clearAuthErrors();
    const displayName = (document.getElementById('register-name')?.value || '').trim();
    const email = (document.getElementById('register-email')?.value || '').trim();
    const password = (document.getElementById('register-password')?.value || '').trim();
    const btn = document.getElementById('register-btn');

    if (!displayName || !email || !password) {
        showAuthError('auth-register-error', 'กรุณากรอกข้อมูลให้ครบทุกช่อง');
        return;
    }
    if (password.length < 6) {
        showAuthError('auth-register-error', 'รหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>กำลังลงทะเบียน...</span>`;
    }

    try {
        if (typeof USER_AUTH !== 'undefined') {
            const res = await USER_AUTH.register(email, password, displayName);
            if (res.success) {
                if (res.autoVerified || res.token) {
                    closeAuthModal();
                    state.user = USER_AUTH.getUser();
                    await refreshUserOrders();
                    updateUserHeaderUI();
                    updateMemberBadges();
                    renderProducts();
                    showToast(res.message || `ยินดีต้อนรับคุณ ${res.user?.displayName || displayName}!`, 'success');
                    if (state.pendingCheckoutAfterAuth && state.cart && state.cart.length > 0) {
                        state.pendingCheckoutAfterAuth = false;
                        setTimeout(() => {
                            startCheckout();
                        }, 400);
                    }
                    return;
                }
                pendingAuthEmail = email;
                const emailDisplay = document.getElementById('auth-otp-target-email');
                if (emailDisplay) emailDisplay.textContent = email;
                switchAuthTab('otp');
                startResendOtpTimer();
                if (res.devOtp) {
                    const otpInput = document.getElementById('auth-otp-input');
                    if (otpInput) otpInput.value = res.devOtp;
                    showToast(`รหัส OTP สำหรับยืนยันตัวตนคือ: ${res.devOtp}`, 'info');
                } else {
                    showToast(res.message || 'ส่งรหัส OTP ไปยังอีเมลของคุณแล้ว กรุณาตรวจสอบกล่องข้อความ', 'info');
                }
            } else {
                showAuthError('auth-register-error', res.message || 'ไม่สามารถสมัครสมาชิกได้');
            }
        }
    } catch (e) {
        showAuthError('auth-register-error', 'เกิดข้อผิดพลาดในการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-user-plus"></i> <span>สมัครสมาชิกฟรี</span>`;
        }
    }
}

async function handleVerifyOtp() {
    clearAuthErrors();
    const otp = (document.getElementById('auth-otp-input')?.value || '').trim();
    const btn = document.getElementById('verify-otp-btn');

    if (!otp || otp.length < 6) {
        showAuthError('auth-otp-error', 'กรุณากรอกรหัส OTP 6 หลัก');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>กำลังตรวจสอบ...</span>`;
    }

    try {
        if (typeof USER_AUTH !== 'undefined') {
            const res = await USER_AUTH.verifyOtp(pendingAuthEmail, otp);
            if (res.success) {
                closeAuthModal();
                state.user = USER_AUTH.getUser();
                await refreshUserOrders();
                updateUserHeaderUI();
                updateMemberBadges();
                renderProducts();
                showToast('สมัครสมาชิกและยืนยันอีเมลสำเร็จ ยินดีต้อนรับ!', 'success');
                if (state.pendingCheckoutAfterAuth && state.cart && state.cart.length > 0) {
                    state.pendingCheckoutAfterAuth = false;
                    setTimeout(() => {
                        startCheckout();
                    }, 400);
                }
            } else {
                showAuthError('auth-otp-error', res.message || 'รหัส OTP ไม่ถูกต้องหรือหมดอายุ');
            }
        }
    } catch (e) {
        showAuthError('auth-otp-error', 'เกิดข้อผิดพลาดในการตรวจสอบ กรุณาลองใหม่อีกครั้ง');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-circle-check"></i> <span>ยืนยันรหัส OTP</span>`;
        }
    }
}

async function handleResendOtp() {
    if (!pendingAuthEmail) return;
    const resendBtn = document.getElementById('resend-otp-btn');
    if (resendBtn?.disabled) return;

    try {
        if (typeof USER_AUTH !== 'undefined') {
            const res = await USER_AUTH.resendOtp(pendingAuthEmail);
            if (res.success) {
                startResendOtpTimer();
                showToast('ส่งรหัส OTP ใหม่เรียบร้อยแล้ว', 'info');
            } else {
                showAuthError('auth-otp-error', res.message || 'ส่งรหัส OTP ไม่สำเร็จ');
            }
        }
    } catch (e) {
        showAuthError('auth-otp-error', 'เกิดข้อผิดพลาดในการส่งรหัสใหม่');
    }
}

function startResendOtpTimer() {
    let seconds = 60;
    const btn = document.getElementById('resend-otp-btn');
    const span = document.getElementById('resend-otp-countdown');
    if (btn) btn.disabled = true;
    if (span) span.textContent = seconds;

    clearInterval(resendOtpTimer);
    resendOtpTimer = setInterval(() => {
        seconds--;
        if (span) span.textContent = seconds;
        if (seconds <= 0) {
            clearInterval(resendOtpTimer);
            if (btn) btn.disabled = false;
        }
    }, 1000);
}

function handleBackToRegister() {
    switchAuthTab('register');
}

async function handleForgotPasswordRequest() {
    clearAuthErrors();
    const email = (document.getElementById('forgot-email')?.value || '').trim();
    const btn = document.getElementById('forgot-request-btn');

    if (!email) {
        showAuthError('auth-forgot-request-error', 'กรุณากรอกอีเมลของคุณ');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>กำลังส่ง...</span>`;
    }

    try {
        if (typeof USER_AUTH !== 'undefined') {
            const res = await USER_AUTH.forgotPassword(email);
            if (res.success) {
                pendingAuthEmail = email;
                const emailDisplay = document.getElementById('auth-forgot-target-email');
                if (emailDisplay) emailDisplay.textContent = email;
                switchAuthTab('forgot-verify');
                showToast('ส่งรหัส OTP กู้คืนรหัสผ่านไปยังอีเมลของคุณแล้ว', 'info');
            } else {
                showAuthError('auth-forgot-request-error', res.message || 'ไม่พบบัญชีผู้ใช้นี้');
            }
        }
    } catch (e) {
        showAuthError('auth-forgot-request-error', 'เกิดข้อผิดพลาดในการเชื่อมต่อ');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> <span>ส่งรหัส OTP กู้คืนรหัสผ่าน</span>`;
        }
    }
}

async function handleResetPasswordSubmit() {
    clearAuthErrors();
    const otp = (document.getElementById('forgot-otp-input')?.value || '').trim();
    const newPass = (document.getElementById('forgot-new-password')?.value || '').trim();
    const confirmPass = (document.getElementById('forgot-confirm-password')?.value || '').trim();
    const btn = document.getElementById('forgot-verify-btn');

    if (!otp || !newPass || !confirmPass) {
        showAuthError('auth-forgot-verify-error', 'กรุณากรอกข้อมูลให้ครบถ้วน');
        return;
    }
    if (newPass.length < 6) {
        showAuthError('auth-forgot-verify-error', 'รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 6 ตัวอักษร');
        return;
    }
    if (newPass !== confirmPass) {
        showAuthError('auth-forgot-verify-error', 'รหัสผ่านใหม่ทั้งสองช่องไม่ตรงกัน');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>กำลังบันทึก...</span>`;
    }

    try {
        if (typeof USER_AUTH !== 'undefined') {
            const res = await USER_AUTH.resetPassword(pendingAuthEmail, otp, newPass);
            if (res.success) {
                closeAuthModal();
                await refreshUserOrders();
                updateUserHeaderUI();
                showToast('เปลี่ยนรหัสผ่านและเข้าสู่ระบบสำเร็จแล้ว!', 'success');
            } else {
                showAuthError('auth-forgot-verify-error', res.message || 'รหัส OTP ไม่ถูกต้องหรือหมดอายุ');
            }
        }
    } catch (e) {
        showAuthError('auth-forgot-verify-error', 'เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> <span>บันทึกรหัสผ่านใหม่ & เข้าสู่ระบบ</span>`;
        }
    }
}

function handleResendResetOtp() {
    handleForgotPasswordRequest();
}

function handleUserLogout() {
    if (typeof USER_AUTH !== 'undefined') {
        USER_AUTH.logout();
    }
    if (typeof state !== 'undefined') {
        state.user = null;
        state.orders = [];
        state.coinsToRedeem = 0;
        state.referralCode = null;
        state.referralDiscount = null;
    }
    localStorage.removeItem('supinkly_orders');
    sessionStorage.removeItem('supinkly_orders');
    updateNavOrdersCount();

    const ordersModal = document.getElementById('orders-modal');
    if (ordersModal && !ordersModal.classList.contains('hidden')) {
        closeOrdersModal();
    }
    const vaultModal = document.getElementById('vault-modal');
    if (vaultModal && !vaultModal.classList.contains('hidden')) {
        closeVaultModal();
    }

    updateUserHeaderUI();
    updateMemberBadges();
    renderProducts();
    showToast('ออกจากระบบและล้างข้อมูลคีย์ในเครื่องนี้เรียบร้อยแล้ว', 'info');
}

function updateUserHeaderUI() {
    const section = document.getElementById('user-header-section');
    if (!section) return;

    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;

    if (isLoggedIn && user) {
        let vipBadgeClass = "bg-amber-100 text-amber-800 border-amber-300";
        if (user.vip?.tier === 'diamond') vipBadgeClass = "bg-cyan-100 text-cyan-800 border-cyan-300";
        else if (user.vip?.tier === 'silver') vipBadgeClass = "bg-slate-200 text-slate-800 border-slate-300";
        else if (user.vip?.tier === 'bronze') vipBadgeClass = "bg-amber-50 text-amber-900 border-amber-200";

        section.innerHTML = `
            <div class="flex items-center gap-1.5 sm:gap-2">
                <div class="flex items-center gap-1">
                    <button onclick="openOrdersModal('orders')" class="h-10 sm:h-11 px-2.5 sm:px-3.5 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-pink-50 hover:bg-pink-100 border-2 border-pink-200 hover:border-pink-300 text-pink-700 transition-all shadow-xs flex items-center justify-center gap-1.5 shrink-0 cursor-pointer active:scale-95" title="ศูนย์สมาชิก & คลังคีย์">
                        <i class="fa-solid fa-circle-user text-pink-500 text-sm sm:text-base"></i>
                        <span class="max-w-[85px] sm:max-w-[110px] truncate">${escapeHTML(user.displayName || user.name || 'สมาชิก')}</span>
                        <span class="inline-flex items-center gap-0.5 px-1.5 py-0.2 rounded-full text-[10px] font-black border ${vipBadgeClass}">
                            <i class="fa-solid fa-crown text-[9px] text-amber-500"></i>
                            <span>${escapeHTML(user.vip?.tierName || 'Bronze')}</span>
                        </span>
                    </button>
                    <button onclick="handleUserLogout()" title="ออกจากระบบ" class="h-10 sm:h-11 w-10 sm:w-11 rounded-xl sm:rounded-2xl bg-slate-100 hover:bg-rose-50 text-slate-500 hover:text-rose-600 border-2 border-slate-200 hover:border-rose-300 transition-all flex items-center justify-center cursor-pointer active:scale-95">
                        <i class="fa-solid fa-right-from-bracket text-xs sm:text-sm"></i>
                    </button>
                </div>
            </div>
        `;
    } else {
        section.innerHTML = `
            <div class="flex items-center gap-1.5 sm:gap-2">
                <button onclick="openOrdersModal('orders')" title="ประวัติการสั่งซื้อ & คีย์ของฉัน" class="h-10 sm:h-11 px-2.5 sm:px-3 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-purple-50 hover:bg-purple-100 border-2 border-purple-200/90 hover:border-purple-300 text-purple-700 transition-all shadow-xs flex items-center justify-center gap-1.5 shrink-0 cursor-pointer active:scale-95">
                    <i class="fa-solid fa-box-open text-sm sm:text-base text-purple-600"></i>
                    <span class="hidden lg:inline font-bold">คีย์ของฉัน</span>
                    <span class="px-1.5 py-0.2 rounded-full bg-purple-200/80 text-purple-900 text-[10px] sm:text-xs font-black leading-none">(<span id="nav-orders-count">${(state.orders || []).length}</span>)</span>
                </button>
                <button onclick="openAuthModal('login')" title="เข้าสู่ระบบบัญชี" class="h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-gradient-to-r from-pink-500 to-rose-500 hover:from-pink-600 hover:to-rose-600 text-white transition-all shadow-sm hover:shadow-pink-500/25 flex items-center justify-center gap-1.5 shrink-0 touch-active cursor-pointer active:scale-95">
                    <i class="fa-solid fa-right-to-bracket text-xs sm:text-sm"></i>
                    <span class="inline font-bold">เข้าสู่ระบบ</span>
                </button>
            </div>
        `;
    }
    if (typeof updateCartUI === 'function') updateCartUI();
    if (typeof updateMemberBadges === 'function') updateMemberBadges();
    updateNavOrdersCount();
}

// Brand Tabs
function renderBrandTabs() {
    const container = document.getElementById('brand-tabs-container');
    if (!container) return;

    const highlightCount = state.products.filter(p => !p.deleted && !!p.isHighlight).length;

    const brands = [
        { key: "all", name: "สินค้าทั้งหมด", icon: "fa-solid fa-shapes", count: state.products.filter(p => !p.deleted).length },
        { key: "highlight", name: "⭐ ดีลไฮไลท์", icon: "fa-solid fa-star text-amber-500", count: highlightCount },
        { key: "CapCut", name: "CapCut", icon: "fa-solid fa-scissors", count: state.products.filter(p => !p.deleted && p.brand === 'CapCut').length },
        { key: "Google AI", name: "Google AI", icon: "fa-solid fa-wand-magic-sparkles", count: state.products.filter(p => !p.deleted && p.brand === 'Google AI').length },
        { key: "Google", name: "Google", icon: "fa-brands fa-google", count: state.products.filter(p => !p.deleted && p.brand === 'Google').length },
        { key: "Grok", name: "Grok", icon: "fa-solid fa-bolt", count: state.products.filter(p => !p.deleted && p.brand === 'Grok').length },
        { key: "Claude", name: "Claude", icon: "fa-solid fa-brain", count: state.products.filter(p => !p.deleted && p.brand === 'Claude').length },
        { key: "Adobe", name: "Adobe", icon: "fa-solid fa-bezier-curve", count: state.products.filter(p => !p.deleted && p.brand === 'Adobe').length },
        { key: "Microsoft", name: "Microsoft", icon: "fa-brands fa-microsoft", count: state.products.filter(p => !p.deleted && p.brand === 'Microsoft').length },
    ];

    container.innerHTML = brands.map(b => `
        <button onclick="selectBrand('${b.key}')" 
            class="brand-tab flex items-center gap-2 px-4 py-2.5 rounded-2xl text-xs md:text-sm font-bold border transition-all whitespace-nowrap cursor-pointer ${state.filterBrand === b.key ? 'active' : ''}">
            <i class="${b.icon} ${state.filterBrand === b.key ? 'text-white' : 'text-pink-500'}"></i>
            <span>${escapeHTML(b.name)}</span>
            <span class="ml-1 px-2 py-0.5 rounded-full text-xs ${state.filterBrand === b.key ? 'bg-white/25 text-white font-black' : 'bg-slate-100 text-slate-600 font-bold'}">${b.count}</span>
        </button>
    `).join('');
}

function selectBrand(brand) {
    state.filterBrand = brand;
    renderBrandTabs();
    applyFilters();
    if (brand === 'highlight') {
        const prodSec = document.getElementById('products-section');
        if (prodSec) prodSec.scrollIntoView({ behavior: 'smooth' });
    }
}

function selectType(type) {
    state.filterType = type;
    document.querySelectorAll('.type-filter-btn').forEach(btn => {
        if (btn.dataset.type === type) {
            btn.classList.add('bg-pink-500', 'text-white', 'shadow-md', 'shadow-pink-500/30', 'border-transparent');
            btn.classList.remove('bg-white', 'text-slate-700', 'border-slate-200');
        } else {
            btn.classList.remove('bg-pink-500', 'text-white', 'shadow-md', 'shadow-pink-500/30', 'border-transparent');
            btn.classList.add('bg-white', 'text-slate-700', 'border-slate-200');
        }
    });
    applyFilters();
}

function initFilters() {
    const searchInput = document.getElementById('search-input');
    const mobileSearchInput = document.getElementById('mobile-search-input');
    const desktopClear = document.getElementById('desktop-search-clear');
    const mobileClear = document.getElementById('mobile-search-clear');

    const handleSearch = (val, origin) => {
        state.searchQuery = (val || '').toLowerCase().trim();
        if (origin !== 'desktop' && searchInput) searchInput.value = val;
        if (origin !== 'mobile' && mobileSearchInput) mobileSearchInput.value = val;
        if (desktopClear) desktopClear.classList.toggle('hidden', !val);
        if (mobileClear) mobileClear.classList.toggle('hidden', !val);
        applyFilters();
    };

    if (searchInput) {
        searchInput.addEventListener('input', (e) => handleSearch(e.target.value, 'desktop'));
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                scrollToProducts();
            }
        });
    }
    if (mobileSearchInput) {
        mobileSearchInput.addEventListener('input', (e) => handleSearch(e.target.value, 'mobile'));
        mobileSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                scrollToProducts();
                mobileSearchInput.blur();
            }
        });
    }

    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) {
        sortSelect.addEventListener('change', (e) => {
            state.sortBy = e.target.value;
            applyFilters();
        });
    }
}

function applyFilters() {
    let result = [...state.products].filter(p => !p.deleted);

    if (state.filterBrand === 'highlight') {
        result = result.filter(p => !!p.isHighlight);
    } else if (state.filterBrand !== 'all') {
        result = result.filter(p => p.brand === state.filterBrand);
    }

    if (state.filterType !== 'all') {
        result = result.filter(p => p.typeKey === state.filterType);
    }

    if (state.searchQuery !== '') {
        result = result.filter(p =>
            p.title.toLowerCase().includes(state.searchQuery) ||
            p.brand.toLowerCase().includes(state.searchQuery) ||
            (p.description && p.description.toLowerCase().includes(state.searchQuery))
        );
    }

    if (state.sortBy === 'price_asc') {
        result.sort((a, b) => a.price - b.price);
    } else if (state.sortBy === 'price_desc') {
        result.sort((a, b) => b.price - a.price);
    } else if (state.sortBy === 'stock') {
        result.sort((a, b) => b.stock - a.stock);
    } else {
        result.sort((a, b) => b.soldCount - a.soldCount);
    }

    state.filteredProducts = result;
    renderProducts();
}

// Mobile-friendly typography & badge helpers
function getShortTypeBadge(type, typeKey) {
    if (typeKey === 'private') return 'ส่วนตัว';
    if (typeKey === 'shared') return 'แชร์';
    if (typeKey === 'link') return 'ลิงก์';
    if (typeKey === 'key') return 'คีย์แท้';
    if (typeKey === 'topup') return 'เติมเงิน';
    if (!type) return 'มาตรฐาน';
    return String(type).replace(/\s*\(.*?\)/g, '').trim() || type;
}

function formatProductPrice(price) {
    if (price === undefined || price === null || price === '') return '0';
    const num = typeof price === 'number' ? price : parseFloat(String(price).replace(/,/g, ''));
    if (isNaN(num)) return '0';
    return (num % 1 === 0) ? num.toLocaleString('th-TH') : num.toLocaleString('th-TH', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// Render Highlight Products Showcase Grid (⭐ ดีลเด็ดไฮไลท์คัดสรรพิเศษ)
function renderHighlightProducts() {
    const container = document.getElementById('highlight-products-grid');
    if (!container) return;

    // Filter active highlight products
    let highlights = state.products.filter(p => !p.deleted && !!p.isHighlight);

    // Fallback: If no products marked as highlight, show top 4 bestsellers
    if (highlights.length === 0) {
        highlights = [...state.products]
            .filter(p => !p.deleted)
            .sort((a, b) => (b.soldCount || 0) - (a.soldCount || 0))
            .slice(0, 4);
    }

    container.innerHTML = highlights.map(product => {
        let typeBadgeClass = "bg-purple-100 text-purple-700 border-purple-200";
        if (product.typeKey === 'private') typeBadgeClass = "bg-pink-100 text-pink-700 border-pink-200";
        if (product.typeKey === 'shared') typeBadgeClass = "bg-amber-100 text-amber-800 border-amber-200";
        if (product.typeKey === 'link') typeBadgeClass = "bg-cyan-100 text-cyan-800 border-cyan-200";
        if (product.typeKey === 'key') typeBadgeClass = "bg-emerald-100 text-emerald-800 border-emerald-200";

        const inStock = product.stock > 0;
        const discountPercent = product.originalPrice > product.price
            ? Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100)
            : 0;

        const shortType = getShortTypeBadge(product.type, product.typeKey);
        const formattedPrice = formatProductPrice(product.price);
        const formattedOrigPrice = formatProductPrice(product.originalPrice);
        const savings = (product.originalPrice > product.price)
            ? formatProductPrice(product.originalPrice - product.price)
            : '0';

        const cardUser = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
        const isWishlisted = isProductWishlisted(product.id);
        const isAlerted = !!(cardUser && Array.isArray(cardUser.stockAlerts) && cardUser.stockAlerts.includes(product.id));

                        const isMsHighlight = (product.brand && /micro/i.test(product.brand)) || 
                                              (product.brandCode && /ms/i.test(product.brandCode)) ||
                                              (product.id && /^ms-/i.test(product.id));
                        return `
            <div class="bg-white/95 backdrop-blur-sm rounded-2xl sm:rounded-3xl p-2.5 sm:p-5 border-2 border-amber-200/90 hover:border-pink-400 shadow-xs hover:shadow-xl hover:shadow-pink-500/10 flex flex-col justify-between transition-all duration-300 group hover:-translate-y-1 relative overflow-hidden cursor-pointer" 
                 data-action="card" data-product-id="${escapeHTML(product.id)}">
                
                <!-- Glow accent -->
                <div class="absolute -top-10 -right-10 w-24 h-24 bg-gradient-to-br from-amber-400/20 to-pink-400/20 rounded-full blur-xl pointer-events-none"></div>

                <div>
                    <!-- Header of Card -->
                    <div class="flex items-center justify-between gap-1 mb-1.5 sm:mb-3">
                        <div class="flex items-center gap-1 sm:gap-2 min-w-0">
                            <span title="${escapeHTML(product.brand || '')}" class="w-6 h-6 sm:w-8 sm:h-8 rounded-lg sm:rounded-xl bg-gradient-to-br from-amber-50 to-pink-50 border border-amber-200 flex items-center justify-center text-[9px] sm:text-xs font-black text-pink-600 shadow-inner shrink-0">
                                ${escapeHTML(product.brandCode || 'AI')}
                            </span>
                            ${isMsHighlight ? '' : `<span class="brand-name-text text-[11px] sm:text-xs font-bold text-slate-700 truncate">${escapeHTML(product.brand || 'Supinkly')}</span>`}
                        </div>
                        <div class="flex items-center gap-1 sm:gap-1.5 shrink-0">
                            <span class="px-1.5 sm:px-2.5 py-0.5 rounded-full text-[9px] sm:text-xs font-bold border ${typeBadgeClass} whitespace-nowrap">
                                <span class="sm:hidden">${escapeHTML(shortType)}</span>
                                <span class="hidden sm:inline">${escapeHTML(product.type)}</span>
                            </span>
                            <button data-action="wishlist" data-product-id="${escapeHTML(product.id)}" title="${isWishlisted ? 'นำออกจากที่ชอบ' : 'บันทึกในรายการโปรด'}" 
                                class="w-7 h-7 sm:w-8 sm:h-8 rounded-full ${isWishlisted ? 'bg-rose-500 text-white shadow-xs' : 'bg-slate-100 hover:bg-rose-50 text-slate-400 hover:text-rose-500 border border-slate-200 hover:border-rose-300'} flex items-center justify-center text-xs transition-all cursor-pointer active:scale-90 shadow-2xs">
                                <i class="fa-${isWishlisted ? 'solid' : 'regular'} fa-heart"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Highlight Ribbon/Badge -->
                    <div class="mb-1.5 sm:mb-2">
                        <span class="inline-flex items-center gap-1 px-1.5 sm:px-2 py-0.5 rounded-md bg-gradient-to-r from-amber-500 to-rose-500 text-white font-black text-[9px] sm:text-[10px] shadow-2xs">
                            <i class="fa-solid fa-crown text-[8px] sm:text-[9px]"></i>
                            <span class="truncate max-w-[120px] sm:max-w-none">${escapeHTML(product.badge || '⭐ สินค้าไฮไลท์')}</span>
                        </span>
                    </div>

                    <!-- Title -->
                    <h3 class="text-[12px] sm:text-base font-normal text-slate-900 line-clamp-2 min-h-[32px] sm:min-h-[44px] group-hover:text-pink-600 transition-colors leading-tight sm:leading-snug">
                        ${escapeHTML(product.title)}
                    </h3>

                    <!-- Specs (Compact on mobile) -->
                    <div class="flex flex-wrap items-center gap-1 sm:gap-2 mt-1.5 sm:mt-3 text-[9px] sm:text-xs text-slate-600 font-medium">
                        <span class="inline-flex items-center gap-0.5 sm:gap-1 bg-amber-50/90 px-1.5 py-0.5 rounded-md border border-amber-200/80 text-amber-900 font-bold">
                            <i class="fa-solid fa-bolt text-amber-500 text-[8px] sm:text-[10px]"></i> ส่งทันที
                        </span>
                        <span class="inline-flex items-center gap-0.5 sm:gap-1 bg-slate-50 px-1.5 py-0.5 rounded-md border border-slate-200">
                            <i class="fa-solid fa-shield-halved text-cyan-600 text-[8px] sm:text-[10px]"></i> ประกัน ${escapeHTML(product.warranty || '30 วัน')}
                        </span>
                        <span class="hidden sm:inline-flex items-center gap-1 bg-slate-50 px-1.5 py-0.5 rounded-md border border-slate-200">
                            <i class="fa-solid fa-globe text-purple-600 text-[10px]"></i> ${escapeHTML(product.region || 'Global')}
                        </span>
                    </div>

                    <!-- Stock Counter (Collision-free) -->
                    <div class="flex items-center justify-between mt-2 sm:mt-3 text-[9px] sm:text-xs font-semibold border-t border-slate-100 pt-1.5 sm:pt-2 gap-1">
                        <span class="inline-flex items-center gap-1 ${inStock ? 'text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded-md border border-emerald-200' : 'text-rose-700 bg-rose-50 px-1.5 py-0.5 rounded-md border border-rose-200'} shrink-0 font-bold">
                            <span class="w-1.5 h-1.5 rounded-full ${inStock ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                            ${inStock ? `สต็อก ${product.stock}` : 'หมด'}
                        </span>
                        <span class="text-slate-400 truncate text-right">ขายแล้ว ${(product.soldCount || 0).toLocaleString()}<span class="hidden sm:inline"> ชิ้น</span></span>
                    </div>
                </div>

                <!-- Price and Action Footer -->
                <div class="mt-2.5 sm:mt-3 pt-2.5 sm:pt-3 border-t border-slate-100 flex flex-col gap-2">
                    <!-- Price Display Row (100% full width, crystal clear, unclipped) -->
                    <div class="flex items-end justify-between gap-1.5">
                        <div class="min-w-0">
                            ${discountPercent > 0 && formattedOrigPrice ? `
                                <div class="flex items-center gap-1.5 mb-0.5">
                                    <span class="text-[10px] sm:text-xs text-slate-400 line-through font-medium">฿${formattedOrigPrice}</span>
                                    <span class="text-[9px] sm:text-[10px] font-black px-1.5 py-0.2 rounded-md bg-rose-50 text-rose-600 border border-rose-200/80 shrink-0">-${discountPercent}%</span>
                                </div>
                            ` : ''}
                            <div class="flex items-baseline gap-0.5 text-pink-600 leading-none">
                                <span class="text-xs sm:text-sm font-black mr-0.5">฿</span>
                                <span class="text-xl sm:text-2xl font-black font-['Outfit'] tracking-tight">${formattedPrice}</span>
                            </div>
                        </div>

                        ${discountPercent > 0 ? `
                            <div class="text-[9px] sm:text-[10px] font-bold text-emerald-700 bg-emerald-50 px-1.5 sm:px-2 py-0.5 rounded-lg border border-emerald-200/70 shrink-0 mb-0.5">
                                ประหยัด ฿${savings}
                            </div>
                        ` : `
                            <div class="text-[9px] sm:text-[10px] font-bold text-slate-500 bg-slate-50 px-1.5 sm:px-2 py-0.5 rounded-lg border border-slate-200 shrink-0 mb-0.5">
                                ราคาพิเศษ
                            </div>
                        `}
                    </div>

                    <!-- Action Buttons Row -->
                    <div class="flex items-center gap-1.5 sm:gap-2 pt-0.5">
                        ${!inStock ? `
                        <button data-action="stock-alert" data-product-id="${escapeHTML(product.id)}" title="${isAlerted ? 'แจ้งเตือนเมื่อมีของ (เปิดแล้ว)' : 'แจ้งเตือนเมื่อมีสินค้า'}" 
                            class="w-8 h-8 sm:w-9 sm:h-9 rounded-xl ${isAlerted ? 'bg-amber-50 border-amber-300 text-amber-600' : 'bg-slate-100 hover:bg-amber-50 border border-slate-200 hover:border-amber-300 text-slate-500 hover:text-amber-500'} border flex items-center justify-center text-xs sm:text-sm transition-all shadow-2xs cursor-pointer active:scale-90 shrink-0">
                            <i class="fa-${isAlerted ? 'solid' : 'regular'} fa-bell"></i>
                        </button>
                        ` : ''}
                        <button data-action="detail" data-product-id="${escapeHTML(product.id)}" title="ดูรายละเอียดสินค้า" 
                            class="w-8 h-8 sm:w-9 sm:h-9 rounded-xl bg-slate-100 hover:bg-pink-50 border border-slate-200 hover:border-pink-300 text-slate-600 hover:text-pink-600 flex items-center justify-center text-xs sm:text-sm transition-all shadow-2xs cursor-pointer active:scale-90 shrink-0">
                            <i class="fa-regular fa-eye"></i>
                        </button>
                        <button data-action="add-cart" data-product-id="${escapeHTML(product.id)}"
                            ${!inStock ? 'disabled' : ''}
                            class="flex-1 h-8 sm:h-9 rounded-xl gradient-btn text-white text-[11px] sm:text-xs font-black flex items-center justify-center gap-1.5 cursor-pointer active:scale-95 transition-transform shadow-xs ${!inStock ? 'opacity-40 cursor-not-allowed' : ''}">
                            <i class="fa-solid fa-cart-plus text-xs"></i>
                            <span>${inStock ? 'ใส่ตะกร้า' : 'หมด'}</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    // Safety cleanup: ensure no "Micros" text ever appears on MS highlight cards
    container.querySelectorAll('[data-product-id]').forEach(card => {
        const pid = card.getAttribute('data-product-id') || '';
        if (pid.startsWith('ms-')) {
            card.querySelectorAll('span.truncate, .brand-name-text').forEach(s => {
                if (/micro/i.test(s.textContent || '')) s.remove();
            });
        }
    });

    container.removeEventListener('click', handleProductCardClick);
    container.addEventListener('click', handleProductCardClick);
}

// Render Products Grid (Bright, High-Contrast Cards)
function renderProducts() {
    renderHighlightProducts();

    const container = document.getElementById('products-grid');
    const countEl = document.getElementById('product-count-display');
    if (!container) return;

    if (countEl) {
        countEl.textContent = `พบสินค้า ${state.filteredProducts.length} รายการ`;
    }

    if (state.filteredProducts.length === 0) {
        container.innerHTML = `
            <div class="col-span-full py-16 text-center bg-white rounded-3xl border border-slate-200 p-8 shadow-sm">
                <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-pink-100 border border-pink-200 flex items-center justify-center text-pink-600 text-2xl">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </div>
                <h3 class="text-lg font-bold text-slate-900">ไม่พบสินค้าที่คุณค้นหา</h3>
                <p class="text-sm text-slate-500 mt-1 font-medium">ลองเปลี่ยนคำค้นหา หรือเลือกหมวดหมู่อื่นดูนะครับ</p>
                <button onclick="resetFilters()" class="mt-4 px-5 py-2.5 rounded-xl text-sm font-bold gradient-btn text-white">
                    ล้างการค้นหาทั้งหมด
                </button>
            </div>
        `;
        return;
    }

    container.innerHTML = state.filteredProducts.map(product => {
        let typeBadgeClass = "bg-purple-100 text-purple-700 border-purple-200";
        if (product.typeKey === 'private') typeBadgeClass = "bg-pink-100 text-pink-700 border-pink-200";
        if (product.typeKey === 'shared') typeBadgeClass = "bg-amber-100 text-amber-800 border-amber-200";
        if (product.typeKey === 'link') typeBadgeClass = "bg-cyan-100 text-cyan-800 border-cyan-200";
        if (product.typeKey === 'key') typeBadgeClass = "bg-emerald-100 text-emerald-800 border-emerald-200";

        const inStock = product.stock > 0;
        const discountPercent = product.originalPrice > product.price
            ? Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100)
            : 0;

        const shortType = getShortTypeBadge(product.type, product.typeKey);
        const formattedPrice = formatProductPrice(product.price);
        const formattedOrigPrice = formatProductPrice(product.originalPrice);
        const savings = (product.originalPrice > product.price)
            ? formatProductPrice(product.originalPrice - product.price)
            : '0';

        const cardUser = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
        const isWishlisted = isProductWishlisted(product.id);
        const isAlerted = !!(cardUser && Array.isArray(cardUser.stockAlerts) && cardUser.stockAlerts.includes(product.id));

        const isMsProd = (product.brand && /micro/i.test(product.brand)) || 
                         (product.brandCode && /ms/i.test(product.brandCode)) ||
                         (product.id && /^ms-/i.test(product.id));
        return `
            <div class="bg-white rounded-2xl sm:rounded-3xl p-2.5 sm:p-5 border-2 border-slate-100 hover:border-pink-300 shadow-xs hover:shadow-xl hover:shadow-pink-500/10 flex flex-col justify-between transition-all duration-300 group hover:-translate-y-1 relative overflow-hidden cursor-pointer" data-action="card" data-product-id="${escapeHTML(product.id)}">
                
                <div>
                    <!-- Header of Card -->
                    <div class="flex items-center justify-between gap-1 mb-1.5 sm:mb-3">
                        <div class="flex items-center gap-1 sm:gap-2 min-w-0">
                            <span title="${escapeHTML(product.brand || '')}" class="w-6 h-6 sm:w-8 sm:h-8 rounded-lg sm:rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center text-[9px] sm:text-xs font-black text-pink-600 shadow-inner shrink-0">
                                ${escapeHTML(product.brandCode || 'AI')}
                            </span>
                            ${isMsProd ? '' : `<span class="brand-name-text text-[11px] sm:text-xs font-bold text-slate-700 truncate">${escapeHTML(product.brand || 'Supinkly')}</span>`}
                        </div>
                        <div class="flex items-center gap-1 sm:gap-1.5 shrink-0">
                            <span class="px-1.5 sm:px-2.5 py-0.5 rounded-full text-[9px] sm:text-xs font-bold border ${typeBadgeClass} whitespace-nowrap">
                                <span class="sm:hidden">${escapeHTML(shortType)}</span>
                                <span class="hidden sm:inline">${escapeHTML(product.type)}</span>
                            </span>
                            <button data-action="wishlist" data-product-id="${escapeHTML(product.id)}" title="${isWishlisted ? 'นำออกจากที่ชอบ' : 'บันทึกในรายการโปรด'}" 
                                class="w-7 h-7 sm:w-8 sm:h-8 rounded-full ${isWishlisted ? 'bg-rose-500 text-white shadow-xs' : 'bg-slate-100 hover:bg-rose-50 text-slate-400 hover:text-rose-500 border border-slate-200 hover:border-rose-300'} flex items-center justify-center text-xs transition-all cursor-pointer active:scale-90 shadow-2xs">
                                <i class="fa-${isWishlisted ? 'solid' : 'regular'} fa-heart"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Title -->
                    <h3 class="text-[12px] sm:text-base font-normal text-slate-900 line-clamp-2 min-h-[32px] sm:min-h-[44px] group-hover:text-pink-600 transition-colors leading-tight sm:leading-snug">
                        ${escapeHTML(product.title)}
                    </h3>

                    <!-- Specs -->
                    <div class="flex flex-wrap items-center gap-1 sm:gap-2 mt-1.5 sm:mt-3 text-[9px] sm:text-xs text-slate-600 font-medium">
                        <span class="inline-flex items-center gap-0.5 sm:gap-1 bg-slate-50 px-1.5 py-0.5 rounded-md border border-slate-200 text-slate-700 font-bold">
                            <i class="fa-solid fa-bolt text-amber-500 text-[8px] sm:text-[10px]"></i> ส่งทันที
                        </span>
                        <span class="inline-flex items-center gap-0.5 sm:gap-1 bg-slate-50 px-1.5 py-0.5 rounded-md border border-slate-200">
                            <i class="fa-solid fa-shield-halved text-cyan-600 text-[8px] sm:text-[10px]"></i> ประกัน ${escapeHTML(product.warranty || '30 วัน')}
                        </span>
                        <span class="hidden sm:inline-flex items-center gap-1 bg-slate-50 px-1.5 py-0.5 rounded-md border border-slate-200">
                            <i class="fa-solid fa-globe text-purple-600 text-[10px]"></i> ${escapeHTML(product.region || 'Global')}
                        </span>
                    </div>

                    <!-- Stock Counter -->
                    <div class="flex items-center justify-between mt-2 sm:mt-3 text-[9px] sm:text-xs font-semibold border-t border-slate-100 pt-1.5 sm:pt-2.5 gap-1">
                        <span class="inline-flex items-center gap-1 ${inStock ? 'text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded-md border border-emerald-200' : 'text-rose-700 bg-rose-50 px-1.5 py-0.5 rounded-md border border-rose-200'} shrink-0 font-bold">
                            <span class="w-1.5 h-1.5 rounded-full ${inStock ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                            ${inStock ? `สต็อก ${product.stock}` : 'หมด'}
                        </span>
                        <span class="text-slate-400 truncate text-right">ขายแล้ว ${(product.soldCount || 0).toLocaleString()}<span class="hidden sm:inline"> ชิ้น</span></span>
                    </div>
                </div>

                <!-- Price and Action Footer -->
                <div class="mt-2.5 sm:mt-3 pt-2.5 sm:pt-3 border-t border-slate-100 flex flex-col gap-2">
                    <!-- Price Display Row (100% full width, crystal clear, unclipped) -->
                    <div class="flex items-end justify-between gap-1.5">
                        <div class="min-w-0">
                            ${discountPercent > 0 && formattedOrigPrice ? `
                                <div class="flex items-center gap-1.5 mb-0.5">
                                    <span class="text-[10px] sm:text-xs text-slate-400 line-through font-medium">฿${formattedOrigPrice}</span>
                                    <span class="text-[9px] sm:text-[10px] font-black px-1.5 py-0.2 rounded-md bg-rose-50 text-rose-600 border border-rose-200/80 shrink-0">-${discountPercent}%</span>
                                </div>
                            ` : ''}
                            <div class="flex items-baseline gap-0.5 text-pink-600 leading-none">
                                <span class="text-xs sm:text-sm font-black mr-0.5">฿</span>
                                <span class="text-xl sm:text-2xl font-black font-['Outfit'] tracking-tight">${formattedPrice}</span>
                            </div>
                        </div>

                        ${discountPercent > 0 ? `
                            <div class="text-[9px] sm:text-[10px] font-bold text-emerald-700 bg-emerald-50 px-1.5 sm:px-2 py-0.5 rounded-lg border border-emerald-200/70 shrink-0 mb-0.5">
                                ประหยัด ฿${savings}
                            </div>
                        ` : `
                            <div class="text-[9px] sm:text-[10px] font-bold text-slate-500 bg-slate-50 px-1.5 sm:px-2 py-0.5 rounded-lg border border-slate-200 shrink-0 mb-0.5">
                                ราคาพิเศษ
                            </div>
                        `}
                    </div>

                    <!-- Action Buttons Row -->
                    <div class="flex items-center gap-1.5 sm:gap-2 pt-0.5">
                        ${!inStock ? `
                        <button data-action="stock-alert" data-product-id="${escapeHTML(product.id)}" title="${isAlerted ? 'แจ้งเตือนเมื่อมีของ (เปิดแล้ว)' : 'แจ้งเตือนเมื่อมีสินค้า'}" 
                            class="w-8 h-8 sm:w-9 sm:h-9 rounded-xl ${isAlerted ? 'bg-amber-50 border-amber-300 text-amber-600' : 'bg-slate-100 hover:bg-amber-50 border border-slate-200 hover:border-amber-300 text-slate-500 hover:text-amber-500'} border flex items-center justify-center text-xs sm:text-sm transition-all shadow-2xs cursor-pointer active:scale-90 shrink-0">
                            <i class="fa-${isAlerted ? 'solid' : 'regular'} fa-bell"></i>
                        </button>
                        ` : ''}
                        <button data-action="detail" data-product-id="${escapeHTML(product.id)}" title="ดูรายละเอียดสินค้า" 
                            class="w-8 h-8 sm:w-9 sm:h-9 rounded-xl bg-slate-100 hover:bg-pink-50 border border-slate-200 hover:border-pink-300 text-slate-600 hover:text-pink-600 flex items-center justify-center text-xs sm:text-sm transition-all shadow-2xs cursor-pointer active:scale-90 shrink-0">
                            <i class="fa-regular fa-eye"></i>
                        </button>
                        <button data-action="add-cart" data-product-id="${escapeHTML(product.id)}"
                            ${!inStock ? 'disabled' : ''}
                            class="flex-1 h-8 sm:h-9 rounded-xl gradient-btn text-white text-[11px] sm:text-xs font-black flex items-center justify-center gap-1.5 cursor-pointer active:scale-95 transition-transform shadow-xs ${!inStock ? 'opacity-40 cursor-not-allowed' : ''}">
                            <i class="fa-solid fa-cart-plus text-xs"></i>
                            <span>${inStock ? 'ใส่ตะกร้า' : 'หมด'}</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    // Safety cleanup: ensure no "Micros" text ever appears on MS product cards
    container.querySelectorAll('[data-product-id]').forEach(card => {
        const pid = card.getAttribute('data-product-id') || '';
        if (pid.startsWith('ms-')) {
            card.querySelectorAll('span.truncate, .brand-name-text').forEach(s => {
                if (/micro/i.test(s.textContent || '')) s.remove();
            });
        }
    });

    // [FIX #6] Event delegation สำหรับ product cards ทั้งหมด
    container.removeEventListener('click', handleProductCardClick);
    container.addEventListener('click', handleProductCardClick);
}

function handleProductCardClick(e) {
    const wishlistBtn = e.target.closest('[data-action="wishlist"]');
    if (wishlistBtn) {
        e.stopPropagation();
        const id = wishlistBtn.getAttribute('data-product-id');
        if (id) toggleProductWishlist(id);
        return;
    }

    const stockAlertBtn = e.target.closest('[data-action="stock-alert"]');
    if (stockAlertBtn) {
        e.stopPropagation();
        const id = stockAlertBtn.getAttribute('data-product-id');
        if (id) toggleProductStockAlert(id);
        return;
    }

    const cartBtn = e.target.closest('[data-action="add-cart"]');
    if (cartBtn) {
        e.stopPropagation();
        if (!cartBtn.disabled) {
            const id = cartBtn.getAttribute('data-product-id');
            if (id) addToCart(id);
        }
        return;
    }

    const detailBtn = e.target.closest('[data-action="detail"]');
    if (detailBtn) {
        e.stopPropagation();
        const id = detailBtn.getAttribute('data-product-id');
        if (id) openProductDetailModal(id);
        return;
    }

    const card = e.target.closest('[data-action="card"]');
    if (card) {
        const id = card.getAttribute('data-product-id');
        if (id) openProductDetailModal(id);
    }
}

function resetFilters() {
    state.filterBrand = 'all';
    state.filterType = 'all';
    state.searchQuery = '';
    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';
    const mobileSearchInput = document.getElementById('mobile-search-input');
    if (mobileSearchInput) mobileSearchInput.value = '';
    const desktopClear = document.getElementById('desktop-search-clear');
    if (desktopClear) desktopClear.classList.add('hidden');
    const mobileClear = document.getElementById('mobile-search-clear');
    if (mobileClear) mobileClear.classList.add('hidden');
    renderBrandTabs();
    selectType('all');
    applyFilters();
}

// ==========================================
// CART (Stock Referenced from G2G Auto-Sync)
// ==========================================
function addToCart(productId) {
    const master = getMasterProduct(productId);
    if (!master) return;

    const availableStock = master.stock || (state.inventory[productId] || []).length || 0;
    if (availableStock <= 0) {
        showToast("ขออภัย สินค้านี้หมดชั่วคราว", "warning");
        return;
    }

    const existingIndex = state.cart.findIndex(item => item.productId === productId);
    if (existingIndex > -1) {
        if (state.cart[existingIndex].quantity < availableStock) {
            state.cart[existingIndex].quantity += 1;
            showToast(`เพิ่ม "${master.title}" ในตะกร้าแล้ว (+1)`, "success");
        } else {
            showToast(`มีสินค้าในสต็อกเพียง ${availableStock} ชิ้น`, "warning");
        }
    } else {
        state.cart.push({ productId: productId, quantity: 1 });
        showToast(`เพิ่ม "${master.title}" ในตะกร้าแล้ว`, "success");
    }

    saveCart();
    if (typeof sendTelemetryHeartbeat === 'function') {
        sendTelemetryHeartbeat('cart_add', { productId, productTitle: master.title });
    }
}

function updateCartQuantity(productId, delta) {
    const item = state.cart.find(i => i.productId === productId);
    if (!item) return;

    const master = getMasterProduct(productId);
    const availableStock = master ? (master.stock || (state.inventory[productId] || []).length || 0) : 0;
    item.quantity += delta;

    if (item.quantity <= 0) {
        removeFromCart(productId);
    } else {
        if (item.quantity > availableStock) {
            item.quantity = availableStock;
            showToast(`สินค้าในสต็อกมีเพียง ${availableStock} ชิ้น`, "warning");
        }
        saveCart();
    }
}

function removeFromCart(productId) {
    state.cart = state.cart.filter(i => i.productId !== productId);
    saveCart();
    showToast("ลบสินค้าออกจากตะกร้าแล้ว", "info");
}

function clearAllCart() {
    state.cart = [];
    saveCart();
    showToast("ล้างสินค้าในตะกร้าทั้งหมดแล้ว", "info");
}

function updateCartUI() {
    const countBadge = document.getElementById('cart-count-badge');
    const mobileCountBadge = document.getElementById('mobile-nav-cart-count');
    const drawerItems = document.getElementById('cart-items-container');
    const subtotalEl = document.getElementById('cart-subtotal');
    const totalEl = document.getElementById('cart-total');
    const checkoutBtn = document.getElementById('cart-checkout-btn');

    // Self-healing: Immediately prune invalid/null items and clamp quantities
    let cartModified = false;
    const validItems = [];
    (state.cart || []).forEach(item => {
        if (item && item.productId && getMasterProduct(item.productId)) {
            const rawQty = parseInt(item.quantity, 10);
            const clampedQty = Math.max(1, Math.min(50, isNaN(rawQty) ? 1 : rawQty));
            if (item.quantity !== clampedQty) {
                item.quantity = clampedQty;
                cartModified = true;
            }
            validItems.push(item);
        } else {
            cartModified = true;
        }
    });

    if (cartModified || validItems.length !== (state.cart ? state.cart.length : 0)) {
        state.cart = validItems;
        localStorage.setItem('supinkly_cart', JSON.stringify(state.cart));
    }

    const totalCount = state.cart.reduce((sum, item) => sum + (parseInt(item.quantity, 10) || 0), 0);
    const verifiedSubtotal = calculateVerifiedTotal();

    // 1. Check applied coupon validity and discount amount
    let couponDiscountAmount = 0;
    if (state.appliedCoupon && typeof validateCouponCode === 'function') {
        const recheck = validateCouponCode(state.appliedCoupon.code, verifiedSubtotal);
        if (recheck.valid) {
            state.appliedCoupon = recheck;
            couponDiscountAmount = recheck.discountAmount;
        } else {
            couponDiscountAmount = 0;
        }
    }
    const subtotalAfterCoupon = Math.max(0, verifiedSubtotal - couponDiscountAmount);

    // 2. VIP Member Auto Discount
    const currentUser = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
    let vipDiscountAmount = 0;
    const vipRow = document.getElementById('cart-vip-discount-row');
    const vipAmountEl = document.getElementById('cart-vip-amount');
    const vipTitleEl = document.getElementById('cart-vip-title');
    if (currentUser && currentUser.vip && currentUser.vip.discountPercent > 0) {
        vipDiscountAmount = Math.round((subtotalAfterCoupon * currentUser.vip.discountPercent / 100) * 100) / 100;
        if (vipRow && vipAmountEl) {
            vipRow.classList.remove('hidden');
            vipAmountEl.textContent = `-฿${vipDiscountAmount.toFixed(2)}`;
            if (vipTitleEl) vipTitleEl.textContent = `ส่วนลดสมาชิก ${currentUser.vip.tierName} (${currentUser.vip.discountPercent}%)`;
        }
    } else if (vipRow) {
        vipRow.classList.add('hidden');
    }
    const subtotalAfterVip = Math.max(0, subtotalAfterCoupon - vipDiscountAmount);

    // 3. Referral Friend Discount (5%)
    let refDiscountAmount = 0;
    const refRow = document.getElementById('cart-referral-discount-row');
    const refAmountEl = document.getElementById('cart-referral-amount');
    const refTitleEl = document.getElementById('cart-referral-title');
    if (state.referralDiscount) {
        refDiscountAmount = Math.round((subtotalAfterVip * 0.05) * 100) / 100;
        if (refRow && refAmountEl) {
            refRow.classList.remove('hidden');
            refAmountEl.textContent = `-฿${refDiscountAmount.toFixed(2)}`;
            if (refTitleEl) refTitleEl.textContent = `ส่วนลดแนะนำเพื่อน (${state.referralDiscount.code || '5%'})`;
        }
    } else if (refRow) {
        refRow.classList.add('hidden');
    }
    const subtotalBeforeCoins = Math.max(1, subtotalAfterVip - refDiscountAmount);

    // 4. Pink Coins Redemption (1 Coin = ฿1)
    const coinsWrap = document.getElementById('cart-coins-wrap');
    const coinsBalanceEl = document.getElementById('cart-coins-balance');
    const coinsBahtEl = document.getElementById('cart-coins-baht');
    const coinsDiscountRow = document.getElementById('cart-coins-discount-row');
    const coinsDiscountAmountEl = document.getElementById('cart-coins-discount-amount');
    const earnCoinsPreview = document.getElementById('cart-earn-coins-preview');
    const earnCoinsVal = document.getElementById('cart-coins-earned-val');

    let coinsDiscountAmount = 0;
    if (currentUser && typeof currentUser.coins === 'number' && currentUser.coins > 0) {
        if (coinsWrap) {
            coinsWrap.classList.remove('hidden');
            if (coinsBalanceEl) coinsBalanceEl.textContent = currentUser.coins;
            if (coinsBahtEl) coinsBahtEl.textContent = currentUser.coins.toFixed(2);
        }
        const maxCoinsAllowed = Math.min(currentUser.coins, Math.floor(subtotalBeforeCoins - 1));
        const coinsToRedeem = Math.min(state.coinsToRedeem || 0, Math.max(0, maxCoinsAllowed));
        state.coinsToRedeem = coinsToRedeem;
        coinsDiscountAmount = coinsToRedeem;

        if (coinsDiscountRow && coinsDiscountAmountEl) {
            if (coinsDiscountAmount > 0) {
                coinsDiscountRow.classList.remove('hidden');
                coinsDiscountAmountEl.textContent = `-฿${coinsDiscountAmount.toFixed(2)}`;
            } else {
                coinsDiscountRow.classList.add('hidden');
            }
        }
    } else {
        if (coinsWrap) coinsWrap.classList.add('hidden');
        if (coinsDiscountRow) coinsDiscountRow.classList.add('hidden');
        state.coinsToRedeem = 0;
    }

    const finalTotal = Math.max(1, subtotalBeforeCoins - coinsDiscountAmount);

    if (countBadge) {
        countBadge.textContent = totalCount;
        countBadge.classList.toggle('hidden', totalCount <= 0);
    }
    if (mobileCountBadge) {
        mobileCountBadge.textContent = totalCount;
        mobileCountBadge.classList.toggle('hidden', totalCount <= 0);
    }

    if (subtotalEl) subtotalEl.textContent = `฿${verifiedSubtotal.toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;
    if (totalEl) totalEl.textContent = `฿${finalTotal.toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

    // Earn Coins Preview
    if (earnCoinsPreview && earnCoinsVal) {
        const coinsEarned = Math.max(1, Math.floor(finalTotal / 10));
        earnCoinsVal.textContent = coinsEarned;
        earnCoinsPreview.classList.toggle('hidden', state.cart.length === 0);
    }

    // Discount Row
    const discountRow = document.getElementById('cart-discount-row');
    const discountAmountEl = document.getElementById('cart-discount-amount');
    if (discountRow && discountAmountEl) {
        if (couponDiscountAmount > 0) {
            discountRow.classList.remove('hidden');
            discountAmountEl.textContent = `-฿${couponDiscountAmount.toFixed(2)}`;
        } else {
            discountRow.classList.add('hidden');
        }
    }

    // Coupon UI Badges and Inputs
    const appliedWrap = document.getElementById('cart-coupon-applied-wrap');
    const appliedCodeEl = document.getElementById('cart-applied-coupon-code');
    const appliedDescEl = document.getElementById('cart-applied-coupon-desc');
    const couponInputWrap = document.getElementById('cart-coupon-input-wrap');
    const quickCouponsWrap = document.getElementById('cart-quick-coupons');

    if (appliedWrap && appliedCodeEl && appliedDescEl) {
        if (state.appliedCoupon && couponDiscountAmount > 0) {
            appliedWrap.classList.remove('hidden');
            appliedCodeEl.textContent = `${state.appliedCoupon.code} (-฿${couponDiscountAmount.toFixed(2)})`;
            appliedDescEl.textContent = state.appliedCoupon.title || 'ใช้ส่วนลดสำเร็จ';
            if (couponInputWrap) couponInputWrap.classList.add('hidden');
            if (quickCouponsWrap) quickCouponsWrap.classList.add('hidden');
        } else {
            appliedWrap.classList.add('hidden');
            if (couponInputWrap) couponInputWrap.classList.remove('hidden');
            if (quickCouponsWrap) quickCouponsWrap.classList.remove('hidden');
        }
    }

    const isMemberLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    if (checkoutBtn) {
        checkoutBtn.disabled = state.cart.length === 0 || finalTotal <= 0;
        if (state.cart.length === 0 || finalTotal <= 0) {
            checkoutBtn.classList.add('opacity-50', 'cursor-not-allowed');
            checkoutBtn.innerHTML = `<i class="fa-solid fa-lock"></i> <span>ไปขั้นตอนชำระเงิน (Checkout)</span>`;
        } else {
            checkoutBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            if (!isMemberLoggedIn) {
                checkoutBtn.innerHTML = `<i class="fa-solid fa-user-plus mr-1"></i> <span>สมัครสมาชิก / เข้าสู่ระบบเพื่อชำระเงิน</span>`;
            } else {
                checkoutBtn.innerHTML = `<i class="fa-solid fa-lock"></i> <span>ไปขั้นตอนชำระเงิน (Checkout)</span>`;
            }
        }
    }

    if (drawerItems) {
        if (state.cart.length === 0) {
            drawerItems.innerHTML = `
                <div class="py-16 text-center">
                    <div class="w-16 h-16 mx-auto mb-3 rounded-full bg-pink-100 border border-pink-200 flex items-center justify-center text-pink-600 text-2xl">
                        <i class="fa-solid fa-basket-shopping"></i>
                    </div>
                    <p class="text-base font-bold text-slate-800">ไม่มีสินค้าในตะกร้า</p>
                    <p class="text-xs text-slate-500 mt-1">เลือกซื้อบัญชี AI และคีย์ที่คุณต้องการได้เลย</p>
                </div>
            `;
        } else {
            drawerItems.innerHTML = state.cart.map(item => {
                const master = getMasterProduct(item.productId);
                if (!master) return '';

                return `
                    <div class="p-3.5 rounded-2xl bg-white border border-slate-200 flex items-center gap-3 shadow-sm">
                        <div class="w-11 h-11 rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center font-black text-xs text-pink-600 shrink-0">
                            ${escapeHTML(master.brandCode)}
                        </div>
                        <div class="flex-1 min-w-0">
                            <h4 class="text-xs font-semibold text-slate-900 truncate">${escapeHTML(master.title)}</h4>
                            <div class="flex items-baseline gap-1.5 mt-0.5">
                                <span class="text-xs sm:text-sm font-black text-pink-600 font-['Outfit']">฿${formatProductPrice(master.price)}</span>
                                ${item.quantity > 1 ? `<span class="text-[10px] text-slate-500 font-medium">(รวม ฿${(master.price * item.quantity).toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})})</span>` : ''}
                            </div>
                        </div>
                        <div class="flex items-center gap-1.5 shrink-0 bg-slate-100 px-2 py-1 rounded-xl border border-slate-200">
                            <button onclick="updateCartQuantity('${master.id}', -1)" class="w-5 h-5 flex items-center justify-center text-slate-600 hover:text-slate-900 text-xs font-bold">-</button>
                            <span class="text-xs font-black text-slate-900 w-4 text-center">${item.quantity}</span>
                            <button onclick="updateCartQuantity('${master.id}', 1)" class="w-5 h-5 flex items-center justify-center text-slate-600 hover:text-slate-900 text-xs font-bold">+</button>
                        </div>
                        <button onclick="removeFromCart('${master.id}')" class="text-slate-400 hover:text-rose-600 p-1 text-xs">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                `;
            }).join('');
        }
    }
}

function openCartDrawer() {
    const drawer = document.getElementById('cart-drawer');
    const overlay = document.getElementById('drawer-overlay');
    if (drawer && overlay) {
        drawer.classList.remove('translate-x-full');
        overlay.classList.remove('hidden');
    }
    // Anti-browser autofill / anti-memory protection for coupon input
    const couponInput = document.getElementById('cart-coupon-input');
    if (couponInput) {
        couponInput.setAttribute('readonly', 'readonly');
        couponInput.setAttribute('autocomplete', 'one-time-code');
        couponInput.name = 'spk_cp_' + Math.random().toString(36).slice(2, 9);
        if (!state.appliedCoupon) {
            couponInput.value = '';
        }
    }
    if (typeof sendTelemetryHeartbeat === 'function') {
        sendTelemetryHeartbeat('cart_view');
    }
}

function closeCartDrawer() {
    const drawer = document.getElementById('cart-drawer');
    const overlay = document.getElementById('drawer-overlay');
    if (drawer && overlay) {
        drawer.classList.add('translate-x-full');
        overlay.classList.add('hidden');
    }
}

// ==========================================
// CHECKOUT & PROMPTPAY QR GENERATION
// ==========================================
function startCheckout() {
    closeCartDrawer();
    state.cart = (state.cart || []).filter(item => item && item.productId && getMasterProduct(item.productId));
    state.cart.forEach(item => {
        item.quantity = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));
    });
    saveCart();

    if (!state.cart || state.cart.length === 0) {
        showToast("กรุณาเลือกสินค้าก่อนดำเนินการชำระเงิน", "warning");
        return;
    }

    // [MEMBER ENFORCEMENT] บังคับให้สมัครสมาชิกหรือเข้าสู่ระบบก่อนซื้อสินค้าทุกครั้ง
    const isLoggedIn = (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn());
    if (!isLoggedIn) {
        state.pendingCheckoutAfterAuth = true;
        showToast("กรุณาสมัครสมาชิกหรือเข้าสู่ระบบก่อนซื้อสินค้า เพื่อบันทึกคีย์และประวัติเข้าบัญชีของคุณ", "warning");
        openAuthModal('register');
        return;
    }

    const modal = document.getElementById('checkout-modal');
    if (!modal) return;

    for (const item of state.cart) {
        const master = getMasterProduct(item.productId);
        const availableStock = master ? (master.stock || (state.inventory[item.productId] || []).length || 0) : 0;
        if (availableStock < item.quantity) {
            showToast(`สินค้า "${master ? master.title : ''}" ในสต็อกไม่เพียงพอ`, "warning");
            return;
        }
    }

    const verifiedSubtotal = calculateVerifiedTotal();
    let couponDiscountAmount = 0;
    if (state.appliedCoupon && typeof validateCouponCode === 'function') {
        const recheck = validateCouponCode(state.appliedCoupon.code, verifiedSubtotal);
        if (recheck.valid) {
            couponDiscountAmount = recheck.discountAmount;
        }
    }
    const subtotalAfterCoupon = Math.max(0, verifiedSubtotal - couponDiscountAmount);

    const currentUser = (typeof USER_AUTH !== 'undefined' && USER_AUTH.getUser) ? USER_AUTH.getUser() : null;
    let vipDiscountAmount = 0;
    if (currentUser && currentUser.vip && currentUser.vip.discountPercent > 0) {
        vipDiscountAmount = Math.round((subtotalAfterCoupon * currentUser.vip.discountPercent / 100) * 100) / 100;
    }
    const subtotalAfterVip = Math.max(0, subtotalAfterCoupon - vipDiscountAmount);

    let refDiscountAmount = 0;
    if (state.referralDiscount) {
        refDiscountAmount = Math.round((subtotalAfterVip * 0.05) * 100) / 100;
    }
    const subtotalBeforeCoins = Math.max(1, subtotalAfterVip - refDiscountAmount);

    let coinsDiscountAmount = 0;
    if (currentUser && typeof currentUser.coins === 'number' && currentUser.coins > 0 && state.coinsToRedeem > 0) {
        const maxCoinsAllowed = Math.min(currentUser.coins, Math.floor(subtotalBeforeCoins - 1));
        coinsDiscountAmount = Math.min(state.coinsToRedeem, Math.max(0, maxCoinsAllowed));
    }

    const verifiedTotal = Math.max(1, Math.round((subtotalBeforeCoins - coinsDiscountAmount) * 100) / 100);
    if (verifiedTotal <= 0) {
        showToast("ยอดชำระเงินต้องมากกว่า 0 บาท", "warning");
        return;
    }
    const refCode = "SPK" + Math.floor(100000 + Math.random() * 900000);

    const checkoutEmailInput = document.getElementById('checkout-email-input');
    if (checkoutEmailInput && currentUser && currentUser.email) {
        checkoutEmailInput.value = currentUser.email;
        checkoutEmailInput.readOnly = true;
        checkoutEmailInput.classList.add('bg-slate-100', 'text-slate-600', 'cursor-not-allowed');
    }

    document.getElementById('checkout-ref-code').textContent = refCode;
    document.getElementById('checkout-total-amount').textContent = `฿${verifiedTotal.toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;
    const accEl = document.getElementById('checkout-account-name');
    if (accEl) accEl.textContent = STORE_CONFIG.promptPayAccountName || 'สุพัฒน์ มีสมบัติ';

    SlipVerifier.clearSlip();

    const emvPayload = generatePromptPayPayload(STORE_CONFIG.promptPayNumber, verifiedTotal);
    const qrImg = document.getElementById('promptpay-qr-img');
    if (qrImg) {
        qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=260x260&margin=8&data=${encodeURIComponent(emvPayload)}`;
    }

    const summaryContainer = document.getElementById('checkout-items-summary');
    if (summaryContainer) {
        let itemsHtml = state.cart.map(i => {
            const master = getMasterProduct(i.productId);
            if (!master) return '';
            return `
                <div class="flex items-center justify-between text-xs py-1 text-slate-700 font-normal">
                    <span class="truncate flex-1 pr-2 font-normal">${escapeHTML(master.title)} (x${i.quantity})</span>
                    <span class="font-black text-slate-900 font-['Outfit']">฿${(master.price * i.quantity).toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})}</span>
                </div>
            `;
        }).join('');
        if (couponDiscountAmount > 0 && state.appliedCoupon) {
            itemsHtml += `
                <div class="flex items-center justify-between text-xs py-1 text-emerald-600 font-semibold border-t border-slate-100">
                    <span class="truncate flex-1 pr-2"><i class="fa-solid fa-tags mr-1"></i>ส่วนลดโค้ด (${escapeHTML(state.appliedCoupon.code)})</span>
                    <span>-฿${couponDiscountAmount.toFixed(2)}</span>
                </div>
            `;
        }
        if (vipDiscountAmount > 0 && currentUser?.vip) {
            itemsHtml += `
                <div class="flex items-center justify-between text-xs py-1 text-amber-700 font-semibold border-t border-slate-100">
                    <span class="truncate flex-1 pr-2"><i class="fa-solid fa-crown mr-1 text-amber-500"></i>ส่วนลด VIP (${escapeHTML(currentUser.vip.tierName)} ${currentUser.vip.discountPercent}%)</span>
                    <span>-฿${vipDiscountAmount.toFixed(2)}</span>
                </div>
            `;
        }
        if (refDiscountAmount > 0) {
            itemsHtml += `
                <div class="flex items-center justify-between text-xs py-1 text-purple-700 font-semibold border-t border-slate-100">
                    <span class="truncate flex-1 pr-2"><i class="fa-solid fa-user-group mr-1 text-purple-500"></i>ส่วนลดแนะนำเพื่อน (5%)</span>
                    <span>-฿${refDiscountAmount.toFixed(2)}</span>
                </div>
            `;
        }
        if (coinsDiscountAmount > 0) {
            itemsHtml += `
                <div class="flex items-center justify-between text-xs py-1 text-pink-700 font-semibold border-t border-slate-100">
                    <span class="truncate flex-1 pr-2"><i class="fa-solid fa-coins mr-1 text-amber-500"></i>ใช้ Pink Coins (${coinsDiscountAmount} เหรียญ)</span>
                    <span>-฿${coinsDiscountAmount.toFixed(2)}</span>
                </div>
            `;
        }
        summaryContainer.innerHTML = itemsHtml;
    }

    startQrCountdown();
    modal.classList.remove('hidden');
    if (typeof sendTelemetryHeartbeat === 'function') {
        sendTelemetryHeartbeat('checkout_start');
    }
}

function closeCheckoutModal() {
    const modal = document.getElementById('checkout-modal');
    if (modal) modal.classList.add('hidden');
    if (state.qrTimer) clearInterval(state.qrTimer);
}

function startQrCountdown() {
    if (state.qrTimer) clearInterval(state.qrTimer);
    state.qrSecondsLeft = 900;
    const timerEl = document.getElementById('qr-timer-text');

    state.qrTimer = setInterval(() => {
        state.qrSecondsLeft--;
        if (state.qrSecondsLeft <= 0) {
            clearInterval(state.qrTimer);
            if (timerEl) timerEl.textContent = "หมดเวลาการชำระเงิน กรุณาสร้าง QR ใหม่อีกครั้ง";
            return;
        }
        const m = Math.floor(state.qrSecondsLeft / 60).toString().padStart(2, '0');
        const s = (state.qrSecondsLeft % 60).toString().padStart(2, '0');
        if (timerEl) timerEl.textContent = `กรุณาชำระเงินภายใน ${m}:${s} นาที`;
    }, 1000);
}

// ==========================================
// SECURE SLIP VERIFICATION & DISPENSE
// ==========================================
async function submitSlipVerification() {
    // [MEMBER ENFORCEMENT] ตรวจสอบสถานะการเข้าสู่ระบบก่อนตรวจสลิป
    const isLoggedIn = (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn());
    if (!isLoggedIn) {
        showToast("กรุณาสมัครสมาชิกหรือเข้าสู่ระบบก่อนดำเนินการชำระเงิน", "warning");
        closeCheckoutModal();
        openAuthModal('login');
        return;
    }

    // Sanitize and validate cart
    state.cart = (state.cart || []).filter(item => item && item.productId && getMasterProduct(item.productId));
    state.cart.forEach(item => {
        item.quantity = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));
    });

    if (!state.cart || state.cart.length === 0) {
        showToast("ตะกร้าสินค้าว่างเปล่า กรุณาเลือกสินค้าก่อนชำระเงิน", "warning");
        return;
    }

    const verifiedSubtotal = calculateVerifiedTotal();
    let couponDiscountAmount = 0;
    if (state.appliedCoupon && typeof validateCouponCode === 'function') {
        const recheck = validateCouponCode(state.appliedCoupon.code, verifiedSubtotal);
        if (recheck.valid) {
            couponDiscountAmount = recheck.discountAmount;
        }
    }
    const subtotalAfterCoupon = Math.max(0, verifiedSubtotal - couponDiscountAmount);

    const currentUser = (typeof USER_AUTH !== 'undefined' && USER_AUTH.getUser) ? USER_AUTH.getUser() : null;
    let vipDiscountAmount = 0;
    if (currentUser && currentUser.vip && currentUser.vip.discountPercent > 0) {
        vipDiscountAmount = Math.round((subtotalAfterCoupon * currentUser.vip.discountPercent / 100) * 100) / 100;
    }
    const subtotalAfterVip = Math.max(0, subtotalAfterCoupon - vipDiscountAmount);

    let refDiscountAmount = 0;
    if (state.referralDiscount) {
        refDiscountAmount = Math.round((subtotalAfterVip * 0.05) * 100) / 100;
    }
    const subtotalBeforeCoins = Math.max(1, subtotalAfterVip - refDiscountAmount);

    let coinsDiscountAmount = 0;
    if (currentUser && typeof currentUser.coins === 'number' && currentUser.coins > 0 && state.coinsToRedeem > 0) {
        const maxCoinsAllowed = Math.min(currentUser.coins, Math.floor(subtotalBeforeCoins - 1));
        coinsDiscountAmount = Math.min(state.coinsToRedeem, Math.max(0, maxCoinsAllowed));
    }

    const verifiedTotal = Math.max(1, Math.round((subtotalBeforeCoins - coinsDiscountAmount) * 100) / 100);
    if (!verifiedTotal || verifiedTotal <= 0) {
        showToast("ยอดชำระเงินไม่ถูกต้อง กรุณาเลือกสินค้าใหม่", "warning");
        return;
    }

    const emailInput = document.getElementById('checkout-email-input');
    const recipientEmail = (currentUser && currentUser.email) ? currentUser.email.trim() : (emailInput ? emailInput.value : '').trim();

    // Stricter email format validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!recipientEmail || !emailRegex.test(recipientEmail)) {
        showToast("ไม่พบข้อมูลอีเมลสมาชิกที่ถูกต้อง กรุณาเข้าสู่ระบบใหม่อีกครั้ง", "warning");
        if (emailInput) emailInput.focus();
        return;
    }

    if (!SlipVerifier.selectedFile) {
        showToast("กรุณาแนบรูปภาพสลิปการโอนเงิน", "warning");
        return;
    }

    if (!SlipVerifier.imageDimensions) {
        showToast("กำลังประมวลผลรูปภาพสลิป กรุณารอสักครู่...", "info");
        return;
    }

    const btn = document.getElementById('verify-slip-btn');
    const originalText = btn.innerHTML;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-sm"></i> กำลังตรวจสอบสลิปกับระบบธนาคาร...`;
    btn.disabled = true;

    try {
        const promoCode = state.appliedCoupon ? state.appliedCoupon.code : '';
        const result = await SlipVerifier.verifySlip(
            verifiedTotal,
            STORE_CONFIG.promptPayNumber,
            state.cart,
            recipientEmail,
            promoCode,
            state.coinsToRedeem || 0,
            state.referralCode || ''
        );

        btn.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400"></i> สลิปถูกต้อง! กำลังจัดส่งรหัส...`;

        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
            closeCheckoutModal();

            // If server returned an order, integrate directly
            if (result && result.order) {
                const serverOrder = result.order;
                if (!state.orders.some(o => o.orderId === serverOrder.orderId)) {
                    state.orders.unshift(serverOrder);
                    saveOrders();
                }
                if (typeof adminOrdersList !== 'undefined' && Array.isArray(adminOrdersList)) {
                    if (!adminOrdersList.some(o => o.orderId === serverOrder.orderId)) {
                        adminOrdersList.unshift(serverOrder);
                    }
                }
                state.cart = [];
                state.appliedCoupon = null;
                state.coinsToRedeem = 0;
                state.referralCode = null;
                state.referralDiscount = null;
                saveCart();
                updateCartUI();
                updateMemberBadges();

                openVaultModal(serverOrder);
                const hasPending = (serverOrder.items || []).some(i => i.status === 'pending_fulfillment' || !i.credentials);
                if (hasPending) {
                    showToast("สลิปถูกต้องและยอดเงินตรง! ร้านค้ากำลังจัดเตรียมบัญชีให้คุณ (5-15 นาที)", "success");
                } else {
                    showToast("สลิปถูกต้องและยอดเงินตรง! ส่งมอบรหัสเข้าคลังเรียบร้อยแล้ว", "success");
                }
                return;
            }

            const deliveredItems = [];
            let hasPendingFulfillment = false;

            for (const item of state.cart) {
                const master = getMasterProduct(item.productId);
                const pool = state.inventory[item.productId] || [];
                const itemQty = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));

                for (let i = 0; i < itemQty; i++) {
                    if (pool.length > 0) {
                        const credential = pool.shift();
                        deliveredItems.push({
                            productId: item.productId,
                            productTitle: master ? master.title : "Digital Item",
                            brand: master ? master.brand : "",
                            type: master ? master.type : "",
                            price: master ? master.price : 0,
                            warranty: master ? master.warranty : "30 วัน",
                            status: "delivered",
                            credentials: credential
                        });
                    } else {
                        // Model 1: On-Demand Fulfillment (Zero-Stock)
                        // Do not generate fake credentials. Set to pending for admin fulfillment.
                        hasPendingFulfillment = true;
                        deliveredItems.push({
                            productId: item.productId,
                            productTitle: master ? master.title : "Digital Item",
                            brand: master ? master.brand : "",
                            type: master ? master.type : "",
                            price: master ? master.price : 0,
                            warranty: master ? master.warranty : "30 วัน",
                            status: "pending_fulfillment",
                            credentials: null
                        });
                    }
                }
            }

            if (deliveredItems.length === 0) {
                showToast("ไม่สามารถประมวลผลคำสั่งซื้อได้ กรุณาลองใหม่อีกครั้ง", "error");
                return;
            }

            // Decrement synced market stock for purchased items
            const customPrices = getCustomPrices();
            for (const item of state.cart) {
                const itemQty = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));
                if (customPrices[item.productId] && typeof customPrices[item.productId].g2gStockAvailable === 'number') {
                    customPrices[item.productId].g2gStockAvailable = Math.max(0, customPrices[item.productId].g2gStockAvailable - itemQty);
                }
            }
            localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));

            saveSecureInventory(state.inventory);
            syncStockCount();
            renderProducts();

            const orderId = "SPK-" + Date.now().toString().slice(-6) + Math.random().toString(36).substring(2, 6).toUpperCase();
            const newOrder = {
                orderId: orderId,
                date: new Date().toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }),
                totalAmount: verifiedTotal,
                paymentMethod: "Thai QR PromptPay",
                recipientEmail: recipientEmail,
                transRef: result.transRef,
                slipFingerprint: SlipVerifier.fileFingerprint,
                items: deliveredItems,
                status: hasPendingFulfillment
                    ? "🟡 รอจัดส่งสินค้า (5-15 นาที)"
                    : "🟢 จัดส่งสำเร็จทันที (Instant Vault)"
            };

            state.orders.unshift(newOrder);
            saveOrders();
            if (typeof adminOrdersList !== 'undefined' && Array.isArray(adminOrdersList)) {
                if (!adminOrdersList.some(o => o.orderId === newOrder.orderId)) {
                    adminOrdersList.unshift(newOrder);
                }
            }
            if (typeof syncLocalOrdersToServer === 'function') {
                syncLocalOrdersToServer([newOrder]);
            }

            state.cart = [];
            state.appliedCoupon = null;
            saveCart();
            updateCartUI();

            openVaultModal(newOrder);
            if (hasPendingFulfillment) {
                showToast("สลิปถูกต้องและยอดเงินตรง! ร้านค้ากำลังจัดเตรียมบัญชีให้คุณ (5-15 นาที)", "success");
            } else {
                showToast("สลิปถูกต้องและยอดเงินตรง! ส่งมอบรหัสเข้าคลังเรียบร้อยแล้ว", "success");
            }
        }, 1200);

    } catch (err) {
        btn.innerHTML = originalText;
        btn.disabled = false;
        showToast(err.message || "การตรวจสอบสลิปล้มเหลว", "warning");
    }
}

// ==========================================
// VAULT MODAL (BRIGHT & CLEAR HIGH-CONTRAST)
// ==========================================
function openVaultModal(order) {
    const modal = document.getElementById('vault-modal');
    if (!modal) return;

    state.currentVaultOrderId = order.orderId || null;

    const idEl = document.getElementById('vault-order-id');
    if (idEl) idEl.textContent = order.orderId || '';
    const dateEl = document.getElementById('vault-order-date');
    if (dateEl) dateEl.textContent = order.date || '';
    const emailEl = document.getElementById('vault-order-email');
    if (emailEl) emailEl.textContent = order.recipientEmail || '';
    const totalEl = document.getElementById('vault-order-total');
    if (totalEl) totalEl.textContent = `฿${(order.totalAmount || 0).toFixed(2)}`;

    // Check if order has items pending fulfillment
    const isPending = (typeof isOrderPending === 'function')
        ? isOrderPending(order)
        : (order.items || []).some(item => !item.credentials || item.status === 'pending_fulfillment');
    modal.setAttribute('data-is-pending', isPending ? 'true' : 'false');

    const statusIconEl = document.getElementById('vault-status-icon');
    const statusTitleEl = document.getElementById('vault-status-title');
    const sectionTitleEl = document.getElementById('vault-items-section-title');

    if (isPending) {
        if (statusIconEl) {
            statusIconEl.className = "w-14 h-14 mx-auto mb-2.5 rounded-full bg-amber-100 text-amber-600 flex items-center justify-center text-2xl border border-amber-300 shadow-sm animate-pulse";
            statusIconEl.innerHTML = `<i class="fa-solid fa-hourglass-half"></i>`;
        }
        if (statusTitleEl) {
            statusTitleEl.textContent = "ชำระเงินสำเร็จแล้ว! ระบบกำลังจัดเตรียมบัญชี";
        }
        if (sectionTitleEl) {
            sectionTitleEl.innerHTML = `<i class="fa-solid fa-box text-pink-500"></i> <span>รายการสินค้าที่สั่งซื้อ (รอจัดส่ง 5–15 นาที):</span>`;
        }
    } else {
        if (statusIconEl) {
            statusIconEl.className = "w-14 h-14 mx-auto mb-2.5 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center text-2xl border border-emerald-300 shadow-sm";
            statusIconEl.innerHTML = `<i class="fa-solid fa-shield-cat"></i>`;
        }
        if (statusTitleEl) {
            statusTitleEl.textContent = "ตรวจสอบสลิปผ่าน & ส่งมอบรหัสเข้าคลังเรียบร้อย!";
        }
        if (sectionTitleEl) {
            sectionTitleEl.innerHTML = `<i class="fa-solid fa-key text-pink-500"></i> <span>ข้อมูลบัญชี / คีย์ของคุณ (กดคัดลอกเพื่อใช้งาน):</span>`;
        }
    }

    const listContainer = document.getElementById('vault-items-list');
    if (listContainer) {
        listContainer.innerHTML = order.items.map((item, idx) => {
            const isItemPending = !item.credentials || item.status === 'pending_fulfillment';
            const cred = item.credentials || {};

            if (isItemPending) {
                return `
                    <div class="p-4 rounded-2xl bg-amber-50/70 border-2 border-amber-300 mb-3 shadow-sm">
                        <div class="flex items-center justify-between gap-2">
                            <h4 class="text-sm font-normal text-slate-900 flex items-center gap-2">
                                <span class="w-6 h-6 rounded-full bg-amber-500 text-white flex items-center justify-center text-xs font-black">${idx + 1}</span>
                                ${escapeHTML(item.productTitle)}
                            </h4>
                            <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-100 text-amber-900 font-bold border border-amber-300 animate-pulse">
                                ⏳ รอจัดส่ง (5–15 นาที)
                            </span>
                        </div>

                        <!-- On-Demand Delivery Process Timeline -->
                        <div class="mt-3.5 p-3.5 rounded-xl bg-white border border-amber-200 space-y-2.5">
                            <div class="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                                <i class="fa-solid fa-circle-notch fa-spin text-amber-500"></i>
                                <span>สถานะการจัดส่ง: เจ้าหน้าที่กำลังจัดเตรียมและตรวจสอบบัญชีแท้ (5-15 นาที)</span>
                            </div>

                            <div class="grid grid-cols-3 gap-2 text-center text-[10px]">
                                <div class="p-1.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 font-bold">
                                    <i class="fa-solid fa-check text-xs block mb-0.5"></i> 1. ได้รับเงินแล้ว
                                </div>
                                <div class="p-1.5 rounded-lg bg-amber-100 border border-amber-300 text-amber-900 font-bold animate-pulse">
                                    <i class="fa-solid fa-spinner fa-spin text-xs block mb-0.5"></i> 2. จัดเตรียมบัญชีแท้
                                </div>
                                <div class="p-1.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-400 font-bold">
                                    <i class="fa-solid fa-key text-xs block mb-0.5"></i> 3. ส่งมอบรหัส
                                </div>
                            </div>

                            <p class="text-[11px] text-slate-600 leading-relaxed font-medium">
                                💡 ตรวจสอบสลิปโอนเงินสำเร็จ 100% ทางร้านกำลังจัดเตรียมบัญชีแท้ให้คุณ เปิดหน้านี้ทิ้งไว้ (ระบบจะแสดงรหัสทันทีเมื่อพร้อม) หรือตรวจดูได้ตลอดเวลาที่เมนู <b>"คีย์ของฉัน"</b>
                            </p>
                        </div>

                        <div class="mt-2.5 flex items-center justify-between text-xs px-1">
                            <span class="text-slate-500 font-medium">🛡️ รับประกันสินค้า: ${escapeHTML(item.warranty || '30 วัน')}</span>
                            <a href="https://www.facebook.com/profile.php?id=61594837747580" target="_blank" rel="noopener noreferrer" 
                               class="text-[#1877F2] hover:text-[#166fe5] font-bold flex items-center gap-1.5 transition-colors">
                                <i class="fa-brands fa-facebook text-sm"></i>
                                <span>ติดต่อเพจ Facebook</span>
                            </a>
                        </div>
                    </div>
                `;
            }

            let credContent = "";
            if (cred.email) {
                credContent = `
                    <div class="space-y-2 mt-2.5">
                        <div class="flex items-center justify-between bg-slate-50 p-3 rounded-xl border border-slate-200">
                            <div>
                                <span class="text-xs text-slate-500 font-bold block">อีเมลบัญชี (Email):</span>
                                <span class="text-sm font-mono font-black text-pink-600 select-all">${escapeHTML(cred.email)}</span>
                            </div>
                            <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.email)}" data-msg="คัดลอกอีเมลแล้ว" class="px-3 py-1.5 rounded-xl bg-pink-100 text-pink-700 hover:bg-pink-200 text-xs font-bold transition-all">
                                <i class="fa-regular fa-copy"></i> คัดลอก
                            </button>
                        </div>
                        <div class="flex items-center justify-between bg-slate-50 p-3 rounded-xl border border-slate-200">
                            <div>
                                <span class="text-xs text-slate-500 font-bold block">รหัสผ่าน (Password):</span>
                                <span class="text-sm font-mono font-black text-cyan-700 select-all">${escapeHTML(cred.password)}</span>
                            </div>
                            <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.password)}" data-msg="คัดลอกรหัสผ่านแล้ว" class="px-3 py-1.5 rounded-xl bg-cyan-100 text-cyan-800 hover:bg-cyan-200 text-xs font-bold transition-all">
                                <i class="fa-regular fa-copy"></i> คัดลอก
                            </button>
                        </div>
                    </div>
                `;
            } else if (cred.link) {
                credContent = `
                    <div class="mt-2.5 bg-slate-50 p-3 rounded-xl border border-slate-200 flex items-center justify-between">
                        <div class="min-w-0 flex-1 pr-2">
                            <span class="text-xs text-slate-500 font-bold block">ลิงก์เปิดใช้งาน (Activation Link):</span>
                            <span class="text-xs font-mono font-bold text-cyan-700 truncate block select-all">${escapeHTML(cred.link)}</span>
                        </div>
                        <div class="flex items-center gap-1.5 shrink-0">
                            <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.link)}" data-msg="คัดลอกลิงก์แล้ว" class="px-3 py-1.5 rounded-xl bg-cyan-100 text-cyan-800 hover:bg-cyan-200 text-xs font-bold">
                                <i class="fa-regular fa-copy"></i> คัดลอก
                            </button>
                            <a href="${sanitizeUrl(cred.link)}" target="_blank" rel="noopener noreferrer" class="px-3 py-1.5 rounded-xl gradient-btn text-white text-xs font-bold flex items-center gap-1">
                                <i class="fa-solid fa-arrow-up-right-from-square"></i> เปิด
                            </a>
                        </div>
                    </div>
                `;
            } else {
                credContent = `
                    <div class="mt-2.5 bg-slate-50 p-3 rounded-xl border border-slate-200 flex items-center justify-between">
                        <div>
                            <span class="text-xs text-slate-500 font-bold block">รหัสผลิตภัณฑ์ (License Key):</span>
                            <span class="text-sm font-mono font-black text-emerald-700 select-all">${escapeHTML(cred.key || '')}</span>
                        </div>
                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.key || '')}" data-msg="คัดลอกคีย์แล้ว" class="px-3 py-1.5 rounded-xl bg-emerald-100 text-emerald-800 hover:bg-emerald-200 text-xs font-bold">
                            <i class="fa-regular fa-copy"></i> คัดลอก
                        </button>
                    </div>
                `;
            }

            return `
                <div class="p-4 rounded-2xl bg-pink-50/40 border border-pink-200 mb-3 shadow-sm">
                    <div class="flex items-center justify-between gap-2">
                        <h4 class="text-sm font-normal text-slate-900 flex items-center gap-2">
                            <span class="w-6 h-6 rounded-full bg-pink-500 text-white flex items-center justify-center text-xs font-black">${idx + 1}</span>
                            ${escapeHTML(item.productTitle)}
                        </h4>
                        <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800 font-bold border border-emerald-300">
                            🛡️ ประกัน ${escapeHTML(item.warranty)}
                        </span>
                    </div>

                    ${credContent}

                    <div class="mt-3 p-3 rounded-xl bg-white border border-slate-200 text-xs text-slate-700 font-medium">
                        <span class="font-bold text-pink-600 block mb-1"><i class="fa-solid fa-circle-info"></i> วิธีเข้าใช้งาน:</span>
                        <div class="whitespace-pre-line text-slate-600">${escapeHTML(cred.instructions || 'เข้าสู่ระบบและเริ่มใช้งานได้ทันที')}</div>
                    </div>

                    <div class="mt-2.5 flex items-center justify-between text-xs px-1 text-slate-500">
                        <span>🛡️ มีปัญหาการใช้งาน ติดต่อสอบถามได้ 24 ชม.</span>
                        <a href="https://www.facebook.com/profile.php?id=61594837747580" target="_blank" rel="noopener noreferrer" 
                           class="text-[#1877F2] hover:text-[#166fe5] font-bold flex items-center gap-1 transition-colors">
                            <i class="fa-brands fa-facebook"></i> ติดต่อเพจ Facebook
                        </a>
                    </div>
                </div>
            `;
        }).join('');
    }

    modal.classList.remove('hidden');
}

function closeVaultModal() {
    state.currentVaultOrderId = null;
    const modal = document.getElementById('vault-modal');
    if (modal) modal.classList.add('hidden');
}

// Real-time server poller for Vault modal & Orders modal (auto-syncs when admin fulfills on server)
let isVaultPollingRunning = false;

async function checkCustomerVaultServerStatus() {
    if (isVaultPollingRunning) return;
    const vaultModal = document.getElementById('vault-modal');
    const ordersModal = document.getElementById('orders-modal');
    const isVaultOpen = vaultModal && !vaultModal.classList.contains('hidden');
    const isOrdersOpen = ordersModal && !ordersModal.classList.contains('hidden');

    if (!isVaultOpen && !isOrdersOpen) return;

    isVaultPollingRunning = true;
    try {
        // 1. Live Poll Vault Modal for current order
        if (isVaultOpen && state.currentVaultOrderId) {
            const localOrder = (state.orders || []).find(o => o.orderId === state.currentVaultOrderId);
            const customerEmail = (localOrder && (localOrder.recipientEmail || localOrder.email))
                || (state.user && state.user.email)
                || '';
            const queryParam = customerEmail ? `?email=${encodeURIComponent(customerEmail)}` : '';

            const res = await fetch(`/api/orders/${encodeURIComponent(state.currentVaultOrderId)}${queryParam}`, {
                headers: {
                    ...(customerEmail ? { 'x-order-email': customerEmail } : {})
                }
            });

            if (res.ok) {
                const data = await res.json();
                if (data && data.success && data.order) {
                    const serverOrder = data.order;
                    const wasPending = vaultModal.getAttribute('data-is-pending') === 'true';

                    const isNowDelivered = (serverOrder.status && (serverOrder.status.includes('จัดส่งสำเร็จ') || serverOrder.status.includes('delivered')))
                        || ((serverOrder.items || []).length > 0 && (serverOrder.items || []).every(it => (it.status === 'delivered' || it.credentials) && it.status !== 'pending_fulfillment'));

                    const serverHasCreds = (serverOrder.items || []).some(it => it.credentials && (it.credentials.email || it.credentials.key || it.credentials.link));

                    if (wasPending && (isNowDelivered || serverHasCreds)) {
                        // Merge into local state
                        const idx = (state.orders || []).findIndex(o => o.orderId === serverOrder.orderId);
                        if (idx !== -1) state.orders[idx] = serverOrder;
                        else state.orders.unshift(serverOrder);
                        saveOrders();

                        // Visual & audible alert to customer
                        playNotificationSound();
                        showToast("🎉 ร้านค้าส่งมอบรหัสให้คุณเรียบร้อยแล้ว!", "success");
                        openVaultModal(serverOrder);

                        if (isOrdersOpen) renderOrdersHistory();
                        updateNavOrdersCount();
                        updateUserHeaderUI();
                    }
                }
            }
        }

        // 2. Live update Orders Modal ("คีย์ของฉัน") if open
        if (isOrdersOpen) {
            renderOrdersHistory();
        }
    } catch (e) {
        // Silent catch for network drops
    } finally {
        isVaultPollingRunning = false;
    }
}

if (!window.vaultPollTimer) {
    window.vaultPollTimer = setInterval(checkCustomerVaultServerStatus, 2500);
}

function copyToClipboard(text, successMsg = "คัดลอกสำเร็จ") {
    if (text === undefined || text === null) text = "";
    navigator.clipboard.writeText(String(text)).then(() => {
        showToast(successMsg, "success");
    }).catch(() => {
        const textarea = document.createElement('textarea');
        textarea.value = String(text);
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast(successMsg, "success");
    });
}

// Safely copy text from data-copy attribute to prevent quotation injection / syntax breakage
function copyFromData(btn, defaultMsg = "คัดลอกสำเร็จ") {
    if (!btn) return;
    const text = btn.getAttribute('data-copy') || '';
    const msg = btn.getAttribute('data-msg') || defaultMsg;
    copyToClipboard(text, msg);
}

function copyCombinedFromData(btn) {
    if (!btn) return;
    const email = btn.getAttribute('data-email') || '';
    const pass = btn.getAttribute('data-password') || '';
    const text = `อีเมล (Email): ${email}\nรหัสผ่าน (Password): ${pass}`;
    copyToClipboard(text, "คัดลอกอีเมลและรหัสผ่านเรียบร้อยแล้ว");
}

// ==========================================
// ORDERS MODAL & MY KEYS ("คีย์ของฉัน")
// ==========================================
let customerKeysFilter = 'all';
let customerKeysSearchQuery = '';

function setCustomerKeysFilter(filterType) {
    customerKeysFilter = filterType;

    const filterButtons = {
        'all': document.getElementById('ck-filter-all'),
        'delivered': document.getElementById('ck-filter-delivered'),
        'pending': document.getElementById('ck-filter-pending')
    };

    Object.keys(filterButtons).forEach(key => {
        const btn = filterButtons[key];
        if (!btn) return;
        if (key === filterType) {
            btn.className = 'customer-key-filter-btn px-3 py-1.5 rounded-xl font-bold transition-all bg-pink-500 text-white shadow-xs';
        } else {
            btn.className = 'customer-key-filter-btn px-3 py-1.5 rounded-xl font-bold transition-all bg-slate-100 hover:bg-slate-200 text-slate-600';
        }
    });

    renderOrdersHistory();
}

function handleCustomerKeysSearch(val) {
    customerKeysSearchQuery = (val || '').toLowerCase().trim();
    const clearBtn = document.getElementById('customer-keys-clear-search');
    if (clearBtn) {
        clearBtn.classList.toggle('hidden', !customerKeysSearchQuery);
    }
    renderOrdersHistory();
}

function clearCustomerKeysSearch() {
    const input = document.getElementById('customer-keys-search');
    if (input) input.value = '';
    handleCustomerKeysSearch('');
}

function copyCombinedCredentials(email, password) {
    const text = `อีเมล (Email): ${email}\nรหัสผ่าน (Password): ${password}`;
    copyToClipboard(text, "คัดลอกอีเมลและรหัสผ่านเรียบร้อยแล้ว");
}

function copyOrderCustomerSummary(orderId) {
    const order = state.orders.find(o => o.orderId === orderId);
    if (!order) return;

    const itemsText = (order.items || []).map(it => `- ${it.productTitle} (฿${(it.price || 0).toFixed(2)})`).join('\n');
    const summary = `🧾 รายละเอียดคำสั่งซื้อ Supinkly.AI\nเลขที่คำสั่งซื้อ: ${order.orderId}\nวันที่สั่งซื้อ: ${order.date || '-'}\nสินค้าในออเดอร์:\n${itemsText}\nยอดรวมทั้งสิ้น: ฿${(order.totalAmount || 0).toFixed(2)}\n🛡️ รับประกันสินค้า 30 วัน Supinkly.AI\nติดต่อช่วยเหลือ: https://www.facebook.com/profile.php?id=61594837747580`;

    copyToClipboard(summary, "คัดลอกสรุปคำสั่งซื้อเรียบร้อยแล้ว");
}

function renderOrdersHistory() {
    const list = document.getElementById('orders-history-list');
    if (!list) return;

    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const hasOrders = Array.isArray(state.orders) && state.orders.length > 0;

    if (!isLoggedIn && !hasOrders) {
        // Enforce zero state only when unauthenticated AND no local orders
        const cntAll = document.getElementById('ck-cnt-all');
        if (cntAll) cntAll.textContent = '0';
        const cntDelivered = document.getElementById('ck-cnt-delivered');
        if (cntDelivered) cntDelivered.textContent = '0';
        const cntPending = document.getElementById('ck-cnt-pending');
        if (cntPending) cntPending.textContent = '0';
        const badgeTotal = document.getElementById('customer-keys-count-badge');
        if (badgeTotal) badgeTotal.textContent = `0 รายการ`;

        const profileCard = document.getElementById('customer-profile-card');
        if (profileCard) profileCard.innerHTML = '';

        list.innerHTML = `
            <div class="py-12 text-center bg-slate-50/60 rounded-2xl border-2 border-dashed border-slate-200 p-6">
                <div class="w-16 h-16 mx-auto mb-3 rounded-3xl bg-purple-100 border border-purple-200 flex items-center justify-center text-purple-600 text-2xl shadow-inner">
                    <i class="fa-solid fa-lock"></i>
                </div>
                <p class="text-base font-black text-slate-800">กรุณาเข้าสู่ระบบเพื่อดูคีย์ของคุณ</p>
                <p class="text-xs text-slate-500 mt-1 max-w-sm mx-auto font-medium">เพื่อความปลอดภัยสูงสุด ข้อมูลคีย์และรหัสผ่านจะแสดงเฉพาะเมื่อคุณเข้าสู่ระบบสมาชิกเท่านั้น</p>
                <button onclick="closeOrdersModal(); openAuthModal('login');" class="mt-4 px-5 py-2.5 rounded-xl gradient-btn text-white text-xs font-bold shadow-sm cursor-pointer hover:opacity-95 transition-all">
                    <i class="fa-solid fa-right-to-bracket mr-1.5"></i> เข้าสู่ระบบสมาชิก
                </button>
            </div>
        `;
        return;
    }

    // Update Customer Profile Card in orders-modal
    const profileCard = document.getElementById('customer-profile-card');
    if (profileCard) {
        const user = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
        if (isLoggedIn && user) {
            profileCard.innerHTML = `
                <div class="p-3 sm:p-3.5 rounded-2xl bg-gradient-to-r from-pink-50/90 via-purple-50/70 to-pink-50/90 border-2 border-pink-200/90 shadow-xs flex flex-wrap items-center justify-between gap-2.5">
                    <div class="flex items-center gap-2.5 min-w-0">
                        <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-pink-500 to-purple-600 text-white flex items-center justify-center font-black text-sm shadow-md shadow-pink-500/20 shrink-0">
                            <i class="fa-solid fa-user-check"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-2 flex-wrap">
                                <span class="font-extrabold text-slate-900 text-xs sm:text-sm truncate">คุณ ${escapeHTML(user.displayName || user.name || 'สมาชิก Supinkly')}</span>
                                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-black border border-emerald-300">
                                    <i class="fa-solid fa-circle-check text-emerald-600"></i> สมาชิกเข้าสู่ระบบแล้ว
                                </span>
                                <button type="button" onclick="switchMemberTab('vip')" class="cursor-pointer inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-100 hover:bg-amber-200 text-amber-800 text-[10px] font-black border border-amber-300 transition-colors">
                                    <i class="fa-solid fa-crown text-amber-600"></i> ${escapeHTML(user.vip?.tierName || 'Bronze')} (${user.vip?.discountPercent || 0}% OFF)
                                </button>
                                <button type="button" onclick="switchMemberTab('coins')" class="cursor-pointer inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-pink-100 hover:bg-pink-200 text-pink-800 text-[10px] font-black border border-pink-300 transition-colors">
                                    <i class="fa-solid fa-coins text-amber-500"></i> ${(user.coins !== undefined ? user.coins : 20).toLocaleString()} Coins
                                </button>
                                <button type="button" onclick="switchMemberTab('wishlist')" class="cursor-pointer inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-100 hover:bg-rose-200 text-rose-800 text-[10px] font-black border border-rose-300 transition-colors">
                                    <i class="fa-solid fa-heart text-rose-500"></i> ${(user.wishlist || []).length} ที่ชอบ
                                </button>
                            </div>
                            <div class="text-[11px] text-slate-500 font-medium truncate flex items-center gap-1.5 mt-0.5">
                                <i class="fa-regular fa-envelope text-slate-400"></i>
                                <span>${escapeHTML(user.email || '')}</span>
                                <span class="text-slate-300">•</span>
                                <span class="text-pink-600 font-bold">บันทึกข้อมูลและคีย์ถาวร</span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                        <button type="button" onclick="handleUserLogout(); closeOrdersModal();" class="px-2.5 py-1.5 rounded-xl bg-white hover:bg-rose-50 text-slate-600 hover:text-rose-600 border border-slate-200 hover:border-rose-300 text-xs font-bold transition-all flex items-center gap-1 shadow-2xs cursor-pointer" title="ออกจากระบบ">
                            <i class="fa-solid fa-right-from-bracket text-xs"></i>
                            <span>ออกจากระบบ</span>
                        </button>
                    </div>
                </div>
            `;
        } else {
            profileCard.innerHTML = `
                <div class="p-3 rounded-2xl bg-amber-50/80 border-2 border-amber-200/90 shadow-xs flex flex-wrap items-center justify-between gap-2">
                    <div class="flex items-center gap-2 text-xs text-amber-900 font-medium">
                        <i class="fa-solid fa-circle-exclamation text-amber-600 shrink-0"></i>
                        <span>คุณกำลังเปิดดูในโหมดผู้เยี่ยมชม เข้าสู่ระบบเพื่อซิงค์คีย์และบันทึกข้อมูลถาวร</span>
                    </div>
                    <button type="button" onclick="closeOrdersModal(); openAuthModal('login');" class="px-3 py-1.5 rounded-xl gradient-btn text-white text-xs font-bold shadow-xs flex items-center gap-1.5 shrink-0 cursor-pointer">
                        <i class="fa-solid fa-right-to-bracket"></i> เข้าสู่ระบบ / สมัครสมาชิก
                    </button>
                </div>
            `;
        }
    }

    const totalOrders = (state.orders || []).length;
    const deliveredOrders = (state.orders || []).filter(isOrderDelivered).length;
    const pendingOrders = (state.orders || []).filter(isOrderPending).length;

    // Update filter counts & badges
    const cntAll = document.getElementById('ck-cnt-all');
    if (cntAll) cntAll.textContent = totalOrders;
    const cntDelivered = document.getElementById('ck-cnt-delivered');
    if (cntDelivered) cntDelivered.textContent = deliveredOrders;
    const cntPending = document.getElementById('ck-cnt-pending');
    if (cntPending) cntPending.textContent = pendingOrders;

    const badgeTotal = document.getElementById('customer-keys-count-badge');
    if (badgeTotal) badgeTotal.textContent = `${totalOrders} รายการ`;

    const navOrdersCount = document.getElementById('nav-orders-count');
    if (navOrdersCount) navOrdersCount.textContent = totalOrders;

    if (totalOrders === 0) {
        list.innerHTML = `
            <div class="py-12 text-center bg-slate-50/60 rounded-2xl border-2 border-dashed border-slate-200 p-6">
                <div class="w-16 h-16 mx-auto mb-3 rounded-3xl bg-pink-100 border border-pink-200 flex items-center justify-center text-pink-600 text-2xl shadow-inner">
                    <i class="fa-solid fa-key"></i>
                </div>
                <p class="text-base font-black text-slate-800">ยังไม่มีประวัติคำสั่งซื้อและคีย์ในระบบ</p>
                <p class="text-xs text-slate-500 mt-1 max-w-sm mx-auto font-medium">เมื่อคุณเลือกซื้อบัญชีหรือคีย์สำเร็จ ข้อมูลรหัสผ่านจะถูกบันทึกและแสดงไว้ที่นี่ทันที เข้าใช้งานได้ตลอด 24 ชม.</p>
                <button onclick="closeOrdersModal()" class="mt-4 px-4 py-2 rounded-xl gradient-btn text-white text-xs font-bold shadow-sm">
                    เลือกดูสินค้าในร้าน
                </button>
            </div>
        `;
        return;
    }

    // Filter by delivery status
    let filtered = state.orders;
    if (customerKeysFilter === 'delivered') {
        filtered = filtered.filter(isOrderDelivered);
    } else if (customerKeysFilter === 'pending') {
        filtered = filtered.filter(isOrderPending);
    }

    // Filter by search query
    if (customerKeysSearchQuery) {
        const q = customerKeysSearchQuery;
        filtered = filtered.filter(o => {
            const matchOrderId = (o.orderId || '').toLowerCase().includes(q);
            const matchDate = (o.date || '').toLowerCase().includes(q);
            const matchItems = (o.items || []).some(it => {
                const titleMatch = (it.productTitle || '').toLowerCase().includes(q);
                const cred = it.credentials || {};
                const emailMatch = (cred.email || '').toLowerCase().includes(q);
                const keyMatch = (cred.key || '').toLowerCase().includes(q);
                const linkMatch = (cred.link || '').toLowerCase().includes(q);
                return titleMatch || emailMatch || keyMatch || linkMatch;
            });
            return matchOrderId || matchDate || matchItems;
        });
    }

    if (filtered.length === 0) {
        list.innerHTML = `
            <div class="py-10 text-center bg-slate-50/60 rounded-2xl border border-slate-200 p-6">
                <i class="fa-solid fa-magnifying-glass text-2xl text-slate-400 mb-2"></i>
                <p class="text-sm font-bold text-slate-700">ไม่พบคีย์หรือคำสั่งซื้อที่ค้นหา "${escapeHTML(customerKeysSearchQuery)}"</p>
                <p class="text-xs text-slate-500 mt-1">ลองค้นหาด้วยคำอื่น หรือกดล้างการค้นหา</p>
                <button onclick="clearCustomerKeysSearch(); setCustomerKeysFilter('all');" class="mt-3 px-3.5 py-1.5 rounded-xl bg-slate-200 hover:bg-slate-300 text-slate-800 text-xs font-bold transition-all">
                    ล้างตัวกรองทั้งหมด
                </button>
            </div>
        `;
        return;
    }

    list.innerHTML = filtered.map((order) => {
        // [FIX] ใช้ชื่อต่างออกไปเพื่อหลีกเลี่ยง variable shadowing กับ function isOrderPending() ใน outer scope
        const isThisOrderPending = !isOrderDelivered(order);

        return `
            <div class="p-4 sm:p-5 rounded-2xl bg-white border-2 ${isThisOrderPending ? 'border-amber-300 bg-amber-50/20' : 'border-slate-200'} mb-3.5 hover:border-pink-300 transition-all shadow-sm">
                <!-- Order Header -->
                <div class="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-100">
                    <div class="flex items-center gap-2">
                        <span class="font-mono font-black text-pink-600 text-xs sm:text-sm tracking-wide bg-pink-50 border border-pink-200 px-2.5 py-0.5 rounded-lg select-all">
                            ${escapeHTML(order.orderId)}
                        </span>
                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(order.orderId)}" data-msg="คัดลอกเลขออเดอร์แล้ว" title="คัดลอกเลขออเดอร์" 
                                class="text-slate-400 hover:text-pink-600 text-xs transition-colors p-1">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                        <span class="text-xs text-slate-500 font-medium flex items-center gap-1 ml-1">
                            <i class="fa-regular fa-calendar text-[11px]"></i> ${escapeHTML(order.date || '-')}
                        </span>
                    </div>
                    <span class="px-3 py-1 rounded-full text-xs font-black flex items-center gap-1.5 shadow-xs ${isThisOrderPending
                ? 'bg-amber-100 text-amber-900 border border-amber-300 animate-pulse'
                : 'bg-emerald-100 text-emerald-900 border border-emerald-300'
            }">
                        <i class="fa-solid ${isThisOrderPending ? 'fa-spinner fa-spin' : 'fa-circle-check'} text-xs"></i>
                        <span>${isThisOrderPending ? 'กำลังจัดเตรียมรหัส (5-15 นาที)' : 'จัดส่งแล้ว (พร้อมใช้งาน)'}</span>
                    </span>
                </div>

                <!-- Items & Credentials -->
                <div class="mt-3.5 space-y-3">
                    ${(order.items || []).map((item, itIdx) => {
                const isPending = !item.credentials || item.status === 'pending_fulfillment';
                const cred = item.credentials || {};

                let credBlock = '';
                if (isPending) {
                    credBlock = `
                                <div class="mt-2.5 p-3 rounded-xl bg-amber-50 border border-amber-200 space-y-2">
                                    <div class="flex items-center justify-between text-xs font-bold text-amber-900">
                                        <span class="flex items-center gap-1.5">
                                            <i class="fa-solid fa-circle-notch fa-spin text-amber-600"></i>
                                            <span>กำลังจัดเตรียมบัญชีแท้ (5-15 นาที)</span>
                                        </span>
                                        <span class="text-[10px] bg-amber-200 text-amber-900 px-2 py-0.5 rounded-md font-extrabold animate-pulse">กำลังดำเนินการ</span>
                                    </div>
                                    <div class="grid grid-cols-3 gap-1.5 text-center text-[10px]">
                                        <div class="p-1 rounded-lg bg-emerald-100 border border-emerald-300 text-emerald-900 font-bold">
                                            <i class="fa-solid fa-check text-[10px] block"></i> 1. ชำระสำเร็จ
                                        </div>
                                        <div class="p-1 rounded-lg bg-amber-200 border border-amber-300 text-amber-900 font-bold animate-pulse">
                                            <i class="fa-solid fa-spinner fa-spin text-[10px] block"></i> 2. จัดเตรียมบัญชีแท้
                                        </div>
                                        <div class="p-1 rounded-lg bg-white/70 border border-slate-200 text-slate-400 font-medium">
                                            <i class="fa-solid fa-key text-[10px] block"></i> 3. ส่งมอบรหัส
                                        </div>
                                    </div>
                                    <div class="flex flex-wrap items-center justify-between gap-1 text-[11px] pt-1">
                                        <span class="text-amber-800 font-medium">✨ หน้านี้จะอัปเดตแสดงรหัสให้อัตโนมัติเมื่อจัดส่งสำเร็จ</span>
                                        <a href="https://www.facebook.com/profile.php?id=61594837747580" target="_blank" rel="noopener noreferrer" 
                                           class="font-bold text-[#1877F2] hover:underline flex items-center gap-1 shrink-0">
                                            <i class="fa-brands fa-facebook"></i> สอบถามแอดมินทาง Facebook
                                        </a>
                                    </div>
                                </div>
                            `;
                } else if (cred.email) {
                    credBlock = `
                                <div class="mt-2.5 p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                                    <div class="flex items-center justify-between gap-2">
                                        <div class="min-w-0 flex-1">
                                            <span class="text-[11px] font-bold text-slate-500 block">อีเมลบัญชี (Email):</span>
                                            <span class="text-xs sm:text-sm font-mono font-black text-pink-600 truncate block select-all">${escapeHTML(cred.email)}</span>
                                        </div>
                                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.email)}" data-msg="คัดลอกอีเมลแล้ว" class="px-2.5 py-1.5 rounded-lg bg-pink-100 hover:bg-pink-200 text-pink-700 text-xs font-bold transition-all shrink-0">
                                            <i class="fa-regular fa-copy"></i> คัดลอก
                                        </button>
                                    </div>
                                    <div class="flex items-center justify-between gap-2 pt-2 border-t border-slate-200/70">
                                        <div class="min-w-0 flex-1">
                                            <span class="text-[11px] font-bold text-slate-500 block">รหัสผ่าน (Password):</span>
                                            <span class="text-xs sm:text-sm font-mono font-black text-cyan-700 truncate block select-all">${escapeHTML(cred.password)}</span>
                                        </div>
                                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.password)}" data-msg="คัดลอกรหัสผ่านแล้ว" class="px-2.5 py-1.5 rounded-lg bg-cyan-100 hover:bg-cyan-200 text-cyan-800 text-xs font-bold transition-all shrink-0">
                                            <i class="fa-regular fa-copy"></i> คัดลอก
                                        </button>
                                    </div>
                                    <div class="pt-2 border-t border-slate-200/70 flex items-center justify-between gap-2">
                                        <button onclick="copyCombinedFromData(this)" data-email="${escapeHTML(cred.email)}" data-password="${escapeHTML(cred.password)}" class="flex-1 py-1.5 rounded-lg bg-gradient-to-r from-pink-500 to-purple-600 text-white text-xs font-bold hover:opacity-95 transition-all shadow-xs flex items-center justify-center gap-1.5">
                                            <i class="fa-solid fa-copy"></i> คัดลอกทั้งคู่ (Email + Password)
                                        </button>
                                    </div>
                                </div>
                                ${cred.instructions ? `
                                    <div class="mt-2 p-2.5 rounded-xl bg-white border border-slate-200 text-[11px] text-slate-600 leading-relaxed font-medium">
                                        <span class="font-bold text-pink-600 block mb-0.5"><i class="fa-solid fa-circle-info"></i> วิธีเข้าใช้งาน:</span>
                                        <div class="whitespace-pre-line">${escapeHTML(cred.instructions)}</div>
                                    </div>
                                ` : ''}
                            `;
                } else if (cred.link) {
                    credBlock = `
                                <div class="mt-2.5 p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                                    <div class="min-w-0 flex-1 pr-2">
                                        <span class="text-[11px] font-bold text-slate-500 block">ลิงก์เปิดใช้งาน (Activation Link):</span>
                                        <span class="text-xs font-mono font-bold text-cyan-700 truncate block select-all">${escapeHTML(cred.link)}</span>
                                    </div>
                                    <div class="flex items-center gap-1.5 shrink-0">
                                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.link)}" data-msg="คัดลอกลิงก์แล้ว" class="px-2.5 py-1.5 rounded-lg bg-cyan-100 hover:bg-cyan-200 text-cyan-800 text-xs font-bold transition-all">
                                            <i class="fa-regular fa-copy"></i> คัดลอก
                                        </button>
                                        <a href="${sanitizeUrl(cred.link)}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1.5 rounded-lg gradient-btn text-white text-xs font-bold flex items-center gap-1">
                                            <i class="fa-solid fa-arrow-up-right-from-square"></i> เปิด
                                        </a>
                                    </div>
                                </div>
                                ${cred.instructions ? `
                                    <div class="mt-2 p-2.5 rounded-xl bg-white border border-slate-200 text-[11px] text-slate-600 leading-relaxed font-medium">
                                        <span class="font-bold text-pink-600 block mb-0.5"><i class="fa-solid fa-circle-info"></i> วิธีใช้งาน:</span>
                                        <div class="whitespace-pre-line">${escapeHTML(cred.instructions)}</div>
                                    </div>
                                ` : ''}
                            `;
                } else {
                    credBlock = `
                                <div class="mt-2.5 p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                                    <div class="min-w-0 flex-1">
                                        <span class="text-[11px] font-bold text-slate-500 block">รหัสผลิตภัณฑ์ (License Key):</span>
                                        <span class="text-xs sm:text-sm font-mono font-black text-emerald-700 truncate block select-all">${escapeHTML(cred.key || '')}</span>
                                    </div>
                                    <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.key || '')}" data-msg="คัดลอกคีย์แล้ว" class="px-2.5 py-1.5 rounded-lg bg-emerald-100 hover:bg-emerald-200 text-emerald-800 text-xs font-bold transition-all shrink-0">
                                        <i class="fa-regular fa-copy"></i> คัดลอก
                                    </button>
                                </div>
                                ${cred.instructions ? `
                                    <div class="mt-2 p-2.5 rounded-xl bg-white border border-slate-200 text-[11px] text-slate-600 leading-relaxed font-medium">
                                        <span class="font-bold text-pink-600 block mb-0.5"><i class="fa-solid fa-circle-info"></i> วิธีใช้งาน:</span>
                                        <div class="whitespace-pre-line">${escapeHTML(cred.instructions)}</div>
                                    </div>
                                ` : ''}
                            `;
                }

                const warrantyStatus = calculateWarrantyStatus(order, item);
                let warrantyBadgeHtml = '';
                if (warrantyStatus.isExpired) {
                    warrantyBadgeHtml = `
                        <span class="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 font-bold border border-slate-200 flex items-center gap-1">
                            <i class="fa-solid fa-hourglass-end text-slate-400"></i> หมดประกัน (${warrantyStatus.expiryDateStr})
                        </span>
                    `;
                } else if (warrantyStatus.isExpiringSoon) {
                    warrantyBadgeHtml = `
                        <span class="text-[11px] px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 font-bold border border-amber-300 flex items-center gap-1 animate-pulse">
                            <i class="fa-solid fa-triangle-exclamation text-amber-500"></i> ใกล้หมดอายุ (${warrantyStatus.daysRemaining} วัน)
                        </span>
                    `;
                } else {
                    warrantyBadgeHtml = `
                        <span class="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-bold border border-emerald-200 flex items-center gap-1">
                            <i class="fa-solid fa-shield-halved text-emerald-500"></i> ประกันเหลือ ${warrantyStatus.daysRemaining} วัน
                        </span>
                    `;
                }

                const credSnippet = cred.email ? `Email: ${cred.email}` : (cred.key ? `Key: ${cred.key}` : (cred.link ? `Link: ${cred.link}` : ''));

                return `
                            <div class="p-3 sm:p-3.5 rounded-xl bg-slate-50/70 border border-slate-200 space-y-2">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="flex items-center gap-2 min-w-0">
                                        <span class="w-5 h-5 rounded-full bg-pink-500 text-white flex items-center justify-center text-[10px] font-black shrink-0">
                                            ${itIdx + 1}
                                        </span>
                                        <span class="font-normal text-slate-900 text-xs sm:text-sm truncate">
                                            ${escapeHTML(item.productTitle)}
                                        </span>
                                    </div>
                                    <div class="flex items-center gap-2 shrink-0">
                                        <span class="font-black text-pink-600 text-xs sm:text-sm font-['Outfit']">฿${(item.price || 0).toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})}</span>
                                    </div>
                                </div>

                                ${credBlock}

                                <!-- Warranty Countdown & 1-Click Action Bar -->
                                <div class="pt-2 border-t border-slate-200/70 flex flex-wrap items-center justify-between gap-2 text-xs">
                                    <div class="flex items-center gap-1.5 flex-wrap">
                                        ${warrantyBadgeHtml}
                                    </div>
                                    <div class="flex items-center gap-1.5 shrink-0">
                                        <button type="button" onclick="claimOrderWarranty('${escapeHTML(order.orderId)}', '${escapeHTML(item.productTitle)}', '${escapeHTML(credSnippet)}')"
                                            class="px-2.5 py-1 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 font-bold text-[11px] border border-indigo-200 transition-all flex items-center gap-1 shadow-2xs cursor-pointer active:scale-95">
                                            <i class="fa-solid fa-headset text-indigo-500"></i>
                                            <span>แจ้งเคลมรหัส</span>
                                        </button>
                                        <button type="button" onclick="renewOrderProduct('${escapeHTML(item.productId || '')}', '${escapeHTML(order.orderId)}')"
                                            class="px-2.5 py-1 rounded-xl bg-pink-50 hover:bg-pink-100 text-pink-700 font-bold text-[11px] border border-pink-200 transition-all flex items-center gap-1 shadow-2xs cursor-pointer active:scale-95">
                                            <i class="fa-solid fa-rotate text-pink-500"></i>
                                            <span>ต่ออายุ (1-Click)</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
            }).join('')}
                </div>

                <!-- Order Footer -->
                <div class="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-100 mt-3 text-xs">
                    <div class="font-bold text-slate-600">
                        ยอดรวมคำสั่งซื้อ: <span class="text-base font-black text-slate-900 font-['Outfit']">฿${(order.totalAmount || 0).toLocaleString('th-TH', {minimumFractionDigits: 2, maximumFractionDigits: 2})}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="copyOrderCustomerSummary('${escapeHTML(order.orderId)}')" class="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold transition-all flex items-center gap-1 shadow-xs">
                            <i class="fa-solid fa-receipt text-slate-500"></i>
                            <span>คัดลอกสรุปคำสั่งซื้อ</span>
                        </button>
                        <button onclick="viewPastOrderVault('${escapeHTML(order.orderId)}')" class="px-3 py-1.5 rounded-xl ${isOrderPending ? 'bg-amber-100 hover:bg-amber-200 text-amber-900 border border-amber-300' : 'gradient-btn-cyan text-white'} text-xs font-bold transition-all flex items-center gap-1 shadow-xs">
                            <i class="fa-solid ${isOrderPending ? 'fa-clock' : 'fa-vault'}"></i>
                            <span>${isOrderPending ? 'ติดตามใน Vault' : 'เปิดใน Vault'}</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ══════════════════════════════════════════
// WARRANTY COUNTDOWN, 1-CLICK RENEW & CLAIM
// ══════════════════════════════════════════
function calculateWarrantyStatus(order, item) {
    const rawWarranty = (item && item.warranty ? item.warranty : '30 วัน').toString().trim();
    let durationDays = 30;
    if (/ตลอดชีพ|lifetime/i.test(rawWarranty)) {
        durationDays = 3650;
    } else {
        const match = rawWarranty.match(/(\d+)\s*(วัน|day|days|เดือน|month|months|ปี|year|years)?/i);
        if (match) {
            const val = parseInt(match[1], 10);
            const unit = (match[2] || 'วัน').toLowerCase();
            if (unit.includes('เดือน') || unit.includes('month')) {
                durationDays = val * 30;
            } else if (unit.includes('ปี') || unit.includes('year')) {
                durationDays = val * 365;
            } else {
                durationDays = val;
            }
        }
    }

    const rawDate = (order && (order.createdAt || order.date || order.timestamp)) || null;
    const orderTime = rawDate ? new Date(rawDate).getTime() : Date.now();
    const expiryTime = orderTime + (durationDays * 24 * 60 * 60 * 1000);
    const msRemaining = expiryTime - Date.now();
    const daysRemaining = Math.max(0, Math.ceil(msRemaining / (24 * 60 * 60 * 1000)));

    return {
        durationDays,
        daysRemaining,
        isExpired: msRemaining <= 0,
        isExpiringSoon: msRemaining > 0 && daysRemaining <= 5,
        expiryDateStr: new Date(expiryTime).toLocaleDateString('th-TH', { year: 'numeric', month: 'short', day: 'numeric' })
    };
}

function renewOrderProduct(productId, orderId) {
    let prod = (state.products || []).find(p => String(p.id) === String(productId));

    if (!prod && orderId) {
        const order = (state.orders || []).find(o => o.orderId === orderId);
        const item = order ? (order.items || []).find(i => String(i.productId) === String(productId)) : null;
        if (item) {
            prod = (state.products || []).find(p => p.title.toLowerCase().trim() === item.productTitle.toLowerCase().trim());
        }
    }

    if (prod) {
        if (typeof addToCart === 'function') {
            addToCart(prod.id);
            const memberModal = document.getElementById('member-center-modal');
            if (memberModal) memberModal.classList.add('hidden');
            const ordersModal = document.getElementById('orders-modal');
            if (ordersModal) ordersModal.classList.add('hidden');

            if (typeof openCartDrawer === 'function') {
                openCartDrawer();
            } else if (typeof toggleCart === 'function') {
                toggleCart();
            }
            showToast(`เพิ่ม "${prod.title}" ลงตะกร้าแล้วเพื่อต่ออายุเรียบร้อย! 🛒`, 'success');
        }
    } else {
        showToast('ไม่พบสินค้ารายการนี้ในคลังปัจจุบัน กรุณาสอบถามทางแชทเพื่อต่ออายุ', 'warning');
    }
}

function claimOrderWarranty(orderId, productTitle, credSnippet) {
    const ticketText = `🚨 [แจ้งเคลมสินค้า/มีปัญหาการใช้งาน]\n• เลขที่คำสั่งซื้อ: #${orderId}\n• รายการ: ${productTitle}${credSnippet ? `\n• ข้อมูล: ${credSnippet}` : ''}\n• ปัญหา: เข้าใช้งานไม่ได้ / รหัสหลุด / ขอเคลมประกัน\n• เวลาที่แจ้ง: ${new Date().toLocaleString('th-TH')}`;

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(ticketText).catch(() => {});
    }

    const memberModal = document.getElementById('member-center-modal');
    if (memberModal) memberModal.classList.add('hidden');
    const ordersModal = document.getElementById('orders-modal');
    if (ordersModal) ordersModal.classList.add('hidden');

    const chatInput = document.getElementById('spk-chat-input');
    if (chatInput) {
        chatInput.value = ticketText;
    }

    const chatWidget = document.getElementById('spk-chat-widget');
    const chatBtn = document.getElementById('spk-chat-btn');
    if (chatWidget && chatWidget.classList.contains('hidden') && chatBtn) {
        chatBtn.click();
    } else if (typeof window.openChatWidget === 'function') {
        window.openChatWidget();
    }

    showToast('คัดลอกข้อมูลแจ้งเคลมแล้ว! นำข้อมูลนี้ส่งให้แอดมินในแชทได้ทันที 💬', 'info');
}

// ══════════════════════════════════════════
// GUEST & ACCOUNT WISHLIST HELPERS
// ══════════════════════════════════════════
function getLocalWishlist() {
    try {
        const raw = localStorage.getItem('supinkly_guest_wishlist');
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function setLocalWishlist(list) {
    try {
        localStorage.setItem('supinkly_guest_wishlist', JSON.stringify(Array.isArray(list) ? list : []));
    } catch { }
}

function getWishlistItems() {
    if (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
        const user = USER_AUTH.getUser();
        if (Array.isArray(user?.wishlist)) return user.wishlist;
    }
    return getLocalWishlist();
}

function isProductWishlisted(productId) {
    if (!productId) return false;
    return getWishlistItems().includes(productId);
}

async function openOrdersModal(initialTab = 'orders') {
    const modal = document.getElementById('orders-modal');
    if (!modal) return;

    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();

    if (isLoggedIn && typeof USER_AUTH.getProfile === 'function') {
        USER_AUTH.getProfile().then(p => {
            if (p) {
                state.user = p;
                updateMemberBadges();
                if (state.activeMemberTab === 'vip') renderVipPane();
                if (state.activeMemberTab === 'coins') renderCoinsPane();
                if (state.activeMemberTab === 'referral') renderReferralPane();
                if (state.activeMemberTab === 'wishlist') renderWishlistPane();
            }
        }).catch(() => { });
    }

    await refreshUserOrders();
    updateMemberBadges();
    modal.classList.remove('hidden');
    switchMemberTab(initialTab || 'orders');
}

function viewPastOrderVault(target) {
    let order = null;
    if (typeof target === 'number') {
        order = state.orders[target];
    } else if (typeof target === 'string') {
        order = state.orders.find(o => o.orderId === target);
    }
    if (order) openVaultModal(order);
}

function closeOrdersModal() {
    const modal = document.getElementById('orders-modal');
    if (modal) modal.classList.add('hidden');
}

// ══════════════════════════════════════════
// MEMBER CENTER TABS & LOYALTY SYSTEM
// ══════════════════════════════════════════
function switchMemberTab(tabName) {
    state.activeMemberTab = tabName;
    const allTabs = ['orders', 'vip', 'coins', 'referral', 'wishlist', 'settings'];

    // Dynamic Modal Title Update
    const modalTitleEl = document.getElementById('member-center-modal-title');
    const tabTitles = {
        orders: 'ศูนย์สมาชิก & คลังคีย์',
        vip: 'ระดับสมาชิก & สิทธิพิเศษ VIP',
        coins: 'กระเป๋า Pink Coins & แต้มสะสม',
        referral: 'ระบบแนะนำเพื่อน (Affiliate)',
        wishlist: 'รายการสินค้าที่ชอบ (Wishlist)',
        settings: 'ตั้งค่าบัญชี & ความปลอดภัย'
    };
    if (modalTitleEl && tabTitles[tabName]) {
        modalTitleEl.textContent = tabTitles[tabName];
    }

    allTabs.forEach(t => {
        const btn = document.getElementById(`member-tab-btn-${t}`);
        const pane = document.getElementById(`member-pane-${t}`);
        if (pane) {
            pane.classList.toggle('hidden', t !== tabName);
        }
        if (btn) {
            if (t === tabName) {
                btn.className = "member-tab-btn px-3 py-2 rounded-xl bg-pink-500 text-white shadow-xs flex items-center gap-1.5 shrink-0 transition-all cursor-pointer font-bold";
                if (typeof btn.scrollIntoView === 'function') {
                    try { btn.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' }); } catch (e) { }
                }
            } else {
                btn.className = "member-tab-btn px-3 py-2 rounded-xl text-slate-600 hover:text-slate-900 hover:bg-white/80 flex items-center gap-1.5 shrink-0 transition-all cursor-pointer font-bold";
            }
        }
    });

    if (tabName === 'vip') renderVipPane();
    else if (tabName === 'coins') renderCoinsPane();
    else if (tabName === 'referral') renderReferralPane();
    else if (tabName === 'wishlist') renderWishlistPane();
    else if (tabName === 'settings') renderSettingsPane();
    else if (tabName === 'orders') renderOrdersHistory();
}

function updateMemberBadges() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;
    const wishlistCount = getWishlistItems().length;

    // Navbar wishlist badge
    const navWishlistBadge = document.getElementById('nav-wishlist-count-badge');
    if (navWishlistBadge) {
        navWishlistBadge.textContent = wishlistCount;
        navWishlistBadge.classList.toggle('hidden', wishlistCount <= 0);
    }

    // Tab buttons counts
    const tabCntOrders = document.getElementById('tab-cnt-orders');
    if (tabCntOrders) tabCntOrders.textContent = (state.orders || []).length;

    const tabBadgeVip = document.getElementById('tab-badge-vip');
    if (tabBadgeVip) tabBadgeVip.textContent = user?.vip?.tierName || 'Bronze';

    const tabCntCoins = document.getElementById('tab-cnt-coins');
    if (tabCntCoins) tabCntCoins.textContent = (user?.coins !== undefined ? user.coins : 20);

    const tabCntWishlist = document.getElementById('tab-cnt-wishlist');
    if (tabCntWishlist) tabCntWishlist.textContent = wishlistCount;

    // Header Notification Center badge
    updateNotificationBadge();
}

// ══════════════════════════════════════════
// IN-APP NOTIFICATION CENTER CONTROLLERS
// ══════════════════════════════════════════
function getReadNotificationIds() {
    try {
        const raw = localStorage.getItem('supinkly_read_notifs');
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? new Set(parsed) : new Set();
    } catch {
        return new Set();
    }
}

function saveReadNotificationIds(idSet) {
    try {
        const arr = Array.from(idSet).slice(-200);
        localStorage.setItem('supinkly_read_notifs', JSON.stringify(arr));
    } catch (e) {}
}

function getMemberNotifications() {
    const notifs = [];
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;
    const todayStr = new Date().toISOString().slice(0, 10);

    // 1. Daily Check-in Alert
    if (isLoggedIn) {
        if (user?.lastCheckInDate !== todayStr) {
            notifs.push({
                id: `checkin_${todayStr}`,
                icon: 'fa-solid fa-gift text-amber-500',
                iconBg: 'bg-amber-100',
                title: 'อย่าลืมเช็คอินรับ Pink Coins วันนี้!',
                desc: 'เข้าเช็คอินรายวันเพื่อรับเหรียญ Pink Coins ฟรี สะสมแลกส่วนลดได้เลย',
                time: 'วันนี้',
                actionType: 'checkin',
                btnText: 'เช็คอินเลย'
            });
        }
    } else {
        notifs.push({
            id: 'guest_welcome_coins',
            icon: 'fa-solid fa-coins text-amber-500',
            iconBg: 'bg-amber-100',
            title: 'โบนัสต้อนรับ 20 Pink Coins ฟรี!',
            desc: 'สมัครสมาชิกวันนี้รับ 20 Pink Coins ทันที ใช้ลดเงินสดในตะกร้าได้เลย',
            time: 'สิทธิพิเศษ',
            actionType: 'register',
            btnText: 'สมัครสมาชิก'
        });
    }

    // 2. Orders Warranty & Renewal Alerts
    const allOrders = (state.orders || []);
    allOrders.forEach(order => {
        (order.items || []).forEach((item, itIdx) => {
            const wStatus = calculateWarrantyStatus(order, item);
            if (wStatus.isExpired) {
                notifs.push({
                    id: `warranty_exp_${order.orderId}_${item.productId || itIdx}`,
                    icon: 'fa-solid fa-hourglass-end text-rose-500',
                    iconBg: 'bg-rose-100',
                    title: `ประกันหมดอายุ: ${item.productTitle}`,
                    desc: `คำสั่งซื้อ #${order.orderId} หมดประกันแล้ว (${wStatus.expiryDateStr})`,
                    time: wStatus.expiryDateStr,
                    actionType: 'renew',
                    productId: item.productId,
                    orderId: order.orderId,
                    btnText: 'ต่ออายุ (1-Click)'
                });
            } else if (wStatus.isExpiringSoon) {
                notifs.push({
                    id: `warranty_soon_${order.orderId}_${item.productId || itIdx}`,
                    icon: 'fa-solid fa-triangle-exclamation text-amber-500',
                    iconBg: 'bg-amber-100',
                    title: `ใกล้หมดประกัน (เหลือ ${wStatus.daysRemaining} วัน): ${item.productTitle}`,
                    desc: `คำสั่งซื้อ #${order.orderId} จะหมดประกันในวันที่ ${wStatus.expiryDateStr}`,
                    time: `เหลือ ${wStatus.daysRemaining} วัน`,
                    actionType: 'renew',
                    productId: item.productId,
                    orderId: order.orderId,
                    btnText: 'ต่ออายุเลย'
                });
            }
        });
    });

    // 3. Stock Alerts (for restocked items)
    if (isLoggedIn && Array.isArray(user?.stockAlerts) && user.stockAlerts.length > 0) {
        user.stockAlerts.forEach(pid => {
            const prod = getMasterProduct(pid);
            if (prod) {
                const stock = (prod.stock || (state.inventory[pid] || []).length || 0);
                if (stock > 0) {
                    notifs.push({
                        id: `stock_restocked_${pid}`,
                        icon: 'fa-solid fa-boxes-stacked text-emerald-500',
                        iconBg: 'bg-emerald-100',
                        title: `สินค้าพร้อมส่ง: ${prod.title}`,
                        desc: `สินค้าที่คุณตั้งเตือนไว้มีของแล้ว ฿${formatProductPrice(prod.price)}`,
                        time: 'เพิ่งเติมสต็อก',
                        actionType: 'cart',
                        productId: prod.id,
                        btnText: 'สั่งซื้อเลย'
                    });
                }
            }
        });
    }

    // 4. VIP Tier perk reminder
    if (isLoggedIn && user?.vip) {
        notifs.push({
            id: `vip_tier_active_${user.vip.tier || 'bronze'}`,
            icon: 'fa-solid fa-crown text-pink-500',
            iconBg: 'bg-pink-100',
            title: `สิทธิประโยชน์ ${user.vip.tierName || 'Bronze'} Member`,
            desc: `คุณได้รับสิทธิ์ส่วนลด ${user.vip.discountPercent || 0}% ทุกบิล พร้อมรับ Pink Coins สะสม`,
            time: 'สิทธิประโยชน์',
            actionType: 'vip',
            btnText: 'ดูสิทธิ VIP'
        });
    }

    return notifs;
}

function updateNotificationBadge() {
    const notifs = getMemberNotifications();
    const readIds = getReadNotificationIds();
    const unreadCount = notifs.filter(n => !readIds.has(n.id)).length;

    const badge = document.getElementById('nav-notification-count-badge');
    if (badge) {
        badge.textContent = unreadCount > 9 ? '9+' : unreadCount;
        badge.classList.toggle('hidden', unreadCount <= 0);
    }

    const unreadTag = document.getElementById('notification-unread-tag');
    if (unreadTag) {
        unreadTag.textContent = `${unreadCount} ใหม่`;
        unreadTag.className = unreadCount > 0 
            ? "px-2 py-0.5 rounded-full bg-amber-200 text-amber-900 text-[10px] font-black"
            : "px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-black";
    }
}

function renderNotificationCenter() {
    const listEl = document.getElementById('notification-items-list');
    if (!listEl) return;

    const notifs = getMemberNotifications();
    const readIds = getReadNotificationIds();

    updateNotificationBadge();

    if (notifs.length === 0) {
        listEl.innerHTML = `
            <div class="py-8 text-center text-slate-400 space-y-2">
                <div class="w-12 h-12 rounded-full bg-slate-100 mx-auto flex items-center justify-center text-slate-400 text-xl">
                    <i class="fa-solid fa-bell-slash"></i>
                </div>
                <div class="text-xs font-bold text-slate-700">ไม่มีการแจ้งเตือนในขณะนี้</div>
                <p class="text-[11px] text-slate-400">เมื่อมีอัปเดตประกันสินค้าหรือโบนัสเหรียญ จะปรากฏที่นี่</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = notifs.map(n => {
        const isRead = readIds.has(n.id);
        let actionAttr = '';
        if (n.actionType === 'checkin') {
            actionAttr = `onclick="closeNotificationCenter(); openOrdersModal('coins');"`;
        } else if (n.actionType === 'register') {
            actionAttr = `onclick="closeNotificationCenter(); openAuthModal('register');"`;
        } else if (n.actionType === 'renew') {
            actionAttr = `onclick="closeNotificationCenter(); renewOrderProduct('${escapeHTML(n.productId || '')}', '${escapeHTML(n.orderId || '')}');"`;
        } else if (n.actionType === 'cart') {
            actionAttr = `onclick="closeNotificationCenter(); addToCart('${escapeHTML(n.productId || '')}'); if (typeof openCartDrawer === 'function') openCartDrawer();"`;
        } else if (n.actionType === 'vip') {
            actionAttr = `onclick="closeNotificationCenter(); openOrdersModal('vip');"`;
        } else {
            actionAttr = `onclick="closeNotificationCenter();"`;
        }

        return `
            <div class="p-2.5 rounded-xl transition-all ${isRead ? 'bg-white opacity-80' : 'bg-amber-50/60 border border-amber-200/70 shadow-2xs'} hover:bg-slate-50">
                <div class="flex items-start gap-2.5">
                    <div class="w-8 h-8 rounded-xl ${n.iconBg || 'bg-amber-100'} flex items-center justify-center text-sm shrink-0 mt-0.5">
                        <i class="${n.icon}"></i>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center justify-between gap-1">
                            <span class="text-xs font-bold text-slate-900 truncate">${escapeHTML(n.title)}</span>
                            ${!isRead ? '<span class="w-2 h-2 rounded-full bg-rose-500 shrink-0"></span>' : ''}
                        </div>
                        <p class="text-[11px] text-slate-600 leading-tight mt-0.5 line-clamp-2">${escapeHTML(n.desc)}</p>
                        <div class="flex items-center justify-between gap-2 mt-2 pt-1 border-t border-slate-100 text-[10px]">
                            <span class="text-slate-400 font-medium">${escapeHTML(n.time)}</span>
                            <button type="button" ${actionAttr} class="font-bold text-pink-600 hover:text-pink-700 bg-pink-50 hover:bg-pink-100 px-2 py-0.5 rounded-md transition-colors cursor-pointer">
                                ${escapeHTML(n.btnText || 'ดูรายละเอียด')} &rarr;
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleNotificationCenter() {
    const dropdown = document.getElementById('notification-center-dropdown');
    if (!dropdown) return;
    const isHidden = dropdown.classList.contains('hidden');
    if (isHidden) {
        dropdown.classList.remove('hidden');
        renderNotificationCenter();
    } else {
        dropdown.classList.add('hidden');
    }
}

function closeNotificationCenter() {
    const dropdown = document.getElementById('notification-center-dropdown');
    if (dropdown) dropdown.classList.add('hidden');
}

function markAllNotificationsRead() {
    const notifs = getMemberNotifications();
    const readIds = getReadNotificationIds();
    notifs.forEach(n => readIds.add(n.id));
    saveReadNotificationIds(readIds);
    renderNotificationCenter();
    showToast('ทำเครื่องหมายว่าอ่านทั้งหมดแล้ว', 'info');
}

function renderVipPane() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;
    const vip = user?.vip || { tier: 'bronze', tierName: 'Bronze', badge: '🥉', discountPercent: 0, nextTierName: 'Silver Member', neededSpend: 500, progressPercent: 0 };
    const totalSpent = Number(user?.totalSpent || 0);

    const card = document.getElementById('vip-metallic-card');
    if (card) {
        card.className = "p-5 rounded-3xl text-white shadow-xl relative overflow-hidden transition-all duration-300";
        if (vip.tier === 'diamond') {
            card.classList.add('bg-gradient-to-br', 'from-cyan-600', 'via-blue-600', 'to-indigo-800');
        } else if (vip.tier === 'gold') {
            card.classList.add('bg-gradient-to-br', 'from-amber-500', 'via-yellow-600', 'to-amber-700');
        } else if (vip.tier === 'silver') {
            card.classList.add('bg-gradient-to-br', 'from-slate-500', 'via-slate-600', 'to-slate-700');
        } else {
            card.classList.add('bg-gradient-to-br', 'from-amber-700', 'via-amber-800', 'to-amber-950');
        }
    }

    const tierNameEl = document.getElementById('vip-card-tier-name');
    if (tierNameEl) tierNameEl.innerHTML = `<span>${escapeHTML(vip.badge || '🥉')} ${escapeHTML(vip.tierName || 'Bronze')} Member</span>`;

    const discountRateEl = document.getElementById('vip-card-discount-rate');
    if (discountRateEl) discountRateEl.textContent = `${vip.discountPercent || 0}%`;

    const progressTextEl = document.getElementById('vip-card-progress-text');
    if (progressTextEl) {
        if (!isLoggedIn) {
            progressTextEl.textContent = `เข้าสู่ระบบเพื่อเริ่มสะสมยอดและปลดล็อก Silver (ลด 3%)`;
        } else if (vip.neededSpend > 0 && vip.nextTierName) {
            progressTextEl.textContent = `ช้อปอีก ฿${vip.neededSpend.toFixed(2)} เพื่อเลื่อนขั้นเป็น ${vip.nextTierName}`;
        } else {
            progressTextEl.textContent = `ยินดีด้วย! คุณอยู่ในระดับสมาชิกสูงสุด Diamond แล้ว ⭐`;
        }
    }

    const progressPctEl = document.getElementById('vip-card-progress-pct');
    if (progressPctEl) progressPctEl.textContent = `${vip.progressPercent || 0}%`;

    const progressBarEl = document.getElementById('vip-card-progress-bar');
    if (progressBarEl) progressBarEl.style.width = `${vip.progressPercent || 0}%`;

    const totalSpentEl = document.getElementById('vip-card-total-spent');
    if (totalSpentEl) totalSpentEl.textContent = totalSpent.toFixed(2);

    const nextTierLabelEl = document.getElementById('vip-card-next-tier-label');
    if (nextTierLabelEl) {
        if (!isLoggedIn) {
            nextTierLabelEl.textContent = `สมาชิกใหม่: เริ่มต้น Bronze (ส่วนลดสะสมสูงสุด 7%)`;
        } else if (vip.nextTierName) {
            nextTierLabelEl.textContent = `ขั้นถัดไป: ${vip.nextTierName}`;
        } else {
            nextTierLabelEl.textContent = `ระดับสูงสุด: ลด 7% ทุกบิล`;
        }
    }

    // Guest prompt banner inside VIP pane
    let guestBanner = document.getElementById('vip-guest-banner');
    if (!isLoggedIn) {
        if (!guestBanner) {
            guestBanner = document.createElement('div');
            guestBanner.id = 'vip-guest-banner';
            guestBanner.className = "p-3 sm:p-3.5 rounded-2xl bg-gradient-to-r from-amber-50 to-pink-50 border-2 border-amber-300 flex items-center justify-between gap-2.5 shadow-2xs";
            const pane = document.getElementById('member-pane-vip');
            if (pane) pane.insertBefore(guestBanner, pane.firstChild);
        }
        guestBanner.innerHTML = `
            <div class="flex items-center gap-2.5 min-w-0">
                <div class="w-8 h-8 rounded-xl bg-amber-400 text-amber-950 flex items-center justify-center font-black text-sm shrink-0 shadow-xs">
                    <i class="fa-solid fa-crown"></i>
                </div>
                <div class="min-w-0 text-xs">
                    <div class="font-bold text-slate-900 truncate">เข้าสู่ระบบเพื่อรับส่วนลด VIP อัตโนมัติ</div>
                    <div class="text-[11px] text-slate-600 truncate">ยิ่งช้อปเยอะยิ่งลดเยอะ สะสมยอดซื้อได้ตลอดชีพ</div>
                </div>
            </div>
            <button onclick="openAuthModal('login')" class="px-3 py-1.5 rounded-xl bg-gradient-to-r from-pink-500 to-rose-600 hover:from-pink-600 hover:to-rose-700 text-white font-bold text-xs shrink-0 shadow-xs cursor-pointer active:scale-95 transition-all">
                เข้าสู่ระบบ
            </button>
        `;
        guestBanner.classList.remove('hidden');
    } else if (guestBanner) {
        guestBanner.classList.add('hidden');
    }
}

function renderCoinsPane() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;
    const coins = Number(user?.coins !== undefined ? user.coins : 20);

    const balEl = document.getElementById('coins-pane-balance');
    if (balEl) balEl.textContent = coins.toLocaleString();

    const bahtEl = document.getElementById('coins-pane-baht');
    if (bahtEl) bahtEl.textContent = coins.toFixed(2);

    // 🗓️ Daily Check-in Streak & 7-Day Matrix
    const todayStr = new Date().toISOString().slice(0, 10);
    const yesterdayStr = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const lastCheck = user?.lastCheckInDate || null;
    const isCheckedInToday = isLoggedIn && lastCheck === todayStr;

    let currentStreak = Number(user?.checkInStreak || 0);
    if (!isCheckedInToday && lastCheck && lastCheck !== yesterdayStr) {
        currentStreak = 0; // broken streak
    }

    const streakCountEl = document.getElementById('checkin-streak-count');
    if (streakCountEl) {
        streakCountEl.textContent = `${currentStreak} วันติด`;
    }

    const cycleDay = isCheckedInToday ? (((currentStreak - 1) % 7) + 1) : ((currentStreak % 7) + 1);
    const rewards = [1, 1, 2, 2, 3, 3, 10];
    const todayReward = rewards[cycleDay - 1];

    const gridEl = document.getElementById('checkin-7days-grid');
    if (gridEl) {
        gridEl.innerHTML = rewards.map((rew, idx) => {
            const dayNum = idx + 1;
            let statusClasses = '';
            let iconHtml = '';

            if (dayNum < cycleDay || (isCheckedInToday && dayNum <= cycleDay)) {
                statusClasses = 'bg-white/25 border border-white/50 text-white';
                iconHtml = '<i class="fa-solid fa-check text-emerald-300 text-xs"></i>';
            } else if (dayNum === cycleDay && !isCheckedInToday) {
                statusClasses = 'bg-amber-300 text-slate-900 border-2 border-white shadow-lg ring-2 ring-amber-200 animate-pulse font-black scale-105';
                iconHtml = '<i class="fa-solid fa-gift text-pink-600 text-xs"></i>';
            } else {
                statusClasses = 'bg-white/10 border border-white/20 text-white/70';
                iconHtml = '<i class="fa-solid fa-coins text-white/50 text-[10px]"></i>';
            }

            return `
                <div class="p-1.5 sm:p-2 rounded-xl flex flex-col items-center justify-between text-center transition-all ${statusClasses}">
                    <span class="text-[9px] sm:text-[10px] font-bold block opacity-90">วันที่ ${dayNum}</span>
                    <div class="my-1">${iconHtml}</div>
                    <span class="text-[10px] sm:text-xs font-black block">+${rew}</span>
                </div>
            `;
        }).join('');
    }

    const checkinBtn = document.getElementById('daily-checkin-btn');
    const checkinBtnText = document.getElementById('daily-checkin-btn-text');
    if (checkinBtn && checkinBtnText) {
        if (!isLoggedIn) {
            checkinBtn.disabled = false;
            checkinBtn.className = "w-full py-2.5 px-4 rounded-2xl bg-white hover:bg-amber-50 text-slate-900 font-extrabold text-xs shadow-md transition-all active:scale-95 flex items-center justify-center gap-2 cursor-pointer";
            checkinBtnText.textContent = "เข้าสู่ระบบเพื่อเช็คอินรับเหรียญฟรี (+1 Coin)";
        } else if (isCheckedInToday) {
            checkinBtn.disabled = true;
            checkinBtn.className = "w-full py-2.5 px-4 rounded-2xl bg-white/30 text-white font-extrabold text-xs border border-white/40 flex items-center justify-center gap-2 cursor-not-allowed opacity-90";
            checkinBtnText.innerHTML = `<span>✓ เช็คอินวันนี้แล้ว (รับ +${todayReward} Coins) พรุ่งนี้กลับมาใหม่นะ!</span>`;
        } else {
            checkinBtn.disabled = false;
            checkinBtn.className = "w-full py-2.5 px-4 rounded-2xl bg-white hover:bg-amber-50 text-slate-900 font-extrabold text-xs shadow-md transition-all active:scale-95 flex items-center justify-center gap-2 cursor-pointer";
            checkinBtnText.innerHTML = `<i class="fa-solid fa-gift text-pink-600"></i> <span>กดรับเหรียญเช็คอินวันที่ ${cycleDay} (+${todayReward} Coins)</span>`;
        }
    }

    const historyList = document.getElementById('coins-history-list');
    if (historyList) {
        if (!isLoggedIn) {
            historyList.innerHTML = `
                <div class="p-3.5 text-center text-xs text-slate-600 bg-amber-50/70 rounded-2xl border border-amber-200 space-y-2">
                    <div class="flex items-center justify-center gap-1.5 font-bold text-amber-900">
                        <i class="fa-solid fa-gift text-pink-500"></i>
                        <span>โบนัสต้อนรับ 20 Pink Coins ฟรี!</span>
                    </div>
                    <p class="text-[11px] text-slate-500">สมัครสมาชิกใหม่วันนี้ รับ 20 Pink Coins ไปใช้ลดเงินสดในตะกร้าได้ทันที</p>
                    <button onclick="openAuthModal('register')" class="px-4 py-1.5 rounded-xl gradient-btn text-white font-bold text-xs shadow-xs cursor-pointer active:scale-95">
                        สมัครสมาชิกเพื่อรับเหรียญ
                    </button>
                </div>
            `;
        } else {
            const history = Array.isArray(user?.coinsHistory) ? [...user.coinsHistory].reverse() : [];
            if (history.length === 0) {
                historyList.innerHTML = `
                    <div class="p-4 text-center text-xs text-slate-500 bg-slate-50 rounded-2xl border border-slate-200">
                        <i class="fa-solid fa-coins text-amber-400 text-lg mb-1 block"></i>
                        <span>ยังไม่มีประวัติการทำรายการ Pink Coins</span>
                    </div>
                `;
            } else {
                historyList.innerHTML = history.slice(0, 30).map(item => {
                    const isEarn = (item.amount || 0) > 0;
                    const dateStr = item.date ? new Date(item.date).toLocaleString('th-TH', { dateStyle: 'short', timeStyle: 'short' }) : '';
                    return `
                        <div class="p-2.5 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between text-xs">
                            <div class="min-w-0 pr-2">
                                <div class="font-bold text-slate-800 truncate">${escapeHTML(item.description || 'รายการพ้อยท์')}</div>
                                <div class="text-[10px] text-slate-400 font-medium">${escapeHTML(dateStr)}</div>
                            </div>
                            <span class="font-black text-xs shrink-0 ${isEarn ? 'text-emerald-600' : 'text-rose-600'}">
                                ${isEarn ? '+' : ''}${item.amount} Coins
                            </span>
                        </div>
                    `;
                }).join('');
            }
        }
    }
}

async function handleDailyCheckIn() {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) {
        showToast('กรุณาเข้าสู่ระบบเพื่อเช็คอินรับเหรียญ Pink Coins', 'info');
        if (typeof openAuthModal === 'function') openAuthModal('login');
        return;
    }

    const user = USER_AUTH.getUser() || {};
    const todayStr = new Date().toISOString().slice(0, 10);
    const yesterdayStr = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

    if (user.lastCheckInDate === todayStr) {
        showToast('คุณได้เช็คอินรับเหรียญของวันนี้ไปแล้ว พรุ่งนี้กลับมาใหม่นะ!', 'info');
        return;
    }

    let newStreak = 1;
    if (user.lastCheckInDate === yesterdayStr) {
        newStreak = Number(user.checkInStreak || 0) + 1;
    }

    const cycleDay = ((newStreak - 1) % 7) + 1;
    const rewards = [1, 1, 2, 2, 3, 3, 10];
    const rewardAmount = rewards[cycleDay - 1];

    const currentCoins = Number(user.coins !== undefined ? user.coins : 20);
    const newCoins = currentCoins + rewardAmount;
    const history = Array.isArray(user.coinsHistory) ? [...user.coinsHistory] : [];
    history.push({
        amount: rewardAmount,
        description: `เช็คอินรายวัน วันที่ ${cycleDay} (สถิติ ${newStreak} วันติด)`,
        date: new Date().toISOString()
    });

    const updatedUser = {
        ...user,
        coins: newCoins,
        lastCheckInDate: todayStr,
        checkInStreak: newStreak,
        coinsHistory: history
    };

    try {
        localStorage.setItem('supinkly_user_info', JSON.stringify(updatedUser));
        sessionStorage.setItem('supinkly_user_info', JSON.stringify(updatedUser));
    } catch (e) {}

    state.user = updatedUser;

    if (typeof USER_AUTH.updateProfile === 'function') {
        USER_AUTH.updateProfile({
            coins: newCoins,
            lastCheckInDate: todayStr,
            checkInStreak: newStreak,
            coinsHistory: history
        }).catch(() => {});
    }

    renderCoinsPane();
    updateMemberBadges();
    renderNotificationCenter();
    updateNotificationBadge();

    showToast(`🎉 เช็คอินสำเร็จ! ได้รับ +${rewardAmount} Pink Coins (สถิติ ${newStreak} วันติด)`, 'success');
}

function renderReferralPane() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;
    const refCode = user?.referralCode || (user ? 'SPK-' + (user.id || user.userId || '').toString().slice(-6).toUpperCase() : '');
    const origin = window.location.origin;
    const pathname = window.location.pathname;
    const shareUrl = refCode ? `${origin}${pathname}?ref=${encodeURIComponent(refCode)}` : '';

    const codeInput = document.getElementById('referral-code-display');
    if (codeInput) {
        codeInput.value = refCode || (isLoggedIn ? 'กำลังโหลดรหัส...' : 'เข้าสู่ระบบเพื่อรับรหัสแนะนำ');
    }

    const linkInput = document.getElementById('referral-link-display');
    if (linkInput) {
        linkInput.value = shareUrl || (isLoggedIn ? 'กำลังโหลดลิงก์...' : 'เข้าสู่ระบบเพื่อสร้างลิงก์ชวนเพื่อน');
    }

    const friendsEl = document.getElementById('referral-stats-friends');
    if (friendsEl) friendsEl.textContent = (user?.referralCount || 0).toLocaleString();

    const coinsEl = document.getElementById('referral-stats-coins');
    if (coinsEl) coinsEl.textContent = (user?.referralEarnings || 0).toLocaleString();
}

function copyReferralCode() {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) {
        showToast("กรุณาเข้าสู่ระบบเพื่อรับรหัสแนะนำของคุณ", "info");
        openAuthModal('login');
        return;
    }
    const input = document.getElementById('referral-code-display');
    if (!input || !input.value || input.value.includes('เข้าสู่ระบบ')) {
        showToast("ไม่พบรหัสแนะนำ กรุณาลองใหม่อีกครั้ง", "warning");
        return;
    }
    copyToClipboard(input.value, "คัดลอกรหัสแนะนำเพื่อนเรียบร้อยแล้ว! เพื่อนใช้ลด 5%");
}

function copyReferralLink() {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) {
        showToast("กรุณาเข้าสู่ระบบเพื่อรับลิงก์แนะนำเพื่อนของคุณ", "info");
        openAuthModal('login');
        return;
    }
    const input = document.getElementById('referral-link-display');
    if (!input || !input.value || input.value.includes('เข้าสู่ระบบ')) {
        showToast("ไม่พบลิงก์แนะนำ กรุณาลองใหม่อีกครั้ง", "warning");
        return;
    }
    copyToClipboard(input.value, "คัดลอกลิงก์แนะนำเพื่อนเรียบร้อยแล้ว! ส่งให้เพื่อนได้เลย");
}

function renderWishlistPane() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const wishlist = getWishlistItems();

    const countEl = document.getElementById('wishlist-pane-count');
    if (countEl) countEl.textContent = wishlist.length;

    const grid = document.getElementById('wishlist-items-grid');
    if (!grid) return;

    if (wishlist.length === 0) {
        grid.innerHTML = `
            <div class="col-span-full py-12 text-center bg-slate-50/70 rounded-2xl border-2 border-dashed border-slate-200 p-6">
                <div class="w-14 h-14 mx-auto mb-2.5 rounded-2xl bg-rose-50 border border-rose-200 flex items-center justify-center text-rose-500 text-2xl shadow-inner">
                    <i class="fa-solid fa-heart"></i>
                </div>
                <h4 class="text-sm font-bold text-slate-800">ยังไม่มีสินค้าในรายการโปรด</h4>
                <p class="text-xs text-slate-500 mt-1 max-w-xs mx-auto">คลิกปุ่ม ❤️ ที่การ์ดสินค้าเพื่อบันทึกสินค้าที่คุณสนใจไว้ดูภายหลัง</p>
                <button onclick="closeOrdersModal(); scrollToProducts();" class="mt-3.5 px-4 py-2 rounded-xl gradient-btn text-white text-xs font-bold shadow-xs cursor-pointer active:scale-95">
                    เลือกดูสินค้าในร้าน
                </button>
            </div>
        `;
        return;
    }

    const guestNotice = !isLoggedIn ? `
        <div class="col-span-full p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs font-medium flex items-center justify-between gap-2">
            <div class="flex items-center gap-1.5 min-w-0">
                <i class="fa-solid fa-circle-info text-amber-500 shrink-0"></i>
                <span class="truncate">บันทึกในเครื่องนี้ • เข้าสู่ระบบเพื่อซิงค์ถาวรข้ามอุปกรณ์</span>
            </div>
            <button onclick="openAuthModal('login')" class="px-2.5 py-1 rounded-lg bg-white border border-amber-300 text-amber-800 font-bold text-[11px] hover:bg-amber-100 shrink-0 cursor-pointer">
                เข้าสู่ระบบ
            </button>
        </div>
    ` : '';

    const validCards = wishlist.map(pid => {
        const product = getMasterProduct(pid);
        if (!product) return '';
        const inStock = (product.stock || (state.inventory[pid] || []).length || 0) > 0;
        return `
            <div class="p-3 rounded-2xl bg-white border border-slate-200 shadow-2xs flex items-center justify-between gap-2.5">
                <div class="flex items-center gap-2.5 min-w-0">
                    <div class="w-10 h-10 rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center font-black text-xs text-pink-600 shrink-0">
                        ${escapeHTML(product.brandCode || 'AI')}
                    </div>
                    <div class="min-w-0">
                        <h5 class="text-xs font-normal text-slate-900 truncate">${escapeHTML(product.title)}</h5>
                        <div class="flex items-center gap-1.5 mt-0.5">
                            <span class="text-xs sm:text-sm font-black text-pink-600 font-['Outfit']">฿${formatProductPrice(product.price)}</span>
                            ${product.originalPrice > product.price ? `
                                <span class="text-[10px] text-slate-400 line-through font-medium">฿${formatProductPrice(product.originalPrice)}</span>
                            ` : ''}
                            <span class="text-[10px] font-bold ${inStock ? 'text-emerald-600' : 'text-rose-500'}">
                                ${inStock ? '🟢 มีของ' : '🔴 หมด'}
                            </span>
                        </div>
                    </div>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                    <button type="button" onclick="addToCart('${escapeHTML(product.id)}');" ${!inStock ? 'disabled' : ''}
                        class="px-2.5 py-1.5 rounded-xl gradient-btn text-white text-xs font-bold shadow-xs cursor-pointer ${!inStock ? 'opacity-40 cursor-not-allowed' : 'active:scale-95'}">
                        <i class="fa-solid fa-cart-plus mr-1"></i>ใส่ตะกร้า
                    </button>
                    <button type="button" onclick="toggleProductWishlist('${escapeHTML(product.id)}');" title="นำออกจากรายการโปรด"
                        class="w-8 h-8 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 flex items-center justify-center text-xs cursor-pointer transition-colors active:scale-90">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            </div>
        `;
    }).filter(Boolean);

    grid.innerHTML = guestNotice + validCards.join('');
}

function addAllWishlistToCart() {
    const wishlist = getWishlistItems();
    if (wishlist.length === 0) {
        showToast("ไม่มีสินค้าในรายการโปรด", "info");
        return;
    }
    let addedCount = 0;
    wishlist.forEach(pid => {
        const p = getMasterProduct(pid);
        if (p && (p.stock || (state.inventory[pid] || []).length || 0) > 0) {
            addToCart(pid);
            addedCount++;
        }
    });
    if (addedCount > 0) {
        showToast(`เพิ่มสินค้า ${addedCount} รายการลงตะกร้าแล้ว`, "success");
        closeOrdersModal();
        openCartDrawer();
    } else {
        showToast("สินค้าในรายการโปรดหมดสต็อกชั่วคราว", "warning");
    }
}

async function toggleProductWishlist(productId) {
    if (!productId) return;
    if (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
        const res = await USER_AUTH.toggleWishlist(productId);
        if (res.success) {
            const isAdded = res.action === 'added';
            showToast(isAdded ? "เพิ่มเข้ารายการโปรดแล้ว ❤️" : "นำออกจากรายการโปรดแล้ว", isAdded ? "success" : "info");
            state.user = USER_AUTH.getUser();
            updateMemberBadges();
            renderProducts();
            renderHighlightProducts();
            if (state.activeMemberTab === 'wishlist') renderWishlistPane();
        } else {
            showToast(res.message || "เกิดข้อผิดพลาด", "warning");
        }
    } else {
        let list = getLocalWishlist();
        const idx = list.indexOf(productId);
        if (idx >= 0) {
            list.splice(idx, 1);
            showToast("นำออกจากรายการโปรดแล้ว", "info");
        } else {
            list.push(productId);
            showToast("เพิ่มเข้ารายการโปรดแล้ว ❤️ (เข้าสู่ระบบเพื่อซิงค์ถาวร)", "success");
        }
        setLocalWishlist(list);
        updateMemberBadges();
        renderProducts();
        renderHighlightProducts();
        if (state.activeMemberTab === 'wishlist') renderWishlistPane();
    }
}

async function toggleProductStockAlert(productId) {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) {
        showToast("กรุณาเข้าสู่ระบบก่อนตั้งค่าแจ้งเตือนสต็อก", "info");
        openAuthModal('login');
        return;
    }
    const res = await USER_AUTH.toggleStockAlert(productId);
    if (res.success) {
        const isAdded = res.action === 'added';
        showToast(isAdded ? "ตั้งค่าแจ้งเตือนเมื่อสินค้าพร้อมจำหน่ายแล้ว 🔔" : "ยกเลิกการแจ้งเตือนแล้ว", isAdded ? "success" : "info");
        state.user = USER_AUTH.getUser();
        renderProducts();
    } else {
        showToast(res.message || "เกิดข้อผิดพลาด", "warning");
    }
}

function renderSettingsPane() {
    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;

    let guestNotice = document.getElementById('settings-guest-notice');
    if (!isLoggedIn) {
        if (!guestNotice) {
            guestNotice = document.createElement('div');
            guestNotice.id = 'settings-guest-notice';
            guestNotice.className = "p-4 rounded-2xl bg-gradient-to-r from-purple-50 to-pink-50 border-2 border-purple-200 text-xs text-slate-800 space-y-2.5 shadow-2xs";
            const pane = document.getElementById('member-pane-settings');
            if (pane) pane.insertBefore(guestNotice, pane.firstChild);
        }
        guestNotice.innerHTML = `
            <div class="flex items-center gap-2.5">
                <div class="w-9 h-9 rounded-xl bg-purple-500 text-white flex items-center justify-center text-sm font-bold shadow-xs shrink-0">
                    <i class="fa-solid fa-user-lock"></i>
                </div>
                <div>
                    <h6 class="font-bold text-slate-900 text-sm">คุณกำลังเข้าชมในฐานะผู้เยี่ยมชม (Guest)</h6>
                    <p class="text-[11px] text-slate-600 mt-0.5">เข้าสู่ระบบหรือสมัครสมาชิกเพื่อจัดการโปรไฟล์ เปลี่ยนรหัสผ่าน และเชื่อมต่อ LINE ID สำหรับรับคีย์ด่วน</p>
                </div>
            </div>
            <button onclick="openAuthModal('login')" class="w-full sm:w-auto px-4 py-2 rounded-xl gradient-btn text-white font-bold text-xs shadow-xs cursor-pointer active:scale-95">
                <i class="fa-solid fa-right-to-bracket mr-1"></i> เข้าสู่ระบบ / สมัครสมาชิก
            </button>
        `;
        guestNotice.classList.remove('hidden');
    } else if (guestNotice) {
        guestNotice.classList.add('hidden');
    }

    const emailEl = document.getElementById('settings-email');
    if (emailEl) emailEl.value = user?.email || (isLoggedIn ? '' : 'ยังไม่ได้เข้าสู่ระบบ');

    const nameEl = document.getElementById('settings-display-name');
    if (nameEl) nameEl.value = user?.displayName || user?.name || '';

    const phoneEl = document.getElementById('settings-phone');
    if (phoneEl) phoneEl.value = user?.phone || '';

    const lineEl = document.getElementById('settings-line-id');
    if (lineEl) lineEl.value = user?.lineId || '';

    const pStatus = document.getElementById('settings-profile-status');
    if (pStatus) pStatus.classList.add('hidden');

    const pwStatus = document.getElementById('settings-password-status');
    if (pwStatus) pwStatus.classList.add('hidden');
}

async function handleSaveProfileSettings() {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) {
        showToast("กรุณาเข้าสู่ระบบก่อนบันทึกข้อมูลโปรไฟล์", "warning");
        openAuthModal('login');
        return;
    }

    const nameEl = document.getElementById('settings-display-name');
    const phoneEl = document.getElementById('settings-phone');
    const lineEl = document.getElementById('settings-line-id');
    const statusEl = document.getElementById('settings-profile-status');

    const displayName = (nameEl ? nameEl.value : '').trim();
    const phone = (phoneEl ? phoneEl.value : '').trim();
    const lineId = (lineEl ? lineEl.value : '').trim();

    if (!displayName) {
        showToast("กรุณากรอกชื่อที่ต้องการแสดง", "warning");
        if (nameEl) nameEl.focus();
        return;
    }

    const res = await USER_AUTH.updateProfile({ displayName, phone, lineId });
    if (statusEl) {
        statusEl.classList.remove('hidden');
        if (res.success) {
            statusEl.className = "p-2.5 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-300";
            statusEl.textContent = "✓ บันทึกข้อมูลส่วนตัวเรียบร้อยแล้ว";
            state.user = USER_AUTH.getUser();
            updateUserHeaderUI();
            updateMemberBadges();
            showToast("บันทึกข้อมูลโปรไฟล์เรียบร้อยแล้ว", "success");
        } else {
            statusEl.className = "p-2.5 rounded-xl text-xs font-bold bg-rose-50 text-rose-800 border border-rose-300";
            statusEl.textContent = res.message || "เกิดข้อผิดพลาดในการบันทึก";
            showToast(res.message || "เกิดข้อผิดพลาด", "warning");
        }
    }
}

async function handleChangePasswordSettings() {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) {
        showToast("กรุณาเข้าสู่ระบบก่อนเปลี่ยนรหัสผ่าน", "warning");
        openAuthModal('login');
        return;
    }

    const oldPassEl = document.getElementById('settings-old-pass');
    const newPassEl = document.getElementById('settings-new-pass');
    const confPassEl = document.getElementById('settings-confirm-pass');
    const statusEl = document.getElementById('settings-password-status');

    const oldPassword = oldPassEl ? oldPassEl.value : '';
    const newPassword = newPassEl ? newPassEl.value : '';
    const confirmPassword = confPassEl ? confPassEl.value : '';

    if (!oldPassword || !newPassword) {
        showToast("กรุณากรอกรหัสผ่านปัจจุบันและรหัสผ่านใหม่", "warning");
        return;
    }
    if (newPassword.length < 6) {
        showToast("รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 6 ตัวอักษร", "warning");
        return;
    }
    if (newPassword !== confirmPassword) {
        showToast("รหัสผ่านใหม่ทั้งสองช่องไม่ตรงกัน", "warning");
        return;
    }

    const res = await USER_AUTH.changePassword(oldPassword, newPassword);
    if (statusEl) {
        statusEl.classList.remove('hidden');
        if (res.success) {
            statusEl.className = "p-2.5 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-300";
            statusEl.textContent = "✓ เปลี่ยนรหัสผ่านสำเร็จเรียบร้อยแล้ว";
            if (oldPassEl) oldPassEl.value = '';
            if (newPassEl) newPassEl.value = '';
            if (confPassEl) confPassEl.value = '';
            showToast("เปลี่ยนรหัสผ่านสำเร็จเรียบร้อยแล้ว", "success");
        } else {
            statusEl.className = "p-2.5 rounded-xl text-xs font-bold bg-rose-50 text-rose-800 border border-rose-300";
            statusEl.textContent = res.message || "รหัสผ่านเดิมไม่ถูกต้อง";
            showToast(res.message || "เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน", "warning");
        }
    }
}

function applyMaxCoins() {
    const user = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
    if (!user || !user.coins || user.coins <= 0) {
        showToast("คุณยังไม่มี Pink Coins สะสม", "info");
        return;
    }
    const verifiedSubtotal = calculateVerifiedTotal();
    let couponDiscount = 0;
    if (state.appliedCoupon && typeof validateCouponCode === 'function') {
        const recheck = validateCouponCode(state.appliedCoupon.code, verifiedSubtotal);
        if (recheck.valid) couponDiscount = recheck.discountAmount || 0;
    }
    const afterCoupon = Math.max(0, verifiedSubtotal - couponDiscount);
    let vipDiscount = 0;
    if (user && user.vip && user.vip.discountPercent > 0) {
        vipDiscount = Math.round((afterCoupon * user.vip.discountPercent / 100) * 100) / 100;
    }
    const afterVip = Math.max(0, afterCoupon - vipDiscount);
    let refDiscount = 0;
    if (state.referralDiscount) {
        refDiscount = Math.round((afterVip * 0.05) * 100) / 100;
    }
    const netBeforeCoins = Math.max(1, afterVip - refDiscount);
    const maxCoinsAllowed = Math.min(user.coins, Math.floor(netBeforeCoins - 1));
    state.coinsToRedeem = Math.max(0, maxCoinsAllowed);
    const input = document.getElementById('cart-coins-input');
    if (input) input.value = state.coinsToRedeem;
    updateCartUI();
    showToast(`ใช้ Pink Coins สูงสุด ${state.coinsToRedeem} เหรียญ`, "info");
}

function clearCoins() {
    state.coinsToRedeem = 0;
    const input = document.getElementById('cart-coins-input');
    if (input) input.value = '';
    updateCartUI();
}

function handleCoinsInputChange(val) {
    const num = parseInt(val, 10) || 0;
    const user = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
    const userCoins = (user && typeof user.coins === 'number') ? user.coins : 0;
    const errEl = document.getElementById('cart-coins-error');
    if (num > userCoins) {
        if (errEl) {
            errEl.textContent = `คุณมี Pink Coins เพียง ${userCoins} เหรียญ`;
            errEl.classList.remove('hidden');
        }
        state.coinsToRedeem = userCoins;
    } else {
        if (errEl) errEl.classList.add('hidden');
        state.coinsToRedeem = Math.max(0, num);
    }
    updateCartUI();
}

async function applyReferralCode(codeToApply) {
    const input = document.getElementById('cart-referral-input');
    const code = (codeToApply || (input ? input.value : '') || '').trim().toUpperCase();
    if (!code) {
        showToast("กรุณากรอกรหัสแนะนำเพื่อน", "warning");
        return;
    }
    const res = await USER_AUTH.validateReferral(code);
    if (res.success && res.referral) {
        state.referralCode = code;
        state.referralDiscount = res.referral;
        showToast(`ใช้รหัสแนะนำของ ${res.referral.referrerName || 'เพื่อน'} สำเร็จ! รับส่วนลด 5%`, "success");
        if (input) input.value = '';
        updateCartUI();
    } else {
        showToast(res.message || "รหัสแนะนำไม่ถูกต้องหรือไม่สามารถใช้กับบัญชีของคุณได้", "warning");
    }
}

function removeReferralCode() {
    state.referralCode = null;
    state.referralDiscount = null;
    showToast("ยกเลิกการใช้รหัสแนะนำเพื่อนแล้ว", "info");
    updateCartUI();
}

// ==========================================
// SECURED ADMIN PANEL (SESSION & PIN AUTHENTICATED)
// ==========================================
function openAdminModal() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }
    const modal = document.getElementById('admin-modal');
    if (!modal) return;
    modal.classList.remove('hidden');
    updateAdminNavBadges();
    renderAdminOrdersList();
    renderAdminStockList();
    renderAdminUsersList();
    loadAdminSettingsIntoForm();
}

function closeAdminModal() {
    const modal = document.getElementById('admin-modal');
    if (modal) modal.classList.add('hidden');
}

function handleAdminLogout() {
    ADMIN_AUTH.logout();
    closeAdminModal();
    showToast("ออกจากระบบผู้ดูแลเรียบร้อยแล้ว", "info");
}

function promptAdminLogin() {
    if (ADMIN_AUTH.checkSession()) {
        openAdminModal();
        return;
    }

    const pinModal = document.getElementById('admin-pin-modal');
    if (pinModal) {
        const pinInput = document.getElementById('admin-pin-input');
        if (pinInput) {
            pinInput.value = '';
            pinInput.type = 'password';
        }
        const eyeIcon = document.getElementById('admin-pin-eye-icon');
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye-slash');
            eyeIcon.classList.add('fa-eye');
        }
        pinModal.classList.remove('hidden');
        setTimeout(() => pinInput?.focus(), 80);
    }
}

function closeAdminPinModal() {
    const pinModal = document.getElementById('admin-pin-modal');
    if (pinModal) pinModal.classList.add('hidden');
}

async function handleResetAdminPinToDefault() {
    ADMIN_AUTH.resetToDefault();
    try {
        const res = await fetch('/api/admin/reset-pin', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({ masterPin: '8899' })
        });
        const data = await res.json();
        if (data && data.success && data.token) {
            sessionStorage.setItem('supinkly_admin_server_token', data.token);
            localStorage.setItem('supinkly_admin_server_token', data.token);
            sessionStorage.setItem('supinkly_admin_pin', '8899');
            localStorage.setItem('supinkly_admin_pin', '8899');
        }
    } catch (e) {
        console.warn("Backend reset pin warning:", e);
    }

    const pinInput = document.getElementById('admin-pin-input');
    if (pinInput) {
        pinInput.value = '';
        pinInput.type = 'password';
        pinInput.placeholder = 'กรอกรหัส PIN (เริ่มต้น: 8899)';
    }
    const eyeIcon = document.getElementById('admin-pin-eye-icon');
    if (eyeIcon) {
        eyeIcon.classList.remove('fa-eye-slash');
        eyeIcon.classList.add('fa-eye');
    }
    showToast("รีเซ็ตรหัส PIN ผู้ดูแลกลับค่าเริ่มต้น (8899) และล้างประวัติการล็อกเรียบร้อยแล้ว", "success");
}

function toggleAdminPinVisibility() {
    const pinInput = document.getElementById('admin-pin-input');
    const eyeIcon = document.getElementById('admin-pin-eye-icon');
    if (!pinInput) return;
    if (pinInput.type === 'password') {
        pinInput.type = 'text';
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye');
            eyeIcon.classList.add('fa-eye-slash');
        }
    } else {
        pinInput.type = 'password';
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye-slash');
            eyeIcon.classList.add('fa-eye');
        }
    }
}

function toggleAdminNewPinVisibility() {
    const pinInput = document.getElementById('admin-new-pin');
    const eyeIcon = document.getElementById('admin-new-pin-eye-icon');
    if (!pinInput) return;
    if (pinInput.type === 'password') {
        pinInput.type = 'text';
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye');
            eyeIcon.classList.add('fa-eye-slash');
        }
    } else {
        pinInput.type = 'password';
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye-slash');
            eyeIcon.classList.add('fa-eye');
        }
    }
}

function toggleAdminConfirmPinVisibility() {
    const pinInput = document.getElementById('admin-confirm-new-pin');
    const eyeIcon = document.getElementById('admin-confirm-pin-eye-icon');
    if (!pinInput) return;
    if (pinInput.type === 'password') {
        pinInput.type = 'text';
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye');
            eyeIcon.classList.add('fa-eye-slash');
        }
    } else {
        pinInput.type = 'password';
        if (eyeIcon) {
            eyeIcon.classList.remove('fa-eye-slash');
            eyeIcon.classList.add('fa-eye');
        }
    }
}

async function handleAdminPinSubmit(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const pinInput = document.getElementById('admin-pin-input');
    const pin = (pinInput ? pinInput.value : '').trim();
    const submitBtn = document.getElementById('admin-pin-submit-btn');

    if (!pin) {
        showToast("กรุณากรอกรหัส PIN ของผู้ดูแลระบบ", "warning");
        return;
    }

    if (submitBtn) submitBtn.disabled = true;

    try {
        await ADMIN_AUTH.verify(pin);
        closeAdminPinModal();
        openAdminModal();
        showToast("เข้าสู่ระบบแอดมินสำเร็จ (เซสชันปลอดภัย 15 นาที)", "success");
    } catch (err) {
        showToast(err.message || "รหัส PIN แอดมินไม่ถูกต้อง", "warning");
        if (pinInput) {
            pinInput.focus();
        }
    } finally {
        if (submitBtn) submitBtn.disabled = false;
    }
}

// ==========================================
// G2G MARKET LINK HELPER (ADMIN ONLY)
// ==========================================
function getG2GMarketLink(productId) {
    const master = (typeof getMasterProduct === 'function') ? getMasterProduct(productId) : null;

    // 1. If admin provided a specific custom URL (and it's not a legacy broken format)
    if (master && master.g2gUrl && typeof isBrokenOrLegacyG2GUrl === 'function' && !isBrokenOrLegacyG2GUrl(master.g2gUrl)) {
        return master.g2gUrl;
    }

    // 2. Check market benchmark
    const benchmark = (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks) ? G2G_MARKET_FEED.benchmarks[productId] : null;
    if (benchmark && benchmark.g2gUrl && typeof isBrokenOrLegacyG2GUrl === 'function' && !isBrokenOrLegacyG2GUrl(benchmark.g2gUrl)) {
        return benchmark.g2gUrl;
    }

    // 3. CapCut category direct on G2G
    const brand = ((master && master.brand) || '').toLowerCase();
    const id = String(productId || '').toLowerCase();
    if (id.startsWith('cpc-') || brand.includes('capcut')) {
        return 'https://www.g2g.com/categories/capcut';
    }

    // 4. Reliable Google site-search for live G2G listings (100% working, never 404)
    const query = (master && (master.g2gRawTitle || master.title)) || (benchmark && benchmark.title) || (master && `${master.brand} ${master.type}`) || 'G2G marketplace';
    return `https://www.google.com/search?q=${encodeURIComponent('site:g2g.com ' + query)}`;
}

function handleG2GSourcingClick(event, productId, targetUrl) {
    if (event) {
        event.stopPropagation();
    }
    const master = (typeof getMasterProduct === 'function') ? getMasterProduct(productId) : null;
    const searchKeyword = (master && (master.g2gRawTitle || master.title)) || '';

    // Copy product search keyword to clipboard so admin can easily paste into G2G if needed
    if (searchKeyword && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(searchKeyword).catch(() => { });
    }

    const effectiveUrl = targetUrl || getG2GMarketLink(productId);
    const shortTitle = searchKeyword ? ` ("${searchKeyword.slice(0, 24)}...")` : '';
    showToast(`กำลังเปิดหน้ารายการสินค้า G2G${shortTitle} (คัดลอกคำค้นหาแล้ว)`, 'info');

    // If anchor href is missing or invalid, trigger window.open
    if (!targetUrl || targetUrl === '#' || targetUrl === 'about:blank#blocked') {
        if (event) event.preventDefault();
        openG2GMarketLink(productId);
    }
}

function openG2GMarketLink(productId) {
    const link = getG2GMarketLink(productId);
    const master = (typeof getMasterProduct === 'function') ? getMasterProduct(productId) : null;
    const titleToCopy = (master && (master.g2gRawTitle || master.title)) || '';
    if (titleToCopy && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(titleToCopy).catch(() => { });
    }
    if (link && link !== '#' && link !== 'about:blank#blocked') {
        const win = window.open(link, '_blank', 'noopener,noreferrer');
        if (!win || win.closed || typeof win.closed === 'undefined') {
            const a = document.createElement('a');
            a.href = link;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
    }
}

// ==========================================
// ADMIN TABS & ON-DEMAND FULFILLMENT
// ==========================================
let currentAdminOrderFilter = 'all';
let adminOrderSearchQuery = '';
let adminStockSearchQuery = '';
let adminStockBrandFilter = 'all';

// ── Admin Orders State & Remote Sync Helpers ─────────────────────────
let adminOrdersList = [];
let adminOrdersLastFetch = 0;
let adminOrdersPollTimer = null;

function isOrderDelivered(order) {
    if (!order) return false;
    const isStatusDelivered = typeof order.status === 'string' && (order.status.includes('จัดส่งสำเร็จ') || order.status.includes('delivered'));
    const isItemsDelivered = Array.isArray(order.items) && order.items.length > 0 && order.items.every(it => {
        // [FIX] ตรวจสอบเฉพาะ credentials จริง (email/key/link) ไม่รวม instructions เพียงอย่างเดียว
        const hasCred = it.credentials && (it.credentials.email || it.credentials.key || it.credentials.link);
        return (it.status === 'delivered' || hasCred) && it.status !== 'pending_fulfillment';
    });
    return isStatusDelivered || isItemsDelivered;
}

function isOrderPending(order) {
    if (!order) return false;
    return !isOrderDelivered(order);
}

function getAdminOrders() {
    return (Array.isArray(adminOrdersList) && adminOrdersList.length > 0) ? adminOrdersList : (state.orders || []);
}

// Fetch all orders from backend server (/api/admin/orders)
async function fetchAdminOrders(forceRefresh = false) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        return state.orders || [];
    }

    const now = Date.now();
    if (!forceRefresh && (now - adminOrdersLastFetch < 2500) && adminOrdersList.length > 0) {
        return adminOrdersList;
    }

    try {
        const res = await fetch('/api/admin/orders', {
            method: 'GET',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success && Array.isArray(data.orders)) {
                adminOrdersList = data.orders;
                adminOrdersLastFetch = now;

                // Merge server orders into state.orders so vault & history also stay updated
                const orderMap = new Map();
                adminOrdersList.forEach(o => { if (o && o.orderId) orderMap.set(o.orderId, o); });
                (state.orders || []).forEach(o => {
                    if (o && o.orderId && !orderMap.has(o.orderId)) {
                        orderMap.set(o.orderId, o);
                    }
                });
                state.orders = Array.from(orderMap.values()).sort((a, b) => {
                    const timeA = new Date(a.date || 0).getTime() || 0;
                    const timeB = new Date(b.date || 0).getTime() || 0;
                    return timeB - timeA;
                });

                updateAdminNavBadges();
                return adminOrdersList;
            }
        }
    } catch (e) {
        console.warn("[ADMIN] Could not fetch orders from server:", e);
    }

    adminOrdersList = state.orders || [];
    return adminOrdersList;
}

function startAdminOrdersAutoRefresh() {
    stopAdminOrdersAutoRefresh();
    adminOrdersPollTimer = setInterval(async () => {
        const modal = document.getElementById('admin-modal');
        if (!modal || modal.classList.contains('hidden')) {
            stopAdminOrdersAutoRefresh();
            return;
        }

        const prevPending = (getAdminOrders()).filter(isOrderPending).length;

        await fetchAdminOrders(true);

        const currentOrders = getAdminOrders();
        const newPending = currentOrders.filter(isOrderPending).length;

        if (newPending > prevPending) {
            showToast(`🔔 มีคำสั่งซื้อใหม่เข้ามาในระบบ! (${newPending} รอส่งมอบ)`, "info");
            playNotificationSound();
        }

        const ordersTab = document.getElementById('admin-tab-orders');
        if (ordersTab && !ordersTab.classList.contains('hidden')) {
            renderAdminOrdersList(false);
        }
    }, 15000);
}

function stopAdminOrdersAutoRefresh() {
    if (adminOrdersPollTimer) {
        clearInterval(adminOrdersPollTimer);
        adminOrdersPollTimer = null;
    }
}

function playNotificationSound() {
    try {
        if (typeof window !== 'undefined' && (window.AudioContext || window.webkitAudioContext)) {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(587.33, ctx.currentTime);
            osc.frequency.setValueAtTime(880, ctx.currentTime + 0.08);
            gain.gain.setValueAtTime(0.12, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.3);
        }
    } catch (e) { }
}

// Helper: Get authenticated headers for Admin API requests
function getAdminHeaders() {
    const token = sessionStorage.getItem('supinkly_admin_server_token') || localStorage.getItem('supinkly_admin_server_token');
    const pin = sessionStorage.getItem('supinkly_admin_pin') || localStorage.getItem('supinkly_admin_pin') || '';
    const headers = {
        'Content-Type': 'application/json'
    };
    if (pin) headers['x-admin-pin'] = pin;
    if (token) {
        headers['x-admin-token'] = token;
        headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
}

// Update Admin Nav Badges (Pending orders, coupons, users & KPI stat cards)
function updateAdminNavBadges() {
    const orders = getAdminOrders();
    const pendingCount = orders.filter(isOrderPending).length;
    const deliveredCount = orders.filter(isOrderDelivered).length;
    const totalSales = orders.reduce((sum, o) => sum + (o.totalAmount || 0), 0);

    const salesEl = document.getElementById('admin-stat-sales');
    if (salesEl) salesEl.textContent = `฿${totalSales.toLocaleString('th-TH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

    const pendingEl = document.getElementById('admin-stat-pending');
    if (pendingEl) pendingEl.textContent = `${pendingCount} ออเดอร์`;

    const deliveredEl = document.getElementById('admin-stat-delivered');
    if (deliveredEl) deliveredEl.textContent = `${deliveredCount} รายการ`;

    const totalOrdersEl = document.getElementById('admin-stat-total-orders');
    if (totalOrdersEl) totalOrdersEl.textContent = `${orders.length} รายการ`;

    const ordersBadge = document.getElementById('admin-orders-count-badge') || document.getElementById('admin-pending-badge');
    if (ordersBadge) {
        ordersBadge.textContent = pendingCount;
        ordersBadge.className = pendingCount > 0
            ? "px-2 py-0.5 rounded-full bg-amber-400 text-slate-900 text-xs font-black animate-pulse"
            : "px-2 py-0.5 rounded-full bg-slate-200 text-slate-700 text-xs font-bold";
    }

    try {
        const promos = typeof getStorePromotions === 'function' ? getStorePromotions() : [];
        const activeCouponsCount = promos.filter(p => p.active !== false).length;
        const couponBadge = document.getElementById('admin-coupons-badge');
        if (couponBadge) couponBadge.textContent = activeCouponsCount;
    } catch (e) { }

    try {
        const usersBadge = document.getElementById('admin-users-badge');
        if (usersBadge && Array.isArray(adminUsersList) && adminUsersList.length > 0) {
            usersBadge.textContent = adminUsersList.length;
        }
    } catch (e) { }
}

// Quick navigation from admin top stat cards
function quickAdminNavigate(tab, subFilter = null) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }

    // Remove active ring from all KPI cards
    const kpiCards = ['sales', 'pending', 'delivered', 'all', 'online'];
    kpiCards.forEach(id => {
        const el = document.getElementById(`admin-kpi-${id}`);
        if (el) {
            el.classList.remove('ring-2', 'ring-pink-500', 'ring-offset-2');
        }
    });

    if (tab === 'analytics') {
        const el = document.getElementById('admin-kpi-sales') || document.getElementById('admin-kpi-online');
        if (el) el.classList.add('ring-2', 'ring-pink-500', 'ring-offset-2');
        if (typeof switchAdminTab === 'function') switchAdminTab('analytics');
        showToast("📊 เปิดหน้ารายงานยอดขายและสถิติสดแบบ Real-time", "info");
        return;
    }

    if (typeof switchAdminTab === 'function') {
        switchAdminTab(tab);
    }

    if (tab === 'orders') {
        const filterKey = subFilter || 'all';
        const cardId = filterKey === 'pending' ? 'pending' : (filterKey === 'delivered' ? 'delivered' : 'all');
        const activeCard = document.getElementById(`admin-kpi-${cardId}`);
        if (activeCard) {
            activeCard.classList.add('ring-2', 'ring-pink-500', 'ring-offset-2');
        }

        if (typeof filterAdminOrders === 'function') {
            filterAdminOrders(filterKey);
        }

        // Calculate count feedback
        const allAdminOrders = getAdminOrders();
        const total = allAdminOrders.length;
        const pending = allAdminOrders.filter(isOrderPending).length;
        const delivered = allAdminOrders.filter(isOrderDelivered).length;

        let msg = "";
        if (filterKey === 'pending') {
            msg = pending > 0
                ? `⚡ กรองออเดอร์: รอส่งมอบรหัส (${pending} รายการ)`
                : `⚡ ขณะนี้ยังไม่มีออเดอร์ที่รอส่งมอบรหัส (0 รายการ)`;
        } else if (filterKey === 'delivered') {
            msg = delivered > 0
                ? `✅ กรองออเดอร์: ส่งมอบสำเร็จ (${delivered} รายการ)`
                : `✅ ขณะนี้ยังไม่มีออเดอร์ที่ส่งมอบสำเร็จ (0 รายการ)`;
        } else {
            msg = total > 0
                ? `📦 แสดงออเดอร์ทั้งหมด (${total} รายการ)`
                : `📦 ขณะนี้ยังไม่มีรายการคำสั่งซื้อในระบบ (0 รายการ)`;
        }
        showToast(msg, "info");

        // Smooth scroll to the orders list so the admin immediately sees the table
        const listEl = document.getElementById('admin-orders-list');
        if (listEl) {
            listEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }
}

// Create a realistic demo order for testing fulfillment and slip verification
async function createDemoOrder() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }

    try {
        const res = await fetch('/api/admin/orders/demo', {
            method: 'POST',
            headers: getAdminHeaders()
        });
        const data = await res.json();
        if (data && data.success && data.order) {
            const demoOrder = data.order;
            if (!Array.isArray(adminOrdersList)) adminOrdersList = [];
            adminOrdersList.unshift(demoOrder);
            if (!Array.isArray(state.orders)) state.orders = [];
            state.orders.unshift(demoOrder);
            saveOrders();
            renderAdminOrdersList();
            updateAdminNavBadges();
            if (typeof filterAdminOrders === 'function') filterAdminOrders('all');
            showToast(`🎉 สร้างออเดอร์ทดสอบ ${demoOrder.orderId} ในเซิร์ฟเวอร์สำเร็จ!`, "success");
            const listEl = document.getElementById('admin-orders-list');
            if (listEl) listEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
            return;
        }
    } catch (e) {
        console.warn("[DEMO] Server demo creation failed, using local fallback:", e);
    }

    const demoOrderId = "SPK-DEMO" + Math.floor(1000 + Math.random() * 9000);
    const demoItems = [
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
    ];

    const demoOrder = {
        orderId: demoOrderId,
        date: new Date().toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }),
        totalAmount: 129.00,
        paymentMethod: "Thai QR PromptPay (ทดสอบ)",
        recipientEmail: "demo.customer@gmail.com",
        transRef: "DEMO_" + Date.now().toString(36).toUpperCase(),
        slipFingerprint: "demo_slip_" + Math.random().toString(36).substring(2, 8),
        slipDataUrl: `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="360" height="460" viewBox="0 0 360 460"><rect width="100%" height="100%" fill="%23f8fafc"/><rect x="16" y="16" width="328" height="428" rx="20" fill="white" stroke="%23e2e8f0" stroke-width="2"/><circle cx="180" cy="70" r="28" fill="%23ec4899"/><path d="M168 70 l8 8 l16 -16" fill="none" stroke="white" stroke-width="4" stroke-linecap="round"/><text x="180" y="125" text-anchor="middle" font-family="sans-serif" font-weight="bold" font-size="16" fill="%230f172a">ชำระเงินสำเร็จ (สลิปจำลอง)</text><text x="180" y="145" text-anchor="middle" font-family="sans-serif" font-size="12" fill="%2364748b">PromptPay QR Verification</text><line x1="40" y1="165" x2="320" y2="165" stroke="%23e2e8f0" stroke-dasharray="4 4"/><text x="40" y="200" font-family="sans-serif" font-size="12" fill="%2364748b">จำนวนเงิน</text><text x="320" y="200" text-anchor="end" font-family="sans-serif" font-weight="bold" font-size="20" fill="%23db2777">฿129.00</text><text x="40" y="240" font-family="sans-serif" font-size="12" fill="%2364748b">ผู้โอน</text><text x="320" y="240" text-anchor="end" font-family="sans-serif" font-size="12" font-weight="bold" fill="%23334155">นายลูกค้า ทดสอบ (Demo)</text><text x="40" y="275" font-family="sans-serif" font-size="12" fill="%2364748b">ผู้รับเงิน</text><text x="320" y="275" text-anchor="end" font-family="sans-serif" font-size="12" font-weight="bold" fill="%23334155">Supinkly.AI Store</text><text x="40" y="310" font-family="sans-serif" font-size="12" fill="%2364748b">รหัสอ้างอิง</text><text x="320" y="310" text-anchor="end" font-family="monospace" font-size="11" fill="%23475569">${demoOrderId}</text><rect x="40" y="340" width="280" height="70" rx="12" fill="%23fdf2f8" stroke="%23fbcfe8"/><text x="180" y="370" text-anchor="middle" font-family="sans-serif" font-weight="bold" font-size="12" fill="%23be185d">ตรวจสอบสลิปอัตโนมัติผ่านแล้ว</text><text x="180" y="392" text-anchor="middle" font-family="sans-serif" font-size="11" fill="%23db2777">SlipOK / PromptPay Hash Verified</text></svg>`,
        items: demoItems,
        status: "🟡 รอส่งมอบ (On-Demand)",
        isDemo: true
    };

    if (!Array.isArray(adminOrdersList)) adminOrdersList = [];
    adminOrdersList.unshift(demoOrder);
    if (!Array.isArray(state.orders)) state.orders = [];
    state.orders.unshift(demoOrder);
    saveOrders();
    renderAdminOrdersList();
    updateAdminNavBadges();

    if (typeof filterAdminOrders === 'function') {
        filterAdminOrders('all');
    }

    showToast(`🎉 สร้างออเดอร์ทดสอบ ${demoOrderId} (+฿129.00) สำเร็จ!`, "success");

    const listEl = document.getElementById('admin-orders-list');
    if (listEl) {
        listEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ==========================================
// CLIENT TELEMETRY & LIVE TRAFFIC TRACKER
// ==========================================
const TELEMETRY = {
    sessionId: null,
    heartbeatInterval: null,

    init() {
        try {
            let sid = sessionStorage.getItem('supinkly_telemetry_sid');
            if (!sid || sid.length < 10) {
                sid = 'sid_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
                sessionStorage.setItem('supinkly_telemetry_sid', sid);
            }
            this.sessionId = sid;

            // Track initial page view
            this.send('page_view', { page: document.title || 'หน้าแรก' });

            // Periodic heartbeat every 20s
            if (!this.heartbeatInterval) {
                this.heartbeatInterval = setInterval(() => {
                    this.send('heartbeat');
                }, 20000);
            }
        } catch (e) {
            console.warn("Telemetry init skipped:", e);
        }
    },

    async send(action, extra = {}) {
        if (!this.sessionId) {
            this.init();
            if (!this.sessionId) return;
        }

        try {
            const userToken = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getToken() : null;
            const headers = { 'Content-Type': 'application/json' };
            if (userToken) headers['x-user-token'] = userToken;

            const cartCount = (state.cart || []).reduce((s, it) => s + (it.quantity || 1), 0);
            const cartTotal = (state.cart || []).reduce((s, it) => {
                const prod = getMasterProduct(it.productId);
                return s + ((prod ? prod.price : 0) * (it.quantity || 1));
            }, 0);

            const payload = {
                sessionId: this.sessionId,
                action: action || 'heartbeat',
                page: extra.page || (location.hash ? location.hash : 'หน้าแรก'),
                productId: extra.productId || null,
                productTitle: extra.productTitle || null,
                cartCount,
                cartTotal,
                timestamp: Date.now()
            };

            await fetch('/api/telemetry/heartbeat', {
                method: 'POST',
                headers,
                body: JSON.stringify(payload)
            });
        } catch (e) {
            // Silently ignore telemetry failure in offline mode
        }
    }
};

function sendTelemetryHeartbeat(action, extra) {
    if (typeof TELEMETRY !== 'undefined' && typeof TELEMETRY.send === 'function') {
        TELEMETRY.send(action, extra);
    }
}

// Switch between the 6 Admin Tabs
function switchAdminTab(tabName) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        showToast("กรุณาเข้าสู่ระบบหลังร้านก่อนดำเนินการ", "warning");
        promptAdminLogin();
        return;
    }

    const tabs = ['orders', 'stock', 'coupons', 'users', 'analytics', 'settings'];
    tabs.forEach(t => {
        const btn = document.getElementById(`admin-tab-btn-${t}`);
        const panel = document.getElementById(`admin-tab-${t}`);
        if (t === tabName) {
            if (btn) {
                btn.className = "px-4 py-2.5 rounded-xl text-xs sm:text-sm font-bold bg-pink-500 text-white flex items-center gap-2 shadow-sm transition-all shrink-0 cursor-pointer";
            }
            if (panel) panel.classList.remove('hidden');
        } else {
            if (btn) {
                btn.className = "px-4 py-2.5 rounded-xl text-xs sm:text-sm font-bold text-slate-600 hover:text-slate-900 hover:bg-white/80 flex items-center gap-2 transition-all shrink-0 cursor-pointer";
            }
            if (panel) panel.classList.add('hidden');
        }
    });

    updateAdminNavBadges();

    if (tabName === 'orders') renderAdminOrdersList();
    if (tabName === 'stock') renderAdminStockList();
    if (tabName === 'coupons') renderAdminCouponsList();
    if (tabName === 'users') renderAdminUsersList();
    if (tabName === 'analytics') {
        fetchAdminAnalytics(true);
        startAdminAnalyticsAutoRefresh();
    } else {
        stopAdminAnalyticsAutoRefresh();
    }
}

// ==========================================
// REAL-TIME ANALYTICS & VISITOR TELEMETRY (ADMIN)
// ==========================================
let adminAnalyticsData = null;
let adminAnalyticsFilter = 'all';
let adminAnalyticsTimer = null;

async function fetchAdminAnalytics(isManual = false) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;

    const refreshIcon = document.getElementById('analytics-refresh-icon');
    if (isManual && refreshIcon) {
        refreshIcon.classList.add('fa-spin');
    }

    try {
        const res = await fetch('/api/admin/analytics', {
            method: 'GET',
            headers: getAdminHeaders()
        });

        if (res.ok) {
            const data = await res.json();
            if (data && data.success) {
                adminAnalyticsData = data;
                renderAdminAnalytics(data);
                if (isManual) showToast("อัปเดตสถิติสดแบบเรียลไทม์แล้ว", "success");
                return;
            }
        }
        // Fallback to local calculation if server responded with non-ok or error
        renderFallbackAdminAnalytics();
    } catch (e) {
        // Fallback for standalone / offline preview
        renderFallbackAdminAnalytics();
    } finally {
        if (refreshIcon) {
            setTimeout(() => refreshIcon.classList.remove('fa-spin'), 600);
        }
    }
}

function renderAdminAnalytics(data) {
    if (!data) return;
    const live = data.live || {};
    const today = data.today || {};

    // 1. Online Active Now
    const activeNowEl = document.getElementById('analytics-active-now');
    if (activeNowEl) activeNowEl.textContent = live.onlineTotal ?? 1;

    const activeNowSubEl = document.getElementById('analytics-active-now-sub');
    if (activeNowSubEl) {
        activeNowSubEl.textContent = `${live.onlineMembersCount || 0} สมาชิก / ${live.onlineGuestsCount || (live.onlineTotal || 1)} ทั่วไป`;
    }

    // Also update Admin Header Top KPI Card 5 (Online Live)
    const adminStatOnlineNow = document.getElementById('admin-stat-online-now');
    if (adminStatOnlineNow) adminStatOnlineNow.textContent = `${live.onlineTotal ?? 1} คน`;

    const adminOnlineBadge = document.getElementById('admin-online-badge');
    if (adminOnlineBadge) adminOnlineBadge.textContent = `${live.onlineTotal ?? 1} คน`;

    const adminStatOnlineSub = document.getElementById('admin-stat-online-sub');
    if (adminStatOnlineSub) {
        adminStatOnlineSub.textContent = `${live.onlineMembersCount || 0} สมาชิก / ${live.onlineGuestsCount || (live.onlineTotal || 1)} ทั่วไป`;
    }

    // 2. Daily Visitors & Pageviews
    const dailyVisitorsEl = document.getElementById('analytics-daily-visitors');
    if (dailyVisitorsEl) dailyVisitorsEl.textContent = today.uniqueVisitors ?? 1;

    const pvBadge = document.getElementById('analytics-pageviews-badge');
    if (pvBadge) pvBadge.textContent = `${today.pageViews ?? 1} วิว`;

    const pvText = document.getElementById('analytics-pageviews-text');
    if (pvText) pvText.textContent = `เปิดชมรวม ${(today.pageViews ?? 1).toLocaleString()} หน้าวันนี้`;

    // 3. Product Browsing & Cart Adds
    const prodViewsEl = document.getElementById('analytics-product-views');
    if (prodViewsEl) prodViewsEl.textContent = (today.productViewsTotal ?? 0).toLocaleString();

    const cartAddsText = document.getElementById('analytics-cart-adds-text');
    if (cartAddsText) cartAddsText.textContent = `หยิบลงตะกร้า ${(today.cartAddsTotal ?? 0).toLocaleString()} ครั้งวันนี้`;

    // 4. Conversion & Revenue
    const convRateEl = document.getElementById('analytics-conversion-rate');
    if (convRateEl) convRateEl.textContent = `${today.conversionRate || '0.0%'} ซื้อ`;

    const todayRevEl = document.getElementById('analytics-today-revenue');
    if (todayRevEl) {
        todayRevEl.textContent = `฿${(today.revenue || 0).toLocaleString('th-TH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }

    const ordersCountText = document.getElementById('analytics-orders-count-text');
    if (ordersCountText) {
        ordersCountText.textContent = `สั่งซื้อสำเร็จ ${today.ordersCount || 0} ออเดอร์`;
    }

    // Sync Timestamp
    const syncLabel = document.getElementById('analytics-last-sync-label');
    if (syncLabel) {
        syncLabel.textContent = `อัปเดตสด: ${new Date().toLocaleTimeString('th-TH')} (รีเฟรชทุก 5 วิ)`;
    }

    // Render User Directory
    renderActiveUsersList(live.activeUsers || []);

    // Render Top Products
    renderTopProductsList(today.topProducts || []);

    // Render Recent Events
    renderRecentEventsList(today.recentEvents || []);
}

function renderFallbackAdminAnalytics() {
    const todayStrPrefix = new Date().toLocaleDateString('th-TH', { dateStyle: 'medium' });
    let todayOrdersCount = 0;
    let todayRevenue = 0;
    (state.orders || []).forEach(o => {
        if ((o.date || '').includes(todayStrPrefix)) {
            todayOrdersCount++;
            todayRevenue += (o.totalAmount || 0);
        }
    });

    const isMember = (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn());
    const memberName = isMember ? USER_AUTH.getUser()?.displayName : null;

    const mockData = {
        success: true,
        live: {
            onlineTotal: 1,
            onlineMembersCount: isMember ? 1 : 0,
            onlineGuestsCount: isMember ? 0 : 1,
            activeUsers: [
                {
                    sessionId: sessionStorage.getItem('supinkly_telemetry_sid') || 'my_session',
                    role: isMember ? 'member' : 'guest',
                    displayName: memberName || 'คุณ (Admin/ผู้เยี่ยมชม)',
                    page: 'ระบบหลังบ้าน (Admin Console)',
                    currentProduct: '',
                    lastAction: 'กำลังตรวจสอบสถิติและคลังสินค้า',
                    cartCount: (state.cart || []).length,
                    cartTotal: (state.cart || []).reduce((s, it) => s + ((getMasterProduct(it.productId)?.price || 0) * (it.quantity || 1)), 0),
                    lastSeenSec: 0,
                    onlineDurationSec: 60
                }
            ]
        },
        today: {
            uniqueVisitors: 1,
            pageViews: 4,
            productViewsTotal: 8,
            cartAddsTotal: (state.cart || []).length,
            ordersCount: todayOrdersCount,
            revenue: todayRevenue,
            conversionRate: todayOrdersCount > 0 ? ((todayOrdersCount / 1) * 100).toFixed(1) + '%' : '0.0%',
            topProducts: PRODUCTS.slice(0, 5).map(p => ({
                productId: p.id,
                title: p.title,
                price: p.price,
                views: Math.floor(Math.random() * 5) + 3,
                cartAdds: 1
            })),
            recentEvents: [
                {
                    time: new Date().toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' }),
                    user: memberName || 'แอดมิน',
                    role: isMember ? 'member' : 'guest',
                    text: 'เปิดตรวจสอบระบบจัดการหลังบ้านและสถิติสด'
                }
            ]
        }
    };
    adminAnalyticsData = mockData;
    renderAdminAnalytics(mockData);
}

function renderActiveUsersList(users) {
    const listEl = document.getElementById('analytics-active-users-list');
    if (!listEl) return;

    let filtered = users;
    if (adminAnalyticsFilter === 'members') {
        filtered = users.filter(u => u.role === 'member');
    } else if (adminAnalyticsFilter === 'guests') {
        filtered = users.filter(u => u.role !== 'member');
    }

    if (!filtered || filtered.length === 0) {
        listEl.innerHTML = `
            <div class="py-12 text-center text-xs text-slate-400 bg-slate-50/60 rounded-xl border border-dashed border-slate-200">
                <i class="fa-solid fa-user-clock text-2xl text-slate-300 mb-2"></i>
                <p class="font-bold text-slate-600">ไม่พบผู้ใช้งานในหมวดนี้ในขณะนี้</p>
                <p class="text-[11px] text-slate-400 mt-0.5">ระบบจะรีเฟรชตรวจจับผู้เยี่ยมชมที่เข้ามาเปิดเว็บโดยอัตโนมัติ</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = filtered.map(u => {
        const isMember = u.role === 'member';
        const activeColor = u.lastSeenSec < 30 ? 'bg-emerald-500' : 'bg-amber-400';
        const roleBadge = isMember
            ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 text-purple-700 border border-purple-200"><i class="fa-solid fa-crown text-[9px] mr-1"></i>สมาชิก</span>`
            : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-600 border border-slate-200"><i class="fa-solid fa-user text-[9px] mr-1"></i>ผู้เยี่ยมชม</span>`;

        const cartInfo = u.cartCount > 0
            ? `<span class="px-2 py-0.5 rounded-lg bg-pink-50 text-pink-700 font-bold border border-pink-200 text-[10px] inline-flex items-center gap-1">
                <i class="fa-solid fa-cart-shopping text-[9px]"></i> ตะกร้า ${u.cartCount} ชิ้น (฿${(u.cartTotal || 0).toFixed(2)})
               </span>`
            : '';

        const timeAgo = u.lastSeenSec <= 5 ? 'เมื่อสักครู่' : `${u.lastSeenSec} วินาทีที่แล้ว`;

        return `
            <div class="p-3.5 rounded-xl border border-slate-200 hover:border-pink-300 hover:shadow-xs transition-all bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                <div class="flex items-start gap-3">
                    <div class="relative mt-0.5 shrink-0">
                        <div class="w-9 h-9 rounded-xl ${isMember ? 'bg-purple-100 text-purple-700' : 'bg-slate-100 text-slate-600'} flex items-center justify-center font-bold text-sm">
                            <i class="fa-solid ${isMember ? 'fa-circle-user' : 'fa-user'}"></i>
                        </div>
                        <span class="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full ${activeColor} ring-2 ring-white"></span>
                    </div>
                    <div>
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="text-xs font-bold text-slate-900">${escapeHTML(u.displayName || 'ผู้เยี่ยมชม')}</span>
                            ${roleBadge}
                            ${cartInfo}
                        </div>
                        <div class="text-[11px] text-slate-600 font-medium mt-0.5 flex flex-wrap items-center gap-1.5">
                            <span class="text-pink-600 font-bold">${escapeHTML(u.lastAction || 'เปิดชมหน้าแรก')}</span>
                            ${u.page ? `<span class="text-slate-400">• หน้า: ${escapeHTML(u.page)}</span>` : ''}
                        </div>
                    </div>
                </div>
                <div class="text-right text-[10px] text-slate-400 font-medium shrink-0 self-end sm:self-center">
                    <div class="flex items-center gap-1 text-emerald-600 font-bold">
                        <span class="w-1.5 h-1.5 rounded-full ${activeColor}"></span>
                        <span>Active ${timeAgo}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function setOnlineUsersFilter(filter) {
    adminAnalyticsFilter = filter;
    ['all', 'members', 'guests'].forEach(f => {
        const btn = document.getElementById(`filter-online-${f}`);
        if (btn) {
            if (f === filter) {
                btn.className = "px-2.5 py-1 rounded-lg bg-white text-slate-900 shadow-2xs cursor-pointer font-bold";
            } else {
                btn.className = "px-2.5 py-1 rounded-lg text-slate-600 hover:text-slate-900 cursor-pointer font-medium";
            }
        }
    });

    if (adminAnalyticsData && adminAnalyticsData.live) {
        renderActiveUsersList(adminAnalyticsData.live.activeUsers || []);
    }
}

function renderTopProductsList(products) {
    const listEl = document.getElementById('analytics-top-products-list');
    if (!listEl) return;

    if (!products || products.length === 0) {
        listEl.innerHTML = `<div class="py-6 text-center text-xs text-slate-400">ยังไม่มีประวัติการดูสินค้าวันนี้</div>`;
        return;
    }

    listEl.innerHTML = products.map((p, idx) => `
        <div class="p-2.5 rounded-xl bg-slate-50 border border-slate-200/80 flex items-center justify-between text-xs">
            <div class="flex items-center gap-2 truncate">
                <span class="w-5 h-5 rounded-md bg-amber-100 text-amber-800 font-bold text-[10px] flex items-center justify-center shrink-0">
                    ${idx + 1}
                </span>
                <span class="font-normal text-slate-800 truncate">${escapeHTML(p.title)}</span>
            </div>
            <div class="flex items-center gap-3 shrink-0 ml-2">
                <span class="text-[11px] text-slate-500 font-medium">ดู <b>${p.views}</b></span>
                <span class="text-[11px] text-pink-600 font-bold">ใส่ตะกร้า <b>${p.cartAdds}</b></span>
            </div>
        </div>
    `).join('');
}

function renderRecentEventsList(events) {
    const listEl = document.getElementById('analytics-recent-events-list');
    if (!listEl) return;

    if (!events || events.length === 0) {
        listEl.innerHTML = `<div class="py-6 text-center text-xs text-slate-400">ยังไม่มีบันทึกกิจกรรมล่าสุด</div>`;
        return;
    }

    listEl.innerHTML = events.map(evt => `
        <div class="p-2 rounded-xl bg-slate-50 border border-slate-100 text-[11px] flex items-start gap-2">
            <span class="w-2 h-2 rounded-full bg-pink-500 mt-1 shrink-0"></span>
            <div class="flex-1 leading-snug">
                <span class="font-bold text-slate-800">${escapeHTML(evt.user || 'ผู้ใช้')}</span>: 
                <span class="text-slate-600">${escapeHTML(evt.text || '')}</span>
            </div>
            <span class="text-[10px] text-slate-400 shrink-0 font-mono">${escapeHTML(evt.time || '')}</span>
        </div>
    `).join('');
}

function startAdminAnalyticsAutoRefresh() {
    stopAdminAnalyticsAutoRefresh();
    adminAnalyticsTimer = setInterval(() => {
        const modal = document.getElementById('admin-modal');
        const tab = document.getElementById('admin-tab-analytics');
        if (modal && !modal.classList.contains('hidden') && tab && !tab.classList.contains('hidden')) {
            fetchAdminAnalytics(false);
        }
    }, 5000);
}

function stopAdminAnalyticsAutoRefresh() {
    if (adminAnalyticsTimer) {
        clearInterval(adminAnalyticsTimer);
        adminAnalyticsTimer = null;
    }
}

// ==========================================
// COUPONS & PROMOTIONS (ADMIN)
// ==========================================
let adminCouponsList = [];
let adminCouponSearchQuery = '';

async function renderAdminCouponsList() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const tableBody = document.getElementById('admin-coupons-table');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/admin/coupons', {
            method: 'GET',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success && Array.isArray(data.coupons)) {
                adminCouponsList = data.coupons;
                saveStorePromotions(data.coupons);
            }
        } else {
            adminCouponsList = getStorePromotions();
        }
    } catch (e) {
        adminCouponsList = getStorePromotions();
    }

    const couponBadge = document.getElementById('admin-coupons-badge');
    if (couponBadge) {
        couponBadge.textContent = adminCouponsList.filter(c => c.active !== false).length;
    }

    let filtered = adminCouponsList;
    if (adminCouponSearchQuery) {
        filtered = filtered.filter(c =>
            (c.code || '').toLowerCase().includes(adminCouponSearchQuery) ||
            (c.title || '').toLowerCase().includes(adminCouponSearchQuery) ||
            (c.description || '').toLowerCase().includes(adminCouponSearchQuery)
        );
    }

    if (!filtered || filtered.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="py-10 text-center text-xs text-slate-400">
                    <i class="fa-solid fa-ticket text-xl text-slate-300 mb-2 block"></i>
                    ไม่พบรายการโค้ดส่วนลด สามารถกด "สร้างโค้ดส่วนลดใหม่" ได้ที่ด้านบน
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = filtered.map(c => {
        const isPercent = (c.discountType === 'percent' || c.type === 'percentage' || c.type === 'percent');
        const discountText = isPercent ? `${c.discountValue || c.value}%` : `฿${(c.discountValue || c.value || 0).toFixed(2)}`;
        const isActive = c.active !== false;

        const conditionParts = [];
        if (c.minSpend && c.minSpend > 0) conditionParts.push(`ขั้นต่ำ ฿${c.minSpend}`);
        if (isPercent && c.maxDiscount && c.maxDiscount > 0) conditionParts.push(`ลดสูงสุด ฿${c.maxDiscount}`);
        if (c.usageLimit && c.usageLimit > 0) conditionParts.push(`จำกัด ${c.usageLimit} ครั้ง (ใช้แล้ว ${c.usedCount || 0})`);
        if (c.expiresAt) conditionParts.push(`หมดอายุ ${c.expiresAt}`);
        const conditionText = conditionParts.length > 0 ? conditionParts.join(' • ') : 'ไม่มีเงื่อนไขขั้นต่ำ';

        return `
            <tr class="hover:bg-slate-50/70 transition-colors">
                <td class="py-3 px-3.5">
                    <div class="flex items-center gap-2">
                        <span class="font-mono font-bold text-pink-600 bg-pink-50 px-2 py-0.5 rounded-md border border-pink-200 text-xs">
                            ${escapeHTML(c.code)}
                        </span>
                        <button type="button" onclick="copyToClipboard('${escapeHTML(c.code)}', 'คัดลอกโค้ด ${escapeHTML(c.code)} แล้ว')"
                            class="text-slate-400 hover:text-slate-600 cursor-pointer" title="คัดลอกโค้ด">
                            <i class="fa-regular fa-copy text-xs"></i>
                        </button>
                    </div>
                    <div class="text-[11px] text-slate-700 font-bold mt-0.5">${escapeHTML(c.title || '')}</div>
                    <div class="text-[10px] text-slate-400">${escapeHTML(c.description || '')}</div>
                </td>
                <td class="py-3 px-3.5 text-center font-bold text-slate-900 text-sm">
                    <span class="text-pink-600">${discountText}</span>
                </td>
                <td class="py-3 px-3.5 text-center text-[11px] text-slate-500 font-medium">
                    ${escapeHTML(conditionText)}
                </td>
                <td class="py-3 px-3.5 text-center">
                    <button type="button" onclick="handleToggleAdminCoupon('${escapeHTML(c.code)}')"
                        class="px-2.5 py-1 rounded-full text-[10px] font-bold cursor-pointer transition-all ${isActive ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-500 border border-slate-200'}">
                        ${isActive ? '🟢 เปิดใช้งาน' : '⚪ ระงับชั่วคราว'}
                    </button>
                </td>
                <td class="py-3 px-3.5 text-right">
                    <button type="button" onclick="handleDeleteAdminCoupon('${escapeHTML(c.code)}')"
                        class="px-2.5 py-1 rounded-lg text-rose-600 hover:bg-rose-50 border border-rose-200 text-xs font-bold cursor-pointer transition-all active:scale-95">
                        <i class="fa-solid fa-trash-can text-xs"></i> ลบ
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function handleAdminCouponSearch(val) {
    adminCouponSearchQuery = (val || '').toLowerCase().trim();
    const clearBtn = document.getElementById('admin-coupon-clear-search');
    if (clearBtn) {
        if (adminCouponSearchQuery) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
    }
    renderAdminCouponsList();
}

function clearAdminCouponSearch() {
    adminCouponSearchQuery = '';
    const input = document.getElementById('admin-coupon-search');
    if (input) input.value = '';
    const clearBtn = document.getElementById('admin-coupon-clear-search');
    if (clearBtn) clearBtn.classList.add('hidden');
    renderAdminCouponsList();
}

function toggleAdminCouponForm(open) {
    const card = document.getElementById('admin-coupon-form-card');
    if (!card) return;
    const shouldOpen = (open !== undefined) ? open : card.classList.contains('hidden');
    const codeInput = document.getElementById('admin-coupon-code-input');
    if (shouldOpen) {
        card.classList.remove('hidden');
        if (codeInput) {
            codeInput.name = 'adm_cp_' + Math.random().toString(36).slice(2, 9);
            codeInput.setAttribute('readonly', 'readonly');
            setTimeout(() => {
                if (codeInput) {
                    codeInput.removeAttribute('readonly');
                    codeInput.focus();
                }
            }, 60);
        }
    } else {
        card.classList.add('hidden');
        if (codeInput) {
            codeInput.value = '';
            codeInput.setAttribute('readonly', 'readonly');
        }
    }
}

function handleAdminCouponTypeChange(val) {
    const unitEl = document.getElementById('admin-coupon-val-unit');
    const maxDiscGroup = document.getElementById('admin-coupon-maxdisc-group');
    if (unitEl) unitEl.textContent = val === 'percent' ? '%' : '฿';
    if (maxDiscGroup) {
        if (val === 'percent') maxDiscGroup.classList.remove('hidden');
        else maxDiscGroup.classList.add('hidden');
    }
}

async function handleAdminCouponFormSubmit(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;

    const code = (document.getElementById('admin-coupon-code-input')?.value || '').trim().toUpperCase();
    const type = document.getElementById('admin-coupon-type-input')?.value || 'percent';
    const val = parseFloat(document.getElementById('admin-coupon-val-input')?.value || '0');
    const minSpend = parseFloat(document.getElementById('admin-coupon-min-input')?.value || '0');
    const maxDiscInput = document.getElementById('admin-coupon-maxdisc-input')?.value;
    const maxDiscount = maxDiscInput ? parseFloat(maxDiscInput) : null;
    const limitInput = document.getElementById('admin-coupon-limit-input')?.value;
    const usageLimit = limitInput ? parseInt(limitInput, 10) : null;
    const expiresAt = document.getElementById('admin-coupon-expiry-input')?.value || null;
    const desc = (document.getElementById('admin-coupon-desc-input')?.value || '').trim();
    const active = document.getElementById('admin-coupon-active-input')?.checked !== false;

    if (!code || code.length < 3) {
        showToast("รหัสโค้ดต้องมีความยาวอย่างน้อย 3 ตัวอักษร", "warning");
        return;
    }
    if (isNaN(val) || val <= 0) {
        showToast("กรุณากรอกมูลค่าส่วนลดที่ถูกต้อง", "warning");
        return;
    }

    const payload = {
        code,
        title: `ส่วนลด ${code} (${type === 'percent' ? val + '%' : '฿' + val})`,
        description: desc || `รับส่วนลด ${type === 'percent' ? val + '%' : '฿' + val} สำหรับคำสั่งซื้อ`,
        discountType: type,
        type: type === 'percent' ? 'percentage' : 'fixed',
        discountValue: val,
        value: val,
        minSpend: isNaN(minSpend) ? 0 : minSpend,
        maxDiscount,
        usageLimit,
        expiresAt,
        active,
        badge: '🎟️ ส่วนลดพิเศษ'
    };

    try {
        const res = await fetch('/api/admin/coupons', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data && data.success) {
            showToast(`สร้างโค้ดส่วนลด "${code}" เรียบร้อยแล้ว`, "success");
        } else {
            showToast(data.message || "สร้างโค้ดในระบบสำเร็จ", "success");
        }
    } catch (e) {
        const promos = getStorePromotions();
        const existingIdx = promos.findIndex(p => p.code === code);
        if (existingIdx > -1) promos[existingIdx] = payload;
        else promos.unshift(payload);
        saveStorePromotions(promos);
        showToast(`บันทึกโค้ดส่วนลด "${code}" สำเร็จ`, "success");
    }

    const adminCodeInput = document.getElementById('admin-coupon-code-input');
    if (adminCodeInput) {
        adminCodeInput.value = '';
        adminCodeInput.setAttribute('readonly', 'readonly');
        adminCodeInput.name = 'adm_cp_' + Math.random().toString(36).slice(2, 9);
        if (typeof adminCodeInput.blur === 'function') adminCodeInput.blur();
    }

    toggleAdminCouponForm(false);
    renderAdminCouponsList();
}

async function handleToggleAdminCoupon(code) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    try {
        await fetch(`/api/admin/coupons/${encodeURIComponent(code)}/toggle`, {
            method: 'POST',
            headers: getAdminHeaders()
        });
    } catch (e) { }

    const promos = getStorePromotions();
    const target = promos.find(p => p.code === code);
    if (target) {
        target.active = !(target.active !== false);
        saveStorePromotions(promos);
        showToast(`อัปเดตสถานะโค้ด "${code}" สำเร็จ`, "info");
    }
    renderAdminCouponsList();
}

async function handleDeleteAdminCoupon(code) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    if (!confirm(`คุณแน่ใจหรือไม่ว่าต้องการลบโค้ด "${code}"?`)) return;

    try {
        await fetch(`/api/admin/coupons/${encodeURIComponent(code)}`, {
            method: 'DELETE',
            headers: getAdminHeaders()
        });
    } catch (e) { }

    let promos = getStorePromotions();
    promos = promos.filter(p => p.code !== code);
    saveStorePromotions(promos);
    showToast(`ลบโค้ด "${code}" เรียบร้อยแล้ว`, "success");
    renderAdminCouponsList();
}

// ==========================================
// USERS & MEMBERS MANAGEMENT (ADMIN)
// ==========================================
let adminUsersList = [];
let adminUserSearchQuery = '';
let adminUserStatusFilter = 'all';

async function renderAdminUsersList() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const tableBody = document.getElementById('admin-users-table');
    if (!tableBody) return;

    try {
        const res = await fetch('/api/admin/users', {
            method: 'GET',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success && Array.isArray(data.users)) {
                adminUsersList = data.users.map(u => ({
                    ...u,
                    id: u.id || u.userId,
                    userId: u.userId || u.id,
                    displayName: u.displayName || 'สมาชิก',
                    isEmailVerified: u.isEmailVerified !== undefined ? u.isEmailVerified : (u.emailVerified !== false),
                    totalOrders: u.totalOrders !== undefined ? u.totalOrders : (u.ordersCount || 0)
                }));
            }
        }
    } catch (e) {
        if (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
            const user = USER_AUTH.getUser();
            if (user) {
                adminUsersList = [{
                    id: user.userId || user.id || 'usr_current',
                    userId: user.userId || user.id || 'usr_current',
                    email: user.email,
                    displayName: user.displayName || 'สมาชิกปัจจุบัน',
                    createdAt: new Date().toISOString(),
                    isEmailVerified: true,
                    totalOrders: 0,
                    totalSpent: 0
                }];
            }
        }
    }

    adminUsersList.forEach(u => {
        let count = 0;
        let spent = 0;
        (state.orders || []).forEach(o => {
            if ((o.recipientEmail || '').toLowerCase() === (u.email || '').toLowerCase()) {
                count++;
                spent += (o.totalAmount || 0);
            }
        });
        u.computedOrders = count;
        u.computedSpent = spent;
    });

    const totalUsers = adminUsersList.length;
    const onlineCount = adminUsersList.filter(u => u.isOnline === true || (u.lastSeen && (Date.now() - new Date(u.lastSeen).getTime() < 120000))).length;
    const offlineCount = Math.max(0, totalUsers - onlineCount);

    document.getElementById('admin-users-count-all') && (document.getElementById('admin-users-count-all').textContent = totalUsers);
    document.getElementById('admin-users-count-online') && (document.getElementById('admin-users-count-online').textContent = onlineCount);
    document.getElementById('admin-users-count-offline') && (document.getElementById('admin-users-count-offline').textContent = offlineCount);
    document.getElementById('admin-users-count-label') && (document.getElementById('admin-users-count-label').textContent = `พบสมาชิก ${totalUsers} คน`);
    document.getElementById('admin-users-badge') && (document.getElementById('admin-users-badge').textContent = totalUsers);

    let filtered = adminUsersList;
    if (adminUserStatusFilter === 'online') {
        filtered = filtered.filter(u => u.isOnline === true || (u.lastSeen && (Date.now() - new Date(u.lastSeen).getTime() < 120000)));
    } else if (adminUserStatusFilter === 'offline') {
        filtered = filtered.filter(u => !(u.isOnline === true || (u.lastSeen && (Date.now() - new Date(u.lastSeen).getTime() < 120000))));
    }

    if (adminUserSearchQuery) {
        filtered = filtered.filter(u =>
            (u.email || '').toLowerCase().includes(adminUserSearchQuery) ||
            (u.displayName || '').toLowerCase().includes(adminUserSearchQuery) ||
            (u.userId || '').toLowerCase().includes(adminUserSearchQuery)
        );
    }

    if (!filtered || filtered.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="py-10 text-center text-xs text-slate-400">
                    <i class="fa-solid fa-users text-2xl text-slate-300 mb-2 block"></i>
                    ยังไม่พบรายชื่อสมาชิกในระบบ เมื่อลูกค้าสมัครสมาชิกผ่านหน้าเว็บ ข้อมูลจะแสดงที่นี่
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = filtered.map(u => {
        const isOnline = u.isOnline === true || (u.lastSeen && (Date.now() - new Date(u.lastSeen).getTime() < 120000));
        const regDate = u.createdAt ? new Date(u.createdAt).toLocaleDateString('th-TH') : '-';
        const totalSpent = u.computedSpent || u.totalSpent || 0;
        const totalOrders = u.computedOrders || u.totalOrders || 0;

        return `
            <tr class="hover:bg-slate-50/70 transition-colors">
                <td class="py-3 px-3.5">
                    <div class="flex items-center gap-2.5">
                        <div class="w-8 h-8 rounded-full bg-pink-100 text-pink-600 font-bold flex items-center justify-center text-xs shrink-0">
                            <i class="fa-solid fa-user"></i>
                        </div>
                        <div>
                            <div class="font-bold text-slate-900 text-xs">${escapeHTML(u.displayName || 'สมาชิก')}</div>
                            <div class="text-[11px] text-slate-500 font-mono">${escapeHTML(u.email)}</div>
                            <div class="text-[9px] text-slate-400 font-mono">ID: ${escapeHTML(u.userId || '')}</div>
                        </div>
                    </div>
                </td>
                <td class="py-3 px-3.5 text-center">
                    <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold ${isOnline ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-500'}">
                        <span class="w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}"></span>
                        ${isOnline ? 'ออนไลน์' : 'ออฟไลน์'}
                    </span>
                </td>
                <td class="py-3 px-3.5 text-center text-xs">
                    ${u.isEmailVerified !== false
                ? '<span class="text-emerald-600 font-bold text-[11px]"><i class="fa-solid fa-circle-check"></i> ยืนยันแล้ว</span>'
                : '<span class="text-amber-600 font-medium text-[11px]"><i class="fa-solid fa-clock"></i> รอยืนยัน</span>'}
                </td>
                <td class="py-3 px-3.5 text-center text-slate-500 text-xs font-medium">
                    ${regDate}
                </td>
                <td class="py-3 px-3.5 text-center">
                    <div class="font-bold text-pink-600 text-xs">฿${totalSpent.toLocaleString('th-TH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</div>
                    <div class="text-[10px] text-slate-400">${totalOrders} ออเดอร์</div>
                </td>
                <td class="py-3 px-3.5 text-right space-x-1">
                    <button type="button" onclick="handleAdminResetUserPassword('${escapeHTML(u.userId || u.id || '')}', '${escapeHTML(u.email || '')}')"
                        class="px-2.5 py-1 rounded-lg text-slate-700 bg-slate-100 hover:bg-slate-200 text-xs font-bold cursor-pointer transition-all" title="รีเซ็ตรหัสผ่าน">
                        <i class="fa-solid fa-key text-[10px]"></i> รีเซ็ตรหัส
                    </button>
                    <button type="button" onclick="handleDeleteAdminUser('${escapeHTML(u.userId || u.id || '')}', '${escapeHTML(u.email || '')}')"
                        class="px-2.5 py-1 rounded-lg text-rose-600 hover:bg-rose-50 border border-rose-200 text-xs font-bold cursor-pointer transition-all active:scale-95" title="ลบผู้ใช้">
                        <i class="fa-solid fa-trash-can text-[10px]"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function handleAdminUserSearch(val) {
    adminUserSearchQuery = (val || '').toLowerCase().trim();
    const clearBtn = document.getElementById('admin-user-clear-search');
    if (clearBtn) {
        if (adminUserSearchQuery) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
    }
    renderAdminUsersList();
}

function clearAdminUserSearch() {
    adminUserSearchQuery = '';
    const input = document.getElementById('admin-user-search');
    if (input) input.value = '';
    const clearBtn = document.getElementById('admin-user-clear-search');
    if (clearBtn) clearBtn.classList.add('hidden');
    renderAdminUsersList();
}

function filterAdminUsersStatus(status) {
    adminUserStatusFilter = status;
    ['all', 'online', 'offline'].forEach(s => {
        const btn = document.getElementById(`admin-users-filter-${s}`);
        if (btn) {
            if (s === status) {
                btn.className = "px-3 py-1.5 rounded-lg bg-white text-slate-900 shadow-2xs font-bold cursor-pointer transition-all";
            } else {
                btn.className = "px-3 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 font-bold cursor-pointer transition-all";
            }
        }
    });
    renderAdminUsersList();
}

function openAdminResetPwModal(userId, email) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }
    const modal = document.getElementById('admin-reset-pw-modal');
    if (!modal) return;

    const idInput = document.getElementById('admin-reset-pw-user-id');
    const labelEl = document.getElementById('admin-reset-pw-user-label');
    const passInput = document.getElementById('admin-reset-pw-input');

    if (idInput) idInput.value = userId || '';
    if (labelEl) labelEl.textContent = `บัญชี: ${email || userId || '-'}`;
    if (passInput) passInput.value = '';

    modal.classList.remove('hidden');
    setTimeout(() => { if (passInput) passInput.focus(); }, 100);
}

function closeAdminResetPwModal() {
    const modal = document.getElementById('admin-reset-pw-modal');
    if (modal) modal.classList.add('hidden');
    const passInput = document.getElementById('admin-reset-pw-input');
    if (passInput) passInput.value = '';
}

async function submitAdminResetPassword() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }
    const idInput = document.getElementById('admin-reset-pw-user-id');
    const passInput = document.getElementById('admin-reset-pw-input');
    const userId = idInput ? idInput.value.trim() : '';
    const newPass = passInput ? passInput.value.trim() : '';

    if (!userId) {
        showToast("ไม่พบรหัสผู้ใช้งาน", "error");
        return;
    }
    if (!newPass || newPass.length < 6) {
        showToast("รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 6 ตัวอักษร", "warning");
        if (passInput) passInput.focus();
        return;
    }

    try {
        const res = await fetch('/api/admin/users/reset-password', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({ userId, newPassword: newPass })
        });
        const data = await res.json();
        if (data && data.success) {
            showToast(data.message || "รีเซ็ตรหัสผ่านสำเร็จเรียบร้อยแล้ว", "success");
            closeAdminResetPwModal();
        } else {
            showToast(data.message || "เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน", "error");
        }
    } catch (e) {
        console.error("submitAdminResetPassword error:", e);
        showToast("ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้", "error");
    }
}

function handleAdminResetUserPassword(userId, email) {
    openAdminResetPwModal(userId, email);
}

async function handleDeleteAdminUser(userId, email) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const targetId = userId || email;
    if (!targetId) {
        showToast("ไม่พบรหัสผู้ใช้ที่ต้องการลบ", "error");
        return;
    }
    if (!confirm(`ยืนยันการลบสมาชิก ${email || targetId} ออกจากระบบ?`)) return;

    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(targetId)}`, {
            method: 'DELETE',
            headers: getAdminHeaders()
        });
        const data = await res.json();
        if (data && data.success) {
            showToast(`ลบสมาชิก ${email || targetId} เรียบร้อยแล้ว`, "success");
        } else {
            showToast(data.message || "ไม่สามารถลบสมาชิกได้", "error");
            return;
        }
    } catch (e) {
        showToast("เกิดข้อผิดพลาดในการเชื่อมต่อเซิร์ฟเวอร์", "error");
        return;
    }

    adminUsersList = adminUsersList.filter(u => u.userId !== targetId && u.id !== targetId && u.email !== email);
    renderAdminUsersList();
}

async function handleClearAllAdminUsers() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const confirmInput = prompt("⚠️ คำเตือน: คุณกำลังจะล้างข้อมูลลูกค้าทั้งหมด! พิมพ์ 'CLEAR-USERS' เพื่อยืนยัน:");
    if (confirmInput !== 'CLEAR-USERS') {
        showToast("ยกเลิกการล้างข้อมูลสมาชิก", "info");
        return;
    }

    try {
        const res = await fetch('/api/admin/users/clear-all', {
            method: 'POST',
            headers: getAdminHeaders()
        });
        const data = await res.json();
        if (data && data.success) {
            showToast("ล้างข้อมูลสมาชิกทั้งหมดเรียบร้อยแล้ว", "success");
        }
    } catch (e) { }

    adminUsersList = [];
    renderAdminUsersList();
}

// ==========================================
// ADMIN SETTINGS & INTEGRATIONS & BACKUP TOOLS
// ==========================================
async function loadAdminSettingsIntoForm() {
    try {
        const res = await fetch('/api/admin/settings', {
            method: 'GET',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success) {
                if (data.promptPayAccountName) {
                    const accEl = document.getElementById('admin-account-name');
                    if (accEl) accEl.value = data.promptPayAccountName;
                }
                if (data.promptPayNumber) {
                    const phoneEl = document.getElementById('admin-promptpay-input');
                    if (phoneEl) phoneEl.value = data.promptPayNumber;
                }
                if (data.slipOkBranchId) {
                    const branchEl = document.getElementById('admin-slipok-branch');
                    if (branchEl) branchEl.value = data.slipOkBranchId;
                }
                if (data.hasSlipOkKey) {
                    const badge = document.getElementById('admin-slipok-status-badge');
                    if (badge) {
                        badge.textContent = `🟢 บันทึกแล้ว (${data.slipOkKeyHint || 'พร้อมใช้งาน'})`;
                        badge.className = "text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 transition-all";
                    }
                }
                if (data.discordWebhookUrl) {
                    const discEl = document.getElementById('admin-discord-webhook');
                    if (discEl && !discEl.value) discEl.value = data.discordWebhookUrl;
                }
                if (data.geminiApiKey) {
                    const geminiEl = document.getElementById('admin-gemini-api-key');
                    if (geminiEl && !geminiEl.value) geminiEl.placeholder = "•••••••• (บันทึกคีย์แล้ว - กรอกใหม่เพื่อเปลี่ยน)";
                }
                if (data.smtpConfig) {
                    const smtp = data.smtpConfig;
                    const hostEl = document.getElementById('admin-smtp-host');
                    if (hostEl && smtp.host) hostEl.value = smtp.host;
                    const portEl = document.getElementById('admin-smtp-port');
                    if (portEl && smtp.port) portEl.value = smtp.port;
                    const userEl = document.getElementById('admin-smtp-user');
                    if (userEl && smtp.user) userEl.value = smtp.user;
                    const fromEl = document.getElementById('admin-smtp-from');
                    if (fromEl && smtp.from) fromEl.value = smtp.from;
                    const logoEl = document.getElementById('admin-smtp-logourl');
                    if (logoEl && smtp.logoUrl) logoEl.value = smtp.logoUrl;

                    const passEl = document.getElementById('admin-smtp-pass');
                    if (passEl && !passEl.value && smtp.pass) {
                        passEl.placeholder = "•••••••• (บันทึกรหัสแอปไว้แล้ว - กรอกใหม่เพื่อเปลี่ยน)";
                    }
                    const brevoEl = document.getElementById('admin-smtp-brevo');
                    if (brevoEl && !brevoEl.value && smtp.brevoKey) {
                        brevoEl.placeholder = "•••••••• (บันทึกไว้แล้ว)";
                    }
                    const resendEl = document.getElementById('admin-smtp-resend');
                    if (resendEl && !resendEl.value && smtp.resendKey) {
                        resendEl.placeholder = "•••••••• (บันทึกไว้แล้ว)";
                    }
                    const sgEl = document.getElementById('admin-smtp-sendgrid');
                    if (sgEl && !sgEl.value && smtp.sendgridKey) {
                        sgEl.placeholder = "•••••••• (บันทึกไว้แล้ว)";
                    }
                    const mjKeyEl = document.getElementById('admin-smtp-mailjet-key');
                    if (mjKeyEl && !mjKeyEl.value && smtp.mailjetKey) {
                        mjKeyEl.placeholder = "•••••••• (บันทึกแล้ว)";
                    }
                    const mjSecEl = document.getElementById('admin-smtp-mailjet-secret');
                    if (mjSecEl && !mjSecEl.value && smtp.mailjetSecret) {
                        mjSecEl.placeholder = "•••••••• (บันทึกแล้ว)";
                    }
                    const testTargetEl = document.getElementById('admin-test-email-target');
                    if (testTargetEl && !testTargetEl.value && smtp.user) {
                        testTargetEl.value = smtp.user;
                    }
                }
                if (data.maintenanceMode !== undefined) {
                    const maintCheck = document.getElementById('admin-maintenance-mode');
                    if (maintCheck) maintCheck.checked = !!data.maintenanceMode;
                    updateMaintenanceBadge(data.maintenanceMode);
                }
            }
        }
    } catch (e) { }
}

function scrollToAdminSetting(sectionId) {
    const el = document.getElementById(sectionId);
    if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function updateMaintenanceBadge(isMaint) {
    const badge = document.getElementById('admin-maintenance-badge');
    const directBtn = document.getElementById('admin-maint-direct-btn');
    if (badge) {
        if (isMaint) {
            badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse"></span> ⚠️ ปิดปรับปรุงอยู่ (Maintenance)`;
            badge.className = "text-[11px] text-amber-800 font-bold bg-amber-50 px-2.5 py-0.5 rounded-full border border-amber-300 flex items-center gap-1";
        } else {
            badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> 🟢 เปิดให้บริการปกติ`;
            badge.className = "text-[11px] text-emerald-700 font-bold bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200 flex items-center gap-1";
        }
    }
    if (directBtn) {
        directBtn.innerHTML = isMaint
            ? `<i class="fa-solid fa-circle-check"></i> <span>คลิกเปิดร้านปกติทันที</span>`
            : `<i class="fa-solid fa-power-off"></i> <span>คลิกปิดเว็บชั่วคราวทันที</span>`;
        directBtn.className = isMaint
            ? "px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold shadow-md flex items-center gap-2 transition-all cursor-pointer active:scale-95"
            : "px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-600 text-white text-xs font-bold shadow-md shadow-amber-500/25 flex items-center gap-2 transition-all cursor-pointer active:scale-95";
    }
}

async function toggleMaintenanceModeDirectly(checked) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }

    const checkbox = document.getElementById('admin-maintenance-mode');
    const newState = (checked !== undefined) ? !!checked : (checkbox ? !checkbox.checked : true);
    if (checkbox) checkbox.checked = newState;

    updateMaintenanceBadge(newState);

    try {
        const res = await fetch('/api/admin/settings', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({ maintenanceMode: newState })
        });
        const data = await res.json();
        if (data && data.success) {
            showToast(newState ? "เปิดโหมดปิดปรับปรุงชั่วคราวแล้ว" : "เปิดให้บริการร้านค้าตามปกติแล้ว", "success");
        }
    } catch (e) {
        showToast(newState ? "เปิดโหมดปรับปรุง (จำลอง)" : "เปิดร้านปกติ (จำลอง)", "info");
    }
}

function toggleSlipOkKeyVisibility() {
    const input = document.getElementById('admin-slipok-apikey');
    const icon = document.getElementById('slipok-eye-icon');
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        if (icon) { icon.classList.remove('fa-eye'); icon.classList.add('fa-eye-slash'); }
    } else {
        input.type = 'password';
        if (icon) { icon.classList.remove('fa-eye-slash'); icon.classList.add('fa-eye'); }
    }
}

async function handleAdminTestSlipOK() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }
    const branchId = document.getElementById('admin-slipok-branch')?.value.trim();
    const apiKey = document.getElementById('admin-slipok-apikey')?.value.trim();
    const resultEl = document.getElementById('admin-slipok-test-result');
    const btn = document.getElementById('admin-test-slipok-btn');

    if (btn) btn.disabled = true;
    if (resultEl) {
        resultEl.classList.remove('hidden');
        resultEl.className = "p-3 rounded-xl text-xs font-medium bg-slate-100 text-slate-700 sm:col-span-2 lg:col-span-3";
        resultEl.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> กำลังทดสอบเชื่อมต่อ SlipOK...`;
    }

    try {
        const res = await fetch('/api/admin/test-slipok', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({ branchId, apiKey })
        });
        const data = await res.json();
        if (resultEl) {
            if (res.status === 403) {
                resultEl.className = "p-3 rounded-xl text-xs font-bold bg-amber-50 text-amber-900 border border-amber-300 sm:col-span-2 lg:col-span-3";
                resultEl.innerHTML = `<i class="fa-solid fa-lock text-amber-600 mr-1.5"></i> เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบด้วยรหัส PIN อีกครั้ง <button type="button" onclick="promptAdminLogin()" class="ml-2 px-2.5 py-1 bg-pink-500 hover:bg-pink-600 text-white rounded-lg text-xs font-bold transition-all cursor-pointer">เข้าสู่ระบบ PIN</button>`;
                return;
            }
            if (data && data.success) {
                resultEl.className = "p-3 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-200 sm:col-span-2 lg:col-span-3";
                resultEl.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-600 mr-1.5"></i> ${data.message || 'เชื่อมต่อ SlipOK สำเร็จ!'}`;
                const badge = document.getElementById('admin-slipok-status-badge');
                if (badge) {
                    badge.textContent = `🟢 เชื่อมต่อสำเร็จ (โควต้า: ${data.quota || '-'})`;
                    badge.className = "text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700";
                }
            } else {
                resultEl.className = "p-3 rounded-xl text-xs font-bold bg-rose-50 text-rose-800 border border-rose-200 sm:col-span-2 lg:col-span-3";
                resultEl.innerHTML = `<i class="fa-solid fa-circle-xmark text-rose-600 mr-1.5"></i> ${data.message || 'การเชื่อมต่อล้มเหลว ตรวจสอบ Branch ID และ API Key'}`;
            }
        }
    } catch (e) {
        if (resultEl) {
            resultEl.className = "p-3 rounded-xl text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200 sm:col-span-2 lg:col-span-3";
            resultEl.innerHTML = `⚠️ ไม่สามารถติดต่อเซิร์ฟเวอร์เพื่อทดสอบ SlipOK ได้ในขณะนี้ (${e.message})`;
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function savePromptPayAndSlipOkSettings() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const phoneEl = document.getElementById('admin-promptpay-input');
    const newPhone = phoneEl ? phoneEl.value.trim().replace(/[-\s]/g, '') : '';
    const newAccountName = (document.getElementById('admin-account-name')?.value || '').trim();
    const newBranchId = (document.getElementById('admin-slipok-branch')?.value || '').trim();
    const newApiKey = (document.getElementById('admin-slipok-apikey')?.value || '').trim();

    if (newPhone && !/^[0-9]{10,15}$/.test(newPhone)) {
        showToast("รูปแบบเบอร์พร้อมเพย์ต้องเป็นตัวเลข 10-15 หลัก", "warning");
        return;
    }

    if (newPhone) STORE_CONFIG.promptPayNumber = newPhone;
    if (newAccountName) STORE_CONFIG.promptPayAccountName = newAccountName;
    if (newBranchId) STORE_CONFIG.slipOkBranchId = newBranchId;
    if (newApiKey && newApiKey !== '******') STORE_CONFIG.slipOkApiKey = newApiKey;

    try {
        await fetch('/api/admin/settings', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({
                promptPayNumber: STORE_CONFIG.promptPayNumber,
                promptPayAccountName: STORE_CONFIG.promptPayAccountName,
                slipOkBranchId: STORE_CONFIG.slipOkBranchId,
                slipOkApiKey: STORE_CONFIG.slipOkApiKey
            })
        });
        localStorage.setItem('supinkly_store_config', JSON.stringify(STORE_CONFIG));
        showToast("บันทึกการตั้งค่าพร้อมเพย์ & SlipOK เรียบร้อยแล้ว", "success");
    } catch (e) {
        localStorage.setItem('supinkly_store_config', JSON.stringify(STORE_CONFIG));
        showToast("บันทึกการตั้งค่าลงเบราว์เซอร์สำเร็จ", "success");
    }
}

async function handleAdminTestDiscord() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const webhookUrl = document.getElementById('admin-discord-webhook')?.value.trim();
    const resultEl = document.getElementById('admin-test-discord-result');
    const btn = document.getElementById('admin-test-discord-btn');

    if (!webhookUrl) {
        showToast("กรุณากรอก Discord Webhook URL", "warning");
        return;
    }

    if (btn) btn.disabled = true;
    if (resultEl) {
        resultEl.classList.remove('hidden');
        resultEl.className = "mt-2 p-3 rounded-xl text-xs font-medium bg-slate-100 text-slate-700";
        resultEl.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> กำลังส่งข้อความทดสอบเข้า Discord...`;
    }

    try {
        const res = await fetch('/api/admin/test-discord', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({ webhookUrl })
        });
        const data = await res.json();
        if (resultEl) {
            if (data && data.success) {
                resultEl.className = "mt-2 p-3 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-200";
                resultEl.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-600 mr-1.5"></i> ${data.message || 'ส่งแจ้งเตือนเข้า Discord สำเร็จ! ตรวจสอบที่ห้องแชทของคุณ'}`;
            } else {
                resultEl.className = "mt-2 p-3 rounded-xl text-xs font-bold bg-rose-50 text-rose-800 border border-rose-200";
                resultEl.innerHTML = `<i class="fa-solid fa-circle-xmark text-rose-600 mr-1.5"></i> ${data.message || 'ส่งไม่สำเร็จ ตรวจสอบ Webhook URL'}`;
            }
        }
    } catch (e) {
        if (resultEl) {
            resultEl.className = "mt-2 p-3 rounded-xl text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200";
            resultEl.innerHTML = `⚠️ ไม่สามารถติดต่อเซิร์ฟเวอร์เพื่อทดสอบได้`;
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

function applySmtpPreset(preset) {
    const hostEl = document.getElementById('admin-smtp-host');
    const portEl = document.getElementById('admin-smtp-port');
    if (!hostEl || !portEl) return;
    if (preset === 'gmail-465') {
        hostEl.value = 'smtp.gmail.com';
        portEl.value = '465';
        showToast("เลือกโปรไฟล์ Gmail SSL (พอร์ต 465) แล้ว", "info");
    } else if (preset === 'gmail-587') {
        hostEl.value = 'smtp.gmail.com';
        portEl.value = '587';
        showToast("เลือกโปรไฟล์ Gmail TLS (พอร์ต 587) แล้ว", "info");
    }
}

async function handleAdminTestEmail() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const targetEmail = document.getElementById('admin-test-email-target')?.value.trim();
    const resultEl = document.getElementById('admin-test-email-result');
    const btn = document.getElementById('admin-test-email-btn');

    if (!targetEmail || !targetEmail.includes('@')) {
        showToast("กรุณากรอกอีเมลผู้รับทดสอบให้ถูกต้อง", "warning");
        const targetInput = document.getElementById('admin-test-email-target');
        if (targetInput) targetInput.focus();
        return;
    }

    const host = document.getElementById('admin-smtp-host')?.value.trim() || '';
    const port = parseInt(document.getElementById('admin-smtp-port')?.value || '465', 10);
    const user = document.getElementById('admin-smtp-user')?.value.trim() || '';
    const pass = document.getElementById('admin-smtp-pass')?.value.trim() || '';
    const from = document.getElementById('admin-smtp-from')?.value.trim() || '';
    const logoUrl = document.getElementById('admin-smtp-logourl')?.value.trim() || '';
    const brevoKey = document.getElementById('admin-smtp-brevo')?.value.trim() || '';
    const resendKey = document.getElementById('admin-smtp-resend')?.value.trim() || '';
    const sendgridKey = document.getElementById('admin-smtp-sendgrid')?.value.trim() || '';
    const mailjetKey = document.getElementById('admin-smtp-mailjet-key')?.value.trim() || '';
    const mailjetSecret = document.getElementById('admin-smtp-mailjet-secret')?.value.trim() || '';

    const smtpConfig = {
        host,
        port,
        user,
        pass,
        from,
        logoUrl,
        brevoKey,
        resendKey,
        sendgridKey,
        mailjetKey,
        mailjetSecret
    };

    if (btn) btn.disabled = true;
    if (resultEl) {
        resultEl.classList.remove('hidden');
        resultEl.className = "mt-2.5 p-3 rounded-xl text-xs font-medium bg-slate-100 text-slate-700 border border-slate-200 animate-pulse";
        resultEl.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5 text-pink-600"></i> กำลังทดสอบส่งอีเมลไปยัง <strong>${escapeHTML(targetEmail)}</strong>...`;
    }

    try {
        const res = await fetch('/api/admin/test-email', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({
                testEmail: targetEmail,
                to: targetEmail,
                smtpConfig: smtpConfig,
                ...smtpConfig
            })
        });
        const data = await res.json();
        if (resultEl) {
            resultEl.classList.remove('animate-pulse');
            if (data && data.success) {
                resultEl.className = "mt-2.5 p-3 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-200 shadow-2xs";
                const msg = escapeHTML(data.message || 'ส่งอีเมลทดสอบสำเร็จ! ตรวจสอบกล่องจดหมายของคุณ').replace(/\n/g, '<br>');
                resultEl.innerHTML = `<div class="flex items-start gap-2"><i class="fa-solid fa-circle-check text-emerald-600 mt-0.5 shrink-0 text-sm"></i><div class="leading-relaxed">${msg}</div></div>`;
            } else {
                resultEl.className = "mt-2.5 p-3 rounded-xl text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200 shadow-2xs";
                const msg = escapeHTML(data.message || 'ส่งอีเมลไม่สำเร็จ ตรวจสอบการตั้งค่า SMTP และ App Password').replace(/\n/g, '<br>');
                resultEl.innerHTML = `<div class="flex items-start gap-2"><i class="fa-solid fa-circle-xmark text-rose-600 mt-0.5 shrink-0 text-sm"></i><div class="leading-relaxed whitespace-pre-wrap">${msg}</div></div>`;
            }
        }
    } catch (e) {
        if (resultEl) {
            resultEl.classList.remove('animate-pulse');
            resultEl.className = "mt-2.5 p-3 rounded-xl text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200";
            resultEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber-600 mr-1.5"></i> ไม่สามารถติดต่อเซิร์ฟเวอร์เพื่อทดสอบส่งอีเมลได้ (${escapeHTML(e.message || 'Network Error')})`;
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function downloadDatabaseBackup() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    try {
        const res = await fetch('/api/admin/backup-db', {
            method: 'GET',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `supinkly_db_backup_${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast("ดาวน์โหลดไฟล์สำรองข้อมูลฐานข้อมูลสำเร็จ!", "success");
            return;
        }
    } catch (e) { }

    const localBackup = {
        exportedAt: new Date().toISOString(),
        version: "2026.1",
        orders: state.orders || [],
        inventory: state.inventory || {},
        promotions: getStorePromotions(),
        config: STORE_CONFIG
    };
    const blob = new Blob([JSON.stringify(localBackup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `supinkly_local_backup_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("ดาวน์โหลดไฟล์สำรองข้อมูลจากเบราว์เซอร์สำเร็จ!", "success");
}

async function handleDatabaseRestore(fileInput) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    const file = fileInput?.files?.[0];
    if (!file) return;

    if (!confirm(`คุณแน่ใจหรือไม่ว่าต้องการกู้คืนข้อมูลจากไฟล์ "${file.name}"? ข้อมูลปัจจุบันอาจถูกเขียนทับ`)) {
        fileInput.value = '';
        return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const jsonText = e.target.result;
            const parsed = JSON.parse(jsonText);

            try {
                const res = await fetch('/api/admin/restore-db', {
                    method: 'POST',
                    headers: getAdminHeaders(),
                    body: JSON.stringify({ backupJson: parsed })
                });
                const data = await res.json();
                if (data && data.success) {
                    showToast("กู้คืนฐานข้อมูลผ่านเซิร์ฟเวอร์เรียบร้อยแล้ว!", "success");
                    setTimeout(() => location.reload(), 1000);
                    return;
                }
            } catch (err) { }

            if (Array.isArray(parsed.orders)) {
                state.orders = parsed.orders;
                saveOrders();
            }
            if (parsed.inventory && typeof parsed.inventory === 'object') {
                state.inventory = parsed.inventory;
                saveSecureInventory(state.inventory);
            }
            if (Array.isArray(parsed.promotions)) {
                saveStorePromotions(parsed.promotions);
            }
            showToast("กู้คืนข้อมูลลงในระบบเรียบร้อยแล้ว กำลังรีโหลด...", "success");
            setTimeout(() => location.reload(), 1200);
        } catch (err) {
            showToast("ไฟล์สำรองไม่ถูกต้องหรือไม่ใช่รูปแบบ JSON ที่ถูกต้อง", "error");
        } finally {
            fileInput.value = '';
        }
    };
    reader.readAsText(file);
}

function handleAdminOrderSearch(val) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    adminOrderSearchQuery = (val || '').toLowerCase().trim();
    const clearBtn = document.getElementById('admin-order-clear-search');
    if (clearBtn) {
        if (adminOrderSearchQuery) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
    }
    renderAdminOrdersList();
}

function clearAdminOrderSearch() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    adminOrderSearchQuery = '';
    const input = document.getElementById('admin-order-search');
    if (input) input.value = '';
    const clearBtn = document.getElementById('admin-order-clear-search');
    if (clearBtn) clearBtn.classList.add('hidden');
    renderAdminOrdersList();
}

function filterAdminOrders(filterType) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    currentAdminOrderFilter = filterType;
    ['all', 'pending', 'delivered'].forEach(f => {
        const btn = document.getElementById(`admin-order-filter-${f}`);
        if (btn) {
            if (f === filterType) {
                btn.className = "px-3 py-2 rounded-xl bg-pink-100 text-pink-700 font-bold transition-all";
            } else {
                btn.className = "px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold transition-all";
            }
        }
    });
    renderAdminOrdersList();
}

function exportOrdersToCSV() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        showToast("สิทธิ์การเข้าถึงถูกปฏิเสธ: กรุณาเข้าสู่ระบบหลังร้านก่อน", "error");
        promptAdminLogin();
        return;
    }

    const ordersToExport = getAdminOrders();
    if (!ordersToExport || ordersToExport.length === 0) {
        showToast("ยังไม่มีข้อมูลคำสั่งซื้อสำหรับส่งออก", "info");
        return;
    }

    const headers = ["Order ID", "Date", "Customer Email", "Total Amount (THB)", "Payment Method", "TransRef", "Status", "Items"];
    const rows = ordersToExport.map(o => {
        const itemNames = (o.items || []).map(i => `${i.productTitle} (x1)`).join(' | ');
        const cleanStatus = (o.status || '').replace(/[\u{1F300}-\u{1F9FF}]/gu, '').trim();
        return [
            o.orderId,
            `"${o.date || ''}"`,
            `"${o.recipientEmail || o.email || ''}"`,
            (o.totalAmount || 0).toFixed(2),
            `"${o.paymentMethod || 'PromptPay'}"`,
            `"${o.transRef || ''}"`,
            `"${cleanStatus}"`,
            `"${itemNames.replace(/"/g, '""')}"`
        ];
    });

    const csvContent = "\uFEFF" + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `supinkly_orders_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast("ส่งออกไฟล์ CSV คำสั่งซื้อเรียบร้อยแล้ว", "success");
}

async function handleClearAllAdminOrders() {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        promptAdminLogin();
        return;
    }
    const orders = getAdminOrders();
    if (!orders || orders.length === 0) {
        showToast("ไม่มีคำสั่งซื้อในระบบให้ล้าง", "info");
        return;
    }
    if (!confirm(`คุณแน่ใจหรือไม่ว่าต้องการล้างข้อมูลคำสั่งซื้อทั้งหมด ${orders.length} รายการ?\n\nการกระทำนี้จะลบออกจากฐานข้อมูลเซิร์ฟเวอร์ถาวรและไม่สามารถย้อนกลับได้!`)) {
        return;
    }

    try {
        const res = await fetch('/api/admin/orders/clear-all', {
            method: 'POST',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success) {
                adminOrdersList = [];
                state.orders = [];
                saveOrders();
                renderAdminOrdersList();
                if (typeof updateAdminNavBadges === 'function') updateAdminNavBadges();
                showToast("ล้างข้อมูลคำสั่งซื้อทั้งหมดจากเซิร์ฟเวอร์เรียบร้อยแล้ว", "success");
                return;
            }
        }
    } catch (e) {
        console.warn("[ADMIN] Clear orders server error, falling back locally:", e);
    }

    adminOrdersList = [];
    state.orders = [];
    saveOrders();
    renderAdminOrdersList();
    if (typeof updateAdminNavBadges === 'function') updateAdminNavBadges();
    showToast("ล้างข้อมูลคำสั่งซื้อทั้งหมดเรียบร้อยแล้ว", "success");
}

async function deleteAdminOrder(orderId) {
    if (!orderId) return;
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        promptAdminLogin();
        return;
    }
    if (!confirm(`คุณแน่ใจหรือไม่ว่าต้องการลบคำสั่งซื้อ ${orderId} ออกจากระบบ?`)) {
        return;
    }

    try {
        const res = await fetch(`/api/admin/orders/${encodeURIComponent(orderId)}`, {
            method: 'DELETE',
            headers: getAdminHeaders()
        });
        if (res.ok) {
            const data = await res.json();
            if (data && data.success) {
                adminOrdersList = adminOrdersList.filter(o => o.orderId !== orderId);
                state.orders = (state.orders || []).filter(o => o.orderId !== orderId);
                saveOrders();
                renderAdminOrdersList();
                if (typeof updateAdminNavBadges === 'function') updateAdminNavBadges();
                showToast(`ลบคำสั่งซื้อ ${orderId} สำเร็จแล้ว`, "success");
                return;
            }
        }
    } catch (e) {
        console.warn("[ADMIN] Delete order server error:", e);
    }

    adminOrdersList = adminOrdersList.filter(o => o.orderId !== orderId);
    state.orders = (state.orders || []).filter(o => o.orderId !== orderId);
    saveOrders();
    renderAdminOrdersList();
    if (typeof updateAdminNavBadges === 'function') updateAdminNavBadges();
    showToast(`ลบคำสั่งซื้อ ${orderId} เรียบร้อยแล้ว`, "success");
}

function copyOrderCustomerReceipt(orderId) {
    const order = (adminOrdersList && adminOrdersList.find(o => o.orderId === orderId)) || (state.orders || []).find(o => o.orderId === orderId);
    if (!order) return;

    let text = `📦 ข้อมูลคำสั่งซื้อ Supinkly.AI\n`;
    text += `เลขออเดอร์: ${order.orderId}\n`;
    text += `วันที่สั่งซื้อ: ${order.date || ''}\n`;
    text += `ยอดชำระ: ฿${(order.totalAmount || 0).toFixed(2)}\n\n`;
    text += `รายการสินค้าและรหัสเข้าใช้งาน:\n`;

    (order.items || []).forEach((it, idx) => {
        text += `\n${idx + 1}. ${it.productTitle}\n`;
        const cred = it.credentials;
        if (cred) {
            if (cred.email) text += `   - Email: ${cred.email}\n`;
            if (cred.password) text += `   - Password: ${cred.password}\n`;
            if (cred.key) text += `   - License Key: ${cred.key}\n`;
            if (cred.link) text += `   - ลิงก์เปิดใช้งาน: ${cred.link}\n`;
            if (cred.instructions) text += `   - คำแนะนำ: ${cred.instructions}\n`;
        } else {
            text += `   - สถานะ: อยู่ระหว่างจัดเตรียมรหัส (5-15 นาที)\n`;
        }
    });

    text += `\n🛡️ ประกันสินค้าและการดูแล 30 วัน\n`;
    text += `หากพบปัญหาหรือต้องการความช่วยเหลือ ติดต่อทางเพจ: https://www.facebook.com/profile.php?id=61594837747580`;

    copyToClipboard(text, "คัดลอกข้อความแจ้งลูกค้าเรียบร้อยแล้ว นำไปส่งในแชทได้ทันที!");
}

async function renderAdminOrdersList(forceFetch = false) {
    const container = document.getElementById('admin-orders-list');
    const badge = document.getElementById('admin-pending-badge');
    const countLabel = document.getElementById('admin-orders-count-label');
    if (!container) return;

    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        container.innerHTML = `
            <div class="py-10 text-center bg-slate-50 rounded-2xl border border-slate-200">
                <p class="text-sm font-bold text-rose-600">กรุณาเข้าสู่ระบบหลังร้านเพื่อดูรายการคำสั่งซื้อ</p>
            </div>
        `;
        return;
    }

    if (forceFetch || adminOrdersList.length === 0) {
        await fetchAdminOrders(forceFetch);
    }

    const allOrders = getAdminOrders();

    // Update KPI stats
    let totalSales = 0;
    let pendingCount = 0;
    let deliveredCount = 0;

    allOrders.forEach(order => {
        totalSales += (order.totalAmount || 0);
        if (isOrderPending(order)) {
            pendingCount++;
        } else {
            deliveredCount++;
        }
    });

    const salesEl = document.getElementById('admin-stat-sales');
    if (salesEl) salesEl.textContent = `฿${totalSales.toLocaleString('th-TH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    const pendingEl = document.getElementById('admin-stat-pending');
    if (pendingEl) {
        pendingEl.textContent = `${pendingCount} ออเดอร์`;
        if (pendingCount > 0) {
            pendingEl.className = "text-base sm:text-lg font-black text-amber-700 mt-1 animate-pulse";
        } else {
            pendingEl.className = "text-base sm:text-lg font-black text-slate-700 mt-1";
        }
    }
    const deliveredEl = document.getElementById('admin-stat-delivered');
    if (deliveredEl) deliveredEl.textContent = `${deliveredCount} รายการ`;
    const totalOrdersEl = document.getElementById('admin-stat-total-orders');
    if (totalOrdersEl) totalOrdersEl.textContent = `${allOrders.length} รายการ`;

    if (badge) {
        badge.textContent = pendingCount;
        if (pendingCount > 0) {
            badge.className = "px-2 py-0.5 rounded-full bg-amber-400 text-slate-900 text-xs font-black animate-bounce";
        } else {
            badge.className = "px-2 py-0.5 rounded-full bg-slate-200 text-slate-700 text-xs font-black";
        }
    }

    // Filter by tab
    let filteredOrders = allOrders;
    if (currentAdminOrderFilter === 'pending') {
        filteredOrders = filteredOrders.filter(isOrderPending);
    } else if (currentAdminOrderFilter === 'delivered') {
        filteredOrders = filteredOrders.filter(isOrderDelivered);
    }

    // Filter by search query
    if (adminOrderSearchQuery) {
        filteredOrders = filteredOrders.filter(o => {
            const idMatch = (o.orderId || '').toLowerCase().includes(adminOrderSearchQuery);
            const emailMatch = (o.recipientEmail || o.email || '').toLowerCase().includes(adminOrderSearchQuery);
            const refMatch = (o.transRef || '').toLowerCase().includes(adminOrderSearchQuery);
            const itemMatch = (o.items || []).some(it => (it.productTitle || '').toLowerCase().includes(adminOrderSearchQuery));
            return idMatch || emailMatch || refMatch || itemMatch;
        });
    }

    if (countLabel) {
        countLabel.textContent = `แสดง ${filteredOrders.length} จากทั้งหมด ${allOrders.length} รายการ`;
    }

    if (filteredOrders.length === 0) {
        const isFilterActive = currentAdminOrderFilter !== 'all' || adminOrderSearchQuery;
        container.innerHTML = `
            <div class="py-12 px-4 text-center bg-slate-50/90 rounded-2xl border-2 border-dashed border-slate-200">
                <div class="w-14 h-14 mx-auto mb-3 rounded-2xl bg-pink-100 text-pink-500 flex items-center justify-center text-2xl shadow-inner">
                    <i class="fa-solid fa-box-open"></i>
                </div>
                <p class="text-sm font-bold text-slate-800">
                    ${isFilterActive ? 'ไม่พบรายการคำสั่งซื้อตามตัวกรองที่เลือก' : 'ขณะนี้ยังไม่มีรายการคำสั่งซื้อในระบบ (0 รายการ)'}
                </p>
                <p class="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                    ${isFilterActive
                ? 'ลองเปลี่ยนตัวกรองเป็น "ทั้งหมด" หรือล้างคำค้นหาเพื่อดูรายการอื่นๆ'
                : 'เมื่อลูกค้าชำระเงินเข้ามา รายการจะบันทึกเข้าเซิร์ฟเวอร์และแสดงที่นี่โดยอัตโนมัติ หรือกดปุ่มด้านล่างเพื่อทดลองสร้างออเดอร์จำลอง'}
                </p>
                <div class="mt-4 flex flex-wrap items-center justify-center gap-2">
                    <button onclick="createDemoOrder()" class="px-4 py-2 rounded-xl bg-gradient-to-r from-pink-500 to-rose-500 hover:from-pink-600 hover:to-rose-600 text-white text-xs font-bold shadow-md hover:shadow-lg transition-all flex items-center gap-2 active:scale-95 cursor-pointer">
                        <i class="fa-solid fa-wand-magic-sparkles"></i>
                        <span>สร้างออเดอร์ทดสอบระบบ (Demo Order)</span>
                    </button>
                    ${allOrders.length > 0 ? `
                        <button onclick="filterAdminOrders('all')" class="px-3.5 py-2 rounded-xl bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 text-xs font-bold transition-all cursor-pointer">
                            ดูออเดอร์ทั้งหมด (${allOrders.length} รายการ)
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
        return;
    }

    container.innerHTML = filteredOrders.map(order => {
        const hasPending = isOrderPending(order);

        return `
            <div class="p-4 rounded-2xl bg-white border-2 ${hasPending ? 'border-amber-300 shadow-sm' : 'border-slate-200'} space-y-3">
                <div class="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-slate-100 text-xs">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="font-mono font-black text-pink-600 text-sm">${escapeHTML(order.orderId)}</span>
                        <span class="text-slate-400">•</span>
                        <span class="text-slate-500 font-medium">${escapeHTML(order.date || '')}</span>
                        <span class="text-slate-400">•</span>
                        <span class="font-bold text-slate-800">ลูกค้า: ${escapeHTML(order.recipientEmail || order.email || 'ไม่ระบุ')}</span>
                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(order.recipientEmail || order.email || '')}" data-msg="คัดลอกอีเมลลูกค้าแล้ว" 
                                title="คัดลอกอีเมลลูกค้า" class="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 font-bold text-[10px] transition-all cursor-pointer">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="openSlipViewModal('${escapeHTML(order.orderId)}')" 
                                class="px-2.5 py-1 rounded-xl bg-purple-50 hover:bg-purple-100 text-purple-700 text-xs font-bold transition-all flex items-center gap-1 border border-purple-200 shadow-2xs cursor-pointer" title="คลิกดูสลิปโอนเงิน">
                            <i class="fa-solid fa-file-invoice-dollar text-[11px]"></i>
                            <span>ดูสลิป</span>
                        </button>
                        <button onclick="copyOrderCustomerReceipt('${escapeHTML(order.orderId)}')" 
                                class="px-2.5 py-1 rounded-xl bg-pink-50 hover:bg-pink-100 text-pink-700 text-xs font-bold transition-all flex items-center gap-1 border border-pink-200 shadow-2xs cursor-pointer">
                            <i class="fa-regular fa-message text-[11px]"></i>
                            <span>ข้อความส่งลูกค้า</span>
                        </button>
                        <button onclick="deleteAdminOrder('${escapeHTML(order.orderId)}')" 
                                class="px-2.5 py-1 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-bold transition-all flex items-center gap-1 border border-rose-200 shadow-2xs cursor-pointer" title="ลบคำสั่งซื้อนี้">
                            <i class="fa-regular fa-trash-can text-[11px]"></i>
                            <span>ลบ</span>
                        </button>
                        <span class="px-2.5 py-1 rounded-full text-xs font-bold ${hasPending ? 'bg-amber-100 text-amber-900 border border-amber-300 animate-pulse' : 'bg-emerald-100 text-emerald-800 border border-emerald-200'}">
                            ${hasPending ? '🟡 รอส่งมอบ (On-Demand)' : '🟢 จัดส่งสำเร็จ'}
                        </span>
                        <span class="font-black text-slate-900 text-sm">฿${(order.totalAmount || 0).toFixed(2)}</span>
                    </div>
                </div>

                <!-- Items in this order -->
                <div class="space-y-2">
                    ${(order.items || []).map((item, itemIdx) => {
            const isItemPending = !item.credentials || item.status === 'pending_fulfillment';
            const cred = item.credentials || {};

            return `
                            <div class="p-3 rounded-xl ${isItemPending ? 'bg-amber-50/70 border border-amber-200' : 'bg-slate-50 border border-slate-200'} flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                <div class="min-w-0 flex-1">
                                    <div class="flex items-center gap-2">
                                        <span class="font-normal text-xs sm:text-sm text-slate-900 truncate">${escapeHTML(item.productTitle)}</span>
                                        <span class="text-[10px] px-2 py-0.5 rounded-full font-bold ${isItemPending ? 'bg-amber-200 text-amber-900' : 'bg-emerald-100 text-emerald-800'}">
                                            ${isItemPending ? 'รอจัดส่ง' : 'จัดส่งแล้ว'}
                                        </span>
                                    </div>
                                    ${!isItemPending ? `
                                        <div class="mt-1 text-xs font-mono text-slate-600 flex flex-wrap items-center gap-2">
                                            ${cred.email ? `<span class="bg-white px-2 py-0.5 rounded border border-slate-200 text-pink-600">Email: <b>${escapeHTML(cred.email)}</b></span>` : ''}
                                            ${cred.password ? `<span class="bg-white px-2 py-0.5 rounded border border-slate-200 text-cyan-700">Pass: <b>${escapeHTML(cred.password)}</b></span>` : ''}
                                            ${cred.key ? `<span class="bg-white px-2 py-0.5 rounded border border-slate-200 text-emerald-700">Key: <b>${escapeHTML(cred.key)}</b></span>` : ''}
                                            ${cred.link ? `<span class="bg-white px-2 py-0.5 rounded border border-slate-200 text-cyan-700 truncate max-w-xs">Link: <b>${escapeHTML(cred.link)}</b></span>` : ''}
                                        </div>
                                    ` : `
                                        <div class="text-[11px] text-amber-700 font-medium mt-0.5">
                                            💡 ซื้อรหัสจาก G2G แล้วกดปุ่ม "ส่งมอบรหัส" ด้านขวา
                                        </div>
                                    `}
                                </div>

                                <div class="flex items-center gap-2 shrink-0">
                                    <button onclick="openG2GMarketLink('${escapeHTML(item.productId)}')" 
                                            class="px-3 py-1.5 rounded-xl bg-orange-100 hover:bg-orange-200 text-orange-900 text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm">
                                        <i class="fa-solid fa-cart-shopping"></i>
                                        <span>ไปซื้อใน G2G</span>
                                    </button>
                                    <button onclick="openFulfillModal('${escapeHTML(order.orderId)}', ${itemIdx})" 
                                            class="px-3.5 py-1.5 rounded-xl ${isItemPending ? 'gradient-btn text-white' : 'bg-slate-200 hover:bg-slate-300 text-slate-700'} text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm">
                                        <i class="fa-solid ${isItemPending ? 'fa-paper-plane' : 'fa-pen-to-square'}"></i>
                                        <span>${isItemPending ? 'ส่งมอบรหัส' : 'แก้ไขรหัส'}</span>
                                    </button>
                                </div>
                            </div>
                        `;
        }).join('')}
                </div>
            </div>
        `;
    }).join('');
}

function setFulfillType(type) {
    const accountFields = document.getElementById('fulfill-fields-account');
    const keyFields = document.getElementById('fulfill-fields-key');
    const btnAcc = document.getElementById('fulfill-type-account');
    const btnKey = document.getElementById('fulfill-type-key');
    const btnLink = document.getElementById('fulfill-type-link');

    [btnAcc, btnKey, btnLink].forEach(b => {
        if (b) b.className = "flex-1 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 transition-all flex items-center justify-center gap-1 font-bold";
    });

    if (type === 'account') {
        if (accountFields) accountFields.classList.remove('hidden');
        if (keyFields) keyFields.classList.add('hidden');
        if (btnAcc) btnAcc.className = "flex-1 py-1.5 rounded-lg bg-white text-pink-600 shadow-2xs font-bold transition-all flex items-center justify-center gap-1";
    } else if (type === 'key') {
        if (accountFields) accountFields.classList.add('hidden');
        if (keyFields) keyFields.classList.remove('hidden');
        const keyInput = document.getElementById('fulfill-key');
        if (keyInput) keyInput.placeholder = "กรอกรหัส License Key (เช่น W11PR-XXXX-XXXX)";
        if (btnKey) btnKey.className = "flex-1 py-1.5 rounded-lg bg-white text-pink-600 shadow-2xs font-bold transition-all flex items-center justify-center gap-1";
    } else if (type === 'link') {
        if (accountFields) accountFields.classList.add('hidden');
        if (keyFields) keyFields.classList.remove('hidden');
        const keyInput = document.getElementById('fulfill-key');
        if (keyInput) keyInput.placeholder = "กรอกลิงก์เปิดใช้งาน (เช่น https://families.google.com/join/...)";
        if (btnLink) btnLink.className = "flex-1 py-1.5 rounded-lg bg-white text-pink-600 shadow-2xs font-bold transition-all flex items-center justify-center gap-1";
    }
}

function autoFillDefaultInstruction(preset) {
    const input = document.getElementById('fulfill-instructions');
    if (!input) return;

    if (preset === 'standard') {
        input.value = "เข้าสู่ระบบและเริ่มใช้งานได้ทันที มีการรับประกันดูแลตลอดอายุการใช้งาน 30 วัน";
    } else if (preset === 'invite') {
        input.value = "คลิกลิงก์ด้านบนเพื่อเข้าร่วมกลุ่มครอบครัวและรับสิทธิ์ใช้งานในบัญชีของคุณทันที รับประกัน 30 วัน";
    }
    showToast("ใส่คำแนะนำสำเร็จรูปแล้ว", "info");
}

function openFulfillModal(orderId, itemIndex) {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("กรุณาเข้าสู่ระบบแอดมินก่อนดำเนินการ", "warning");
        promptAdminLogin();
        return;
    }

    const order = (adminOrdersList && adminOrdersList.find(o => o.orderId === orderId)) || (state.orders || []).find(o => o.orderId === orderId);
    if (!order || !order.items || !order.items[itemIndex]) {
        showToast("ไม่พบข้อมูลคำสั่งซื้อ", "warning");
        return;
    }

    const item = order.items[itemIndex];
    const modal = document.getElementById('admin-fulfill-modal');
    if (!modal) return;

    document.getElementById('fulfill-order-id').value = orderId;
    document.getElementById('fulfill-item-index').value = itemIndex;
    document.getElementById('fulfill-order-id-label').textContent = orderId;
    document.getElementById('fulfill-customer-email-label').textContent = order.recipientEmail || order.email || 'ลูกค้าหน้าร้าน';
    document.getElementById('fulfill-product-title-label').textContent = item.productTitle;

    const master = getMasterProduct(item.productId);
    const g2gRawTitleEl = document.getElementById('fulfill-g2g-raw-title-label');
    if (g2gRawTitleEl) {
        g2gRawTitleEl.textContent = (master && (master.g2gRawTitle || master.title)) || item.productTitle || '';
    }

    const g2gBtn = document.getElementById('fulfill-g2g-btn');
    if (g2gBtn) {
        g2gBtn.onclick = () => openG2GMarketLink(item.productId);
    }

    const cred = item.credentials || {};
    document.getElementById('fulfill-quick-paste').value = '';
    document.getElementById('fulfill-email').value = cred.email || '';
    document.getElementById('fulfill-password').value = cred.password || '';
    document.getElementById('fulfill-key').value = cred.key || cred.link || '';
    document.getElementById('fulfill-instructions').value = cred.instructions || 'เข้าสู่ระบบและเริ่มใช้งานได้ทันที รับประกัน 30 วัน';

    // Auto-detect mode based on item
    if (cred.email) {
        setFulfillType('account');
    } else if (cred.link) {
        setFulfillType('link');
    } else if (cred.key) {
        setFulfillType('key');
    } else {
        const prod = getMasterProduct(item.productId);
        if (prod && (prod.typeKey === 'key' || prod.brand === 'Microsoft')) {
            setFulfillType('key');
        } else if (prod && (prod.title.includes('Link') || prod.title.includes('Invite'))) {
            setFulfillType('link');
        } else {
            setFulfillType('account');
        }
    }

    modal.classList.remove('hidden');
}

function closeFulfillModal() {
    const modal = document.getElementById('admin-fulfill-modal');
    if (modal) modal.classList.add('hidden');
}

function copyFulfillG2GTitle() {
    const label = document.getElementById('fulfill-g2g-raw-title-label');
    const text = label ? label.textContent.trim() : '';
    if (text) {
        navigator.clipboard.writeText(text);
        showToast(`คัดลอกชื่อสินค้าสำหรับค้นหาใน G2G เรียบร้อย: "${text}"`, "info");
    }
}

function handleFulfillQuickPaste(val) {
    val = (val || '').trim();
    if (!val) return;

    if (val.includes(':')) {
        const parts = val.split(':');
        const email = parts[0].trim();
        const pass = parts.slice(1).join(':').trim();
        document.getElementById('fulfill-email').value = email;
        document.getElementById('fulfill-password').value = pass;
        setFulfillType('account');
        showToast("แยก Email และ Password ให้อัตโนมัติแล้ว", "info");
    } else if (val.startsWith('http://') || val.startsWith('https://')) {
        document.getElementById('fulfill-key').value = val;
        setFulfillType('link');
        showToast("ระบุเป็นลิงก์เปิดใช้งาน (Link) เรียบร้อย", "info");
    } else if (val.length > 5 && !val.includes(' ')) {
        document.getElementById('fulfill-key').value = val;
        setFulfillType('key');
        showToast("ระบุเป็น License Key เรียบร้อย", "info");
    }
}

async function handleFulfillSubmit(e) {
    e.preventDefault();

    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeFulfillModal();
        promptAdminLogin();
        return;
    }

    const orderId = document.getElementById('fulfill-order-id').value;
    const itemIndex = parseInt(document.getElementById('fulfill-item-index').value, 10);
    const email = document.getElementById('fulfill-email').value.trim();
    const password = document.getElementById('fulfill-password').value.trim();
    const key = document.getElementById('fulfill-key').value.trim();
    const instructions = document.getElementById('fulfill-instructions').value.trim() || 'เข้าสู่ระบบและเริ่มใช้งานได้ทันที รับประกัน 30 วัน';

    if (email && !password) {
        showToast("กรุณากรอกรหัสผ่าน (Password) ควบคู่กับ Email", "warning");
        return;
    }
    if (!email && password) {
        showToast("กรุณากรอก Email ควบคู่กับรหัสผ่าน (Password)", "warning");
        return;
    }
    if (!email && !password && !key) {
        showToast("กรุณากรอก Email:Password หรือรหัส License Key / ลิงก์ เพื่อส่งมอบ", "warning");
        return;
    }

    const order = (adminOrdersList && adminOrdersList.find(o => (o.orderId || '').trim().toUpperCase() === orderId.trim().toUpperCase()))
        || (state.orders || []).find(o => (o.orderId || '').trim().toUpperCase() === orderId.trim().toUpperCase());

    if (!order || !order.items || !order.items[itemIndex]) {
        showToast("ไม่พบคำสั่งซื้อหรือรายการสินค้า", "warning");
        return;
    }

    let cred = {};
    if (email && password) {
        cred = { email, password, instructions };
    } else if (key && (key.startsWith('http://') || key.startsWith('https://'))) {
        cred = { link: key, instructions };
    } else if (key) {
        cred = { key, instructions };
    } else {
        showToast("ข้อมูลการส่งมอบไม่สมบูรณ์", "warning");
        return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const origBtnText = submitBtn ? submitBtn.innerHTML : '';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> กำลังบันทึกและส่งมอบ...`;
    }

    // 1. Call backend fulfillment endpoint POST /api/admin/fulfill
    try {
        const res = await fetch('/api/admin/fulfill', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({
                orderId,
                itemIndex,
                credentials: cred,
                orderData: order // Supply local order data for server recovery if needed
            })
        });

        const data = await res.json().catch(() => null);

        if (res.ok && data && data.success && data.order) {
            const updatedOrder = data.order;

            // Update in adminOrdersList
            const aIdx = (adminOrdersList || []).findIndex(o => (o.orderId || '').toUpperCase() === orderId.toUpperCase());
            if (aIdx !== -1) adminOrdersList[aIdx] = updatedOrder;
            else adminOrdersList.unshift(updatedOrder);

            // Update in state.orders
            const sIdx = (state.orders || []).findIndex(o => (o.orderId || '').toUpperCase() === orderId.toUpperCase());
            if (sIdx !== -1) state.orders[sIdx] = updatedOrder;
            else (state.orders || []).unshift(updatedOrder);
            saveOrders();

            closeFulfillModal();
            renderAdminOrdersList();
            if (typeof updateAdminNavBadges === 'function') updateAdminNavBadges();

            if (state.currentVaultOrderId === orderId) {
                openVaultModal(updatedOrder);
            }
            const ordersModal = document.getElementById('orders-modal');
            if (ordersModal && !ordersModal.classList.contains('hidden')) {
                renderOrdersHistory();
            }

            showToast(`ส่งมอบรหัสให้คำสั่งซื้อ ${orderId} สำเร็จเรียบร้อย! (บันทึกเข้าระบบ & ส่งใบเสร็จแล้ว)`, "success");
            return;
        } else {
            console.error("[ADMIN] Fulfill server rejected request:", data);
            showToast(data?.message || "ไม่สามารถส่งมอบรหัสได้ กรุณาตรวจสอบสิทธิ์การเข้าถึงหรือข้อมูลคำสั่งซื้อ", "error");
            return;
        }
    } catch (apiErr) {
        console.warn("[ADMIN] Fulfill network error:", apiErr);
        // Offline / emergency local update
        const item = order.items[itemIndex];
        item.credentials = cred;
        item.status = 'delivered';
        const allDelivered = order.items.every(it => it.credentials && it.status !== 'pending_fulfillment');
        if (allDelivered) {
            order.status = "🟢 จัดส่งสำเร็จเรียบร้อย";
        }
        const aIdx = adminOrdersList.findIndex(o => o.orderId === orderId);
        if (aIdx !== -1) adminOrdersList[aIdx] = order;
        const sIdx = (state.orders || []).findIndex(o => o.orderId === orderId);
        if (sIdx !== -1) state.orders[sIdx] = order;
        saveOrders();
        closeFulfillModal();
        renderAdminOrdersList();
        if (typeof updateAdminNavBadges === 'function') updateAdminNavBadges();
        showToast(`บันทึกการส่งมอบในโหมดออฟไลน์แล้ว (จะซิงค์เมื่อเชื่อมต่อเซิร์ฟเวอร์)`, "warning");
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = origBtnText;
        }
    }
}

async function openAdminModal() {
    if (!ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }

    const modal = document.getElementById('admin-modal');
    if (!modal) return;

    const promptpayEl = document.getElementById('admin-promptpay-input');
    if (promptpayEl) promptpayEl.value = STORE_CONFIG.promptPayNumber || '';

    const accNameEl = document.getElementById('admin-account-name');
    if (accNameEl) accNameEl.value = STORE_CONFIG.promptPayAccountName || 'สุพัฒน์ มีสมบัติ';

    const branchEl = document.getElementById('admin-slipok-branch');
    if (branchEl) branchEl.value = STORE_CONFIG.slipOkBranchId || '77491';

    const slipOkKeyEl = document.getElementById('admin-slipok-apikey') || document.getElementById('admin-slipok-key');
    if (slipOkKeyEl) slipOkKeyEl.value = STORE_CONFIG.slipOkApiKey || '';

    const pinInput = document.getElementById('admin-new-pin');
    if (pinInput) pinInput.value = '';
    const confirmPinInput = document.getElementById('admin-confirm-new-pin');
    if (confirmPinInput) confirmPinInput.value = '';

    if (typeof loadAdminSettingsIntoForm === 'function') {
        loadAdminSettingsIntoForm();
    }
    if (typeof updateAdminNavBadges === 'function') {
        updateAdminNavBadges();
    }

    renderAdminStockList();
    switchAdminTab('orders');
    modal.classList.remove('hidden');

    // Fetch orders from server and start live auto-refresh
    await renderAdminOrdersList(true);
    startAdminOrdersAutoRefresh();
}

function closeAdminModal() {
    const modal = document.getElementById('admin-modal');
    if (modal) modal.classList.add('hidden');
    stopAdminOrdersAutoRefresh();
    if (typeof stopAdminAnalyticsAutoRefresh === 'function') {
        stopAdminAnalyticsAutoRefresh();
    }
}


async function triggerManualAutoSync() {
    const syncBtn = document.querySelector('button[onclick="triggerManualAutoSync()"]');
    if (syncBtn) {
        syncBtn.classList.add('opacity-75', 'pointer-events-none');
    }
    try {
        if (typeof G2G_SYNC !== 'undefined' && typeof G2G_SYNC.performAutoSync === 'function') {
            await G2G_SYNC.performAutoSync();
            renderAdminStockList();
            renderProducts();
            showToast("ซิงค์ราคา สต็อก และชื่อค้นหา G2G ล่าสุดสำเร็จแล้ว!", "success");
        } else {
            syncStockCount();
            renderAdminStockList();
            renderProducts();
            showToast("รีเฟรชสต็อกสินค้าเรียบร้อยแล้ว", "info");
        }
    } finally {
        if (syncBtn) {
            syncBtn.classList.remove('opacity-75', 'pointer-events-none');
        }
    }
}

function handleAdminStockSearch(val) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    adminStockSearchQuery = (val || '').toLowerCase().trim();
    const clearBtn = document.getElementById('admin-stock-clear-search');
    if (clearBtn) {
        if (adminStockSearchQuery) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
    }
    renderAdminStockList();
}

function clearAdminStockSearch() {
    const input = document.getElementById('admin-stock-search');
    if (input) input.value = '';
    const clearBtn = document.getElementById('admin-stock-clear-search');
    if (clearBtn) clearBtn.classList.add('hidden');
    adminStockSearchQuery = '';
    renderAdminStockList();
}

function filterAdminStockBrand(brand) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    adminStockBrandFilter = brand;
    const chips = ['all', 'highlight', 'CapCut', 'Google AI', 'Google', 'Grok', 'Claude', 'Adobe', 'Microsoft', 'deleted'];
    chips.forEach(c => {
        const chipId = c === 'Google AI' ? 'admin-stock-chip-Google-AI' : `admin-stock-chip-${c}`;
        const btn = document.getElementById(chipId);
        if (btn) {
            const matches = (c === brand);
            if (matches) {
                if (c === 'deleted') {
                    btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-rose-600 text-white transition-all shrink-0 flex items-center gap-1 shadow-2xs";
                } else if (c === 'highlight') {
                    btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-amber-500 text-white transition-all shrink-0 flex items-center gap-1 shadow-2xs";
                } else {
                    btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-pink-100 text-pink-700 transition-all shrink-0 shadow-2xs";
                }
            } else {
                if (c === 'deleted') {
                    btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-slate-100 hover:bg-rose-100 text-slate-600 hover:text-rose-700 transition-all shrink-0 flex items-center gap-1";
                } else if (c === 'highlight') {
                    btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-slate-100 hover:bg-amber-100 text-slate-700 hover:text-amber-800 transition-all shrink-0 flex items-center gap-1";
                } else {
                    btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 transition-all shrink-0";
                }
            }
        }
    });
    renderAdminStockList();
}

function renderAdminStockList() {
    const container = document.getElementById('admin-stock-table');
    if (!container) return;

    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        container.innerHTML = `
            <tr>
                <td colspan="6" class="py-12 text-center text-rose-500 text-xs font-bold bg-rose-50/50">
                    <i class="fa-solid fa-lock text-rose-400 text-xl mb-2 block"></i>
                    กรุณาเข้าสู่ระบบหลังร้านเพื่อดูและจัดการสต็อกสินค้า
                </td>
            </tr>
        `;
        return;
    }

    const allMasterProds = typeof getAllMasterProducts === 'function' ? getAllMasterProducts(true) : state.products;

    // Update deleted badge count
    const deletedCount = allMasterProds.filter(p => !!p.deleted).length;
    const deletedCountEl = document.getElementById('admin-deleted-count');
    if (deletedCountEl) deletedCountEl.textContent = deletedCount;

    let prods = [];
    if (adminStockBrandFilter === 'deleted') {
        prods = allMasterProds.filter(p => !!p.deleted);
    } else if (adminStockBrandFilter === 'highlight') {
        prods = allMasterProds.filter(p => !p.deleted && !!p.isHighlight);
    } else if (adminStockBrandFilter === 'all') {
        prods = allMasterProds.filter(p => !p.deleted);
    } else {
        prods = allMasterProds.filter(p => !p.deleted && (
            (p.brand || '').toLowerCase() === adminStockBrandFilter.toLowerCase() ||
            (adminStockBrandFilter === 'Google' && p.brand === 'Google') ||
            (adminStockBrandFilter === 'Google AI' && p.brand === 'Google AI')
        ));
    }

    if (adminStockSearchQuery) {
        prods = prods.filter(p =>
            (p.title || '').toLowerCase().includes(adminStockSearchQuery) ||
            (p.brand || '').toLowerCase().includes(adminStockSearchQuery) ||
            (p.type || '').toLowerCase().includes(adminStockSearchQuery) ||
            (p.id || '').toLowerCase().includes(adminStockSearchQuery)
        );
    }

    const countEl = document.getElementById('admin-stock-count');
    if (countEl) countEl.textContent = prods.length;

    if (prods.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="6" class="py-12 text-center text-slate-400 text-xs font-medium">
                    <i class="fa-solid fa-magnifying-glass mb-2 text-slate-300 text-2xl block"></i>
                    ไม่พบรายการสินค้าที่ตรงกับเงื่อนไขการค้นหา
                    ${adminStockSearchQuery ? `<br><button onclick="clearAdminStockSearch()" class="mt-2 text-pink-600 font-bold hover:underline cursor-pointer">ล้างคำค้นหา</button>` : ''}
                </td>
            </tr>
        `;
        return;
    }

    const customPrices = getCustomPrices();

    container.innerHTML = prods.map(p => {
        const master = getMasterProduct(p.id) || p;
        const pool = state.inventory[p.id] || [];
        const marketStock = customPrices[p.id]?.g2gStockAvailable
            ?? (typeof G2G_MARKET_FEED !== 'undefined' ? G2G_MARKET_FEED.benchmarks[p.id]?.g2gStock : 50)
            ?? 50;

        const g2gBenchmark = typeof G2G_MARKET_FEED !== 'undefined' ? G2G_MARKET_FEED.benchmarks[p.id] : null;
        const costTHB = (customPrices[p.id] && customPrices[p.id].marketCostTHB)
            || (g2gBenchmark ? Math.round(g2gBenchmark.baseCostUSD * 36.50 * 100) / 100 : 0);

        const profit = master.price - costTHB;
        const profitPct = master.price > 0 ? ((profit / master.price) * 100).toFixed(0) : 0;
        const isManual = customPrices[p.id]?.manualOverride === true;
        const isDeleted = master.deleted === true;

        return `
            <tr class="border-b border-slate-100 hover:bg-slate-50/80 text-xs font-medium transition-colors group ${isDeleted ? 'bg-rose-50/30' : ''}">
                <!-- 1. รายการสินค้า -->
                <td class="py-3 px-3.5">
                    <div class="flex items-center gap-3">
                        <div onclick="openEditPriceModal('${p.id}', 'title')" 
                             title="คลิกเพื่อแก้ไขข้อมูลสินค้า"
                             class="relative w-11 h-11 rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center font-black text-xs text-pink-600 shrink-0 cursor-pointer shadow-2xs hover:border-pink-400 hover:bg-pink-100 transition-all">
                            ${escapeHTML(master.brandCode || 'AI')}
                        </div>
                        <div class="min-w-0 flex-1">
                            <div onclick="openEditPriceModal('${p.id}', 'title')"
                                 title="คลิกเพื่อแก้ไขข้อมูลสินค้า"
                                 class="font-normal text-slate-900 text-xs sm:text-sm hover:text-pink-600 cursor-pointer transition-colors line-clamp-1 flex items-center gap-1.5">
                                <span>${escapeHTML(master.title)}</span>
                                <i class="fa-solid fa-pen-to-square text-[10px] text-slate-300 hover:text-pink-500 opacity-60 hover:opacity-100"></i>
                            </div>
                            <div class="flex flex-wrap items-center gap-1.5 mt-1">
                                <span class="text-[10px] px-2 py-0.5 rounded-full font-bold bg-pink-50 text-pink-700 border border-pink-200">
                                    ${escapeHTML(master.brand)}
                                </span>
                                <span class="text-[10px] text-slate-500 font-medium">
                                    ${escapeHTML(master.type)}
                                </span>
                                <span class="text-[10px] px-2 py-0.5 rounded-full font-bold ${isManual ? 'bg-amber-50 text-amber-800 border border-amber-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'}">
                                    ${isManual ? '🟡 ตั้งเอง' : '🟢 Auto-Sync'}
                                </span>
                                ${master.isHighlight ? '<span class="text-[10px] px-2 py-0.5 rounded-full font-bold bg-amber-100 text-amber-800 border border-amber-300">⭐ ไฮไลท์</span>' : ''}
                                ${isDeleted ? '<span class="text-[10px] px-2 py-0.5 rounded-full font-bold bg-rose-100 text-rose-700 border border-rose-300">🗑️ ลบแล้ว</span>' : ''}
                            </div>
                        </div>
                    </div>
                </td>

                <!-- 2. ต้นทุนตลาด G2G -->
                <td class="py-3 px-3 text-center">
                    <div class="font-bold text-slate-700 text-xs font-mono">฿${costTHB.toFixed(2)}</div>
                    <div class="flex items-center justify-center gap-1 mt-1">
                        ${(() => {
                const effectiveG2GUrl = getG2GMarketLink(p.id);
                return `
                            <a href="${sanitizeUrl(effectiveG2GUrl)}" target="_blank" rel="noopener noreferrer"
                               onclick="handleG2GSourcingClick(event, '${escapeHTML(p.id)}', '${sanitizeUrl(effectiveG2GUrl)}')"
                               class="px-2 py-0.5 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300 text-[10px] font-bold transition-all flex items-center gap-1 shadow-2xs hover:scale-105 active:scale-95"
                               title="เปิดดูแหล่งต้นทุนและสั่งซื้อบน G2G">
                                <i class="fa-solid fa-cart-shopping text-[9px] text-amber-600"></i>
                                <span>ซื้อ G2G ↗</span>
                            </a>
                            `;
            })()}
                        <button type="button" 
                                onclick="const t = '${escapeHTML(master.g2gRawTitle || master.title)}'; navigator.clipboard.writeText(t); showToast('คัดลอกชื่อภาษาอังกฤษสำหรับค้นหาใน G2G แล้ว: ' + t.slice(0, 32) + '...', 'info');"
                                class="p-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-500 hover:text-slate-800 border border-slate-200 text-[10px] cursor-pointer"
                                title="คัดลอกชื่อสินค้าภาษาอังกฤษของ G2G">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>
                </td>

                <!-- 3. ราคาขายหน้าร้าน (Click to Edit) -->
                <td class="py-3 px-3 text-center">
                    <div onclick="openEditPriceModal('${p.id}', 'price')"
                         title="คลิกเพื่อแก้ไขราคาขายทันที"
                         class="cursor-pointer py-1 px-2.5 rounded-xl hover:bg-pink-50 border border-transparent hover:border-pink-200 transition-all inline-block group/price">
                        <div class="font-black text-pink-600 text-sm font-mono flex items-center justify-center gap-1">
                            <span>฿${master.price.toFixed(2)}</span>
                            <i class="fa-solid fa-pen text-[9px] text-pink-400 opacity-0 group-hover/price:opacity-100 transition-opacity"></i>
                        </div>
                        <div class="text-[10px] text-slate-400 line-through font-mono">฿${master.originalPrice.toFixed(2)}</div>
                    </div>
                </td>

                <!-- 4. กำไรโดยประมาณ -->
                <td class="py-3 px-3 text-center">
                    <span class="inline-flex items-center px-2 py-1 rounded-xl text-xs font-black font-mono ${profit >= 0 ? 'text-emerald-700 bg-emerald-50 border border-emerald-200' : 'text-rose-700 bg-rose-50 border border-rose-200'}">
                        ${profit >= 0 ? '+' : ''}฿${profit.toFixed(2)} (${profitPct}%)
                    </span>
                </td>

                <!-- 5. คงเหลือ (คลัง / ตลาด) -->
                <td class="py-3 px-3 text-center">
                    <div class="flex flex-col items-center gap-1">
                        <button type="button" onclick="openAddStockModal('${p.id}')"
                                class="px-2.5 py-0.5 rounded-full text-[11px] font-bold cursor-pointer transition-all hover:scale-105 active:scale-95 ${pool.length > 0 ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-rose-50 text-rose-700 border border-rose-200'}"
                                title="คลิกเพื่อเติมสต็อกคลัง">
                            คลัง: ${pool.length} ${pool.length === 0 ? '(หมด)' : ''}
                        </button>
                        <span class="text-[10px] text-slate-500 font-medium">
                            ตลาด: <b class="text-cyan-700 font-mono">${marketStock}</b>
                        </span>
                    </div>
                </td>

                <!-- 6. การจัดการ (Sticky Right Column - NEVER CUT OFF) -->
                <td class="py-3 px-4 text-right sticky right-0 bg-white group-hover:bg-slate-50 border-b border-slate-100 shadow-[-6px_0_12px_-4px_rgba(0,0,0,0.06)] z-10 min-w-[250px] transition-colors">
                    <div class="flex items-center justify-end gap-1.5 whitespace-nowrap">
                        ${!isDeleted ? `
                        <!-- Restock Button -->
                        <button type="button" onclick="openAddStockModal('${p.id}')"
                                class="h-8.5 px-2.5 sm:px-3 rounded-xl bg-gradient-to-r from-pink-500 to-rose-500 hover:from-pink-600 hover:to-rose-600 text-white text-xs font-bold transition-all shadow-2xs hover:shadow-xs flex items-center gap-1 cursor-pointer active:scale-95 shrink-0"
                                title="เติมสต็อกสินค้า">
                            <i class="fa-solid fa-plus text-[11px]"></i>
                            <span>เติมสต็อก</span>
                        </button>

                        <!-- Edit Button -->
                        <button type="button" onclick="openEditPriceModal('${p.id}')"
                                class="h-8.5 px-2.5 sm:px-3 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-slate-900 border border-slate-200 hover:border-slate-300 text-xs font-bold transition-all flex items-center gap-1 cursor-pointer active:scale-95 shrink-0 shadow-2xs"
                                title="แก้ไขข้อมูลสินค้าและราคา">
                            <i class="fa-regular fa-pen-to-square text-[11px] text-slate-500"></i>
                            <span>แก้ไข</span>
                        </button>

                        <!-- Delete Button: Clear, Comfortable Hit Size, Soft Rose Style -->
                        <button type="button" onclick="handleDeleteProduct('${p.id}')"
                                class="h-8.5 px-2.5 sm:px-3 rounded-xl bg-rose-50 hover:bg-rose-600 text-rose-600 hover:text-white border border-rose-200 hover:border-rose-600 text-xs font-bold transition-all flex items-center gap-1 cursor-pointer active:scale-95 shrink-0 shadow-2xs group/del"
                                title="ลบสินค้านี้ออกจากระบบ">
                            <i class="fa-solid fa-trash-can text-[11px] text-rose-500 group-hover/del:text-white transition-colors"></i>
                            <span>ลบ</span>
                        </button>
                        ` : `
                        <!-- Restore Button -->
                        <button type="button" onclick="handleRestoreProduct('${p.id}')"
                                class="h-8.5 px-3 rounded-xl bg-emerald-50 hover:bg-emerald-600 text-emerald-700 hover:text-white border border-emerald-300 hover:border-emerald-600 text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 shadow-2xs shrink-0"
                                title="กู้คืนสินค้านี้กลับมาแสดงหน้าร้าน">
                            <i class="fa-solid fa-rotate-left text-[11px]"></i>
                            <span>กู้คืน</span>
                        </button>
                        `}
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// Edit Price & Product Modal Handlers
function openEditPriceModal(productId, focusField = null) {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("กรุณาเข้าสู่ระบบแอดมินก่อนดำเนินการ", "warning");
        promptAdminLogin();
        return;
    }

    const master = getMasterProduct(productId);
    if (!master) return;

    const modal = document.getElementById('edit-price-modal');
    if (!modal) return;

    document.getElementById('edit-price-product-id').value = productId;
    const isNewInput = document.getElementById('edit-product-is-new');
    if (isNewInput) isNewInput.value = '0';

    const modalTitle = document.getElementById('edit-product-modal-title');
    if (modalTitle) modalTitle.textContent = "จัดการข้อมูลสินค้า & ราคา";

    const prodTitleDisplay = document.getElementById('edit-price-product-title');
    if (prodTitleDisplay) prodTitleDisplay.textContent = master.title;

    const prodIdDisplay = document.getElementById('edit-product-id-display');
    if (prodIdDisplay) prodIdDisplay.textContent = `ID: ${master.id}`;

    // Fill Product Info
    const titleInput = document.getElementById('edit-product-title-input');
    if (titleInput) titleInput.value = master.title || '';

    const subtitleInput = document.getElementById('edit-product-subtitle-input');
    if (subtitleInput) subtitleInput.value = master.subtitle || '';

    const brandInput = document.getElementById('edit-product-brand-input');
    if (brandInput) brandInput.value = master.brand || '';

    const typeInput = document.getElementById('edit-product-type-input');
    if (typeInput) typeInput.value = master.type || '';

    const durationInput = document.getElementById('edit-product-duration-input');
    if (durationInput) durationInput.value = master.duration || '';

    const devicesInput = document.getElementById('edit-product-devices-input');
    if (devicesInput) devicesInput.value = master.devices || '';

    const warrantyInput = document.getElementById('edit-product-warranty-input');
    if (warrantyInput) warrantyInput.value = master.warranty || '';

    const descInput = document.getElementById('edit-product-desc-input');
    if (descInput) descInput.value = master.description || '';

    // G2G Raw Title & URL
    const g2gRawTitleEl = document.getElementById('edit-price-g2g-raw-title');
    if (g2gRawTitleEl) g2gRawTitleEl.textContent = master.g2gRawTitle || master.title;

    const g2gUrlInput = document.getElementById('edit-price-g2g-url');
    if (g2gUrlInput) {
        const rawUrl = master.g2gUrl || '';
        g2gUrlInput.value = (typeof isBrokenOrLegacyG2GUrl === 'function' && isBrokenOrLegacyG2GUrl(rawUrl)) ? '' : rawUrl;
    }

    // Price Inputs
    const saleInput = document.getElementById('edit-price-sale');
    if (saleInput) saleInput.value = master.price;

    const origInput = document.getElementById('edit-price-original');
    if (origInput) origInput.value = master.originalPrice;

    // Badge & Highlight
    const badgeInput = document.getElementById('edit-price-badge');
    if (badgeInput) badgeInput.value = master.badge || '';

    const highlightCheck = document.getElementById('edit-product-is-highlight');
    if (highlightCheck) highlightCheck.checked = !!master.isHighlight;

    const btnDelete = document.getElementById('btn-delete-product');
    if (btnDelete) btnDelete.classList.remove('hidden');

    updateEditPricePreview();
    modal.classList.remove('hidden');

    // Auto focus and select input according to focusField
    setTimeout(() => {
        if (focusField === 'price' && saleInput) {
            saleInput.focus();
            saleInput.select();
        } else if (focusField === 'title' && titleInput) {
            titleInput.focus();
            titleInput.select();
        }
    }, 60);
}

function openAddNewProductModal() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("กรุณาเข้าสู่ระบบแอดมินก่อนดำเนินการ", "warning");
        promptAdminLogin();
        return;
    }

    const modal = document.getElementById('edit-price-modal');
    if (!modal) return;

    const newId = `prod-${Date.now().toString(36)}`;
    document.getElementById('edit-price-product-id').value = newId;

    const isNewInput = document.getElementById('edit-product-is-new');
    if (isNewInput) isNewInput.value = '1';

    const modalTitle = document.getElementById('edit-product-modal-title');
    if (modalTitle) modalTitle.textContent = "เพิ่มสินค้าใหม่เข้าสู่ระบบ";

    const prodTitleDisplay = document.getElementById('edit-price-product-title');
    if (prodTitleDisplay) prodTitleDisplay.textContent = "สินค้าใหม่";

    const prodIdDisplay = document.getElementById('edit-product-id-display');
    if (prodIdDisplay) prodIdDisplay.textContent = `ID ใหม่: ${newId}`;

    const titleInput = document.getElementById('edit-product-title-input');
    if (titleInput) titleInput.value = '';

    const subtitleInput = document.getElementById('edit-product-subtitle-input');
    if (subtitleInput) subtitleInput.value = '';

    const brandInput = document.getElementById('edit-product-brand-input');
    if (brandInput) brandInput.value = 'AI Tools';

    const typeInput = document.getElementById('edit-product-type-input');
    if (typeInput) typeInput.value = 'บัญชีส่วนตัว (Private)';

    const durationInput = document.getElementById('edit-product-duration-input');
    if (durationInput) durationInput.value = '1 เดือน (30 วัน)';

    const devicesInput = document.getElementById('edit-product-devices-input');
    if (devicesInput) devicesInput.value = 'iOS • Android • PC';

    const warrantyInput = document.getElementById('edit-product-warranty-input');
    if (warrantyInput) warrantyInput.value = '30 วัน';

    const descInput = document.getElementById('edit-product-desc-input');
    if (descInput) descInput.value = '• บัญชีแท้ใช้งานได้ทันที 100%\n• รับประกันตลอดอายุการใช้งานตามเงื่อนไข';

    const g2gRawTitleEl = document.getElementById('edit-price-g2g-raw-title');
    if (g2gRawTitleEl) g2gRawTitleEl.textContent = 'ยังไม่ได้เชื่อมต่อ G2G';

    const g2gUrlInput = document.getElementById('edit-price-g2g-url');
    if (g2gUrlInput) g2gUrlInput.value = '';

    const saleInput = document.getElementById('edit-price-sale');
    if (saleInput) saleInput.value = 99;

    const origInput = document.getElementById('edit-price-original');
    if (origInput) origInput.value = 199;

    const badgeInput = document.getElementById('edit-price-badge');
    if (badgeInput) badgeInput.value = '🔥 มาใหม่';

    const highlightCheck = document.getElementById('edit-product-is-highlight');
    if (highlightCheck) highlightCheck.checked = false;

    const btnDelete = document.getElementById('btn-delete-product');
    if (btnDelete) btnDelete.classList.add('hidden');

    updateEditPricePreview();
    modal.classList.remove('hidden');

    setTimeout(() => {
        if (titleInput) titleInput.focus();
    }, 60);
}

function updateEditPricePreview() {
    const productId = document.getElementById('edit-price-product-id').value;
    const saleVal = parseFloat(document.getElementById('edit-price-sale').value) || 0;
    const customPrices = getCustomPrices();

    const g2gBenchmark = typeof G2G_MARKET_FEED !== 'undefined' ? G2G_MARKET_FEED.benchmarks[productId] : null;
    const costTHB = (customPrices[productId] && customPrices[productId].marketCostTHB)
        || (g2gBenchmark ? Math.round(g2gBenchmark.baseCostUSD * 36.50 * 100) / 100 : 0);

    const costEl = document.getElementById('edit-price-cost-preview');
    if (costEl) costEl.textContent = `฿${costTHB.toFixed(2)}`;

    const autoCalcEl = document.getElementById('edit-price-auto-calc-preview');
    if (autoCalcEl) {
        const recPrice = Math.max(29, Math.round(costTHB * 1.55));
        autoCalcEl.textContent = `฿${recPrice.toFixed(2)}`;
    }

    const margin = saleVal - costTHB;
    const marginPct = saleVal > 0 ? ((margin / saleVal) * 100).toFixed(1) : 0;
    const marginEl = document.getElementById('edit-price-margin-preview');
    if (marginEl) {
        if (margin >= 0) {
            marginEl.className = "font-black text-emerald-600";
            marginEl.textContent = `+฿${margin.toFixed(2)} (${marginPct}%)`;
        } else {
            marginEl.className = "font-black text-rose-600";
            marginEl.textContent = `-฿${Math.abs(margin).toFixed(2)} (${marginPct}%) [ขาดทุน]`;
        }
    }

    const badgeEl = document.getElementById('edit-price-status-badge');
    if (badgeEl) {
        const isManual = customPrices[productId]?.manualOverride === true;
        badgeEl.textContent = isManual ? "🟡 ราคาตั้งเอง (Manual Override)" : "🟢 ราคาตลาด Auto-Sync อัจฉริยะ";
        badgeEl.className = isManual ? "font-bold text-amber-600" : "font-bold text-emerald-600";
    }
}

function applyRecommendedAutoPriceToInput() {
    const autoCalcEl = document.getElementById('edit-price-auto-calc-preview');
    if (!autoCalcEl) return;
    const cleanNum = parseFloat(autoCalcEl.textContent.replace(/[^\d.]/g, ''));
    if (!isNaN(cleanNum)) {
        const saleInput = document.getElementById('edit-price-sale');
        if (saleInput) {
            saleInput.value = cleanNum;
            updateEditPricePreview();
            showToast(`นำราคาแนะนำ ฿${cleanNum.toFixed(2)} มาใส่เรียบร้อยแล้ว`, "info");
        }
    }
}

function setEditBadgePreset(badgeText) {
    const input = document.getElementById('edit-price-badge');
    if (input) {
        input.value = badgeText;
        showToast(badgeText ? `ตั้งป้ายกำกับ: "${badgeText}"` : "ล้างป้ายกำกับแล้ว", "info");
    }
}

async function handleResetToAutoPrice() {
    const productId = document.getElementById('edit-price-product-id').value;
    if (!productId) return;

    const customPrices = getCustomPrices();
    if (customPrices[productId]) {
        delete customPrices[productId].manualOverride;
        delete customPrices[productId].lastManualUpdate;
        localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));
    }

    const customProducts = getCustomProducts();
    if (customProducts[productId] && customProducts[productId].price !== undefined) {
        const isBuiltin = typeof PRODUCTS !== 'undefined' && PRODUCTS.some(p => p.id === productId);
        if (isBuiltin) {
            delete customProducts[productId].price;
            delete customProducts[productId].originalPrice;
            localStorage.setItem('supinkly_custom_products', JSON.stringify(customProducts));
        }
    }

    if (window.location.protocol.startsWith('http')) {
        try {
            await fetch('/api/admin/price', {
                method: 'POST',
                headers: getAdminHeaders(),
                body: JSON.stringify({ productId, action: 'reset' })
            });
        } catch (e) {
            console.warn('[ADMIN SYNC] Could not reset price on server:', e.message);
        }
    }

    if (typeof G2G_SYNC !== 'undefined') {
        G2G_SYNC.performAutoSync();
    } else {
        syncStockCount();
    }

    const updatedMaster = getMasterProduct(productId);
    if (updatedMaster) {
        document.getElementById('edit-price-sale').value = updatedMaster.price;
        document.getElementById('edit-price-original').value = updatedMaster.originalPrice;
    }
    updateEditPricePreview();
    renderAdminStockList();
    showToast("คืนค่าราคาสินค้าเป็นระบบ Auto-Sync ตลาดอัตโนมัติแล้ว", "success");
}

function closeEditPriceModal() {
    const modal = document.getElementById('edit-price-modal');
    if (modal) modal.classList.add('hidden');
}

async function handleSaveEditedProduct() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeEditPriceModal();
        promptAdminLogin();
        return;
    }

    const productId = document.getElementById('edit-price-product-id').value;
    const isNew = document.getElementById('edit-product-is-new')?.value === '1';

    const titleInput = document.getElementById('edit-product-title-input');
    const titleVal = titleInput ? titleInput.value.trim() : '';

    if (!titleVal) {
        showToast("กรุณากรอกชื่อสินค้า", "warning");
        if (titleInput) titleInput.focus();
        return;
    }

    const subtitleVal = (document.getElementById('edit-product-subtitle-input')?.value || '').trim();
    const brandVal = (document.getElementById('edit-product-brand-input')?.value || 'AI Tools').trim();
    const typeVal = (document.getElementById('edit-product-type-input')?.value || 'บัญชีส่วนตัว (Private)').trim();
    const durationVal = (document.getElementById('edit-product-duration-input')?.value || '1 เดือน (30 วัน)').trim();
    const devicesVal = (document.getElementById('edit-product-devices-input')?.value || 'iOS • PC').trim();
    const warrantyVal = (document.getElementById('edit-product-warranty-input')?.value || '30 วัน').trim();
    const descVal = (document.getElementById('edit-product-desc-input')?.value || '').trim();
    const rawG2GUrlVal = (document.getElementById('edit-price-g2g-url')?.value || '').trim();
    const g2gUrlVal = (typeof isBrokenOrLegacyG2GUrl === 'function' && isBrokenOrLegacyG2GUrl(rawG2GUrlVal)) ? '' : rawG2GUrlVal;

    const saleVal = parseFloat(document.getElementById('edit-price-sale').value);
    const origVal = parseFloat(document.getElementById('edit-price-original').value);
    const badgeVal = (document.getElementById('edit-price-badge')?.value || '').trim();
    const isHighlight = !!document.getElementById('edit-product-is-highlight')?.checked;

    if (isNaN(saleVal) || saleVal < 0) {
        showToast("กรุณากรอกราคาขายที่ถูกต้อง", "warning");
        document.getElementById('edit-price-sale')?.focus();
        return;
    }

    const nowIso = new Date().toISOString();
    const finalPrice = Math.round(saleVal * 100) / 100;
    const finalOrigPrice = isNaN(origVal) || origVal < saleVal ? finalPrice : Math.round(origVal * 100) / 100;

    // 1. Save custom products metadata locally
    const customProducts = getCustomProducts();
    customProducts[productId] = {
        ...(customProducts[productId] || {}),
        id: productId,
        title: titleVal,
        subtitle: subtitleVal,
        brand: brandVal,
        type: typeVal,
        duration: durationVal,
        devices: devicesVal,
        warranty: warrantyVal,
        description: descVal,
        badge: badgeVal,
        isHighlight: isHighlight,
        price: finalPrice,
        originalPrice: finalOrigPrice,
        g2gUrl: g2gUrlVal,
        deleted: false,
        updatedAt: nowIso
    };
    localStorage.setItem('supinkly_custom_products', JSON.stringify(customProducts));

    // 2. Save custom price overrides locally
    const customPrices = getCustomPrices();
    customPrices[productId] = {
        ...(customPrices[productId] || {}),
        price: finalPrice,
        originalPrice: finalOrigPrice,
        badge: badgeVal,
        isHighlight: isHighlight,
        g2gUrl: g2gUrlVal,
        manualOverride: true,
        lastManualUpdate: nowIso,
        updatedAt: nowIso
    };
    localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));

    // 3. Synchronize with backend server (so checkout & receipt verification get real updated price)
    if (window.location.protocol.startsWith('http')) {
        try {
            const productPayload = {
                id: productId,
                title: titleVal,
                subtitle: subtitleVal,
                description: descVal,
                brand: brandVal,
                type: typeVal,
                duration: durationVal,
                devices: devicesVal,
                warranty: warrantyVal,
                price: finalPrice,
                originalPrice: finalOrigPrice,
                badge: badgeVal,
                isHighlight: isHighlight,
                g2gUrl: g2gUrlVal
            };

            let res = await fetch('/api/admin/product', {
                method: 'POST',
                headers: getAdminHeaders(),
                body: JSON.stringify(productPayload)
            });

            if (res.status === 401 || res.status === 403) {
                // Try refreshing admin token using stored PIN
                const pin = sessionStorage.getItem('supinkly_admin_pin') || localStorage.getItem('supinkly_admin_pin') || '';
                if (pin) {
                    try {
                        const loginRes = await fetch('/api/admin/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ pin })
                        });
                        if (loginRes.ok) {
                            const d = await loginRes.json();
                            if (d && d.token) {
                                sessionStorage.setItem('supinkly_admin_server_token', d.token);
                                localStorage.setItem('supinkly_admin_server_token', d.token);
                                res = await fetch('/api/admin/product', {
                                    method: 'POST',
                                    headers: getAdminHeaders(),
                                    body: JSON.stringify(productPayload)
                                });
                            }
                        }
                    } catch (e) { }
                }
            }

            // Also explicitly sync price override to ensure customPrices is recorded
            await fetch('/api/admin/price', {
                method: 'POST',
                headers: getAdminHeaders(),
                body: JSON.stringify({
                    productId: productId,
                    price: finalPrice,
                    originalPrice: finalOrigPrice,
                    badge: badgeVal,
                    g2gUrl: g2gUrlVal
                })
            }).catch(() => { });

        } catch (syncErr) {
            console.warn('[ADMIN SYNC] Could not sync product to server:', syncErr.message);
        }
    }

    // 4. Reload application catalog
    state.products = getAllMasterProducts(false).map(p => ({
        ...p,
        stock: p.stock || 0
    }));
    applyCustomPricesToProducts();
    syncStockCount();
    applyFilters();
    updateCartUI();
    renderProducts();
    renderAdminStockList();
    closeEditPriceModal();

    showToast(isNew ? `เพิ่มสินค้า "${titleVal}" สำเร็จ!` : `บันทึกข้อมูลสินค้า "${titleVal}" เรียบร้อยแล้ว`, "success");
}

function handleSaveEditedPrice() {
    handleSaveEditedProduct();
}

function handleDeleteProduct(productId) {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        promptAdminLogin();
        return;
    }

    const master = getMasterProduct(productId);
    const title = master ? master.title : productId;

    if (!confirm(`คุณต้องการลบสินค้า "${title}" ใช่หรือไม่?\n\n(สินค้านี้จะไม่แสดงหน้าร้าน แต่คุณสามารถกู้คืนได้จากแท็บ "ที่ลบแล้ว")`)) {
        return;
    }

    const customProducts = getCustomProducts();
    customProducts[productId] = {
        ...(customProducts[productId] || {}),
        id: productId,
        title: title,
        deleted: true,
        deletedAt: new Date().toISOString()
    };
    localStorage.setItem('supinkly_custom_products', JSON.stringify(customProducts));

    if (window.location.protocol.startsWith('http')) {
        try {
            fetch('/api/admin/product/delete', {
                method: 'POST',
                headers: getAdminHeaders(),
                body: JSON.stringify({ productId })
            }).catch(() => { });
        } catch (e) { }
    }

    // Remove from active cart if customer has it
    state.cart = state.cart.filter(item => item.productId !== productId);
    localStorage.setItem('supinkly_cart', JSON.stringify(state.cart));

    // Refresh state
    state.products = getAllMasterProducts(false).map(p => ({
        ...p,
        stock: p.stock || 0
    }));
    applyCustomPricesToProducts();
    syncStockCount();
    applyFilters();
    updateCartUI();
    renderProducts();
    renderAdminStockList();

    showToast(`ลบสินค้า "${title}" ออกจากร้านค้าแล้ว`, "success");
}

function handleRestoreProduct(productId) {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        promptAdminLogin();
        return;
    }

    const customProducts = getCustomProducts();
    if (customProducts[productId]) {
        delete customProducts[productId].deleted;
        delete customProducts[productId].deletedAt;
        localStorage.setItem('supinkly_custom_products', JSON.stringify(customProducts));
    }

    // Refresh state
    state.products = getAllMasterProducts(false).map(p => ({
        ...p,
        stock: p.stock || 0
    }));
    applyCustomPricesToProducts();
    syncStockCount();
    applyFilters();
    updateCartUI();
    renderProducts();
    renderAdminStockList();

    showToast(`กู้คืนสินค้ากลับสู่หน้าร้านเรียบร้อยแล้ว`, "success");
}

function handleDeleteCurrentProduct() {
    const productId = document.getElementById('edit-price-product-id').value;
    if (!productId) return;
    closeEditPriceModal();
    handleDeleteProduct(productId);
}

function openAddStockModal(productId) {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("กรุณาเข้าสู่ระบบแอดมินก่อนดำเนินการ", "warning");
        promptAdminLogin();
        return;
    }

    const master = getMasterProduct(productId);
    if (!master) return;

    const modal = document.getElementById('add-stock-modal');
    if (!modal) return;

    const pool = state.inventory[productId] || [];
    document.getElementById('add-stock-product-id').value = productId;
    document.getElementById('add-stock-product-title').textContent = `${master.title} (คลังปัจจุบัน: ${pool.length} ชิ้น)`;
    document.getElementById('add-stock-textarea').value = '';
    updateStockTextCounter();

    modal.classList.remove('hidden');
}

function updateStockTextCounter() {
    const text = (document.getElementById('add-stock-textarea')?.value || '').trim();
    const badge = document.getElementById('add-stock-counter-badge');
    if (!badge) return;
    if (!text) {
        badge.innerHTML = `<i class="fa-solid fa-barcode text-slate-400"></i><span>ยังไม่มีข้อมูล (0 ชิ้น)</span>`;
        return;
    }
    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    let accounts = 0, links = 0, keys = 0;
    lines.forEach(l => {
        if (l.includes(':')) accounts++;
        else if (l.startsWith('http')) links++;
        else keys++;
    });
    badge.innerHTML = `<i class="fa-solid fa-check text-emerald-600"></i><span class="text-emerald-700 font-bold">ตรวจพบ ${lines.length} ชิ้น</span> <span class="text-slate-500 font-normal">(${accounts ? `บัญชี: ${accounts} ` : ''}${keys ? `คีย์: ${keys} ` : ''}${links ? `ลิงก์: ${links}` : ''})</span>`;
}

function clearStockTextarea() {
    const textarea = document.getElementById('add-stock-textarea');
    if (textarea) {
        textarea.value = '';
        updateStockTextCounter();
    }
}

function insertStockSampleFormat(type) {
    const textarea = document.getElementById('add-stock-textarea');
    if (!textarea) return;
    let sample = '';
    if (type === 'account') {
        sample = `user_${Date.now().toString().slice(-4)}@domain.com:Pass_${Math.random().toString(36).slice(-6)}`;
    } else if (type === 'key') {
        sample = `KEY-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    } else if (type === 'link') {
        sample = `https://invite.example.com/join/${Math.random().toString(36).substring(2, 10)}`;
    }
    textarea.value = (textarea.value.trim() ? textarea.value.trim() + '\n' : '') + sample;
    updateStockTextCounter();
}

function handleStockFileUpload(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const content = e.target.result || '';
        const textarea = document.getElementById('add-stock-textarea');
        if (textarea) {
            textarea.value = (textarea.value.trim() ? textarea.value.trim() + '\n' : '') + content.trim();
            updateStockTextCounter();
            showToast(`นำเข้าสำเร็จจากไฟล์ "${file.name}"`, "success");
        }
    };
    reader.readAsText(file);
    event.target.value = '';
}

function closeAddStockModal() {
    const modal = document.getElementById('add-stock-modal');
    if (modal) modal.classList.add('hidden');
}

function handleSaveAddedStock() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeAddStockModal();
        promptAdminLogin();
        return;
    }

    const productId = document.getElementById('add-stock-product-id').value;
    const text = document.getElementById('add-stock-textarea').value.trim();
    if (!text) {
        showToast("กรุณากรอกข้อมูลบัญชีหรือคีย์", "warning");
        return;
    }

    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    if (!state.inventory[productId]) {
        state.inventory[productId] = [];
    }

    lines.forEach(line => {
        if (line.includes(':')) {
            const parts = line.split(':');
            state.inventory[productId].push({
                email: parts[0].trim(),
                password: parts.slice(1).join(':').trim(),
                instructions: "เข้าสู่ระบบและใช้งานได้ทันที"
            });
        } else if (line.startsWith('http')) {
            state.inventory[productId].push({
                link: line,
                instructions: "คลิกเปิดลิงก์เพื่อรับสิทธิ์ใช้งานทันที"
            });
        } else {
            state.inventory[productId].push({
                key: line,
                instructions: "นำคีย์ไปเปิดใช้งานในโปรแกรม"
            });
        }
    });

    saveSecureInventory(state.inventory);
    syncStockCount();
    renderProducts();
    renderAdminStockList();
    closeAddStockModal();
    showToast(`เติมสต็อกสำเร็จ +${lines.length} ชิ้น!`, "success");
}

async function saveAdminSettings() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeAdminModal();
        promptAdminLogin();
        return;
    }

    const phoneEl = document.getElementById('admin-promptpay-input');
    const newPhone = phoneEl ? phoneEl.value.trim() : '';
    const newAccountName = (document.getElementById('admin-account-name') ? document.getElementById('admin-account-name').value : '').trim();
    const newBranchId = (document.getElementById('admin-slipok-branch') ? document.getElementById('admin-slipok-branch').value : '').trim();
    const slipOkKeyEl = document.getElementById('admin-slipok-apikey') || document.getElementById('admin-slipok-key');
    const newApiKey = slipOkKeyEl ? slipOkKeyEl.value.trim() : '';
    const pinEl = document.getElementById('admin-new-pin');
    const newPin = pinEl ? pinEl.value.trim() : '';
    const confirmPinEl = document.getElementById('admin-confirm-new-pin');
    const confirmPin = confirmPinEl ? confirmPinEl.value.trim() : '';

    if (newPin) {
        if (newPin.length < 4 || newPin.length > 32) {
            showToast("รหัส PIN หรือรหัสผ่านต้องมีความยาวระหว่าง 4 ถึง 32 ตัวอักษร", "warning");
            pinEl?.focus();
            return;
        }
        if (confirmPinEl && confirmPin && newPin !== confirmPin) {
            showToast("รหัส PIN ยืนยันไม่ตรงกับรหัส PIN ใหม่ กรุณาตรวจสอบอีกครั้ง", "warning");
            confirmPinEl.focus();
            return;
        }
    }
    const discordWebhookUrl = (document.getElementById('admin-discord-webhook')?.value || '').trim();
    const geminiApiKey = (document.getElementById('admin-gemini-api-key')?.value || '').trim();
    const maintCheck = document.getElementById('admin-maintenance-mode');
    const maintenanceMode = maintCheck ? maintCheck.checked : undefined;

    const host = document.getElementById('admin-smtp-host')?.value.trim() || '';
    const port = parseInt(document.getElementById('admin-smtp-port')?.value || '465', 10);
    const user = document.getElementById('admin-smtp-user')?.value.trim() || '';
    const pass = document.getElementById('admin-smtp-pass')?.value.trim() || '';
    const from = document.getElementById('admin-smtp-from')?.value.trim() || '';
    const logoUrl = document.getElementById('admin-smtp-logourl')?.value.trim() || '';
    const brevoKey = document.getElementById('admin-smtp-brevo')?.value.trim() || '';
    const resendKey = document.getElementById('admin-smtp-resend')?.value.trim() || '';
    const sendgridKey = document.getElementById('admin-smtp-sendgrid')?.value.trim() || '';
    const mailjetKey = document.getElementById('admin-smtp-mailjet-key')?.value.trim() || '';
    const mailjetSecret = document.getElementById('admin-smtp-mailjet-secret')?.value.trim() || '';

    let cleanPhone = '';
    if (newPhone) {
        cleanPhone = newPhone.replace(/[-\s]/g, '');
        if (!/^[0-9]{10,15}$/.test(cleanPhone)) {
            showToast("รูปแบบหมายเลขพร้อมเพย์ไม่ถูกต้อง (ต้องเป็นตัวเลข 10-15 หลัก)", "warning");
            return;
        }
        STORE_CONFIG.promptPayNumber = cleanPhone;
    }
    if (newAccountName) {
        STORE_CONFIG.promptPayAccountName = newAccountName;
        const checkoutAccName = document.getElementById('checkout-account-name');
        if (checkoutAccName) checkoutAccName.textContent = newAccountName;
    }
    if (newBranchId) {
        STORE_CONFIG.slipOkBranchId = newBranchId;
    }
    if (newApiKey && newApiKey !== '******') {
        STORE_CONFIG.slipOkApiKey = newApiKey;
    }

    // Persist store config locally
    try {
        localStorage.setItem('supinkly_store_config', JSON.stringify({
            promptPayNumber: STORE_CONFIG.promptPayNumber,
            promptPayAccountName: STORE_CONFIG.promptPayAccountName,
            slipOkBranchId: STORE_CONFIG.slipOkBranchId,
            slipOkApiKey: STORE_CONFIG.slipOkApiKey
        }));
    } catch (e) {
        console.error("Config save error:", e);
    }

    // Save all settings to Server Database via API
    try {
        const payload = {
            promptPayNumber: cleanPhone || STORE_CONFIG.promptPayNumber,
            promptPayAccountName: newAccountName || STORE_CONFIG.promptPayAccountName,
            slipOkBranchId: newBranchId || STORE_CONFIG.slipOkBranchId,
            slipOkApiKey: newApiKey,
            discordWebhookUrl,
            geminiApiKey,
            maintenanceMode,
            smtpConfig: {
                host,
                port,
                user,
                pass,
                from,
                logoUrl,
                brevoKey,
                resendKey,
                sendgridKey,
                mailjetKey,
                mailjetSecret
            }
        };
        if (newPin) payload.newPin = newPin;

        const res = await fetch('/api/admin/settings', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data && data.success) {
            if (data.newAdminToken) {
                sessionStorage.setItem('supinkly_admin_server_token', data.newAdminToken);
                localStorage.setItem('supinkly_admin_server_token', data.newAdminToken);
            }
            if (newPin) {
                await ADMIN_AUTH.setPin(newPin);
                if (pinEl) pinEl.value = '';
                if (confirmPinEl) confirmPinEl.value = '';
                showToast("เปลี่ยนรหัส PIN แอดมินใหม่สำเร็จแล้ว", "success");
            }
            showToast("บันทึกการตั้งค่าทั้งหมด (SMTP, พร้อมเพย์, บอท) เรียบร้อยแล้ว", "success");
        } else {
            showToast(data.message || "บันทึกการตั้งค่าสำเร็จ", "info");
        }
    } catch (e) {
        console.warn("Could not save settings to server:", e);
        if (newPin) {
            try {
                await ADMIN_AUTH.setPin(newPin);
                if (pinEl) pinEl.value = '';
                if (confirmPinEl) confirmPinEl.value = '';
                showToast("เปลี่ยนรหัส PIN แอดมินในเบราว์เซอร์สำเร็จ", "info");
            } catch (err) {
                showToast(err.message, "warning");
                return;
            }
        }
        showToast("บันทึกการตั้งค่าลงเบราว์เซอร์แล้ว", "info");
    }

    closeAdminModal();
}

// Dedicated Direct Admin PIN Change Action
async function handleChangeAdminPinOnly() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeAdminModal();
        promptAdminLogin();
        return;
    }

    const pinEl = document.getElementById('admin-new-pin');
    const confirmEl = document.getElementById('admin-confirm-new-pin');
    const newPin = pinEl ? pinEl.value.trim() : '';
    const confirmPin = confirmEl ? confirmEl.value.trim() : '';

    if (!newPin) {
        showToast("กรุณากรอกรหัส PIN หรือรหัสผ่านใหม่", "warning");
        pinEl?.focus();
        return;
    }

    if (newPin.length < 4 || newPin.length > 32) {
        showToast("รหัส PIN หรือรหัสผ่านต้องมีความยาวระหว่าง 4 ถึง 32 ตัวอักษร", "warning");
        pinEl?.focus();
        return;
    }

    if (confirmEl && confirmPin && newPin !== confirmPin) {
        showToast("รหัส PIN ยืนยันไม่ตรงกับรหัส PIN ใหม่ กรุณากรอกให้ตรงกัน", "warning");
        confirmEl.focus();
        return;
    }

    const saveBtn = document.getElementById('admin-change-pin-btn');
    const origHtml = saveBtn ? saveBtn.innerHTML : '';
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> กำลังบันทึก...';
    }

    try {
        const res = await fetch('/api/admin/change-pin', {
            method: 'POST',
            headers: getAdminHeaders(),
            body: JSON.stringify({ newPin })
        });
        const data = await res.json();
        if (data && data.success) {
            if (data.token) {
                sessionStorage.setItem('supinkly_admin_server_token', data.token);
                localStorage.setItem('supinkly_admin_server_token', data.token);
            }
            await ADMIN_AUTH.setPin(newPin);
            if (pinEl) pinEl.value = '';
            if (confirmEl) confirmEl.value = '';
            showToast("เปลี่ยนรหัส PIN แอดมินใหม่สำเร็จแล้ว! รหัสใหม่มีผลทันที", "success");
        } else {
            showToast(data.message || "เปลี่ยนรหัส PIN ไม่สำเร็จ", "warning");
        }
    } catch (err) {
        try {
            await ADMIN_AUTH.setPin(newPin);
            if (pinEl) pinEl.value = '';
            if (confirmEl) confirmEl.value = '';
            showToast("เปลี่ยนรหัส PIN แอดมินในเบราว์เซอร์สำเร็จแล้ว", "success");
        } catch (e) {
            showToast(e.message || "เกิดข้อผิดพลาดในการเปลี่ยนรหัส PIN", "warning");
        }
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.innerHTML = origHtml || '<i class="fa-solid fa-floppy-disk"></i> บันทึกเปลี่ยนรหัส PIN ทันที';
        }
    }
}

// ==========================================
// PRODUCT DETAIL MODAL
// ==========================================
function openProductDetailModal(productId) {
    const product = getMasterProduct(productId);
    if (!product) return;

    const modal = document.getElementById('product-detail-modal');
    if (!modal) return;

    const availableStock = product.stock || (state.inventory[productId] || []).length || 0;

    const setElemText = (id, text) => {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    };

    setElemText('modal-product-title', product.title || '');
    setElemText('modal-product-desc', product.description || '');
    setElemText('modal-product-spec-type', product.type || 'สิทธิ์แท้ 100%');
    setElemText('modal-product-duration', product.duration || '30 วัน');
    setElemText('modal-product-warranty', product.warranty ? `รับประกัน ${product.warranty}` : 'รับประกัน 30 วัน');
    setElemText('modal-product-devices', product.devices || 'iOS • Android • Windows • Mac');
    setElemText('modal-product-region', product.region || 'Global (ทั่วโลก)');
    setElemText('modal-product-stock', `${availableStock} ชิ้น`);
    setElemText('modal-product-sold', `${(product.soldCount || 0).toLocaleString()} ชิ้น`);
    const discountPercent = (product.originalPrice && product.originalPrice > product.price)
        ? Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100)
        : 0;
    const formattedPrice = formatProductPrice(product.price);
    const formattedOrigPrice = product.originalPrice ? formatProductPrice(product.originalPrice) : '';

    setElemText('modal-product-price', formattedPrice);
    const origPriceEl = document.getElementById('modal-product-original-price');
    if (origPriceEl) {
        origPriceEl.textContent = (formattedOrigPrice && discountPercent > 0) ? `฿${formattedOrigPrice}` : '';
        origPriceEl.style.display = (formattedOrigPrice && discountPercent > 0) ? 'inline' : 'none';
    }
    const discountBadgeEl = document.getElementById('modal-product-discount-badge');
    if (discountBadgeEl) {
        if (discountPercent > 0) {
            const modalSavings = formatProductPrice(product.originalPrice - product.price);
            discountBadgeEl.textContent = `-${discountPercent}% (ประหยัด ฿${modalSavings})`;
            discountBadgeEl.classList.remove('hidden');
        } else {
            discountBadgeEl.classList.add('hidden');
        }
    }

    const featuresList = document.getElementById('modal-product-features-list');
    if (featuresList) {
        const descLines = (product.description || '').split('\n').map(l => l.trim()).filter(l => l.length > 0);
        if (descLines.length > 0) {
            featuresList.innerHTML = descLines.map(line => `
                <div class="flex items-start gap-2 text-xs text-slate-700 bg-slate-50/80 p-2.5 rounded-xl border border-slate-100">
                    <i class="fa-solid fa-check text-pink-500 mt-0.5 shrink-0 text-xs"></i>
                    <span class="font-normal">${escapeHTML(line.replace(/^[•\-\*]\s*/, ''))}</span>
                </div>
            `).join('');
        } else {
            featuresList.innerHTML = `
                <div class="flex items-start gap-2 text-xs text-slate-700 bg-slate-50/80 p-2.5 rounded-xl border border-slate-100">
                    <i class="fa-solid fa-check text-pink-500 mt-0.5 shrink-0 text-xs"></i>
                    <span class="font-normal">สิทธิ์แท้มาตรฐาน พร้อมการรับประกันและดูแลตลอดการใช้งาน</span>
                </div>
            `;
        }
    }

    const user = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;

    // Wishlist Toggle in Modal
    const wishBtn = document.getElementById('modal-wishlist-btn');
    if (wishBtn) {
        const isWishlisted = isProductWishlisted(product.id);
        wishBtn.innerHTML = `<i class="fa-${isWishlisted ? 'solid' : 'regular'} fa-heart"></i>`;
        wishBtn.className = `w-11 h-11 sm:w-12 sm:h-12 rounded-2xl ${isWishlisted ? 'bg-rose-500 text-white shadow-md shadow-rose-500/25' : 'bg-rose-50 hover:bg-rose-100 text-rose-500 border border-rose-200'} flex items-center justify-center text-base sm:text-lg cursor-pointer transition-all active:scale-95 shadow-xs`;
        wishBtn.onclick = async () => {
            await toggleProductWishlist(product.id);
            const nowWishlisted = isProductWishlisted(product.id);
            wishBtn.innerHTML = `<i class="fa-${nowWishlisted ? 'solid' : 'regular'} fa-heart"></i>`;
            wishBtn.className = `w-11 h-11 sm:w-12 sm:h-12 rounded-2xl ${nowWishlisted ? 'bg-rose-500 text-white shadow-md shadow-rose-500/25' : 'bg-rose-50 hover:bg-rose-100 text-rose-500 border border-rose-200'} flex items-center justify-center text-base sm:text-lg cursor-pointer transition-all active:scale-95 shadow-xs`;
        };
    }

    // Stock Alert Toggle in Modal (Shown when stock is 0)
    const alertBtn = document.getElementById('modal-stock-alert-btn');
    if (alertBtn) {
        if (availableStock <= 0) {
            const isAlerted = !!(user && Array.isArray(user.stockAlerts) && user.stockAlerts.includes(product.id));
            alertBtn.classList.remove('hidden');
            alertBtn.innerHTML = `<i class="fa-${isAlerted ? 'solid' : 'regular'} fa-bell"></i>`;
            alertBtn.className = `w-11 h-11 sm:w-12 sm:h-12 rounded-2xl ${isAlerted ? 'bg-amber-500 text-white shadow-md shadow-amber-500/25' : 'bg-amber-50 hover:bg-amber-100 text-amber-600 border border-amber-200'} flex items-center justify-center text-base sm:text-lg cursor-pointer transition-all active:scale-95 shadow-xs`;
            alertBtn.onclick = async () => {
                await toggleProductStockAlert(product.id);
                const freshUser = (typeof USER_AUTH !== 'undefined') ? USER_AUTH.getUser() : null;
                const nowAlerted = !!(freshUser && Array.isArray(freshUser.stockAlerts) && freshUser.stockAlerts.includes(product.id));
                alertBtn.innerHTML = `<i class="fa-${nowAlerted ? 'solid' : 'regular'} fa-bell"></i>`;
                alertBtn.className = `w-11 h-11 sm:w-12 sm:h-12 rounded-2xl ${nowAlerted ? 'bg-amber-500 text-white shadow-md shadow-amber-500/25' : 'bg-amber-50 hover:bg-amber-100 text-amber-600 border border-amber-200'} flex items-center justify-center text-base sm:text-lg cursor-pointer transition-all active:scale-95 shadow-xs`;
            };
        } else {
            alertBtn.classList.add('hidden');
        }
    }

    const addBtn = document.getElementById('modal-add-cart-btn');
    if (addBtn) {
        addBtn.disabled = availableStock <= 0;
        if (availableStock <= 0) {
            addBtn.innerHTML = `<i class="fa-solid fa-ban"></i> <span>สินค้าหมดชั่วคราว</span>`;
            addBtn.classList.add('opacity-50', 'cursor-not-allowed');
        } else {
            addBtn.innerHTML = `<i class="fa-solid fa-cart-plus"></i> <span>ใส่ตะกร้าสินค้า</span>`;
            addBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
        addBtn.onclick = () => {
            addToCart(product.id);
            closeProductDetailModal();
        };
    }

    modal.classList.remove('hidden');
    if (typeof sendTelemetryHeartbeat === 'function') {
        sendTelemetryHeartbeat('product_view', { productId, productTitle: product.title });
    }
}

function closeProductDetailModal() {
    const modal = document.getElementById('product-detail-modal');
    if (modal) modal.classList.add('hidden');
}

// ==========================================
// STORE COUPONS & PROMOTIONS POPUP
// ==========================================
function openCouponsModal() {
    renderCouponsModal();
    const modal = document.getElementById('coupons-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeCouponsModal() {
    const modal = document.getElementById('coupons-modal');
    if (modal) modal.classList.add('hidden');
}

function renderCouponsModal() {
    const list = document.getElementById('coupons-modal-list');
    const badge = document.getElementById('coupons-modal-count-badge');
    const promotions = (typeof getStorePromotions === 'function' ? getStorePromotions() : []).filter(p => p.active !== false);

    if (badge) badge.textContent = `${promotions.length} โค้ด`;
    if (!list) return;

    if (promotions.length === 0) {
        list.innerHTML = `
            <div class="py-12 text-center text-slate-400 text-xs">
                <i class="fa-solid fa-ticket-simple text-3xl mb-2 text-slate-300"></i>
                <p>ขณะนี้ยังไม่มีโค้ดส่วนลดที่เปิดใช้งาน</p>
            </div>
        `;
        return;
    }

    list.innerHTML = promotions.map(promo => {
        const isPct = (promo.discountType === 'percent' || promo.type === 'percentage');
        const valText = isPct ? `${promo.discountValue || promo.value}%` : `฿${promo.discountValue || promo.value}`;
        const minSpend = promo.minSpend ? `ขั้นต่ำ ฿${promo.minSpend.toFixed(2)}` : 'ไม่มีขั้นต่ำ';
        const isApplied = state.appliedCoupon && (state.appliedCoupon.code || '').toUpperCase() === (promo.code || '').toUpperCase();

        return `
            <div class="p-3.5 sm:p-4 rounded-2xl bg-gradient-to-r from-pink-50/60 to-purple-50/60 border border-pink-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
                <div class="flex items-start gap-3">
                    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-pink-500 to-rose-600 text-white flex flex-col items-center justify-center shrink-0 shadow-sm shadow-pink-500/20">
                        <span class="text-xs font-black font-mono leading-none">${valText}</span>
                        <span class="text-[9px] uppercase font-bold mt-0.5">ส่วนลด</span>
                    </div>
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="font-mono font-bold text-sm text-pink-600 bg-white px-2 py-0.5 rounded-lg border border-pink-200 select-all">${escapeHTML(promo.code)}</span>
                            <span class="text-[10px] text-slate-500 font-semibold bg-slate-100 px-2 py-0.5 rounded-full">${minSpend}</span>
                        </div>
                        <h4 class="text-xs font-bold text-slate-800 mt-1">${escapeHTML(promo.title || '')}</h4>
                        <p class="text-[11px] text-slate-500 mt-0.5">${escapeHTML(promo.description || '')}</p>
                    </div>
                </div>
                <div class="flex items-center gap-2 justify-end shrink-0">
                    <button type="button" onclick="copyAndApplyPromoCode('${escapeHTML(promo.code)}')" 
                        class="px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm cursor-pointer ${isApplied ? 'bg-emerald-500 text-white' : 'gradient-btn text-white hover:scale-105 active:scale-95'}">
                        <i class="fa-solid ${isApplied ? 'fa-circle-check' : 'fa-copy'}"></i>
                        <span>${isApplied ? 'กำลังใช้งานอยู่' : 'คัดลอก & นำไปใช้'}</span>
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

function copyAndApplyPromoCode(code) {
    if (!code) return;
    copyToClipboard(code, `คัดลอกโค้ด "${code}" แล้ว`);

    const subtotal = calculateVerifiedTotal();
    const result = typeof validateCouponCode === 'function' ? validateCouponCode(code, subtotal) : { valid: false, message: 'ไม่สามารถตรวจสอบโค้ดได้' };

    if (result.valid) {
        state.appliedCoupon = result;
        showToast(result.message || `นำโค้ด "${code}" ไปใช้ในตะกร้าเรียบร้อยแล้ว`, "success");
    } else {
        state.appliedCoupon = { code: code.toUpperCase(), discountAmount: 0, title: 'โค้ดส่วนลด' };
        showToast(`คัดลอกโค้ด "${code}" แล้ว! (${result.message})`, "info");
    }

    updateCartUI();
    closeCouponsModal();
    openCartDrawer();
}

function copyAndApplyPromo(code) {
    copyAndApplyPromoCode(code);
}

function claimVoucher(code, btn) {
    if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = `<i class="fa-solid fa-check text-emerald-300"></i> <span>เก็บสำเร็จ!</span>`;
        btn.classList.add('bg-emerald-600');
        setTimeout(() => {
            btn.innerHTML = orig;
            btn.classList.remove('bg-emerald-600');
        }, 1800);
    }
    copyAndApplyPromoCode(code);
}

function applyCouponFromCart() {
    const input = document.getElementById('cart-coupon-input');
    const code = (input ? input.value : '').trim().toUpperCase();
    if (!code) {
        showToast("กรุณากรอกโค้ดส่วนลด", "warning");
        return;
    }

    const subtotal = calculateVerifiedTotal();
    if (subtotal <= 0) {
        showToast("กรุณาเพิ่มสินค้าลงในตะกร้าก่อนใช้โค้ดส่วนลด", "warning");
        return;
    }

    const result = typeof validateCouponCode === 'function' ? validateCouponCode(code, subtotal) : { valid: false, message: 'ระบบไม่พร้อมใช้งาน' };
    if (!result.valid) {
        showToast(result.message || "โค้ดส่วนลดไม่ถูกต้อง", "warning");
        return;
    }

    state.appliedCoupon = result;
    if (input) {
        input.value = '';
        input.setAttribute('readonly', 'readonly');
        input.name = 'spk_cp_' + Math.random().toString(36).slice(2, 9);
        if (typeof input.blur === 'function') input.blur();
    }
    showToast(result.message, "success");
    updateCartUI();
}

function quickApplyCoupon(code) {
    const input = document.getElementById('cart-coupon-input');
    if (input) {
        input.removeAttribute('readonly');
        input.value = code;
    }
    applyCouponFromCart();
}

function removeAppliedCoupon() {
    state.appliedCoupon = null;
    const input = document.getElementById('cart-coupon-input');
    if (input) {
        input.value = '';
        input.setAttribute('readonly', 'readonly');
        input.name = 'spk_cp_' + Math.random().toString(36).slice(2, 9);
    }
    showToast("ยกเลิกการใช้โค้ดส่วนลดแล้ว", "info");
    updateCartUI();
}

// ==========================================
// LOGO MASCOT POPUP
// ==========================================
function openLogoPopup() {
    const modal = document.getElementById('logo-popup-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeLogoPopup() {
    const modal = document.getElementById('logo-popup-modal');
    if (modal) modal.classList.add('hidden');
}

// ==========================================
// MOBILE MENU DRAWER
// ==========================================
function openMobileMenu() {
    const drawer = document.getElementById('mobile-menu-drawer');
    const overlay = document.getElementById('mobile-menu-overlay');
    if (drawer) drawer.classList.remove('-translate-x-full');
    if (overlay) overlay.classList.remove('hidden');
}

function closeMobileMenu() {
    const drawer = document.getElementById('mobile-menu-drawer');
    const overlay = document.getElementById('mobile-menu-overlay');
    if (drawer) drawer.classList.add('-translate-x-full');
    if (overlay) overlay.classList.add('hidden');
}

// ==========================================
// SMOOTH SCROLL TO PRODUCTS
// ==========================================
function scrollToProducts() {
    const section = document.getElementById('products-section') || document.getElementById('brand-tabs-sticky-bar') || document.getElementById('featured-ai');
    if (section) {
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ==========================================
// ADMIN SLIP VIEW MODAL
// ==========================================
let currentViewingSlipOrderId = null;

function openSlipViewModal(orderId) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }

    const order = (adminOrdersList && adminOrdersList.find(o => o.orderId === orderId)) || (state.orders || []).find(o => o.orderId === orderId);
    if (!order) {
        showToast("ไม่พบข้อมูลคำสั่งซื้อ", "warning");
        return;
    }

    const modal = document.getElementById('admin-slip-view-modal');
    if (!modal) return;

    currentViewingSlipOrderId = orderId;

    const titleEl = document.getElementById('admin-slip-modal-title');
    if (titleEl) titleEl.textContent = `ตรวจสอบสลิปการโอนเงิน — ${order.orderId}`;

    const subtitleEl = document.getElementById('admin-slip-modal-subtitle');
    if (subtitleEl) subtitleEl.textContent = `คำสั่งซื้อ: ${order.orderId} | วันที่: ${order.date || '-'}`;

    const imgEl = document.getElementById('admin-slip-modal-img');
    const loadingEl = document.getElementById('admin-slip-modal-loading');
    const errorEl = document.getElementById('admin-slip-modal-error');
    const emptyEl = document.getElementById('admin-slip-modal-empty');
    const directBtn = document.getElementById('admin-slip-direct-url-btn');
    const downloadBtn = document.getElementById('admin-slip-download-btn');

    // Slip audit details
    const transEl = document.getElementById('admin-slip-audit-transref');
    if (transEl) transEl.textContent = order.transRef || order.transactionId || '-';

    const amtEl = document.getElementById('admin-slip-audit-amount');
    if (amtEl) amtEl.textContent = `฿${(order.totalAmount || 0).toFixed(2)}`;

    const dateEl = document.getElementById('admin-slip-audit-date');
    if (dateEl) dateEl.textContent = order.date || '-';

    const hashEl = document.getElementById('admin-slip-audit-hash');
    if (hashEl) hashEl.textContent = order.slipHash || order.hash || '-';

    const statusEl = document.getElementById('admin-slip-audit-status');
    if (statusEl) {
        statusEl.innerHTML = `<i class="fa-solid fa-circle-check"></i> ตรวจสอบผ่านแล้ว`;
    }

    const slipUrl = order.slipUrl || order.slipImage || order.slipDataUrl || order.slipData || '';

    // Reset states
    if (loadingEl) loadingEl.classList.add('hidden');
    if (errorEl) errorEl.classList.add('hidden');
    if (emptyEl) emptyEl.classList.add('hidden');
    if (imgEl) {
        imgEl.classList.add('hidden');
        imgEl.src = '';
    }

    if (slipUrl) {
        if (directBtn) {
            directBtn.href = slipUrl;
            directBtn.classList.remove('hidden');
        }
        if (downloadBtn) {
            downloadBtn.href = slipUrl;
            downloadBtn.download = `slip-${order.orderId}.jpg`;
            downloadBtn.classList.remove('hidden');
        }

        if (loadingEl) loadingEl.classList.remove('hidden');

        if (imgEl) {
            imgEl.onload = () => {
                if (loadingEl) loadingEl.classList.add('hidden');
                imgEl.classList.remove('hidden');
                if (errorEl) errorEl.classList.add('hidden');
            };
            imgEl.onerror = () => {
                if (loadingEl) loadingEl.classList.add('hidden');
                imgEl.classList.add('hidden');
                if (errorEl) errorEl.classList.remove('hidden');
            };
            imgEl.src = slipUrl;
        }
    } else {
        if (emptyEl) emptyEl.classList.remove('hidden');
        if (errorEl) errorEl.classList.remove('hidden');
        if (directBtn) directBtn.classList.add('hidden');
        if (downloadBtn) downloadBtn.classList.add('hidden');
    }

    modal.classList.remove('hidden');
}

function closeSlipViewModal() {
    const modal = document.getElementById('admin-slip-view-modal');
    if (modal) modal.classList.add('hidden');
    currentViewingSlipOrderId = null;
}

async function handleAdminSlipReupload(input) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }
    if (!input || !input.files || !input.files[0]) return;
    if (!currentViewingSlipOrderId) {
        showToast("ไม่พบรหัสคำสั่งซื้อที่ต้องการแนบสลิป", "error");
        return;
    }
    const file = input.files[0];
    if (!file.type.match(/^image\/(jpeg|png|webp)$/i)) {
        showToast("กรุณาเลือกไฟล์รูปภาพ JPG, PNG หรือ WebP เท่านั้น", "warning");
        input.value = '';
        return;
    }
    if (file.size > 15 * 1024 * 1024) {
        showToast("ขนาดไฟล์รูปภาพต้องไม่เกิน 15MB", "warning");
        input.value = '';
        return;
    }

    const formData = new FormData();
    formData.append('slip', file);

    const headers = {};
    const token = sessionStorage.getItem('supinkly_admin_server_token') || localStorage.getItem('supinkly_admin_server_token');
    const pin = sessionStorage.getItem('supinkly_admin_pin') || '';
    if (pin) headers['x-admin-pin'] = pin;
    if (token) {
        headers['x-admin-token'] = token;
        headers['Authorization'] = `Bearer ${token}`;
    }

    showToast("กำลังอัปโหลดรูปภาพสลิป...", "info");
    try {
        const res = await fetch(`/api/admin/orders/${encodeURIComponent(currentViewingSlipOrderId)}/attach-slip`, {
            method: 'POST',
            headers,
            body: formData
        });
        const data = await res.json();
        if (data && data.success) {
            showToast(data.message || "แนบรูปสลิปให้คำสั่งซื้อเรียบร้อยแล้ว", "success");
            const order = (state.orders || []).find(o => o.orderId === currentViewingSlipOrderId);
            if (order) {
                order.slipUrl = data.slipUrl;
                if (data.slipData) order.slipData = data.slipData;
                saveOrders();
            }
            openSlipViewModal(currentViewingSlipOrderId);
        } else {
            showToast(data.message || "เกิดข้อผิดพลาดในการอัปโหลดสลิป", "error");
        }
    } catch (e) {
        console.error("handleAdminSlipReupload error:", e);
        showToast("ไม่สามารถอัปโหลดรูปภาพสลิปได้ กรุณาลองใหม่อีกครั้ง", "error");
    } finally {
        input.value = '';
    }
}

// Toast System (Bright, Clear Alerts)
function showToast(message, type = "info") {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast px-4 py-3.5 rounded-2xl shadow-xl border-2 flex items-center gap-3 text-xs sm:text-sm font-bold z-50 bg-white`;

    if (type === 'success') {
        toast.classList.add('border-emerald-300', 'text-emerald-800');
        toast.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-600 text-base"></i> <span>${escapeHTML(message)}</span>`;
    } else if (type === 'warning') {
        toast.classList.add('border-amber-300', 'text-amber-800');
        toast.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber-600 text-base"></i> <span>${escapeHTML(message)}</span>`;
    } else {
        toast.classList.add('border-pink-300', 'text-pink-800');
        toast.innerHTML = `<i class="fa-solid fa-circle-info text-pink-600 text-base"></i> <span>${escapeHTML(message)}</span>`;
    }

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3200);
}

// ==========================================
// UNIVERSAL ESCAPE (ESC) KEY HANDLER
// Close modals, drawers, popups, and panels in hierarchical LIFO order
// ==========================================
function closeTopmostModal() {
    // 0. Notification Center Dropdown (z-[80])
    const notifDropdown = document.getElementById('notification-center-dropdown');
    if (notifDropdown && !notifDropdown.classList.contains('hidden')) {
        closeNotificationCenter();
        return true;
    }

    // 1. Admin Chat Panel (z-[200])
    const adminChat = document.getElementById('admin-chat-panel');
    if (adminChat && !adminChat.classList.contains('hidden')) {
        closeAdminChatPanel();
        return true;
    }

    // 2. Coupons Promo Modal (z-[160])
    const couponsModal = document.getElementById('coupons-modal');
    if (couponsModal && !couponsModal.classList.contains('hidden')) {
        closeCouponsModal();
        return true;
    }

    // 3. Logo Mascot Popup (z-[150])
    const logoPopup = document.getElementById('logo-popup-modal');
    if (logoPopup && !logoPopup.classList.contains('hidden')) {
        closeLogoPopup();
        return true;
    }

    // 4. Mobile Menu Navigation Drawer (z-[110])
    const mobileOverlay = document.getElementById('mobile-menu-overlay');
    const mobileDrawer = document.getElementById('mobile-menu-drawer');
    if ((mobileOverlay && !mobileOverlay.classList.contains('hidden')) ||
        (mobileDrawer && !mobileDrawer.classList.contains('-translate-x-full'))) {
        closeMobileMenu();
        return true;
    }

    // 5. Admin Slip View Modal (z-[75])
    const slipModal = document.getElementById('admin-slip-view-modal');
    if (slipModal && !slipModal.classList.contains('hidden')) {
        closeSlipViewModal();
        return true;
    }

    // 6. Product Detail Modal (z-[70])
    const productDetailModal = document.getElementById('product-detail-modal');
    if (productDetailModal && !productDetailModal.classList.contains('hidden')) {
        closeProductDetailModal();
        return true;
    }

    // 7. Checkout & Payment Modal (z-[70])
    const checkoutModal = document.getElementById('checkout-modal');
    if (checkoutModal && !checkoutModal.classList.contains('hidden')) {
        closeCheckoutModal();
        return true;
    }

    // 8. Instant Delivery Vault Modal (z-[70])
    const vaultModal = document.getElementById('vault-modal');
    if (vaultModal && !vaultModal.classList.contains('hidden')) {
        closeVaultModal();
        return true;
    }

    // 9. User Authentication Modal (Login / Register / OTP / Forgot) (z-[70])
    const authModal = document.getElementById('auth-modal');
    if (authModal && !authModal.classList.contains('hidden')) {
        closeAuthModal();
        return true;
    }

    // 10. Admin Edit & Manage Product Modal (z-[60])
    const editPriceModal = document.getElementById('edit-price-modal');
    if (editPriceModal && !editPriceModal.classList.contains('hidden')) {
        closeEditPriceModal();
        return true;
    }

    // 11. Admin Add Stock Modal (z-[60])
    const addStockModal = document.getElementById('add-stock-modal');
    if (addStockModal && !addStockModal.classList.contains('hidden')) {
        closeAddStockModal();
        return true;
    }

    // 12. Admin Fulfill Order Modal (z-50)
    const fulfillModal = document.getElementById('admin-fulfill-modal');
    if (fulfillModal && !fulfillModal.classList.contains('hidden')) {
        closeFulfillModal();
        return true;
    }

    // 13. Admin Reset Password Confirmation Modal (z-50)
    const resetPwModal = document.getElementById('admin-reset-pw-modal');
    if (resetPwModal && !resetPwModal.classList.contains('hidden')) {
        closeAdminResetPwModal();
        return true;
    }

    // 14. Admin PIN Security Gate Modal (z-50)
    const pinModal = document.getElementById('admin-pin-modal');
    if (pinModal && !pinModal.classList.contains('hidden')) {
        closeAdminPinModal();
        return true;
    }

    // 15. Orders History & My Keys Modal (z-50)
    const ordersModal = document.getElementById('orders-modal');
    if (ordersModal && !ordersModal.classList.contains('hidden')) {
        closeOrdersModal();
        return true;
    }

    // 16. Secured Admin Dashboard Modal (z-50)
    const adminModal = document.getElementById('admin-modal');
    if (adminModal && !adminModal.classList.contains('hidden')) {
        closeAdminModal();
        return true;
    }

    // 17. Cart Drawer & Overlay (z-50)
    const cartOverlay = document.getElementById('drawer-overlay');
    const cartDrawer = document.getElementById('cart-drawer');
    if ((cartOverlay && !cartOverlay.classList.contains('hidden')) ||
        (cartDrawer && !cartDrawer.classList.contains('translate-x-full'))) {
        closeCartDrawer();
        return true;
    }

    // 18. Customer Live Chat Window
    const chatWindow = document.getElementById('spk-chat-window') || document.getElementById('chat-window');
    if (chatWindow && !chatWindow.classList.contains('hidden')) {
        if (typeof window.closeLiveChat === 'function') {
            window.closeLiveChat();
        } else if (typeof window.SupinklyChat !== 'undefined' && typeof window.SupinklyChat.close === 'function') {
            window.SupinklyChat.close();
        } else {
            chatWindow.classList.add('hidden');
        }
        return true;
    }

    // 19. Generic fallback for any other modal overlay
    const anyModal = Array.from(document.querySelectorAll('.fixed.inset-0:not(.hidden)'))
        .filter(el => el.id !== 'global-admin-maintenance-bar' && !el.classList.contains('pointer-events-none'));
    if (anyModal.length > 0) {
        anyModal[anyModal.length - 1].classList.add('hidden');
        return true;
    }

    // 20. If an input or textarea is focused and no modal is open, blur it
    if (document.activeElement && typeof document.activeElement.blur === 'function' &&
        (document.activeElement.tagName === 'INPUT' || document.activeElement.tagName === 'TEXTAREA')) {
        document.activeElement.blur();
        return true;
    }

    return false;
}

function initEvents() {
    const slipInput = document.getElementById('slip-file-input');
    if (slipInput) {
        slipInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files[0]) {
                SlipVerifier.handleFileSelect(e.target.files[0]);
            }
        });
    }

    const dropzone = document.getElementById('slip-dropzone');
    if (dropzone) {
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('border-pink-500', 'bg-pink-50');
        });
        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('border-pink-500', 'bg-pink-50');
        });
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('border-pink-500', 'bg-pink-50');
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                SlipVerifier.handleFileSelect(e.dataTransfer.files[0]);
            }
        });
    }

    // Universal ESC key listener to exit/close any modal, popup, or drawer (Capture phase for instant priority)
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) {
            const closed = closeTopmostModal();
            if (closed) {
                e.preventDefault();
                e.stopPropagation();
            }
        }
    }, true);

    // Owner shortcut to open admin login (Ctrl + Shift + A)
    window.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
            e.preventDefault();
            promptAdminLogin();
        }
    });

    // Shortcut: Ctrl + Shift + C → เปิดแผงแชท (ถ้า auth แล้ว)
    window.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.key === 'c')) {
            e.preventDefault();
            if (ADMIN_AUTH.checkSession()) openAdminChatPanel();
            else promptAdminLogin();
        }
    });

    // Setup anti-browser autofill / anti-memory protection for coupon & promo inputs
    const promoInputs = [
        document.getElementById('cart-coupon-input'),
        document.getElementById('admin-coupon-code-input')
    ];
    promoInputs.forEach(input => {
        if (!input) return;
        input.setAttribute('autocomplete', 'one-time-code');
        input.setAttribute('autocorrect', 'off');
        input.setAttribute('autocapitalize', 'characters');
        input.setAttribute('spellcheck', 'false');
        input.setAttribute('data-lpignore', 'true');
        input.setAttribute('data-1p-ignore', 'true');
        input.setAttribute('data-bwignore', 'true');
        input.setAttribute('data-dashlane-ignore', 'true');
        input.setAttribute('data-form-type', 'other');
        input.setAttribute('aria-autocomplete', 'none');
        input.name = 'spk_cp_' + Math.random().toString(36).slice(2, 9);
        const unlock = () => {
            input.removeAttribute('readonly');
            input.setAttribute('autocomplete', 'one-time-code');
        };
        input.addEventListener('pointerdown', unlock, { passive: true });
        input.addEventListener('touchstart', unlock, { passive: true });
        input.addEventListener('focus', unlock, { passive: true });
    });

    // Setup anti-browser autofill / anti-memory protection for all search inputs
    const searchInputs = [
        document.getElementById('search-input'),
        document.getElementById('mobile-search-input'),
        document.getElementById('customer-keys-search'),
        document.getElementById('admin-order-search'),
        document.getElementById('admin-stock-search'),
        document.getElementById('admin-user-search'),
        document.getElementById('admin-coupon-search')
    ];
    searchInputs.forEach(input => {
        if (!input) return;
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('autocorrect', 'off');
        input.setAttribute('autocapitalize', 'none');
        input.setAttribute('spellcheck', 'false');
        input.setAttribute('data-lpignore', 'true');
        input.setAttribute('data-1p-ignore', 'true');
        input.setAttribute('data-bwignore', 'true');
        input.setAttribute('data-dashlane-ignore', 'true');
        input.setAttribute('data-form-type', 'other');
        input.setAttribute('aria-autocomplete', 'none');
        input.name = 'spk_s_' + Math.random().toString(36).slice(2, 9);
        const unlock = () => {
            input.removeAttribute('readonly');
            input.setAttribute('autocomplete', 'off');
        };
        input.addEventListener('pointerdown', unlock, { passive: true });
        input.addEventListener('touchstart', unlock, { passive: true });
        input.addEventListener('focus', unlock, { passive: true });
    });
}

// ─────────────────────────────────────────────────────────────
// ADMIN LIVE CHAT — WebSocket Client (Admin Side)
// ─────────────────────────────────────────────────────────────
const ADMIN_CHAT = (() => {
    const WS_URL = (() => {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const host = location.hostname === 'localhost' || location.hostname === '127.0.0.1'
            ? `${location.hostname}:3000`
            : location.host;
        return `${proto}://${host}/ws/chat`;
    })();

    let ws = null;
    let activeRoom = null;   // sessionId ที่กำลัง active
    const rooms = {};     // sessionId → { name, messages[] }
    let adminTyping = null;
    let unread = {};     // sessionId → count

    /* ── Helpers ─────────────────────────────────────────────── */
    function fmtTime(ts) {
        return new Date(ts).toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' });
    }

    function setStatus(text) {
        const el = document.getElementById('admin-chat-status');
        if (el) el.textContent = text;
    }

    /* ── Room List ───────────────────────────────────────────── */
    function renderRoomList() {
        const list = document.getElementById('admin-room-list');
        const cnt = document.getElementById('admin-room-count');
        if (!list) return;

        const keys = Object.keys(rooms);
        if (cnt) cnt.textContent = keys.length;

        if (keys.length === 0) {
            list.innerHTML = `<div class="px-3 py-3 text-[11px] text-slate-400 text-center font-medium">ยังไม่มีลูกค้าเชื่อมต่อ</div>`;
            return;
        }

        list.innerHTML = keys.map(sid => {
            const r = rooms[sid];
            const isActive = sid === activeRoom;
            const badge = unread[sid] || 0;
            return `
                <div onclick="ADMIN_CHAT.selectRoom('${escapeHTML(sid)}')"
                    class="px-3 py-2.5 cursor-pointer flex items-center gap-2 transition-colors ${isActive ? 'bg-pink-50 border-l-2 border-pink-500' : 'hover:bg-slate-100'}">
                    <div class="w-7 h-7 rounded-full bg-pink-100 text-pink-600 flex items-center justify-center text-[11px] font-black shrink-0">
                        ${escapeHTML(r.name.charAt(0).toUpperCase())}
                    </div>
                    <span class="text-xs font-bold text-slate-800 truncate flex-1">${escapeHTML(r.name)}</span>
                    ${badge > 0 ? `<span class="w-4 h-4 rounded-full bg-red-500 text-white text-[10px] font-black flex items-center justify-center shrink-0">${badge}</span>` : ''}
                </div>`;
        }).join('');
    }

    /* ── Messages ────────────────────────────────────────────── */
    function renderMessages(sid) {
        const box = document.getElementById('admin-messages');
        if (!box || !rooms[sid]) return;
        box.innerHTML = '';
        rooms[sid].messages.forEach(m => appendMsgToBox(m, box));
        box.scrollTop = box.scrollHeight;
    }

    function appendMsgToBox(m, box) {
        if (!box) box = document.getElementById('admin-messages');
        if (!box) return;
        const isOwn = m.from === 'admin' && m.own;

        const wrap = document.createElement('div');
        wrap.className = `flex ${isOwn ? 'justify-end' : 'justify-start'} gap-2`;
        const bubble = document.createElement('div');
        bubble.className = `max-w-[80%] px-3.5 py-2.5 rounded-2xl text-sm font-medium leading-relaxed shadow-xs
            ${isOwn
                ? 'bg-gradient-to-br from-pink-500 to-purple-600 text-white rounded-br-md'
                : 'bg-white border border-slate-200 text-slate-900 rounded-bl-md'}`;
        bubble.innerHTML = `
            ${!isOwn ? `<div class="text-[10px] font-bold text-emerald-600 mb-0.5 flex items-center gap-1"><i class="fa-solid fa-user text-[9px]"></i> ${escapeHTML(m.name || 'ลูกค้า')}</div>` : ''}
            <div class="whitespace-pre-wrap break-words">${escapeHTML(m.text)}</div>
            <div class="text-[10px] mt-1 ${isOwn ? 'text-white/60 text-right' : 'text-slate-400'}">${fmtTime(m.ts)}</div>
        `;
        wrap.appendChild(bubble);
        box.appendChild(wrap);
        box.scrollTop = box.scrollHeight;
    }

    /* ── Select Room ─────────────────────────────────────────── */
    function selectRoom(sid) {
        activeRoom = sid;
        unread[sid] = 0;

        const nameEl = document.getElementById('admin-active-room-name');
        const dotEl = document.getElementById('admin-active-online-dot');
        if (nameEl) nameEl.textContent = rooms[sid]?.name || sid;
        if (dotEl) dotEl.classList.remove('hidden');

        renderMessages(sid);
        renderRoomList();
        document.getElementById('admin-msg-input')?.focus();
    }

    /* ── Send Message ────────────────────────────────────────── */
    function sendMsg() {
        if (!activeRoom || !ws || ws.readyState !== 1) {
            showToast('กรุณาเลือกลูกค้าก่อนส่งข้อความ', 'warning');
            return;
        }
        const inp = document.getElementById('admin-msg-input');
        const text = (inp?.value || '').trim();
        if (!text) return;

        ws.send(JSON.stringify({ type: 'message', text, targetSessionId: activeRoom }));
        inp.value = '';
        inp.style.height = '';
    }

    /* ── Connect ─────────────────────────────────────────────── */
    function connect(pinOverride) {
        if (ws && ws.readyState < 2) return;
        ws = new WebSocket(WS_URL);

        const token = sessionStorage.getItem('supinkly_admin_server_token') || localStorage.getItem('supinkly_admin_server_token') || '';
        const pin = pinOverride || sessionStorage.getItem('supinkly_admin_pin') || '';

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'auth', role: 'admin', token, pin }));
        };

        ws.onmessage = ({ data }) => {
            let msg;
            try { msg = JSON.parse(data); } catch { return; }

            if (msg.type === 'auth_ok') {
                setStatus(`เชื่อมต่อแล้ว (Admin) 🟢 — ${new Date().toLocaleTimeString('th-TH')}`);
            }

            if (msg.type === 'auth_fail') {
                setStatus('❌ PIN ไม่ถูกต้อง');
                ws.close();
            }

            if (msg.type === 'room_list') {
                msg.rooms.forEach(r => {
                    if (!rooms[r.sessionId]) rooms[r.sessionId] = { name: r.name, messages: [] };
                });
                renderRoomList();
            }

            if (msg.type === 'new_room') {
                if (!rooms[msg.sessionId]) rooms[msg.sessionId] = { name: msg.name, messages: [] };
                renderRoomList();
                // Badge บน chat button
                updateChatButtonBadge();
                showToast(`💬 ลูกค้าใหม่ "${msg.name}" เริ่มแชท`, 'info');
            }

            if (msg.type === 'room_closed') {
                delete rooms[msg.sessionId];
                if (activeRoom === msg.sessionId) {
                    activeRoom = null;
                    const box = document.getElementById('admin-messages');
                    if (box) box.innerHTML = `<div class="text-center"><span class="inline-block px-3 py-1.5 rounded-full bg-slate-100 text-slate-400 text-xs font-medium">ลูกค้าออกจากการสนทนาแล้ว</span></div>`;
                }
                renderRoomList();
            }

            if (msg.type === 'message') {
                const sid = msg.sessionId;
                if (!rooms[sid]) rooms[sid] = { name: msg.name || sid, messages: [] };
                rooms[sid].messages.push(msg);

                if (sid === activeRoom) {
                    appendMsgToBox(msg);
                } else if (!msg.own) {
                    unread[sid] = (unread[sid] || 0) + 1;
                    renderRoomList();
                    updateChatButtonBadge();
                }
            }

            if (msg.type === 'typing' && msg.sessionId === activeRoom) {
                const el = document.getElementById('admin-typing-indicator');
                if (el) el.classList.remove('hidden');
                clearTimeout(adminTyping);
                adminTyping = setTimeout(() => el && el.classList.add('hidden'), 3000);
            }
        };

        ws.onclose = () => {
            setStatus('การเชื่อมต่อขาด');
        };
    }

    /* ── Badge on floating chat button ───────────────────────── */
    function updateChatButtonBadge() {
        const btn = document.getElementById('admin-floating-chat-btn');
        if (!btn) return;
        const total = Object.values(unread).reduce((s, n) => s + n, 0)
            + Object.keys(rooms).filter(sid => rooms[sid].messages.length === 0).length;
        const badge = btn.querySelector('.chat-badge');
        if (badge) {
            if (total > 0) {
                badge.textContent = total > 9 ? '9+' : total;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        }
    }

    return { connect, selectRoom, sendMsg };
})();

/* ── Open / Close Admin Chat Panel ──────────────────────────── */
function openAdminChatPanel() {
    if (!ADMIN_AUTH.checkSession()) {
        promptAdminLogin();
        return;
    }
    const panel = document.getElementById('admin-chat-panel');
    if (!panel) return;
    panel.classList.remove('hidden');

    // Init event listeners (once)
    if (!panel.dataset.chatInited) {
        panel.dataset.chatInited = '1';

        const sendBtn = document.getElementById('admin-send-btn');
        const msgInp = document.getElementById('admin-msg-input');

        sendBtn?.addEventListener('click', () => ADMIN_CHAT.sendMsg());
        msgInp?.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ADMIN_CHAT.sendMsg(); }
        });
        msgInp?.addEventListener('input', () => {
            msgInp.style.height = '';
            msgInp.style.height = Math.min(msgInp.scrollHeight, 100) + 'px';
        });

        // Connect WebSocket as admin
        ADMIN_CHAT.connect();
    }
}

function closeAdminChatPanel() {
    const panel = document.getElementById('admin-chat-panel');
    if (panel) panel.classList.add('hidden');
}

/* ── Inject floating admin chat shortcut button ──────────────── */
(function injectAdminChatButton() {
    // เพิ่มปุ่ม Live Chat ลอยด้านซ้ายล่าง (สำหรับแอดมิน — ปิดได้)
    const btn = document.createElement('button');
    btn.id = 'admin-floating-chat-btn';
    btn.title = 'Live Chat แอดมิน (Ctrl+Shift+C)';
    btn.className = 'hidden fixed bottom-[76px] left-3 sm:bottom-6 sm:left-6 z-40 w-11 h-11 sm:w-14 sm:h-14 rounded-full bg-emerald-500 hover:bg-emerald-600 text-white shadow-xl hover:scale-110 active:scale-95 transition-all flex items-center justify-center';
    btn.innerHTML = `
        <i class="fa-solid fa-headset text-lg sm:text-xl"></i>
        <span class="chat-badge hidden absolute -top-1 -right-1 w-4 h-4 sm:w-5 sm:h-5 rounded-full bg-red-500 border-2 border-white text-white text-[9px] sm:text-[10px] font-black flex items-center justify-center"></span>`;
    btn.addEventListener('click', openAdminChatPanel);
    document.body.appendChild(btn);

    // แสดงปุ่มนี้เฉพาะเมื่อแอดมิน login อยู่
    setInterval(() => {
        if (typeof ADMIN_AUTH !== 'undefined' && ADMIN_AUTH.checkSession()) {
            btn.classList.remove('hidden');
        } else {
            btn.classList.add('hidden');
        }
    }, 2000);
})();

// Export Admin Stock & Product Management APIs to global window
window.renderAdminStockList = renderAdminStockList;
window.handleAdminStockSearch = handleAdminStockSearch;
window.clearAdminStockSearch = clearAdminStockSearch;
window.filterAdminStockBrand = filterAdminStockBrand;
window.openEditPriceModal = openEditPriceModal;
window.openAddNewProductModal = openAddNewProductModal;
window.handleSaveEditedProduct = handleSaveEditedProduct;
window.handleSaveEditedPrice = handleSaveEditedPrice;
window.handleDeleteProduct = handleDeleteProduct;
window.handleRestoreProduct = handleRestoreProduct;
window.handleDeleteCurrentProduct = handleDeleteCurrentProduct;
window.applyRecommendedAutoPriceToInput = applyRecommendedAutoPriceToInput;
window.setEditBadgePreset = setEditBadgePreset;
window.triggerManualAutoSync = triggerManualAutoSync;
window.openAddStockModal = openAddStockModal;
window.closeAddStockModal = closeAddStockModal;
window.handleSaveAddedStock = handleSaveAddedStock;
window.updateStockTextCounter = updateStockTextCounter;
window.clearStockTextarea = clearStockTextarea;
window.insertStockSampleFormat = insertStockSampleFormat;
window.handleStockFileUpload = handleStockFileUpload;

// Admin Navigation & Orders Management Controllers
window.switchAdminTab = switchAdminTab;
window.quickAdminNavigate = quickAdminNavigate;
window.updateAdminNavBadges = updateAdminNavBadges;
window.renderAdminOrdersList = renderAdminOrdersList;
window.handleAdminOrderSearch = handleAdminOrderSearch;
window.clearAdminOrderSearch = clearAdminOrderSearch;
window.filterAdminOrders = filterAdminOrders;
window.exportOrdersToCSV = exportOrdersToCSV;
window.handleClearAllAdminOrders = handleClearAllAdminOrders;
window.deleteAdminOrder = deleteAdminOrder;
window.syncLocalOrdersToServer = syncLocalOrdersToServer;
window.createDemoOrder = createDemoOrder;
window.openFulfillModal = openFulfillModal;
window.closeFulfillModal = closeFulfillModal;
window.copyFulfillG2GTitle = copyFulfillG2GTitle;
window.handleFulfillQuickPaste = handleFulfillQuickPaste;
window.handleFulfillSubmit = handleFulfillSubmit;
window.setFulfillType = setFulfillType;
window.autoFillDefaultInstruction = autoFillDefaultInstruction;

// Admin Real-Time Analytics & Telemetry Controllers
window.fetchAdminAnalytics = fetchAdminAnalytics;
window.renderAdminAnalytics = renderAdminAnalytics;
window.renderFallbackAdminAnalytics = renderFallbackAdminAnalytics;
window.renderActiveUsersList = renderActiveUsersList;
window.setOnlineUsersFilter = setOnlineUsersFilter;
window.renderTopProductsList = renderTopProductsList;
window.renderRecentEventsList = renderRecentEventsList;
window.startAdminAnalyticsAutoRefresh = startAdminAnalyticsAutoRefresh;
window.stopAdminAnalyticsAutoRefresh = stopAdminAnalyticsAutoRefresh;
window.sendTelemetryHeartbeat = sendTelemetryHeartbeat;
window.TELEMETRY = TELEMETRY;

// Admin Coupons Management Controllers
window.renderAdminCouponsList = renderAdminCouponsList;
window.handleAdminCouponSearch = handleAdminCouponSearch;
window.clearAdminCouponSearch = clearAdminCouponSearch;
window.toggleAdminCouponForm = toggleAdminCouponForm;
window.handleAdminCouponTypeChange = handleAdminCouponTypeChange;
window.handleAdminCouponFormSubmit = handleAdminCouponFormSubmit;
window.handleToggleAdminCoupon = handleToggleAdminCoupon;
window.handleDeleteAdminCoupon = handleDeleteAdminCoupon;

// Admin Users Management Controllers
window.renderAdminUsersList = renderAdminUsersList;
window.handleAdminUserSearch = handleAdminUserSearch;
window.clearAdminUserSearch = clearAdminUserSearch;
window.filterAdminUsersStatus = filterAdminUsersStatus;
window.handleAdminResetUserPassword = handleAdminResetUserPassword;
window.openAdminResetPwModal = openAdminResetPwModal;
window.closeAdminResetPwModal = closeAdminResetPwModal;
window.submitAdminResetPassword = submitAdminResetPassword;
window.handleDeleteAdminUser = handleDeleteAdminUser;
window.handleClearAllAdminUsers = handleClearAllAdminUsers;

// Admin Settings & Store Configuration Tools
window.loadAdminSettingsIntoForm = loadAdminSettingsIntoForm;
window.scrollToAdminSetting = scrollToAdminSetting;
window.updateMaintenanceBadge = updateMaintenanceBadge;
window.toggleMaintenanceModeDirectly = toggleMaintenanceModeDirectly;
window.toggleSlipOkKeyVisibility = toggleSlipOkKeyVisibility;
window.handleAdminTestSlipOK = handleAdminTestSlipOK;
window.savePromptPayAndSlipOkSettings = savePromptPayAndSlipOkSettings;
window.handleAdminTestDiscord = handleAdminTestDiscord;
window.applySmtpPreset = applySmtpPreset;
window.handleAdminTestEmail = handleAdminTestEmail;
window.downloadDatabaseBackup = downloadDatabaseBackup;
window.handleDatabaseRestore = handleDatabaseRestore;
window.saveAdminSettings = saveAdminSettings;
window.handleChangeAdminPinOnly = handleChangeAdminPinOnly;
window.toggleAdminNewPinVisibility = toggleAdminNewPinVisibility;
window.toggleAdminConfirmPinVisibility = toggleAdminConfirmPinVisibility;

// Admin Authentication & Modal Controllers
window.openAdminModal = openAdminModal;
window.closeAdminModal = closeAdminModal;
window.promptAdminLogin = promptAdminLogin;
window.closeAdminPinModal = closeAdminPinModal;
window.handleAdminPinSubmit = handleAdminPinSubmit;
window.handleAdminLogout = handleAdminLogout;
window.handleResetAdminPinToDefault = handleResetAdminPinToDefault;
window.toggleAdminPinVisibility = toggleAdminPinVisibility;

// User Authentication & Header UI Controllers
window.openAuthModal = openAuthModal;
window.closeAuthModal = closeAuthModal;
window.switchAuthTab = switchAuthTab;
window.handleLogin = handleLogin;
window.handleRegister = handleRegister;
window.handleVerifyOtp = handleVerifyOtp;
window.handleResendOtp = handleResendOtp;
window.handleForgotPasswordRequest = handleForgotPasswordRequest;
window.handleResetPasswordSubmit = handleResetPasswordSubmit;
window.handleResendResetOtp = handleResendResetOtp;
window.handleBackToRegister = handleBackToRegister;
window.handleUserLogout = handleUserLogout;
window.updateUserHeaderUI = updateUserHeaderUI;

// Customer-Facing Modals, Cart, Coupons, and Interactive Controllers
window.openProductDetailModal = openProductDetailModal;
window.closeProductDetailModal = closeProductDetailModal;
window.openCouponsModal = openCouponsModal;
window.closeCouponsModal = closeCouponsModal;
window.renderCouponsModal = renderCouponsModal;
window.copyAndApplyPromoCode = copyAndApplyPromoCode;
window.copyAndApplyPromo = copyAndApplyPromo;
window.claimVoucher = claimVoucher;
window.applyCouponFromCart = applyCouponFromCart;
window.quickApplyCoupon = quickApplyCoupon;
window.removeAppliedCoupon = removeAppliedCoupon;
window.openLogoPopup = openLogoPopup;
window.closeLogoPopup = closeLogoPopup;
window.openMobileMenu = openMobileMenu;
window.closeMobileMenu = closeMobileMenu;
window.scrollToProducts = scrollToProducts;
window.renderHighlightProducts = renderHighlightProducts;
window.renderProducts = renderProducts;
window.openSlipViewModal = openSlipViewModal;
window.closeSlipViewModal = closeSlipViewModal;
window.handleAdminSlipReupload = handleAdminSlipReupload;
window.clearSlip = () => (typeof SlipVerifier !== 'undefined' && SlipVerifier.clearSlip) ? SlipVerifier.clearSlip() : null;
window.openOrdersModal = openOrdersModal;
window.closeOrdersModal = closeOrdersModal;
window.renderOrdersHistory = renderOrdersHistory;
window.setCustomerKeysFilter = setCustomerKeysFilter;
window.handleCustomerKeysSearch = handleCustomerKeysSearch;
window.clearCustomerKeysSearch = clearCustomerKeysSearch;
window.openCartDrawer = openCartDrawer;
window.closeCartDrawer = closeCartDrawer;
window.addToCart = addToCart;
window.updateCartQuantity = updateCartQuantity;
window.removeFromCart = removeFromCart;
window.clearAllCart = clearAllCart;
window.startCheckout = startCheckout;
window.closeCheckoutModal = closeCheckoutModal;
window.copyOrderCustomerReceipt = copyOrderCustomerReceipt;
window.copyOrderCustomerSummary = copyOrderCustomerSummary;
window.viewPastOrderVault = viewPastOrderVault;
window.openVaultModal = openVaultModal;
window.closeVaultModal = closeVaultModal;
window.closeTopmostModal = closeTopmostModal;

// Member Center & Loyalty System Controllers
window.switchMemberTab = switchMemberTab;
window.renderVipPane = renderVipPane;
window.renderCoinsPane = renderCoinsPane;
window.renderReferralPane = renderReferralPane;
window.copyReferralCode = copyReferralCode;
window.copyReferralLink = copyReferralLink;
window.renderWishlistPane = renderWishlistPane;
window.addAllWishlistToCart = addAllWishlistToCart;
window.toggleProductWishlist = toggleProductWishlist;
window.toggleProductStockAlert = toggleProductStockAlert;
window.renderSettingsPane = renderSettingsPane;
window.handleSaveProfileSettings = handleSaveProfileSettings;
window.handleChangePasswordSettings = handleChangePasswordSettings;
window.updateMemberBadges = updateMemberBadges;
window.getWishlistItems = getWishlistItems;
window.isProductWishlisted = isProductWishlisted;

// In-App Notification Center & Check-in & Warranty Controllers
window.toggleNotificationCenter = toggleNotificationCenter;
window.closeNotificationCenter = closeNotificationCenter;
window.renderNotificationCenter = renderNotificationCenter;
window.markAllNotificationsRead = markAllNotificationsRead;
window.updateNotificationBadge = updateNotificationBadge;
window.handleDailyCheckIn = handleDailyCheckIn;
window.calculateWarrantyStatus = calculateWarrantyStatus;
window.renewOrderProduct = renewOrderProduct;
window.claimOrderWarranty = claimOrderWarranty;

// Additional UI & Navigation Controllers
window.selectBrand = selectBrand;
window.selectType = selectType;
window.applyFilters = applyFilters;
window.resetFilters = resetFilters;
window.submitSlipVerification = submitSlipVerification;
window.closeEditPriceModal = closeEditPriceModal;
window.updateEditPricePreview = updateEditPricePreview;
window.handleResetToAutoPrice = handleResetToAutoPrice;
window.openAdminChatPanel = openAdminChatPanel;
window.closeAdminChatPanel = closeAdminChatPanel;
window.copyFromData = copyFromData;
window.copyCombinedFromData = copyCombinedFromData;
window.copyToClipboard = copyToClipboard;
window.openG2GMarketLink = openG2GMarketLink;
window.getG2GMarketLink = getG2GMarketLink;
window.handleG2GSourcingClick = handleG2GSourcingClick;

// Outside Click Dismissal for Notification Center Dropdown
if (typeof document !== 'undefined') {
    document.addEventListener('click', (e) => {
        const dropdown = document.getElementById('notification-center-dropdown');
        const bellBtn = document.getElementById('nav-notification-btn');
        if (!dropdown || dropdown.classList.contains('hidden')) return;
        if (dropdown.contains(e.target) || (bellBtn && bellBtn.contains(e.target))) {
            return;
        }
        closeNotificationCenter();
    });

    // Initial Badge Refresh
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            updateNotificationBadge();
        });
    } else {
        setTimeout(updateNotificationBadge, 300);
    }
}

// Auto-check for ?admin=1 query parameter on page load
if (typeof window !== 'undefined' && window.location && window.location.search) {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('admin') === '1') {
            setTimeout(() => {
                if (typeof promptAdminLogin === 'function') promptAdminLogin();
            }, 300);
        }
    } catch (e) { }
}

// Immediate Telemetry initialization if page is already loaded
if (typeof document !== 'undefined' && (document.readyState === 'complete' || document.readyState === 'interactive')) {
    if (typeof TELEMETRY !== 'undefined' && typeof TELEMETRY.init === 'function') {
        TELEMETRY.init();
    }
}

// Background sync any pending local orders to server database
if (typeof window !== 'undefined') {
    setTimeout(() => {
        if (typeof syncLocalOrdersToServer === 'function') {
            syncLocalOrdersToServer();
        }
    }, 1500);
}
