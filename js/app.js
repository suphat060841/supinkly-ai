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

// Hardened Admin Authentication (Server-Verified & Cryptographic Session Token)
const ADMIN_AUTH = {
    MAX_ATTEMPTS: 5,
    LOCKOUT_DURATION_MS: 5 * 60 * 1000, // 5 minutes
    SESSION_DURATION_MS: 4 * 60 * 60 * 1000, // 4 hours session

    async hashPin(pin) {
        const encoder = new TextEncoder();
        const data = encoder.encode("supinkly_sec_salt_" + String(pin).trim());
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    getLockoutStatus() {
        const until = parseInt(localStorage.getItem('supinkly_admin_lockout_until') || '0', 10);
        if (Date.now() < until) {
            const remSeconds = Math.ceil((until - Date.now()) / 1000);
            return { locked: true, remainingSeconds: remSeconds };
        }
        return { locked: false };
    },

    async setPin(newPin) {
        if (!newPin || String(newPin).trim().length < 4) {
            throw new Error("รหัส PIN ต้องมีความยาวอย่างน้อย 4 หลัก");
        }
        const hashed = await this.hashPin(newPin);
        localStorage.setItem('supinkly_admin_pin_hash', hashed);
    },

    async verify(enteredPin) {
        const lockout = this.getLockoutStatus();
        if (lockout.locked) {
            const minutes = Math.ceil(lockout.remainingSeconds / 60);
            throw new Error(`ระบบถูกล็อกชั่วคราว กรุณารออีก ${minutes} นาที`);
        }

        const isHttp = window.location.protocol.startsWith('http');

        if (isHttp) {
            try {
                const res = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pin: enteredPin.trim() })
                });
                const data = await res.json();
                if (!res.ok || !data.success) {
                    let attempts = parseInt(localStorage.getItem('supinkly_admin_failed_attempts') || '0', 10) + 1;
                    localStorage.setItem('supinkly_admin_failed_attempts', String(attempts));
                    if (attempts >= this.MAX_ATTEMPTS) {
                        const lockoutUntil = Date.now() + this.LOCKOUT_DURATION_MS;
                        localStorage.setItem('supinkly_admin_lockout_until', String(lockoutUntil));
                        throw new Error("กรอก PIN ผิดเกิน 5 ครั้ง! ระบบล็อกการเข้าถึงชั่วคราว 5 นาที");
                    }
                    throw new Error(data.message || `รหัส PIN ไม่ถูกต้อง (เหลือโอกาสลองอีก ${this.MAX_ATTEMPTS - attempts} ครั้ง)`);
                }

                localStorage.removeItem('supinkly_admin_failed_attempts');
                localStorage.removeItem('supinkly_admin_lockout_until');

                const sessionData = {
                    token: data.token,
                    expiresAt: data.expiresAt || (Date.now() + this.SESSION_DURATION_MS)
                };
                sessionStorage.setItem('supinkly_admin_session', JSON.stringify(sessionData));
                return true;
            } catch (err) {
                throw err;
            }
        } else {
            // Local file:// protocol fallback for offline dev
            const hashedEntered = await this.hashPin(enteredPin);
            let storedHash = localStorage.getItem('supinkly_admin_pin_hash');
            if (!storedHash) {
                storedHash = await this.hashPin('8899');
            }

            if (hashedEntered === storedHash) {
                localStorage.removeItem('supinkly_admin_failed_attempts');
                localStorage.removeItem('supinkly_admin_lockout_until');

                const sessionToken = Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2, '0')).join('');
                const sessionData = {
                    token: sessionToken,
                    expiresAt: Date.now() + this.SESSION_DURATION_MS
                };
                sessionStorage.setItem('supinkly_admin_session', JSON.stringify(sessionData));
                return true;
            } else {
                let attempts = parseInt(localStorage.getItem('supinkly_admin_failed_attempts') || '0', 10) + 1;
                localStorage.setItem('supinkly_admin_failed_attempts', String(attempts));
                if (attempts >= this.MAX_ATTEMPTS) {
                    const lockoutUntil = Date.now() + this.LOCKOUT_DURATION_MS;
                    localStorage.setItem('supinkly_admin_lockout_until', String(lockoutUntil));
                    throw new Error("กรอก PIN ผิดเกิน 5 ครั้ง! ระบบล็อกการเข้าถึงชั่วคราว 5 นาที");
                } else {
                    throw new Error(`รหัส PIN ไม่ถูกต้อง (เหลือโอกาสลองอีก ${this.MAX_ATTEMPTS - attempts} ครั้ง)`);
                }
            }
        }
    },

    getToken() {
        try {
            const raw = sessionStorage.getItem('supinkly_admin_session');
            if (!raw) return null;
            const session = JSON.parse(raw);
            if (session && session.token && Date.now() < session.expiresAt) {
                return session.token;
            }
        } catch {}
        return null;
    },

    getHeaders() {
        const token = this.getToken();
        return {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}`, 'x-admin-token': token } : {})
        };
    },

    checkSession() {
        const token = this.getToken();
        if (!token) {
            sessionStorage.removeItem('supinkly_admin_session');
            return false;
        }
        return true;
    },

    logout() {
        sessionStorage.removeItem('supinkly_admin_session');
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
    products: PRODUCTS.map(p => ({ ...p, stock: p.stock || 50 })),
    inventory: getSecureInventory(),
    filteredProducts: [],
    cart: loadAndSanitizeCart(),
    user: (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) ? USER_AUTH.getUser() : null,
    orders: JSON.parse(localStorage.getItem('supinkly_orders') || '[]'),
    filterBrand: 'all',
    filterType: 'all',
    searchQuery: '',
    sortBy: 'popular',
    qrTimer: null,
    qrSecondsLeft: 900
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
    let modified = false;

    // Remove any stale cached prices that were not manually overridden by admin
    Object.keys(customPrices).forEach(id => {
        if (!customPrices[id].manualOverride) {
            delete customPrices[id];
            modified = true;
        }
    });

    if (modified) {
        try {
            localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));
        } catch (e) {}
    }

    state.products.forEach(p => {
        if (customPrices[p.id] && customPrices[p.id].manualOverride) {
            if (typeof customPrices[p.id].price === 'number') p.price = customPrices[p.id].price;
            if (typeof customPrices[p.id].originalPrice === 'number') p.originalPrice = customPrices[p.id].originalPrice;
        }
    });
}

// Sync live stock count & custom prices (Referenced from G2G Market Auto-Sync)
function syncStockCount() {
    // [FIX] Snapshot g2gStockAvailable BEFORE applyCustomPricesToProducts() clears non-manualOverride entries
    const rawCustomPrices = getCustomPrices();
    const g2gStockSnapshot = {};
    Object.keys(rawCustomPrices).forEach(id => {
        if (rawCustomPrices[id]?.g2gStockAvailable != null) {
            g2gStockSnapshot[id] = rawCustomPrices[id].g2gStockAvailable;
        }
    });

    applyCustomPricesToProducts();

    state.products.forEach(p => {
        const pool = state.inventory[p.id] || [];
        const g2gStock = g2gStockSnapshot[p.id]
            ?? (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks[p.id]?.g2gStock)
            ?? (p.stock || 50);

        p.vaultStock = pool.length;
        p.marketStock = g2gStock;
        // Total available stock references G2G real-time market availability
        p.stock = Math.max(pool.length, g2gStock || 50);
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
document.addEventListener('DOMContentLoaded', async () => {
    syncStockCount();
    initHeader();
    initFilters();
    renderProducts();
    updateCartUI();
    renderBrandTabs();
    initEvents();

    // Launch G2G Market Real-Time Auto-Sync Engine (Zero button clicks required)
    if (typeof G2G_SYNC !== 'undefined') {
        G2G_SYNC.init();
    }

    // Restore user session & sync server orders if logged in
    if (window.location.protocol.startsWith('http') && typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
        try {
            const ok = await USER_AUTH.verifySession();
            if (ok) {
                await syncUserOrdersFromServer();
                initHeader(); // re-render header with user info
            } else {
                initHeader(); // session expired — show login button
            }
        } catch {}
    }
});

function saveCart() {
    localStorage.setItem('supinkly_cart', JSON.stringify(state.cart));
    updateCartUI();
}

function saveOrders() {
    localStorage.setItem('supinkly_orders', JSON.stringify(state.orders));
    const navCnt = document.getElementById('nav-orders-count');
    if (navCnt) navCnt.textContent = state.orders.length;
}

// Header & User Actions
function initHeader() {
    const userContainer = document.getElementById('user-header-section');
    if (!userContainer) return;

    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;
    const displayName = user?.displayName || user?.email?.split('@')[0] || '';

    if (isLoggedIn && user) {
        userContainer.innerHTML = `
            <div class="flex items-center gap-1.5 sm:gap-2">
                <button onclick="openOrdersModal()" class="h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-purple-50 border-2 border-purple-200 text-purple-700 hover:bg-purple-100 hover:border-purple-300 transition-all shadow-sm flex items-center justify-center gap-1.5 sm:gap-2 shrink-0">
                    <i class="fa-solid fa-box-open text-sm sm:text-base text-pink-500"></i>
                    <span>คีย์ของฉัน (<span id="nav-orders-count">${state.orders.length}</span>)</span>
                </button>
                <div class="relative group">
                    <button class="h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-emerald-50 border-2 border-emerald-200 text-emerald-700 hover:bg-emerald-100 transition-all shadow-sm flex items-center justify-center gap-1.5 shrink-0">
                        <i class="fa-solid fa-circle-user text-emerald-500 text-base"></i>
                        <span class="hidden sm:inline max-w-[80px] truncate">${escapeHTML(displayName)}</span>
                        <i class="fa-solid fa-chevron-down text-[10px] text-emerald-500"></i>
                    </button>
                    <div class="hidden group-hover:flex absolute right-0 top-full mt-1.5 w-44 bg-white rounded-2xl shadow-xl border border-slate-100 flex-col overflow-hidden z-50 py-1">
                        <div class="px-4 py-2 border-b border-slate-100">
                            <div class="text-xs font-bold text-slate-800 truncate">${escapeHTML(displayName)}</div>
                            <div class="text-[10px] text-slate-400 font-medium truncate">${escapeHTML(user.email || '')}</div>
                        </div>
                        <button onclick="openOrdersModal()" class="w-full text-left px-4 py-2.5 text-xs font-bold text-slate-700 hover:bg-slate-50 flex items-center gap-2">
                            <i class="fa-solid fa-vault text-purple-500 w-4"></i> คีย์ของฉัน
                        </button>
                        <button onclick="handleUserLogout()" class="w-full text-left px-4 py-2.5 text-xs font-bold text-red-600 hover:bg-red-50 flex items-center gap-2">
                            <i class="fa-solid fa-right-from-bracket w-4"></i> ออกจากระบบ
                        </button>
                    </div>
                </div>
            </div>
        `;
    } else {
        userContainer.innerHTML = `
            <div class="flex items-center gap-1.5 sm:gap-2">
                <button onclick="openOrdersModal()" class="h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-purple-50 border-2 border-purple-200 text-purple-700 hover:bg-purple-100 hover:border-purple-300 transition-all shadow-sm flex items-center justify-center gap-1.5 sm:gap-2 shrink-0">
                    <i class="fa-solid fa-box-open text-sm sm:text-base text-pink-500"></i>
                    <span>คีย์ของฉัน (<span id="nav-orders-count">${state.orders.length}</span>)</span>
                </button>
                <button onclick="openAuthModal('login')" class="h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-pink-500 hover:bg-pink-600 text-white transition-all shadow-sm flex items-center justify-center gap-1.5 shrink-0">
                    <i class="fa-solid fa-right-to-bracket text-sm"></i>
                    <span class="hidden sm:inline">เข้าสู่ระบบ</span>
                </button>
            </div>
        `;
    }
}

// Brand Tabs
function renderBrandTabs() {
    const container = document.getElementById('brand-tabs-container');
    if (!container) return;

    const brands = [
        { key: "all", name: "สินค้าทั้งหมด", icon: "fa-solid fa-shapes", count: state.products.length },
        { key: "CapCut", name: "CapCut", icon: "fa-solid fa-scissors", count: state.products.filter(p => p.brand === 'CapCut').length },
        { key: "Google AI", name: "Google AI", icon: "fa-solid fa-wand-magic-sparkles", count: state.products.filter(p => p.brand === 'Google AI').length },
        { key: "Google", name: "Google", icon: "fa-brands fa-google", count: state.products.filter(p => p.brand === 'Google').length },
        { key: "Grok", name: "Grok", icon: "fa-solid fa-bolt", count: state.products.filter(p => p.brand === 'Grok').length },
        { key: "Claude", name: "Claude", icon: "fa-solid fa-brain", count: state.products.filter(p => p.brand === 'Claude').length },
        { key: "Adobe", name: "Adobe", icon: "fa-solid fa-bezier-curve", count: state.products.filter(p => p.brand === 'Adobe').length },
        { key: "Microsoft", name: "Microsoft", icon: "fa-brands fa-microsoft", count: state.products.filter(p => p.brand === 'Microsoft').length },
    ];

    container.innerHTML = brands.map(b => `
        <button onclick="selectBrand('${b.key}')" 
            class="brand-tab flex items-center gap-1.5 sm:gap-2 px-3 py-1.5 sm:px-4 sm:py-2.5 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold border transition-all whitespace-nowrap shrink-0 ${state.filterBrand === b.key ? 'active' : ''}">
            <i class="${b.icon} ${state.filterBrand === b.key ? 'text-white' : 'text-pink-500'} text-xs sm:text-sm"></i>
            <span>${escapeHTML(b.name)}</span>
            <span class="ml-0.5 sm:ml-1 px-1.5 py-0.2 sm:px-2 sm:py-0.5 rounded-full text-[10px] sm:text-xs ${state.filterBrand === b.key ? 'bg-white/25 text-white font-black' : 'bg-slate-100 text-slate-600 font-bold'}">${b.count}</span>
        </button>
    `).join('');
}

function selectBrand(brand) {
    state.filterBrand = brand;
    renderBrandTabs();
    applyFilters();
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
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase().trim();
            applyFilters();
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
    let result = [...state.products];

    if (state.filterBrand !== 'all') {
        result = result.filter(p => p.brand === state.filterBrand);
    }

    if (state.filterType !== 'all') {
        result = result.filter(p => p.typeKey === state.filterType);
    }

    if (state.searchQuery !== '') {
        const q = state.searchQuery.toLowerCase().trim();
        result = result.filter(p => 
            (p.title && p.title.toLowerCase().includes(q)) ||
            (p.brand && p.brand.toLowerCase().includes(q)) ||
            (p.subtitle && p.subtitle.toLowerCase().includes(q)) ||
            (p.devices && p.devices.toLowerCase().includes(q)) ||
            (p.type && p.type.toLowerCase().includes(q)) ||
            (p.badge && p.badge.toLowerCase().includes(q)) ||
            (p.description && p.description.toLowerCase().includes(q))
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

// Render Products Grid (Bright, High-Contrast, Ultra-Readable Cards)
function renderProducts() {
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
        let typeBadgeClass = "bg-purple-50 text-purple-700 border-purple-200";
        let typeIcon = "fa-solid fa-sparkles";
        if (product.typeKey === 'private') {
            typeBadgeClass = "bg-rose-50 text-rose-700 border-rose-200";
            typeIcon = "fa-solid fa-user-shield";
        } else if (product.typeKey === 'shared') {
            typeBadgeClass = "bg-amber-50 text-amber-800 border-amber-200";
            typeIcon = "fa-solid fa-users";
        } else if (product.typeKey === 'link') {
            typeBadgeClass = "bg-cyan-50 text-cyan-800 border-cyan-200";
            typeIcon = "fa-solid fa-link";
        } else if (product.typeKey === 'key') {
            typeBadgeClass = "bg-emerald-50 text-emerald-800 border-emerald-200";
            typeIcon = "fa-solid fa-key";
        } else if (product.typeKey === 'topup') {
            typeBadgeClass = "bg-indigo-50 text-indigo-800 border-indigo-200";
            typeIcon = "fa-solid fa-bolt";
        }

        const inStock = product.stock > 0;
        const brandGrad = product.brandBadgeColor || "from-pink-500 to-rose-500";
        const discountPct = (product.originalPrice && product.originalPrice > product.price)
            ? Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100)
            : 0;

        return `
            <div class="bg-white rounded-2xl sm:rounded-3xl p-4 sm:p-5 border-2 border-slate-100 hover:border-pink-300 shadow-xs hover:shadow-xl hover:shadow-pink-500/10 flex flex-col justify-between transition-all duration-300 group hover:-translate-y-1 relative overflow-hidden">
                
                <div>
                    <!-- Header of Card: Brand & Plan Type -->
                    <div class="flex items-center justify-between gap-1.5 mb-2.5">
                        <div class="flex items-center gap-2">
                            <span class="w-8 h-8 rounded-xl bg-gradient-to-tr ${brandGrad} text-white flex items-center justify-center text-[11px] font-bold shadow-xs">
                                ${escapeHTML(product.brandCode)}
                            </span>
                            <span class="text-xs font-bold text-slate-800 tracking-wide">${escapeHTML(product.brand)}</span>
                        </div>
                        <span class="px-2.5 py-1 rounded-full text-[11px] font-bold border ${typeBadgeClass} flex items-center gap-1">
                            <i class="${typeIcon} text-[10px]"></i>
                            <span>${escapeHTML(product.type)}</span>
                        </span>
                    </div>

                    <!-- Marketing Badge (e.g. 🔥 ขายดีอันดับ 1) -->
                    ${product.badge ? `
                        <div class="mb-2">
                            <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[11px] font-bold bg-pink-100 text-pink-700 border border-pink-200">
                                <span>${escapeHTML(product.badge)}</span>
                            </span>
                        </div>
                    ` : ''}

                    <!-- Product Title -->
                    <h3 class="text-sm sm:text-base font-bold text-slate-900 line-clamp-2 min-h-[40px] sm:min-h-[44px] group-hover:text-pink-600 transition-colors leading-snug">
                        ${escapeHTML(product.title)}
                    </h3>

                    <!-- Concise Subtitle Benefit -->
                    <p class="text-xs text-slate-500 font-medium mt-1 leading-relaxed line-clamp-2 min-h-[32px]">
                        ${escapeHTML(product.subtitle || product.description)}
                    </p>

                    <!-- 2x2 Neat Specs Grid -->
                    <div class="grid grid-cols-2 gap-1.5 mt-3 text-[11px] font-medium text-slate-700">
                        <div class="bg-slate-50 border border-slate-200/90 rounded-xl px-2.5 py-1.5 flex items-center gap-1.5 truncate" title="ระยะเวลา: ${escapeHTML(product.duration || '30 วัน')}">
                            <i class="fa-regular fa-clock text-pink-500 text-xs shrink-0"></i>
                            <span class="truncate">${escapeHTML(product.duration || '30 วัน')}</span>
                        </div>
                        <div class="bg-slate-50 border border-slate-200/90 rounded-xl px-2.5 py-1.5 flex items-center gap-1.5 truncate" title="อุปกรณ์: ${escapeHTML(product.devices || 'ทุกอุปกรณ์')}">
                            <i class="fa-solid fa-desktop text-blue-500 text-xs shrink-0"></i>
                            <span class="truncate">${escapeHTML(product.devices || 'ทุกอุปกรณ์')}</span>
                        </div>
                        <div class="bg-slate-50 border border-slate-200/90 rounded-xl px-2.5 py-1.5 flex items-center gap-1.5 truncate" title="รับประกัน: ${escapeHTML(product.warranty || '30 วัน')}">
                            <i class="fa-solid fa-shield-halved text-emerald-600 text-xs shrink-0"></i>
                            <span class="truncate">ประกัน ${escapeHTML(product.warranty || '30 วัน')}</span>
                        </div>
                        <div class="bg-slate-50 border border-slate-200/90 rounded-xl px-2.5 py-1.5 flex items-center gap-1.5 truncate" title="ระบบพร้อมส่งมอบตลอด 24 ชม.">
                            <i class="fa-solid fa-bolt text-amber-500 text-xs shrink-0"></i>
                            <span class="truncate">พร้อมส่งมอบ 24 ชม.</span>
                        </div>
                    </div>

                    <!-- Live Stock Counter & Rating -->
                    <div class="flex items-center justify-between mt-3 text-xs font-semibold border-t border-slate-100 pt-2.5">
                        <span class="flex items-center gap-1.5 ${inStock ? 'text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-lg border border-emerald-200 font-bold' : 'text-rose-700 bg-rose-50 px-2.5 py-0.5 rounded-lg border border-rose-200 font-bold'}">
                            <span class="w-2 h-2 rounded-full ${inStock ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                            <span class="text-[11px]">${inStock ? `มีพร้อมส่ง (${product.stock} ชิ้น)` : 'สินค้าหมดชั่วคราว'}</span>
                        </span>
                        <span class="flex items-center gap-1 text-slate-500 text-[11px] font-semibold">
                            <i class="fa-solid fa-star text-amber-400 text-xs"></i>
                            <b class="text-slate-800">${product.rating || '5.0'}</b>
                            <span class="text-slate-400">(${product.soldCount.toLocaleString()})</span>
                        </span>
                    </div>
                </div>

                <!-- Price and Action Buttons -->
                <div class="mt-3.5 pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                    <div>
                        <div class="flex items-center gap-1.5">
                            <span class="text-xs text-slate-400 line-through font-medium">฿${product.originalPrice.toFixed(2)}</span>
                            ${discountPct > 0 ? `<span class="text-[10px] font-bold text-rose-600 bg-rose-50 border border-rose-200 px-1.5 py-0.2 rounded-md">-${discountPct}%</span>` : ''}
                        </div>
                        <div class="text-2xl sm:text-2xl font-black text-pink-600 flex items-baseline tracking-tight">
                            <span class="text-sm font-extrabold mr-0.5">฿</span>${product.price.toFixed(2)}
                        </div>
                    </div>
                    <div class="flex items-center gap-1.5 sm:gap-2">
                        <button data-action="detail" data-product-id="${escapeHTML(product.id)}" title="ดูรายละเอียดสินค้า" 
                            class="w-10 h-10 rounded-2xl bg-slate-100 border border-slate-200 hover:border-pink-300 text-slate-600 hover:text-pink-600 flex items-center justify-center text-sm transition-all shadow-2xs hover:scale-105 active:scale-95">
                            <i class="fa-regular fa-eye"></i>
                        </button>
                        <button data-action="add-cart" data-product-id="${escapeHTML(product.id)}"
                            ${!inStock ? 'disabled' : ''}
                            class="gradient-btn px-3.5 sm:px-4 h-10 rounded-2xl text-xs sm:text-sm font-bold flex items-center gap-1.5 shadow-md shadow-pink-500/20 hover:scale-[1.02] active:scale-95 transition-all ${!inStock ? 'opacity-40 cursor-not-allowed shadow-none' : ''}">
                            <i class="fa-solid fa-cart-plus"></i>
                            <span>${inStock ? 'ใส่ตะกร้า' : 'หมด'}</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    // [FIX #6] Event delegation สำหรับ product cards ทั้งหมด
    container.removeEventListener('click', handleProductCardClick);
    container.addEventListener('click', handleProductCardClick);
}

function handleProductCardClick(e) {
    const detailBtn = e.target.closest('[data-action="detail"]');
    const cartBtn   = e.target.closest('[data-action="add-cart"]');
    if (detailBtn) {
        const id = detailBtn.getAttribute('data-product-id');
        if (id) openProductDetailModal(id);
    } else if (cartBtn && !cartBtn.disabled) {
        const id = cartBtn.getAttribute('data-product-id');
        if (id) addToCart(id);
    }

}

function resetFilters() {
    state.filterBrand = 'all';
    state.filterType = 'all';
    state.searchQuery = '';
    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';
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

    const availableStock = master.stock || (state.inventory[productId] || []).length || 50;
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
}

function updateCartQuantity(productId, delta) {
    const item = state.cart.find(i => i.productId === productId);
    if (!item) return;

    const master = getMasterProduct(productId);
    const availableStock = master ? (master.stock || (state.inventory[productId] || []).length || 50) : 50;
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
    const verifiedTotal = calculateVerifiedTotal();

    if (countBadge) {
        countBadge.textContent = totalCount;
        countBadge.classList.toggle('hidden', totalCount <= 0);
    }

    if (subtotalEl) subtotalEl.textContent = `฿${verifiedTotal.toFixed(2)}`;
    if (totalEl) totalEl.textContent = `฿${verifiedTotal.toFixed(2)}`;

    if (checkoutBtn) {
        checkoutBtn.disabled = state.cart.length === 0 || verifiedTotal <= 0;
        if (state.cart.length === 0 || verifiedTotal <= 0) {
            checkoutBtn.classList.add('opacity-50', 'cursor-not-allowed');
        } else {
            checkoutBtn.classList.remove('opacity-50', 'cursor-not-allowed');
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
                        <div class="w-11 h-11 rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center font-bold text-xs text-pink-600 shrink-0">
                            ${escapeHTML(master.brandCode)}
                        </div>
                        <div class="flex-1 min-w-0">
                            <h4 class="text-xs font-bold text-slate-900 truncate">${escapeHTML(master.title)}</h4>
                            <div class="text-xs text-pink-600 font-bold mt-0.5">฿${master.price.toFixed(2)}</div>
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

    const modal = document.getElementById('checkout-modal');
    if (!modal) return;

    for (const item of state.cart) {
        const master = getMasterProduct(item.productId);
        const availableStock = master ? (master.stock || (state.inventory[item.productId] || []).length || 50) : 50;
        if (availableStock < item.quantity) {
            showToast(`สินค้า "${master ? master.title : ''}" ในสต็อกไม่เพียงพอ`, "warning");
            return;
        }
    }

    const verifiedTotal = calculateVerifiedTotal();
    if (verifiedTotal <= 0) {
        showToast("ยอดชำระเงินต้องมากกว่า 0 บาท", "warning");
        return;
    }
    const refCode = "SPK" + Math.floor(100000 + Math.random() * 900000);

    document.getElementById('checkout-ref-code').textContent = refCode;
    document.getElementById('checkout-total-amount').textContent = `฿${verifiedTotal.toFixed(2)}`;
    const activeAuthUser = (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) ? USER_AUTH.getUser() : null;
    document.getElementById('checkout-email-input').value = activeAuthUser?.email || '';
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
        summaryContainer.innerHTML = state.cart.map(i => {
            const master = getMasterProduct(i.productId);
            if (!master) return '';
            return `
                <div class="flex items-center justify-between text-xs py-1 text-slate-700 font-medium">
                    <span class="truncate flex-1 pr-2">${escapeHTML(master.title)} (x${i.quantity})</span>
                    <span class="font-bold text-pink-600">฿${(master.price * i.quantity).toFixed(2)}</span>
                </div>
            `;
        }).join('');
    }

    startQrCountdown();
    modal.classList.remove('hidden');
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
            // [SECURITY] Disable submit button when QR expires
            const verifyBtn = document.getElementById('verify-slip-btn');
            if (verifyBtn) {
                verifyBtn.disabled = true;
                verifyBtn.innerHTML = `<i class="fa-solid fa-clock-rotate-left text-sm"></i> QR หมดอายุ — กรุณาสร้าง QR ใหม่`;
                verifyBtn.classList.add('opacity-50', 'cursor-not-allowed');
            }
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
    // Sanitize and validate cart
    state.cart = (state.cart || []).filter(item => item && item.productId && getMasterProduct(item.productId));
    state.cart.forEach(item => {
        item.quantity = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));
    });

    if (!state.cart || state.cart.length === 0) {
        showToast("ตะกร้าสินค้าว่างเปล่า กรุณาเลือกสินค้าก่อนชำระเงิน", "warning");
        return;
    }

    const verifiedTotal = calculateVerifiedTotal();
    if (!verifiedTotal || verifiedTotal <= 0) {
        showToast("ยอดชำระเงินไม่ถูกต้อง กรุณาเลือกสินค้าใหม่", "warning");
        return;
    }

    const emailInput = document.getElementById('checkout-email-input');
    const recipientEmail = (emailInput ? emailInput.value : '').trim();

    // Stricter email format validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!recipientEmail || !emailRegex.test(recipientEmail)) {
        showToast("กรุณากรอกอีเมลที่ถูกต้องสำหรับรับสำรองข้อมูลสินค้า (เช่น name@example.com)", "warning");
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
        let finalOrder = null;

        if (window.location.protocol.startsWith('http')) {
            const formData = new FormData();
            formData.append('slip', SlipVerifier.selectedFile);
            formData.append('email', recipientEmail);
            formData.append('cartItems', JSON.stringify(state.cart.map(i => ({ productId: i.productId, quantity: i.quantity }))));

            const headers = {};
            if (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
                const token = USER_AUTH.getToken();
                if (token) headers['x-user-token'] = token;
            }

            const res = await fetch('/api/checkout/verify-slip', {
                method: 'POST',
                headers,
                body: formData
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                throw new Error(data.message || "การตรวจสอบสลิปล้มเหลว หรือยอดเงินไม่ถูกต้อง");
            }

            finalOrder = data.order;
        } else {
            // Local file:// protocol fallback for offline developer testing
            const result = await SlipVerifier.verifySlip(verifiedTotal, STORE_CONFIG.promptPayNumber, state.cart, recipientEmail);
            const deliveredItems = [];
            let hasPendingFulfillment = false;
            for (const item of state.cart) {
                const master = getMasterProduct(item.productId);
                const pool = state.inventory[item.productId] || [];
                const itemQty = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));
                for (let i = 0; i < itemQty; i++) {
                    if (pool.length > 0) {
                        deliveredItems.push({
                            productId: item.productId,
                            productTitle: master ? master.title : "Digital Item",
                            price: master ? master.price : 0,
                            warranty: master ? master.warranty : "30 วัน",
                            status: "delivered",
                            credentials: pool.shift()
                        });
                    } else {
                        hasPendingFulfillment = true;
                        deliveredItems.push({
                            productId: item.productId,
                            productTitle: master ? master.title : "Digital Item",
                            price: master ? master.price : 0,
                            warranty: master ? master.warranty : "30 วัน",
                            status: "pending_fulfillment",
                            credentials: null
                        });
                    }
                }
            }
            finalOrder = {
                orderId: "SPK-" + Date.now().toString().slice(-6) + Math.random().toString(36).substring(2, 6).toUpperCase(),
                date: new Date().toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }),
                totalAmount: verifiedTotal,
                paymentMethod: "Thai QR PromptPay",
                recipientEmail: recipientEmail,
                transRef: result.transRef,
                slipFingerprint: SlipVerifier.fileFingerprint,
                items: deliveredItems,
                status: hasPendingFulfillment ? "🟡 รอจัดส่งสินค้า (5-15 นาที)" : "🟢 จัดส่งสำเร็จทันที (Instant Vault)"
            };
        }

        btn.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400"></i> สลิปถูกต้อง! กำลังจัดส่งรหัส...`;

        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
            closeCheckoutModal();

            // Decrement synced market stock for purchased items
            const customPrices = getCustomPrices();
            for (const item of state.cart) {
                const itemQty = Math.max(1, Math.min(50, parseInt(item.quantity, 10) || 1));
                if (customPrices[item.productId] && typeof customPrices[item.productId].g2gStockAvailable === 'number') {
                    customPrices[item.productId].g2gStockAvailable = Math.max(0, customPrices[item.productId].g2gStockAvailable - itemQty);
                }
            }
            try {
                localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));
            } catch (e) {}

            state.orders.unshift(finalOrder);
            saveOrders();

            state.cart = [];
            saveCart();

            syncStockCount();
            renderProducts();

            openVaultModal(finalOrder);
            const isPending = (finalOrder.items || []).some(it => !it.credentials || it.status === 'pending_fulfillment');
            if (isPending) {
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
    const isPending = order.items.some(item => !item.credentials || item.status === 'pending_fulfillment');
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
                            <h4 class="text-sm font-bold text-slate-900 flex items-center gap-2">
                                <span class="w-6 h-6 rounded-full bg-amber-500 text-white flex items-center justify-center text-xs font-bold">${idx + 1}</span>
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
                                <span class="text-sm font-mono font-bold text-pink-600 select-all">${escapeHTML(cred.email)}</span>
                            </div>
                            <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.email)}" data-msg="คัดลอกอีเมลแล้ว" class="px-3 py-1.5 rounded-xl bg-pink-100 text-pink-700 hover:bg-pink-200 text-xs font-bold transition-all">
                                <i class="fa-regular fa-copy"></i> คัดลอก
                            </button>
                        </div>
                        <div class="flex items-center justify-between bg-slate-50 p-3 rounded-xl border border-slate-200">
                            <div>
                                <span class="text-xs text-slate-500 font-bold block">รหัสผ่าน (Password):</span>
                                <span class="text-sm font-mono font-bold text-cyan-700 select-all">${escapeHTML(cred.password)}</span>
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
                            <a href="${escapeHTML(cred.link)}" target="_blank" class="px-3 py-1.5 rounded-xl gradient-btn text-white text-xs font-bold flex items-center gap-1">
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
                            <span class="text-sm font-mono font-bold text-emerald-700 select-all">${escapeHTML(cred.key || '')}</span>
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
                        <h4 class="text-sm font-bold text-slate-900 flex items-center gap-2">
                            <span class="w-6 h-6 rounded-full bg-pink-500 text-white flex items-center justify-center text-xs font-bold">${idx + 1}</span>
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

// Background poller for Vault modal & Orders modal (auto-updates when admin fulfills order)
if (!window.vaultPollTimer) {
    window.vaultPollTimer = setInterval(() => {
        const modal = document.getElementById('vault-modal');
        if (modal && !modal.classList.contains('hidden') && state.currentVaultOrderId) {
            const currentOrder = state.orders.find(o => o.orderId === state.currentVaultOrderId);
            if (currentOrder) {
                const wasPending = modal.getAttribute('data-is-pending') === 'true';
                const isNowDelivered = currentOrder.items.every(it => it.credentials && it.status !== 'pending_fulfillment');
                if (wasPending && isNowDelivered) {
                    showToast("🎉 ร้านค้าส่งมอบรหัสให้คุณเรียบร้อยแล้ว!", "success");
                    openVaultModal(currentOrder);
                }
            }
        }

        // Also live update Orders Modal ("คีย์ของฉัน") if open
        const ordersModal = document.getElementById('orders-modal');
        if (ordersModal && !ordersModal.classList.contains('hidden')) {
            renderOrdersHistory();
        }
    }, 2000);
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

    const totalOrders = state.orders.length;
    const deliveredOrders = state.orders.filter(o => o.items && o.items.every(it => it.credentials && it.status !== 'pending_fulfillment')).length;
    const pendingOrders = totalOrders - deliveredOrders;

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
        filtered = filtered.filter(o => o.items && o.items.every(it => it.credentials && it.status !== 'pending_fulfillment'));
    } else if (customerKeysFilter === 'pending') {
        filtered = filtered.filter(o => o.items && o.items.some(it => !it.credentials || it.status === 'pending_fulfillment'));
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
        const isOrderPending = (order.items || []).some(it => !it.credentials || it.status === 'pending_fulfillment');
        
        return `
            <div class="p-4 sm:p-5 rounded-2xl bg-white border-2 ${isOrderPending ? 'border-amber-300 bg-amber-50/20' : 'border-slate-200'} mb-3.5 hover:border-pink-300 transition-all shadow-sm">
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
                    <span class="px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1.5 shadow-xs ${
                        isOrderPending 
                            ? 'bg-amber-100 text-amber-900 border border-amber-300 animate-pulse' 
                            : 'bg-emerald-100 text-emerald-900 border border-emerald-300'
                    }">
                        <i class="fa-solid ${isOrderPending ? 'fa-spinner fa-spin' : 'fa-circle-check'} text-xs"></i>
                        <span>${isOrderPending ? 'กำลังจัดเตรียมรหัส (5-15 นาที)' : 'จัดส่งแล้ว (พร้อมใช้งาน)'}</span>
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
                                        <span class="text-[10px] bg-amber-200 text-amber-900 px-2 py-0.5 rounded-md font-bold animate-pulse">กำลังดำเนินการ</span>
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
                                            <span class="text-xs sm:text-sm font-mono font-bold text-pink-600 truncate block select-all">${escapeHTML(cred.email)}</span>
                                        </div>
                                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(cred.email)}" data-msg="คัดลอกอีเมลแล้ว" class="px-2.5 py-1.5 rounded-lg bg-pink-100 hover:bg-pink-200 text-pink-700 text-xs font-bold transition-all shrink-0">
                                            <i class="fa-regular fa-copy"></i> คัดลอก
                                        </button>
                                    </div>
                                    <div class="flex items-center justify-between gap-2 pt-2 border-t border-slate-200/70">
                                        <div class="min-w-0 flex-1">
                                            <span class="text-[11px] font-bold text-slate-500 block">รหัสผ่าน (Password):</span>
                                            <span class="text-xs sm:text-sm font-mono font-bold text-cyan-700 truncate block select-all">${escapeHTML(cred.password)}</span>
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
                                        <a href="${escapeHTML(cred.link)}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1.5 rounded-lg gradient-btn text-white text-xs font-bold flex items-center gap-1">
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
                                        <span class="text-xs sm:text-sm font-mono font-bold text-emerald-700 truncate block select-all">${escapeHTML(cred.key || '')}</span>
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

                        return `
                            <div class="p-3 sm:p-3.5 rounded-xl bg-slate-50/70 border border-slate-200">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="flex items-center gap-2 min-w-0">
                                        <span class="w-5 h-5 rounded-full bg-pink-500 text-white flex items-center justify-center text-[10px] font-bold shrink-0">
                                            ${itIdx + 1}
                                        </span>
                                        <span class="font-bold text-slate-900 text-xs sm:text-sm truncate">
                                            ${escapeHTML(item.productTitle)}
                                        </span>
                                    </div>
                                    <div class="flex items-center gap-2 shrink-0">
                                        <span class="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-bold border border-emerald-200">
                                            🛡️ ประกัน ${escapeHTML(item.warranty || '30 วัน')}
                                        </span>
                                        <span class="font-bold text-pink-600 text-xs sm:text-sm">฿${(item.price || 0).toFixed(2)}</span>
                                    </div>
                                </div>

                                ${credBlock}
                            </div>
                        `;
                    }).join('')}
                </div>

                <!-- Order Footer -->
                <div class="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-100 mt-3 text-xs">
                    <div class="font-bold text-slate-600">
                        ยอดรวมคำสั่งซื้อ: <span class="text-base font-black text-slate-900">฿${(order.totalAmount || 0).toFixed(2)}</span>
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

function openOrdersModal() {
    const modal = document.getElementById('orders-modal');
    if (!modal) return;

    renderOrdersHistory();
    modal.classList.remove('hidden');

    // If logged in, fetch latest orders from server in background to reflect fulfillment updates
    if (typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn()) {
        syncUserOrdersFromServer().then(() => {
            renderOrdersHistory();
        }).catch(() => {});
    }
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

// ==========================================
// SECURED ADMIN PANEL (SESSION & PIN AUTHENTICATED)
// ==========================================
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
        if (pinInput) pinInput.value = '';
        pinModal.classList.remove('hidden');
    }
}

function closeAdminPinModal() {
    const pinModal = document.getElementById('admin-pin-modal');
    if (pinModal) pinModal.classList.add('hidden');
}

async function handleAdminPinSubmit(e) {
    e.preventDefault();
    const pinInput = document.getElementById('admin-pin-input');
    const pin = (pinInput ? pinInput.value : '').trim();
    const submitBtn = document.getElementById('admin-pin-submit-btn');

    if (!pin) {
        showToast("กรุณากรอกรหัส PIN", "warning");
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
            pinInput.value = '';
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
    const master = getMasterProduct(productId);
    if (!master) return "https://www.g2g.com";
    const brand = (master.brand || '').toLowerCase();
    if (brand.includes("capcut")) return "https://www.g2g.com/categories/capcut-accounts";
    if (brand.includes("google")) return "https://www.g2g.com/categories/gemini-accounts";
    if (brand.includes("grok")) return "https://www.g2g.com/categories/xai-accounts";
    if (brand.includes("claude")) return "https://www.g2g.com/categories/claude-accounts";
    if (brand.includes("adobe")) return "https://www.g2g.com/categories/adobe-accounts";
    if (brand.includes("microsoft") || brand.includes("windows")) return "https://www.g2g.com/categories/microsoft-accounts";
    return `https://www.g2g.com/search?q=${encodeURIComponent(master.brand + " " + master.type)}`;
}

function openG2GMarketLink(productId) {
    const link = getG2GMarketLink(productId);
    window.open(link, '_blank');
}

// ==========================================
// ADMIN TABS & ON-DEMAND FULFILLMENT
// ==========================================
let currentAdminOrderFilter = 'all';
let adminOrderSearchQuery = '';
let adminStockSearchQuery = '';
let adminStockBrandFilter = 'all';

function switchAdminTab(tabName) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) {
        showToast("กรุณาเข้าสู่ระบบหลังร้านก่อนดำเนินการ", "warning");
        promptAdminLogin();
        return;
    }

    const tabs = ['orders', 'stock', 'settings'];
    tabs.forEach(t => {
        const btn = document.getElementById(`admin-tab-btn-${t}`);
        const panel = document.getElementById(`admin-tab-${t}`);
        if (t === tabName) {
            if (btn) {
                btn.className = "px-4 py-2 rounded-xl text-xs sm:text-sm font-bold bg-pink-500 text-white flex items-center gap-2 shadow-sm transition-all shrink-0";
            }
            if (panel) panel.classList.remove('hidden');
        } else {
            if (btn) {
                btn.className = "px-4 py-2 rounded-xl text-xs sm:text-sm font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center gap-2 transition-all shrink-0";
            }
            if (panel) panel.classList.add('hidden');
        }
    });

    if (tabName === 'orders') renderAdminOrdersList();
    if (tabName === 'stock') renderAdminStockList();
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

    if (!state.orders || state.orders.length === 0) {
        showToast("ยังไม่มีข้อมูลคำสั่งซื้อสำหรับส่งออก", "info");
        return;
    }

    const headers = ["Order ID", "Date", "Customer Email", "Total Amount (THB)", "Payment Method", "TransRef", "Status", "Items"];
    const rows = state.orders.map(o => {
        const itemNames = (o.items || []).map(i => `${i.productTitle} (x1)`).join(' | ');
        const cleanStatus = (o.status || '').replace(/[\u{1F300}-\u{1F9FF}]/gu, '').trim();
        return [
            o.orderId,
            `"${o.date || ''}"`,
            `"${o.recipientEmail || ''}"`,
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

function copyOrderCustomerReceipt(orderId) {
    const order = state.orders.find(o => o.orderId === orderId);
    if (!order) return;

    let text = `📦 ข้อมูลคำสั่งซื้อ Supinkly.AI\n`;
    text += `เลขออเดอร์: ${order.orderId}\n`;
    text += `วันที่สั่งซื้อ: ${order.date}\n`;
    text += `ยอดชำระ: ฿${(order.totalAmount || 0).toFixed(2)}\n\n`;
    text += `รายการสินค้าและรหัสเข้าใช้งาน:\n`;
    
    order.items.forEach((it, idx) => {
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

function renderAdminOrdersList() {
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

    // Update KPI stats
    let totalSales = 0;
    let pendingCount = 0;
    let deliveredCount = 0;

    state.orders.forEach(order => {
        totalSales += (order.totalAmount || 0);
        const hasPending = order.items.some(it => !it.credentials || it.status === 'pending_fulfillment');
        if (hasPending) {
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
    if (totalOrdersEl) totalOrdersEl.textContent = `${state.orders.length} รายการ`;

    if (badge) {
        badge.textContent = pendingCount;
        if (pendingCount > 0) {
            badge.className = "px-2 py-0.5 rounded-full bg-amber-400 text-slate-900 text-xs font-black animate-bounce";
        } else {
            badge.className = "px-2 py-0.5 rounded-full bg-slate-200 text-slate-700 text-xs font-black";
        }
    }

    // Filter by tab
    let filteredOrders = state.orders;
    if (currentAdminOrderFilter === 'pending') {
        filteredOrders = filteredOrders.filter(o => o.items.some(it => !it.credentials || it.status === 'pending_fulfillment'));
    } else if (currentAdminOrderFilter === 'delivered') {
        filteredOrders = filteredOrders.filter(o => o.items.every(it => it.credentials && it.status !== 'pending_fulfillment'));
    }

    // Filter by search query
    if (adminOrderSearchQuery) {
        filteredOrders = filteredOrders.filter(o => {
            const idMatch = (o.orderId || '').toLowerCase().includes(adminOrderSearchQuery);
            const emailMatch = (o.recipientEmail || '').toLowerCase().includes(adminOrderSearchQuery);
            const refMatch = (o.transRef || '').toLowerCase().includes(adminOrderSearchQuery);
            const itemMatch = (o.items || []).some(it => (it.productTitle || '').toLowerCase().includes(adminOrderSearchQuery));
            return idMatch || emailMatch || refMatch || itemMatch;
        });
    }

    if (countLabel) {
        countLabel.textContent = `แสดง ${filteredOrders.length} จากทั้งหมด ${state.orders.length} รายการ`;
    }

    if (filteredOrders.length === 0) {
        container.innerHTML = `
            <div class="py-10 text-center bg-slate-50 rounded-2xl border border-slate-200">
                <div class="w-12 h-12 mx-auto mb-2 rounded-full bg-slate-200 text-slate-400 flex items-center justify-center text-xl">
                    <i class="fa-solid fa-box-open"></i>
                </div>
                <p class="text-sm font-bold text-slate-700">ไม่มีรายการคำสั่งซื้อในหมวดนี้</p>
                <p class="text-xs text-slate-400 mt-0.5">เมื่อมีลูกค้าชำระเงินเข้ามา ออเดอร์จะแสดงที่นี่โดยอัตโนมัติ</p>
            </div>
        `;
        return;
    }

    container.innerHTML = filteredOrders.map(order => {
        const hasPending = order.items.some(it => !it.credentials || it.status === 'pending_fulfillment');

        return `
            <div class="p-4 rounded-2xl bg-white border-2 ${hasPending ? 'border-amber-300 shadow-sm' : 'border-slate-200'} space-y-3">
                <div class="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-slate-100 text-xs">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="font-mono font-black text-pink-600 text-sm">${escapeHTML(order.orderId)}</span>
                        <span class="text-slate-400">•</span>
                        <span class="text-slate-500 font-medium">${escapeHTML(order.date)}</span>
                        <span class="text-slate-400">•</span>
                        <span class="font-bold text-slate-800">ลูกค้า: ${escapeHTML(order.recipientEmail || 'ไม่ระบุ')}</span>
                        <button onclick="copyFromData(this)" data-copy="${escapeHTML(order.recipientEmail || '')}" data-msg="คัดลอกอีเมลลูกค้าแล้ว" 
                                title="คัดลอกอีเมลลูกค้า" class="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 font-bold text-[10px] transition-all">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="copyOrderCustomerReceipt('${escapeHTML(order.orderId)}')" 
                                class="px-2.5 py-1 rounded-xl bg-pink-50 hover:bg-pink-100 text-pink-700 text-xs font-bold transition-all flex items-center gap-1 border border-pink-200 shadow-2xs">
                            <i class="fa-regular fa-message text-[11px]"></i>
                            <span>ข้อความส่งลูกค้า</span>
                        </button>
                        <span class="px-2.5 py-1 rounded-full text-xs font-bold ${hasPending ? 'bg-amber-100 text-amber-900 border border-amber-300 animate-pulse' : 'bg-emerald-100 text-emerald-800 border border-emerald-200'}">
                            ${hasPending ? '🟡 รอส่งมอบ (On-Demand)' : '🟢 จัดส่งสำเร็จ'}
                        </span>
                        <span class="font-black text-slate-900 text-sm">฿${(order.totalAmount || 0).toFixed(2)}</span>
                    </div>
                </div>

                <!-- Items in this order -->
                <div class="space-y-2">
                    ${order.items.map((item, itemIdx) => {
                        const isItemPending = !item.credentials || item.status === 'pending_fulfillment';
                        const cred = item.credentials || {};

                        return `
                            <div class="p-3 rounded-xl ${isItemPending ? 'bg-amber-50/70 border border-amber-200' : 'bg-slate-50 border border-slate-200'} flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                <div class="min-w-0 flex-1">
                                    <div class="flex items-center gap-2">
                                        <span class="font-bold text-xs sm:text-sm text-slate-900 truncate">${escapeHTML(item.productTitle)}</span>
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

    const order = state.orders.find(o => o.orderId === orderId);
    if (!order || !order.items[itemIndex]) {
        showToast("ไม่พบข้อมูลคำสั่งซื้อ", "warning");
        return;
    }

    const item = order.items[itemIndex];
    const modal = document.getElementById('admin-fulfill-modal');
    if (!modal) return;

    document.getElementById('fulfill-order-id').value = orderId;
    document.getElementById('fulfill-item-index').value = itemIndex;
    document.getElementById('fulfill-order-id-label').textContent = orderId;
    document.getElementById('fulfill-customer-email-label').textContent = order.recipientEmail || 'ลูกค้าหน้าร้าน';
    document.getElementById('fulfill-product-title-label').textContent = item.productTitle;

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

function handleFulfillSubmit(e) {
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
    const instructions = document.getElementById('fulfill-instructions').value.trim() || 'เข้าสู่ระบบและเริ่มใช้งานได้ทันที';

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

    const order = state.orders.find(o => o.orderId === orderId);
    if (!order || !order.items[itemIndex]) {
        showToast("ไม่พบคำสั่งซื้อ", "warning");
        return;
    }

    const item = order.items[itemIndex];
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

    item.credentials = cred;
    item.status = 'delivered';

    // If all items are delivered, set order status
    const allDelivered = order.items.every(it => it.credentials && it.status !== 'pending_fulfillment');
    if (allDelivered) {
        order.status = "🟢 จัดส่งสำเร็จเรียบร้อย";
    }

    saveOrders();
    closeFulfillModal();
    renderAdminOrdersList();

    // If the customer has vault modal open for this order, re-render it
    if (state.currentVaultOrderId === orderId) {
        openVaultModal(order);
    }
    const ordersModal = document.getElementById('orders-modal');
    if (ordersModal && !ordersModal.classList.contains('hidden')) {
        renderOrdersHistory();
    }

    // Sync fulfillment to server if online
    if (window.location.protocol.startsWith('http') && ADMIN_AUTH.checkSession()) {
        try {
            fetch('/api/admin/fulfill', {
                method: 'POST',
                headers: ADMIN_AUTH.getHeaders(),
                body: JSON.stringify({ orderId, itemIndex, credentials: cred })
            }).catch(e => console.warn("Server fulfill sync error:", e));
        } catch (e) {}
    }

    showToast(`ส่งมอบรหัสให้คำสั่งซื้อ ${orderId} สำเร็จแล้ว!`, "success");
}

async function syncAdminOrdersFromServer() {
    if (window.location.protocol.startsWith('http') && ADMIN_AUTH.checkSession()) {
        try {
            const res = await fetch('/api/admin/orders', {
                headers: ADMIN_AUTH.getHeaders()
            });
            if (res.ok) {
                const data = await res.json();
                if (data.success && Array.isArray(data.orders)) {
                    const serverOrders = data.orders;
                    const map = new Map();
                    (state.orders || []).forEach(o => { if (o && o.orderId) map.set(o.orderId, o); });
                    serverOrders.forEach(o => { if (o && o.orderId) map.set(o.orderId, o); });
                    state.orders = Array.from(map.values()).sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
                    saveOrders();
                }
            }
        } catch (e) {
            console.warn("Could not sync orders from server:", e);
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

    document.getElementById('admin-promptpay-input').value = STORE_CONFIG.promptPayNumber || '';
    const accNameEl = document.getElementById('admin-account-name');
    if (accNameEl) accNameEl.value = STORE_CONFIG.promptPayAccountName || 'สุพัฒน์ มีสมบัติ';
    const branchEl = document.getElementById('admin-slipok-branch');
    if (branchEl) branchEl.value = STORE_CONFIG.slipOkBranchId || '77491';
    const pinInput = document.getElementById('admin-new-pin');
    if (pinInput) pinInput.value = '';

    await syncAdminOrdersFromServer();
    renderAdminOrdersList();
    renderAdminStockList();
    switchAdminTab('orders');
    modal.classList.remove('hidden');
}

function closeAdminModal() {
    const modal = document.getElementById('admin-modal');
    if (modal) modal.classList.add('hidden');
}

function handleAdminStockSearch(val) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    adminStockSearchQuery = (val || '').toLowerCase().trim();
    renderAdminStockList();
}

function filterAdminStockBrand(brand) {
    if (typeof ADMIN_AUTH !== 'undefined' && !ADMIN_AUTH.checkSession()) return;
    adminStockBrandFilter = brand;
    const chips = ['all', 'CapCut', 'Google-AI', 'Google', 'Grok', 'Claude', 'Adobe', 'Microsoft'];
    chips.forEach(c => {
        const btn = document.getElementById(`admin-stock-chip-${c}`);
        if (btn) {
            const matches = (c === 'all' && brand === 'all') || 
                            (c === 'Google-AI' && brand === 'Google AI') || 
                            (c === brand);
            if (matches) {
                btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-pink-100 text-pink-700 transition-all shrink-0";
            } else {
                btn.className = "admin-stock-brand-chip px-2.5 py-1.5 rounded-xl text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 transition-all shrink-0";
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
                <td colspan="6" class="py-8 text-center text-rose-500 text-xs font-bold">
                    กรุณาเข้าสู่ระบบหลังร้านเพื่อดูและจัดการสต็อกสินค้า
                </td>
            </tr>
        `;
        return;
    }

    let prods = state.products;

    if (adminStockBrandFilter !== 'all') {
        prods = prods.filter(p => p.brand.toLowerCase() === adminStockBrandFilter.toLowerCase() || (adminStockBrandFilter === 'Google' && p.brand === 'Google'));
    }

    if (adminStockSearchQuery) {
        prods = prods.filter(p => (p.title || '').toLowerCase().includes(adminStockSearchQuery) || (p.brand || '').toLowerCase().includes(adminStockSearchQuery));
    }

    if (prods.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="6" class="py-8 text-center text-slate-400 text-xs font-medium">
                    <i class="fa-solid fa-magnifying-glass mb-1 text-slate-300 text-base block"></i>
                    ไม่พบรายการสินค้าที่ตรงกับคำค้นหา
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
            ?? (typeof G2G_MARKET_FEED !== 'undefined' ? G2G_MARKET_FEED.benchmarks[p.id]?.g2gStock : 50);

        const g2gBenchmark = typeof G2G_MARKET_FEED !== 'undefined' ? G2G_MARKET_FEED.benchmarks[p.id] : null;
        const costTHB = (customPrices[p.id] && customPrices[p.id].marketCostTHB) 
            || (g2gBenchmark ? Math.round(g2gBenchmark.baseCostUSD * 36.50 * 100) / 100 : 0);

        const profit = master.price - costTHB;
        const profitPct = master.price > 0 ? ((profit / master.price) * 100).toFixed(0) : 0;
        const isManual = customPrices[p.id]?.manualOverride === true;

        return `
            <tr class="border-b border-slate-100 hover:bg-slate-50 text-xs font-medium transition-colors">
                <td class="py-3 px-3.5">
                    <div class="font-bold text-slate-900 text-xs sm:text-sm">${escapeHTML(master.title)}</div>
                    <div class="flex items-center gap-1.5 mt-0.5">
                        <span class="text-[11px] font-bold text-pink-600">${escapeHTML(master.brand)} (${escapeHTML(master.type)})</span>
                        <span class="text-slate-300">•</span>
                        <span class="text-[10px] px-2 py-0.5 rounded-full font-bold ${isManual ? 'bg-amber-100 text-amber-800 border border-amber-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'}">
                            ${isManual ? '🟡 ราคาตั้งเอง' : '🟢 ตลาด Auto-Sync'}
                        </span>
                    </div>
                </td>
                <td class="py-3 px-3.5 text-center font-mono">
                    <span class="text-slate-500 font-bold text-xs">฿${costTHB.toFixed(2)}</span>
                </td>
                <td class="py-3 px-3.5 text-center">
                    <div class="font-black text-pink-600 text-sm font-mono">฿${master.price.toFixed(2)}</div>
                    <div class="text-[10px] text-slate-400 line-through font-mono">฿${master.originalPrice.toFixed(2)}</div>
                </td>
                <td class="py-3 px-3.5 text-center font-mono">
                    <span class="font-black text-xs ${profit >= 0 ? 'text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-lg border border-emerald-200' : 'text-rose-700 bg-rose-50 px-2 py-0.5 rounded-lg border border-rose-200'}">
                        ${profit >= 0 ? '+' : ''}฿${profit.toFixed(2)} (${profitPct}%)
                    </span>
                </td>
                <td class="py-3 px-3.5 text-center">
                    <div class="flex flex-col items-center gap-1">
                        <span class="px-2 py-0.5 rounded-full text-[11px] font-bold ${pool.length > 0 ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-600'}">
                            คลัง: ${pool.length}
                        </span>
                        <span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-cyan-50 text-cyan-800 border border-cyan-200">
                            ตลาด: ${marketStock}
                        </span>
                    </div>
                </td>
                <td class="py-3 px-3.5 text-right">
                    <div class="flex items-center justify-end gap-1.5">
                        <button onclick="openEditPriceModal('${p.id}')" class="px-2.5 py-1.5 rounded-xl bg-amber-100 text-amber-800 hover:bg-amber-200 text-xs font-bold transition-all shadow-2xs flex items-center gap-1">
                            <i class="fa-solid fa-tag"></i> แก้ไขราคา
                        </button>
                        <button onclick="openAddStockModal('${p.id}')" class="px-2.5 py-1.5 rounded-xl bg-pink-100 text-pink-700 hover:bg-pink-200 text-xs font-bold transition-all shadow-2xs flex items-center gap-1">
                            <i class="fa-solid fa-plus"></i> เติมสต็อก
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// Edit Price Modal Handlers
function openEditPriceModal(productId) {
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
    document.getElementById('edit-price-product-title').textContent = master.title;
    document.getElementById('edit-price-sale').value = master.price;
    document.getElementById('edit-price-original').value = master.originalPrice;

    updateEditPricePreview();
    modal.classList.remove('hidden');
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

function handleResetToAutoPrice() {
    const productId = document.getElementById('edit-price-product-id').value;
    if (!productId) return;

    const customPrices = getCustomPrices();
    if (customPrices[productId]) {
        delete customPrices[productId].manualOverride;
        delete customPrices[productId].lastManualUpdate;
        localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));
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

function handleSaveEditedPrice() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeEditPriceModal();
        promptAdminLogin();
        return;
    }

    const productId = document.getElementById('edit-price-product-id').value;
    const saleVal = parseFloat(document.getElementById('edit-price-sale').value);
    const origVal = parseFloat(document.getElementById('edit-price-original').value);

    if (isNaN(saleVal) || saleVal < 0) {
        showToast("กรุณากรอกราคาขายที่ถูกต้อง", "warning");
        return;
    }

    const customPrices = getCustomPrices();
    const existing = customPrices[productId] || {};
    customPrices[productId] = {
        ...existing,
        price: Math.round(saleVal * 100) / 100,
        originalPrice: isNaN(origVal) || origVal < saleVal ? Math.round(saleVal * 100) / 100 : Math.round(origVal * 100) / 100,
        manualOverride: true,
        lastManualUpdate: new Date().toISOString()
    };

    localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));

    // Refresh application state
    applyCustomPricesToProducts();
    applyFilters();
    updateCartUI();
    renderAdminStockList();
    closeEditPriceModal();

    showToast(`อัปเดตราคาใหม่เป็น ฿${customPrices[productId].price.toFixed(2)} เรียบร้อยแล้ว`, "success");
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

    document.getElementById('add-stock-product-id').value = productId;
    document.getElementById('add-stock-product-title').textContent = master.title;
    document.getElementById('add-stock-textarea').value = '';
    
    modal.classList.remove('hidden');
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

    // Sync added stock to server if online
    if (window.location.protocol.startsWith('http') && ADMIN_AUTH.checkSession()) {
        try {
            const addedCreds = [];
            lines.forEach(line => {
                if (line.includes(':')) {
                    const parts = line.split(':');
                    addedCreds.push({
                        email: parts[0].trim(),
                        password: parts.slice(1).join(':').trim(),
                        instructions: "เข้าสู่ระบบและใช้งานได้ทันที"
                    });
                } else if (line.startsWith('http')) {
                    addedCreds.push({
                        link: line,
                        instructions: "คลิกเปิดลิงก์เพื่อรับสิทธิ์ใช้งานทันที"
                    });
                } else {
                    addedCreds.push({
                        key: line,
                        instructions: "นำคีย์ไปเปิดใช้งานในโปรแกรม"
                    });
                }
            });

            fetch('/api/admin/stock', {
                method: 'POST',
                headers: ADMIN_AUTH.getHeaders(),
                body: JSON.stringify({ productId, newCredentials: addedCreds })
            }).catch(e => console.warn("Stock sync error:", e));
        } catch (e) {}
    }

    showToast(`เติมสต็อกสำเร็จ +${lines.length} ชิ้น!`, "success");
}

async function saveAdminSettings() {
    if (!ADMIN_AUTH.checkSession()) {
        showToast("เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่", "warning");
        closeAdminModal();
        promptAdminLogin();
        return;
    }

    const newPhone = (document.getElementById('admin-promptpay-input') ? document.getElementById('admin-promptpay-input').value : '').trim();
    const newAccountName = (document.getElementById('admin-account-name') ? document.getElementById('admin-account-name').value : '').trim();
    const newBranchId = (document.getElementById('admin-slipok-branch') ? document.getElementById('admin-slipok-branch').value : '').trim();
    const newPin = (document.getElementById('admin-new-pin') ? document.getElementById('admin-new-pin').value : '').trim();

    if (newPhone) {
        const cleanPhone = newPhone.replace(/[-\s]/g, '');
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

    // Persist store config safely (no secret API keys stored in client localStorage)
    try {
        localStorage.setItem('supinkly_store_config', JSON.stringify({
            promptPayNumber: STORE_CONFIG.promptPayNumber,
            promptPayAccountName: STORE_CONFIG.promptPayAccountName,
            slipOkBranchId: STORE_CONFIG.slipOkBranchId
        }));
    } catch (e) {
        console.error("Config save error:", e);
    }

    if (newPin) {
        try {
            await ADMIN_AUTH.setPin(newPin);
            showToast("เปลี่ยนรหัส PIN แอดมินใหม่สำเร็จ", "info");
        } catch (err) {
            showToast(err.message, "warning");
            return;
        }
    }

    showToast("บันทึกการตั้งค่าร้านค้าเรียบร้อยแล้ว", "success");
    closeAdminModal();
}

// Product Detail Modal
function openProductDetailModal(productId) {
    const product = getMasterProduct(productId);
    if (!product) return;

    const modal = document.getElementById('product-detail-modal');
    if (!modal) return;

    const stateProd = (state.products || []).find(p => p.id === productId);
    const availableStock = (stateProd && stateProd.stock) || product.stock || (state.inventory[productId] || []).length || 50;

    document.getElementById('modal-product-brand').textContent = product.brand;
    document.getElementById('modal-product-type').textContent = product.type;
    document.getElementById('modal-product-title').textContent = product.title;
    document.getElementById('modal-product-desc').textContent = product.description;
    document.getElementById('modal-product-price').textContent = `฿${product.price.toFixed(2)}`;
    document.getElementById('modal-product-original-price').textContent = `฿${product.originalPrice.toFixed(2)}`;
    document.getElementById('modal-product-warranty').textContent = product.warranty;
    document.getElementById('modal-product-stock').textContent = `${availableStock} ชิ้น (พร้อมส่ง)`;
    document.getElementById('modal-product-sold').textContent = `${product.soldCount.toLocaleString()} ชิ้น`;
    const durEl = document.getElementById('modal-product-duration');
    if (durEl) durEl.textContent = product.duration || '30 วัน';
    const devEl = document.getElementById('modal-product-devices');
    if (devEl) devEl.textContent = product.devices || 'ทุกอุปกรณ์';
    const regionEl = document.getElementById('modal-product-region');
    if (regionEl) regionEl.textContent = product.region;

    const addBtn = document.getElementById('modal-add-cart-btn');
    if (addBtn) {
        addBtn.disabled = availableStock <= 0;
        addBtn.onclick = () => {
            addToCart(product.id);
            closeProductDetailModal();
        };
    }

    modal.classList.remove('hidden');
}

function closeProductDetailModal() {
    const modal = document.getElementById('product-detail-modal');
    if (modal) modal.classList.add('hidden');
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
}

// ─────────────────────────────────────────────────────────────
// ADMIN LIVE CHAT — WebSocket Client (Admin Side)
// ─────────────────────────────────────────────────────────────
const ADMIN_CHAT = (() => {
    const WS_URL = (() => {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const host  = location.hostname === 'localhost' || location.hostname === '127.0.0.1'
            ? `${location.hostname}:3000`
            : location.host;
        return `${proto}://${host}/ws/chat`;
    })();

    let ws           = null;
    let activeRoom   = null;   // sessionId ที่กำลัง active
    const rooms      = {};     // sessionId → { name, messages[] }
    let adminTyping  = null;
    let unread       = {};     // sessionId → count

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
        const cnt  = document.getElementById('admin-room-count');
        if (!list) return;

        const keys = Object.keys(rooms);
        if (cnt) cnt.textContent = keys.length;

        if (keys.length === 0) {
            list.innerHTML = `<div class="px-3 py-3 text-[11px] text-slate-400 text-center font-medium">ยังไม่มีลูกค้าเชื่อมต่อ</div>`;
            return;
        }

        list.innerHTML = keys.map(sid => {
            const r        = rooms[sid];
            const isActive = sid === activeRoom;
            const badge    = unread[sid] || 0;
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
        const dotEl  = document.getElementById('admin-active-online-dot');
        if (nameEl) nameEl.textContent = rooms[sid]?.name || sid;
        if (dotEl)  dotEl.classList.remove('hidden');

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
        const inp  = document.getElementById('admin-msg-input');
        const text = (inp?.value || '').trim();
        if (!text) return;

        ws.send(JSON.stringify({ type: 'message', text, targetSessionId: activeRoom }));
        inp.value = '';
        inp.style.height = '';
    }

    /* ── Connect ─────────────────────────────────────────────── */
    function connect(pin) {
        if (ws && ws.readyState < 2) return;
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            const token = typeof ADMIN_AUTH !== 'undefined' ? ADMIN_AUTH.getToken() : null;
            // [SECURITY] Send token only — no raw PIN over WebSocket
            ws.send(JSON.stringify({ type: 'auth', role: 'admin', token }));
        };

        ws.onmessage = ({ data }) => {
            let msg;
            try { msg = JSON.parse(data); } catch { return; }

            if (msg.type === 'auth_ok') {
                setStatus(`เชื่อมต่อแล้ว (Admin) 🟢 — ${new Date().toLocaleTimeString('th-TH')}`);
            }

            if (msg.type === 'auth_fail') {
                setStatus('❌ สิทธิ์การเข้าถึงไม่ถูกต้อง หรือเซสชันหมดอายุ');
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

        const sendBtn  = document.getElementById('admin-send-btn');
        const msgInp   = document.getElementById('admin-msg-input');

        sendBtn?.addEventListener('click', () => ADMIN_CHAT.sendMsg());
        msgInp?.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ADMIN_CHAT.sendMsg(); }
        });
        msgInp?.addEventListener('input', () => {
            msgInp.style.height = '';
            msgInp.style.height = Math.min(msgInp.scrollHeight, 100) + 'px';
        });

        // Connect WebSocket as admin (token from session)
        const token = ADMIN_AUTH.getToken();
        if (token) {
            ADMIN_CHAT.connect();
        } else {
            // No valid session — prompt admin to login first
            showToast('กรุณาเข้าสู่ระบบแอดมินก่อนใช้ Live Chat', 'warning');
            closeAdminChatPanel();
            promptAdminLogin();
        }
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
    btn.className = 'hidden fixed bottom-6 left-6 z-50 w-14 h-14 rounded-full bg-emerald-500 hover:bg-emerald-600 text-white shadow-xl hover:scale-110 transition-all flex items-center justify-center';
    btn.innerHTML = `
        <i class="fa-solid fa-headset text-xl"></i>
        <span class="chat-badge hidden absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-500 border-2 border-white text-white text-[10px] font-black flex items-center justify-center"></span>`;
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


// ==========================================
// USER AUTH UI FUNCTIONS
// ==========================================

function openAuthModal(tab = 'login') {
    const modal = document.getElementById('auth-modal');
    if (!modal) return;
    switchAuthTab(tab);
    modal.classList.remove('hidden');
    setTimeout(() => {
        const el = tab === 'login'
            ? document.getElementById('login-email')
            : document.getElementById('register-email');
        if (el) el.focus();
    }, 100);
}

function closeAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) modal.classList.add('hidden');
}

function switchAuthTab(tab) {
    const loginForm    = document.getElementById('auth-form-login');
    const registerForm = document.getElementById('auth-form-register');
    const tabLogin     = document.getElementById('auth-tab-login');
    const tabRegister  = document.getElementById('auth-tab-register');

    if (tab === 'login') {
        loginForm?.classList.remove('hidden');
        registerForm?.classList.add('hidden');
        tabLogin?.classList.add('border-pink-500', 'text-pink-600');
        tabLogin?.classList.remove('border-transparent', 'text-slate-500');
        tabRegister?.classList.remove('border-pink-500', 'text-pink-600');
        tabRegister?.classList.add('border-transparent', 'text-slate-500');
    } else {
        loginForm?.classList.add('hidden');
        registerForm?.classList.remove('hidden');
        tabRegister?.classList.add('border-pink-500', 'text-pink-600');
        tabRegister?.classList.remove('border-transparent', 'text-slate-500');
        tabLogin?.classList.remove('border-pink-500', 'text-pink-600');
        tabLogin?.classList.add('border-transparent', 'text-slate-500');
    }
}

function setAuthError(formType, msg) {
    const el = document.getElementById(`auth-${formType}-error`);
    if (!el) return;
    if (msg) {
        el.textContent = msg;
        el.classList.remove('hidden');
    } else {
        el.classList.add('hidden');
    }
}

function setAuthBtnLoading(btnId, loading) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = loading;
    btn.innerHTML = loading
        ? `<i class="fa-solid fa-spinner fa-spin text-sm"></i> กรุณารอ...`
        : btnId === 'login-btn'
            ? `<i class="fa-solid fa-right-to-bracket"></i> เข้าสู่ระบบ`
            : `<i class="fa-solid fa-user-plus"></i> สมัครสมาชิกฟรี`;
}

async function handleLogin() {
    if (typeof USER_AUTH === 'undefined') {
        showToast('ระบบ login ใช้งานได้เฉพาะเมื่อเปิดผ่าน server เท่านั้น', 'warning');
        return;
    }
    const email    = (document.getElementById('login-email')?.value || '').trim();
    const password = (document.getElementById('login-password')?.value || '').trim();

    setAuthError('login', '');
    if (!email || !password) {
        setAuthError('login', 'กรุณากรอกอีเมลและรหัสผ่าน');
        return;
    }

    setAuthBtnLoading('login-btn', true);
    try {
        const result = await USER_AUTH.login(email, password);
        if (result.success) {
            state.user = result.user;
            closeAuthModal();
            await syncUserOrdersFromServer();
            initHeader();
            showToast(`🎉 ยินดีต้อนรับกลับ, ${escapeHTML(result.user?.displayName || email)}!`, 'success');
        } else {
            setAuthError('login', result.message || 'เข้าสู่ระบบไม่สำเร็จ');
        }
    } catch {
        setAuthError('login', 'เกิดข้อผิดพลาด กรุณาลองใหม่');
    } finally {
        setAuthBtnLoading('login-btn', false);
    }
}

async function handleRegister() {
    if (typeof USER_AUTH === 'undefined') {
        showToast('ระบบสมัครสมาชิกใช้งานได้เฉพาะเมื่อเปิดผ่าน server เท่านั้น', 'warning');
        return;
    }
    const name     = (document.getElementById('register-name')?.value || '').trim();
    const email    = (document.getElementById('register-email')?.value || '').trim();
    const password = (document.getElementById('register-password')?.value || '').trim();

    setAuthError('register', '');
    if (!email || !password) {
        setAuthError('register', 'กรุณากรอกอีเมลและรหัสผ่าน');
        return;
    }
    if (password.length < 6) {
        setAuthError('register', 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร');
        return;
    }

    setAuthBtnLoading('register-btn', true);
    try {
        const result = await USER_AUTH.register(email, password, name || undefined);
        if (result.success) {
            state.user = result.user;
            closeAuthModal();
            await syncUserOrdersFromServer();
            initHeader();
            showToast(`✅ สมัครสมาชิกสำเร็จ! ยินดีต้อนรับ ${escapeHTML(result.user?.displayName || email)}`, 'success');
        } else {
            setAuthError('register', result.message || 'สมัครสมาชิกไม่สำเร็จ');
        }
    } catch {
        setAuthError('register', 'เกิดข้อผิดพลาด กรุณาลองใหม่');
    } finally {
        setAuthBtnLoading('register-btn', false);
    }
}

async function handleUserLogout() {
    if (typeof USER_AUTH !== 'undefined') await USER_AUTH.logout();
    state.user = null;
    initHeader();
    showToast('ออกจากระบบเรียบร้อยแล้ว', 'info');
}

async function syncUserOrdersFromServer() {
    if (typeof USER_AUTH === 'undefined' || !USER_AUTH.isLoggedIn()) return;
    if (!window.location.protocol.startsWith('http')) return;
    try {
        // [SECURITY & SYNC] Safely claim genuine local orders that belong to this account
        const localOrderIds = (state.orders || []).map(o => o.orderId).filter(Boolean);
        if (localOrderIds.length > 0) {
            await USER_AUTH.linkLocalOrders(localOrderIds);
        }

        const serverOrders = await USER_AUTH.fetchMyOrders();
        if (Array.isArray(serverOrders) && serverOrders.length > 0) {
            const map = new Map();
            (state.orders || []).forEach(o => { if (o?.orderId) map.set(o.orderId, o); });
            serverOrders.forEach(o => { if (o?.orderId) map.set(o.orderId, o); });
            state.orders = Array.from(map.values()).sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
            saveOrders();
        }
    } catch {}
}

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    const icon = btn.querySelector('i');
    if (icon) {
        icon.className = isHidden ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    }
}


