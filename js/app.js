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

// Hardened Admin Authentication (Brute-Force Rate Limiting & Session Token)
const ADMIN_AUTH = {
    MAX_ATTEMPTS: 5,
    LOCKOUT_DURATION_MS: 5 * 60 * 1000, // 5 minutes
    SESSION_DURATION_MS: 15 * 60 * 1000, // 15 minutes auto-logout

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

        const hashedEntered = await this.hashPin(enteredPin);
        let storedHash = localStorage.getItem('supinkly_admin_pin_hash');

        if (!storedHash) {
            // Default PIN 8899
            storedHash = await this.hashPin('8899');
        }

        if (hashedEntered === storedHash) {
            // Reset attempts on success
            localStorage.removeItem('supinkly_admin_failed_attempts');
            localStorage.removeItem('supinkly_admin_lockout_until');

            // Issue cryptographic session token
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
    },

    checkSession() {
        try {
            const raw = sessionStorage.getItem('supinkly_admin_session');
            if (!raw) return false;
            const session = JSON.parse(raw);
            if (session && session.token && Date.now() < session.expiresAt) {
                session.expiresAt = Date.now() + this.SESSION_DURATION_MS;
                sessionStorage.setItem('supinkly_admin_session', JSON.stringify(session));
                return true;
            }
        } catch {
            // corrupt session
        }
        sessionStorage.removeItem('supinkly_admin_session');
        return false;
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
    products: PRODUCTS.map(p => ({ ...p, stock: 0 })),
    inventory: getSecureInventory(),
    filteredProducts: [],
    cart: loadAndSanitizeCart(),
    user: JSON.parse(localStorage.getItem('supinkly_user') || JSON.stringify({
        id: "USR-8821",
        name: "Supinkly Member",
        email: "member@supinkly.ai",
        isLoggedIn: true,
        points: 450
    })),
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
    // Clean up any legacy 1.00 Baht test price on cpc-01
    if (customPrices['cpc-01'] && customPrices['cpc-01'].price === 1.00 && !customPrices['cpc-01'].manualOverride) {
        delete customPrices['cpc-01'];
        try {
            localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));
        } catch (e) { }
    }

    state.products.forEach(p => {
        if (customPrices[p.id]) {
            if (typeof customPrices[p.id].price === 'number') p.price = customPrices[p.id].price;
            if (typeof customPrices[p.id].originalPrice === 'number') p.originalPrice = customPrices[p.id].originalPrice;
        }
    });
}

// Sync live stock count & custom prices (Referenced from G2G Market Auto-Sync)
function syncStockCount() {
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
    updateCartUI();
    renderBrandTabs();
    initEvents();

    // Launch G2G Market Real-Time Auto-Sync Engine (Zero button clicks required)
    if (typeof G2G_SYNC !== 'undefined') {
        G2G_SYNC.init();
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
                updateUserHeaderUI();
                showToast(`ยินดีต้อนรับคุณ ${res.user?.displayName || email}!`, 'success');
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
                pendingAuthEmail = email;
                const emailDisplay = document.getElementById('auth-otp-target-email');
                if (emailDisplay) emailDisplay.textContent = email;
                switchAuthTab('otp');
                startResendOtpTimer();
                showToast('ส่งรหัส OTP ไปยังอีเมลของคุณแล้ว กรุณาตรวจสอบกล่องข้อความ', 'info');
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
                updateUserHeaderUI();
                showToast('สมัครสมาชิกและยืนยันอีเมลสำเร็จ ยินดีต้อนรับ!', 'success');
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
    updateUserHeaderUI();
    showToast('ออกจากระบบสมาชิกเรียบร้อยแล้ว', 'info');
}

function updateUserHeaderUI() {
    const section = document.getElementById('user-header-section');
    if (!section) return;

    const isLoggedIn = typeof USER_AUTH !== 'undefined' && USER_AUTH.isLoggedIn();
    const user = isLoggedIn ? USER_AUTH.getUser() : null;

    if (isLoggedIn && user) {
        section.innerHTML = `
            <div class="flex items-center gap-1.5 sm:gap-2">
                <button onclick="openOrdersModal()" class="hidden sm:flex h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-purple-50 border-2 border-purple-200 text-purple-700 hover:bg-purple-100 hover:border-purple-300 transition-all shadow-sm items-center justify-center gap-1.5 sm:gap-2 shrink-0 cursor-pointer">
                    <i class="fa-solid fa-box-open text-sm sm:text-base text-pink-500"></i>
                    <span>คีย์ของฉัน (<span id="nav-orders-count">${state.orders.length}</span>)</span>
                </button>
                <div class="flex items-center gap-1">
                    <button onclick="openOrdersModal()" class="h-9 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-pink-50 hover:bg-pink-100 border-2 border-pink-200 text-pink-700 transition-all shadow-sm flex items-center justify-center gap-1.5 shrink-0 cursor-pointer" title="ดูคีย์และข้อมูลสมาชิก">
                        <i class="fa-solid fa-circle-user text-pink-500"></i>
                        <span class="max-w-[110px] truncate">${escapeHTML(user.displayName || user.name || user.email || 'สมาชิก')}</span>
                    </button>
                    <button onclick="handleUserLogout()" title="ออกจากระบบ" class="h-9 sm:h-11 px-2.5 rounded-xl sm:rounded-2xl bg-slate-100 hover:bg-rose-50 text-slate-500 hover:text-rose-600 border border-slate-200 transition-all flex items-center justify-center cursor-pointer">
                        <i class="fa-solid fa-right-from-bracket text-xs"></i>
                    </button>
                </div>
            </div>
        `;
    } else {
        section.innerHTML = `
            <div class="flex items-center gap-1.5 sm:gap-2">
                <button onclick="openOrdersModal()" class="hidden sm:flex h-10 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-purple-50 border-2 border-purple-200 text-purple-700 hover:bg-purple-100 hover:border-purple-300 transition-all shadow-sm items-center justify-center gap-1.5 sm:gap-2 shrink-0 cursor-pointer">
                    <i class="fa-solid fa-box-open text-sm sm:text-base text-pink-500"></i>
                    <span>คีย์ของฉัน (<span id="nav-orders-count">${state.orders.length}</span>)</span>
                </button>
                <button onclick="openAuthModal('login')" class="h-9 sm:h-11 px-3 sm:px-4 rounded-xl sm:rounded-2xl text-xs sm:text-sm font-bold bg-pink-500 hover:bg-pink-600 text-white transition-all shadow-sm flex items-center justify-center gap-1 sm:gap-1.5 shrink-0 touch-active cursor-pointer">
                    <i class="fa-solid fa-right-to-bracket text-xs sm:text-sm"></i>
                    <span class="inline font-bold">เข้าสู่ระบบ</span>
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
            class="brand-tab flex items-center gap-2 px-4 py-2.5 rounded-2xl text-xs md:text-sm font-bold border transition-all whitespace-nowrap ${state.filterBrand === b.key ? 'active' : ''}">
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
        result = result.filter(p =>
            p.title.toLowerCase().includes(state.searchQuery) ||
            p.brand.toLowerCase().includes(state.searchQuery) ||
            p.description.toLowerCase().includes(state.searchQuery)
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

// Render Products Grid (Bright, High-Contrast Cards)
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
        let typeBadgeClass = "bg-purple-100 text-purple-700 border-purple-200";
        if (product.typeKey === 'private') typeBadgeClass = "bg-pink-100 text-pink-700 border-pink-200";
        if (product.typeKey === 'shared') typeBadgeClass = "bg-amber-100 text-amber-800 border-amber-200";
        if (product.typeKey === 'link') typeBadgeClass = "bg-cyan-100 text-cyan-800 border-cyan-200";
        if (product.typeKey === 'key') typeBadgeClass = "bg-emerald-100 text-emerald-800 border-emerald-200";

        const inStock = product.stock > 0;

        // [FIX #6] ใช้ data-* attribute แทน onclick('${id}') เพื่อป้องกัน JS-context XSS
        // ❌ Before: onclick="addToCart('${product.id}')" ← single quote ใน id → XSS
        // ✅ After:  data-product-id="${escapeHTML(product.id)}" + event delegation
        return `
            <div class="bg-white rounded-3xl p-5 border-2 border-slate-100 hover:border-pink-300 shadow-sm hover:shadow-xl hover:shadow-pink-500/10 flex flex-col justify-between transition-all duration-300 group hover:-translate-y-1 relative overflow-hidden">
                
                <div>
                    <!-- Header of Card -->
                    <div class="flex items-center justify-between gap-2 mb-3">
                        <div class="flex items-center gap-2">
                            <span class="w-8 h-8 rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center text-xs font-black text-pink-600 shadow-inner">
                                ${escapeHTML(product.brandCode)}
                            </span>
                            <span class="text-xs font-bold text-slate-700">${escapeHTML(product.brand)}</span>
                        </div>
                        <span class="px-2.5 py-1 rounded-full text-xs font-bold border ${typeBadgeClass}">
                            ${escapeHTML(product.type)}
                        </span>
                    </div>

                    <!-- Title -->
                    <h3 class="text-base font-extrabold text-slate-900 line-clamp-2 min-h-[44px] group-hover:text-pink-600 transition-colors leading-snug">
                        ${escapeHTML(product.title)}
                    </h3>

                    <!-- Specs -->
                    <div class="flex flex-wrap items-center gap-2 mt-3.5 text-xs text-slate-600 font-medium">
                        <span class="flex items-center gap-1 bg-slate-50 px-2.5 py-1 rounded-lg border border-slate-200">
                            <i class="fa-solid fa-bolt text-amber-500"></i> ส่งทันที
                        </span>
                        <span class="flex items-center gap-1 bg-slate-50 px-2.5 py-1 rounded-lg border border-slate-200">
                            <i class="fa-solid fa-shield-halved text-cyan-600"></i> ประกัน ${escapeHTML(product.warranty)}
                        </span>
                        <span class="flex items-center gap-1 bg-slate-50 px-2.5 py-1 rounded-lg border border-slate-200">
                            <i class="fa-solid fa-globe text-purple-600"></i> ${escapeHTML(product.region)}
                        </span>
                    </div>

                    <!-- Stock Counter -->
                    <div class="flex items-center justify-between mt-4 text-xs font-semibold border-t border-slate-100 pt-2.5">
                        <span class="flex items-center gap-1.5 ${inStock ? 'text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-lg border border-emerald-200' : 'text-rose-700 bg-rose-50 px-2 py-0.5 rounded-lg border border-rose-200'}">
                            <span class="w-2 h-2 rounded-full ${inStock ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                            ${inStock ? `สต็อกพร้อมส่ง ${product.stock} ชิ้น` : 'สินค้าหมดชั่วคราว'}
                        </span>
                        <span class="text-slate-400">ขายแล้ว ${product.soldCount.toLocaleString()} ชิ้น</span>
                    </div>
                </div>

                <!-- Price and Buttons -->
                <div class="mt-4 pt-3.5 border-t border-slate-100 flex items-center justify-between gap-3">
                    <div>
                        <div class="text-xs text-slate-400 line-through font-medium">฿${product.originalPrice.toFixed(2)}</div>
                        <div class="text-2xl font-black text-pink-600 flex items-baseline gap-0.5">
                            <span class="text-sm">฿</span>${product.price.toFixed(2)}
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <button data-action="detail" data-product-id="${escapeHTML(product.id)}" title="ดูรายละเอียด" 
                            class="w-10 h-10 rounded-2xl bg-slate-100 border border-slate-200 hover:border-pink-300 text-slate-600 hover:text-pink-600 flex items-center justify-center text-sm transition-all shadow-sm">
                            <i class="fa-regular fa-eye"></i>
                        </button>
                        <button data-action="add-cart" data-product-id="${escapeHTML(product.id)}"
                            ${!inStock ? 'disabled' : ''}
                            class="gradient-btn px-4 h-10 rounded-2xl text-xs sm:text-sm font-extrabold flex items-center gap-1.5 ${!inStock ? 'opacity-40 cursor-not-allowed' : ''}">
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
    const cartBtn = e.target.closest('[data-action="add-cart"]');
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
                        <div class="w-11 h-11 rounded-xl bg-pink-50 border border-pink-200 flex items-center justify-center font-black text-xs text-pink-600 shrink-0">
                            ${escapeHTML(master.brandCode)}
                        </div>
                        <div class="flex-1 min-w-0">
                            <h4 class="text-xs font-bold text-slate-900 truncate">${escapeHTML(master.title)}</h4>
                            <div class="text-xs text-pink-600 font-extrabold mt-0.5">฿${master.price.toFixed(2)}</div>
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
        const availableStock = master ? (master.stock || (state.inventory[item.productId] || []).length || 0) : 0;
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
    document.getElementById('checkout-email-input').value = state.user ? state.user.email : '';
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
        const result = await SlipVerifier.verifySlip(verifiedTotal, STORE_CONFIG.promptPayNumber);

        btn.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400"></i> สลิปถูกต้อง! กำลังจัดส่งรหัส...`;

        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
            closeCheckoutModal();

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

            state.cart = [];
            saveCart();

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
                            <h4 class="text-sm font-extrabold text-slate-900 flex items-center gap-2">
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
                        <h4 class="text-sm font-extrabold text-slate-900 flex items-center gap-2">
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
                    <span class="px-3 py-1 rounded-full text-xs font-black flex items-center gap-1.5 shadow-xs ${isOrderPending
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

                return `
                            <div class="p-3 sm:p-3.5 rounded-xl bg-slate-50/70 border border-slate-200">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="flex items-center gap-2 min-w-0">
                                        <span class="w-5 h-5 rounded-full bg-pink-500 text-white flex items-center justify-center text-[10px] font-black shrink-0">
                                            ${itIdx + 1}
                                        </span>
                                        <span class="font-extrabold text-slate-900 text-xs sm:text-sm truncate">
                                            ${escapeHTML(item.productTitle)}
                                        </span>
                                    </div>
                                    <div class="flex items-center gap-2 shrink-0">
                                        <span class="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-bold border border-emerald-200">
                                            🛡️ ประกัน ${escapeHTML(item.warranty || '30 วัน')}
                                        </span>
                                        <span class="font-black text-pink-600 text-xs sm:text-sm">฿${(item.price || 0).toFixed(2)}</span>
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

    showToast(`ส่งมอบรหัสให้คำสั่งซื้อ ${orderId} สำเร็จแล้ว!`, "success");
}

function openAdminModal() {
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
                             class="relative w-11 h-11 rounded-xl overflow-hidden bg-slate-100 border border-slate-200 shrink-0 cursor-pointer group/img shadow-2xs hover:border-pink-400 transition-all">
                            <img src="${escapeHTML(master.image || `images/products/${p.id}.jpg`)}" 
                                 alt="${escapeHTML(master.title)}" 
                                 class="w-full h-full object-cover group-hover/img:scale-105 transition-transform"
                                 onerror="this.onerror=null;this.src='images/logo.png'">
                            <div class="absolute inset-0 bg-black/30 opacity-0 group-hover/img:opacity-100 flex items-center justify-center transition-opacity text-white text-[10px]">
                                <i class="fa-solid fa-pen"></i>
                            </div>
                        </div>
                        <div class="min-w-0 flex-1">
                            <div onclick="openEditPriceModal('${p.id}', 'title')"
                                 title="คลิกเพื่อแก้ไขข้อมูลสินค้า"
                                 class="font-bold text-slate-900 text-xs sm:text-sm hover:text-pink-600 cursor-pointer transition-colors line-clamp-1 flex items-center gap-1.5">
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
                        ${master.g2gUrl ? `
                        <a href="${escapeHTML(master.g2gUrl)}" target="_blank" rel="noopener noreferrer"
                           class="px-2 py-0.5 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300 text-[10px] font-bold transition-all flex items-center gap-1 shadow-2xs"
                           title="เปิดลิงก์สินค้าบน G2G">
                            <i class="fa-solid fa-cart-shopping text-[9px] text-amber-600"></i>
                            <span>ซื้อ G2G ↗</span>
                        </a>
                        ` : `
                        <span class="text-[10px] text-slate-400">ไม่มีลิงก์</span>
                        `}
                        <button type="button" 
                                onclick="navigator.clipboard.writeText('${escapeHTML(master.g2gRawTitle || master.title)}'); showToast('คัดลอกชื่อสินค้าแล้ว', 'info');"
                                class="p-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-500 hover:text-slate-800 border border-slate-200 text-[10px] cursor-pointer"
                                title="คัดลอกชื่อสินค้าบน G2G">
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
    if (g2gUrlInput) g2gUrlInput.value = master.g2gUrl || '';

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

function handleSaveEditedProduct() {
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
    const g2gUrlVal = (document.getElementById('edit-price-g2g-url')?.value || '').trim();

    const saleVal = parseFloat(document.getElementById('edit-price-sale').value);
    const origVal = parseFloat(document.getElementById('edit-price-original').value);
    const badgeVal = (document.getElementById('edit-price-badge')?.value || '').trim();
    const isHighlight = !!document.getElementById('edit-product-is-highlight')?.checked;

    if (isNaN(saleVal) || saleVal < 0) {
        showToast("กรุณากรอกราคาขายที่ถูกต้อง", "warning");
        document.getElementById('edit-price-sale')?.focus();
        return;
    }

    // 1. Save custom products metadata
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
        price: Math.round(saleVal * 100) / 100,
        originalPrice: isNaN(origVal) || origVal < saleVal ? Math.round(saleVal * 100) / 100 : Math.round(origVal * 100) / 100,
        g2gUrl: g2gUrlVal,
        deleted: false,
        updatedAt: new Date().toISOString()
    };
    localStorage.setItem('supinkly_custom_products', JSON.stringify(customProducts));

    // 2. Save custom price overrides
    const customPrices = getCustomPrices();
    customPrices[productId] = {
        ...(customPrices[productId] || {}),
        price: Math.round(saleVal * 100) / 100,
        originalPrice: isNaN(origVal) || origVal < saleVal ? Math.round(saleVal * 100) / 100 : Math.round(origVal * 100) / 100,
        badge: badgeVal,
        isHighlight: isHighlight,
        g2gUrl: g2gUrlVal,
        manualOverride: true,
        lastManualUpdate: new Date().toISOString()
    };
    localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));

    // 3. Reload application catalog
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
    STORE_CONFIG.slipOkApiKey = newApiKey;

    // Persist store config
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

    const availableStock = product.stock || (state.inventory[productId] || []).length || 0;

    document.getElementById('modal-product-brand').textContent = product.brand;
    document.getElementById('modal-product-type').textContent = product.type;
    document.getElementById('modal-product-title').textContent = product.title;
    document.getElementById('modal-product-desc').textContent = product.description;
    document.getElementById('modal-product-price').textContent = `฿${product.price.toFixed(2)}`;
    document.getElementById('modal-product-original-price').textContent = `฿${product.originalPrice.toFixed(2)}`;
    document.getElementById('modal-product-warranty').textContent = product.warranty;
    document.getElementById('modal-product-stock').textContent = `${availableStock} ชิ้น`;
    document.getElementById('modal-product-sold').textContent = `${product.soldCount.toLocaleString()} ชิ้น`;
    document.getElementById('modal-product-region').textContent = product.region;

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
    function connect(pin) {
        if (ws && ws.readyState < 2) return;
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'auth', role: 'admin', pin }));
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

        // Connect WebSocket as admin (reuse session PIN prompt)
        const pinHash = localStorage.getItem('supinkly_admin_pin_hash');
        // ใช้ prompt สั้นๆ รับ PIN เพื่อ auth กับ WS Server
        const pin = window.prompt('กรอก PIN แอดมินเพื่อเชื่อมต่อ Live Chat:');
        if (pin) ADMIN_CHAT.connect(pin.trim());
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

// Admin Authentication & Modal Controllers
window.openAdminModal = openAdminModal;
window.closeAdminModal = closeAdminModal;
window.promptAdminLogin = promptAdminLogin;
window.closeAdminPinModal = closeAdminPinModal;
window.handleAdminPinSubmit = handleAdminPinSubmit;
window.handleAdminLogout = handleAdminLogout;

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
