/**
 * Supinkly.AI — User Authentication Module
 * จัดการ login / register / forgot-password / session สำหรับลูกค้า
 */

const USER_AUTH = (() => {
    const TOKEN_KEY   = 'supinkly_user_token';
    const USER_KEY    = 'supinkly_user_info';
    const EXPIRY_KEY  = 'supinkly_user_expiry';

    // ── Helpers ────────────────────────────────────────────────
    function getToken()   { 
        return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || null; 
    }
    
    function getUser()    {
        try { 
            const raw = localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY);
            return raw ? JSON.parse(raw) : null; 
        } catch { return null; }
    }
    
    function getHeaders() {
        const t = getToken();
        return t ? { 'Content-Type': 'application/json', 'x-user-token': t } : { 'Content-Type': 'application/json' };
    }
    
    function isLoggedIn() {
        const token = getToken();
        if (!token) return false;
        const expiryStr = localStorage.getItem(EXPIRY_KEY) || sessionStorage.getItem(EXPIRY_KEY);
        const expiry = parseInt(expiryStr || '0', 10);
        if (expiry > 0 && Date.now() >= expiry) {
            clearSession();
            return false;
        }
        return true;
    }

    function saveSession(token, expiresAt, user) {
        if (!token) return;
        const normalizedUser = user ? { ...user, userId: user.userId || user.id, id: user.id || user.userId } : null;
        const exp = expiresAt || (Date.now() + 30 * 24 * 60 * 60 * 1000);
        localStorage.setItem(TOKEN_KEY,  token);
        localStorage.setItem(EXPIRY_KEY, String(exp));
        if (normalizedUser) {
            localStorage.setItem(USER_KEY, JSON.stringify(normalizedUser));
        }
        try {
            sessionStorage.setItem(TOKEN_KEY, token);
            sessionStorage.setItem(EXPIRY_KEY, String(exp));
            if (normalizedUser) sessionStorage.setItem(USER_KEY, JSON.stringify(normalizedUser));
        } catch {}
    }

    function clearSession() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(EXPIRY_KEY);
        localStorage.removeItem(USER_KEY);
        localStorage.removeItem('supinkly_user');
        try {
            sessionStorage.removeItem(TOKEN_KEY);
            sessionStorage.removeItem(EXPIRY_KEY);
            sessionStorage.removeItem(USER_KEY);
        } catch {}
    }

    // ── Register ───────────────────────────────────────────────
    async function register(email, password, displayName) {
        try {
            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, displayName })
            });
            const data = await res.json();
            if (data.success && data.token) saveSession(data.token, data.expiresAt, data.user);
            return data;
        } catch (e) {
            return { success: false, message: "ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้ กรุณาตรวจสอบอินเทอร์เน็ตแล้วลองใหม่อีกครั้ง" };
        }
    }

    // ── Verify Registration OTP ────────────────────────────────
    async function verifyOtp(email, otp) {
        try {
            const res = await fetch('/api/auth/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, otp })
            });
            const data = await res.json();
            if (data.success && data.token) saveSession(data.token, data.expiresAt, data.user);
            return data;
        } catch (e) {
            return { success: false, message: "ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้ กรุณาลองใหม่อีกครั้ง" };
        }
    }

    // ── Resend Registration OTP ────────────────────────────────
    async function resendOtp(email) {
        try {
            const res = await fetch('/api/auth/resend-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            return await res.json();
        } catch (e) {
            return { success: false, message: "ไม่สามารถส่งรหัส OTP ได้ กรุณาลองใหม่อีกครั้ง" };
        }
    }

    // ── Forgot Password (Request OTP) ──────────────────────────
    async function forgotPassword(email) {
        try {
            const res = await fetch('/api/auth/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            return await res.json();
        } catch (e) {
            return { success: false, message: "ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้ กรุณาลองใหม่อีกครั้ง" };
        }
    }

    // ── Reset Password (Verify OTP & Save New Password) ─────────
    async function resetPassword(email, otp, newPassword) {
        try {
            const res = await fetch('/api/auth/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, otp, newPassword })
            });
            const data = await res.json();
            if (data.success && data.token) saveSession(data.token, data.expiresAt, data.user);
            return data;
        } catch (e) {
            return { success: false, message: "ไม่สามารถเปลี่ยนรหัสผ่านได้ กรุณาลองใหม่อีกครั้ง" };
        }
    }

    // ── Login ──────────────────────────────────────────────────
    async function login(email, password) {
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            if (data.success && data.token) saveSession(data.token, data.expiresAt, data.user);
            return data;
        } catch (e) {
            return { success: false, message: "ไม่สามารถเข้าสู่ระบบได้ กรุณาตรวจสอบอินเทอร์เน็ตแล้วลองใหม่อีกครั้ง" };
        }
    }

    // ── Logout ─────────────────────────────────────────────────
    async function logout() {
        const headers = getHeaders();
        clearSession();
        try {
            await fetch('/api/auth/logout', { method: 'POST', headers });
        } catch {}
    }

    // ── Verify session against server ──────────────────────────
    async function verifySession() {
        if (!isLoggedIn()) return false;
        try {
            const res  = await fetch('/api/auth/verify-session', { method: 'POST', headers: getHeaders() });
            if (res.status === 401) {
                // Token is genuinely invalid/revoked by server
                clearSession();
                return false;
            }
            if (res.ok) {
                const data = await res.json();
                if (data.success && data.user) {
                    const normalizedUser = { ...data.user, userId: data.user.userId || data.user.id, id: data.user.id || data.user.userId };
                    localStorage.setItem(USER_KEY, JSON.stringify(normalizedUser));
                    try { sessionStorage.setItem(USER_KEY, JSON.stringify(normalizedUser)); } catch {}
                    return true;
                }
            }
        } catch {
            // Network error or server restart: keep existing session valid!
            return isLoggedIn();
        }
        return isLoggedIn();
    }

    // ── Link local orders to account ───────────────────────────
    async function linkLocalOrders(orderIds) {
        if (!isLoggedIn() || !Array.isArray(orderIds) || orderIds.length === 0) return 0;
        try {
            const res = await fetch('/api/auth/link-local-orders', {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({ orderIds })
            });
            const data = await res.json();
            return data.success ? data.linkedCount : 0;
        } catch { return 0; }
    }

    // ── Fetch all orders for this account ──────────────────────
    async function fetchMyOrders() {
        if (!isLoggedIn()) return [];
        try {
            const res  = await fetch('/api/auth/my-orders', { headers: getHeaders() });
            if (!res.ok) return [];
            const data = await res.json();
            return (data.success && Array.isArray(data.orders)) ? data.orders : [];
        } catch { return []; }
    }

    return { 
        getToken, 
        getUser, 
        getHeaders, 
        isLoggedIn, 
        saveSession,
        clearSession,
        register, 
        verifyOtp, 
        resendOtp, 
        forgotPassword, 
        resetPassword, 
        login, 
        logout, 
        verifySession, 
        linkLocalOrders, 
        fetchMyOrders 
    };
})();
