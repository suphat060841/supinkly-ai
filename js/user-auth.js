/**
 * Supinkly.AI — User Authentication Module
 * จัดการ login / register / forgot-password / session สำหรับลูกค้า
 */

const USER_AUTH = (() => {
    const TOKEN_KEY   = 'supinkly_user_token';
    const USER_KEY    = 'supinkly_user_info';
    const EXPIRY_KEY  = 'supinkly_user_expiry';

    // ── Helpers ────────────────────────────────────────────────
    function getToken()   { return localStorage.getItem(TOKEN_KEY); }
    function getUser()    {
        try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch { return null; }
    }
    function getHeaders() {
        const t = getToken();
        return t ? { 'Content-Type': 'application/json', 'x-user-token': t } : { 'Content-Type': 'application/json' };
    }
    function isLoggedIn() {
        const expiry = parseInt(localStorage.getItem(EXPIRY_KEY) || '0', 10);
        return !!getToken() && Date.now() < expiry;
    }

    function saveSession(token, expiresAt, user) {
        localStorage.setItem(TOKEN_KEY,  token);
        localStorage.setItem(EXPIRY_KEY, String(expiresAt));
        localStorage.setItem(USER_KEY,   JSON.stringify(user));
    }

    function clearSession() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(EXPIRY_KEY);
        localStorage.removeItem(USER_KEY);
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
        try {
            await fetch('/api/auth/logout', { method: 'POST', headers: getHeaders() });
        } catch {}
        clearSession();
    }

    // ── Verify session against server ──────────────────────────
    async function verifySession() {
        if (!isLoggedIn()) return false;
        try {
            const res  = await fetch('/api/auth/verify-session', { method: 'POST', headers: getHeaders() });
            const data = await res.json();
            if (data.success && data.user) {
                localStorage.setItem(USER_KEY, JSON.stringify(data.user));
                return true;
            }
        } catch {}
        clearSession();
        return false;
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
            const data = await res.json();
            return data.success ? data.orders : [];
        } catch { return []; }
    }

    return { 
        getToken, 
        getUser, 
        getHeaders, 
        isLoggedIn, 
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
