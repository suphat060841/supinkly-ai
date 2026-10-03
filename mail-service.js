/**
 * Supinkly.AI - Zero-Dependency Email Delivery Engine
 * Supports:
 * 1. Direct TLS/SSL SMTP (Port 465) via Node.js native `tls`
 * 2. STARTTLS SMTP (Port 587) via Node.js native `net` + `tls`
 * 3. HTTP API (e.g. Resend API) via native `fetch`
 * 4. Automatic Dev / Console Fallback when no SMTP is configured
 */

const tls = require('tls');
const net = require('net');

function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function sanitizeHeader(str) {
    if (str == null) return '';
    return String(str).replace(/[\r\n]/g, '').trim();
}

class MailService {
    constructor() {
        this.lastSentOtp = null;
    }

    /**
     * Get effective mail config (prioritizes environment variables, then database settings)
     */
    getConfig(db = {}) {
        const smtp = db.smtpConfig || {};
        const rawPass = process.env.SMTP_PASS || smtp.pass || '';
        return {
            host: String(process.env.SMTP_HOST || smtp.host || '').trim(),
            port: parseInt(process.env.SMTP_PORT || smtp.port || '465', 10),
            user: String(process.env.SMTP_USER || smtp.user || '').trim(),
            pass: String(rawPass).replace(/\s+/g, ''),
            from: String(process.env.SMTP_FROM || smtp.from || (process.env.SMTP_USER || smtp.user || 'no-reply@supinkly.ai')).trim(),
            resendKey: String(process.env.RESEND_API_KEY || smtp.resendKey || '').trim()
        };
    }

    /**
     * Check if real mail sending is configured
     */
    isConfigured(config) {
        return !!(config.resendKey || (config.host && config.user && config.pass));
    }

    /**
     * Generate modern, responsive Supinkly.AI branded HTML email for OTP verification
     */
    generateOtpEmailHtml(email, otp, displayName) {
        const name = escapeHtml(displayName || email.split('@')[0]);
        const safeOtp = escapeHtml(otp);
        return `
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>รหัสยืนยันการสมัครสมาชิก - Supinkly.AI</title>
</head>
<body style="margin: 0; padding: 0; background-color: #F8FAFC; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1E293B;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #F8FAFC; padding: 30px 10px;">
        <tr>
            <td align="center">
                <!-- Main Card -->
                <table role="presentation" width="100%" max-width="560" cellspacing="0" cellpadding="0" border="0" style="max-width: 560px; background-color: #FFFFFF; border-radius: 24px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.06); border: 1px solid #E2E8F0;">
                    
                    <!-- Header with Gradient -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #FF2E7E 0%, #8B5CF6 100%); padding: 32px 30px; text-align: center;">
                            <div style="font-size: 26px; font-weight: 900; color: #FFFFFF; letter-spacing: -0.5px; margin-bottom: 4px;">
                                Supinkly<span style="color: #FDE047;">.AI</span>
                            </div>
                            <div style="font-size: 13px; color: rgba(255,255,255,0.9); font-weight: 500;">
                                แพลตฟอร์มดิจิทัล & บัญชี AI มาตรฐานความปลอดภัยระดับสูง
                            </div>
                        </td>
                    </tr>

                    <!-- Body Content -->
                    <tr>
                        <td style="padding: 36px 32px 28px 32px;">
                            <h2 style="font-size: 20px; font-weight: 700; color: #0F172A; margin: 0 0 12px 0;">
                                ยืนยันอีเมลของคุณเพื่อเปิดใช้งานบัญชี
                            </h2>
                            <p style="font-size: 14px; line-height: 1.6; color: #475569; margin: 0 0 24px 0;">
                                สวัสดีคุณ <strong>${name}</strong>,<br>
                                ขอบคุณที่สมัครสมาชิกกับ <strong>Supinkly.AI</strong> กรุณานำรหัสยืนยัน 6 หลักด้านล่างนี้ไปกรอกในหน้าต่างลงทะเบียนเพื่อยืนยันตัวตนของคุณ:
                            </p>

                            <!-- Big OTP Highlight Box -->
                            <div style="background: #FFF1F2; border: 2px dashed #FDA4AF; border-radius: 20px; padding: 24px 20px; text-align: center; margin: 0 0 24px 0;">
                                <div style="font-size: 12px; font-weight: 700; color: #E11D48; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
                                    รหัสยืนยัน OTP (รหัสมีอายุ 10 นาที)
                                </div>
                                <div style="font-family: 'Courier New', Courier, monospace, sans-serif; font-size: 38px; font-weight: 800; letter-spacing: 8px; color: #BE123C; padding: 6px 0;">
                                    ${otp}
                                </div>
                                <div style="font-size: 12px; color: #9F1239; margin-top: 8px;">
                                    ห้ามแชร์รหัสนี้ให้ผู้อื่นเด็ดขาด เพื่อความปลอดภัยของบัญชี
                                </div>
                            </div>

                            <!-- Bullet Reminders -->
                            <div style="background-color: #F1F5F9; border-radius: 14px; padding: 14px 18px; margin-bottom: 24px;">
                                <div style="font-size: 12px; color: #334155; line-height: 1.6;">
                                    • รหัสนี้จะหมดอายุภายใน <strong>10 นาที</strong> นับจากเวลาที่ส่ง<br>
                                    • หากคุณไม่ได้ทำรายการสมัครสมาชิกที่ Supinkly.AI โปรดละเลยอีเมลฉบับนี้ บัญชีจะไม่ถูกสร้างขึ้น
                                </div>
                            </div>

                            <p style="font-size: 12px; line-height: 1.5; color: #64748B; margin: 0;">
                                มีคำถามหรือต้องการความช่วยเหลือ? ติดต่อฝ่ายบริการลูกค้าได้ตลอด 24 ชม. ผ่านทาง Live Chat บนหน้าเว็บไซต์ หรือ Facebook เพจ
                            </p>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #F8FAFC; border-top: 1px solid #E2E8F0; padding: 20px 32px; text-align: center;">
                            <div style="font-size: 11px; color: #94A3B8;">
                                &copy; 2026 Supinkly.AI Marketplace. All rights reserved.<br>
                                อีเมลนี้ส่งอัตโนมัติจากระบบ กรุณาอย่าตอบกลับโดยตรง
                            </div>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `.trim();
    }

    /**
     * Parse and sanitize email sender headers
     */
    resolveSender(config) {
        let fromEmail = config.user;
        if (config.from) {
            const match = config.from.match(/<([^>]+)>/);
            if (match && match[1] && match[1].includes('@')) {
                fromEmail = match[1].trim();
            } else if (config.from.includes('@')) {
                fromEmail = config.from.trim();
            }
        }
        const cleanFrom = config.from && config.from.includes('@')
            ? sanitizeHeader(config.from)
            : `Supinkly.AI <${config.user || fromEmail}>`;
        return { fromEmail: sanitizeHeader(fromEmail || config.user), cleanFrom };
    }

    /**
     * Send email via native Node.js Direct TLS/SSL SMTP socket (Port 465)
     */
    sendViaSmtpTls(config, { to, subject, html }) {
        return new Promise((resolve, reject) => {
            const timeoutMs = 15000;
            const socket = tls.connect({
                host: config.host,
                port: config.port || 465,
                servername: config.host,
                rejectUnauthorized: false
            });

            let buffer = '';
            let step = 0;
            const { fromEmail, cleanFrom } = this.resolveSender(config);

            const timer = setTimeout(() => {
                socket.destroy();
                reject(new Error(`SMTP SSL (Port ${config.port || 465}) เชื่อมต่อหมดเวลาหลังจาก 15 วินาที`));
            }, timeoutMs);

            const sendLine = (line) => {
                if (socket.destroyed) return;
                socket.write(line + '\r\n');
            };

            socket.on('data', (chunk) => {
                buffer += chunk.toString('utf-8');
                const lines = buffer.split('\r\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (!line || line.length < 3) continue;
                    const code = parseInt(line.substring(0, 3), 10);
                    const isFinal = line.charAt(3) !== '-';
                    if (!isFinal) continue;

                    try {
                        const cleanTo = sanitizeHeader(to);
                        const cleanSubject = sanitizeHeader(subject);

                        if (step === 0 && code === 220) {
                            step = 1;
                            sendLine('EHLO localhost');
                        } else if (step === 1 && code === 250) {
                            step = 2;
                            sendLine('AUTH LOGIN');
                        } else if (step === 2 && code === 334) {
                            step = 3;
                            sendLine(Buffer.from(config.user).toString('base64'));
                        } else if (step === 3 && code === 334) {
                            step = 4;
                            sendLine(Buffer.from(config.pass).toString('base64'));
                        } else if (step === 4 && code === 235) {
                            step = 5;
                            sendLine(`MAIL FROM:<${fromEmail}>`);
                        } else if (step === 5 && code === 250) {
                            step = 6;
                            sendLine(`RCPT TO:<${cleanTo}>`);
                        } else if (step === 6 && code === 250) {
                            step = 7;
                            sendLine('DATA');
                        } else if (step === 7 && code === 354) {
                            step = 8;
                            const boundary = '----=_SupinklyBoundary_' + Date.now().toString(16);
                            const mime = [
                                `From: ${cleanFrom}`,
                                `To: ${cleanTo}`,
                                `Subject: =?UTF-8?B?${Buffer.from(cleanSubject).toString('base64')}?=`,
                                'MIME-Version: 1.0',
                                `Content-Type: multipart/alternative; boundary="${boundary}"`,
                                '',
                                `--${boundary}`,
                                'Content-Type: text/plain; charset=UTF-8',
                                'Content-Transfer-Encoding: base64',
                                '',
                                Buffer.from(`รหัสยืนยัน OTP Supinkly.AI: ${cleanSubject}`).toString('base64'),
                                '',
                                `--${boundary}`,
                                'Content-Type: text/html; charset=UTF-8',
                                'Content-Transfer-Encoding: base64',
                                '',
                                Buffer.from(html).toString('base64'),
                                '',
                                `--${boundary}--`,
                                '.'
                            ].join('\r\n');
                            sendLine(mime);
                        } else if (step === 8 && code === 250) {
                            step = 9;
                            sendLine('QUIT');
                            clearTimeout(timer);
                            socket.end();
                            resolve({ success: true, method: 'smtp-tls-465' });
                        } else if (code === 535) {
                            clearTimeout(timer);
                            socket.destroy();
                            reject(new Error(`SMTP Authentication Failed (535): รหัสผ่านหรือชื่อผู้ใช้ไม่ถูกต้อง หากใช้ Gmail ต้องเปิด 2-Step Verification และสร้าง App Password 16 หลักจาก Google Account (${line})`));
                        } else if (code >= 400) {
                            clearTimeout(timer);
                            socket.destroy();
                            reject(new Error(`SMTP Error [${code}]: ${line}`));
                        }
                    } catch (err) {
                        clearTimeout(timer);
                        socket.destroy();
                        reject(err);
                    }
                }
            });

            socket.on('error', (err) => {
                clearTimeout(timer);
                reject(err);
            });
        });
    }

    /**
     * Send email via native Node.js STARTTLS SMTP socket (Port 587)
     */
    sendViaSmtpStarttls(config, { to, subject, html }) {
        return new Promise((resolve, reject) => {
            const timeoutMs = 15000;
            let timer = null;
            let activeSocket = null;

            const cleanup = () => {
                if (timer) clearTimeout(timer);
                if (activeSocket && !activeSocket.destroyed) {
                    try { activeSocket.destroy(); } catch (e) {}
                }
            };

            timer = setTimeout(() => {
                cleanup();
                reject(new Error(`SMTP STARTTLS (Port ${config.port || 587}) เชื่อมต่อหมดเวลาหลังจาก 15 วินาที`));
            }, timeoutMs);

            const { fromEmail, cleanFrom } = this.resolveSender(config);
            const plainSocket = net.connect({
                host: config.host,
                port: config.port || 587
            });
            activeSocket = plainSocket;

            let buffer = '';
            let phase = 'INIT';

            const sendLine = (sock, line) => {
                if (!sock || sock.destroyed) return;
                sock.write(line + '\r\n');
            };

            const handleData = (sock, chunk) => {
                buffer += chunk.toString('utf-8');
                const lines = buffer.split('\r\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (!line || line.length < 3) continue;
                    const code = parseInt(line.substring(0, 3), 10);
                    const isFinal = line.charAt(3) !== '-';
                    if (!isFinal) continue;

                    try {
                        const cleanTo = sanitizeHeader(to);
                        const cleanSubject = sanitizeHeader(subject);

                        if (phase === 'INIT' && code === 220) {
                            phase = 'EHLO1';
                            sendLine(sock, 'EHLO localhost');
                        } else if (phase === 'EHLO1' && code === 250) {
                            phase = 'STARTTLS';
                            sendLine(sock, 'STARTTLS');
                        } else if (phase === 'STARTTLS' && code === 220) {
                            phase = 'UPGRADING';
                            plainSocket.removeAllListeners('data');
                            plainSocket.removeAllListeners('error');

                            const tlsSocket = tls.connect({
                                socket: plainSocket,
                                host: config.host,
                                servername: config.host,
                                rejectUnauthorized: false
                            }, () => {
                                phase = 'EHLO2';
                                activeSocket = tlsSocket;
                                sendLine(tlsSocket, 'EHLO localhost');
                            });

                            activeSocket = tlsSocket;
                            tlsSocket.on('data', (c) => handleData(tlsSocket, c));
                            tlsSocket.on('error', (err) => {
                                cleanup();
                                reject(err);
                            });
                        } else if (phase === 'EHLO2' && code === 250) {
                            phase = 'AUTH';
                            sendLine(sock, 'AUTH LOGIN');
                        } else if (phase === 'AUTH' && code === 334) {
                            phase = 'USER';
                            sendLine(sock, Buffer.from(config.user).toString('base64'));
                        } else if (phase === 'USER' && code === 334) {
                            phase = 'PASS';
                            sendLine(sock, Buffer.from(config.pass).toString('base64'));
                        } else if (phase === 'PASS' && code === 235) {
                            phase = 'FROM';
                            sendLine(sock, `MAIL FROM:<${fromEmail}>`);
                        } else if (phase === 'FROM' && code === 250) {
                            phase = 'RCPT';
                            sendLine(sock, `RCPT TO:<${cleanTo}>`);
                        } else if (phase === 'RCPT' && code === 250) {
                            phase = 'DATA';
                            sendLine(sock, 'DATA');
                        } else if (phase === 'DATA' && code === 354) {
                            phase = 'BODY';
                            const boundary = '----=_SupinklyBoundary_' + Date.now().toString(16);
                            const mime = [
                                `From: ${cleanFrom}`,
                                `To: ${cleanTo}`,
                                `Subject: =?UTF-8?B?${Buffer.from(cleanSubject).toString('base64')}?=`,
                                'MIME-Version: 1.0',
                                `Content-Type: multipart/alternative; boundary="${boundary}"`,
                                '',
                                `--${boundary}`,
                                'Content-Type: text/plain; charset=UTF-8',
                                'Content-Transfer-Encoding: base64',
                                '',
                                Buffer.from(`รหัสยืนยัน OTP Supinkly.AI: ${cleanSubject}`).toString('base64'),
                                '',
                                `--${boundary}`,
                                'Content-Type: text/html; charset=UTF-8',
                                'Content-Transfer-Encoding: base64',
                                '',
                                Buffer.from(html).toString('base64'),
                                '',
                                `--${boundary}--`,
                                '.'
                            ].join('\r\n');
                            sendLine(sock, mime);
                        } else if (phase === 'BODY' && code === 250) {
                            phase = 'QUIT';
                            sendLine(sock, 'QUIT');
                            if (timer) clearTimeout(timer);
                            sock.end();
                            resolve({ success: true, method: 'smtp-starttls-587' });
                        } else if (code === 535) {
                            cleanup();
                            reject(new Error(`SMTP Authentication Failed (535): รหัสผ่านหรือชื่อผู้ใช้ไม่ถูกต้อง หากใช้ Gmail ต้องเปิด 2-Step Verification และสร้าง App Password 16 หลักจาก Google Account (${line})`));
                        } else if (code >= 400) {
                            cleanup();
                            reject(new Error(`SMTP STARTTLS Error [${code}]: ${line}`));
                        }
                    } catch (err) {
                        cleanup();
                        reject(err);
                    }
                }
            };

            plainSocket.on('data', (c) => handleData(plainSocket, c));
            plainSocket.on('error', (err) => {
                cleanup();
                reject(err);
            });
        });
    }

    /**
     * Send email via SMTP with intelligent Port 465 / 587 routing & fallback
     */
    async sendEmailViaSmtp(config, { to, subject, html }) {
        if (config.port === 587) {
            try {
                return await this.sendViaSmtpStarttls(config, { to, subject, html });
            } catch (err) {
                // If 587 failed and host is Gmail, attempt 465 fallback
                if (config.host.includes('gmail') || config.host.includes('google')) {
                    console.log('[MAIL] Port 587 failed, attempting fallback to Port 465 SSL...');
                    return await this.sendViaSmtpTls({ ...config, port: 465 }, { to, subject, html });
                }
                throw err;
            }
        }

        // Port 465 (or default)
        try {
            return await this.sendViaSmtpTls(config, { to, subject, html });
        } catch (err) {
            // If Port 465 timed out or connection was refused, and host is Gmail, attempt Port 587 STARTTLS
            const isConnIssue = err.message && (err.message.includes('timeout') || err.message.includes('ECONNREFUSED') || err.message.includes('ETIMEDOUT'));
            if (isConnIssue && (config.host.includes('gmail') || config.host.includes('google'))) {
                console.log('[MAIL] Port 465 connection issue, attempting fallback to Port 587 STARTTLS...');
                return await this.sendViaSmtpStarttls({ ...config, port: 587 }, { to, subject, html });
            }
            throw err;
        }
    }

    /**
     * Send email via Resend API (Native fetch HTTP) with auto unverified domain recovery
     */
    async sendViaResend(config, { to, subject, html }) {
        let fromAddress = config.from && config.from.includes('@')
            ? config.from
            : 'Supinkly.AI <onboarding@resend.dev>';

        const payload = {
            from: fromAddress,
            to: [to],
            subject: subject,
            html: html
        };

        let res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${config.resendKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        let data = await res.json().catch(() => ({}));

        // If custom domain unverified, automatically fallback to onboarding@resend.dev
        if (!res.ok && data.message && data.message.toLowerCase().includes('domain') && !fromAddress.includes('resend.dev')) {
            console.warn('[MAIL] Resend custom domain unverified, retrying with onboarding@resend.dev...');
            payload.from = 'Supinkly.AI <onboarding@resend.dev>';
            res = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${config.resendKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
            data = await res.json().catch(() => ({}));
        }

        if (!res.ok) {
            throw new Error(data.message || `Resend HTTP error ${res.status}`);
        }
        return { success: true, method: 'resend', id: data.id };
    }

    /**
     * Dispatch OTP Email to user (handles SMTP, API, and graceful Dev/Console fallback)
     */
    async sendOtpEmail(toEmail, otp, displayName, db = {}) {
        const config = this.getConfig(db);
        const subject = `[Supinkly.AI] รหัสยืนยันการสมัครสมาชิก: ${otp}`;
        const html = this.generateOtpEmailHtml(toEmail, otp, displayName);

        this.lastSentOtp = {
            email: toEmail,
            otp,
            createdAt: new Date().toISOString()
        };

        let lastError = null;

        // 1. Try Resend HTTP API if configured
        if (config.resendKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลผ่าน Resend API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaResend(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน Resend สำเร็จ ID: ${res.id}`);
                return { success: true, delivered: true, method: 'resend' };
            } catch (err) {
                console.error('[MAIL] Resend failed, trying SMTP fallback:', err.message);
                lastError = err.message;
            }
        }

        // 2. Try SMTP if configured
        if (config.host && config.user && config.pass) {
            try {
                console.log(`[MAIL] กำลังเชื่อมต่อ SMTP ${config.host}:${config.port} เพื่อส่งไปยัง ${toEmail}...`);
                const sRes = await this.sendEmailViaSmtp(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน SMTP สำเร็จ (${sRes.method}) ไปยัง: ${toEmail}`);
                return { success: true, delivered: true, method: sRes.method };
            } catch (err) {
                console.error('[MAIL] SMTP failed:', err.message);
                lastError = err.message;
            }
        }

        // 3. Fallback / Dev Mode (when no SMTP credentials are provided yet)
        console.log(`
======================================================================
[SUPINKLY OTP NOTIFICATION]
⚡ ถึง: ${toEmail} (${displayName || 'ผู้ใช้งาน'})
🔑 รหัสยืนยัน OTP 6 หลัก: ${otp}
⏰ รหัสมีอายุ 10 นาที
💡 หมายเหตุ: ${lastError ? `[ข้อผิดพลาดการส่ง: ${lastError}]` : 'ยังไม่ได้เชื่อมต่อ SMTP ร้านค้า'}
======================================================================
        `);

        return {
            success: true,
            delivered: false,
            fallbackConsole: true,
            method: 'console',
            otp,
            deliveryError: lastError || undefined
        };
    }

    /**
     * Generate modern, responsive Supinkly.AI branded HTML email for Password Reset OTP
     */
    generateResetPasswordEmailHtml(email, otp, displayName) {
        const name = escapeHtml(displayName || email.split('@')[0]);
        const safeOtp = escapeHtml(otp);
        return `
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>รหัสตั้งรหัสผ่านใหม่ - Supinkly.AI</title>
</head>
<body style="margin: 0; padding: 0; background-color: #F8FAFC; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1E293B;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #F8FAFC; padding: 30px 10px;">
        <tr>
            <td align="center">
                <!-- Main Card -->
                <table role="presentation" width="100%" max-width="560" cellspacing="0" cellpadding="0" border="0" style="max-width: 560px; background-color: #FFFFFF; border-radius: 24px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.06); border: 1px solid #E2E8F0;">
                    
                    <!-- Header with Gradient -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #FF2E7E 0%, #8B5CF6 100%); padding: 32px 30px; text-align: center;">
                            <div style="font-size: 26px; font-weight: 900; color: #FFFFFF; letter-spacing: -0.5px; margin-bottom: 4px;">
                                Supinkly<span style="color: #FDE047;">.AI</span>
                            </div>
                            <div style="font-size: 13px; color: rgba(255,255,255,0.9); font-weight: 500;">
                                แพลตฟอร์มดิจิทัล & บัญชี AI มาตรฐานความปลอดภัยระดับสูง
                            </div>
                        </td>
                    </tr>

                    <!-- Body Content -->
                    <tr>
                        <td style="padding: 36px 32px 28px 32px;">
                            <h2 style="font-size: 20px; font-weight: 700; color: #0F172A; margin: 0 0 12px 0;">
                                คำขอตั้งรหัสผ่านใหม่สำหรับบัญชีของคุณ
                            </h2>
                            <p style="font-size: 14px; line-height: 1.6; color: #475569; margin: 0 0 24px 0;">
                                สวัสดีคุณ <strong>${name}</strong>,<br>
                                เราได้รับคำขอตั้งรหัสผ่านใหม่สำหรับบัญชีของคุณที่ <strong>Supinkly.AI</strong> กรุณานำรหัสยืนยัน 6 หลักด้านล่างนี้ไปกรอกเพื่อตั้งรหัสผ่านใหม่:
                            </p>

                            <!-- Big OTP Highlight Box -->
                            <div style="background: #FFF1F2; border: 2px dashed #FDA4AF; border-radius: 20px; padding: 24px 20px; text-align: center; margin: 0 0 24px 0;">
                                <div style="font-size: 12px; font-weight: 700; color: #E11D48; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
                                    รหัส OTP รีเซ็ตรหัสผ่าน (รหัสมีอายุ 10 นาที)
                                </div>
                                <div style="font-family: 'Courier New', Courier, monospace, sans-serif; font-size: 38px; font-weight: 800; letter-spacing: 8px; color: #BE123C; padding: 6px 0;">
                                    ${safeOtp}
                                </div>
                                <div style="font-size: 12px; color: #9F1239; margin-top: 8px;">
                                    ห้ามแชร์รหัสนี้ให้ผู้อื่นเด็ดขาด เพื่อความปลอดภัยของบัญชี
                                </div>
                            </div>

                            <!-- Bullet Reminders -->
                            <div style="background-color: #F1F5F9; border-radius: 14px; padding: 14px 18px; margin-bottom: 24px;">
                                <div style="font-size: 12px; color: #334155; line-height: 1.6;">
                                    • รหัสนี้จะหมดอายุภายใน <strong>10 นาที</strong> นับจากเวลาที่ส่งคำขอ<br>
                                    • หากคุณไม่ได้เป็นผู้ส่งคำขอตั้งรหัสผ่านใหม่ บัญชีของคุณยังคงปลอดภัย และโปรดละเลยอีเมลฉบับนี้
                                </div>
                            </div>

                            <p style="font-size: 12px; line-height: 1.5; color: #64748B; margin: 0;">
                                มีคำถามหรือพบปัญหา? ติดต่อทีมงานได้ตลอด 24 ชม. ผ่านทาง Live Chat หรือ Facebook เพจ
                            </p>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #F8FAFC; border-top: 1px solid #E2E8F0; padding: 20px 32px; text-align: center;">
                            <div style="font-size: 11px; color: #94A3B8;">
                                &copy; 2026 Supinkly.AI Marketplace. All rights reserved.<br>
                                อีเมลนี้ส่งอัตโนมัติจากระบบ กรุณาอย่าตอบกลับโดยตรง
                            </div>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `.trim();
    }

    /**
     * Dispatch Password Reset OTP Email
     */
    async sendResetPasswordEmail(toEmail, otp, displayName, db = {}) {
        const config = this.getConfig(db);
        const subject = `[Supinkly.AI] รหัส OTP สำหรับตั้งรหัสผ่านใหม่: ${otp}`;
        const html = this.generateResetPasswordEmailHtml(toEmail, otp, displayName);

        let lastError = null;

        // 1. Try Resend HTTP API if configured
        if (config.resendKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Resend ไปยัง: ${toEmail}...`);
                const res = await this.sendViaResend(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Resend สำเร็จ ID: ${res.id}`);
                return { success: true, delivered: true, method: 'resend' };
            } catch (err) {
                console.error('[MAIL] Resend failed, trying SMTP fallback:', err.message);
                lastError = err.message;
            }
        }

        // 2. Try SMTP if configured
        if (config.host && config.user && config.pass) {
            try {
                console.log(`[MAIL] กำลังเชื่อมต่อ SMTP ${config.host}:${config.port} เพื่อส่งอีเมลรีเซ็ตรหัสผ่านไปยัง ${toEmail}...`);
                const sRes = await this.sendEmailViaSmtp(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน SMTP สำเร็จ (${sRes.method}) ไปยัง: ${toEmail}`);
                return { success: true, delivered: true, method: sRes.method };
            } catch (err) {
                console.error('[MAIL] SMTP failed:', err.message);
                lastError = err.message;
            }
        }

        // 3. Fallback / Dev Mode
        console.log(`
======================================================================
[SUPINKLY PASSWORD RESET OTP]
⚡ ถึง: ${toEmail} (${displayName || 'ผู้ใช้งาน'})
🔑 รหัส OTP ตั้งรหัสผ่านใหม่: ${otp}
⏰ รหัสมีอายุ 10 นาที
💡 หมายเหตุ: ${lastError ? `[ข้อผิดพลาดการส่ง: ${lastError}]` : 'ยังไม่ได้เชื่อมต่อ SMTP ร้านค้า'}
======================================================================
        `);

        return {
            success: true,
            delivered: false,
            fallbackConsole: true,
            method: 'console',
            otp,
            deliveryError: lastError || undefined
        };
    }

    /**
     * Test connection to mail service (Gmail SMTP or Resend API)
     */
    async testConnection(testRecipient, customConfig = null, db = {}) {
        const base = this.getConfig(db);
        const config = customConfig ? { ...base, ...customConfig } : base;
        config.pass = String(config.pass || '').replace(/\s+/g, '');
        config.user = String(config.user || '').trim();
        config.host = String(config.host || '').trim();
        config.port = parseInt(config.port || '465', 10);
        config.resendKey = String(config.resendKey || '').trim();
        config.from = String(config.from || '').trim();

        if (!this.isConfigured(config)) {
            return {
                success: false,
                message: 'ยังไม่ได้ระบุข้อมูลสำหรับส่งอีเมล กรุณาระบุ SMTP (Host, User, App Password) หรือ Resend API Key'
            };
        }

        const to = (testRecipient || config.user || '').trim();
        if (!to || !to.includes('@')) {
            return {
                success: false,
                message: 'กรุณาระบุอีเมลผู้รับสำหรับการทดสอบ (เช่น อีเมลของคุณ)'
            };
        }

        const testSubject = `[Supinkly.AI] ทดสอบการเชื่อมต่อระบบอีเมลสำเร็จ (${new Date().toLocaleTimeString('th-TH')})`;
        const testHtml = `
            <div style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width:520px; margin:20px auto; padding:28px; border:1px solid #E2E8F0; border-radius:20px; background:#ffffff;">
                <div style="text-align:center; margin-bottom:20px;">
                    <span style="font-size:24px; font-weight:900; color:#FF2E7E;">Supinkly<span style="color:#8B5CF6;">.AI</span></span>
                    <div style="font-size:12px; color:#64748B; margin-top:4px;">ระบบทดสอบการส่งอีเมลอัตโนมัติ</div>
                </div>
                <div style="background:#ECFDF5; border:1px solid #A7F3D0; border-radius:14px; padding:16px; margin-bottom:20px; text-align:center;">
                    <div style="font-size:16px; font-weight:bold; color:#065F46;">✅ การเชื่อมต่อระบบส่งอีเมลสมบูรณ์ 100%!</div>
                    <div style="font-size:12px; color:#047857; margin-top:4px;">เซิร์ฟเวอร์สามารถส่งอีเมลจริงเข้ากล่องจดหมายได้เรียบร้อยแล้ว</div>
                </div>
                <div style="background:#F8FAFC; border-radius:12px; padding:14px; font-size:12px; color:#334155; line-height:1.6; margin-bottom:20px;">
                    • <strong>เวลาที่ส่ง:</strong> ${new Date().toLocaleString('th-TH')}<br>
                    • <strong>อีเมลผู้รับ:</strong> ${to}<br>
                    • <strong>ระบบที่ใช้:</strong> ${config.resendKey ? 'Resend HTTP API' : `SMTP Server (${config.host}:${config.port})`}
                </div>
                <p style="font-size:12px; color:#64748B; line-height:1.5; margin:0;">
                    ระบบ OTP สำหรับการยืนยันตัวตนสมาชิก และการตั้งรหัสผ่านใหม่ พร้อมส่งมอบถึงลูกค้าจริงทุกคนแล้ว
                </p>
            </div>
        `;

        const errors = [];

        // 1. Try Resend if configured
        if (config.resendKey) {
            try {
                console.log(`[MAIL-TEST] กำลังทดสอบส่งผ่าน Resend ไปยัง: ${to}...`);
                const res = await this.sendViaResend(config, { to, subject: testSubject, html: testHtml });
                return {
                    success: true,
                    method: 'Resend API',
                    recipient: to,
                    message: `ส่งอีเมลทดสอบผ่าน Resend API สำเร็จแล้ว (ID: ${res.id}) กรุณาตรวจสอบกล่องจดหมาย ${to} (และโฟลเดอร์สแปม)`
                };
            } catch (err) {
                console.error('[MAIL-TEST] Resend test error:', err.message);
                let errText = err.message;
                if (errText.includes('validation_error') || errText.includes('only send testing emails')) {
                    errText = 'Resend ไม่อนุญาตให้ส่ง: ในโหมดฟรี Resend อนุญาตให้ส่งได้เฉพาะอีเมลที่คุณใช้สมัครบัญชี Resend เท่านั้น';
                }
                errors.push(`[Resend]: ${errText}`);
            }
        }

        // 2. Try SMTP if configured
        if (config.host && config.user && config.pass) {
            try {
                console.log(`[MAIL-TEST] กำลังทดสอบเชื่อมต่อ SMTP ${config.host}:${config.port} ไปยัง: ${to}...`);
                const res = await this.sendEmailViaSmtp(config, { to, subject: testSubject, html: testHtml });
                return {
                    success: true,
                    method: res.method || `SMTP (${config.host}:${config.port})`,
                    recipient: to,
                    message: `ส่งอีเมลทดสอบผ่าน SMTP (${config.host}) สำเร็จแล้ว! กรุณาตรวจสอบกล่องจดหมาย ${to} (รวมถึงโฟลเดอร์ Junk/Spam)`
                };
            } catch (err) {
                console.error('[MAIL-TEST] SMTP test error:', err.message);
                let msg = err.message || 'Unknown SMTP error';
                if (msg.includes('535') || msg.includes('BadCredentials') || msg.includes('Username and Password not accepted')) {
                    msg = `รหัสผ่านหรือผู้ใช้ไม่ถูกต้อง (535 Bad Credentials): หากใช้ Gmail ต้องเปิด 2-Step Verification และสร้าง "App Password (รหัสผ่านสำหรับแอป 16 หลัก)" จากความปลอดภัยบัญชี Google (ห้ามใช้รหัสผ่าน Gmail ปกติ) [ระบบได้ลบช่องว่างให้อัตโนมัติแล้ว]`;
                } else if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
                    msg = `หมดเวลาเชื่อมต่อ (Connection Timeout): เซิร์ฟเวอร์ไม่สามารถติดต่อ ${config.host}:${config.port} ได้ แนะนำให้ลองเปลี่ยนเป็น Port 587 หรือ 465`;
                } else if (msg.includes('ECONNREFUSED')) {
                    msg = `การเชื่อมต่อถูกปฏิเสธ (Connection Refused): พอร์ต ${config.port} บน ${config.host} ปิดอยู่หรือไม่สามารถเข้าถึงได้`;
                }
                errors.push(`[SMTP]: ${msg}`);
            }
        }

        return {
            success: false,
            message: errors.join('\n') || 'ไม่สามารถส่งอีเมลได้ กรุณาตรวจสอบการตั้งค่า'
        };
    }
}

module.exports = new MailService();
