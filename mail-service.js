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

function isConnectionIssue(err) {
    if (!err) return false;
    const msg = String(err.message || '').toLowerCase();
    const code = String(err.code || '').toUpperCase();
    return (
        msg.includes('timeout') ||
        msg.includes('timed out') ||
        msg.includes('หมดเวลา') ||
        msg.includes('econnrefused') ||
        msg.includes('etimedout') ||
        msg.includes('econnreset') ||
        msg.includes('ehostunreach') ||
        msg.includes('enetunreach') ||
        msg.includes('epipe') ||
        msg.includes('closed') ||
        msg.includes('disconnect') ||
        ['ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE'].includes(code)
    );
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
            resendKey:         String(process.env.RESEND_API_KEY       || smtp.resendKey         || '').trim(),
            brevoKey:          String(process.env.BREVO_API_KEY         || smtp.brevoKey          || '').trim(),
            sendgridKey:       String(process.env.SENDGRID_API_KEY      || smtp.sendgridKey       || '').trim(),
            mailjetKey:        String(process.env.MAILJET_API_KEY       || smtp.mailjetKey        || '').trim(),
            mailjetSecret:     String(process.env.MAILJET_SECRET_KEY    || smtp.mailjetSecret     || '').trim(),
            gmailClientId:     String(process.env.GMAIL_CLIENT_ID      || smtp.gmailClientId     || '').trim(),
            gmailClientSecret: String(process.env.GMAIL_CLIENT_SECRET  || smtp.gmailClientSecret || '').trim(),
            gmailRefreshToken: String(process.env.GMAIL_REFRESH_TOKEN  || smtp.gmailRefreshToken || '').trim(),
            gmailUser:         String(process.env.GMAIL_USER           || smtp.gmailUser         || process.env.SMTP_USER || smtp.user || '').trim(),
        };
    }

    /**
     * Check if real mail sending is configured
     */
    isConfigured(config) {
        return !!(
            config.brevoKey ||
            config.resendKey ||
            config.sendgridKey ||
            (config.mailjetKey && config.mailjetSecret) ||
            (config.gmailClientId && config.gmailClientSecret && config.gmailRefreshToken) ||
            (config.host && config.user && config.pass)
        );
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
            let isSettled = false;

            const safeReject = (err) => {
                if (isSettled) return;
                isSettled = true;
                clearTimeout(timer);
                try { socket.destroy(); } catch (_) {}
                const errorObj = err instanceof Error ? err : new Error(String(err?.message || err?.code || err || 'SMTP TLS Socket Error'));
                if (err && err.code) errorObj.code = err.code;
                reject(errorObj);
            };

            const safeResolve = (val) => {
                if (isSettled) return;
                isSettled = true;
                clearTimeout(timer);
                try { socket.end(); } catch (_) {}
                resolve(val);
            };

            const socket = tls.connect({
                host: config.host,
                port: config.port || 465,
                servername: config.host,
                family: 4, // Force IPv4 to prevent hanging on cloud Docker IPv6 blackholes
                rejectUnauthorized: false
            });

            let buffer = '';
            let step = 0;
            const { fromEmail, cleanFrom } = this.resolveSender(config);

            const timer = setTimeout(() => {
                safeReject(new Error(`SMTP SSL (Port ${config.port || 465}) Connection Timeout (เชื่อมต่อหมดเวลาหลังจาก 15 วินาที)`));
            }, timeoutMs);

            const sendLine = (line) => {
                if (isSettled || socket.destroyed) return;
                socket.write(line + '\r\n');
            };

            socket.on('data', (chunk) => {
                if (isSettled) return;
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
                            safeResolve({ success: true, method: 'smtp-tls-465' });
                        } else if (code === 535) {
                            safeReject(new Error(`SMTP Authentication Failed (535): รหัสผ่านหรือชื่อผู้ใช้ไม่ถูกต้อง หากใช้ Gmail ต้องเปิด 2-Step Verification และสร้าง App Password 16 หลักจาก Google Account (${line})`));
                        } else if (code >= 400) {
                            safeReject(new Error(`SMTP Error [${code}]: ${line}`));
                        }
                    } catch (err) {
                        safeReject(err);
                    }
                }
            });

            socket.on('error', (err) => {
                safeReject(err);
            });

            socket.on('close', (hadError) => {
                if (!isSettled) {
                    safeReject(new Error(`การเชื่อมต่อกับ SMTP Server (${config.host}:${config.port || 465}) ถูกปิดก่อนส่งสำเร็จ (Socket closed by server, hadError=${hadError})`));
                }
            });

            socket.on('end', () => {
                if (!isSettled && step < 9) {
                    safeReject(new Error(`เซิร์ฟเวอร์ SMTP (${config.host}:${config.port || 465}) ยุติการเชื่อมต่อ (FIN received before completion)`));
                }
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
            let isSettled = false;

            const cleanup = () => {
                if (timer) clearTimeout(timer);
                if (activeSocket && !activeSocket.destroyed) {
                    try { activeSocket.destroy(); } catch (e) {}
                }
            };

            const safeReject = (err) => {
                if (isSettled) return;
                isSettled = true;
                cleanup();
                const errorObj = err instanceof Error ? err : new Error(String(err?.message || err?.code || err || 'SMTP STARTTLS Socket Error'));
                if (err && err.code) errorObj.code = err.code;
                reject(errorObj);
            };

            const safeResolve = (val) => {
                if (isSettled) return;
                isSettled = true;
                if (timer) clearTimeout(timer);
                if (activeSocket && !activeSocket.destroyed) {
                    try { activeSocket.end(); } catch (e) {}
                }
                resolve(val);
            };

            timer = setTimeout(() => {
                safeReject(new Error(`SMTP STARTTLS (Port ${config.port || 587}) Connection Timeout (เชื่อมต่อหมดเวลาหลังจาก 15 วินาที)`));
            }, timeoutMs);

            const { fromEmail, cleanFrom } = this.resolveSender(config);
            const plainSocket = net.connect({
                host: config.host,
                port: config.port || 587,
                family: 4 // Force IPv4
            });
            activeSocket = plainSocket;

            let buffer = '';
            let phase = 'INIT';

            const sendLine = (sock, line) => {
                if (isSettled || !sock || sock.destroyed) return;
                sock.write(line + '\r\n');
            };

            const handleData = (sock, chunk) => {
                if (isSettled) return;
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
                            plainSocket.removeAllListeners('close');
                            plainSocket.removeAllListeners('end');

                            const tlsSocket = tls.connect({
                                socket: plainSocket,
                                host: config.host,
                                servername: config.host,
                                family: 4,
                                rejectUnauthorized: false
                            }, () => {
                                phase = 'EHLO2';
                                activeSocket = tlsSocket;
                                sendLine(tlsSocket, 'EHLO localhost');
                            });

                            activeSocket = tlsSocket;
                            tlsSocket.on('data', (c) => handleData(tlsSocket, c));
                            tlsSocket.on('error', (err) => safeReject(err));
                            tlsSocket.on('close', (hadError) => {
                                if (!isSettled) {
                                    safeReject(new Error(`การเชื่อมต่อ SMTP STARTTLS ถูกปิดก่อนส่งสำเร็จ (hadError=${hadError})`));
                                }
                            });
                            tlsSocket.on('end', () => {
                                if (!isSettled && phase !== 'QUIT') {
                                    safeReject(new Error('เซิร์ฟเวอร์ SMTP STARTTLS ยุติการเชื่อมต่อ (FIN received)'));
                                }
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
                            safeResolve({ success: true, method: 'smtp-starttls-587' });
                        } else if (code === 535) {
                            safeReject(new Error(`SMTP Authentication Failed (535): รหัสผ่านหรือชื่อผู้ใช้ไม่ถูกต้อง หากใช้ Gmail ต้องเปิด 2-Step Verification และสร้าง App Password 16 หลักจาก Google Account (${line})`));
                        } else if (code >= 400) {
                            safeReject(new Error(`SMTP STARTTLS Error [${code}]: ${line}`));
                        }
                    } catch (err) {
                        safeReject(err);
                    }
                }
            };

            plainSocket.on('data', (c) => handleData(plainSocket, c));
            plainSocket.on('error', (err) => safeReject(err));
            plainSocket.on('close', (hadError) => {
                if (!isSettled && phase !== 'UPGRADING' && phase !== 'QUIT') {
                    safeReject(new Error(`การเชื่อมต่อเน็ตเวิร์ก Port ${config.port || 587} ถูกปิด (hadError=${hadError})`));
                }
            });
            plainSocket.on('end', () => {
                if (!isSettled && phase !== 'UPGRADING' && phase !== 'QUIT') {
                    safeReject(new Error('เซิร์ฟเวอร์ SMTP ยุติการเชื่อมต่อ (FIN received)'));
                }
            });
        });
    }

    /**
     * Send email via SMTP with intelligent Port 465 / 587 routing & fallback
     */
    async sendEmailViaSmtp(config, { to, subject, html }) {
        const isGmail = config.host.includes('gmail') || config.host.includes('google');

        if (config.port === 587) {
            try {
                return await this.sendViaSmtpStarttls(config, { to, subject, html });
            } catch (err) {
                // If 587 failed and host is Gmail, attempt 465 fallback
                if (isConnectionIssue(err) && isGmail) {
                    console.log('[MAIL] Port 587 STARTTLS connection issue, attempting automatic fallback to Port 465 SSL...');
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
            if (isConnectionIssue(err) && isGmail) {
                console.log('[MAIL] Port 465 SSL connection issue, attempting automatic fallback to Port 587 STARTTLS...');
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
     * Send email via Brevo (Sendinblue) REST API (HTTPS Port 443)
     */
    async sendViaBrevo(config, { to, subject, html }) {
        const { fromEmail, cleanFrom } = this.resolveSender(config);
        const senderName = cleanFrom && cleanFrom.includes('<')
            ? cleanFrom.split('<')[0].trim()
            : 'Supinkly.AI';

        const payload = {
            sender: {
                name: senderName || 'Supinkly.AI',
                email: fromEmail || config.user || 'no-reply@supinkly.ai'
            },
            to: [{ email: to }],
            subject: subject,
            htmlContent: html
        };

        const res = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'api-key': config.brevoKey,
                'content-type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.message || `Brevo API error ${res.status}`);
        }
        return { success: true, method: 'brevo', messageId: data.messageId };
    }

    /**
     * Send email via SendGrid REST API (HTTPS Port 443) — free 100 emails/day
     * สมัครฟรีที่ https://sendgrid.com → Settings → API Keys
     */
    async sendViaSendGrid(config, { to, subject, html }) {
        const { fromEmail, cleanFrom } = this.resolveSender(config);
        const senderName = cleanFrom && cleanFrom.includes('<')
            ? cleanFrom.split('<')[0].trim()
            : 'Supinkly.AI';

        const payload = {
            personalizations: [{ to: [{ email: to }] }],
            from: { email: fromEmail || config.user || 'no-reply@supinkly.ai', name: senderName || 'Supinkly.AI' },
            subject: subject,
            content: [{ type: 'text/html', value: html }]
        };

        const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${config.sendgridKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        // SendGrid returns 202 Accepted on success (no body)
        if (res.status === 202 || res.status === 200) {
            return { success: true, method: 'sendgrid', messageId: res.headers.get('x-message-id') || 'sent' };
        }
        const errData = await res.json().catch(() => ({}));
        const errMsg = (errData.errors && errData.errors[0] && errData.errors[0].message) || `SendGrid API error ${res.status}`;
        throw new Error(errMsg);
    }

    /**
     * Send email via Mailjet REST API (HTTPS Port 443) — free 200 emails/day
     * สมัครฟรีที่ https://app.mailjet.com → Account → Master API Key & Sub API key management
     */
    async sendViaMailjet(config, { to, subject, html }) {
        const { fromEmail, cleanFrom } = this.resolveSender(config);
        const senderName = cleanFrom && cleanFrom.includes('<')
            ? cleanFrom.split('<')[0].trim()
            : 'Supinkly.AI';

        const payload = {
            Messages: [{
                From: {
                    Email: fromEmail || config.user || 'no-reply@supinkly.ai',
                    Name: senderName || 'Supinkly.AI'
                },
                To: [{ Email: to }],
                Subject: subject,
                HTMLPart: html
            }]
        };

        const credentials = Buffer.from(`${config.mailjetKey}:${config.mailjetSecret}`).toString('base64');
        const res = await fetch('https://api.mailjet.com/v3.1/send', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${credentials}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            const errMsg = (data.ErrorMessage) || (data.Messages && data.Messages[0] && data.Messages[0].Errors && data.Messages[0].Errors[0] && data.Messages[0].Errors[0].ErrorMessage) || `Mailjet API error ${res.status}`;
            throw new Error(errMsg);
        }
        const msgId = data.Messages && data.Messages[0] && data.Messages[0].To && data.Messages[0].To[0] && data.Messages[0].To[0].MessageID;
        return { success: true, method: 'mailjet', messageId: String(msgId || 'sent') };
    }

    /**
     * Send email via Gmail REST API (OAuth2) — uses HTTPS Port 443, works on Render Free!
     * ใช้ Gmail จริง ส่งจาก Gmail ของคุณ โดยไม่ต้องใช้ SMTP port
     *
     * Setup (ทำครั้งเดียว):
     * 1. ไป https://console.cloud.google.com → New Project
     * 2. API & Services → Enable APIs → Gmail API → Enable
     * 3. OAuth consent screen → External → กรอกชื่อแอป → Save
     * 4. Credentials → Create Credentials → OAuth 2.0 Client ID → Web Application
     *    - Authorized redirect URIs: https://developers.google.com/oauthplayground
     * 5. Copy Client ID และ Client Secret
     * 6. ไป https://developers.google.com/oauthplayground
     *    - คลิก ⚙️ → ติ๊ก "Use your own OAuth credentials" → ใส่ Client ID + Secret
     *    - Step 1: เลือก "Gmail API v1" → "https://mail.google.com/" → Authorize APIs
     *    - Step 2: Exchange authorization code for tokens → Copy "Refresh token"
     */
    async sendViaGmailApi(config, { to, subject, html }) {
        const { gmailClientId, gmailClientSecret, gmailRefreshToken, gmailUser } = config;

        // 1. Get fresh access token using refresh token
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id:     gmailClientId,
                client_secret: gmailClientSecret,
                refresh_token: gmailRefreshToken,
                grant_type:    'refresh_token'
            }).toString()
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
            const errMsg = tokenData.error_description || tokenData.error || `Token error ${tokenRes.status}`;
            throw new Error(`Gmail OAuth token ไม่ถูกต้อง: ${errMsg}`);
        }
        const accessToken = tokenData.access_token;

        // 2. Build RFC 2822 email message
        const fromName = 'Supinkly.AI';
        const fromAddr = sanitizeHeader(gmailUser);
        const emailLines = [
            `From: ${fromName} <${fromAddr}>`,
            `To: ${sanitizeHeader(to)}`,
            `Subject: =?UTF-8?B?${Buffer.from(sanitizeHeader(subject)).toString('base64')}?=`,
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
            'Content-Transfer-Encoding: base64',
            '',
            // RFC 2045: base64 lines must be <= 76 chars
            Buffer.from(html).toString('base64').replace(/.{76}/g, '$&\r\n')
        ];
        const rawEmail = emailLines.join('\r\n');
        // base64url encode (replace +→-, /→_, remove =)
        const encodedEmail = Buffer.from(rawEmail)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        // 3. Send via Gmail API
        const sendRes = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/send`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ raw: encodedEmail })
        });

        const sendData = await sendRes.json().catch(() => ({}));
        if (!sendRes.ok) {
            const errMsg = (sendData.error && sendData.error.message) || `Gmail API error ${sendRes.status}`;
            throw new Error(errMsg);
        }
        return { success: true, method: 'gmail-api', messageId: sendData.id || 'sent' };
    }

    /**
     * Dispatch OTP Email to user (handles Brevo, Resend, SMTP, and graceful Dev/Console fallback)
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

        // 1. Try Brevo HTTP API if configured (HTTPS Port 443)
        if (config.brevoKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลผ่าน Brevo API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaBrevo(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน Brevo สำเร็จ MessageID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'brevo' };
            } catch (err) {
                console.error('[MAIL] Brevo failed, trying fallback:', err.message);
                lastError = err.message;
            }
        }

        // 2. Try Resend HTTP API if configured (HTTPS Port 443)
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

        // 3. Try SendGrid HTTP API if configured (HTTPS Port 443) — free 100/day
        if (config.sendgridKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลผ่าน SendGrid API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaSendGrid(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน SendGrid สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'sendgrid' };
            } catch (err) {
                console.error('[MAIL] SendGrid failed, trying fallback:', err.message);
                lastError = err.message;
            }
        }

        // 4. Try Mailjet HTTP API if configured (HTTPS Port 443) — free 200/day
        if (config.mailjetKey && config.mailjetSecret) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลผ่าน Mailjet API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaMailjet(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน Mailjet สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'mailjet' };
            } catch (err) {
                console.error('[MAIL] Mailjet failed, trying SMTP fallback:', err.message);
                lastError = err.message;
            }
        }

        // 5. Try Gmail API (OAuth2, HTTPS Port 443 – works on Render Free)
        if (config.gmailClientId && config.gmailClientSecret && config.gmailRefreshToken) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลผ่าน Gmail API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaGmailApi(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน Gmail API สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'gmail-api' };
            } catch (err) {
                console.error('[MAIL] Gmail API failed, trying SMTP fallback:', err.message);
                lastError = err.message;
            }
        }

        // 5. Try SMTP if configured
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

        // 1. Try Brevo HTTP API if configured (works on Render Free – uses HTTPS Port 443)
        if (config.brevoKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Brevo ไปยัง: ${toEmail}...`);
                const res = await this.sendViaBrevo(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Brevo สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'brevo' };
            } catch (err) {
                console.error('[MAIL] Brevo failed, trying Resend fallback:', err.message);
                lastError = err.message;
            }
        }

        // 2. Try Resend HTTP API if configured
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

        // 3. Try SendGrid HTTP API if configured (HTTPS Port 443)
        if (config.sendgridKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลรีเซ็ตรหัสผ่านผ่าน SendGrid ไปยัง: ${toEmail}...`);
                const res = await this.sendViaSendGrid(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน SendGrid สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'sendgrid' };
            } catch (err) {
                console.error('[MAIL] SendGrid failed:', err.message);
                lastError = err.message;
            }
        }

        // 4. Try Mailjet HTTP API if configured (HTTPS Port 443)
        if (config.mailjetKey && config.mailjetSecret) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Mailjet ไปยัง: ${toEmail}...`);
                const res = await this.sendViaMailjet(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Mailjet สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'mailjet' };
            } catch (err) {
                console.error('[MAIL] Mailjet failed:', err.message);
                lastError = err.message;
            }
        }

        // 5. Try Gmail API (OAuth2, HTTPS Port 443 – works on Render Free)
        if (config.gmailClientId && config.gmailClientSecret && config.gmailRefreshToken) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Gmail API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaGmailApi(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Gmail API สำเร็จ ID: ${res.messageId}`);
                return { success: true, delivered: true, method: 'gmail-api' };
            } catch (err) {
                console.error('[MAIL] Gmail API failed, trying SMTP fallback:', err.message);
                lastError = err.message;
            }
        }

        // 5. Try SMTP if configured
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
        const config = { ...base };
        if (customConfig && typeof customConfig === 'object') {
            for (const [k, v] of Object.entries(customConfig)) {
                if (v !== undefined && v !== null && v !== '') {
                    config[k] = v;
                }
            }
        }

        config.pass = String(config.pass || '').replace(/\s+/g, '');
        config.user = String(config.user || '').trim();
        config.host = String(config.host || '').trim();
        config.port = parseInt(config.port || '465', 10);
        config.resendKey = String(config.resendKey || '').trim();
        config.brevoKey = String(config.brevoKey || '').trim();
        config.from = String(config.from || '').trim();

        if (!this.isConfigured(config)) {
            return {
                success: false,
                message: 'ยังไม่ได้ระบุข้อมูลสำหรับส่งอีเมล กรุณาระบุ Gmail API (OAuth), Brevo API Key, Resend API Key หรือ SMTP (Host, User, App Password 16 หลัก)'
            };
        }

        const to = (testRecipient || config.gmailUser || config.user || '').trim();
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
                    • <strong>ระบบที่ใช้:</strong> ${config.brevoKey ? 'Brevo HTTP API' : config.resendKey ? 'Resend HTTP API' : (config.gmailClientId && config.gmailRefreshToken) ? 'Gmail API' : `SMTP Server (${config.host}:${config.port})`}
                </div>
                <p style="font-size:12px; color:#64748B; line-height:1.5; margin:0;">
                    ระบบ OTP สำหรับการยืนยันตัวตนสมาชิก และการตั้งรหัสผ่านใหม่ พร้อมส่งมอบถึงลูกค้าจริงทุกคนแล้ว
                </p>
            </div>
        `;

        const errors = [];

        // 1. Try Brevo if configured (HTTPS Port 443 – works on Render Free)
        if (config.brevoKey) {
            try {
                console.log(`[MAIL-TEST] กำลังทดสอบส่งผ่าน Brevo ไปยัง: ${to}...`);
                const res = await this.sendViaBrevo(config, { to, subject: testSubject, html: testHtml });
                return {
                    success: true,
                    method: 'Brevo API',
                    recipient: to,
                    message: `ส่งอีเมลทดสอบผ่าน Brevo API สำเร็จแล้ว (ID: ${res.messageId}) กรุณาตรวจสอบกล่องจดหมาย ${to} (และโฟลเดอร์สแปม)`
                };
            } catch (err) {
                console.error('[MAIL-TEST] Brevo test error:', err);
                let errText = (err && (err.message || String(err))) || 'Brevo error';
                errors.push(`[Brevo]: ${errText}`);
            }
        }

        // 2. Try Resend if configured
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
                console.error('[MAIL-TEST] Resend test error:', err);
                let errText = (err && (err.message || String(err))) || 'Resend error';
                if (errText.includes('validation_error') || errText.includes('only send testing emails')) {
                    errText = 'Resend ไม่อนุญาตให้ส่ง: ในโหมดฟรี Resend อนุญาตให้ส่งได้เฉพาะอีเมลที่คุณใช้สมัครบัญชี Resend เท่านั้น';
                }
                errors.push(`[Resend]: ${errText}`);
            }
        }

        // 3. Try SendGrid if configured
        if (config.sendgridKey) {
            try {
                console.log(`[MAIL-TEST] กำลังทดสอบส่งผ่าน SendGrid ไปยัง: ${to}...`);
                const res = await this.sendViaSendGrid(config, { to, subject: testSubject, html: testHtml });
                return {
                    success: true,
                    method: 'SendGrid API',
                    recipient: to,
                    message: `ส่งอีเมลทดสอบผ่าน SendGrid API สำเร็จแล้ว (ID: ${res.messageId}) กรุณาตรวจสอบกล่องจดหมาย ${to} (และโฟลเดอร์สแปม)`
                };
            } catch (err) {
                console.error('[MAIL-TEST] SendGrid test error:', err);
                let errText = (err && (err.message || String(err))) || 'SendGrid error';
                errors.push(`[SendGrid]: ${errText}`);
            }
        }

        // 4. Try Mailjet if configured
        if (config.mailjetKey && config.mailjetSecret) {
            try {
                console.log(`[MAIL-TEST] กำลังทดสอบส่งผ่าน Mailjet ไปยัง: ${to}...`);
                const res = await this.sendViaMailjet(config, { to, subject: testSubject, html: testHtml });
                return {
                    success: true,
                    method: 'Mailjet API',
                    recipient: to,
                    message: `ส่งอีเมลทดสอบผ่าน Mailjet API สำเร็จแล้ว (ID: ${res.messageId}) กรุณาตรวจสอบกล่องจดหมาย ${to} (และโฟลเดอร์สแปม)`
                };
            } catch (err) {
                console.error('[MAIL-TEST] Mailjet test error:', err);
                let errText = (err && (err.message || String(err))) || 'Mailjet error';
                errors.push(`[Mailjet]: ${errText}`);
            }
        }

        // 5. Try Gmail API (OAuth2, HTTPS Port 443 – works on Render Free)
        if (config.gmailClientId && config.gmailClientSecret && config.gmailRefreshToken) {
            try {
                console.log(`[MAIL-TEST] กำลังทดสอบส่งผ่าน Gmail API ไปยัง: ${to}...`);
                const res = await this.sendViaGmailApi(config, { to, subject: testSubject, html: testHtml });
                return {
                    success: true,
                    method: 'Gmail API',
                    recipient: to,
                    message: `ส่งอีเมลทดสอบผ่าน Gmail API สำเร็จแล้ว (ID: ${res.messageId}) กรุณาตรวจสอบกล่องจดหมาย ${to} (และโฟลเดอร์สแปม)`
                };
            } catch (err) {
                console.error('[MAIL-TEST] Gmail API test error:', err);
                errors.push(`[Gmail API]: ${(err && err.message) || String(err)}`);
            }
        }

        // 5. Try SMTP if configured
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
                console.error('[MAIL-TEST] SMTP test error:', err);
                const rawMsg = (err && (err.message || (typeof err === 'string' ? err : ''))) || '';
                const errCode = (err && err.code) || '';
                const combined = `${rawMsg} ${errCode}`.trim();

                let msg = '';
                if (combined.includes('535') || combined.includes('BadCredentials') || combined.includes('Username and Password not accepted')) {
                    msg = `รหัสผ่านหรือผู้ใช้ไม่ถูกต้อง (535 Bad Credentials):\n• หากใช้ Gmail ต้องเปิด 2-Step Verification และสร้าง "App Password (รหัสผ่านสำหรับแอป 16 หลัก)" จาก Google Account (myaccount.google.com/apppasswords)\n• ห้ามใช้รหัสผ่าน Gmail ปกติเด็ดขาด (ระบบตัดช่องว่าง 16 หลักให้อัตโนมัติแล้ว)`;
                } else if (combined.includes('534') || combined.includes('Application-specific password required')) {
                    msg = `Google แจ้งเตือนความปลอดภัย (534):\nต้องสร้าง "App Password 16 หลัก" ในบัญชี Google (เปิด 2-Step Verification แล้วไปที่ myaccount.google.com/apppasswords)`;
                } else if (isConnectionIssue(err) || combined.includes('timeout') || combined.includes('ETIMEDOUT') || combined.includes('หมดเวลา')) {
                    msg = `หมดเวลาเชื่อมต่อ (Connection Timeout / Blocked):\nเซิร์ฟเวอร์ไม่สามารถติดต่อ ${config.host}:${config.port} ได้ (เซิร์ฟเวอร์โฮสติ้ง Render อาจมีการจำกัดพอร์ต SMTP ขาออก)\n👉 แนะนำให้กดปุ่มเปลี่ยนพรีเซ็ตเป็น "Gmail (Port 587 STARTTLS)" หรือ "Port 465 SSL"\n👉 หรือใช้ Resend API (ส่งผ่าน HTTPS Port 443 รับประกันส่งได้ 100%)`;
                } else if (combined.includes('ECONNREFUSED')) {
                    msg = `การเชื่อมต่อถูกปฏิเสธ (Connection Refused):\nพอร์ต ${config.port} บน ${config.host} ปิดอยู่หรือไม่สามารถเข้าถึงได้ แนะนำให้ลองเปลี่ยนเป็น Port 587 หรือใช้ Resend API`;
                } else if (combined.includes('ECONNRESET') || combined.includes('closed') || combined.includes('Closed by')) {
                    msg = `การเชื่อมต่อถูกตัดกลางคัน (Connection Reset):\nเซิร์ฟเวอร์ตัดสายการเชื่อมต่อ แนะนำให้ลองสลับ Port (465 <-> 587) หรือใช้ Resend API`;
                } else {
                    msg = rawMsg || (errCode ? `Network Socket Error [${errCode}]` : '') || (err ? String(err) : '') || 'การเชื่อมต่อกับเซิร์ฟเวอร์ส่งอีเมลล้มเหลว';
                }
                errors.push(`[SMTP]: ${msg}`);
            }
        }

        return {
            success: false,
            message: errors.join('\n\n') || 'ไม่สามารถส่งอีเมลได้ กรุณาตรวจสอบการตั้งค่า'
        };
    }
}

module.exports = new MailService();
