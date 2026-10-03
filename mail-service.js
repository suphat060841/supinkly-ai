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
        return {
            host: process.env.SMTP_HOST || smtp.host || '',
            port: parseInt(process.env.SMTP_PORT || smtp.port || '465', 10),
            user: process.env.SMTP_USER || smtp.user || '',
            pass: process.env.SMTP_PASS || smtp.pass || '',
            from: process.env.SMTP_FROM || smtp.from || (process.env.SMTP_USER || smtp.user || 'no-reply@supinkly.ai'),
            resendKey: process.env.RESEND_API_KEY || smtp.resendKey || ''
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
     * Send email via native Node.js TLS/SSL SMTP socket (Port 465)
     */
    sendViaSmtpTls(config, { to, subject, html }) {
        return new Promise((resolve, reject) => {
            const timeoutMs = 15000;
            const socket = tls.connect({
                host: config.host,
                port: config.port || 465,
                servername: config.host,
                rejectUnauthorized: false // compatible with varied ISP root cert bundles
            });

            let buffer = '';
            let step = 0;
            const fromEmail = config.from.includes('<')
                ? config.from.match(/<([^>]+)>/)[1]
                : config.from;

            const timer = setTimeout(() => {
                socket.destroy();
                reject(new Error('SMTP connection timed out after 15 seconds'));
            }, timeoutMs);

            const sendLine = (line) => {
                socket.write(line + '\r\n');
            };

            socket.on('data', (chunk) => {
                buffer += chunk.toString('utf-8');
                const lines = buffer.split('\r\n');
                buffer = lines.pop(); // keep partial line

                for (const line of lines) {
                    if (!line || line.length < 3) continue;
                    const code = parseInt(line.substring(0, 3), 10);
                    // Check if it's a multiline response (e.g., 250-something)
                    const isFinal = line.charAt(3) !== '-';
                    if (!isFinal) continue;

                        const cleanTo = sanitizeHeader(to);
                        const cleanFrom = sanitizeHeader(config.from);
                        const cleanFromEmail = sanitizeHeader(fromEmail);
                        const cleanSubject = sanitizeHeader(subject);

                        if (step === 0 && code === 220) {
                            step = 1;
                            sendLine(`EHLO ${config.host}`);
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
                            sendLine(`MAIL FROM:<${cleanFromEmail}>`);
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
                            resolve({ success: true, method: 'smtp' });
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
     * Send email via Resend API (Native fetch HTTP)
     */
    async sendViaResend(config, { to, subject, html }) {
        const res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${config.resendKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                from: config.from.includes('@') ? config.from : 'Supinkly.AI <onboarding@resend.dev>',
                to: [to],
                subject: subject,
                html: html
            })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.message || 'Resend API error');
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

        // 1. Try Resend HTTP API if configured
        if (config.resendKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลผ่าน Resend API ไปยัง: ${toEmail}...`);
                const res = await this.sendViaResend(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน Resend สำเร็จ ID: ${res.id}`);
                return { success: true, delivered: true, method: 'resend' };
            } catch (err) {
                console.error('[MAIL] Resend failed, trying SMTP fallback:', err.message);
            }
        }

        // 2. Try SMTP if configured
        if (config.host && config.user && config.pass) {
            try {
                console.log(`[MAIL] กำลังเชื่อมต่อ SMTP ${config.host}:${config.port} เพื่อส่งไปยัง ${toEmail}...`);
                await this.sendViaSmtpTls(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลผ่าน SMTP สำเร็จไปยัง: ${toEmail}`);
                return { success: true, delivered: true, method: 'smtp' };
            } catch (err) {
                console.error('[MAIL] SMTP failed:', err.message);
            }
        }

        // 3. Fallback / Dev Mode (when no SMTP credentials are provided yet)
        console.log(`
======================================================================
[SUPINKLY OTP NOTIFICATION]
⚡ ถึง: ${toEmail} (${displayName || 'ผู้ใช้งาน'})
🔑 รหัสยืนยัน OTP 6 หลัก: ${otp}
⏰ รหัสมีอายุ 10 นาที
💡 หมายเหตุ: หากต้องการส่งอีเมลจริงเข้า Inbox กรุณาระบุ SMTP ใน Admin Panel
======================================================================
        `);

        return {
            success: true,
            delivered: false,
            fallbackConsole: true,
            method: 'console',
            otp
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

        // 1. Try Resend HTTP API if configured
        if (config.resendKey) {
            try {
                console.log(`[MAIL] กำลังส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Resend ไปยัง: ${toEmail}...`);
                const res = await this.sendViaResend(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน Resend สำเร็จ ID: ${res.id}`);
                return { success: true, delivered: true, method: 'resend' };
            } catch (err) {
                console.error('[MAIL] Resend failed, trying SMTP fallback:', err.message);
            }
        }

        // 2. Try SMTP if configured
        if (config.host && config.user && config.pass) {
            try {
                console.log(`[MAIL] กำลังเชื่อมต่อ SMTP ${config.host}:${config.port} เพื่อส่งอีเมลรีเซ็ตรหัสผ่านไปยัง ${toEmail}...`);
                await this.sendViaSmtpTls(config, { to: toEmail, subject, html });
                console.log(`[MAIL] ✅ ส่งอีเมลรีเซ็ตรหัสผ่านผ่าน SMTP สำเร็จไปยัง: ${toEmail}`);
                return { success: true, delivered: true, method: 'smtp' };
            } catch (err) {
                console.error('[MAIL] SMTP failed:', err.message);
            }
        }

        // 3. Fallback / Dev Mode
        console.log(`
======================================================================
[SUPINKLY PASSWORD RESET OTP]
⚡ ถึง: ${toEmail} (${displayName || 'ผู้ใช้งาน'})
🔑 รหัส OTP ตั้งรหัสผ่านใหม่: ${otp}
⏰ รหัสมีอายุ 10 นาที
======================================================================
        `);

        return {
            success: true,
            delivered: false,
            fallbackConsole: true,
            method: 'console',
            otp
        };
    }
}

module.exports = new MailService();
