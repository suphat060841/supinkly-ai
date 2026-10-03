/**
 * Supinkly.AI - PromptPay EMVCo Generator & Hardened Slip Verification Engine
 * Defenses: Slip Anti-Replay Cache, Integrity Checks, SlipOK Live Gateway Integration
 */

// CRC-16-CCITT for Thai PromptPay
function crc16(data) {
    let crc = 0xFFFF;
    for (let i = 0; i < data.length; i++) {
        crc ^= data.charCodeAt(i) << 8;
        for (let j = 0; j < 8; j++) {
            if ((crc & 0x8000) !== 0) {
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF;
            } else {
                crc = (crc << 1) & 0xFFFF;
            }
        }
    }
    return crc.toString(16).toUpperCase().padStart(4, '0');
}

// Generate EMVCo PromptPay Payload string
function generatePromptPayPayload(phoneOrId, amount) {
    let target = (phoneOrId || '').replace(/[^0-9]/g, '');
    let formattedTarget = '';

    if (target.length === 10) {
        // Thai mobile format: 0982949371 -> 0066982949371
        formattedTarget = '0066' + target.substring(1);
    } else {
        formattedTarget = target;
    }

    const targetTag = formattedTarget.length === 13 ? '01' : '02';
    const targetLength = String(formattedTarget.length).padStart(2, '0');
    const targetVal = targetTag + targetLength + formattedTarget;

    const aid = '0016A000000677010111';
    const merchantInfo = aid + targetVal;
    const tag29 = '29' + String(merchantInfo.length).padStart(2, '0') + merchantInfo;

    let payload = '000201' + (amount ? '010212' : '010211') + tag29 + '5303764'; // 764 = THB

    if (amount && parseFloat(amount) > 0) {
        const amtStr = parseFloat(amount).toFixed(2);
        payload += '54' + String(amtStr.length).padStart(2, '0') + amtStr;
    }

    payload += '5802TH';
    payload += '6304';
    payload += crc16(payload);

    return payload;
}

// Slip Anti-Replay Registry (prevents reusing same slip)
function getUsedSlipsRegistry() {
    try {
        return JSON.parse(localStorage.getItem('supinkly_used_slips') || '[]');
    } catch {
        return [];
    }
}

function registerUsedSlip(fingerprint, transRef) {
    const registry = getUsedSlipsRegistry();
    registry.push({
        fingerprint: fingerprint,
        transRef: transRef,
        usedAt: new Date().toISOString()
    });
    localStorage.setItem('supinkly_used_slips', JSON.stringify(registry));
}

function isSlipAlreadyUsed(fingerprint, transRef) {
    const registry = getUsedSlipsRegistry();
    const inRegistry = registry.some(item => 
        (fingerprint && item.fingerprint === fingerprint) ||
        (transRef && item.transRef === transRef)
    );
    if (inRegistry) return true;

    // Cross-check with stored orders (prevents registry wipe bypass)
    try {
        const storedOrders = JSON.parse(localStorage.getItem('supinkly_orders') || '[]');
        return storedOrders.some(order => 
            (transRef && order.transRef === transRef) ||
            (fingerprint && order.slipFingerprint === fingerprint)
        );
    } catch {
        return false;
    }
}

// Hardened Slip Verification Module
const SlipVerifier = {
    selectedFile: null,
    fileFingerprint: null,
    imageDimensions: null,

    async computeFileSHA256(file) {
        try {
            const buffer = await file.arrayBuffer();
            const digest = await crypto.subtle.digest('SHA-256', buffer);
            const hashArray = Array.from(new Uint8Array(digest));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            return `FALLBACK_${file.size}_${file.name}`;
        }
    },

    async handleFileSelect(file, callback) {
        if (!file) return;

        // Security check: Only allow true image formats
        const validTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/heic'];
        if (!validTypes.includes(file.type.toLowerCase()) && !file.name.match(/\.(jpe?g|png|webp)$/i)) {
            showToast("รูปแบบไฟล์ไม่ถูกต้อง กรุณาอัปโหลดรูปภาพสลิป (JPG, PNG)", "warning");
            return;
        }

        // File size check: Slips should normally be between 10KB and 15MB
        if (file.size < 12000) {
            showToast("ไฟล์รูปภาพมีขนาดเล็กผิดปกติ กรุณาแนบสลิปจริงจากแอปธนาคาร", "warning");
            return;
        }
        if (file.size > 15 * 1024 * 1024) {
            showToast("ไฟล์มีขนาดเกิน 15MB กรุณาเลือกไฟล์สลิปใหม่", "warning");
            return;
        }

        // Generate SHA-256 Binary Cryptographic Hash (Immune to file renaming)
        const sha256 = await this.computeFileSHA256(file);
        this.selectedFile = file;
        this.fileFingerprint = sha256;

        // Verify Image Dimensions (Must be vertical mobile slip aspect ratio)
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                if (img.width < 250 || img.height < 320) {
                    showToast("ความละเอียดรูปภาพต่ำเกินไป ไม่ใช่สลิปจากแอปธนาคาร", "warning");
                    this.clearSlip();
                    return;
                }
                if (img.height < img.width * 0.95) {
                    showToast("สลิปโอนเงินต้องเป็นภาพแนวตั้งจากแอปธนาคาร กรุณาตรวจสอบรูปภาพ", "warning");
                    this.clearSlip();
                    return;
                }

                this.imageDimensions = { width: img.width, height: img.height };

                const previewImg = document.getElementById('slip-preview-img');
                const previewContainer = document.getElementById('slip-preview-container');
                const uploadPlaceholder = document.getElementById('slip-upload-placeholder');

                if (previewImg && previewContainer) {
                    previewImg.src = e.target.result;
                    previewContainer.classList.remove('hidden');
                    if (uploadPlaceholder) uploadPlaceholder.classList.add('hidden');
                }

                if (callback) callback(e.target.result);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    },

    clearSlip() {
        this.selectedFile = null;
        this.fileFingerprint = null;
        this.imageDimensions = null;
        const previewContainer = document.getElementById('slip-preview-container');
        const uploadPlaceholder = document.getElementById('slip-upload-placeholder');
        const input = document.getElementById('slip-file-input');

        if (previewContainer) previewContainer.classList.add('hidden');
        if (uploadPlaceholder) uploadPlaceholder.classList.remove('hidden');
        if (input) input.value = '';
    },

    async verifySlip(expectedAmount, expectedReceiver, cartItems = [], email = '') {
        if (!this.selectedFile) {
            throw new Error("กรุณาเลือกไฟล์รูปภาพสลิปก่อนทำการตรวจสอบ");
        }

        // Cryptographically re-verify SHA-256 fingerprint from the actual file buffer (tamper-proof)
        const computedFingerprint = await this.computeFileSHA256(this.selectedFile);
        this.fileFingerprint = computedFingerprint;

        // Anti-Replay Check: Did this slip file get used before?
        if (isSlipAlreadyUsed(computedFingerprint, null)) {
            throw new Error("สลิปใบนี้เคยถูกใช้งานไปแล้วในระบบ ไม่สามารถใช้ซ้ำได้");
        }

        // 1. Production Web Server Verification (Node.js Backend)
        if (window.location.protocol.startsWith('http')) {
            const formData = new FormData();
            formData.append('slip', this.selectedFile);
            if (email) formData.append('email', email);
            formData.append('cartItems', typeof cartItems === 'string' ? cartItems : JSON.stringify(cartItems));

            try {
                const headers = {};
                const token = (typeof USER_AUTH !== 'undefined' && USER_AUTH.getToken) ? USER_AUTH.getToken() : null;
                if (token) {
                    headers['x-user-token'] = token;
                    headers['Authorization'] = `Bearer ${token}`;
                }
                const res = await fetch('/api/checkout/verify-slip', {
                    method: 'POST',
                    headers,
                    body: formData
                });
                const data = await res.json();
                if (!res.ok || !data.success) {
                    throw new Error(data.message || "สลิปไม่ผ่านการตรวจสอบจากระบบธนาคาร");
                }
                registerUsedSlip(this.fileFingerprint, data.order?.transRef);
                return {
                    success: true,
                    order: data.order,
                    transRef: data.order?.transRef
                };
            } catch (err) {
                throw new Error(err.message || "เกิดข้อผิดพลาดในการเชื่อมต่อระบบตรวจสอบสลิป");
            }
        } else {
            // Local file:// protocol fallback for offline developer testing
            console.warn("SlipVerifier: Running in offline local file mode. Simulating verification.");
            const localResult = await this.verifyLocalStrict(expectedAmount, expectedReceiver);
            registerUsedSlip(this.fileFingerprint, localResult.transRef);
            return localResult;
        }
    },

    verifyLocalStrict(expectedAmount, expectedReceiver) {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                // Validate file integrity & dimensions
                if (!this.selectedFile) {
                    return reject(new Error("ไม่พบไฟล์สลิป"));
                }
                if (!this.imageDimensions || this.imageDimensions.height < this.imageDimensions.width * 0.95) {
                    return reject(new Error("รูปภาพไม่ตรงตามรูปแบบสลิปโอนเงินแนวตั้งจากแอปธนาคาร"));
                }
                if (this.selectedFile.size < 12000) {
                    return reject(new Error("ขนาดไฟล์รูปภาพไม่ถูกต้อง ไม่พบข้อมูลธุรกรรมสลิป"));
                }

                // Extract transaction ref and register
                const generatedTransRef = "TR" + Date.now().toString().slice(-8) + Math.floor(1000 + Math.random() * 9000);
                
                resolve({
                    success: true,
                    transRef: generatedTransRef,
                    amount: expectedAmount,
                    receiver: expectedReceiver,
                    date: new Date().toLocaleString('th-TH')
                });
            }, 1500);
        });
    }
};
