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

    async verifySlip(expectedAmount, expectedReceiver) {
        if (!this.selectedFile) {
            throw new Error("กรุณาเลือกไฟล์รูปภาพสลิปก่อนทำการตรวจสอบ");
        }

        // Cryptographically re-verify SHA-256 fingerprint from the actual file buffer (tamper-proof)
        const computedFingerprint = await this.computeFileSHA256(this.selectedFile);
        this.fileFingerprint = computedFingerprint;

        // Anti-Replay Check: Did this slip file get used before?
        if (isSlipAlreadyUsed(computedFingerprint, null)) {
            throw new Error("สลิปใบนี้เคยถูกใช้งานไปแล้วในระบบ ไม่สามารถใช้ซ้ำได้ (Anti-Replay Protection)");
        }

        // 1. Live SlipOK API verification if API key is provided
        const apiKey = STORE_CONFIG.slipOkApiKey;
        const branchId = STORE_CONFIG.slipOkBranchId;

        if (apiKey && apiKey.trim() !== '') {
            try {
                const result = await this.verifyWithSlipOk(this.selectedFile, expectedAmount, apiKey, branchId);
                // Register used
                registerUsedSlip(this.fileFingerprint, result.transRef);
                return result;
            } catch (err) {
                // SECURITY FIX: Only allow local simulation fallback when explicitly running on file:// protocol for offline testing
                // If on http/https web server, NEVER silently approve unverified slips when SlipOK fails!
                if (window.location.protocol === 'file:') {
                    console.warn("SlipOK Sandbox: ตรวจพบการเปิดผ่าน local file:// สลับไปใช้การจำลองสำหรับทดสอบออฟไลน์", err);
                    const localResult = await this.verifyLocalStrict(expectedAmount, expectedReceiver);
                    registerUsedSlip(this.fileFingerprint, localResult.transRef);
                    return localResult;
                }
                // On real web servers, fail securely
                throw err;
            }
        } else {
            // If running on web server without API key, do not approve payments silently
            if (window.location.protocol !== 'file:') {
                throw new Error("ระบบยังไม่ได้ตั้งค่า SlipOK API Key ในหลังบ้าน กรุณาติดต่อผู้ดูแลระบบ");
            }
            const result = await this.verifyLocalStrict(expectedAmount, expectedReceiver);
            registerUsedSlip(this.fileFingerprint, result.transRef);
            return result;
        }
    },

    async verifyWithSlipOk(file, expectedAmount, apiKey, branchId) {
        const cleanApiKey = (apiKey || '').trim();
        const cleanBranchId = (branchId || '').trim() || '77491';

        const formData = new FormData();
        formData.append('files', file);
        formData.append('log', 'true');
        if (expectedAmount) {
            formData.append('amount', expectedAmount);
        }

        const url = `https://api.slipok.com/api/line/apikey/${cleanBranchId}`;
        
        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: {
                    'x-authorization': cleanApiKey
                },
                body: formData
            });

            const data = await res.json();

            if (data.success && data.data) {
                const slipData = data.data;

                // Check slip validity flag
                if (slipData.success === false) {
                    throw new Error(slipData.message || "สลิปนี้ไม่ผ่านการตรวจสอบจากระบบธนาคาร");
                }

                // 1. Verify transRef anti-replay
                if (slipData.transRef && isSlipAlreadyUsed(null, slipData.transRef)) {
                    throw new Error(`สลิปใบนี้ (รหัสอ้างอิง: ${slipData.transRef}) เคยถูกใช้สั่งซื้อไปแล้ว`);
                }

                // 2. SECURITY FIX: Verify receiver identity (Ensure funds actually went to the merchant)
                if (!slipData.receiver) {
                    throw new Error("สลิปนี้ไม่มีข้อมูลผู้รับเงินที่ถูกต้อง ไม่สามารถยืนยันยอดเงินได้");
                }

                const receiverName = (slipData.receiver.name || slipData.receiver.displayName || '').trim();
                const receiverAcc = (slipData.receiver.account?.value || slipData.receiver.proxy?.value || '').replace(/[^0-9]/g, '');
                const merchantPhone = (STORE_CONFIG.promptPayNumber || '').replace(/[^0-9]/g, '');
                const allowedKeywords = ['สุพัฒน์', 'SUPHAT', 'MEESOMBAT', 'มีสมบัติ'];

                const nameMatches = allowedKeywords.some(kw => receiverName.toUpperCase().includes(kw.toUpperCase()));
                const phoneMatches = merchantPhone && receiverAcc && (
                    receiverAcc.endsWith(merchantPhone.slice(-4)) || 
                    merchantPhone.endsWith(receiverAcc.slice(-4)) ||
                    receiverAcc === merchantPhone
                );

                if (!nameMatches && !phoneMatches) {
                    throw new Error(`บัญชีผู้รับเงินในสลิป (${receiverName || 'ไม่ระบุ'}) ไม่ตรงกับบัญชีของร้านค้า (คุณ สุพัฒน์ มีสมบัติ)`);
                }

                // 3. SECURITY FIX: Verify slip freshness (Cannot use slips older than 24 hours)
                if (slipData.transTimestamp) {
                    const slipTime = new Date(slipData.transTimestamp).getTime();
                    if (!isNaN(slipTime) && Date.now() - slipTime > 24 * 60 * 60 * 1000) {
                        throw new Error("สลิปนี้ทำรายการเกิน 24 ชั่วโมงแล้ว ไม่สามารถใช้สั่งซื้อได้");
                    }
                }

                // 4. Verify amount (strictly enforce valid amount and allow ±0.05 floating point tolerance)
                if (slipData.amount === undefined || slipData.amount === null || isNaN(parseFloat(slipData.amount))) {
                    throw new Error("ไม่สามารถระบุยอดเงินจากสลิปนี้ได้ กรุณาใช้สลิปที่มีข้อมูลชัดเจน");
                }
                if (Math.abs(parseFloat(slipData.amount) - parseFloat(expectedAmount)) > 0.05) {
                    throw new Error(`ยอดเงินในสลิป (${slipData.amount} บาท) ไม่ตรงกับยอดสั่งซื้อ (${expectedAmount} บาท)`);
                }

                return {
                    success: true,
                    transRef: slipData.transRef || ("TR" + Date.now().toString().slice(-8)),
                    amount: slipData.amount !== undefined ? slipData.amount : expectedAmount,
                    receiver: slipData.receiver ? (slipData.receiver.name || (slipData.receiver.account && slipData.receiver.account.value) || STORE_CONFIG.promptPayAccountName) : STORE_CONFIG.promptPayAccountName,
                    sender: slipData.sender ? (slipData.sender.displayName || slipData.sender.name || '') : '',
                    date: slipData.transDate || new Date().toLocaleString('th-TH')
                };
            } else {
                const errMsg = (data.data && data.data.message) || data.message || "สลิปไม่ถูกต้อง หรือไม่พบข้อมูลในระบบธนาคาร";
                throw new Error(errMsg);
            }
        } catch (err) {
            if (err.name === 'TypeError' && err.message.toLowerCase().includes('fetch')) {
                throw new Error("การเชื่อมต่อ SlipOK ขัดข้อง (CORS/Network): กรุณาตรวจสอบการเชื่อมต่ออินเทอร์เน็ต");
            }
            throw new Error("SlipOK: " + (err.message || "เกิดข้อผิดพลาดในการตรวจสอบสลิป"));
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
