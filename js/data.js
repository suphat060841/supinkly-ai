/**
 * Supinkly.AI - Public Product Catalog & Store Configuration
 * SECURED: Sensitive credentials removed from public catalog.
 */

const STORE_CONFIG = (() => {
    const defaults = {
        storeName: "Supinkly.AI Shop",
        promptPayNumber: "0982949371", // เบอร์พร้อมเพย์รับเงิน (ใช้สร้าง QR Code เท่านั้น ไม่แสดงเบอร์หน้าร้าน)
        promptPayAccountName: "สุพัฒน์ มีสมบัติ",
        slipOkBranchId: "77491",
        autoDelivery: true
    };
    try {
        const stored = localStorage.getItem('supinkly_store_config');
        if (stored) {
            const parsed = JSON.parse(stored) || {};
            // Security lockdown: PromptPay account name must always match merchant identity
            parsed.promptPayAccountName = defaults.promptPayAccountName;
            if (!parsed.promptPayNumber || parsed.promptPayNumber.replace(/[^0-9]/g, '').length < 10) {
                parsed.promptPayNumber = defaults.promptPayNumber;
            }
            if (!parsed.slipOkBranchId) parsed.slipOkBranchId = defaults.slipOkBranchId;
            // Purge leaked secrets from browser localStorage
            delete parsed.slipOkApiKey;
            delete parsed.slipOkEndpoint;
            localStorage.setItem('supinkly_store_config', JSON.stringify(parsed));
            return { ...defaults, ...parsed };
        }
    } catch (e) {
        console.warn("Could not read store config from storage:", e);
    }
    return defaults;
})();

// Master Product Catalog (Read-Only Public Metadata - Standard Thai Retail Profitable Prices)
const PRODUCTS = [
    {
        id: "cpc-01",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "บัญชีส่วนตัว 100% ไม่แชร์ใคร • ปลดล็อกเอฟเฟกต์ & 4K ไม่มีลายน้ำ",
        badge: "🔥 ขายดีอันดับ 1",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 89.00,
        originalPrice: 199.00,
        soldCount: 29343,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี CapCut Pro ส่วนตัว 1 เดือน ใช้งานได้ทั้งบน iOS, Android และ PC ไม่แชร์ร่วมกับผู้อื่น เปลี่ยนรหัสผ่านได้ ฟีเจอร์ตัดต่อระดับ Pro ครบทุกฟังก์ชัน ปลดล็อกเอฟเฟกต์ เสียง และ Export 4K ไม่มีลายน้ำ"
    },
    {
        id: "cpc-02",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Pro (1 เดือน) - บัญชีหาร",
        subtitle: "บัญชีหารราคาประหยัด • ปลดล็อกฟังก์ชัน Pro ครบ ใช้งานง่าย ส่งรหัสทันที",
        badge: "คุ้มค่าสุด",
        type: "บัญชีหาร (Shared)",
        typeKey: "shared",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 59.00,
        originalPrice: 129.00,
        soldCount: 1786,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชีหาร CapCut Pro 1 เดือน ราคาประหยัด รองรับมือถือและคอมพิวเตอร์ ฟังก์ชัน Pro ครบ ใช้งานง่าย ส่งรหัสทันที"
    },
    {
        id: "cpc-03",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Team (1 เดือน) - บัญชีทีม",
        subtitle: "แชร์เทมเพลตและพื้นที่ Cloud ร่วมกัน • เหมาะสำหรับทีมงานและสตูดิโอ",
        badge: "สำหรับทีมงาน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 129.00,
        originalPrice: 299.00,
        soldCount: 1243,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "CapCut แผน Team เหมาะสำหรับการทำงานร่วมกัน แชร์เทมเพลต และจัดเก็บไฟล์งานบน Cloud ร่วมกัน"
    },
    {
        id: "cpc-04",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut VIP / SVIP (1 เดือน)",
        subtitle: "สิทธิพิเศษ VIP • ปลดล็อกสต็อกสติกเกอร์และ AI อัตโนมัติ",
        badge: "สิทธิพิเศษ VIP",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 199.00,
        originalPrice: 390.00,
        soldCount: 272,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บริการเปิดสิทธิ์ VIP CapCut สำหรับผู้ที่ต้องการใช้งานสิทธิพิเศษเพิ่มเติม ปลดล็อกสต็อกสติกเกอร์และ AI อัตโนมัติ"
    },
    {
        id: "goo-ai-01",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - ลิงก์เชิญ",
        subtitle: "ลิงก์เปิดสิทธิ์ผูกเข้า Gmail ของคุณโดยตรง • ไม่ต้องแชร์รหัสผ่าน",
        badge: "👑 แนะนำยอดนิยม",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์ (Web/App)",
        price: 99.00,
        originalPrice: 750.00,
        soldCount: 6673,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "ลิงก์เปิดสิทธิ์ Google AI Pro (Gemini Advanced) ผูกเข้ากับบัญชี Google ส่วนตัวของคุณได้ทันที ไม่ต้องให้รหัสผ่าน ใช้งาน Gemini 1.5 Pro / Ultra พร้อมความจุ Google One"
    },
    {
        id: "goo-ai-02",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Ultra (Gemini Ultra 1 เดือน) - บัญชีส่วนตัว",
        subtitle: "โมเดลระดับท็อป Ultra • วิเคราะห์เอกสารและประมวลผลโค้ดขนาดยักษ์",
        badge: "ตัวท็อปความเร็วสูง",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์ (Web/App)",
        price: 2490.00,
        originalPrice: 3500.00,
        soldCount: 20,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี Google AI Ultra สูงสุดของฝั่ง Google โมเดลเรือธงความเร็วสูง วิเคราะห์เอกสารและประมวลผลโค้ดขนาดยักษ์ รองรับ Context Window หลายล้านโทเคน"
    },
    {
        id: "goo-ai-03",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - บัญชีแชร์",
        subtitle: "บัญชีแชร์ราคาประหยัด • ใช้งาน Gemini 1.5 Pro เต็มประสิทธิภาพ",
        badge: "ประหยัดงบ",
        type: "บัญชีแชร์ (Shared)",
        typeKey: "shared",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์ (Web/App)",
        price: 79.00,
        originalPrice: 290.00,
        soldCount: 223,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชีแชร์ Google AI Pro พร้อม Gemini Advanced ใช้งานสร้างสรรค์ข้อความ เขียนโค้ด วิเคราะห์รูปภาพและไฟล์เสียงในราคาสุดคุ้ม"
    },
    {
        id: "goo-01",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google Drive 5TB + Gemini Advanced (1 เดือน)",
        subtitle: "พื้นที่คลาวด์ 5,000 GB จุใจ + AI Gemini ขั้นสูงในบัญชีส่วนตัว",
        badge: "ความจุยักษ์ 5TB",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์",
        price: 149.00,
        originalPrice: 490.00,
        soldCount: 812,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี Google ส่วนตัว พร้อมแพ็กเกจพื้นที่เก็บข้อมูล Google Drive 5TB และใช้งาน Gemini Advanced ครบทุกความสามารถใน Google Workspace"
    },
    {
        id: "goo-02",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google Storage 5TB (1 เดือน) - ลิงก์อัปเกรด",
        subtitle: "ลิงก์อัปเกรดพื้นที่ 5 TB เข้าอีเมลเดิมของคุณโดยตรง • ไม่ต้องย้ายไฟล์",
        badge: "อัปเกรดอีเมลเดิม",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์",
        price: 129.00,
        originalPrice: 450.00,
        soldCount: 8741,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "ลิงก์อัปเกรดพื้นที่ Google Drive ขนาด 5 TB เข้าอีเมลของท่านโดยตรง ไม่ต้องย้ายไฟล์เดิม จัดส่งลิงก์ทันทีหลังชำระเงิน"
    },
    {
        id: "grk-01",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (7 วัน) - บัญชีส่วนตัว",
        subtitle: "AI ของ Elon Musk ดึงข้อมูลสดจาก X (Twitter) • เจนภาพ Aurora Flux",
        badge: "ทดลองใช้งาน 7 วัน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "7 วัน",
        region: "Global",
        devices: "Web & App",
        price: 259.00,
        originalPrice: 490.00,
        soldCount: 1821,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "7 วัน",
        description: "บัญชี xAI Grok (SuperGrok) แบบส่วนตัว 7 วัน สำหรับสายทดลอง ประมวลผลแบบ Real-time ดึงข้อมูลสดจาก X (Twitter) และเจนภาพด้วย Aurora Flux"
    },
    {
        id: "grk-02",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "แพ็กเกจเต็ม 1 เดือน • สนทนา Real-time & สร้างภาพ AI ความละเอียดสูงไม่จำกัด",
        badge: "สายโปร 1 เดือน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 890.00,
        originalPrice: 1490.00,
        soldCount: 877,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี SuperGrok ส่วนตัวเต็ม 1 เดือน ปลดล็อกขีดจำกัดการสนทนา ฟีเจอร์ Fun Mode & Normal Mode และสร้างภาพ AI ความละเอียดสูงไม่จำกัด"
    },
    {
        id: "grk-03",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI SuperGrok Heavy (1 เดือน) - ปริมาณสูงพิเศษ",
        subtitle: "โควต้าคำถามมหาศาล • สำหรับงานวิเคราะห์ข้อมูลและธุรกิจตลอดวัน",
        badge: "Heavy Capacity",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 4990.00,
        originalPrice: 6500.00,
        soldCount: 14,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "แพ็กเกจ Heavy Capacity สำหรับผู้ใช้งานระดับ Professional และนักวิเคราะห์ข้อมูลที่ต้องการส่ง prompt จำนวนมหาศาลตลอดทั้งวัน"
    },
    {
        id: "cld-01",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "Claude 3.5 Sonnet ส่วนตัว 100% • ใช้งาน Artifacts, Projects & วิเคราะห์โค้ด",
        badge: "🔥 ฉลาดที่สุดสำหรับโค้ด",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 790.00,
        originalPrice: 990.00,
        soldCount: 424,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี Claude Pro แท้ 1 เดือน ส่วนตัว 100% ปลดล็อก Claude 3.5 Sonnet และ Opus ใช้งานฟังก์ชัน Artifacts, Project Knowledge, ส่งไฟล์ PDF วิเคราะห์โค้ดได้จุใจ"
    },
    {
        id: "cld-02",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - บัญชีหาร",
        subtitle: "บัญชีหารราคาประหยัด • เข้าถึง Claude 3.5 Sonnet ได้เหมือนกัน ส่งรหัสทันที",
        badge: "ราคาประหยัด",
        type: "บัญชีหาร (Shared)",
        typeKey: "shared",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 250.00,
        originalPrice: 490.00,
        soldCount: 3497,
        rating: 4.8,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชีหาร Claude Pro ประหยัดงบ เข้าถึง Claude 3.5 Sonnet ได้เหมือนกัน ส่งมอบรหัสทันที 24 ชม."
    },
    {
        id: "adb-01",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Acrobat Pro DC (1 เดือน)",
        subtitle: "แก้ไข PDF แปลงไฟล์ เซ็นเอกสารอิเล็กทรอนิกส์ ครบทุกฟังก์ชัน",
        badge: "งานเอกสารมืออาชีพ",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน",
        region: "Global",
        devices: "PC & Mobile",
        price: 450.00,
        originalPrice: 790.00,
        soldCount: 88,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "จัดการเอกสาร แก้ไข PDF แปลงไฟล์ เซ็นลายเซ็นอิเล็กทรอนิกส์ด้วย Adobe Acrobat Pro เต็มรูปแบบ"
    },
    {
        id: "adb-02",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Creative Cloud All Apps (1 เดือน) + 100GB",
        subtitle: "ปลดล็อกครบ 20+ แอป (Photoshop, Illustrator, Premiere) + Firefly AI",
        badge: "👑 รวมครบทุกโปรแกรม",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "PC & Mac",
        price: 690.00,
        originalPrice: 2190.00,
        soldCount: 612,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "ปลดล็อกครบ 20+ แอป Adobe ได้แก่ Photoshop, Illustrator, Premiere Pro, After Effects พร้อม Generative Credits สำหรับ Firefly AI"
    },
    {
        id: "ms-01",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Windows 11 Pro / Home - คีย์แท้ถาวร (OEM)",
        subtitle: "คีย์แท้จากไมโครซอฟท์ ใช้งานได้ตลอดชีพ 1 PC • อัปเดตแพตช์ได้ตลอด",
        badge: "⚡ คีย์แท้ตลอดชีพ",
        type: "คีย์แท้ถาวร (Key)",
        typeKey: "key",
        duration: "ตลอดชีพ (Lifetime)",
        region: "Global",
        devices: "1 PC (คอมพิวเตอร์)",
        price: 250.00,
        originalPrice: 1890.00,
        soldCount: 15420,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "ตลอดชีพ",
        description: "รหัสเปิดใช้งานคีย์แท้ Windows 11 OEM ใช้งานได้ถาวร 1 PC อัปเดตแพตช์ความปลอดภัยได้ตลอดชีพ ไม่เด้งหมดอายุ ส่งคีย์ทันที"
    },
    {
        id: "ms-02",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft 365 (1 เดือน) + 1TB OneDrive Cloud",
        subtitle: "Word, Excel, PowerPoint ของแท้ + พื้นที่คลาวด์ OneDrive 1,000 GB",
        badge: "ออฟฟิศแท้ + คลาวด์",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "PC • Mac • Mobile",
        price: 220.00,
        originalPrice: 450.00,
        soldCount: 822,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "สิทธิ์การใช้งาน Word, Excel, PowerPoint, Outlook ของแท้ พร้อมพื้นที่เก็บข้อมูลคลาวด์ OneDrive ปลอดภัยขนาด 1TB"
    },
    {
        id: "ms-03",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft Copilot Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "AI ผู้ช่วยใน Word, Excel, PowerPoint + เจนภาพ DALL-E 3 พรีเมียม",
        badge: "AI Office ผู้ช่วย",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์",
        price: 550.00,
        originalPrice: 850.00,
        soldCount: 310,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "ปลดล็อกขุมพลัง AI ของ Microsoft สั่งสร้างสไลด์ สรุปตาราง Excel วิเคราะห์เอกสาร และสร้างรูปภาพผ่าน DALL-E 3 ความเร็วระดับพรีเมียม"
    }
];

// Look up guaranteed price & live stock from Master Catalog (with custom price/stock override)
function getMasterProduct(productId) {
    const product = PRODUCTS.find(p => p.id === productId);
    if (!product) return null;
    if (productId === 'cpc-01') {
        return {
            ...product,
            price: 1.00,
            originalPrice: 199.00,
            stock: 99
        };
    }
    try {
        const customPrices = JSON.parse(localStorage.getItem('supinkly_custom_prices') || '{}');
        const custom = customPrices && customPrices[productId];
        if (custom) {
            return {
                ...product,
                price: typeof custom.price === 'number' ? custom.price : product.price,
                originalPrice: typeof custom.originalPrice === 'number' ? custom.originalPrice : product.originalPrice,
                stock: typeof custom.g2gStockAvailable === 'number' ? custom.g2gStockAvailable : (product.stock || 50),
                marketCostTHB: custom.marketCostTHB
            };
        }
    } catch (e) {
        // fallback
    }
    return product;
}
