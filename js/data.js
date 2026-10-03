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
        subtitle: "บัญชีส่วนตัวสำหรับ 1 ผู้ใช้ • ปลดล็อกเอฟเฟกต์ & เรนเดอร์ 4K ไม่มีลายน้ำ",
        badge: "แพ็กเกจยอดนิยม",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 129.00,
        originalPrice: 220.00,
        soldCount: 482,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี CapCut Pro รูปแบบส่วนตัว ระยะเวลา 1 เดือน รองรับการใช้งานทั้งบน iOS, Android และ PC เข้าใช้งานแยกเดี่ยว ปลดล็อกเอฟเฟกต์เสียง เทมเพลต และส่งออกไฟล์ 4K โดยไม่มีลายน้ำ"
    },
    {
        id: "cpc-02",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Pro (1 เดือน) - บัญชีหาร",
        subtitle: "บัญชีหารเพื่อการประหยัด • ปลดล็อกฟังก์ชัน Pro ใช้งานสะดวก",
        badge: "ราคาประหยัด",
        type: "บัญชีหาร (Shared)",
        typeKey: "shared",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 79.00,
        originalPrice: 129.00,
        soldCount: 215,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชีหาร CapCut Pro ระยะเวลา 1 เดือน เหมาะสำหรับผู้ที่ต้องการใช้งานฟังก์ชัน Pro พื้นฐานในราคาประหยัด รองรับทั้งสมาร์ตโฟนและคอมพิวเตอร์"
    },
    {
        id: "cpc-03",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Team (1 เดือน) - บัญชีทีม",
        subtitle: "แชร์เทมเพลตและพื้นที่ Cloud ร่วมกัน • เหมาะสำหรับงานเป็นทีม",
        badge: "สำหรับทีมงาน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 189.00,
        originalPrice: 290.00,
        soldCount: 94,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "CapCut แผน Team ระยะเวลา 1 เดือน เหมาะสำหรับการทำงานร่วมกัน สามารถแชร์เทมเพลตและจัดเก็บไฟล์งานบน Cloud ของทีมได้"
    },
    {
        id: "cpc-04",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut VIP / SVIP (1 เดือน)",
        subtitle: "สิทธิ์ระดับ VIP • ปลดล็อกคลังสติกเกอร์และเครื่องมือ AI",
        badge: "สิทธิ์พิเศษ VIP",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน",
        region: "Global",
        devices: "iOS • Android • PC",
        price: 259.00,
        originalPrice: 350.00,
        soldCount: 68,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บริการเปิดสิทธิ์ VIP CapCut สำหรับผู้ที่ต้องการใช้งานฟังก์ชันเฉพาะทางเพิ่มเติม เช่น คลังสติกเกอร์พิเศษและเครื่องมือช่วยตัดต่ออัตโนมัติ"
    },
    {
        id: "goo-ai-01",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - ลิงก์เชิญ",
        subtitle: "ลิงก์เปิดสิทธิ์ผูกเข้ากับ Gmail ของคุณโดยตรง • ไม่ต้องแจ้งรหัสผ่าน",
        badge: "แนะนำยอดนิยม",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์ (Web/App)",
        price: 150.00,
        originalPrice: 350.00,
        soldCount: 385,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "ลิงก์เชิญเปิดสิทธิ์ Google AI Pro (Gemini Advanced) ผูกเข้ากับบัญชี Google ส่วนตัวของท่านโดยตรง สะดวก ปลอดภัย ไม่ต้องส่งมอบรหัสผ่านส่วนตัว ใช้งาน Gemini 1.5 Pro พร้อมพื้นที่ Google One"
    },
    {
        id: "goo-ai-02",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Ultra (Gemini Ultra 1 เดือน) - บัญชีส่วนตัว",
        subtitle: "โมเดลประมวลผลประสิทธิภาพสูง Ultra • เหมาะสำหรับงานวิเคราะห์และเขียนโค้ด",
        badge: "ประสิทธิภาพสูง",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์ (Web/App)",
        price: 2590.00,
        originalPrice: 3200.00,
        soldCount: 18,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี Google AI Ultra สำหรับการประมวลผลงานขั้นสูง วิเคราะห์เอกสารทางวิชาการและโค้ดโปรแกรม รองรับ Context Window ขนาดใหญ่พิเศษ"
    },
    {
        id: "goo-ai-03",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - บัญชีแชร์",
        subtitle: "บัญชีแชร์ราคาประหยัด • ใช้งาน Gemini 1.5 Pro ได้คุ้มค่า",
        badge: "ราคาประหยัด",
        type: "บัญชีแชร์ (Shared)",
        typeKey: "shared",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์ (Web/App)",
        price: 99.00,
        originalPrice: 199.00,
        soldCount: 162,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชีแชร์ Google AI Pro ใช้งานสร้างสรรค์เนื้อหา วิเคราะห์ข้อมูล และประมวลผลคำถามทั่วไปผ่านโมเดล Gemini 1.5 Pro ในราคาย่อมเยา"
    },
    {
        id: "goo-01",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google Drive 5TB + Gemini Advanced (1 เดือน)",
        subtitle: "พื้นที่คลาวด์ 5TB พร้อมสิทธิ์ Gemini Advanced ในบัญชีเดียว",
        badge: "พื้นที่จัดเก็บ 5TB",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์",
        price: 229.00,
        originalPrice: 450.00,
        soldCount: 195,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี Google ส่วนตัว มาพร้อมพื้นที่จัดเก็บข้อมูล Google Drive ขนาด 5TB และสิทธิ์การใช้งาน Gemini Advanced ครบถ้วนใน Google Workspace"
    },
    {
        id: "goo-02",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google Storage 5TB (1 เดือน) - ลิงก์อัปเกรด",
        subtitle: "ลิงก์อัปเกรดพื้นที่ 5TB เข้าอีเมลเดิมของคุณ • ไม่ต้องย้ายไฟล์",
        badge: "อัปเกรดอีเมลเดิม",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์",
        price: 179.00,
        originalPrice: 350.00,
        soldCount: 410,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "ลิงก์อัปเกรดพื้นที่ Google Drive ขนาด 5TB เข้าบัญชีอีเมลเดิมของท่านโดยตรง สะดวก ไม่ต้องสำรองหรือย้ายไฟล์เก่า"
    },
    {
        id: "grk-01",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (7 วัน) - บัญชีส่วนตัว",
        subtitle: "ทดลองใช้งาน 7 วัน • สรุปข้อมูลล่าสุดจาก X และสร้างภาพ AI",
        badge: "แพ็กเกจ 7 วัน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "7 วัน",
        region: "Global",
        devices: "Web & App",
        price: 290.00,
        originalPrice: 390.00,
        soldCount: 128,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "7 วัน",
        description: "บัญชี xAI Grok (SuperGrok) แบบส่วนตัว ระยะเวลา 7 วัน เหมาะสำหรับผู้ที่ต้องการทดลองใช้งานการค้นหาข้อมูลแบบเรียลไทม์และการสร้างภาพด้วย Aurora Flux"
    },
    {
        id: "grk-02",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "แพ็กเกจเต็ม 1 เดือน • ใช้งานโมเดล Grok และสร้างภาพความละเอียดสูง",
        badge: "แพ็กเกจ 1 เดือน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 950.00,
        originalPrice: 1290.00,
        soldCount: 86,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี SuperGrok ส่วนตัว ระยะเวลา 1 เดือน รองรับการสนทนาโหมดทั่วไปและ Fun Mode พร้อมการสร้างรูปภาพ AI คุณภาพสูง"
    },
    {
        id: "grk-03",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI SuperGrok Heavy (1 เดือน) - ปริมาณสูงพิเศษ",
        subtitle: "โควต้าการส่งคำสั่งระดับสูง • เหมาะสำหรับงานวิจัยและวิเคราะห์ข้อมูล",
        badge: "โควต้าปริมาณสูง",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 4990.00,
        originalPrice: 5500.00,
        soldCount: 12,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "แพ็กเกจ Heavy Capacity รองรับปริมาณคำสั่งและการประมวลผลข้อมูลปริมาณมาก เหมาะสำหรับงานวิจัยและการใช้งานทางธุรกิจ"
    },
    {
        id: "cld-01",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "เข้าถึง Claude 3.5 Sonnet บัญชีส่วนตัว • รองรับ Artifacts และ Projects",
        badge: "สำหรับงานเขียนโค้ด",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 850.00,
        originalPrice: 1050.00,
        soldCount: 275,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชี Claude Pro รูปแบบส่วนตัว 1 เดือน เข้าใช้งาน Claude 3.5 Sonnet และ Opus รองรับการทำงานผ่านฟังก์ชัน Artifacts, Project Knowledge และการวิเคราะห์โค้ดเอกสาร"
    },
    {
        id: "cld-02",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - บัญชีหาร",
        subtitle: "บัญชีหารเพื่อการประหยัด • เข้าถึง Claude 3.5 Sonnet ได้เหมือนกัน",
        badge: "ราคาประหยัด",
        type: "บัญชีหาร (Shared)",
        typeKey: "shared",
        duration: "1 เดือน",
        region: "Global",
        devices: "Web & App",
        price: 290.00,
        originalPrice: 390.00,
        soldCount: 180,
        rating: 4.8,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "บัญชีหาร Claude Pro ระยะเวลา 1 เดือน สำหรับผู้เริ่มต้นที่ต้องการสัมผัสความสามารถของ Claude 3.5 Sonnet ในราคาประหยัด"
    },
    {
        id: "adb-01",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Acrobat Pro DC (1 เดือน)",
        subtitle: "จัดการเอกสาร PDF แปลงไฟล์ และเซ็นชื่ออิเล็กทรอนิกส์",
        badge: "งานเอกสาร PDF",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน",
        region: "Global",
        devices: "PC & Mobile",
        price: 490.00,
        originalPrice: 690.00,
        soldCount: 72,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "โปรแกรมจัดการเอกสาร Adobe Acrobat Pro DC เต็มรูปแบบ สำหรับการแก้ไข แปลงไฟล์เอกสาร และสร้างลายเซ็นดิจิทัล"
    },
    {
        id: "adb-02",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Creative Cloud All Apps (1 เดือน) + 100GB",
        subtitle: "รวมแอปสร้างสรรค์ (Photoshop, Illustrator, Premiere) + Firefly AI",
        badge: "รวมทุกแอปสร้างสรรค์",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "PC & Mac",
        price: 790.00,
        originalPrice: 1290.00,
        soldCount: 165,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "แพ็กเกจรวมแอปพลิเคชันตระกูล Adobe เช่น Photoshop, Illustrator, Premiere Pro, After Effects พร้อม Generative Credits สำหรับ Firefly AI"
    },
    {
        id: "ms-01",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Windows 11 Pro / Home - คีย์แท้ถาวร (OEM)",
        subtitle: "คีย์แท้รูปแบบ OEM สำหรับ 1 PC • รองรับการอัปเดตความปลอดภัยเป็นทางการ",
        badge: "คีย์ถาวร 1 PC",
        type: "คีย์แท้ถาวร (Key)",
        typeKey: "key",
        duration: "ตลอดชีพ (Lifetime)",
        region: "Global",
        devices: "1 PC (คอมพิวเตอร์)",
        price: 290.00,
        originalPrice: 590.00,
        soldCount: 390,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "ตลอดชีพ",
        description: "รหัสเปิดใช้งาน Windows 11 รูปแบบ OEM ใช้งานได้ถาวรบนคอมพิวเตอร์ 1 เครื่อง รองรับการอัปเดตระบบความปลอดภัยตามมาตรฐาน จัดส่งคีย์ทันทีหลังชำระเงิน"
    },
    {
        id: "ms-02",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft 365 (1 เดือน) + 1TB OneDrive Cloud",
        subtitle: "สิทธิ์ใช้งาน Word, Excel, PowerPoint แท้ พร้อมคลาวด์ OneDrive 1TB",
        badge: "ออฟฟิศแท้ + คลาวด์",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "PC • Mac • Mobile",
        price: 259.00,
        originalPrice: 390.00,
        soldCount: 210,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "สิทธิ์การใช้งานแอปพลิเคชันสำนักงาน Word, Excel, PowerPoint และ Outlook พร้อมพื้นที่เก็บข้อมูลคลาวด์ OneDrive ขนาด 1TB สำหรับ 1 เดือน"
    },
    {
        id: "ms-03",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft Copilot Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "ผู้ช่วย AI ใน Word, Excel, PowerPoint พร้อมการสร้างภาพ DALL-E 3",
        badge: "AI เสริมงานออฟฟิศ",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน",
        region: "Global",
        devices: "ทุกอุปกรณ์",
        price: 590.00,
        originalPrice: 790.00,
        soldCount: 92,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "เปิดใช้งาน Microsoft Copilot Pro ผู้ช่วย AI สำหรับการสรุปเอกสาร วิเคราะห์ข้อมูลในตาราง และสร้างภาพประกอบด้วย DALL-E 3"
    }
];

// Ensure every master product has guaranteed default stock (50 pcs minimum)
PRODUCTS.forEach(p => {
    if (typeof p.stock !== 'number') {
        const benchmarkStock = (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[p.id]?.g2gStock);
        p.stock = benchmarkStock || 50;
    }
});

// Look up guaranteed price & live stock from Master Catalog (with custom price/stock override)
function getMasterProduct(productId) {
    const product = PRODUCTS.find(p => p.id === productId);
    if (!product) return null;
    let price = product.price;
    let originalPrice = product.originalPrice;
    let stock = product.stock || 50;
    let marketCostTHB = product.marketCostTHB || 0;

    // Check G2G market benchmark default if available
    if (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[productId]) {
        const benchmark = G2G_MARKET_FEED.benchmarks[productId];
        if (typeof benchmark.g2gStock === 'number') {
            stock = benchmark.g2gStock;
        }
        if (typeof benchmark.baseCostUSD === 'number') {
            marketCostTHB = Math.round(benchmark.baseCostUSD * 36.50 * 100) / 100;
        }
    }

    try {
        const customPrices = JSON.parse(localStorage.getItem('supinkly_custom_prices') || '{}');
        const custom = customPrices && customPrices[productId];
        if (custom) {
            if (typeof custom.price === 'number') price = custom.price;
            if (typeof custom.originalPrice === 'number') originalPrice = custom.originalPrice;
            if (typeof custom.g2gStockAvailable === 'number' && custom.g2gStockAvailable > 0) stock = custom.g2gStockAvailable;
            if (typeof custom.marketCostTHB === 'number') marketCostTHB = custom.marketCostTHB;
        }
    } catch (e) {
        // fallback
    }

    return {
        ...product,
        price,
        originalPrice,
        stock: stock || 50,
        marketCostTHB
    };
}
