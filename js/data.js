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
        subtitle: "บัญชีส่วนตัว 1 ผู้ใช้ • ปลดล็อกเครื่องมือ Pro & เรนเดอร์ 4K ไร้ลายน้ำ",
        badge: "⭐ แพ็คขายดีติดดาว",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "iOS • Android • Windows • Mac",
        price: 129.00,
        originalPrice: 220.00,
        soldCount: 482,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• บัญชีส่วนตัวเดี่ยว 1 ผู้ใช้ ไม่แชร์ใคร ใช้งานได้เต็มสิทธิ์\n• เรนเดอร์คมชัดสูงสุด 4K 60fps ไม่มีลายน้ำ ลื่นไหลไม่สะดุด\n• ปลดล็อกเอฟเฟกต์ เสียงดนตรี เทมเพลต และเครื่องมือ AI อัจฉริยะครบทุกฟังก์ชัน"
    },
    {
        id: "cpc-02",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Pro (1 เดือน) - สิทธิ์ประหยัด",
        subtitle: "โปรไฟล์แยกราคาประหยัด • เรนเดอร์ไร้ลายน้ำ ปลดล็อกฟังก์ชัน Pro ครบ",
        badge: "ราคาประหยัด",
        type: "บัญชีหาร (Shared)",
        typeKey: "shared",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "iOS • Android • PC",
        price: 79.00,
        originalPrice: 129.00,
        soldCount: 215,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• สิทธิ์โปรไฟล์แยก ใช้งานฟังก์ชัน Pro ครบถ้วนในราคาสบายกระเป๋า\n• ส่งออกวิดีโอคมชัด ไม่มีลายน้ำ พร้อมฟอนต์และเทมเพลตลิขสิทธิ์\n• เข้าใช้งานง่ายผ่านโปรไฟล์ส่วนตัว ดูแลตลอดอายุการใช้งาน 30 วัน"
    },
    {
        id: "cpc-03",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Team (1 เดือน) - สิทธิ์เวิร์กสเปซทีม",
        subtitle: "พื้นที่ทำงาน Cloud ร่วมกัน • แชร์โปรเจกต์และฟังก์ชัน Pro ทั้งทีม",
        badge: "สำหรับทีมงาน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "iOS • Android • Windows • Mac",
        price: 189.00,
        originalPrice: 290.00,
        soldCount: 94,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• สิทธิ์พื้นที่ทำงานทีม (Team Workspace) เหมาะสำหรับครีเอเตอร์และสตูดิโอ\n• แชร์ไฟล์ ตัดต่อ และประสานงานโปรเจกต์บนคลาวด์กลางร่วมกันแบบเรียลไทม์\n• สมาชิกทุกคนในทีมได้รับฟังก์ชัน CapCut Pro เต็มรูปแบบ"
    },
    {
        id: "cpc-04",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut VIP / SVIP (1 เดือน) - สิทธิ์ขั้นสูง",
        subtitle: "ระดับ VIP สูงสุด • ปลดล็อก AI Script-to-Video และคลาวด์เรนเดอร์ความเร็วสูง",
        badge: "สิทธิ์พิเศษ VIP",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "iOS • Android • PC",
        price: 259.00,
        originalPrice: 350.00,
        soldCount: 68,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• สิทธิ์ระดับ VIP สูงสุด เข้าถึงเครื่องมือ AI แปลงสคริปต์ข้อความเป็นวิดีโอ\n• สร้างเสียงพากย์ AI หลายภาษา และคลังสติกเกอร์/แอนิเมชันพรีเมียม\n• เรนเดอร์ผ่าน Cloud Server ความเร็วสูงพิเศษ ประหยัดเวลาทำงาน"
    },
    {
        id: "goo-ai-01",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - ลิงก์เปิดสิทธิ์",
        subtitle: "อัปเกรดเข้า Gmail ของคุณโดยตรง • ปลอดภัย 100% พร้อมคลาวด์ 2TB",
        badge: "⭐ แนะนำยอดนิยม",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (Web, Android, iOS)",
        price: 150.00,
        originalPrice: 350.00,
        soldCount: 385,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• อัปเกรดตรงเข้า Gmail ส่วนตัวผ่านลิงก์ทางการ ไม่ต้องให้รหัสผ่าน ข้อมูลส่วนตัว 100%\n• เข้าถึงโมเดลเรือธง Gemini Advanced (1.5/2.0 Pro) คิดวิเคราะห์และเขียนโค้ดขั้นสูง\n• ได้รับพื้นที่คลาวด์ Google One 2TB (Drive, Gmail, Photos) พร้อม AI ช่วยงานใน Docs/Gmail"
    },
    {
        id: "goo-ai-02",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Ultra (Gemini Ultra 1 เดือน) - บัญชีวิจัยขั้นสูง",
        subtitle: "พลังประมวลผลสูงสุด • รองรับ 1 ล้านโทเค็น สำหรับงานวิจัยและวิเคราะห์โค้ด",
        badge: "ประสิทธิภาพสูง",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (Web & App)",
        price: 2590.00,
        originalPrice: 3200.00,
        soldCount: 18,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• ขุมพลังระดับองค์กร ออกแบบสำหรับงานวิจัย วิเคราะห์ข้อมูล และเดเวลอปเปอร์\n• รองรับ Context Window ขนาดใหญ่พิเศษกว่า 1 ล้านโทเค็น วิเคราะห์เอกสารหนาและซอร์สโค้ดทั้งโปรเจกต์\n• ประมวลผลรวดเร็วและแม่นยำสูงสุด พร้อมโควต้าตอบกลับระดับสูงสุด"
    },
    {
        id: "goo-ai-03",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - สิทธิ์ประหยัด",
        subtitle: "สิทธิ์ใช้งานราคาประหยัด • สัมผัสพลัง Gemini 1.5 Pro ในราคาสบายกระเป๋า",
        badge: "ราคาประหยัด",
        type: "บัญชีแชร์ (Shared)",
        typeKey: "shared",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (Web & App)",
        price: 99.00,
        originalPrice: 199.00,
        soldCount: 162,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• สิทธิ์เข้าใช้งานราคาประหยัด เหมาะสำหรับนักเรียน นักศึกษา และผู้เริ่มต้น\n• ใช้งาน Gemini 1.5 Pro เขียนบทความ แปลภาษา วิเคราะห์ข้อมูล และร่างไอเดียเร็ว\n• เข้าใช้งานได้ทันที คุ้มค่าและประหยัดงบที่สุด"
    },
    {
        id: "goo-01",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google Drive 5TB + Gemini Advanced (1 เดือน)",
        subtitle: "คลาวด์ขนาดใหญ่ 5,000 GB + ใช้งาน Gemini Advanced ในบัญชีเดียว",
        badge: "พื้นที่จัดเก็บ 5TB",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (PC, Mac, Mobile)",
        price: 229.00,
        originalPrice: 450.00,
        soldCount: 195,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• บัญชีส่วนตัวพร้อมพื้นที่คลาวด์ขนาดมหึมา 5TB (5,000 GB)\n• สำรองข้อมูล รูปภาพ และไฟล์วิดีโอ 4K/8K ได้จุใจ ปลอดภัยระดับองค์กร\n• รวมสิทธิ์เข้าใช้งาน Gemini Advanced ช่วยงานในตัวบัญชี"
    },
    {
        id: "goo-02",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google One Subscription Pro 5TB (18 เดือน) - Activation Link",
        subtitle: "เปิดสิทธิ์บนบัญชี Google ของคุณโดยตรง • คลาวด์ 5TB ยาวนาน 18 เดือน",
        badge: "🔥 ดีลพิเศษ 18 เดือน",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "18 เดือน (18 Months)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (PC, Mac, Mobile)",
        price: 99.00,
        originalPrice: 690.00,
        soldCount: 410,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• เปิดสิทธิ์ตรงเข้า Gmail เดิมของคุณ ไม่ต้องย้ายข้อมูล ไม่ต้องเปิดเผยรหัสผ่าน\n• เพิ่มพื้นที่ Google One 5TB (5,000 GB) ใช้กับ Drive, Gmail, Photos ยาวนาน 18 เดือน\n• ปลอดภัย 100% รับสิทธิ์ผ่านลิงก์ทางการใน 1 นาที พร้อมสิทธิ์ใช้งาน Gemini Pro"
    },
    {
        id: "grk-01",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (7 วัน) - บัญชีส่วนตัว",
        subtitle: "แพ็กเกจทดลอง 7 วัน • ข้อมูลเรียลไทม์บน X + เจนภาพ AI Aurora Flux",
        badge: "แพ็กเกจทดลอง 7 วัน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "7 วัน",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "Web & App (iOS, Android, PC)",
        price: 290.00,
        originalPrice: 390.00,
        soldCount: 128,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "7 วัน",
        description: "• แพ็กเกจทดลอง 7 วัน บัญชีส่วนตัวพร้อมสิทธิ์ X (Twitter) Premium\n• ดึงข้อมูลและประเด็นร้อนแบบเรียลไทม์จากทวิตเตอร์ ไม่มีตกเทรนด์\n• สร้างรูปภาพ AI คุณภาพสูงคมชัดด้วยโมเดล Aurora Flux"
    },
    {
        id: "grk-02",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "บัญชีส่วนตัว 1 เดือน • Grok โมเดลล่าสุด ไร้โฆษณาบน X โควต้าสูง",
        badge: "⭐ แพ็กเกจยอดนิยม 1 เดือน",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "Web & App (iOS, Android, PC)",
        price: 950.00,
        originalPrice: 1290.00,
        soldCount: 86,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• บัญชีส่วนตัว X Premium+ ระดับสูงสุด ไร้โฆษณาบนหน้าฟีด X\n• เข้าถึงโมเดล Grok รุ่นล่าสุด โควต้าคำสั่งสูง วิเคราะห์ข้อมูลเจาะลึก\n• เจนรูปภาพ AI ความละเอียดสูงไม่อั้น ตอบโจทย์งานข่าวและคอนเทนต์"
    },
    {
        id: "grk-03",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI SuperGrok Heavy (1 เดือน) - โควต้าประมวลผลสูง",
        subtitle: "โควต้าประมวลผลสูง (Heavy) • ขยาย Rate Limit สำหรับงานโค้ดและดาต้า",
        badge: "โควต้าปริมาณสูง",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "Web & App (iOS, Android, PC)",
        price: 4990.00,
        originalPrice: 5500.00,
        soldCount: 12,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• สิทธิ์ระดับ Heavy Capacity ขยาย Rate Limit สูงสุดสำหรับงานหนัก\n• รองรับการวิเคราะห์โค้ดและข้อมูลมหาศาลได้อย่างต่อเนื่อง ไม่ติดขัด\n• เหมาะสำหรับโปรแกรมเมอร์ นักวิเคราะห์ดาต้า และทีมงานที่ต้องการความเร็วสูง"
    },
    {
        id: "cld-01",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "บัญชีส่วนตัว 1 ผู้ใช้ • Claude 3.5 Sonnet โควต้า 5 เท่า พร้อม Artifacts",
        badge: "⭐ ยอดนิยมสำหรับเขียนโค้ด",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "Web, Mac, Windows, iOS, Android",
        price: 850.00,
        originalPrice: 1050.00,
        soldCount: 275,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• บัญชีส่วนตัว 1 ผู้ใช้ แชทและโปรเจกต์เป็นส่วนตัว 100%\n• เข้าใช้งานโมเดลตัวท็อป Claude 3.5 Sonnet โควต้ามากกว่าฟรี 5 เท่า\n• ปลดล็อกฟีเจอร์พรีเมียม Artifacts (พรีวิวโค้ด/เว็บสด) และระบบ Projects"
    },
    {
        id: "cld-02",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - สิทธิ์ประหยัด",
        subtitle: "สิทธิ์ใช้งานราคาประหยัด • เข้าถึง Claude 3.5 Sonnet ในราคาสบายกระเป๋า",
        badge: "ราคาประหยัด",
        type: "บัญชีหาร (Shared)",
        typeKey: "shared",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "Web, Mac, Windows, iOS, Android",
        price: 290.00,
        originalPrice: 390.00,
        soldCount: 180,
        rating: 4.8,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• สิทธิ์เข้าใช้งานราคาประหยัด สัมผัสความฉลาดของ Claude 3.5 Sonnet\n• ช่วยเขียนโค้ด แปลภาษาธรรมชาติ และสรุปเนื้อหาเชิงลึกได้อย่างยอดเยี่ยม\n• เหมาะสำหรับผู้เริ่มต้นและใช้งานทั่วไปในราคาคุ้มค่าที่สุด"
    },
    {
        id: "adb-01",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Acrobat Pro DC (1 เดือน) - ลิขสิทธิ์แท้",
        subtitle: "จัดการ PDF ตัวเต็ม • แก้ไข แปลงไฟล์เป็น Word/Excel และเซ็นชื่อดิจิทัล",
        badge: "งานเอกสาร PDF",
        type: "เติมเงิน VIP (Top-up)",
        typeKey: "topup",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "PC, Mac & Mobile",
        price: 490.00,
        originalPrice: 690.00,
        soldCount: 72,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• ลิขสิทธิ์แท้ตัวเต็ม แก้ไขข้อความ รูปภาพ และจัดหน้า PDF ได้อย่างอิสระ\n• แปลงไฟล์ PDF เป็น Word, Excel, PowerPoint โดยคงฟอนต์และตารางแม่นยำ\n• สแกนเอกสารด้วย OCR เป็นข้อความค้นหาได้ และสร้างลายเซ็นอิเล็กทรอนิกส์ถูกกฎหมาย"
    },
    {
        id: "adb-02",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Creative Cloud All Apps (1 เดือน) + 100GB",
        subtitle: "รวม 20+ แอปสร้างสรรค์ (Photoshop, Premiere) + Firefly AI & Cloud 100GB",
        badge: "⭐ รวมทุกแอปสร้างสรรค์",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "PC & Mac (รองรับ 2 เครื่องพร้อมกัน)",
        price: 790.00,
        originalPrice: 1290.00,
        soldCount: 165,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• ลิขสิทธิ์แท้ รวมโปรแกรมสร้างสรรค์กว่า 20 แอป (Photoshop, Illustrator, Premiere Pro)\n• พื้นที่จัดเก็บ Adobe Cloud 100GB พร้อมเครดิตสร้างภาพด้วย AI Firefly\n• ติดตั้งผ่าน Creative Cloud Desktop แท้ อัปเดตล่าสุดเสมอ ใช้งานได้ 2 เครื่อง"
    },
    {
        id: "ms-01",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Windows 11 Pro / Home - คีย์แท้ถาวร (OEM License)",
        subtitle: "คีย์แท้ดิจิทัล 25 หลัก • เปิดใช้งานถาวรตลอดชีพ อัปเดตทางการ Microsoft",
        badge: "⭐ คีย์ถาวรตลอดชีพ",
        type: "คีย์แท้ถาวร (Key)",
        typeKey: "key",
        duration: "ตลอดชีพ (Lifetime)",
        region: "Global (ใช้งานได้ทั่วโลก ทุกภาษา)",
        devices: "1 PC (คอมพิวเตอร์ / โน้ตบุ๊ก)",
        price: 290.00,
        originalPrice: 590.00,
        soldCount: 390,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "ตลอดชีพ",
        description: "• คีย์แท้ 25 หลัก เปิดใช้งานถาวรตลอดชีพ ผูกติดกับเมนบอร์ดเครื่อง (1 PC)\n• รองรับทั้ง Clean Install และอัปเกรดจาก Home เป็น Pro ได้ทันที\n• ดาวน์โหลดและอัปเดตความปลอดภัยผ่าน Windows Update ทางการ Microsoft 100%"
    },
    {
        id: "ms-02",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft 365 Personal (1 เดือน) + 1TB OneDrive Cloud",
        subtitle: "ชุดออฟฟิศแท้ (Word, Excel, PowerPoint) + พื้นที่คลาวด์ OneDrive 1TB",
        badge: "ออฟฟิศแท้ + คลาวด์ 1TB",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "สูงสุด 5 เครื่อง (PC, Mac, iPad, iPhone, Android)",
        price: 259.00,
        originalPrice: 390.00,
        soldCount: 210,
        rating: 4.9,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• ออฟฟิศแท้เวอร์ชันล่าสุด Word, Excel, PowerPoint, Outlook ครบชุด\n• ใช้งานได้สูงสุด 5 เครื่องพร้อมกัน ทั้งคอมพิวเตอร์ แท็บเล็ต และมือถือ\n• พื้นที่คลาวด์ OneDrive 1TB (1,000 GB) พร้อมระบบความปลอดภัยป้องกัน Ransomware"
    },
    {
        id: "ms-03",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft Copilot Pro (1 เดือน) - สิทธิ์ผู้ช่วย AI ส่วนตัว",
        subtitle: "ผู้ช่วย AI ในโปรแกรม Office • เข้าถึง GPT-4o และสร้างภาพ DALL-E 3 รวดเร็ว",
        badge: "AI เสริมงานออฟฟิศ",
        type: "บัญชีส่วนตัว (Private)",
        typeKey: "private",
        duration: "1 เดือน (30 วัน)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (PC, Mac, Web, Mobile)",
        price: 590.00,
        originalPrice: 790.00,
        soldCount: 92,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• ผู้ช่วย AI อัจฉริยะ เชื่อมต่อตรงใน Word, Excel, PowerPoint ช่วยร่างงานและทำสไลด์\n• เข้าถึงโมเดล GPT-4o รวดเร็วพิเศษแม้ในช่วงเวลาเร่งด่วน\n• รับโควต้าเร่งความเร็วสร้างภาพด้วย DALL-E 3 สูงถึง 100 บูสต์ต่อวัน"
    }
];

// Ensure every master product has banner image, raw G2G title, direct link, and guaranteed default stock (50 pcs minimum)
PRODUCTS.forEach(p => {
    if (!p.image) {
        p.image = `images/products/${p.id}.jpg`;
    }
    if (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[p.id]) {
        p.g2gRawTitle = G2G_MARKET_FEED.benchmarks[p.id].title || '';
        p.g2gUrl = G2G_MARKET_FEED.benchmarks[p.id].g2gUrl || '';
    }
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
    let g2gRawTitle = product.g2gRawTitle || '';
    let g2gUrl = product.g2gUrl || '';

    // Check G2G market benchmark default if available
    if (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[productId]) {
        const benchmark = G2G_MARKET_FEED.benchmarks[productId];
        if (benchmark.title) g2gRawTitle = benchmark.title;
        if (benchmark.g2gUrl) g2gUrl = benchmark.g2gUrl;
        if (typeof benchmark.g2gStock === 'number') {
            stock = benchmark.g2gStock;
        }
        if (typeof benchmark.baseCostUSD === 'number') {
            marketCostTHB = Math.round(benchmark.baseCostUSD * 36.50 * 100) / 100;
        }
    }

    let badge = product.badge;

    try {
        const customPrices = JSON.parse(localStorage.getItem('supinkly_custom_prices') || '{}');
        const custom = customPrices && customPrices[productId];
        if (custom) {
            if (typeof custom.price === 'number') price = custom.price;
            if (typeof custom.originalPrice === 'number') originalPrice = custom.originalPrice;
            if (typeof custom.badge === 'string') badge = custom.badge;
            if (typeof custom.g2gStockAvailable === 'number' && custom.g2gStockAvailable > 0) stock = custom.g2gStockAvailable;
            if (typeof custom.marketCostTHB === 'number') marketCostTHB = custom.marketCostTHB;
        }
    } catch (e) {
        // fallback
    }

    return {
        ...product,
        image: product.image || `images/products/${product.id}.jpg`,
        badge,
        price,
        originalPrice,
        stock: stock || 50,
        marketCostTHB,
        g2gRawTitle,
        g2gUrl
    };
}

// ==========================================
// STORE PROMOTIONS & DISCOUNT COUPONS
// ==========================================
const DEFAULT_PROMOTIONS = [
    {
        code: "SUPINKLY10",
        title: "ส่วนลดต้อนรับสมาชิกใหม่ 10%",
        description: "รับส่วนลด 10% ทุกรายการ เมื่อสั่งซื้อขั้นต่ำ ฿100 (ลดสูงสุด ฿100)",
        discountType: "percent",
        type: "percentage",
        discountValue: 10,
        value: 10,
        minSpend: 100,
        maxDiscount: 100,
        expiresAt: "2026-12-31",
        active: true,
        badge: "🔥 โค้ดยอดฮิต",
        color: "from-pink-500 to-rose-500"
    },
    {
        code: "PINKLOVE50",
        title: "ส่วนลดพิเศษ Supinkly ฿50",
        description: "ลดทันที ฿50 เมื่อช้อปครบ ฿300 ขึ้นไป สิทธิ์คุ้มจุใจ",
        discountType: "fixed",
        type: "fixed",
        discountValue: 50,
        value: 50,
        minSpend: 300,
        maxDiscount: 50,
        expiresAt: "2026-12-31",
        active: true,
        badge: "💖 แนะนำ",
        color: "from-purple-500 to-indigo-600"
    },
    {
        code: "NEWAI20",
        title: "ส่วนลดคีย์ AI สุดคุ้ม 20%",
        description: "ลด 20% สำหรับคีย์และบัญชี AI ยอดขั้นต่ำ ฿250 (ลดสูงสุด ฿150)",
        discountType: "percent",
        type: "percentage",
        discountValue: 20,
        value: 20,
        minSpend: 250,
        maxDiscount: 150,
        expiresAt: "2026-12-31",
        active: true,
        badge: "⚡ AI สปีด",
        color: "from-cyan-500 to-blue-600"
    },
    {
        code: "VIP100",
        title: "ส่วนลด VIP ลูกค้าคนสำคัญ ฿100",
        description: "ลดทันที ฿100 เมื่อช้อปครบ ฿600 ขึ้นไป คุ้มที่สุดสำหรับแพ็คเกจใหญ่",
        discountType: "fixed",
        type: "fixed",
        discountValue: 100,
        value: 100,
        minSpend: 600,
        maxDiscount: 100,
        expiresAt: "2026-12-31",
        active: true,
        badge: "👑 VIP DEAL",
        color: "from-amber-500 to-orange-600"
    }
];

function getStorePromotions() {
    try {
        const stored = localStorage.getItem('supinkly_promotions');
        if (stored) {
            const parsed = JSON.parse(stored);
            if (Array.isArray(parsed) && parsed.length > 0) {
                return parsed.map(p => {
                    const isPct = (p.discountType === 'percent' || p.type === 'percentage' || p.type === 'percent');
                    const val = typeof p.discountValue === 'number' ? p.discountValue : (typeof p.value === 'number' ? p.value : 0);
                    return {
                        ...p,
                        discountType: isPct ? 'percent' : 'fixed',
                        type: isPct ? 'percentage' : 'fixed',
                        discountValue: val,
                        value: val
                    };
                });
            }
        }
    } catch (e) {}
    localStorage.setItem('supinkly_promotions', JSON.stringify(DEFAULT_PROMOTIONS));
    return DEFAULT_PROMOTIONS;
}

function saveStorePromotions(promos) {
    try {
        localStorage.setItem('supinkly_promotions', JSON.stringify(promos));
    } catch (e) {}
}

function validateCouponCode(code, subtotal) {
    if (!code || typeof code !== 'string') {
        return { valid: false, message: "กรุณากรอกโค้ดส่วนลด" };
    }
    const cleanCode = code.trim().toUpperCase();
    const promotions = getStorePromotions();
    const coupon = promotions.find(p => (p.code || '').toUpperCase() === cleanCode);

    if (!coupon) {
        return { valid: false, message: `ไม่พบโค้ดส่วนลด "${cleanCode}" หรือโค้ดหมดอายุแล้ว` };
    }

    if (coupon.active === false) {
        return { valid: false, message: `โค้ดส่วนลด "${cleanCode}" ถูกปิดใช้งานชั่วคราว` };
    }

    if (coupon.expiresAt) {
        const exp = new Date(coupon.expiresAt + 'T23:59:59');
        if (!isNaN(exp.getTime()) && Date.now() > exp.getTime()) {
            return { valid: false, message: `โค้ดส่วนลด "${cleanCode}" หมดอายุการใช้งานแล้ว` };
        }
    }

    if (coupon.usageLimit && typeof coupon.usedCount === 'number' && coupon.usedCount >= coupon.usageLimit) {
        return { valid: false, message: `โค้ดส่วนลด "${cleanCode}" มีผู้ใช้สิทธิ์ครบตามจำนวนที่กำหนดแล้ว` };
    }

    const currentSubtotal = Math.max(0, subtotal || 0);
    const minSpend = Math.max(0, coupon.minSpend || 0);

    if (currentSubtotal < minSpend) {
        return {
            valid: false,
            message: `โค้ด "${cleanCode}" ใช้ได้เมื่อมียอดสั่งซื้อขั้นต่ำ ฿${minSpend.toFixed(2)} (ขาดอีก ฿${(minSpend - currentSubtotal).toFixed(2)})`
        };
    }

    const isPercent = (coupon.discountType === 'percent' || coupon.type === 'percentage' || coupon.type === 'percent');
    const discountVal = typeof coupon.discountValue === 'number' ? coupon.discountValue : (typeof coupon.value === 'number' ? coupon.value : 0);

    let discountAmount = 0;
    if (isPercent) {
        discountAmount = Math.round((currentSubtotal * discountVal / 100) * 100) / 100;
        if (coupon.maxDiscount && coupon.maxDiscount > 0) {
            discountAmount = Math.min(discountAmount, coupon.maxDiscount);
        }
    } else {
        discountAmount = Math.min(currentSubtotal, discountVal);
    }

    discountAmount = Math.max(0, Math.round(discountAmount * 100) / 100);
    const netTotal = Math.max(1, Math.round((currentSubtotal - discountAmount) * 100) / 100);

    return {
        valid: true,
        coupon: {
            ...coupon,
            discountType: isPercent ? 'percent' : 'fixed',
            type: isPercent ? 'percentage' : 'fixed',
            discountValue: discountVal,
            value: discountVal
        },
        code: coupon.code,
        title: coupon.title,
        type: isPercent ? 'percentage' : 'fixed',
        discountType: isPercent ? 'percent' : 'fixed',
        value: discountVal,
        discountValue: discountVal,
        discountAmount,
        netTotal,
        message: `ใช้โค้ด "${coupon.code}" สำเร็จ! ประหยัดไป ฿${discountAmount.toFixed(2)}`
    };
}

