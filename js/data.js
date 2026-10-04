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
        subtitle: "สิทธิ์ใช้งานส่วนตัว 1 ผู้ใช้ • ปลดล็อกทุกเครื่องมือโปร & เรนเดอร์ 4K ไม่มีลายน้ำ",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชีส่วนตัวเดี่ยว (Private Dedicated Account) สำหรับใช้งานคนเดียว ไม่แชร์ร่วมกับผู้อื่น สามารถปรับแต่งข้อมูลส่วนตัวได้\n• ฟังก์ชันและคุณสมบัติเด่น: ปลดล็อกฟังก์ชัน CapCut Pro เต็มพิกัด, ส่งออกวิดีโอความละเอียดสูง 4K 60fps ไม่มีลายน้ำ, ใช้งานคลังเสียงดนตรี เอฟเฟกต์ และเทมเพลตลิขสิทธิ์ Pro ได้ไม่จำกัด, ระบบตัดต่อพื้นหลัง AI อัตโนมัติและตัดเสียงรบกวนอัจฉริยะ\n• อุปกรณ์ที่รองรับ: รองรับการใช้งานทั้งบน Windows, macOS, iOS (iPhone/iPad) และ Android\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลเข้าสู่ระบบผ่านระบบอัตโนมัติทันทีหลังชำระเงิน พร้อมขั้นตอนการใช้งานเข้าใจง่าย\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะการใช้งานตลอด 30 วันเต็ม หากพบปัญหาทีมงานพร้อมแก้ไขหรือเปลี่ยนบัญชีใหม่ทันที"
    },
    {
        id: "cpc-02",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Pro (1 เดือน) - สิทธิ์ประหยัด",
        subtitle: "สิทธิ์เข้าใช้งานโปรไฟล์แยก • ปลดล็อกเครื่องมือ Pro เรนเดอร์คมชัดไร้ลายน้ำ ในราคาคุ้มค่า",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์เข้าใช้งานแบบโปรไฟล์แยก (Shared Profile Access) เหมาะสำหรับผู้ที่ต้องการใช้งานเครื่องมือ Pro ในราคาประหยัด คุ้มค่าที่สุด\n• ฟังก์ชันและคุณสมบัติเด่น: ปลดล็อกฟอนต์ เทมเพลต และเอฟเฟกต์ Pro ครบถ้วน, ส่งออกผลงานคมชัดโดยไม่มีลายน้ำ\n• ข้อแนะนำการใช้งาน: ใช้งานผ่านโปรไฟล์ส่วนตัวที่กำหนด โดยไม่ต้องแก้ไขข้อมูลหลักของบัญชี เพื่อคงสถานะความเสถียรและสิทธิ์การรับประกัน\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลเข้าใช้งานพร้อมคำแนะนำการล็อกอินอัตโนมัติทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลความต่อเนื่องตลอดระยะเวลา 30 วันเต็ม"
    },
    {
        id: "cpc-03",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut Team (1 เดือน) - สิทธิ์เวิร์กสเปซทีม",
        subtitle: "พื้นที่ทำงานร่วมกันบน Cloud • แชร์โปรเจกต์ วิดีโอ และเทมเพลตสำหรับทีมงานและองค์กร",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์ที่นั่งสำหรับทีมงาน (Team Workspace Seat License) รองรับการทำงานประสานงานร่วมกันอย่างเป็นระบบ\n• ฟังก์ชันและคุณสมบัติเด่น: ปลดล็อกฟังก์ชัน Pro ให้ทุกคนในทีม, แชร์ไฟล์โปรเจกต์และสื่อวิดีโอบน Cloud Storage กลางของทีมได้อย่างสะดวกรวดเร็ว ตรวจและส่งมอบงานได้แบบเรียลไทม์\n• เหมาะสำหรับ: ฟรีแลนซ์, คอนเทนต์ครีเอเตอร์, โปรดักชัน และดิจิทัลเอเจนซี\n• รูปแบบการจัดส่ง: ส่งมอบสิทธิ์เข้าสู่พื้นที่ทำงานของทีมทันที พร้อมคำแนะนำการเชิญและตั้งค่าสิทธิ์\n• มาตรฐานการรับประกัน: รับประกันการใช้งานระบบคลาวด์ทีมตลอดระยะเวลา 30 วัน"
    },
    {
        id: "cpc-04",
        brand: "CapCut",
        brandCode: "CPC",
        brandBadgeColor: "from-cyan-500 to-blue-600",
        title: "CapCut VIP / SVIP (1 เดือน) - สิทธิ์ขั้นสูง",
        subtitle: "สิทธิ์ระดับ VIP สูงสุด • ปลดล็อกฟังก์ชัน AI อัจฉริยะและระบบคลาวด์เรนเดอร์ความเร็วสูง",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์สมาชิกระดับ VIP / SVIP ชั้นสูง มอบขีดความสามารถในการตัดต่อที่เหนือกว่า\n• ฟังก์ชันและคุณสมบัติเด่น: เครื่องมือ AI แปลงสคริปต์ข้อความเป็นวิดีโอ (AI Script-to-Video), สร้างเสียงพากย์ AI หลายภาษาอย่างเป็นธรรมชาติ, คลังสติกเกอร์และแอนิเมชันระดับพรีเมียม, จัดลำดับความสำคัญในการเรนเดอร์ผ่าน Cloud Server ความเร็วสูง\n• รูปแบบการจัดส่ง: ดำเนินการเปิดสิทธิ์และส่งมอบข้อมูลเข้าใช้งานทันทีผ่านระบบอัตโนมัติ\n• มาตรฐานการรับประกัน: รับประกันความสมบูรณ์ของฟังก์ชันและสถานะ VIP ตลอด 30 วัน"
    },
    {
        id: "goo-ai-01",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - ลิงก์เปิดสิทธิ์",
        subtitle: "อัปเกรดตรงเข้า Gmail เดิมของคุณ • ปลอดภัยสูงสุด 100% ไม่ต้องเปิดเผยรหัสผ่าน",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: ลิงก์เปิดสิทธิ์ทางการ (Google One AI Premium Invite Link) อัปเกรดเข้าสู่บัญชี Gmail ส่วนตัวของท่านโดยตรง\n• ความเป็นส่วนตัวและความปลอดภัย: ปลอดภัยสูงสุด ไม่ต้องเปิดเผยรหัสผ่าน ข้อมูลอีเมล รูปภาพ และเอกสารบน Google Drive เป็นส่วนตัว 100%\n• สิทธิประโยชน์และฟังก์ชัน: เข้าใช้งานโมเดลเรือธง Gemini Advanced (Gemini 1.5/2.0 Pro) สำหรับคิดวิเคราะห์งานซับซ้อน เขียนโค้ด ร่างเอกสาร, พร้อมพื้นที่คลาวด์ Google One 2TB (Drive, Gmail, Photos) และระบบ AI ช่วยงานใน Docs/Gmail\n• รูปแบบการจัดส่ง: จัดส่งลิงก์เปิดสิทธิ์ทางการทันที พร้อมคู่มือการกดรับสิทธิ์ใน 1 นาที\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะการใช้งานครบ 30 วันเต็มโดยทีมงาน Supinkly"
    },
    {
        id: "goo-ai-02",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Ultra (Gemini Ultra 1 เดือน) - บัญชีวิจัยขั้นสูง",
        subtitle: "ขีดความสามารถประมวลผลระดับสูงสุด • วิเคราะห์เอกสารหนาและโปรเจกต์ซอร์สโค้ดขนาดใหญ่",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชีส่วนตัวระดับ Google Enterprise AI Dedicated Account สำหรับงานวิจัย งานวิเคราะห์ข้อมูล และนักพัฒนาซอฟต์แวร์\n• ฟังก์ชันและคุณสมบัติเด่น: รองรับหน้าต่างบริบท (Context Window) ขนาดใหญ่พิเศษมากกว่า 1 ล้านโทเค็น วิเคราะห์หนังสือทั้งเล่ม รายงานวิจัยหนา และโปรเจกต์ซอร์สโค้ดขนาดใหญ่ได้อย่างแม่นยำ พร้อมอัตราการตอบกลับที่รวดเร็วและทรงพลังที่สุด\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลบัญชีเฉพาะบุคคล ปลอดภัย พร้อมใช้งานได้ทันที\n• มาตรฐานการรับประกัน: ดูแลรับประกันความต่อเนื่องของบริการตลอดสัญญา 30 วัน"
    },
    {
        id: "goo-ai-03",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - สิทธิ์ประหยัด",
        subtitle: "สิทธิ์เข้าใช้งานราคาประหยัด • ใช้งาน Gemini 1.5 Pro เต็มประสิทธิภาพ เหมาะกับการศึกษา",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์เข้าใช้งานแบบร่วมราคาประหยัด (Budget Access) เหมาะสำหรับนักเรียน นักศึกษา หรือผู้ที่ต้องการทดลองใช้พลังของ AI เจนใหม่ในราคาสบายกระเป๋า\n• ฟังก์ชันและคุณสมบัติเด่น: สอบถาม วิเคราะห์ข้อมูล เขียนเนื้อหาบทความ แปลภาษา และร่างสคริปต์ด้วย Gemini 1.5 Pro ได้อย่างสะดวกรวดเร็ว\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลเข้าใช้งานพร้อมคู่มือการล็อกอินทันทีหลังยืนยันการชำระเงิน\n• มาตรฐานการรับประกัน: รับประกันดูแลความราบรื่นในการใช้งานตลอด 30 วัน"
    },
    {
        id: "goo-01",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google Drive 5TB + Gemini Advanced (1 เดือน)",
        subtitle: "พื้นที่คลาวด์ขนาดใหญ่ 5,000 GB พร้อมขุมพลัง Gemini Advanced ในบัญชีเดียว",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชีส่วนตัว Google Workspace Dedicated Account พร้อมความจุระดับองค์กร\n• พื้นที่จัดเก็บและความจุ: คลาวด์สตอเรจขนาดใหญ่ 5TB (5,000 GB) สำหรับสำรองข้อมูลสำคัญ, จัดเก็บไฟล์วิดีโอ 4K/8K, คลังรูปภาพ และข้อมูลธุรกิจได้อย่างมั่นใจ\n• สิทธิ์พิเศษ: รวมการเข้าใช้งานโมเดล Gemini Advanced สำหรับช่วยคิดและประมวลผลข้อมูลในตัวบัญชี\n• รูปแบบการจัดส่ง: จัดส่งบัญชีอีเมลและรหัสผ่านส่วนตัวทันที พร้อมใช้งานทันที\n• มาตรฐานการรับประกัน: รับประกันพื้นที่และความเสถียรของระบบคลาวด์ตลอด 30 วัน"
    },
    {
        id: "goo-02",
        brand: "Google",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google One Subscription Pro 5TB (18 เดือน) - Activation Link",
        subtitle: "เปิดสิทธิ์บนบัญชี Google ของท่านโดยตรง (On Your Own Account) • ดีลพิเศษ 18 เดือน",
        badge: "🔥 ดีลพิเศษ 18 เดือน",
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "18 เดือน (18 Months)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (PC, Mac, Mobile)",
        price: 249.00,
        originalPrice: 690.00,
        soldCount: 410,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: เปิดสิทธิ์ผ่าน Activation Link ทางการ อัปเกรดตรงเข้าสู่บัญชี Google ส่วนตัวของท่าน (Activate On Your Own Account)\n• สิทธิประโยชน์ที่ได้รับ: อัปเกรดพื้นที่จัดเก็บข้อมูล Google One Cloud เป็น 5TB (5,000 GB) ใช้งานร่วมกับ Google Drive, Gmail และ Google Photos พร้อมสิทธิ์เข้าใช้งาน Gemini Pro\n• ความปลอดภัยและความเป็นส่วนตัว: ปลอดภัยสูงสุด 100% ไม่ต้องเปิดเผยรหัสผ่าน ไม่ต้องสร้างอีเมลใหม่ และไม่ต้องย้ายโอนไฟล์ข้อมูลเดิม\n• ระยะเวลาของสิทธิ์: สิทธิ์การใช้งานระยะยาว 18 เดือน (Special Offer 18 Months)\n• รูปแบบการจัดส่ง: จัดส่งลิงก์ Activation Link พร้อมคู่มือขั้นตอนการกดรับสิทธิ์อย่างละเอียดทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะการใช้งาน 30 วันแรกตามมาตรฐานความปลอดภัยของบริการดิจิทัล"
    },
    {
        id: "grk-01",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (7 วัน) - บัญชีส่วนตัว",
        subtitle: "แพ็กเกจทดลอง 7 วัน • เข้าถึงข้อมูลเรียลไทม์บน X และเจนภาพด้วย Aurora Flux",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชีส่วนตัว X (Twitter) Premium พร้อมสิทธิ์เข้าใช้งานระบบปัญญาประดิษฐ์ xAI Grok ระยะเวลา 7 วัน\n• ฟังก์ชันและคุณสมบัติเด่น: ติดตามและวิเคราะห์ข้อมูลข่าวสาร ประเด็นร้อนรอบโลกแบบเรียลไทม์จากทวิตเตอร์, รองรับ Fun Mode และ Normal Mode, สร้างสรรค์รูปภาพ AI คุณภาพสูงคมชัดด้วยโมเดล Aurora Flux\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลการเข้าสู่ระบบส่วนตัวทันทีผ่านระบบอัตโนมัติ\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะการใช้งานเต็มระยะเวลา 7 วัน"
    },
    {
        id: "grk-02",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI Grok / SuperGrok (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "แพ็กเกจมาตรฐาน 1 เดือน • โมเดล Grok รุ่นล่าสุด โควต้าสูง ไร้โฆษณาบนหน้าฟีด X",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชีส่วนตัว X Premium+ ระดับสูงสุด ระยะเวลา 30 วัน ใช้งานเดี่ยวเต็มประสิทธิภาพ\n• ฟังก์ชันและคุณสมบัติเด่น: สิทธิ์เข้าถึงโมเดลปัญญาประดิษฐ์ Grok รุ่นล่าสุด, โควต้าคำสั่งระดับสูง, ประสบการณ์ใช้งานแพลตฟอร์ม X แบบไร้โฆษณาคั่น, เจนภาพ AI ความละเอียดสูงได้อย่างอิสระ เหมาะสำหรับงานวิจัย ข่าวสาร และการสร้างคอนเทนต์เชิงลึก\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลบัญชีพร้อมใช้งานส่วนตัวทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะบัญชีตลอด 30 วันเต็ม"
    },
    {
        id: "grk-03",
        brand: "Grok",
        brandCode: "GRK",
        brandBadgeColor: "from-slate-700 to-zinc-950",
        title: "xAI SuperGrok Heavy (1 เดือน) - โควต้าประมวลผลสูง",
        subtitle: "โควต้าคำสั่งระดับ Heavy Capacity • สำหรับงานเขียนโปรแกรมและการวิเคราะห์ข้อมูลปริมาณมาก",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชี SuperGrok ระดับ Heavy Capacity ออกแบบมาโดยเฉพาะสำหรับงานที่ต้องการการประมวลผลต่อเนื่องสูง\n• ฟังก์ชันและคุณสมบัติเด่น: ขยายขีดจำกัด Rate Limit รองรับการป้อนคำสั่งและวิเคราะห์โค้ดจำนวนมหาศาลได้อย่างลื่นไหล เหมาะสำหรับโปรแกรมเมอร์และทีมวิเคราะห์ข้อมูล\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลบัญชีเฉพาะบุคคลทันทีหลังชำระเงิน\n• มาตรฐานการรับประกัน: รับประกันดูแลความเสถียรของระบบตลอด 30 วัน"
    },
    {
        id: "cld-01",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - บัญชีส่วนตัว",
        subtitle: "เข้าใช้งาน Claude 3.5 Sonnet เต็มสิทธิ์ • โควต้ามากกว่าฟรี 5 เท่า พร้อม Artifacts & Projects",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: บัญชีส่วนตัวเดี่ยว (Dedicated Private Account) สำหรับผู้ใช้ 1 ท่าน ข้อมูลการแชทและโปรเจกต์เป็นส่วนตัว 100%\n• ขีดความสามารถระดับแนวหน้า: เข้าถึงโมเดลอัจฉริยะอันดับหนึ่งอย่าง Claude 3.5 Sonnet และ Claude 3 Opus, โควต้าการใช้งานมากกว่าบัญชีฟรีถึง 5 เท่า, สิทธิ์เข้าใช้งานสม่ำเสมอแม้ในช่วงเวลาเร่งด่วน\n• ฟังก์ชันพรีเมียม: รองรับฟังก์ชัน Artifacts สำหรับรันโค้ดและพรีวิวหน้าเว็บสดได้ในหน้าต่างแชท, และระบบ Projects สำหรับป้อนเอกสารอ้างอิงและคลังความรู้เฉพาะทาง\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลบัญชีส่วนบุคคลอัตโนมัติทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะการใช้งานครบ 30 วันเต็ม"
    },
    {
        id: "cld-02",
        brand: "Claude",
        brandCode: "CLD",
        brandBadgeColor: "from-amber-600 to-orange-700",
        title: "Anthropic Claude Pro (1 เดือน) - สิทธิ์ประหยัด",
        subtitle: "สิทธิ์เข้าใช้งานราคาประหยัด • สัมผัสความฉลาดของ Claude 3.5 Sonnet ได้อย่างคุ้มค่า",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์เข้าใช้งานแบบร่วมราคาประหยัด (Budget Profile) เหมาะสำหรับผู้เริ่มต้นศึกษาหรือใช้งานทั่วไปในงบสบายกระเป๋า\n• ฟังก์ชันและคุณสมบัติเด่น: ใช้งานโมเดล Claude 3.5 Sonnet ที่มีความโดดเด่นด้านการเขียนโค้ด งานแปลภาษาที่สละสลวยเป็นธรรมชาติ และการวิเคราะห์เนื้อหาเชิงลึก\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลการเข้าสู่ระบบพร้อมใช้งานทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลความพร้อมใช้งานตลอด 30 วัน"
    },
    {
        id: "adb-01",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Acrobat Pro DC (1 เดือน) - ลิขสิทธิ์แท้",
        subtitle: "จัดการเอกสาร PDF เต็มรูปแบบ • แก้ไขข้อความ แปลงไฟล์ สแกน OCR และเซ็นชื่อดิจิทัล",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์การใช้งานโปรแกรม Adobe Acrobat Pro DC ตัวเต็ม ลิขสิทธิ์ถูกต้อง\n• ฟังก์ชันและคุณสมบัติเด่น: แก้ไขข้อความ รูปภาพ และจัดหน้าเอกสาร PDF ได้อย่างอิสระ, แปลงไฟล์ PDF เป็น Word, Excel, PowerPoint โดยคงฟอนต์และโครงสร้างตารางได้อย่างแม่นยำ, ระบบสแกนเอกสารด้วย OCR แปลงภาพเอกสารเป็นข้อความค้นหาได้, ระบบสร้างลายเซ็นอิเล็กทรอนิกส์และแบบฟอร์มที่มีผลทางกฎหมาย\n• อุปกรณ์ที่รองรับ: รองรับการใช้งานทั้งบน Windows, macOS และอุปกรณ์พกพา\n• รูปแบบการจัดส่ง: ส่งมอบข้อมูลสิทธิ์การใช้งานพร้อมคำแนะนำการดาวน์โหลดและติดตั้งทันที\n• มาตรฐานการรับประกัน: รับประกันสิทธิ์การใช้งานตลอดอายุสัญญา 30 วัน"
    },
    {
        id: "adb-02",
        brand: "Adobe",
        brandCode: "ADB",
        brandBadgeColor: "from-red-600 to-rose-800",
        title: "Adobe Creative Cloud All Apps (1 เดือน) + 100GB",
        subtitle: "รวมโปรแกรมสร้างสรรค์กว่า 20 แอป (Photoshop, Illustrator, Premiere Pro) + Firefly AI",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์การใช้งาน Adobe Creative Cloud All Apps ลิขสิทธิ์แท้ เปิดใช้งานผ่านระบบทางการของ Adobe\n• สิ่งที่ได้รับ: ใช้งานโปรแกรมสร้างสรรค์ชั้นนำระดับโลกครบวงจรกว่า 20 แอปพลิเคชัน (เช่น Photoshop, Illustrator, Premiere Pro, After Effects, InDesign, Lightroom ฯลฯ) พร้อมพื้นที่จัดเก็บข้อมูล Adobe Cloud 100GB และเครดิตการสร้างสรรค์ด้วย Generative AI (Adobe Firefly)\n• การติดตั้งและการอัปเดต: ดาวน์โหลดและติดตั้งผ่านโปรแกรมทางการ Adobe Creative Cloud Desktop รองรับการอัปเดตเวอร์ชันล่าสุดเสมอ ใช้งานได้ 2 อุปกรณ์พร้อมกัน (PC / Mac)\n• รูปแบบการจัดส่ง: จัดส่งขั้นตอนเปิดรับสิทธิ์ผ่านระบบอัตโนมัติทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะสิทธิ์การใช้งานแท้ตลอด 30 วันเต็ม"
    },
    {
        id: "ms-01",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Windows 11 Pro / Home - คีย์แท้ถาวร (OEM License)",
        subtitle: "รหัสลิขสิทธิ์ดิจิทัล 25 หลักสำหรับ 1 PC • เปิดใช้งานถาวรตลอดชีพ อัปเดตทางการจาก Microsoft",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: รหัสลิขสิทธิ์ดิจิทัลแท้ 25 หลัก (Genuine 25-Digit OEM License Key) สำหรับคอมพิวเตอร์ 1 เครื่อง\n• ขอบเขตการใช้งาน: เปิดใช้งาน Windows 11 Pro ได้อย่างสมบูรณ์แบบถาวรตลอดชีพ (สิทธิ์ผูกติดกับฮาร์ดแวร์/เมนบอร์ด) รองรับทั้งการลงวินโดวส์ใหม่แบบหมดจด (Clean Install) และการอัปเกรดจาก Windows 11 Home เป็น Pro ได้ทันทีโดยไม่ต้องลงระบบใหม่\n• ความปลอดภัยและความถูกต้อง: ดาวน์โหลดไฟล์ติดตั้ง ISO แท้ได้โดยตรงจากเว็บไซต์ทางการของ Microsoft รองรับ Windows Update และรับแพตช์ความปลอดภัยอย่างเป็นทางการ 100%\n• รูปแบบการจัดส่ง: จัดส่งรหัสคีย์ 25 หลักผ่านระบบทันที พร้อมคู่มือขั้นตอนการใส่คีย์ภาษาไทยเข้าใจง่าย\n• มาตรฐานการรับประกัน: รับประกันการเปิดใช้งาน (Activation Guarantee) ผ่านเซิร์ฟเวอร์ Microsoft 100% ตลอดอายุการใช้งาน"
    },
    {
        id: "ms-02",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft 365 Personal (1 เดือน) + 1TB OneDrive Cloud",
        subtitle: "ชุดโปรแกรมออฟฟิศแท้ (Word, Excel, PowerPoint) + พื้นที่คลาวด์ 1,000 GB ปลอดภัย",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์การใช้งานชุดโปรแกรมสำนักงานระดับพรีเมียม Microsoft 365 ลิขสิทธิ์แท้ ระยะเวลา 1 เดือน\n• ซอฟต์แวร์ที่ได้รับ: ใช้งานโปรแกรม Word, Excel, PowerPoint, Outlook, OneNote เวอร์ชันล่าสุด รองรับการลงชื่อเข้าใช้งานได้สูงสุด 5 อุปกรณ์พร้อมกัน ทั้งคอมพิวเตอร์ โน้ตบุ๊ก แท็บเล็ต iPad และสมาร์ตโฟน\n• คลาวด์และความปลอดภัย: มาพร้อมพื้นที่จัดเก็บข้อมูลบนคลาวด์ OneDrive ขนาด 1TB (1,000 GB) พร้อมระบบความปลอดภัยขั้นสูง ป้องกันและกู้คืนไฟล์จาก Ransomware\n• รูปแบบการจัดส่ง: จัดส่งข้อมูลสิทธิ์และคู่มือการตั้งค่าอัตโนมัติทันที\n• มาตรฐานการรับประกัน: รับประกันดูแลความสมบูรณ์ของระบบตลอด 30 วัน"
    },
    {
        id: "ms-03",
        brand: "Microsoft",
        brandCode: "MS",
        brandBadgeColor: "from-blue-600 to-cyan-700",
        title: "Microsoft Copilot Pro (1 เดือน) - สิทธิ์ผู้ช่วย AI ส่วนตัว",
        subtitle: "ผู้ช่วย AI อัจฉริยะใน Word, Excel, PowerPoint • เข้าถึง GPT-4o และสร้างภาพ DALL-E 3 เร็วพิเศษ",
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
        description: "【ข้อมูลผลิตภัณฑ์และการรับประกัน】\n• สิทธิ์การใช้งาน: สิทธิ์การใช้งาน Microsoft Copilot Pro ผู้ช่วยปัญญาประดิษฐ์ระดับพรีเมียมสำหรับยกระดับการทำงาน\n• ฟังก์ชันการทำงาน: ผสานการทำงานร่วมกับโปรแกรม Microsoft 365 (Word, Excel, PowerPoint, Outlook) โดยตรง ช่วยร่างเอกสาร สรุปประเด็น วิเคราะห์สเปรดชีต และสร้างสไลด์นำเสนอได้อย่างมีประสิทธิภาพ\n• สิทธิ์ประโยชน์ด้าน AI: เข้าถึงโมเดลปัญญาประดิษฐ์รุ่นล่าสุด GPT-4o ได้อย่างรวดเร็วแม้ในช่วงเวลาที่มีผู้ใช้งานหนาแน่น พร้อมโควต้าเร่งความเร็วการสร้างรูปภาพด้วย DALL-E 3 สูงถึง 100 บูสต์ต่อวัน\n• รูปแบบการจัดส่ง: ส่งมอบข้อมูลการเข้าใช้งานส่วนบุคคลทันทีหลังชำระเงิน\n• มาตรฐานการรับประกัน: รับประกันดูแลสถานะการใช้งานครบ 30 วันเต็ม"
    }
];

// Ensure every master product has banner image and guaranteed default stock (50 pcs minimum)
PRODUCTS.forEach(p => {
    if (!p.image) {
        p.image = `images/products/${p.id}.jpg`;
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
        marketCostTHB
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

