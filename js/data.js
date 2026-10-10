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
        id: "goo-02",
        brand: "Google One",
        brandCode: "GOO",
        brandBadgeColor: "from-blue-500 via-green-500 to-yellow-500",
        title: "Google One Subscription Pro 5TB (18 เดือน) - Activation Link",
        subtitle: "เปิดสิทธิ์บนบัญชี Google ของคุณโดยตรง • คลาวด์ 5TB ยาวนาน 18 เดือน เฉลี่ยเพียง 14 บาท/วัน",
        badge: "🔥 ดีลพิเศษ 18 เดือน",
        isHighlight: true,
        type: "ลิงก์เปิดสิทธิ์ (Link)",
        typeKey: "link",
        duration: "18 เดือน (18 Months)",
        region: "Global (ใช้งานได้ทั่วโลก)",
        devices: "ทุกอุปกรณ์ (PC, Mac, Mobile)",
        price: 250.00,
        originalPrice: 690.00,
        soldCount: 410,
        rating: 5.0,
        deliveryType: "instant",
        warranty: "30 วัน",
        description: "• เปิดสิทธิ์ตรงเข้า Gmail เดิมของคุณ ไม่ต้องย้ายข้อมูล ไม่ต้องเปิดเผยรหัสผ่าน\n• เพิ่มพื้นที่ Google One 5TB (5,000 GB) ใช้กับ Drive, Gmail, Photos ยาวนาน 18 เดือน\n• ปลอดภัย 100% รับสิทธิ์ผ่านลิงก์ทางการใน 1 นาที พร้อมสิทธิ์ใช้งาน Gemini Pro"
    },
    {
        id: "goo-ai-01",
        brand: "Google AI",
        brandCode: "GOO",
        brandBadgeColor: "from-amber-400 to-red-500",
        title: "Google AI Pro (Gemini Advanced 1 เดือน) - Activation Link",
        subtitle: "อัปเกรดเข้า Gmail ของคุณโดยตรง • ปลอดภัย 100% พร้อมคลาวด์ 2TB",
        badge: "⭐ แนะนำยอดนิยม",
        isHighlight: true,
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
    }
];

// Helper to detect broken or legacy 404 G2G URLs
function isBrokenOrLegacyG2GUrl(url) {
    if (!url || typeof url !== 'string') return true;
    const clean = url.trim();
    if (clean.includes('/categories?q=') || clean.includes('/search?q=') || /\/categories\/[a-z0-9\-]+-accounts\b/i.test(clean) || clean === 'https://www.g2g.com' || clean === 'https://www.g2g.com/') {
        return true;
    }
    return false;
}

// Ensure every master product has raw G2G title, direct link, and guaranteed default stock (50 pcs minimum)
PRODUCTS.forEach(p => {
    if (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[p.id]) {
        p.g2gRawTitle = G2G_MARKET_FEED.benchmarks[p.id].title || '';
        p.g2gUrl = G2G_MARKET_FEED.benchmarks[p.id].g2gUrl || '';
    }
    if (typeof p.stock !== 'number') {
        const benchmarkStock = (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[p.id]?.g2gStock);
        p.stock = benchmarkStock || 50;
    }
});

// Auto-clean legacy broken G2G links from custom overrides in localStorage
try {
    const rawPrices = localStorage.getItem('supinkly_custom_prices');
    if (rawPrices) {
        const parsed = JSON.parse(rawPrices);
        let updated = false;
        for (const k in parsed) {
            if (parsed[k] && parsed[k].g2gUrl && isBrokenOrLegacyG2GUrl(parsed[k].g2gUrl)) {
                delete parsed[k].g2gUrl;
                updated = true;
            }
        }
        if (updated) localStorage.setItem('supinkly_custom_prices', JSON.stringify(parsed));
    }
    const rawProds = localStorage.getItem('supinkly_custom_products');
    if (rawProds) {
        const parsed = JSON.parse(rawProds);
        let updated = false;
        for (const k in parsed) {
            if (parsed[k] && parsed[k].g2gUrl && isBrokenOrLegacyG2GUrl(parsed[k].g2gUrl)) {
                delete parsed[k].g2gUrl;
                updated = true;
            }
        }
        if (updated) localStorage.setItem('supinkly_custom_products', JSON.stringify(parsed));
    }
} catch (e) {}

function getCustomProducts() {
    try {
        return JSON.parse(localStorage.getItem('supinkly_custom_products') || '{}');
    } catch (e) {
        return {};
    }
}

// Look up guaranteed product details & live stock from Master Catalog (with custom title, description, price, delete flags)
function getMasterProduct(productId) {
    if (!productId) return null;
    let product = PRODUCTS.find(p => p.id === productId);

    const customProducts = getCustomProducts();
    const customProd = customProducts[productId];

    // Support newly created custom products
    if (!product && customProd) {
        product = {
            id: productId,
            brand: customProd.brand || "AI Tools",
            brandCode: (customProd.brand || "AI").slice(0, 3).toUpperCase(),
            brandBadgeColor: "from-pink-500 to-purple-600",
            title: customProd.title || productId,
            subtitle: customProd.subtitle || "",
            badge: customProd.badge || "",
            type: customProd.type || "บัญชีส่วนตัว (Private)",
            typeKey: "private",
            duration: customProd.duration || "1 เดือน (30 วัน)",
            region: "Global (ใช้งานได้ทั่วโลก)",
            devices: customProd.devices || "iOS • Android • PC",
            price: typeof customProd.price === 'number' ? customProd.price : 99,
            originalPrice: typeof customProd.originalPrice === 'number' ? customProd.originalPrice : 159,
            soldCount: 0,
            rating: 5.0,
            deliveryType: "instant",
            warranty: customProd.warranty || "30 วัน",
            description: customProd.description || "",
            image: null
        };
    }

    if (!product) return null;

    let title = product.title;
    let subtitle = product.subtitle || '';
    let description = product.description || '';
    let brand = product.brand || 'AI Tools';
    let type = product.type || 'บัญชีส่วนตัว (Private)';
    let duration = product.duration || '1 เดือน (30 วัน)';
    let devices = product.devices || 'iOS • Android • PC';
    let warranty = product.warranty || '30 วัน';
    let badge = product.badge || '';
    let price = product.price;
    let originalPrice = product.originalPrice;
    let stock = product.stock || 50;
    let marketCostTHB = product.marketCostTHB || 0;
    let g2gRawTitle = product.g2gRawTitle || product.title;
    let g2gUrl = product.g2gUrl || '';
    let deleted = false;

    // Check G2G market benchmark default if available
    if (typeof G2G_MARKET_FEED !== 'undefined' && G2G_MARKET_FEED.benchmarks && G2G_MARKET_FEED.benchmarks[productId]) {
        const benchmark = G2G_MARKET_FEED.benchmarks[productId];
        if (benchmark.title) g2gRawTitle = benchmark.title;
        if (benchmark.g2gUrl && !isBrokenOrLegacyG2GUrl(benchmark.g2gUrl)) {
            g2gUrl = benchmark.g2gUrl;
        }
        if (typeof benchmark.g2gStock === 'number') {
            stock = benchmark.g2gStock;
        }
        if (typeof benchmark.baseCostUSD === 'number') {
            const fxRate = (typeof G2G_SYNC !== 'undefined' && G2G_SYNC.currentExchangeRate) ? G2G_SYNC.currentExchangeRate : 36.50;
            marketCostTHB = Math.round(benchmark.baseCostUSD * fxRate * 100) / 100;
        }
    }

    // Apply customProducts overrides (Title, Subtitle, Description, Brand, Type, Duration, Warranty, Devices, Delete)
    let isHighlight = !!product.isHighlight;
    if (customProd) {
        if (customProd.title) title = customProd.title;
        if (customProd.subtitle !== undefined) subtitle = customProd.subtitle;
        if (customProd.description !== undefined) description = customProd.description;
        if (customProd.brand) brand = customProd.brand;
        if (customProd.type) type = customProd.type;
        if (customProd.duration) duration = customProd.duration;
        if (customProd.devices) devices = customProd.devices;
        if (customProd.warranty) warranty = customProd.warranty;
        if (typeof customProd.price === 'number') price = customProd.price;
        if (typeof customProd.originalPrice === 'number') originalPrice = customProd.originalPrice;
        if (typeof customProd.badge === 'string') badge = customProd.badge;
        if (customProd.isHighlight !== undefined) isHighlight = !!customProd.isHighlight;
        if (customProd.g2gUrl && !isBrokenOrLegacyG2GUrl(customProd.g2gUrl)) {
            g2gUrl = customProd.g2gUrl;
        }
        if (customProd.deleted === true) deleted = true;
    }

    // Apply customPrices overrides
    try {
        const customPrices = JSON.parse(localStorage.getItem('supinkly_custom_prices') || '{}');
        const custom = customPrices && customPrices[productId];
        if (custom) {
            const hasCustomProdPrice = customProd && typeof customProd.price === 'number';
            if (custom.manualOverride === true || !hasCustomProdPrice) {
                if (typeof custom.price === 'number') price = custom.price;
                if (typeof custom.originalPrice === 'number') originalPrice = custom.originalPrice;
            }
            if (typeof custom.badge === 'string') badge = custom.badge;
            if (custom.isHighlight !== undefined) isHighlight = !!custom.isHighlight;
            if (typeof custom.g2gStockAvailable === 'number' && custom.g2gStockAvailable > 0) stock = custom.g2gStockAvailable;
            if (typeof custom.marketCostTHB === 'number') marketCostTHB = custom.marketCostTHB;
            if (typeof custom.g2gRawTitle === 'string' && custom.g2gRawTitle.trim()) {
                g2gRawTitle = custom.g2gRawTitle.trim();
            }
            if (typeof custom.g2gUrl === 'string' && custom.g2gUrl && !isBrokenOrLegacyG2GUrl(custom.g2gUrl)) {
                g2gUrl = custom.g2gUrl;
            }
        }
    } catch (e) {}

    // Ensure valid, working G2G sourcing link (guaranteed 100% no 404)
    if (!g2gUrl || isBrokenOrLegacyG2GUrl(g2gUrl)) {
        const isCapcut = String(productId).startsWith('cpc-') || (brand || '').toLowerCase().includes('capcut');
        g2gUrl = isCapcut 
            ? 'https://www.g2g.com/categories/capcut' 
            : `https://www.google.com/search?q=${encodeURIComponent('site:g2g.com ' + (g2gRawTitle || title))}`;
    }

    return {
        ...product,
        id: productId,
        title,
        subtitle,
        description,
        brand,
        type,
        duration,
        devices,
        warranty,
        image: null,
        badge,
        isHighlight,
        price,
        originalPrice,
        stock: stock || 50,
        marketCostTHB,
        g2gRawTitle,
        g2gUrl,
        deleted
    };
}

function getAllMasterProducts(includeDeleted = false) {
    const customProducts = getCustomProducts();
    const result = [];
    const seenIds = new Set();

    // 1. Base catalog PRODUCTS
    PRODUCTS.forEach(p => {
        seenIds.add(p.id);
        const master = getMasterProduct(p.id);
        if (master) {
            if (includeDeleted || !master.deleted) {
                result.push(master);
            }
        }
    });

    // 2. Newly added custom products
    Object.keys(customProducts).forEach(id => {
        if (!seenIds.has(id)) {
            const master = getMasterProduct(id);
            if (master) {
                if (includeDeleted || !master.deleted) {
                    result.push(master);
                }
            }
        }
    });

    return result;
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

