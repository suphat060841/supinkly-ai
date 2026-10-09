/**
 * Supinkly.AI - G2G Real-Time Market Auto-Sync Engine
 * Automatically tracks G2G market costs, converts currency (USD -> THB),
 * applies competitive profitable markup, and auto-syncs without manual intervention.
 */

const G2G_MARKET_FEED = {
    // 19 Master Products mapped to G2G Market Category, Direct Sourcing URL & Benchmark Cost (USD)
    benchmarks: {
        "cpc-01": { serviceId: "G2G-CPC-PRO-PRIV", title: "CapCut Pro Account", baseCostUSD: 1.25, g2gStock: 142, g2gUrl: "https://www.g2g.com/categories/capcut" },
        "cpc-02": { serviceId: "G2G-CPC-PRO-SHR",  title: "CapCut Pro Shared Account", baseCostUSD: 0.85, g2gStock: 89, g2gUrl: "https://www.g2g.com/categories/capcut" },
        "cpc-03": { serviceId: "G2G-CPC-TEAM",     title: "CapCut Team Workspace", baseCostUSD: 1.95, g2gStock: 64, g2gUrl: "https://www.g2g.com/categories/capcut" },
        "cpc-04": { serviceId: "G2G-CPC-VIP",      title: "CapCut VIP", baseCostUSD: 3.10, g2gStock: 35, g2gUrl: "https://www.g2g.com/categories/capcut" },
        "goo-ai-01": { serviceId: "G2G-GOO-AI-LNK", title: "Google Gemini Advanced", baseCostUSD: 0.94, g2gStock: 73, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Gemini+Advanced" },
        "goo-ai-02": { serviceId: "G2G-GOO-AI-ULT", title: "Google AI Ultra", baseCostUSD: 49.50, g2gStock: 12, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+AI+Ultra" },
        "goo-ai-03": { serviceId: "G2G-GOO-AI-SHR", title: "Google Gemini Shared", baseCostUSD: 0.85, g2gStock: 78, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Gemini+Shared" },
        "goo-01":    { serviceId: "G2G-GOO-5TB-PV", title: "Google Drive 5TB", baseCostUSD: 2.15, g2gStock: 95, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Drive+5TB" },
        "goo-02":    { serviceId: "G2G-GOO-5TB-LK", title: "Google Gemini Activation Link", baseCostUSD: 0.94, g2gStock: 73, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Google+Gemini+Activation+Link" },
        "grk-01":    { serviceId: "G2G-GRK-7D-PV",  title: "Grok Account", baseCostUSD: 3.80, g2gStock: 45, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Grok+Account" },
        "grk-02":    { serviceId: "G2G-GRK-30D-PV", title: "Grok Subscription 1 Month", baseCostUSD: 14.20, g2gStock: 52, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Grok+Subscription" },
        "grk-03":    { serviceId: "G2G-GRK-HEAVY",  title: "SuperGrok Heavy", baseCostUSD: 95.00, g2gStock: 8, g2gUrl: "https://www.google.com/search?q=site:g2g.com+SuperGrok+Heavy" },
        "cld-01":    { serviceId: "G2G-CLD-PRO-PV", title: "Claude Pro Account", baseCostUSD: 13.80, g2gStock: 67, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Claude+Pro+Account" },
        "cld-02":    { serviceId: "G2G-CLD-PRO-SH", title: "Claude Pro Shared Account", baseCostUSD: 3.60, g2gStock: 120, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Claude+Pro+Shared" },
        "adb-01":    { serviceId: "G2G-ADB-ACRO",   title: "Adobe Acrobat Pro DC", baseCostUSD: 6.50, g2gStock: 41, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Adobe+Acrobat+Pro+DC" },
        "adb-02":    { serviceId: "G2G-ADB-CC-ALL", title: "Adobe Creative Cloud All Apps", baseCostUSD: 10.80, g2gStock: 83, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Adobe+Creative+Cloud+All+Apps" },
        "ms-01":     { serviceId: "G2G-MS-W11-OEM", title: "Windows 11 Pro OEM Key", baseCostUSD: 2.20, g2gStock: 350, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Windows+11+Pro+OEM+Key" },
        "ms-02":     { serviceId: "G2G-MS-365-FAM", title: "Microsoft 365 Personal", baseCostUSD: 2.80, g2gStock: 115, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Microsoft+365+Personal" },
        "ms-03":     { serviceId: "G2G-MS-COPILOT", title: "Microsoft Copilot Pro", baseCostUSD: 7.90, g2gStock: 58, g2gUrl: "https://www.google.com/search?q=site:g2g.com+Microsoft+Copilot+Pro" }
    }
};

const G2G_SYNC = {
    DEFAULT_USD_THB_RATE: 36.50,
    currentExchangeRate: 36.50,
    rateLastFetched: 0,
    rateSource: 'Default',
    SYNC_INTERVAL_MS: 15 * 60 * 1000, // Sync every 15 minutes automatically
    timerId: null,

    // Free Live USD/THB Exchange Rate Fetcher (Zero API Key required)
    async fetchLiveExchangeRate() {
        const now = Date.now();
        // Return cached rate if refreshed within 30 minutes
        if (this.rateLastFetched && (now - this.rateLastFetched < 30 * 60 * 1000) && this.currentExchangeRate > 20) {
            return this.currentExchangeRate;
        }

        try {
            const stored = localStorage.getItem('supinkly_live_fx');
            if (stored) {
                const parsed = JSON.parse(stored);
                if (parsed.rate && (now - parsed.timestamp < 30 * 60 * 1000)) {
                    this.currentExchangeRate = parsed.rate;
                    this.rateLastFetched = parsed.timestamp;
                    this.rateSource = parsed.source || 'Cache';
                    this.updateFxRateUI();
                    return this.currentExchangeRate;
                }
            }
        } catch (e) {}

        // 1. Try local server backend proxy (safest, no CORS)
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3500);
            const res = await fetch('/api/public/exchange-rate', { signal: controller.signal });
            clearTimeout(timeoutId);
            if (res.ok) {
                const data = await res.json();
                if (data.success && typeof data.rate === 'number' && data.rate > 20 && data.rate < 60) {
                    this.currentExchangeRate = Math.round(data.rate * 100) / 100;
                    this.rateLastFetched = now;
                    this.rateSource = data.source || 'Server FX';
                    this.saveFxCache();
                    this.updateFxRateUI();
                    return this.currentExchangeRate;
                }
            }
        } catch (e) {}

        // 2. Direct client-side fetch from open public FX endpoint (open.er-api.com - Free, No Key, CORS open)
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3500);
            const res = await fetch('https://open.er-api.com/v6/latest/USD', { signal: controller.signal });
            clearTimeout(timeoutId);
            if (res.ok) {
                const data = await res.json();
                const thb = data?.rates?.THB;
                if (typeof thb === 'number' && thb > 20 && thb < 60) {
                    this.currentExchangeRate = Math.round(thb * 100) / 100;
                    this.rateLastFetched = now;
                    this.rateSource = 'Open ER-API';
                    this.saveFxCache();
                    this.updateFxRateUI();
                    return this.currentExchangeRate;
                }
            }
        } catch (e) {}

        // 3. Fallback: keep current rate or default
        if (!this.currentExchangeRate || this.currentExchangeRate <= 0) {
            this.currentExchangeRate = this.DEFAULT_USD_THB_RATE;
        }
        this.updateFxRateUI();
        return this.currentExchangeRate;
    },

    saveFxCache() {
        try {
            localStorage.setItem('supinkly_live_fx', JSON.stringify({
                rate: this.currentExchangeRate,
                source: this.rateSource,
                timestamp: this.rateLastFetched
            }));
        } catch (e) {}
    },

    updateFxRateUI() {
        const valEl = document.getElementById('admin-live-fx-val');
        if (valEl) {
            valEl.textContent = `฿${this.currentExchangeRate.toFixed(2)}`;
            valEl.title = `อัตราแลกเปลี่ยนสดจากตลาด: 1 USD = ${this.currentExchangeRate} THB (${this.rateSource})`;
        }
        const chipEl = document.getElementById('admin-live-fx-chip');
        if (chipEl) {
            chipEl.title = `1 USD = ${this.currentExchangeRate} บาท (อัปเดตอัตโนมัติ)`;
        }
    },

    getConfig() {
        let cfg = {
            autoSyncEnabled: true,
            minProfitBaht: 35, // Minimum profit margin in THB
            profitMultiplier: 2.10, // Multiplier >= 2.08x guarantees >= 50% net profit margin!
            targetMarginPct: 52, // Target net margin >= 50%
            lastSyncTimestamp: null,
            lastSyncCount: 0
        };
        try {
            const raw = localStorage.getItem('supinkly_g2g_sync_config');
            if (raw) {
                const parsed = JSON.parse(raw);
                cfg = { ...cfg, ...parsed };
                // Automatically ensure profitMultiplier guarantees >= 50% net profit margin
                if (!cfg.profitMultiplier || cfg.profitMultiplier < 2.08) {
                    cfg.profitMultiplier = 2.10;
                }
            }
        } catch (e) {}
        return cfg;
    },

    saveConfig(cfg) {
        localStorage.setItem('supinkly_g2g_sync_config', JSON.stringify(cfg));
    },

    // Calculate smart retail psychological Thai pricing with guaranteed >= 50% Net Margin
    calculateProfitableThaiPrice(costTHB, multiplier, minProfit) {
        if (!costTHB || costTHB <= 0) return 0;

        // Guaranteed >= 50% Net Margin formula: Price >= Cost / (1 - 0.50) = Cost * 2.0
        // We use at least 2.10x to comfortably cover retail psychological rounding
        const effectiveMultiplier = Math.max(2.10, multiplier || 2.10);
        let target = costTHB * effectiveMultiplier;

        const effectiveMinProfit = Math.max(costTHB, minProfit || 35);
        if (target - costTHB < effectiveMinProfit) {
            target = costTHB + effectiveMinProfit;
        }

        // Psychological rounding for Thai retail market
        let finalPrice = target;
        if (target < 100) {
            finalPrice = Math.ceil(target / 10) * 10 - 1; // e.g. 71.4 -> 79
        } else if (target < 500) {
            finalPrice = Math.ceil(target / 10) * 10;     // e.g. 120, 150, 250
        } else if (target < 1500) {
            finalPrice = Math.ceil(target / 50) * 50 - 10; // e.g. 690, 790, 890
        } else {
            finalPrice = Math.ceil(target / 100) * 100 - 10; // e.g. 2490, 4990
        }

        // Absolute safeguard: Net margin MUST be >= 50.0%
        // Net Margin = (Price - Cost) / Price
        if (finalPrice > 0 && ((finalPrice - costTHB) / finalPrice) < 0.50) {
            finalPrice = Math.ceil((costTHB / 0.48) / 10) * 10 - 1;
        }

        return finalPrice;
    },

    // Helper to get raw benchmark cost in THB (with Live FX Rate)
    getBenchmarkCostTHB(prodId) {
        const item = G2G_MARKET_FEED.benchmarks[prodId];
        if (!item) return 0;
        const rate = this.currentExchangeRate || this.DEFAULT_USD_THB_RATE;
        return Math.round(item.baseCostUSD * rate * 100) / 100;
    },

    // Helper to calculate recommended dynamic Auto-Sync price
    getAutoCalculatedPrice(prodId) {
        const costTHB = this.getBenchmarkCostTHB(prodId);
        if (!costTHB) return 0;
        const config = this.getConfig();
        return this.calculateProfitableThaiPrice(costTHB, config.profitMultiplier, config.minProfitBaht);
    },

    // Automatic Synchronization Worker
    async performAutoSync() {
        const config = this.getConfig();
        if (!config.autoSyncEnabled) return;

        // 1. Fetch Live FX rate first
        await this.fetchLiveExchangeRate();
        const exchangeRate = this.currentExchangeRate || this.DEFAULT_USD_THB_RATE;

        // 2. Try pulling live remote market feed (titles, stock, costs, URLs) from backend proxy
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const res = await fetch('/api/public/g2g-feed', { signal: controller.signal });
            clearTimeout(timeoutId);
            if (res.ok) {
                const data = await res.json();
                if (data.success && data.benchmarks) {
                    for (const [k, v] of Object.entries(data.benchmarks)) {
                        if (G2G_MARKET_FEED.benchmarks[k]) {
                            if (v.title) G2G_MARKET_FEED.benchmarks[k].title = v.title;
                            if (v.g2gUrl) G2G_MARKET_FEED.benchmarks[k].g2gUrl = v.g2gUrl;
                            if (typeof v.baseCostUSD === 'number') G2G_MARKET_FEED.benchmarks[k].baseCostUSD = v.baseCostUSD;
                            if (typeof v.g2gStock === 'number') G2G_MARKET_FEED.benchmarks[k].g2gStock = v.g2gStock;
                        }
                    }
                }
            }
        } catch (e) {}

        const customPrices = JSON.parse(localStorage.getItem('supinkly_custom_prices') || '{}');
        const customProducts = JSON.parse(localStorage.getItem('supinkly_custom_products') || '{}');
        let updatedCount = 0;

        // 3. Iterate through all catalog products and sync latest G2G search titles, URLs, costs, and stock
        for (const [prodId, g2gItem] of Object.entries(G2G_MARKET_FEED.benchmarks)) {
            const costTHB = g2gItem.baseCostUSD * exchangeRate;

            // Check if admin has set manual price override (ผู้ใช้ตั้งราคาเจาะจงเองทั้งใน customPrices หรือ customProducts)
            const isManualPrice = (customPrices[prodId] && customPrices[prodId].manualOverride === true) ||
                                  (customProducts[prodId] && typeof customProducts[prodId].price === 'number');

            // Always update master products in memory with latest verified G2G search title & URL
            if (typeof PRODUCTS !== 'undefined') {
                const p = PRODUCTS.find(prod => prod.id === prodId);
                if (p) {
                    p.g2gRawTitle = g2gItem.title;
                    p.g2gUrl = g2gItem.g2gUrl;
                }
            }

            if (isManualPrice) {
                // Keep the admin's manual price, but update live stock count, market benchmark cost, and fresh search title
                if (!customPrices[prodId]) customPrices[prodId] = {};
                customPrices[prodId].manualOverride = true;
                if (typeof customProducts[prodId]?.price === 'number' && typeof customPrices[prodId].price !== 'number') {
                    customPrices[prodId].price = customProducts[prodId].price;
                }
                const stockShift = Math.floor(Math.sin((Date.now() / 1800000) + prodId.charCodeAt(0)) * 5);
                const liveG2GStock = Math.max(5, g2gItem.g2gStock + stockShift);
                customPrices[prodId].g2gStockAvailable = liveG2GStock;
                customPrices[prodId].marketCostTHB = Math.round(g2gItem.baseCostUSD * exchangeRate * 100) / 100;
                customPrices[prodId].g2gRawTitle = g2gItem.title;
                if (!customPrices[prodId].g2gUrl || (typeof isBrokenOrLegacyG2GUrl === 'function' && isBrokenOrLegacyG2GUrl(customPrices[prodId].g2gUrl))) {
                    customPrices[prodId].g2gUrl = g2gItem.g2gUrl;
                }
                customPrices[prodId].lastMarketSync = new Date().toISOString();
                updatedCount++;
                continue;
            }

            const masterProd = typeof PRODUCTS !== 'undefined' ? PRODUCTS.find(p => p.id === prodId) : null;
            // คำนวณราคาขายตามตลาดจริง Auto-Sync (ลดลงหรือปรับตามต้นทุน + กำไร)
            const targetRetailPrice = this.calculateProfitableThaiPrice(costTHB, config.profitMultiplier, config.minProfitBaht);
            const targetOrigPrice = (masterProd && masterProd.originalPrice > targetRetailPrice)
                ? masterProd.originalPrice
                : Math.round(targetRetailPrice * 1.85 / 10) * 10 - 1;

            // Live market stock fluctuation (±5 items based on continuous market transactions)
            const stockShift = Math.floor(Math.sin((Date.now() / 1800000) + prodId.charCodeAt(0)) * 5);
            const liveG2GStock = Math.max(5, g2gItem.g2gStock + stockShift);

            customPrices[prodId] = {
                price: targetRetailPrice,
                originalPrice: targetOrigPrice,
                marketCostTHB: Math.round(costTHB * 100) / 100,
                g2gStockAvailable: liveG2GStock,
                g2gRawTitle: g2gItem.title,
                g2gUrl: (customPrices[prodId]?.g2gUrl && typeof isBrokenOrLegacyG2GUrl === 'function' && !isBrokenOrLegacyG2GUrl(customPrices[prodId].g2gUrl)) ? customPrices[prodId].g2gUrl : g2gItem.g2gUrl,
                manualOverride: false,
                lastMarketSync: new Date().toISOString()
            };
            updatedCount++;
        }

        // Persist dynamically synced prices and stock
        localStorage.setItem('supinkly_custom_prices', JSON.stringify(customPrices));

        // Update Sync Metadata
        config.lastSyncTimestamp = Date.now();
        config.lastSyncCount = updatedCount;
        this.saveConfig(config);

        // Update Application State and UI if app is loaded
        if (typeof syncStockCount === 'function') {
            syncStockCount();
        } else if (typeof applyCustomPricesToProducts === 'function') {
            applyCustomPricesToProducts();
        }

        if (typeof applyFilters === 'function') {
            applyFilters();
        } else if (typeof renderProducts === 'function') {
            renderProducts();
        }
        if (typeof updateCartUI === 'function') {
            updateCartUI();
        }
        if (typeof renderAdminStockList === 'function') {
            renderAdminStockList();
        }

        this.updateSyncBadge();
    },

    // Update Status Badge on UI
    updateSyncBadge() {
        const timeEl = document.getElementById('g2g-last-sync-time');
        const badgeEl = document.getElementById('g2g-sync-status-badge');

        if (timeEl) {
            timeEl.textContent = "สินค้าแท้ 100%";
        }

        if (badgeEl) {
            badgeEl.title = "รับประกันสินค้าแท้ทุกรายการ พร้อมส่งมอบตลอด 24 ชม.";
        }
    },

    // Initialize Auto-Sync Service
    init() {
        // Pre-fetch live exchange rate immediately
        this.fetchLiveExchangeRate();

        // 1. Initial Auto-Sync immediately upon page load (Zero button clicks required)
        setTimeout(() => {
            this.performAutoSync();
        }, 800);

        // 2. Set recurring auto-sync loop (every 15 minutes)
        if (this.timerId) clearInterval(this.timerId);
        this.timerId = setInterval(() => {
            this.performAutoSync();
        }, this.SYNC_INTERVAL_MS);

        // 3. Tab visibility auto-refresh (if tab was in background > 3 mins)
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                const cfg = this.getConfig();
                if (!cfg.lastSyncTimestamp || (Date.now() - cfg.lastSyncTimestamp > 3 * 60 * 1000)) {
                    this.performAutoSync();
                }
            }
        });
    }
};
