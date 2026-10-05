const fs = require('fs');
const vm = require('vm');

const context = {
    localStorage: {
        getItem: () => null,
        setItem: () => {}
    },
    console: console,
    document: {
        getElementById: () => null,
        addEventListener: () => {}
    },
    window: {}
};
vm.createContext(context);

vm.runInContext(fs.readFileSync('js/g2g-sync.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('js/data.js', 'utf8'), context);

const products = context.PRODUCTS.map((p, idx) => ({
    no: idx + 1,
    id: p.id,
    brand: p.brand,
    thaiTitle: p.title,
    g2gRawTitle: context.G2G_MARKET_FEED.benchmarks[p.id]?.title || '',
    serviceId: context.G2G_MARKET_FEED.benchmarks[p.id]?.serviceId || '',
    costUSD: context.G2G_MARKET_FEED.benchmarks[p.id]?.baseCostUSD || 0,
    g2gUrl: p.g2gUrl || ''
}));

console.log(JSON.stringify(products, null, 2));
