const crypto = require('crypto');

const STORE_DEALS_SETTING_KEY = 'storeDealsCatalog';
const STORE_DEALS_MAX_ITEMS = 500;

function toNonNegativeInt(value, fallback = 0) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed) || parsed < 0) return fallback;
    return parsed;
}

function toBoundedInt(value, fallback, min, max) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
}

function sanitizeUrl(input) {
    const raw = String(input || '').trim();
    if (!raw) return '';
    try {
        const parsed = new URL(raw);
        const protocol = String(parsed.protocol || '').toLowerCase();
        if (protocol !== 'http:' && protocol !== 'https:') return '';
        return parsed.toString();
    } catch {
        return '';
    }
}

function parseJson(raw, fallback) {
    if (raw === undefined || raw === null || raw === '') return fallback;
    try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (parsed === undefined || parsed === null) return fallback;
        return parsed;
    } catch {
        return fallback;
    }
}

function buildDealId() {
    try {
        return crypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
    }
}

function normalizeDealResources(raw) {
    const source = raw && typeof raw === 'object' ? raw : {};
    return {
        ramMb: toNonNegativeInt(source.ramMb, 0),
        cpuPercent: toNonNegativeInt(source.cpuPercent, 0),
        diskMb: toNonNegativeInt(source.diskMb, 0),
        swapMb: toNonNegativeInt(source.swapMb, 0),
        allocations: toNonNegativeInt(source.allocations, 0),
        images: toNonNegativeInt(source.images, 0),
        packages: toNonNegativeInt(source.packages, 0)
    };
}

function normalizeStoreDeal(raw, nowMs = Date.now()) {
    const source = raw && typeof raw === 'object' ? raw : {};
    const id = String(source.id || '').trim() || buildDealId();
    const name = String(source.name || '').trim().slice(0, 120);
    const description = String(source.description || '').trim().slice(0, 1200);
    const imageUrl = sanitizeUrl(source.imageUrl);
    const enabled = String(source.enabled).trim().toLowerCase() === 'false'
        ? false
        : Boolean(source.enabled === true || source.enabled === 1 || source.enabled === '1' || source.enabled === 'true' || source.enabled === undefined);
    const featured = Boolean(source.featured === true || source.featured === 1 || source.featured === '1' || source.featured === 'true');
    const priceCoins = toBoundedInt(source.priceCoins, 0, 0, 1_000_000_000);
    const stockTotalRaw = toBoundedInt(source.stockTotal, 1, 1, 1_000_000_000);
    const stockSoldRaw = toBoundedInt(source.stockSold, 0, 0, stockTotalRaw);
    const createdAtMs = toNonNegativeInt(source.createdAtMs, nowMs) || nowMs;
    const updatedAtMs = toNonNegativeInt(source.updatedAtMs, createdAtMs) || createdAtMs;
    const resources = normalizeDealResources(source.resources);

    return {
        id,
        name: name || 'Untitled Deal',
        description,
        imageUrl,
        enabled,
        featured,
        priceCoins,
        stockTotal: stockTotalRaw,
        stockSold: stockSoldRaw,
        createdAtMs,
        updatedAtMs,
        resources
    };
}

function normalizeStoreDealsCatalog(raw) {
    const parsed = parseJson(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => normalizeStoreDeal(entry))
        .slice(0, STORE_DEALS_MAX_ITEMS)
        .sort((a, b) => {
            if (a.featured !== b.featured) return a.featured ? -1 : 1;
            return b.createdAtMs - a.createdAtMs;
        });
}

function getStoreDealRemainingStock(deal) {
    if (!deal || typeof deal !== 'object') return 0;
    return Math.max(0, toNonNegativeInt(deal.stockTotal, 0) - toNonNegativeInt(deal.stockSold, 0));
}

function getStoreDealStatus(deal) {
    if (!deal || typeof deal !== 'object') return 'invalid';
    if (!deal.enabled) return 'disabled';
    if (getStoreDealRemainingStock(deal) <= 0) return 'sold_out';
    return 'active';
}

module.exports = {
    STORE_DEALS_SETTING_KEY,
    normalizeDealResources,
    normalizeStoreDeal,
    normalizeStoreDealsCatalog,
    getStoreDealRemainingStock,
    getStoreDealStatus
};
