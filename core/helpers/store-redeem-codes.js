const crypto = require('crypto');

const STORE_REDEEM_CODES_SETTING_KEY = 'storeRedeemCodesCatalog';
const STORE_REDEEM_CODES_MAX_ITEMS = 1000;
const STORE_REDEEM_RECENT_USES_LIMIT = 200;

function toNonNegativeInt(value, fallback = 0) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed) || parsed < 0) return fallback;
    return parsed;
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

function parseTimestampMs(value, fallback = 0) {
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
        return Math.floor(value);
    }
    const raw = String(value || '').trim();
    if (!raw) return fallback;
    if (/^\d+$/.test(raw)) {
        const parsed = Number.parseInt(raw, 10);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
    }
    const dateMs = new Date(raw).getTime();
    if (Number.isFinite(dateMs) && dateMs > 0) {
        return Math.floor(dateMs);
    }
    return fallback;
}

function buildRedeemId() {
    try {
        return crypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
    }
}

function normalizeRedeemCodeValue(value) {
    return String(value || '')
        .trim()
        .toUpperCase()
        .replace(/\s+/g, '')
        .replace(/[^A-Z0-9_-]/g, '')
        .slice(0, 64);
}

function normalizeRedeemRewards(raw) {
    const source = raw && typeof raw === 'object' ? raw : {};
    return {
        coins: toNonNegativeInt(source.coins, 0),
        ramMb: toNonNegativeInt(source.ramMb, 0),
        cpuPercent: toNonNegativeInt(source.cpuPercent, 0),
        diskMb: toNonNegativeInt(source.diskMb, 0),
        swapMb: toNonNegativeInt(source.swapMb, 0),
        allocations: toNonNegativeInt(source.allocations, 0),
        images: toNonNegativeInt(source.images, 0),
        databases: toNonNegativeInt(source.databases, 0),
        packages: toNonNegativeInt(source.packages, 0)
    };
}

function normalizeUsageByUser(raw) {
    const src = raw && typeof raw === 'object' ? raw : {};
    const out = {};
    for (const [key, value] of Object.entries(src)) {
        const userId = String(key || '').trim();
        if (!/^\d+$/.test(userId)) continue;
        const count = toNonNegativeInt(value, 0);
        if (count <= 0) continue;
        out[userId] = count;
    }
    return out;
}

function normalizeRecentUses(raw) {
    const parsed = Array.isArray(raw) ? raw : [];
    return parsed
        .map((entry) => {
            const source = entry && typeof entry === 'object' ? entry : {};
            return {
                userId: toNonNegativeInt(source.userId, 0),
                username: String(source.username || '').trim().slice(0, 120),
                usedAtMs: parseTimestampMs(source.usedAtMs, Date.now())
            };
        })
        .filter((entry) => entry.userId > 0)
        .sort((a, b) => b.usedAtMs - a.usedAtMs)
        .slice(0, STORE_REDEEM_RECENT_USES_LIMIT);
}

function normalizeStoreRedeemCode(raw, nowMs = Date.now()) {
    const source = raw && typeof raw === 'object' ? raw : {};
    const id = String(source.id || '').trim() || buildRedeemId();
    const code = normalizeRedeemCodeValue(source.code);
    const name = String(source.name || '').trim().slice(0, 120) || code || 'Unnamed Code';
    const description = String(source.description || '').trim().slice(0, 1200);
    const enabled = String(source.enabled).trim().toLowerCase() === 'false'
        ? false
        : Boolean(source.enabled === true || source.enabled === 1 || source.enabled === '1' || source.enabled === 'true' || source.enabled === undefined);
    const createdAtMs = parseTimestampMs(source.createdAtMs, nowMs) || nowMs;
    const updatedAtMs = parseTimestampMs(source.updatedAtMs, createdAtMs) || createdAtMs;
    const expiresAtMs = Math.max(0, parseTimestampMs(source.expiresAtMs, 0));
    const maxUses = Math.max(0, toNonNegativeInt(source.maxUses, 0));
    const usesCount = Math.max(0, toNonNegativeInt(source.usesCount, 0));
    const perUserLimit = Math.max(0, toNonNegativeInt(source.perUserLimit, 0));
    const usageByUser = normalizeUsageByUser(source.usageByUser);
    const recentUses = normalizeRecentUses(source.recentUses);
    const rewards = normalizeRedeemRewards(source.rewards);

    return {
        id,
        code,
        name,
        description,
        enabled,
        expiresAtMs,
        maxUses,
        usesCount,
        perUserLimit,
        usageByUser,
        recentUses,
        createdAtMs,
        updatedAtMs,
        rewards
    };
}

function normalizeStoreRedeemCodesCatalog(raw) {
    const parsed = parseJson(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => normalizeStoreRedeemCode(entry))
        .filter((entry) => Boolean(entry.code))
        .slice(0, STORE_REDEEM_CODES_MAX_ITEMS)
        .sort((a, b) => b.createdAtMs - a.createdAtMs);
}

function getStoreRedeemCodeStatus(codeEntry, nowMs = Date.now()) {
    if (!codeEntry || typeof codeEntry !== 'object') return 'invalid';
    if (!codeEntry.enabled) return 'disabled';
    if (Number(codeEntry.expiresAtMs || 0) > 0 && Number(codeEntry.expiresAtMs) <= nowMs) return 'expired';
    if (Number(codeEntry.maxUses || 0) > 0 && Number(codeEntry.usesCount || 0) >= Number(codeEntry.maxUses)) return 'exhausted';
    return 'active';
}

function getStoreRedeemCodeRemainingUses(codeEntry) {
    if (!codeEntry || typeof codeEntry !== 'object') return 0;
    const maxUses = Math.max(0, Number.parseInt(codeEntry.maxUses, 10) || 0);
    const usesCount = Math.max(0, Number.parseInt(codeEntry.usesCount, 10) || 0);
    if (maxUses <= 0) return null;
    return Math.max(0, maxUses - usesCount);
}

function getStoreRedeemCodeUserUses(codeEntry, userId) {
    if (!codeEntry || typeof codeEntry !== 'object') return 0;
    const usageByUser = codeEntry.usageByUser && typeof codeEntry.usageByUser === 'object' ? codeEntry.usageByUser : {};
    const key = String(Number.parseInt(userId, 10) || 0);
    if (!key || key === '0') return 0;
    return Math.max(0, Number.parseInt(usageByUser[key], 10) || 0);
}

function canUserRedeemStoreCode(codeEntry, userId, nowMs = Date.now()) {
    const status = getStoreRedeemCodeStatus(codeEntry, nowMs);
    if (status !== 'active') {
        return {
            ok: false,
            error: status === 'expired'
                ? 'This redeem code has expired.'
                : status === 'exhausted'
                    ? 'This redeem code has reached max uses.'
                    : status === 'disabled'
                        ? 'This redeem code is disabled.'
                        : 'Redeem code is invalid.'
        };
    }

    const perUserLimit = Math.max(0, Number.parseInt(codeEntry.perUserLimit, 10) || 0);
    if (perUserLimit > 0) {
        const usedByUser = getStoreRedeemCodeUserUses(codeEntry, userId);
        if (usedByUser >= perUserLimit) {
            return { ok: false, error: 'You reached the per-user usage limit for this code.' };
        }
    }

    return { ok: true };
}

function applyStoreRedeemCodeUsage(codeEntry, options = {}) {
    const nowMs = Date.now();
    const source = normalizeStoreRedeemCode(codeEntry, nowMs);
    const userId = Math.max(0, Number.parseInt(options.userId, 10) || 0);
    const username = String(options.username || '').trim().slice(0, 120);
    const usedAtMs = parseTimestampMs(options.usedAtMs, nowMs) || nowMs;

    source.usesCount = Math.max(0, Number.parseInt(source.usesCount, 10) || 0) + 1;
    if (userId > 0) {
        const key = String(userId);
        const current = Math.max(0, Number.parseInt(source.usageByUser[key], 10) || 0);
        source.usageByUser[key] = current + 1;
        source.recentUses.unshift({ userId, username, usedAtMs });
        source.recentUses = normalizeRecentUses(source.recentUses);
    }
    source.updatedAtMs = nowMs;
    return source;
}

module.exports = {
    STORE_REDEEM_CODES_SETTING_KEY,
    normalizeRedeemCodeValue,
    normalizeRedeemRewards,
    normalizeStoreRedeemCode,
    normalizeStoreRedeemCodesCatalog,
    getStoreRedeemCodeStatus,
    getStoreRedeemCodeRemainingUses,
    getStoreRedeemCodeUserUses,
    canUserRedeemStoreCode,
    applyStoreRedeemCodeUsage
};
