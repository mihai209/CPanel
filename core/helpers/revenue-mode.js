const crypto = require('crypto');

const REVENUE_PLAN_CATALOG_SETTING_KEY = 'revenuePlanCatalog';
const USER_REVENUE_PROFILE_KEY_PREFIX = 'user_revenue_profile_';
const DAY_MS = 24 * 60 * 60 * 1000;
const REVENUE_SUSPEND_REASON_PREFIX = '[REVENUE_MODE]';

function toSafeInt(value, fallback = 0, min = 0, max = 1000000000) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
}

function parseBoolean(value, fallback = false) {
    if (value === undefined || value === null) return fallback;
    if (Array.isArray(value)) {
        for (const entry of value) {
            if (parseBoolean(entry, false)) return true;
        }
        return false;
    }
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) return fallback;
    return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function parseTimestamp(value, fallback = 0) {
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
    if (Number.isFinite(dateMs) && dateMs > 0) return Math.floor(dateMs);
    return fallback;
}

function createRevenuePlanId() {
    try {
        return crypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }
}

function normalizeRevenuePlan(rawPlan) {
    const plan = rawPlan && typeof rawPlan === 'object' ? rawPlan : {};
    const id = String(plan.id || '').trim() || createRevenuePlanId();
    const name = String(plan.name || '').trim().slice(0, 120) || `Plan ${id}`;

    return {
        id,
        name,
        description: String(plan.description || '').trim().slice(0, 500),
        enabled: parseBoolean(plan.enabled, true),
        periodDays: toSafeInt(plan.periodDays, 30, 1, 3650),
        priceCoins: toSafeInt(plan.priceCoins, 0, 0, 1000000000),
        maxServers: toSafeInt(plan.maxServers, 0, 0, 1000000),
        maxMemoryMb: toSafeInt(plan.maxMemoryMb, 0, 0, 1000000000),
        maxCpuPercent: toSafeInt(plan.maxCpuPercent, 0, 0, 1000000000),
        maxDiskMb: toSafeInt(plan.maxDiskMb, 0, 0, 1000000000),
        createdAtMs: parseTimestamp(plan.createdAtMs, Date.now()),
        updatedAtMs: parseTimestamp(plan.updatedAtMs, Date.now())
    };
}

function normalizeRevenuePlanCatalog(rawCatalog) {
    let parsed = rawCatalog;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = [];
        }
    }
    if (!Array.isArray(parsed)) parsed = [];

    const byId = new Map();
    parsed.forEach((entry) => {
        const normalized = normalizeRevenuePlan(entry);
        byId.set(normalized.id, normalized);
    });

    return Array.from(byId.values()).sort((a, b) => a.name.localeCompare(b.name));
}

function getUserRevenueProfileSettingKey(userId) {
    return `${USER_REVENUE_PROFILE_KEY_PREFIX}${Number.parseInt(userId, 10) || 0}`;
}

function normalizeUserRevenueProfile(rawProfile, nowMs = Date.now()) {
    let source = rawProfile;
    if (typeof source === 'string') {
        try {
            source = JSON.parse(source);
        } catch {
            source = {};
        }
    }
    if (!source || typeof source !== 'object') source = {};

    const statusRaw = String(source.status || '').trim().toLowerCase();
    const status = ['inactive', 'trial', 'active', 'past_due', 'expired'].includes(statusRaw) ? statusRaw : 'inactive';
    const periodDays = toSafeInt(source.periodDays, 30, 1, 3650);
    const createdAtMs = parseTimestamp(source.createdAtMs, nowMs);

    return {
        status,
        planId: String(source.planId || '').trim(),
        planNameSnapshot: String(source.planNameSnapshot || '').trim().slice(0, 120),
        periodDays,
        priceCoins: toSafeInt(source.priceCoins, 0, 0, 1000000000),
        trial: parseBoolean(source.trial, false),
        createdAtMs,
        updatedAtMs: parseTimestamp(source.updatedAtMs, nowMs),
        lastRenewAtMs: parseTimestamp(source.lastRenewAtMs, 0),
        nextRenewAtMs: parseTimestamp(source.nextRenewAtMs, 0),
        graceEndsAtMs: parseTimestamp(source.graceEndsAtMs, 0)
    };
}

function estimateWalletRunwayDays(walletCoins, dailyBurnCoins) {
    const wallet = Number.isFinite(Number(walletCoins)) ? Number(walletCoins) : 0;
    const burn = Number.isFinite(Number(dailyBurnCoins)) ? Number(dailyBurnCoins) : 0;
    if (burn <= 0) return null;
    if (wallet <= 0) return 0;
    return Math.max(0, wallet / burn);
}

function describeRunway(runwayDays) {
    if (runwayDays === null) return 'Stable (no recurring burn).';
    const days = Number(runwayDays);
    if (!Number.isFinite(days)) return 'Unknown';
    if (days <= 0) return 'Out of funds now';
    if (days < 1) return `${(days * 24).toFixed(1)}h`;
    if (days < 7) return `${days.toFixed(1)} days`;
    if (days < 30) return `${Math.round(days)} days`;
    const months = days / 30;
    return `${months.toFixed(1)} months`;
}

module.exports = {
    REVENUE_PLAN_CATALOG_SETTING_KEY,
    USER_REVENUE_PROFILE_KEY_PREFIX,
    DAY_MS,
    REVENUE_SUSPEND_REASON_PREFIX,
    toSafeInt,
    parseBoolean,
    parseTimestamp,
    normalizeRevenuePlan,
    normalizeRevenuePlanCatalog,
    getUserRevenueProfileSettingKey,
    normalizeUserRevenueProfile,
    estimateWalletRunwayDays,
    describeRunway
};
