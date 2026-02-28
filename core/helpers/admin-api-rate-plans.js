const ADMIN_API_RATE_PLAN_SETTING_PREFIX = 'admin_api_rate_plan_';

function toSafeInt(value, fallback = 0, min = 0, max = 1000000000) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
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

function getAdminApiRatePlanSettingKey(adminApiKeyId) {
    return `${ADMIN_API_RATE_PLAN_SETTING_PREFIX}${Number.parseInt(adminApiKeyId, 10) || 0}`;
}

function normalizeAdminApiRatePlan(raw) {
    let source = raw;
    if (typeof source === 'string') {
        try {
            source = JSON.parse(source);
        } catch {
            source = {};
        }
    }
    if (!source || typeof source !== 'object') source = {};

    return {
        enabled: parseBoolean(source.enabled, false),
        perMinute: toSafeInt(source.perMinute, 120, 0, 1000000),
        perHour: toSafeInt(source.perHour, 3600, 0, 10000000),
        perDay: toSafeInt(source.perDay, 50000, 0, 100000000)
    };
}

function getWindowDurationSeconds(scope) {
    if (scope === 'minute') return 60;
    if (scope === 'hour') return 3600;
    return 86400;
}

function getWindowSlot(scope, nowMs) {
    const date = new Date(nowMs);
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    const hour = String(date.getUTCHours()).padStart(2, '0');
    const minute = String(date.getUTCMinutes()).padStart(2, '0');

    if (scope === 'minute') return `${year}${month}${day}${hour}${minute}`;
    if (scope === 'hour') return `${year}${month}${day}${hour}`;
    return `${year}${month}${day}`;
}

function getSecondsUntilNextWindow(scope, nowMs) {
    const seconds = Math.floor(nowMs / 1000);
    const size = getWindowDurationSeconds(scope);
    const nextBoundary = Math.ceil((seconds + 1) / size) * size;
    return Math.max(1, nextBoundary - seconds);
}

function createAdminApiRateLimiter() {
    const counters = new Map(); // keyId -> { minute: {slot,count}, hour:..., day:... }

    function readCounter(keyId, scope, nowMs) {
        let entry = counters.get(keyId);
        if (!entry) {
            entry = {
                minute: { slot: '', count: 0 },
                hour: { slot: '', count: 0 },
                day: { slot: '', count: 0 }
            };
            counters.set(keyId, entry);
        }

        const slot = getWindowSlot(scope, nowMs);
        const current = entry[scope];
        if (current.slot !== slot) {
            current.slot = slot;
            current.count = 0;
        }
        return current;
    }

    function evaluateLimit(keyId, scope, limit, nowMs) {
        if (!Number.isInteger(limit) || limit <= 0) {
            return { ok: true, remaining: null, retryAfterSeconds: 0, limit: 0 };
        }
        const current = readCounter(keyId, scope, nowMs);
        if ((current.count + 1) > limit) {
            return {
                ok: false,
                remaining: 0,
                retryAfterSeconds: getSecondsUntilNextWindow(scope, nowMs),
                limit
            };
        }
        return {
            ok: true,
            remaining: Math.max(0, limit - (current.count + 1)),
            retryAfterSeconds: 0,
            limit
        };
    }

    function commitUse(keyId, nowMs) {
        ['minute', 'hour', 'day'].forEach((scope) => {
            const current = readCounter(keyId, scope, nowMs);
            current.count += 1;
        });
    }

    function consume(adminApiKeyId, plan, nowMs = Date.now()) {
        const keyId = Number.parseInt(adminApiKeyId, 10) || 0;
        if (keyId <= 0) {
            return { ok: true, headers: {} };
        }

        const normalizedPlan = normalizeAdminApiRatePlan(plan);
        if (!normalizedPlan.enabled) {
            return { ok: true, headers: {} };
        }

        const checks = [
            { scope: 'minute', limit: normalizedPlan.perMinute },
            { scope: 'hour', limit: normalizedPlan.perHour },
            { scope: 'day', limit: normalizedPlan.perDay }
        ];

        let blocked = null;
        const details = {};
        for (const check of checks) {
            const result = evaluateLimit(keyId, check.scope, check.limit, nowMs);
            details[check.scope] = result;
            if (!result.ok) {
                if (!blocked || result.retryAfterSeconds > blocked.retryAfterSeconds) {
                    blocked = { ...result, scope: check.scope };
                }
            }
        }

        if (blocked) {
            return {
                ok: false,
                scope: blocked.scope,
                retryAfterSeconds: blocked.retryAfterSeconds,
                headers: {
                    'Retry-After': String(blocked.retryAfterSeconds),
                    'X-RateLimit-Blocked-Scope': blocked.scope,
                    'X-RateLimit-Limit': String(blocked.limit)
                }
            };
        }

        commitUse(keyId, nowMs);

        return {
            ok: true,
            headers: {
                'X-RateLimit-Minute-Limit': String(details.minute.limit || 0),
                'X-RateLimit-Minute-Remaining': details.minute.remaining === null ? 'unlimited' : String(details.minute.remaining),
                'X-RateLimit-Hour-Limit': String(details.hour.limit || 0),
                'X-RateLimit-Hour-Remaining': details.hour.remaining === null ? 'unlimited' : String(details.hour.remaining),
                'X-RateLimit-Day-Limit': String(details.day.limit || 0),
                'X-RateLimit-Day-Remaining': details.day.remaining === null ? 'unlimited' : String(details.day.remaining)
            }
        };
    }

    return { consume };
}

module.exports = {
    ADMIN_API_RATE_PLAN_SETTING_PREFIX,
    parseBoolean,
    toSafeInt,
    getAdminApiRatePlanSettingKey,
    normalizeAdminApiRatePlan,
    createAdminApiRateLimiter
};
