function createSettingsCache({ Settings, redisClient = null } = {}) {
    const memoryTtlMs = Math.max(1000, Number.parseInt(process.env.SETTINGS_CACHE_TTL_MS || '5000', 10) || 5000);
    const redisTtlSec = Math.max(1, Number.parseInt(process.env.SETTINGS_CACHE_REDIS_TTL_SEC || String(Math.ceil(memoryTtlMs / 1000)), 10) || Math.ceil(memoryTtlMs / 1000));
    const redisKey = String(process.env.SETTINGS_CACHE_KEY || 'cpanel:settings:all:v1');

    let memoValue = null;
    let memoExpiresAt = 0;
    let memoPromise = null;

    const nowMs = () => Date.now();

    const mapRows = (rows) => {
        const result = {};
        for (const row of rows || []) {
            if (!row) continue;
            const key = typeof row.key === 'string' ? row.key : String(row.key || '');
            if (!key) continue;
            result[key] = row.value;
        }
        return result;
    };

    const setMemo = (value) => {
        memoValue = value;
        memoExpiresAt = nowMs() + memoryTtlMs;
    };

    const getFromMemo = () => {
        if (!memoValue) return null;
        if (memoExpiresAt <= nowMs()) return null;
        return memoValue;
    };

    const getFromRedis = async () => {
        if (!redisClient || !redisClient.isReady) return null;
        try {
            const raw = await redisClient.get(redisKey);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
            return parsed;
        } catch {
            return null;
        }
    };

    const writeToRedis = async (value) => {
        if (!redisClient || !redisClient.isReady) return;
        try {
            await redisClient.set(redisKey, JSON.stringify(value), { EX: redisTtlSec });
        } catch {
            // ignore cache write errors
        }
    };

    const loadFresh = async () => {
        const rows = await Settings.findAll();
        const mapped = mapRows(rows);
        setMemo(mapped);
        await writeToRedis(mapped);
        return mapped;
    };

    const getSettingsMap = async () => {
        const memo = getFromMemo();
        if (memo) return memo;

        if (memoPromise) return memoPromise;

        memoPromise = (async () => {
            const cached = await getFromRedis();
            if (cached) {
                setMemo(cached);
                return cached;
            }
            return loadFresh();
        })();

        try {
            return await memoPromise;
        } finally {
            memoPromise = null;
        }
    };

    const invalidate = async () => {
        memoValue = null;
        memoExpiresAt = 0;
        memoPromise = null;
        if (!redisClient || !redisClient.isReady) return;
        try {
            await redisClient.del(redisKey);
        } catch {
            // ignore
        }
    };

    return {
        getSettingsMap,
        invalidate,
        loadFresh
    };
}

function bindSettingsInvalidation(Settings, cache) {
    if (!Settings || !cache || typeof cache.invalidate !== 'function') return;
    if (Settings.__settingsCacheInvalidationBound) return;
    Settings.__settingsCacheInvalidationBound = true;

    const wrap = (methodName) => {
        const original = Settings[methodName];
        if (typeof original !== 'function') return;
        Settings[methodName] = async function wrappedSettingsMethod(...args) {
            const result = await original.apply(this, args);
            try {
                await cache.invalidate();
            } catch {
                // ignore invalidation failures
            }
            return result;
        };
    };

    ['upsert', 'create', 'bulkCreate', 'update', 'destroy'].forEach(wrap);
}

module.exports = {
    createSettingsCache,
    bindSettingsInvalidation
};
