const { bootInfo, bootWarn } = require('./boot');

function isEnabled(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function toSafeInt(value, fallback, min, max) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function toSafeString(value, fallback = '') {
    const normalized = String(value === undefined || value === null ? '' : value).trim();
    return normalized || fallback;
}

function getEnvRedisConfig() {
    return normalizeRedisConfig({
        enabled: process.env.REDIS_ENABLED,
        url: process.env.REDIS_URL,
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT,
        db: process.env.REDIS_DB,
        username: process.env.REDIS_USERNAME,
        password: process.env.REDIS_PASSWORD,
        tls: process.env.REDIS_TLS,
        sessionPrefix: process.env.REDIS_SESSION_PREFIX
    }, { fallbackToEnv: false });
}

function normalizeRedisConfig(raw = {}, options = {}) {
    const fallbackToEnv = options.fallbackToEnv !== false;
    const env = fallbackToEnv ? getEnvRedisConfig() : null;

    const read = (...keys) => {
        for (const key of keys) {
            if (raw[key] !== undefined && raw[key] !== null) return raw[key];
        }
        return undefined;
    };

    const enabled = read('enabled', 'redisEnabled');
    const url = toSafeString(read('url', 'redisUrl'), env ? env.url : '');
    const host = toSafeString(read('host', 'redisHost'), env ? env.host : '127.0.0.1');
    const port = toSafeInt(read('port', 'redisPort'), env ? env.port : 6379, 1, 65535);
    const db = toSafeInt(read('db', 'redisDb'), env ? env.db : 0, 0, 16);
    const username = toSafeString(read('username', 'redisUsername'), env ? env.username : '');
    const password = toSafeString(read('password', 'redisPassword'), env ? env.password : '');
    const tls = read('tls', 'redisTls');
    const sessionPrefix = toSafeString(read('sessionPrefix', 'redisSessionPrefix'), env ? env.sessionPrefix : 'cpanel:sess:');

    return {
        enabled: enabled === undefined ? (env ? env.enabled : false) : isEnabled(enabled),
        url,
        host,
        port,
        db,
        username,
        password,
        tls: tls === undefined ? (env ? env.tls : false) : isEnabled(tls),
        sessionPrefix,
        mode: url ? 'url' : 'host'
    };
}

let redisEnabled = false;
let redisClient = null;
let redisReady = false;
let redisSource = 'env';
let redisConfig = getEnvRedisConfig();
let redisLastError = '';
let redisLastAttemptAt = 0;
let redisConnectedAt = 0;

function readRedisPackage() {
    try {
        const redis = require('redis');
        if (redis && typeof redis.createClient === 'function') {
            return redis.createClient;
        }
        return null;
    } catch (error) {
        bootWarn('redis runtime package is missing; fallback to local stores error=%s', error.message || error);
        return null;
    }
}

function buildClientOptions(config) {
    if (config.url) {
        return {
            url: config.url,
            socket: {
                reconnectStrategy: (retries) => Math.min(250 * retries, 5000)
            }
        };
    }

    return {
        socket: {
            host: config.host,
            port: config.port,
            tls: config.tls,
            reconnectStrategy: (retries) => Math.min(250 * retries, 5000)
        },
        username: config.username || undefined,
        password: config.password || undefined,
        database: config.db
    };
}

function trackClientEvents(client) {
    client.on('ready', () => {
        redisReady = true;
        redisLastError = '';
        redisConnectedAt = Date.now();
        bootInfo('configured redis status=ready source=%s', redisSource);
    });
    client.on('end', () => {
        redisReady = false;
        bootWarn('redis connection closed');
    });
    client.on('error', (error) => {
        redisReady = false;
        redisLastError = String(error && error.message ? error.message : error || 'unknown redis error');
        bootWarn('redis client error error=%s', redisLastError);
    });
}

function applyClientRuntimeConfig(config, source) {
    redisEnabled = Boolean(config.enabled);
    redisSource = source || 'runtime';
    redisConfig = config;
    redisReady = false;
    redisLastError = '';
    redisLastAttemptAt = Date.now();
}

function connectClient(client, config) {
    client.connect().then(() => {
        redisReady = true;
        redisLastError = '';
        redisConnectedAt = Date.now();
        if (config.url) {
            bootInfo('configured redis endpoint=url source=%s', redisSource);
        } else {
            bootInfo(
                'configured redis endpoint=%s:%s db=%s tls=%s source=%s',
                config.host,
                config.port,
                config.db,
                config.tls ? 'on' : 'off',
                redisSource
            );
        }
    }).catch((error) => {
        redisReady = false;
        redisLastError = String(error && error.message ? error.message : error || 'redis connect error');
        bootWarn('failed to connect redis; fallback to local stores error=%s', redisLastError);
    });
}

function createClientFromConfig(config, source = 'env') {
    applyClientRuntimeConfig(config, source);

    if (!config.enabled) {
        redisClient = null;
        return null;
    }

    const createClient = readRedisPackage();
    if (!createClient) {
        redisClient = null;
        redisLastError = 'redis package unavailable';
        return null;
    }

    const options = buildClientOptions(config);
    const client = createClient(options);
    trackClientEvents(client);
    redisClient = client;
    connectClient(client, config);
    return client;
}

async function disconnectCurrentClient() {
    const current = redisClient;
    redisClient = null;
    redisReady = false;
    if (!current) return;

    try {
        if (typeof current.quit === 'function') {
            await current.quit();
            return;
        }
    } catch {
        // ignore and fallback to disconnect
    }

    try {
        if (typeof current.disconnect === 'function') {
            current.disconnect();
        }
    } catch {
        // ignore
    }
}

async function waitForReady(targetClient, timeoutMs = 4000) {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
        if (redisClient === targetClient && redisReady) return true;
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return false;
}

function createRedisClient(initialConfig = null, source = 'env') {
    const normalized = normalizeRedisConfig(initialConfig || {}, { fallbackToEnv: true });
    return createClientFromConfig(normalized, source);
}

async function reconfigureRedis(nextConfig = null, source = 'settings') {
    const normalized = normalizeRedisConfig(nextConfig || {}, { fallbackToEnv: true });

    await disconnectCurrentClient();
    const client = createClientFromConfig(normalized, source);

    if (!normalized.enabled) {
        return { ok: true, enabled: false, ready: false, error: '' };
    }
    if (!client) {
        return { ok: false, enabled: true, ready: false, error: redisLastError || 'failed to initialize redis client' };
    }

    const ready = await waitForReady(client, 4500);
    return {
        ok: ready,
        enabled: true,
        ready,
        error: ready ? '' : (redisLastError || 'redis connection timeout')
    };
}

async function testRedisConnection(testConfig = null) {
    const normalized = normalizeRedisConfig(testConfig || {}, { fallbackToEnv: true });
    if (!normalized.enabled) {
        return { ok: true, message: 'Redis is disabled in this configuration.' };
    }

    const createClient = readRedisPackage();
    if (!createClient) {
        return { ok: false, message: 'Redis package is not installed.' };
    }

    const tempClient = createClient(buildClientOptions(normalized));
    try {
        const startedAt = Date.now();
        await tempClient.connect();
        await tempClient.ping();
        const elapsed = Date.now() - startedAt;
        return { ok: true, message: `Connection successful (${elapsed} ms).` };
    } catch (error) {
        return { ok: false, message: String(error && error.message ? error.message : error || 'Redis test failed') };
    } finally {
        try {
            await tempClient.quit();
        } catch {
            try {
                if (typeof tempClient.disconnect === 'function') tempClient.disconnect();
            } catch {
                // ignore
            }
        }
    }
}

function getRedisClient() {
    return redisClient;
}

function isRedisReady() {
    return redisEnabled && Boolean(redisClient) && redisReady;
}

function getRedisRuntimeInfo() {
    const config = redisConfig || getEnvRedisConfig();
    return {
        enabled: redisEnabled,
        ready: isRedisReady(),
        source: redisSource,
        lastError: redisLastError,
        lastAttemptAt: redisLastAttemptAt || 0,
        connectedAt: redisConnectedAt || 0,
        config: {
            enabled: Boolean(config.enabled),
            mode: config.mode,
            url: config.url,
            host: config.host,
            port: config.port,
            db: config.db,
            username: config.username,
            tls: Boolean(config.tls),
            sessionPrefix: config.sessionPrefix,
            hasPassword: Boolean(config.password)
        }
    };
}

module.exports = {
    createRedisClient,
    getRedisClient,
    isRedisReady,
    reconfigureRedis,
    testRedisConnection,
    getRedisRuntimeInfo,
    normalizeRedisConfig,
    getEnvRedisConfig
};
