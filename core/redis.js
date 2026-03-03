const { bootInfo, bootWarn } = require('./boot');

function isEnabled(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

let redisEnabled = false;
let redisClient = null;
let redisReady = false;

function createRedisClient() {
    redisEnabled = isEnabled(process.env.REDIS_ENABLED);
    if (!redisEnabled) return null;

    let createClient;
    try {
        ({ createClient } = require('redis'));
    } catch (error) {
        bootWarn('redis runtime package is missing; fallback to local stores error=%s', error.message || error);
        return null;
    }

    const redisUrl = String(process.env.REDIS_URL || '').trim();
    const redisHost = String(process.env.REDIS_HOST || '127.0.0.1').trim();
    const redisPort = Number.parseInt(process.env.REDIS_PORT, 10) || 6379;
    const redisDb = Number.parseInt(process.env.REDIS_DB, 10) || 0;
    const redisUser = String(process.env.REDIS_USERNAME || '').trim() || undefined;
    const redisPass = String(process.env.REDIS_PASSWORD || '').trim() || undefined;
    const redisTls = isEnabled(process.env.REDIS_TLS);

    const options = redisUrl
        ? {
            url: redisUrl,
            socket: {
                reconnectStrategy: (retries) => Math.min(250 * retries, 5000)
            }
        }
        : {
            socket: {
                host: redisHost,
                port: redisPort,
                tls: redisTls,
                reconnectStrategy: (retries) => Math.min(250 * retries, 5000)
            },
            username: redisUser,
            password: redisPass,
            database: redisDb
        };

    const client = createClient(options);
    client.on('ready', () => {
        redisReady = true;
        bootInfo('configured redis status=ready');
    });
    client.on('end', () => {
        redisReady = false;
        bootWarn('redis connection closed');
    });
    client.on('error', (error) => {
        redisReady = false;
        bootWarn('redis client error error=%s', error.message || error);
    });

    client.connect().then(() => {
        redisReady = true;
        if (redisUrl) {
            bootInfo('configured redis endpoint=url');
        } else {
            bootInfo('configured redis endpoint=%s:%s db=%s tls=%s', redisHost, redisPort, redisDb, redisTls ? 'on' : 'off');
        }
    }).catch((error) => {
        redisReady = false;
        bootWarn('failed to connect redis; fallback to local stores error=%s', error.message || error);
    });

    redisClient = client;
    return client;
}

function getRedisClient() {
    return redisClient;
}

function isRedisReady() {
    return redisEnabled && Boolean(redisClient) && redisReady;
}

module.exports = {
    createRedisClient,
    getRedisClient,
    isRedisReady
};
