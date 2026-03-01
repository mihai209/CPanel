const crypto = require('crypto');

const SERVER_API_KEY_PERMISSION_CATALOG = Object.freeze([
    'server.view',
    'server.console',
    'server.power',
    'server.files.read',
    'server.files.write',
    'server.files.download',
    'server.startup.read',
    'server.startup.write',
    'server.backups.view',
    'server.backups.manage',
    'server.databases.view',
    'server.databases.manage',
    'server.schedules.view',
    'server.schedules.manage',
    'server.network.view',
    'server.network.manage',
    'server.activity.view'
]);

const SERVER_API_KEY_WILDCARD = '*';
const SERVER_API_KEY_TOKEN_PREFIX = 'cp_srv_';

function normalizeServerApiKeyPermissions(input) {
    const list = Array.isArray(input) ? input : [];
    const output = [];
    const seen = new Set();

    for (const entry of list) {
        const value = String(entry || '').trim();
        if (!value) continue;
        if (value === SERVER_API_KEY_WILDCARD) {
            return [SERVER_API_KEY_WILDCARD];
        }
        if (!SERVER_API_KEY_PERMISSION_CATALOG.includes(value)) continue;
        if (seen.has(value)) continue;
        seen.add(value);
        output.push(value);
    }

    return output.sort();
}

function generateServerApiKeyToken() {
    const secret = crypto.randomBytes(32).toString('hex');
    return {
        token: `${SERVER_API_KEY_TOKEN_PREFIX}${secret}`,
        keyPrefix: secret.slice(0, 12)
    };
}

function parseServerApiBearerToken(value) {
    const rawHeader = String(value || '').trim();
    const headerMatch = rawHeader.match(/^Bearer\s+(.+)$/i);
    if (!headerMatch) return null;

    const token = String(headerMatch[1] || '').trim();
    if (!token.startsWith(SERVER_API_KEY_TOKEN_PREFIX)) return null;
    const secret = token.slice(SERVER_API_KEY_TOKEN_PREFIX.length);
    if (!/^[a-f0-9]{64}$/i.test(secret)) return null;

    return {
        token,
        secret,
        keyPrefix: secret.slice(0, 12)
    };
}

function hashServerApiKeyToken(token, appSecret) {
    return crypto
        .createHmac('sha256', String(appSecret || ''))
        .update(String(token || ''))
        .digest('hex');
}

function isServerApiKeyActive(apiKey, now = Date.now()) {
    if (!apiKey) return false;
    if (apiKey.revokedAt) return false;

    if (apiKey.expiresAt) {
        const expiresAtMs = new Date(apiKey.expiresAt).getTime();
        if (Number.isFinite(expiresAtMs) && expiresAtMs > 0 && expiresAtMs <= now) {
            return false;
        }
    }

    return true;
}

function hasServerApiKeyPermission(apiKey, permission) {
    const needed = String(permission || '').trim();
    if (!needed) return false;
    if (!apiKey) return false;

    const permissions = normalizeServerApiKeyPermissions(apiKey.permissions);
    if (permissions.includes(SERVER_API_KEY_WILDCARD)) return true;
    if (permissions.includes(needed)) return true;

    if (needed.startsWith('server.files.') && permissions.includes('server.files.read')) {
        return needed === 'server.files.list' || needed === 'server.files.read';
    }

    return false;
}

module.exports = {
    SERVER_API_KEY_PERMISSION_CATALOG,
    SERVER_API_KEY_WILDCARD,
    SERVER_API_KEY_TOKEN_PREFIX,
    normalizeServerApiKeyPermissions,
    generateServerApiKeyToken,
    parseServerApiBearerToken,
    hashServerApiKeyToken,
    isServerApiKeyActive,
    hasServerApiKeyPermission
};
