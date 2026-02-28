const crypto = require('crypto');
const net = require('net');

const ADMIN_API_KEY_PERMISSION_CATALOG = Object.freeze([
    'admin.observability.view',
    'admin.jobs.view',
    'admin.jobs.manage',
    'admin.audit.view',
    'admin.rbac.view',
    'admin.rbac.manage',
    'admin.backups.view',
    'admin.backups.manage',
    'admin.incidents.view',
    'admin.incidents.manage'
]);

const ADMIN_API_KEY_WILDCARD = '*';
const ADMIN_API_KEY_TOKEN_PREFIX = 'cp_adm_';

function normalizeAdminApiKeyPermissions(input) {
    const list = Array.isArray(input) ? input : [];
    const output = [];
    const seen = new Set();

    for (const entry of list) {
        const value = String(entry || '').trim();
        if (!value) continue;
        if (value === ADMIN_API_KEY_WILDCARD) {
            return [ADMIN_API_KEY_WILDCARD];
        }
        if (!ADMIN_API_KEY_PERMISSION_CATALOG.includes(value)) continue;
        if (seen.has(value)) continue;
        seen.add(value);
        output.push(value);
    }

    return output.sort();
}

function generateAdminApiKeyToken() {
    const secret = crypto.randomBytes(32).toString('hex');
    return {
        token: `${ADMIN_API_KEY_TOKEN_PREFIX}${secret}`,
        keyPrefix: secret.slice(0, 12)
    };
}

function parseAdminApiBearerToken(value) {
    const rawHeader = String(value || '').trim();
    const headerMatch = rawHeader.match(/^Bearer\s+(.+)$/i);
    if (!headerMatch) return null;

    const token = String(headerMatch[1] || '').trim();
    if (!token.startsWith(ADMIN_API_KEY_TOKEN_PREFIX)) return null;
    const secret = token.slice(ADMIN_API_KEY_TOKEN_PREFIX.length);
    if (!/^[a-f0-9]{64}$/i.test(secret)) return null;

    return {
        token,
        secret,
        keyPrefix: secret.slice(0, 12)
    };
}

function hashAdminApiKeyToken(token, appSecret) {
    return crypto
        .createHmac('sha256', String(appSecret || ''))
        .update(String(token || ''))
        .digest('hex');
}

function normalizeAdminApiIpAllowlist(input) {
    const list = Array.isArray(input)
        ? input
        : String(input || '')
            .split(/[\n,\s]+/g)
            .map((entry) => entry.trim());

    const seen = new Set();
    const output = [];

    list.forEach((rawEntry) => {
        const entry = String(rawEntry || '').trim();
        if (!entry) return;

        if (entry.includes('/')) {
            const [baseRaw, prefixRaw] = entry.split('/', 2);
            const base = String(baseRaw || '').trim();
            const prefix = Number.parseInt(String(prefixRaw || '').trim(), 10);
            const family = net.isIP(base);
            if (!family) return;
            const maxPrefix = family === 6 ? 128 : 32;
            if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) return;
            const normalized = `${base}/${prefix}`;
            if (seen.has(normalized)) return;
            seen.add(normalized);
            output.push(normalized);
            return;
        }

        if (!net.isIP(entry)) return;
        if (seen.has(entry)) return;
        seen.add(entry);
        output.push(entry);
    });

    return output.sort((a, b) => a.localeCompare(b));
}

function normalizeAdminApiRotationDays(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isInteger(parsed) || parsed < 0) return 0;
    return Math.min(parsed, 3650);
}

function normalizeAdminApiKeyExpiresAt(value) {
    if (value === null || value === undefined || value === '') return null;
    const raw = String(value).trim();
    if (!raw) return null;
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return null;
    return parsed;
}

function normalizeIpForAllowlistMatch(ip) {
    const raw = String(ip || '').trim();
    if (!raw) return '';
    if (raw.includes(':') && raw.startsWith('::ffff:')) {
        return raw.slice('::ffff:'.length);
    }
    return raw;
}

function isAdminApiKeyIpAllowed(apiKey, requestIp) {
    const normalizedIp = normalizeIpForAllowlistMatch(requestIp);
    if (!normalizedIp || !net.isIP(normalizedIp)) return false;

    const allowlist = normalizeAdminApiIpAllowlist(apiKey && apiKey.allowedIps);
    if (!allowlist.length) return true;

    const blocklist = new net.BlockList();
    allowlist.forEach((entry) => {
        if (entry.includes('/')) {
            const [base, prefixRaw] = entry.split('/', 2);
            const prefix = Number.parseInt(prefixRaw, 10);
            const family = net.isIP(base) === 6 ? 'ipv6' : 'ipv4';
            try {
                blocklist.addSubnet(base, prefix, family);
            } catch {
                // ignore malformed values
            }
            return;
        }
        try {
            blocklist.addAddress(entry, net.isIP(entry) === 6 ? 'ipv6' : 'ipv4');
        } catch {
            // ignore malformed values
        }
    });

    const family = net.isIP(normalizedIp) === 6 ? 'ipv6' : 'ipv4';
    return blocklist.check(normalizedIp, family);
}

function getAdminApiKeyInactiveReason(apiKey, nowInput = new Date()) {
    if (!apiKey) return 'missing';
    if (apiKey.revokedAt) return 'revoked';

    const now = nowInput instanceof Date ? nowInput : new Date(nowInput);
    if (apiKey.expiresAt) {
        const expiresAt = new Date(apiKey.expiresAt);
        if (!Number.isNaN(expiresAt.getTime()) && now.getTime() >= expiresAt.getTime()) {
            return 'expired';
        }
    }

    const rotationDays = normalizeAdminApiRotationDays(apiKey.rotationIntervalDays);
    if (rotationDays > 0) {
        const baseAt = apiKey.rotatedAt || apiKey.createdAt || null;
        if (baseAt) {
            const baseDate = new Date(baseAt);
            if (!Number.isNaN(baseDate.getTime())) {
                const maxAgeMs = rotationDays * 24 * 60 * 60 * 1000;
                if ((now.getTime() - baseDate.getTime()) >= maxAgeMs) {
                    return 'rotation_required';
                }
            }
        }
    }

    return null;
}

function isAdminApiKeyActive(apiKey) {
    return !getAdminApiKeyInactiveReason(apiKey);
}

function hasAdminApiKeyPermission(apiKey, permission) {
    const needed = String(permission || '').trim();
    if (!needed) return false;
    if (!apiKey) return false;

    const permissions = normalizeAdminApiKeyPermissions(apiKey.permissions);
    if (permissions.includes(ADMIN_API_KEY_WILDCARD)) return true;
    return permissions.includes(needed);
}

module.exports = {
    ADMIN_API_KEY_PERMISSION_CATALOG,
    ADMIN_API_KEY_WILDCARD,
    ADMIN_API_KEY_TOKEN_PREFIX,
    normalizeAdminApiKeyPermissions,
    generateAdminApiKeyToken,
    parseAdminApiBearerToken,
    hashAdminApiKeyToken,
    normalizeAdminApiIpAllowlist,
    normalizeAdminApiRotationDays,
    normalizeAdminApiKeyExpiresAt,
    isAdminApiKeyIpAllowed,
    getAdminApiKeyInactiveReason,
    isAdminApiKeyActive,
    hasAdminApiKeyPermission
};
