const LOGIN_GEO_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const loginGeoCache = new Map();

function normalizeLoginType(rawType) {
    const normalized = String(rawType || '').trim().toLowerCase();
    if (normalized === 'discord' || normalized === 'google' || normalized === 'github' || normalized === 'reddit') {
        return normalized;
    }
    return 'email';
}

function formatLoginTypeLabel(rawType) {
    const type = normalizeLoginType(rawType);
    if (type === 'email') return 'EMAIL';
    return type.toUpperCase();
}

function extractClientIp(req) {
    const forwarded = String((req && req.headers && req.headers['x-forwarded-for']) || '')
        .split(',')
        .map((entry) => String(entry || '').trim())
        .filter(Boolean);
    const candidates = [
        ...forwarded,
        req && req.headers ? req.headers['cf-connecting-ip'] : '',
        req && req.headers ? req.headers['x-real-ip'] : '',
        req ? req.ip : ''
    ];

    for (const value of candidates) {
        const ip = String(value || '').trim();
        if (!ip) continue;
        return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    }
    return 'unknown';
}

function isPrivateOrLocalIp(ipRaw) {
    const ip = String(ipRaw || '').trim().toLowerCase();
    if (!ip || ip === 'unknown') return true;
    if (ip === '::1' || ip === 'localhost') return true;
    if (ip.startsWith('10.')) return true;
    if (ip.startsWith('192.168.')) return true;
    if (ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.')) return true;
    if (ip.startsWith('172.2') || ip.startsWith('172.30.') || ip.startsWith('172.31.')) return true;
    if (ip.startsWith('127.')) return true;
    if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80:')) return true;
    return false;
}

function parseOperatingSystem(userAgentRaw) {
    const ua = String(userAgentRaw || '').toLowerCase();
    if (!ua) return 'Unknown OS';
    if (ua.includes('windows nt 10.0')) return 'Windows';
    if (ua.includes('windows nt 6.3')) return 'Windows 8.1';
    if (ua.includes('windows nt 6.2')) return 'Windows 8';
    if (ua.includes('windows nt 6.1')) return 'Windows 7';
    if (ua.includes('windows')) return 'Windows';
    if (ua.includes('android')) return 'Android';
    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) return 'iOS';
    if (ua.includes('mac os x') || ua.includes('macintosh')) return 'macOS';
    if (ua.includes('cros')) return 'ChromeOS';
    if (ua.includes('ubuntu')) return 'Ubuntu';
    if (ua.includes('debian')) return 'Debian';
    if (ua.includes('fedora')) return 'Fedora';
    if (ua.includes('linux')) return 'Linux';
    return 'Unknown OS';
}

function getCachedLocation(ip) {
    const cached = loginGeoCache.get(ip);
    if (!cached) return null;
    if (Date.now() > cached.expiresAt) {
        loginGeoCache.delete(ip);
        return null;
    }
    return cached.location;
}

function setCachedLocation(ip, location) {
    loginGeoCache.set(ip, {
        location,
        expiresAt: Date.now() + LOGIN_GEO_CACHE_TTL_MS
    });
}

async function resolveGeoLocation(req, ip, axios) {
    const cloudflareCountry = String((req && req.headers && req.headers['cf-ipcountry']) || '').trim().toUpperCase();
    if (cloudflareCountry && cloudflareCountry !== 'XX' && cloudflareCountry !== 'T1') {
        return cloudflareCountry;
    }
    if (isPrivateOrLocalIp(ip)) return 'Local/Private Network';
    if (!axios || typeof axios.get !== 'function') return 'Unknown';

    const cached = getCachedLocation(ip);
    if (cached) return cached;

    try {
        const response = await axios.get(`https://ipwho.is/${encodeURIComponent(ip)}`, {
            timeout: 2200
        });
        const payload = response && response.data ? response.data : {};
        if (payload.success === false) {
            setCachedLocation(ip, 'Unknown');
            return 'Unknown';
        }
        const city = String(payload.city || '').trim();
        const region = String(payload.region || '').trim();
        const country = String(payload.country || '').trim() || String(payload.country_code || '').trim();
        const parts = [city, region, country].filter(Boolean);
        const location = parts.length > 0 ? parts.join(', ') : 'Unknown';
        setCachedLocation(ip, location);
        return location;
    } catch {
        setCachedLocation(ip, 'Unknown');
        return 'Unknown';
    }
}

async function recordUserLoginEvent({
    req,
    user,
    loginType,
    UserLoginEvent,
    axios
}) {
    try {
        if (!UserLoginEvent || typeof UserLoginEvent.create !== 'function') return;
        if (!user || !user.id) return;

        const ip = extractClientIp(req);
        const userAgent = String((req && req.headers && req.headers['user-agent']) || '').trim().slice(0, 1024);
        const operatingSystem = parseOperatingSystem(userAgent);
        const location = await resolveGeoLocation(req, ip, axios);

        await UserLoginEvent.create({
            userId: Number.parseInt(user.id, 10),
            usernameSnapshot: String(user.username || '').trim() || `user-${user.id}`,
            loginType: normalizeLoginType(loginType),
            ipAddress: String(ip || 'unknown').slice(0, 120),
            location: String(location || 'Unknown').slice(0, 160),
            operatingSystem: String(operatingSystem || 'Unknown OS').slice(0, 120),
            userAgent
        });
    } catch (error) {
        console.error('Failed to record login history event:', error && error.message ? error.message : error);
    }
}

module.exports = {
    normalizeLoginType,
    formatLoginTypeLabel,
    extractClientIp,
    parseOperatingSystem,
    recordUserLoginEvent
};
