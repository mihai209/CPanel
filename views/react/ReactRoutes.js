export const ReactRoutes = {
    dashboard: '/',
    serverConsolePattern: '/server/:containerId',
    account: '/account',
    deviceLogin: '/account/device-login',
    themes: '/themes',
    experimentalFeatures: '/experimental-features',
    changeView: '/experimental/change-view'
};

const RESERVED_SERVER_SEGMENTS = new Set(['notfound', 'no-permissions', 'suspended']);

export function resolveBrandImage(pageData = {}) {
    return pageData.faviconUrl || '/assets/rocky.png';
}

export function resolveUserAvatar(user = {}, fallback = '/assets/rocky.png') {
    if (user && user.avatarProvider === 'url' && user.avatarUrl) {
        return user.avatarUrl;
    }
    if (user && user.gravatarHash) {
        return `https://www.gravatar.com/avatar/${user.gravatarHash}?d=retro&s=120`;
    }
    return fallback;
}

export function buildServerConsoleRoute(containerId = '') {
    return `/server/${encodeURIComponent(String(containerId || '').trim())}`;
}

export function isServerConsolePath(pathname = '') {
    const normalized = String(pathname || '').trim().replace(/\/+$/, '') || '/';
    const match = normalized.match(/^\/server\/([^/]+)$/);
    if (!match) return false;
    try {
        return !RESERVED_SERVER_SEGMENTS.has(decodeURIComponent(match[1]).trim().toLowerCase());
    } catch {
        return !RESERVED_SERVER_SEGMENTS.has(String(match[1] || '').trim().toLowerCase());
    }
}
