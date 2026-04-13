export const ReactRoutes = {
    dashboard: '/',
    serverConsolePattern: '/server/:containerId',
    serverFilesPattern: '/server/:containerId/files',
    serverBackupsPattern: '/server/:containerId/backups',
    serverNetworkPattern: '/server/:containerId/network',
    serverApiPattern: '/server/:containerId/api',
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

export function buildServerFilesRoute(containerId = '') {
    return `/server/${encodeURIComponent(String(containerId || '').trim())}/files`;
}

export function buildServerBackupsRoute(containerId = '') {
    return `/server/${encodeURIComponent(String(containerId || '').trim())}/backups`;
}

export function buildServerNetworkRoute(containerId = '') {
    return `/server/${encodeURIComponent(String(containerId || '').trim())}/network`;
}

export function buildServerApiRoute(containerId = '') {
    return `/server/${encodeURIComponent(String(containerId || '').trim())}/api`;
}

function parseServerRoute(pathname = '') {
    const normalized = String(pathname || '').trim().replace(/\/+$/, '') || '/';
    const match = normalized.match(/^\/server\/([^/]+)(?:\/(files|backups|network|api))?$/);
    if (!match) return null;
    let containerId = '';
    try {
        containerId = decodeURIComponent(match[1]).trim();
    } catch {
        containerId = String(match[1] || '').trim();
    }
    if (!containerId || RESERVED_SERVER_SEGMENTS.has(containerId.toLowerCase())) {
        return null;
    }
    return {
        containerId,
        page: match[2] || 'console'
    };
}

export function isServerConsolePath(pathname = '') {
    const parsed = parseServerRoute(pathname);
    return Boolean(parsed && parsed.page === 'console');
}

export function resolveServerReactPage(pathname = '') {
    return parseServerRoute(pathname);
}
