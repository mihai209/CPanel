export const ReactRoutes = {
    dashboard: '/',
    serverConsolePattern: '/server/:containerId',
    serverFilesPattern: '/server/:containerId/files',
    serverBackupsPattern: '/server/:containerId/backups',
    serverNetworkPattern: '/server/:containerId/network',
    serverApiPattern: '/server/:containerId/api',
    serverDatabasesPattern: '/server/:containerId/databases',
    serverUsersPattern: '/server/:containerId/users',
    serverSchedulesPattern: '/server/:containerId/schedules',
    serverStartupPattern: '/server/:containerId/startup',
    serverFilesEditPattern: '/server/:containerId/files/edit',
    serverMinecraftCenterPattern: '/server/:containerId/minecraft-center',
    serverMinecraftAddonsPattern: '/server/:containerId/minecraft/addons',
    serverMinecraftInstallerPattern: '/server/:containerId/minecraft/installer',
    serverMinecraftProxyPattern: '/server/:containerId/minecraft/proxy',
    serverOverviewPattern: '/server/:containerId/overview',
    serverActivityPattern: '/server/:containerId/activity',
    serverTimelinePattern: '/server/:containerId/timeline',
    serverNotFoundPattern: '/server/:containerId/notfound',
    serverNoPermissionsPattern: '/server/:containerId/no-permissions',
    serverSuspendedPattern: '/server/:containerId/suspended',
    account: '/account',
    deviceLogin: '/account/device-login',
    themes: '/themes',
    rewards: '/rewards',
    afk: '/afk',
    experimentalFeatures: '/instable/outdated',
    changeView: '/experimental/change-view',
    connectorsCheck: '/connectors-check',
    notifications: '/notifications',
    admin: '/admin'
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
    const match = normalized.match(/^\/server\/([^/]+)(?:\/(minecraft-center|minecraft\/addons|minecraft\/installer|minecraft\/proxy|files\/edit|files|backups|network|api|databases|users|schedules|startup|overview|activity|timeline|notfound|no-permissions|suspended))?$/);
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
