export const ReactRoutes = {
    dashboard: '/',
    account: '/account',
    deviceLogin: '/account/device-login',
    themes: '/themes',
    experimentalFeatures: '/experimental-features',
    changeView: '/experimental/change-view'
};

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
