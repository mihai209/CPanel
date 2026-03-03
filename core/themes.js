const DEFAULT_THEME_ID = 'default';

const THEME_CATALOG = Object.freeze([
    {
        id: 'default',
        label: 'Default',
        cssPath: '/themes/default/index.css'
    },
    {
        id: 'minecraft',
        label: 'Minecraft',
        cssPath: '/themes/minecraft/index.css'
    },
    {
        id: 'gothic',
        label: 'Gothic',
        cssPath: '/themes/gothic/index.css'
    },
    {
        id: 'azure',
        label: 'Azure',
        cssPath: '/themes/azure/index.css'
    },
    {
        id: 'light',
        label: 'Light',
        cssPath: '/themes/light/index.css'
    },
    {
        id: 'discord-l',
        label: 'Discord L',
        cssPath: '/themes/discord-l/index.css'
    },
    {
        id: 'tropical-island',
        label: 'Tropical Island',
        cssPath: '/themes/tropical-island/index.css'
    },
    {
        id: 'ocean-deep-sea',
        label: 'Ocean / Deep Sea',
        cssPath: '/themes/ocean-deep-sea/index.css'
    },
    {
        id: 'jurassic-summer',
        label: 'Jurassic Summer',
        cssPath: '/themes/jurassic-summer/index.css'
    },
    {
        id: 'sunset-gamer',
        label: 'Sunset Gamer',
        cssPath: '/themes/sunset-gamer/index.css'
    },
    {
        id: 'minimal-summer-clean',
        label: 'Minimal Summer Clean',
        cssPath: '/themes/minimal-summer-clean/index.css'
    },
    {
        id: 'dino-cartoon-fun',
        label: 'Dino Cartoon Fun',
        cssPath: '/themes/dino-cartoon-fun/index.css'
    },
    {
        id: 'sky-islands-fantasy',
        label: 'Sky Islands Fantasy',
        cssPath: '/themes/sky-islands-fantasy/index.css'
    }
]);

const THEME_BY_ID = new Map(THEME_CATALOG.map((entry) => [entry.id, entry]));

function normalizeThemeId(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized || !THEME_BY_ID.has(normalized)) {
        return DEFAULT_THEME_ID;
    }
    return normalized;
}

function getThemeCssPath(themeId) {
    const normalized = normalizeThemeId(themeId);
    const entry = THEME_BY_ID.get(normalized);
    return entry ? entry.cssPath : THEME_BY_ID.get(DEFAULT_THEME_ID).cssPath;
}

function getThemeCatalog() {
    return THEME_CATALOG;
}

function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function getUserThemeId(userLike) {
    if (!userLike) return DEFAULT_THEME_ID;
    if (isPlainObject(userLike.permissions)) {
        return normalizeThemeId(userLike.permissions.uiTheme);
    }
    return normalizeThemeId(userLike.uiTheme);
}

function withThemeInPermissions(currentPermissions, themeId) {
    const nextPermissions = isPlainObject(currentPermissions) ? { ...currentPermissions } : {};
    nextPermissions.uiTheme = normalizeThemeId(themeId);
    return nextPermissions;
}

module.exports = {
    DEFAULT_THEME_ID,
    THEME_CATALOG,
    normalizeThemeId,
    getThemeCssPath,
    getThemeCatalog,
    getUserThemeId,
    withThemeInPermissions
};
