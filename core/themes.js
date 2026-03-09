const DEFAULT_THEME_ID = 'default';
const DEFAULT_USER_CUSTOM_THEME = Object.freeze({
    enabled: false,
    backgroundImageUrl: '',
    backgroundColor: '#0d0d0f',
    panelSurface: '#141419',
    cardBackground: '#1f2023',
    cardBorder: '#2e3036',
    accentColor: '#3b82f6',
    textColor: '#ffffff',
    mutedTextColor: '#a1a1aa',
    serverCardBackground: '#1f2023',
    serverCardBorder: '#2e3036',
    serverCardRadius: 12
});

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
    },
    {
        id: 'neon-circuit',
        label: 'Neon Circuit',
        cssPath: '/themes/neon-circuit/index.css'
    },
    {
        id: 'forest-night',
        label: 'Forest Night',
        cssPath: '/themes/forest-night/index.css'
    },
    {
        id: 'retro-synth',
        label: 'Retro Synth',
        cssPath: '/themes/retro-synth/index.css'
    },
    {
        id: 'm-bunicii',
        label: 'M-Bunicii Nature',
        cssPath: '/themes/m-bunicii/index.css'
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

function isSafeCssColor(value) {
    const raw = String(value || '').trim();
    if (!raw) return false;
    if (/^#[0-9a-fA-F]{3,8}$/.test(raw)) return true;
    if (/^rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+(\s*,\s*(0|0?\.\d+|1(\.0+)?)\s*)?\)$/.test(raw)) return true;
    if (/^hsla?\(\s*\d+\s*,\s*\d+%\s*,\s*\d+%(\s*,\s*(0|0?\.\d+|1(\.0+)?)\s*)?\)$/.test(raw)) return true;
    return false;
}

function sanitizeCssColor(value, fallback) {
    const raw = String(value || '').trim();
    return isSafeCssColor(raw) ? raw : fallback;
}

function sanitizeImageUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    let parsed;
    try {
        parsed = new URL(raw);
    } catch {
        return '';
    }
    const protocol = String(parsed.protocol || '').toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') return '';
    const pathname = String(parsed.pathname || '').toLowerCase();
    const allowed = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.avif'];
    if (!allowed.some((ext) => pathname.endsWith(ext))) return '';
    return parsed.toString();
}

function sanitizeRadius(value) {
    const parsed = Number.parseInt(String(value === undefined ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return DEFAULT_USER_CUSTOM_THEME.serverCardRadius;
    return Math.min(28, Math.max(4, parsed));
}

function normalizeUserCustomThemeConfig(input) {
    const source = isPlainObject(input) ? input : {};
    return {
        enabled: source.enabled === true || source.enabled === 'true' || source.enabled === 1 || source.enabled === '1' || source.enabled === 'on',
        backgroundImageUrl: sanitizeImageUrl(source.backgroundImageUrl),
        backgroundColor: sanitizeCssColor(source.backgroundColor, DEFAULT_USER_CUSTOM_THEME.backgroundColor),
        panelSurface: sanitizeCssColor(source.panelSurface, DEFAULT_USER_CUSTOM_THEME.panelSurface),
        cardBackground: sanitizeCssColor(source.cardBackground, DEFAULT_USER_CUSTOM_THEME.cardBackground),
        cardBorder: sanitizeCssColor(source.cardBorder, DEFAULT_USER_CUSTOM_THEME.cardBorder),
        accentColor: sanitizeCssColor(source.accentColor, DEFAULT_USER_CUSTOM_THEME.accentColor),
        textColor: sanitizeCssColor(source.textColor, DEFAULT_USER_CUSTOM_THEME.textColor),
        mutedTextColor: sanitizeCssColor(source.mutedTextColor, DEFAULT_USER_CUSTOM_THEME.mutedTextColor),
        serverCardBackground: sanitizeCssColor(source.serverCardBackground, DEFAULT_USER_CUSTOM_THEME.serverCardBackground),
        serverCardBorder: sanitizeCssColor(source.serverCardBorder, DEFAULT_USER_CUSTOM_THEME.serverCardBorder),
        serverCardRadius: sanitizeRadius(source.serverCardRadius)
    };
}

function getUserThemeId(userLike) {
    if (!userLike) return DEFAULT_THEME_ID;
    if (isPlainObject(userLike.permissions)) {
        return normalizeThemeId(userLike.permissions.uiTheme);
    }
    return normalizeThemeId(userLike.uiTheme);
}

function getUserCustomTheme(userLike) {
    if (!userLike) return { ...DEFAULT_USER_CUSTOM_THEME };
    if (isPlainObject(userLike.permissions)) {
        return normalizeUserCustomThemeConfig(userLike.permissions.uiCustomTheme);
    }
    return normalizeUserCustomThemeConfig(userLike.uiCustomTheme);
}

function withThemeInPermissions(currentPermissions, themeId) {
    const nextPermissions = isPlainObject(currentPermissions) ? { ...currentPermissions } : {};
    nextPermissions.uiTheme = normalizeThemeId(themeId);
    return nextPermissions;
}

function withUserCustomThemeInPermissions(currentPermissions, nextCustomTheme) {
    const nextPermissions = isPlainObject(currentPermissions) ? { ...currentPermissions } : {};
    const currentCustomTheme = normalizeUserCustomThemeConfig(nextPermissions.uiCustomTheme);
    const merged = normalizeUserCustomThemeConfig({
        ...currentCustomTheme,
        ...(isPlainObject(nextCustomTheme) ? nextCustomTheme : {})
    });
    nextPermissions.uiCustomTheme = merged;
    return nextPermissions;
}

function withUserCustomThemeEnabled(currentPermissions, enabled) {
    return withUserCustomThemeInPermissions(currentPermissions, { enabled: Boolean(enabled) });
}

module.exports = {
    DEFAULT_THEME_ID,
    DEFAULT_USER_CUSTOM_THEME,
    THEME_CATALOG,
    normalizeThemeId,
    getThemeCssPath,
    getThemeCatalog,
    normalizeUserCustomThemeConfig,
    getUserThemeId,
    getUserCustomTheme,
    withThemeInPermissions,
    withUserCustomThemeInPermissions,
    withUserCustomThemeEnabled
};
