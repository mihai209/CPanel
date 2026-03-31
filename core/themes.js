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

const THEME_PREVIEWS = Object.freeze({
    ace: {
        eyebrow: 'Refined',
        summary: 'Cool blue panels with a measured gold accent.',
        background: 'linear-gradient(145deg, #0d1326 0%, #141c35 46%, #1d2847 100%)',
        swatches: ['#5d85ff', '#ffd666', '#eef4ff']
    },
    azure: {
        eyebrow: 'Cloud',
        summary: 'Crisp blue gradients with bright panel edges.',
        background: 'linear-gradient(145deg, #0a1630 0%, #123a7a 100%)',
        swatches: ['#4f7cff', '#7cc7ff', '#dceaff']
    },
    default: {
        eyebrow: 'Base',
        summary: 'Neutral dark shell tuned for daily use.',
        background: 'linear-gradient(145deg, #111216 0%, #1b1d23 100%)',
        swatches: ['#3b82f6', '#2e3036', '#f4f4f5']
    },
    'dino-cartoon-fun': {
        eyebrow: 'Playful',
        summary: 'Punchy greens and warm cartoon contrast.',
        background: 'linear-gradient(145deg, #13281d 0%, #355d2d 100%)',
        swatches: ['#82d957', '#ffd166', '#f8fff0']
    },
    'forest-night': {
        eyebrow: 'Moody',
        summary: 'Dense forest tones with subdued teal glow.',
        background: 'linear-gradient(145deg, #07120f 0%, #10211d 100%)',
        swatches: ['#5fd1a7', '#27443b', '#e4fff7']
    },
    gothic: {
        eyebrow: 'Dramatic',
        summary: 'Heavy charcoal surfaces with blood-red trim.',
        background: 'linear-gradient(145deg, #120b12 0%, #26111d 100%)',
        swatches: ['#bf375f', '#4b1021', '#ffe3ea']
    },
    hacker: {
        eyebrow: 'Terminal',
        summary: 'Hard green glow over near-black control surfaces.',
        background: 'linear-gradient(180deg, #030807 0%, #07110e 38%, #081511 100%)',
        swatches: ['#3bff9a', '#0b1b13', '#dfffee']
    },
    'jurassic-summer': {
        eyebrow: 'Wild',
        summary: 'Sunlit jungle palette with amber callouts.',
        background: 'linear-gradient(145deg, #17311f 0%, #406329 100%)',
        swatches: ['#9be15d', '#ffb84d', '#f7ffe8']
    },
    light: {
        eyebrow: 'Bright',
        summary: 'Clean light surfaces with calm blue controls.',
        background: 'linear-gradient(145deg, #f2f7ff 0%, #dbe7f8 100%)',
        swatches: ['#3b82f6', '#ffffff', '#1f2937']
    },
    'm-bunicii': {
        eyebrow: 'Nature',
        summary: 'Wood, moss, and gold wrapped around a custom backdrop.',
        background: 'linear-gradient(145deg, #1f3d2b 0%, #314f39 100%)',
        swatches: ['#4caf50', '#6b4f2a', '#f5c542']
    },
    minecraft: {
        eyebrow: 'Blocky',
        summary: 'Minecraft-inspired greens and earthy shadows.',
        background: 'linear-gradient(145deg, #183320 0%, #355f32 100%)',
        swatches: ['#6cc04a', '#8b5e3c', '#eef7ea']
    },
    'minimal-summer-clean': {
        eyebrow: 'Clean',
        summary: 'Soft light contrast with uncluttered accents.',
        background: 'linear-gradient(145deg, #f8ead1 0%, #f3d9a9 100%)',
        swatches: ['#ff9f43', '#fff8ef', '#3a2c1d']
    },
    'neon-circuit': {
        eyebrow: 'Electric',
        summary: 'Neon cyan currents through dark glass layers.',
        background: 'linear-gradient(140deg, #05060d 0%, #0b1020 45%, #0a0f1f 100%)',
        swatches: ['#2effc8', '#ff94e0', '#e9f8ff']
    },
    'ocean-deep-sea': {
        eyebrow: 'Abyss',
        summary: 'Blue depth with aquatic glow and quiet contrast.',
        background: 'linear-gradient(145deg, #081625 0%, #103c5b 100%)',
        swatches: ['#4cc9f0', '#12324a', '#dff7ff']
    },
    'retro-synth': {
        eyebrow: 'Synthwave',
        summary: 'Sunset magenta and electric cyan over dark chrome.',
        background: 'linear-gradient(145deg, #180d26 0%, #36124a 100%)',
        swatches: ['#ff5db1', '#5bc0ff', '#ffe6f7']
    },
    'school-again': {
        eyebrow: 'Notebook',
        summary: 'Warm wood and classroom blue with nostalgic contrast.',
        background: 'linear-gradient(180deg, #f1dfb8 0%, #d2b48c 36%, #8b5e3c 100%)',
        swatches: ['#62b5ff', '#ffe19a', '#fff4dd']
    },
    'sky-islands-fantasy': {
        eyebrow: 'Airborne',
        summary: 'Floating fantasy palette with airy blue light.',
        background: 'linear-gradient(145deg, #0f1e37 0%, #395f98 100%)',
        swatches: ['#8fd3ff', '#c3f0ff', '#eefbff']
    },
    'sunset-gamer': {
        eyebrow: 'Late Glow',
        summary: 'Orange-violet heat built for evening sessions.',
        background: 'linear-gradient(145deg, #1e1428 0%, #5e2e50 100%)',
        swatches: ['#ff9f43', '#9b5cff', '#ffe9d6']
    },
    'super-dark': {
        eyebrow: 'Stealth',
        summary: 'Almost-black surfaces with restrained high contrast.',
        background: 'linear-gradient(180deg, #020202 0%, #070707 36%, #0c0c0d 100%)',
        swatches: ['#f4f4f5', '#0a0a0b', '#27272a']
    },
    'tropical-island': {
        eyebrow: 'Holiday',
        summary: 'Bright aqua and sand for a warm lighter panel mood.',
        background: 'linear-gradient(145deg, #10313c 0%, #1f7d8c 100%)',
        swatches: ['#4dd0e1', '#ffd166', '#effff8']
    },
    'winter-time': {
        eyebrow: 'Frost',
        summary: 'Cold blues and white haze over glassy panels.',
        background: 'linear-gradient(180deg, #cde7ff 0%, #7da7d9 42%, #264b73 100%)',
        swatches: ['#d8efff', '#7da7d9', '#f5fbff']
    },
    'zombie-apocalipse': {
        eyebrow: 'Survival',
        summary: 'Muted decay with toxic green and ember red accents.',
        background: 'linear-gradient(180deg, #181b16 0%, #262d21 38%, #0f120e 100%)',
        swatches: ['#92ff58', '#ff7858', '#f0f7e9']
    }
});

const THEME_CATALOG = Object.freeze([
    {
        id: 'ace',
        label: 'Ace',
        cssPath: '/themes/ace/index.css'
    },
    {
        id: 'default',
        label: 'Default',
        cssPath: '/themes/default/index.css'
    },
    {
        id: 'hacker',
        label: 'Hacker',
        cssPath: '/themes/hacker/index.css'
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
    },
    {
        id: 'school-again',
        label: 'School Again?',
        cssPath: '/themes/school-again/index.css'
    },
    {
        id: 'super-dark',
        label: 'Super Dark',
        cssPath: '/themes/super-dark/index.css'
    },
    {
        id: 'winter-time',
        label: 'Winter Time',
        cssPath: '/themes/winter-time/index.css'
    },
    {
        id: 'zombie-apocalipse',
        label: 'Zombie Apocalipse',
        cssPath: '/themes/zombie-apocalipse/index.css'
    }
].map((entry) => ({
    ...entry,
    preview: THEME_PREVIEWS[entry.id] || {
        eyebrow: 'Preset',
        summary: 'Preset panel styling for your account.',
        background: 'linear-gradient(145deg, #141419 0%, #1f2023 100%)',
        swatches: ['#3b82f6', '#2e3036', '#ffffff']
    }
})).slice().sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: 'base', numeric: true })));

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
