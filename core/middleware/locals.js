const {
    DEFAULT_THEME_ID,
    normalizeThemeId,
    getThemeCssPath,
    getThemeCatalog,
    getUserThemeId
} = require('../themes');
const {
    getAvailableLanguageCodes,
    resolveRequestLanguage,
    translateByKey,
    translateText
} = require('../i18n');

function registerLocalsMiddleware(app, Settings, User, settingsCache = null) {
    app.use(async (req, res, next) => {
        try {
            let settingsMap = null;
            if (settingsCache && typeof settingsCache.getSettingsMap === 'function') {
                settingsMap = await settingsCache.getSettingsMap();
            }
            if (!settingsMap) {
                const allSettings = await Settings.findAll();
                settingsMap = {};
                allSettings.forEach((s) => {
                    settingsMap[s.key] = s.value;
                });
            }
            res.locals.settings = settingsMap;
            next();
        } catch (error) {
            console.error("Error fetching settings:", error);
            res.locals.settings = { brandName: 'CPanel', faviconUrl: '/favicon.ico' };
            next();
        }
    });

    app.use(async (req, res, next) => {
        const activeLanguage = resolveRequestLanguage(req);
        if (req.session) {
            req.session.uiLanguage = activeLanguage;
        }
        res.cookie('cpanel_lang', activeLanguage, {
            httpOnly: false,
            sameSite: 'lax',
            maxAge: 365 * 24 * 60 * 60 * 1000
        });

        const translateLiteral = (value) => {
            if (value === undefined || value === null) return value;
            return translateText(activeLanguage, String(value));
        };

        res.locals.langCode = activeLanguage;
        res.locals.availableLanguages = getAvailableLanguageCodes();
        res.locals.currentPath = req.originalUrl || req.path || '/';
        res.locals.t = (key, fallback = '') => translateByKey(activeLanguage, key, fallback);
        res.locals.translateText = translateLiteral;
        req.t = res.locals.t;
        req.translateText = translateLiteral;

        res.locals.error = req.query.error ? translateLiteral(req.query.error) : null;
        res.locals.warning = req.query.warning ? translateLiteral(req.query.warning) : null;
        res.locals.success = req.query.success ? translateLiteral(req.query.success) : null;
        res.locals.themeCatalog = getThemeCatalog();

        let activeThemeId = DEFAULT_THEME_ID;
        try {
            if (req.session && req.session.user) {
                if (!req.session.user.uiTheme && User && req.session.user.id) {
                    const account = await User.findByPk(req.session.user.id, { attributes: ['id', 'permissions'] });
                    if (account) {
                        req.session.user.uiTheme = getUserThemeId(account.toJSON());
                    }
                }
                activeThemeId = normalizeThemeId(req.session.user.uiTheme);
            }
        } catch (error) {
            console.warn('Failed to resolve user theme from session/db:', error.message || error);
        }

        res.locals.activeTheme = activeThemeId;
        res.locals.activeThemeCssPath = getThemeCssPath(activeThemeId);
        next();
    });
}

module.exports = {
    registerLocalsMiddleware
};
