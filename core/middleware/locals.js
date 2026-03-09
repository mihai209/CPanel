const {
    DEFAULT_THEME_ID,
    normalizeThemeId,
    getThemeCssPath,
    getThemeCatalog,
    getUserThemeId,
    getUserCustomTheme
} = require('../themes');

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
        res.locals.error = req.query.error || null;
        res.locals.success = req.query.success || null;
        res.locals.themeCatalog = getThemeCatalog();

        let activeThemeId = DEFAULT_THEME_ID;
        let activeUserCustomTheme = getUserCustomTheme(null);
        try {
            if (req.session && req.session.user) {
                const sessionMissingTheme = !req.session.user.uiTheme;
                const sessionMissingCustomTheme = !req.session.user.uiCustomTheme;
                if ((sessionMissingTheme || sessionMissingCustomTheme) && User && req.session.user.id) {
                    const account = await User.findByPk(req.session.user.id, { attributes: ['id', 'permissions'] });
                    if (account) {
                        const accountData = account.toJSON();
                        req.session.user.uiTheme = getUserThemeId(accountData);
                        req.session.user.uiCustomTheme = getUserCustomTheme(accountData);
                    }
                }
                activeThemeId = normalizeThemeId(req.session.user.uiTheme);
                activeUserCustomTheme = getUserCustomTheme(req.session.user);
            }
        } catch (error) {
            console.warn('Failed to resolve user theme from session/db:', error.message || error);
        }

        res.locals.activeTheme = activeThemeId;
        res.locals.activeThemeCssPath = getThemeCssPath(activeThemeId);
        res.locals.activeUserCustomTheme = activeUserCustomTheme;
        res.locals.activeUserCustomThemeEnabled = Boolean(activeUserCustomTheme && activeUserCustomTheme.enabled);
        next();
    });
}

module.exports = {
    registerLocalsMiddleware
};
