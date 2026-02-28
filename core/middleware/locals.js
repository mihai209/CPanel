function registerLocalsMiddleware(app, Settings) {
    app.use(async (req, res, next) => {
        try {
            const allSettings = await Settings.findAll();
            const settingsMap = {};
            allSettings.forEach((s) => {
                settingsMap[s.key] = s.value;
            });
            res.locals.settings = settingsMap;
            next();
        } catch (error) {
            console.error("Error fetching settings:", error);
            res.locals.settings = { brandName: 'CPanel', faviconUrl: '/favicon.ico' };
            next();
        }
    });

    app.use((req, res, next) => {
        res.locals.error = req.query.error || null;
        res.locals.success = req.query.success || null;
        next();
    });
}

module.exports = {
    registerLocalsMiddleware
};
