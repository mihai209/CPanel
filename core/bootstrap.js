const express = require('express');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const SequelizeStore = require('connect-session-sequelize')(session.Store);

function bootstrapApp(deps) {
    const {
        app,
        sequelize,
        settingsModel,
        userModel,
        secretKey,
        passport,
        registerSecurityMiddleware,
        registerLocalsMiddleware
    } = deps;

    global.connectorStatus = {};

    registerSecurityMiddleware(app);

    const sessionStore = new SequelizeStore({
        db: sequelize,
        checkExpirationInterval: 15 * 60 * 1000,
        expiration: 7 * 24 * 60 * 60 * 1000
    });

    app.use(session({
        secret: secretKey,
        store: sessionStore,
        resave: false,
        saveUninitialized: false,
        proxy: true,
        cookie: {
            secure: false,
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        }
    }));

    sessionStore.sync();

    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await userModel.findByPk(id);
            done(null, user);
        } catch (error) {
            done(error, null);
        }
    });

    app.use(passport.initialize());
    app.use(passport.session());

    app.set('view engine', 'ejs');
    app.set('views', './views');
    app.use(express.static('public'));

    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 500,
        skip: (req) => req.path === '/ratelimited' || req.path.startsWith('/assets/'),
        handler: (req, res) => {
            res.redirect('/ratelimited');
        }
    });
    app.use(limiter);

    const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 5,
        skipSuccessfulRequests: true,
        message: 'Too many login attempts from this IP, please try again after 15 minutes.'
    });

    registerLocalsMiddleware(app, settingsModel);

    return {
        loginLimiter
    };
}

module.exports = { bootstrapApp };
