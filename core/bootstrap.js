const express = require('express');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const SequelizeStore = require('connect-session-sequelize')(session.Store);
const { bootInfo, bootWarn } = require('./boot');

function bootstrapApp(deps) {
    const {
        app,
        sequelize,
        redisClient,
        settingsCache,
        settingsModel,
        userModel,
        secretKey,
        passport,
        registerSecurityMiddleware,
        registerLocalsMiddleware
    } = deps;

    global.connectorStatus = {};

    registerSecurityMiddleware(app);

    let sessionStore = null;
    let usingRedisSessionStore = false;

    if (redisClient) {
        try {
            const redisModule = require('connect-redis');
            const RedisStore = redisModule.RedisStore || redisModule.default || redisModule;
            const prefix = String(process.env.REDIS_SESSION_PREFIX || 'cpanel:sess:');
            sessionStore = new RedisStore({
                client: redisClient,
                prefix
            });
            usingRedisSessionStore = true;
            bootInfo('configured session store type=redis prefix=%s', prefix);
        } catch (error) {
            bootWarn('failed to initialize redis session store; using database session store error=%s', error.message || error);
            sessionStore = null;
        }
    }

    if (!sessionStore) {
        sessionStore = new SequelizeStore({
            db: sequelize,
            checkExpirationInterval: 15 * 60 * 1000,
            expiration: 7 * 24 * 60 * 60 * 1000
        });
        bootInfo('configured session store type=database');
    }

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

    if (!usingRedisSessionStore && typeof sessionStore.sync === 'function') {
        sessionStore.sync().catch((error) => {
            console.error('Session store sync failed:', error);
        });
    }

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

    registerLocalsMiddleware(app, settingsModel, userModel, settingsCache);

    return {
        loginLimiter
    };
}

module.exports = { bootstrapApp };
