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
        SecurityEvent,
        secretKey,
        passport,
        registerSecurityMiddleware,
        registerLocalsMiddleware
    } = deps;

    global.connectorStatus = {};

    const extractIp = (req) => {
        const forwarded = req && req.headers ? req.headers['x-forwarded-for'] : '';
        const raw = Array.isArray(forwarded)
            ? forwarded[0]
            : String(forwarded || '').split(',')[0];
        const value = String(raw || (req && req.ip) || (req && req.socket && req.socket.remoteAddress) || '').trim();
        return value.replace(/^::ffff:/, '') || null;
    };
    const truncate = (value, max = 255) => {
        const text = String(value === undefined || value === null ? '' : value);
        return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
    };
    const logSecurityEvent = (req, payload) => {
        if (!SecurityEvent || typeof SecurityEvent.create !== 'function') return;
        const userId = req && req.session && req.session.user ? Number.parseInt(req.session.user.id, 10) || null : null;
        SecurityEvent.create({
            userId,
            severity: truncate(payload && payload.severity ? payload.severity : 'medium', 16),
            category: truncate(payload && payload.category ? payload.category : 'rate_limit', 40),
            eventType: truncate(payload && payload.eventType ? payload.eventType : 'rate_limit.hit', 120),
            message: truncate(payload && payload.message ? payload.message : 'Rate limit reached.', 255),
            source: 'panel',
            method: truncate(req && req.method ? req.method : '', 10) || null,
            path: truncate((req && (req.originalUrl || req.url)) || '', 255) || null,
            ip: truncate(extractIp(req) || '', 120) || null,
            userAgent: truncate((req && req.headers && req.headers['user-agent']) || '', 2000) || null,
            requestId: truncate((req && req.requestId) || '', 64) || null,
            metadata: payload && payload.metadata ? payload.metadata : {}
        }).catch(() => {});
    };

    registerSecurityMiddleware(app, {
        SecurityEvent
    });

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
            req.__securityRateLimitedLogged = true;
            logSecurityEvent(req, {
                severity: 'medium',
                category: 'rate_limit',
                eventType: 'rate_limit.global',
                message: 'Global rate limiter triggered.',
                metadata: { scope: 'global' }
            });
            res.redirect('/ratelimited');
        }
    });
    app.use(limiter);

    const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 5,
        skipSuccessfulRequests: true,
        handler: (req, res) => {
            req.__securityRateLimitedLogged = true;
            logSecurityEvent(req, {
                severity: 'high',
                category: 'rate_limit',
                eventType: 'rate_limit.login',
                message: 'Login rate limiter triggered.',
                metadata: { scope: 'login' }
            });
            return res.status(429).send('Too many login attempts from this IP, please try again after 15 minutes.');
        }
    });

    registerLocalsMiddleware(app, settingsModel, userModel, settingsCache);

    return {
        loginLimiter
    };
}

module.exports = { bootstrapApp };
