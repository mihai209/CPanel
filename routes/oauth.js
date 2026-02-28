const DiscordStrategy = require('passport-discord').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const RedditStrategy = require('passport-reddit').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const crypto = require('crypto');
const bcrypt = require('bcrypt');

function registerOAuthRoutes({ app, passport, User, LinkedAccount, md5 }) {
    const APP_OAUTH_URL = (process.env.APP_URL || '').replace(/\/$/, '');
    const OAUTH_DEBUG_ENABLED = ['1', 'true', 'yes', 'on'].includes(String(process.env.DEBUG || '').trim().toLowerCase());
    const oauthDebug = (...args) => {
        if (!OAUTH_DEBUG_ENABLED) return;
        console.log(...args);
    };

    // Helper: generate a unique username from a display name
    async function generateUniqueUsername(base) {
        const sanitized = String(base || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20) || 'user';
        let candidate = sanitized;
        let i = 1;
        while (await User.findOne({ where: { username: candidate } })) {
            candidate = `${sanitized}${i++}`;
        }
        return candidate;
    }

    // Helper: finish OAuth login — upsert user, set session, redirect
    async function handleOAuthCallback(profile, provider, done, req) {
        try {
            const oauthEmail = (
                (profile.emails && profile.emails[0] && profile.emails[0].value) ||
                profile.email ||
                (profile._json && profile._json.email)
            ) ? String((profile.emails && profile.emails[0] && profile.emails[0].value) || profile.email || (profile._json && profile._json.email)).toLowerCase().trim() : null;
            const oauthId = String(profile.id || '');
            const oauthUsername = profile.username || profile.displayName || profile.id;

            oauthDebug(`[OAuth Debug] Provider: ${provider}, ID: ${oauthId}, Email: ${oauthEmail}, Username: ${oauthUsername}`);
            oauthDebug(`[OAuth Debug] Profile:`, JSON.stringify(profile, null, 2));

            // 1. Check if user is already logged in (Linking flow)
            const currentUser = (req && req.user) || (req && req.session && req.session.user);

            oauthDebug(`[OAuth Debug] Current User in Req:`, !!req.user);
            oauthDebug(`[OAuth Debug] Current User in Session:`, !!(req.session && req.session.user));
            if (req && req.session) {
                oauthDebug(`[OAuth Debug] Raw Session ID:`, req.sessionID);
                oauthDebug(`[OAuth Debug] Session Keys:`, Object.keys(req.session));
            }

            if (currentUser) {
                const loggedInUser = await User.findByPk(currentUser.id);
                if (!loggedInUser) return done(new Error('User not found'), null);

                // Check if this providerId is already linked to ANOTHER user
                const existingLink = await LinkedAccount.findOne({ where: { provider, providerId: oauthId } });
                if (existingLink && existingLink.userId !== loggedInUser.id) {
                    return done(null, false, { message: 'This OAuth account is already linked to another user.' });
                }

                // Also check legacy oauthId on User table
                const existingUserWithLegacyLink = await User.findOne({ where: { oauthProvider: provider, oauthId } });
                if (existingUserWithLegacyLink && existingUserWithLegacyLink.id !== loggedInUser.id) {
                    return done(null, false, { message: 'This OAuth account is already linked to another user.' });
                }

                // Create or update link
                const [link, created] = await LinkedAccount.findOrCreate({
                    where: { userId: loggedInUser.id, provider },
                    defaults: { providerId: oauthId, providerEmail: oauthEmail, providerUsername: oauthUsername }
                });

                if (!created) {
                    await link.update({ providerId: oauthId, providerEmail: oauthEmail, providerUsername: oauthUsername });
                }

                oauthDebug(`[OAuth Link] Provider ${provider} linked for user ${loggedInUser.id}`);
                return done(null, loggedInUser);
            }

            // 2. Login flow: find by LinkedAccount
            let linkedAcc = await LinkedAccount.findOne({ where: { provider, providerId: oauthId } });
            let user;
            if (linkedAcc) {
                user = await User.findByPk(linkedAcc.userId);
            }

            // 3. Fallback: legacy mapping or email
            if (!user) {
                user = await User.findOne({ where: { oauthProvider: provider, oauthId } });

                if (!user && oauthEmail) {
                    user = await User.findOne({ where: { email: oauthEmail } });

                    if (user) {
                        oauthDebug(`[OAuth] Linking existing user ${user.username} (ID: ${user.id}) with provider ${provider}.`);
                        if (req && req.session) {
                            req.session.oauthAutoLinked = true;
                        }
                    }
                }
            }

            if (!user) {
                // 4. Create new user
                const displayName = profile.displayName || profile.username || profile.name || 'User';
                const username = await generateUniqueUsername(displayName);
                const avatarUrl = (profile.photos && profile.photos[0]) ? profile.photos[0].value : null;
                const randomPassword = crypto.randomBytes(32).toString('hex');
                const hashedPassword = await bcrypt.hash(randomPassword, 12);

                user = await User.create({
                    username,
                    email: oauthEmail || `${provider}_${profile.id}@oauth.local`,
                    password: hashedPassword,
                    firstName: (profile.name && profile.name.givenName) || displayName,
                    lastName: (profile.name && profile.name.familyName) || '',
                    avatarUrl,
                    avatarProvider: 'url',
                    oauthProvider: provider,
                    oauthId: oauthId
                });

                await LinkedAccount.create({ userId: user.id, provider, providerId: oauthId, providerEmail: oauthEmail, providerUsername: oauthUsername });
            } else {
                // Link if not already linked (migration or first time via this provider if email matched)
                const [link, created] = await LinkedAccount.findOrCreate({
                    where: { userId: user.id, provider },
                    defaults: { providerId: oauthId, providerEmail: oauthEmail, providerUsername: oauthUsername }
                });
                if (!created) {
                    await link.update({ providerId: oauthId, providerEmail: oauthEmail, providerUsername: oauthUsername });
                }

                // Sync avatar
                if (user.avatarProvider === 'url') {
                    const avatarUrl = (profile.photos && profile.photos[0]) ? profile.photos[0].value : null;
                    if (avatarUrl) await user.update({ avatarUrl });
                }
            }

            if (user.isSuspended) {
                return done(null, false, { message: 'Your account has been suspended. Contact an administrator.' });
            }

            return done(null, user);
        } catch (err) {
            return done(err, null);
        }
    }

    // Middleware: dynamically register (or skip) a Passport strategy before the auth route
    function withStrategy(provider, strategyFactory) {
        return (req, res, next) => {
            const settings = res.locals.settings || {};
            const enabledKey = `auth${provider.charAt(0).toUpperCase() + provider.slice(1)}Enabled`;

            if (settings[enabledKey] !== 'true') {
                return res.redirect('/login?error=' + encodeURIComponent(`${provider} login is not enabled.`));
            }

            const clientIdKey = `auth${provider.charAt(0).toUpperCase() + provider.slice(1)}ClientId`;
            const clientSecretKey = `auth${provider.charAt(0).toUpperCase() + provider.slice(1)}ClientSecret`;
            const clientId = settings[clientIdKey] || '';
            const clientSecret = settings[clientSecretKey] || '';

            if (!clientId || !clientSecret) {
                return res.redirect('/login?error=' + encodeURIComponent(`${provider} login is missing Client ID or Client Secret. Configure it in Admin → Auth Providers.`));
            }

            // Register strategy fresh (credentials may have changed)
            passport.use(provider, strategyFactory(clientId, clientSecret));
            next();
        };
    }

    // Helper: finalize session after successful OAuth authentication
    async function finalizeOAuthLogin(user, req, res, next) {
        const isAlreadyLoggedIn = (req.user && String(req.user.id) === String(user.id)) || (req.session.user && String(req.session.user.id) === String(user.id));
        const wasAutoLinked = req.session.oauthAutoLinked;
        delete req.session.oauthAutoLinked;

        oauthDebug(`[OAuth Finalize] User: ${user.username}, Already Logged In: ${isAlreadyLoggedIn}, Auto Linked: ${wasAutoLinked}`);

        if (isAlreadyLoggedIn || wasAutoLinked) {
            return res.redirect('/account?success=' + encodeURIComponent(wasAutoLinked ? 'Account automatically linked by email!' : 'Account linked successfully!'));
        }

        if (user.twoFactorEnabled) {
            req.session.login2faUser = {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin,
                coins: Number.isFinite(Number(user.coins)) ? Number(user.coins) : 0,
                gravatarHash: md5(user.email.trim().toLowerCase()),
                avatarUrl: user.avatarUrl,
                avatarProvider: user.avatarProvider
            };

            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });

            return res.redirect('/login/2fa');
        }

        // Standard session login
        req.logIn(user, (loginErr) => {
            if (loginErr) return next(loginErr);
            req.session.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin,
                coins: Number.isFinite(Number(user.coins)) ? Number(user.coins) : 0,
                avatarUrl: user.avatarUrl,
                avatarProvider: user.avatarProvider,
                gravatarHash: md5(user.email.trim().toLowerCase())
            };
            req.session.save(() => res.redirect('/'));
        });
    }

    // ---- Discord ----
    app.get('/auth/discord',
        withStrategy('discord', (clientId, clientSecret) =>
            new DiscordStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/discord/callback`,
                scope: ['identify', 'email'],
                passReqToCallback: true
            }, (req, accessToken, refreshToken, profile, done) => handleOAuthCallback(profile, 'discord', done, req))
        ),
        passport.authenticate('discord')
    );

    app.get('/auth/discord/callback',
        (req, res, next) => {
            const settings = res.locals.settings || {};
            const clientId = settings.authDiscordClientId || '';
            const clientSecret = settings.authDiscordClientSecret || '';
            if (!clientId || !clientSecret) return res.redirect('/login?error=' + encodeURIComponent('Discord is not configured.'));
            passport.use('discord', new DiscordStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/discord/callback`,
                scope: ['identify', 'email'],
                passReqToCallback: true
            }, (req, at, rt, profile, done) => handleOAuthCallback(profile, 'discord', done, req)));
            next();
        },
        (req, res, next) => {
            passport.authenticate('discord', async (err, user, info) => {
                if (err) return next(err);
                if (!user) return res.redirect('/login?error=' + encodeURIComponent((info && info.message) || 'Discord authentication failed.'));
                await finalizeOAuthLogin(user, req, res, next);
            })(req, res, next);
        }
    );

    // ---- Google ----
    app.get('/auth/google',
        withStrategy('google', (clientId, clientSecret) =>
            new GoogleStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/google/callback`,
                passReqToCallback: true
            }, (req, accessToken, refreshToken, profile, done) => handleOAuthCallback(profile, 'google', done, req))
        ),
        passport.authenticate('google', { scope: ['profile', 'email'] })
    );

    app.get('/auth/google/callback',
        (req, res, next) => {
            const settings = res.locals.settings || {};
            const clientId = settings.authGoogleClientId || '';
            const clientSecret = settings.authGoogleClientSecret || '';
            if (!clientId || !clientSecret) return res.redirect('/login?error=' + encodeURIComponent('Google is not configured.'));
            passport.use('google', new GoogleStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/google/callback`,
                passReqToCallback: true
            }, (req, at, rt, profile, done) => handleOAuthCallback(profile, 'google', done, req)));
            next();
        },
        (req, res, next) => {
            passport.authenticate('google', async (err, user, info) => {
                if (err) return next(err);
                if (!user) return res.redirect('/login?error=' + encodeURIComponent((info && info.message) || 'Google authentication failed.'));
                await finalizeOAuthLogin(user, req, res, next);
            })(req, res, next);
        }
    );

    // ---- Reddit ----
    app.get('/auth/reddit',
        withStrategy('reddit', (clientId, clientSecret) =>
            new RedditStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/reddit/callback`,
                passReqToCallback: true
            }, (req, accessToken, refreshToken, profile, done) => handleOAuthCallback(profile, 'reddit', done, req))
        ),
        passport.authenticate('reddit', { state: 'true', duration: 'permanent' })
    );

    app.get('/auth/reddit/callback',
        (req, res, next) => {
            const settings = res.locals.settings || {};
            const clientId = settings.authRedditClientId || '';
            const clientSecret = settings.authRedditClientSecret || '';
            if (!clientId || !clientSecret) return res.redirect('/login?error=' + encodeURIComponent('Reddit is not configured.'));
            passport.use('reddit', new RedditStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/reddit/callback`,
                passReqToCallback: true
            }, (req, at, rt, profile, done) => handleOAuthCallback(profile, 'reddit', done, req)));
            next();
        },
        (req, res, next) => {
            passport.authenticate('reddit', async (err, user, info) => {
                if (err) return next(err);
                if (!user) return res.redirect('/login?error=' + encodeURIComponent((info && info.message) || 'Reddit authentication failed.'));
                await finalizeOAuthLogin(user, req, res, next);
            })(req, res, next);
        }
    );

    // ---- GitHub ----
    app.get('/auth/github',
        withStrategy('github', (clientId, clientSecret) =>
            new GitHubStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/github/callback`,
                scope: ['user:email'],
                passReqToCallback: true
            }, (req, accessToken, refreshToken, profile, done) => handleOAuthCallback(profile, 'github', done, req))
        ),
        passport.authenticate('github')
    );

    app.get('/auth/github/callback',
        (req, res, next) => {
            const settings = res.locals.settings || {};
            const clientId = settings.authGithubClientId || '';
            const clientSecret = settings.authGithubClientSecret || '';
            if (!clientId || !clientSecret) return res.redirect('/login?error=' + encodeURIComponent('GitHub is not configured.'));
            passport.use('github', new GitHubStrategy({
                clientID: clientId,
                clientSecret: clientSecret,
                callbackURL: `${APP_OAUTH_URL}/auth/github/callback`,
                scope: ['user:email'],
                passReqToCallback: true
            }, (req, at, rt, profile, done) => handleOAuthCallback(profile, 'github', done, req)));
            next();
        },
        (req, res, next) => {
            passport.authenticate('github', async (err, user, info) => {
                if (err) return next(err);
                if (!user) return res.redirect('/login?error=' + encodeURIComponent((info && info.message) || 'GitHub authentication failed.'));
                await finalizeOAuthLogin(user, req, res, next);
            })(req, res, next);
        }
    );
}

module.exports = {
    registerOAuthRoutes
};
