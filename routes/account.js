const {
    DEFAULT_USER_CUSTOM_THEME,
    getThemeCatalog,
    normalizeThemeId,
    normalizeUserCustomThemeConfig,
    getUserThemeId,
    getUserCustomTheme,
    withThemeInPermissions,
    withUserCustomThemeInPermissions,
    withUserCustomThemeEnabled
} = require('../core/themes');
const { getGoogleTokenSettingKey } = require('../core/backups/google-drive');
const { formatLoginTypeLabel } = require('../core/helpers/login-history');
const { sendToUserUI } = require('../core/websocket-runtime');
const {
    getNotificationSettings,
    countUnreadNotifications,
    listNotifications,
    markNotificationRead,
    markAllNotificationsRead
} = require('../core/notifications/service');

function registerAccountRoutes({
    app,
    requireAuth,
    requireAdmin,
    User,
    LinkedAccount,
    UserLoginEvent,
    Settings,
    Op,
    md5,
    APP_URL,
    speakeasy,
    QRCode,
    bcrypt,
    UserNotification,
    UserBrowserSubscription,
    NotificationDeliveryLog
}) {
    const allowedThemeIds = new Set(getThemeCatalog().map((entry) => entry.id));
    const defaultCustomTheme = normalizeUserCustomThemeConfig(DEFAULT_USER_CUSTOM_THEME);

    const parseToggle = (value) => {
        if (value === true || value === 'true' || value === 1 || value === '1' || value === 'on' || value === 'yes') return true;
        return false;
    };

    const normalizeExperimentalViewMode = (value) => {
        const val = String(value || '').trim().toLowerCase();
        return val === 'ejs' ? 'ejs' : 'react';
    };

    const wantsReactPageData = (req) => {
        return String(req && req.query ? req.query.__reactData || '' : '').trim() === '1';
    };

    const updateSessionThemeState = (req, themeId, customTheme) => {
        if (!req || !req.session || !req.session.user) return;
        if (themeId) req.session.user.uiTheme = normalizeThemeId(themeId);
        if (customTheme) req.session.user.uiCustomTheme = normalizeUserCustomThemeConfig(customTheme);
    };

    const updateSessionExperimentalState = (req, userLike = null) => {
        if (!req || !req.session || !req.session.user) return;
        const source = userLike && typeof userLike.toJSON === 'function' ? userLike.toJSON() : userLike;
        if (source && Object.prototype.hasOwnProperty.call(source, 'experimentalAiEnabled')) {
            req.session.user.experimentalAiEnabled = Boolean(source.experimentalAiEnabled);
        }
        if (source && Object.prototype.hasOwnProperty.call(source, 'experimentalViewMode')) {
            req.session.user.experimentalViewMode = normalizeExperimentalViewMode(source.experimentalViewMode);
        }
    };

    const getAiAdminConfig = async () => {
        if (!Settings || typeof Settings.findByPk !== 'function') {
            return { enabled: false, providers: [], defaultProviderId: '' };
        }
        const row = await Settings.findByPk('aiAgentsConfig');
        if (!row || !row.value) return { enabled: false, providers: [], defaultProviderId: '' };
        try {
            const parsed = JSON.parse(row.value);
            if (!parsed || typeof parsed !== 'object') return { enabled: false, providers: [], defaultProviderId: '' };
            return {
                enabled: String(parsed.enabled || 'false').toLowerCase() === 'true',
                providers: Array.isArray(parsed.providers) ? parsed.providers : [],
                defaultProviderId: String(parsed.defaultProviderId || '')
            };
        } catch {
            return { enabled: false, providers: [], defaultProviderId: '' };
        }
    };

    const resolveAiDailyQuotaLimit = async (user) => {
        if (user && Number.isInteger(user.aiDailyQuotaOverride)) return user.aiDailyQuotaOverride;
        if (!Settings || typeof Settings.findByPk !== 'function') return 100;
        try {
            const row = await Settings.findByPk('aiDailyQuota');
            const parsed = Number.parseInt(row && row.value, 10);
            if (Number.isInteger(parsed) && parsed > 0 && parsed < 10000) return parsed;
        } catch {}
        return 100;
    };

    const buildExperimentalFeaturesViewModel = async (user) => {
        const aiAdminConfig = await getAiAdminConfig();
        const providerReady = Array.isArray(aiAdminConfig.providers)
            ? aiAdminConfig.providers.some((p) => p && p.enabled && p.apiKey)
            : false;
        const limit = await resolveAiDailyQuotaLimit(user);
        const today = new Date().toISOString().slice(0, 10);
        let used = 0;
        try {
            if (typeof getRedisClient === 'function') {
                const redisClient = getRedisClient();
                if (redisClient && redisClient.isReady) {
                    const raw = await redisClient.get(`ai:quota:${user.id}:${today}`);
                    const parsed = Number.parseInt(raw, 10);
                    if (Number.isInteger(parsed)) used = parsed;
                }
            }
        } catch {}
        return {
            aiAdminEnabled: Boolean(aiAdminConfig.enabled),
            aiProviderReady: providerReady,
            quotaUsed: used,
            quotaLimit: limit
        };
    };

    const applyPresetThemeForUser = async (user, rawTheme) => {
        const nextTheme = normalizeThemeId(rawTheme);
        if (rawTheme && !allowedThemeIds.has(String(rawTheme).trim().toLowerCase())) {
            throw new Error('INVALID_THEME');
        }
        let nextPermissions = withThemeInPermissions(user.permissions, nextTheme);
        // Preset apply turns off custom override so the selected preset is visible immediately.
        nextPermissions = withUserCustomThemeEnabled(nextPermissions, false);
        user.permissions = nextPermissions;
        await user.save();
        return {
            nextTheme,
            customTheme: getUserCustomTheme({ permissions: nextPermissions })
        };
    };

    const getThemeViewData = async (userId) => {
        const user = await User.findByPk(userId);
        if (!user) return null;
        const userData = user.toJSON();
        return {
            user,
            userData,
            activeTheme: getUserThemeId(userData),
            customTheme: getUserCustomTheme(userData),
            themeCatalog: getThemeCatalog()
        };
    };

    const buildNotificationPageState = async (userId) => {
        const [settings, unreadCount, recentNotifications, browserSubscriptions] = await Promise.all([
            getNotificationSettings(Settings),
            countUnreadNotifications(UserNotification, userId),
            listNotifications(UserNotification, userId, 8),
            UserBrowserSubscription.findAll({
                where: { userId, revokedAt: null },
                order: [['updatedAt', 'DESC']],
                limit: 5
            })
        ]);
        return {
            notificationSettings: settings,
            notificationUnreadCount: unreadCount,
            recentNotifications,
            browserSubscriptionCount: browserSubscriptions.length
        };
    };

    // Account Page (GET)
    app.get('/account', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id, {
                include: [{ model: LinkedAccount, as: 'linkedAccounts' }]
            });
            if (!user) return res.redirect('/login');

            const userData = user.toJSON();
            const normalizedLinkedAccounts = Array.isArray(userData.linkedAccounts)
                ? userData.linkedAccounts
                    .map((entry) => {
                        const provider = String((entry && entry.provider) || '').trim().toLowerCase();
                        if (!provider) return null;
                        return {
                            ...entry,
                            provider
                        };
                    })
                    .filter(Boolean)
                : [];

            // Legacy fallback: older records may only have oauthProvider/oauthId on User table.
            const legacyProvider = String(userData.oauthProvider || '').trim().toLowerCase();
            const legacyProviderId = String(userData.oauthId || '').trim();
            if (
                legacyProvider &&
                legacyProviderId &&
                !normalizedLinkedAccounts.some((entry) => entry.provider === legacyProvider)
            ) {
                normalizedLinkedAccounts.push({
                    id: `legacy-${legacyProvider}`,
                    userId: userData.id,
                    provider: legacyProvider,
                    providerId: legacyProviderId,
                    providerEmail: null,
                    providerUsername: userData.username || null,
                    isLegacy: true
                });
            }

            console.log(`[Account Debug] Rendering for user: ${userData.username} (ID: ${userData.id})`);
            console.log(
                `[Account Debug] Linked Accounts summary: count=${normalizedLinkedAccounts.length}`
            );

            const providerDefinitions = [
                { id: 'discord', name: 'Discord', icon: 'bi-discord', color: '#5865F2' },
                { id: 'google', name: 'Google', icon: 'bi-google', color: '#DB4437' },
                { id: 'reddit', name: 'Reddit', icon: 'bi-reddit', color: '#FF4500' },
                { id: 'github', name: 'GitHub', icon: 'bi-github', color: '#d0d8e5' }
            ];
            const settingsMap = (res.locals && res.locals.settings && typeof res.locals.settings === 'object')
                ? res.locals.settings
                : {};
            const linkedProviders = providerDefinitions
                .map((provider) => {
                    const link = normalizedLinkedAccounts.find((entry) => entry.provider === provider.id) || null;
                    const configKey = `auth${provider.id.charAt(0).toUpperCase() + provider.id.slice(1)}Enabled`;
                    const isConfigured = String(settingsMap[configKey] || '').toLowerCase() === 'true';
                    if (!isConfigured && !link) return null;
                    return {
                        ...provider,
                        isConfigured,
                        isLinked: Boolean(link),
                        linkAction: `/auth/${provider.id}`,
                        unlinkAction: `/account/unlink/${provider.id}`
                    };
                })
                .filter(Boolean);

            const activeTheme = getUserThemeId(userData);
            const activeCustomTheme = getUserCustomTheme(userData);
            const notificationState = await buildNotificationPageState(userData.id);
            if (req.session && req.session.user) {
                req.session.user.uiTheme = activeTheme;
                req.session.user.uiCustomTheme = activeCustomTheme;
            }

            const reactPageData = {
                routePath: '/account',
                brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
                faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
                appUrl: APP_URL,
                success: req.query.success || null,
                error: req.query.error || null,
                activeTheme,
                user: {
                    id: userData.id,
                    username: userData.username,
                    firstName: userData.firstName || '',
                    lastName: userData.lastName || '',
                    email: userData.email || '',
                    avatarUrl: userData.avatarUrl || '',
                    avatarProvider: userData.avatarProvider || 'gravatar',
                    gravatarHash: userData.gravatarHash || md5(String(userData.email || '').trim().toLowerCase()),
                    twoFactorEnabled: Boolean(userData.twoFactorEnabled),
                    notificationUnreadCount: notificationState.notificationUnreadCount
                },
                linkedProviders,
                notificationSettings: notificationState.notificationSettings,
                browserSubscriptionCount: notificationState.browserSubscriptionCount,
                recentNotifications: notificationState.recentNotifications
            };

            if (wantsReactPageData(req)) {
                return res.json(reactPageData);
            }

            if (normalizeExperimentalViewMode(user.experimentalViewMode) === 'react') {
                return res.render('react/loader', {
                    title: 'Account Settings',
                    reactEntry: 'app',
                    reactPageData
                });
            }

            res.render('account', {
                user: userData,
                linkedAccounts: normalizedLinkedAccounts,
                activeTheme,
                title: 'Account Settings',
                appUrl: APP_URL,
                path: '/account',
                success: req.query.success || null,
                error: req.query.error || null,
                notificationSettings: notificationState.notificationSettings,
                browserSubscriptionCount: notificationState.browserSubscriptionCount,
                recentNotifications: notificationState.recentNotifications
            });
        } catch (err) {
            console.error('Error fetching account:', err);
            res.redirect('/?error=Failed to load account settings.');
        }
    });

    app.get('/themes', requireAuth, async (req, res) => {
        try {
            const data = await getThemeViewData(req.session.user.id);
            if (!data) return res.redirect('/login');
            updateSessionThemeState(req, data.activeTheme, data.customTheme);

            const reactPageData = {
                routePath: '/themes',
                brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
                faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
                user: {
                    username: data.userData.username,
                    avatarUrl: data.userData.avatarUrl || '',
                    avatarProvider: data.userData.avatarProvider || 'gravatar',
                    gravatarHash: data.userData.gravatarHash || md5(String(data.userData.email || '').trim().toLowerCase()),
                },
                activeTheme: data.activeTheme,
                customTheme: data.customTheme,
                themeCatalog: data.themeCatalog,
                initialThemeHref: (res.locals.settings && res.locals.settings.initialThemeHref) || '/themes/default/index.css',
                success: req.query.success || null,
                error: req.query.error || null
            };

            if (wantsReactPageData(req)) {
                return res.json(reactPageData);
            }

            if (normalizeExperimentalViewMode(data.userData.experimentalViewMode) === 'react') {
                return res.render('react/loader', {
                    title: 'Themes',
                    reactEntry: 'themes',
                    reactPageData
                });
            }

            return res.render('themes', {
                user: data.userData,
                title: 'Themes',
                appUrl: APP_URL,
                themeCatalog: data.themeCatalog,
                activeTheme: data.activeTheme,
                customTheme: data.customTheme,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (err) {
            console.error('Failed to load themes page:', err);
            return res.redirect('/account?error=' + encodeURIComponent('Failed to load themes.'));
        }
    });

    app.get('/experimental-features', requireAuth, (req, res) => {
        return res.redirect('/instable/outdated');
    });

    app.get('/instable/outdated', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');
            updateSessionExperimentalState(req, user);
            const featureModel = await buildExperimentalFeaturesViewModel(user);
            const reactPageData = {
                routePath: '/instable/outdated',
                brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
                faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
                user: {
                    username: user.username,
                    email: user.email || '',
                    avatarUrl: user.avatarUrl || '',
                    avatarProvider: user.avatarProvider || 'gravatar',
                    gravatarHash: md5(String(user.email || '').trim().toLowerCase()),
                    experimentalAiEnabled: Boolean(user.experimentalAiEnabled)
                },
                currentViewMode: normalizeExperimentalViewMode(user.experimentalViewMode),
                success: req.query.success || null,
                error: req.query.error || null,
                ...featureModel
            };

            if (wantsReactPageData(req)) {
                return res.json(reactPageData);
            }

            if (normalizeExperimentalViewMode(user.experimentalViewMode) === 'react') {
                return res.render('react/loader', {
                    title: 'Experimental Features',
                    reactEntry: 'app',
                    reactPageData
                });
            }
            return res.render('experimental/features', {
                user: user.toJSON(),
                title: 'Outdated Features',
                path: '/instable/outdated',
                currentViewMode: normalizeExperimentalViewMode(user.experimentalViewMode),
                ...featureModel,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (err) {
            console.error('Failed to load experimental features page:', err);
            return res.redirect('/account?error=' + encodeURIComponent('Failed to load experimental features.'));
        }
    });

    app.get('/experimental/ai', requireAuth, async (req, res) => {
        return res.redirect('/instable/outdated');
    });

    app.post('/instable/outdated/ai', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');
            const aiAdminConfig = await getAiAdminConfig();
            const providerReady = Array.isArray(aiAdminConfig.providers)
                ? aiAdminConfig.providers.some((p) => p && p.enabled && p.apiKey)
                : false;
            if (!aiAdminConfig.enabled || !providerReady) {
                return res.redirect('/instable/outdated?error=' + encodeURIComponent('AI agents are not enabled by admin.'));
            }
            const enabled = parseToggle(req.body && req.body.enabled);
            await user.update({ experimentalAiEnabled: enabled });
            updateSessionExperimentalState(req, { experimentalAiEnabled: enabled });
            return res.redirect('/instable/outdated?success=' + encodeURIComponent('Experimental AI setting updated.'));
        } catch (err) {
            console.error('Failed to update experimental AI setting:', err);
            return res.redirect('/instable/outdated?error=' + encodeURIComponent('Failed to update setting.'));
        }
    });

    app.post('/experimental/ai', requireAuth, async (req, res) => {
        return res.redirect(307, '/instable/outdated/ai');
    });

    app.get('/experimental/change-view', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id, { attributes: ['id', 'username', 'experimentalViewMode'] });
            if (!user) return res.redirect('/login');
            updateSessionExperimentalState(req, user);
            const reactPageData = {
                routePath: '/experimental/change-view',
                brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
                faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
                user: {
                    username: user.username
                },
                currentViewMode: normalizeExperimentalViewMode(user.experimentalViewMode),
                success: req.query.success || null,
                error: req.query.error || null,
                applied: String(req.query.applied || '') === '1'
            };

            if (wantsReactPageData(req)) {
                return res.json(reactPageData);
            }

            if (normalizeExperimentalViewMode(user.experimentalViewMode) === 'react') {
                return res.render('react/loader', {
                    title: 'Change View',
                    reactEntry: 'app',
                    reactPageData
                });
            }
            return res.render('experimental/change-view', {
                user: user.toJSON(),
                title: 'Change View',
                path: '/experimental/change-view',
                currentViewMode: normalizeExperimentalViewMode(user.experimentalViewMode),
                success: req.query.success || null,
                error: req.query.error || null,
                applied: String(req.query.applied || '') === '1'
            });
        } catch (err) {
            console.error('Failed to load change-view page:', err);
            return res.redirect('/experimental-features?error=' + encodeURIComponent('Failed to load change view settings.'));
        }
    });

    app.post('/experimental/change-view', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id, { attributes: ['id', 'experimentalViewMode'] });
            if (!user) return res.redirect('/login');
            const nextMode = normalizeExperimentalViewMode(req.body && req.body.viewMode);
            await user.update({ experimentalViewMode: nextMode });
            updateSessionExperimentalState(req, { experimentalViewMode: nextMode });
            return res.redirect(`/experimental/change-view?applied=1&success=${encodeURIComponent(`View preference saved. ${nextMode === 'react' ? 'React beta view is now enabled for migrated pages.' : 'Legacy EJS view is active again.'}`)}`);
        } catch (err) {
            console.error('Failed to update experimental view mode:', err);
            return res.redirect('/experimental/change-view?error=' + encodeURIComponent('Failed to update view mode.'));
        }
    });

    app.post('/themes/apply', requireAuth, async (req, res) => {
        const rawTheme = String((req.body && req.body.theme) || '').trim().toLowerCase();
        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');
            const nextState = await applyPresetThemeForUser(user, rawTheme);
            updateSessionThemeState(req, nextState.nextTheme, nextState.customTheme);
            return res.redirect('/themes?success=' + encodeURIComponent('Theme updated successfully.'));
        } catch (err) {
            if (err && err.message === 'INVALID_THEME') {
                return res.redirect('/themes?error=' + encodeURIComponent('Invalid theme selected.'));
            }
            console.error('Failed to apply preset theme:', err);
            return res.redirect('/themes?error=' + encodeURIComponent('Failed to update theme.'));
        }
    });

    app.post('/themes/custom-mode', requireAuth, async (req, res) => {
        try {
            const enabled = parseToggle(req.body && req.body.enabled);
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');
            const nextPermissions = withUserCustomThemeEnabled(user.permissions, enabled);
            user.permissions = nextPermissions;
            await user.save();
            const customTheme = getUserCustomTheme({ permissions: nextPermissions });
            updateSessionThemeState(req, null, customTheme);
            return res.redirect('/themes?success=' + encodeURIComponent(enabled ? 'Custom theme enabled.' : 'Custom theme disabled.'));
        } catch (err) {
            console.error('Failed to toggle custom theme mode:', err);
            return res.redirect('/themes?error=' + encodeURIComponent('Failed to update custom theme mode.'));
        }
    });

    app.get('/themes/builder', requireAuth, async (req, res) => {
        try {
            const data = await getThemeViewData(req.session.user.id);
            if (!data) return res.redirect('/login');
            updateSessionThemeState(req, data.activeTheme, data.customTheme);
            return res.render('themes-builder', {
                user: data.userData,
                title: 'Theme Builder',
                appUrl: APP_URL,
                activeTheme: data.activeTheme,
                customTheme: data.customTheme,
                defaultCustomTheme,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (err) {
            console.error('Failed to load theme builder:', err);
            return res.redirect('/themes?error=' + encodeURIComponent('Failed to load theme builder.'));
        }
    });

    app.post('/themes/builder', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');
            const draftTheme = normalizeUserCustomThemeConfig({
                enabled: parseToggle(req.body && req.body.enabled),
                backgroundImageUrl: String((req.body && req.body.backgroundImageUrl) || '').trim(),
                backgroundColor: String((req.body && req.body.backgroundColor) || '').trim(),
                panelSurface: String((req.body && req.body.panelSurface) || '').trim(),
                cardBackground: String((req.body && req.body.cardBackground) || '').trim(),
                cardBorder: String((req.body && req.body.cardBorder) || '').trim(),
                accentColor: String((req.body && req.body.accentColor) || '').trim(),
                textColor: String((req.body && req.body.textColor) || '').trim(),
                mutedTextColor: String((req.body && req.body.mutedTextColor) || '').trim(),
                serverCardBackground: String((req.body && req.body.serverCardBackground) || '').trim(),
                serverCardBorder: String((req.body && req.body.serverCardBorder) || '').trim(),
                serverCardRadius: String((req.body && req.body.serverCardRadius) || '').trim()
            });

            const nextPermissions = withUserCustomThemeInPermissions(user.permissions, draftTheme);
            user.permissions = nextPermissions;
            await user.save();
            const savedCustomTheme = getUserCustomTheme({ permissions: nextPermissions });
            updateSessionThemeState(req, null, savedCustomTheme);
            return res.redirect('/themes/builder?success=' + encodeURIComponent('Custom theme saved successfully.'));
        } catch (err) {
            console.error('Failed to save custom theme:', err);
            return res.redirect('/themes/builder?error=' + encodeURIComponent('Failed to save custom theme.'));
        }
    });

    // Unlink account
    app.post('/account/unlink/:provider', requireAuth, async (req, res) => {
        try {
            const provider = String(req.params.provider || '').trim().toLowerCase();
            const userId = req.session.user.id;
            if (!provider) {
                return res.redirect('/account?error=Invalid provider.');
            }

            const user = await User.findByPk(userId);
            const links = await LinkedAccount.findAll({ where: { userId } });
            const matchingIds = links
                .filter((entry) => String(entry.provider || '').trim().toLowerCase() === provider)
                .map((entry) => entry.id);

            if (matchingIds.length > 0) {
                await LinkedAccount.destroy({ where: { id: { [Op.in]: matchingIds } } });
            }
            console.log(`[Unlink] Removed provider ${provider} for user ${userId} (rows: ${matchingIds.length})`);

            if (String(user.oauthProvider || '').trim().toLowerCase() === provider) {
                await user.update({ oauthProvider: null, oauthId: null });
            }
            if (provider === 'google' && Settings && typeof Settings.destroy === 'function') {
                const tokenKey = getGoogleTokenSettingKey(userId);
                if (tokenKey) {
                    await Settings.destroy({ where: { key: tokenKey } }).catch(() => {});
                }
            }

            res.redirect('/account?success=Account unlinked successfully.');
        } catch (err) {
            console.error('Error unlinking account:', err);
            res.redirect('/account?error=Failed to unlink account.');
        }
    });

    // Update Account Details (POST)
    app.post('/account/update', requireAuth, async (req, res) => {
        const { firstName, lastName, email, avatarUrl, avatarProvider } = req.body;

        // Validate Avatar URL if provided
        if (avatarUrl && avatarUrl.trim() !== '') {
            const validExtensions = /\.(png|webp|jpg|jpeg|gif)$/i;
            if (!validExtensions.test(avatarUrl)) {
                return res.redirect('/account?error=' + encodeURIComponent('Invalid avatar URL. Must end with .png, .webp, .jpg, .jpeg, or .gif'));
            }
        }

        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');

            // Update fields
            user.firstName = firstName;
            user.lastName = lastName;
            user.email = email;
            user.avatarUrl = avatarUrl;
            user.avatarProvider = avatarProvider || 'gravatar';
            await user.save();

            // Update session
            req.session.user.firstName = firstName;
            req.session.user.lastName = lastName;
            req.session.user.email = email;
            req.session.user.avatarUrl = avatarUrl;
            req.session.user.avatarProvider = user.avatarProvider;
            req.session.user.gravatarHash = md5(email.trim().toLowerCase());
            req.session.user.avatarUrl = avatarUrl;

            return res.redirect('/account?success=' + encodeURIComponent('Account details updated successfully!'));
        } catch (err) {
            console.error("Failed to update account:", err);
            return res.redirect('/account?error=' + encodeURIComponent('Failed to update account details.'));
        }
    });

    // Update Theme Preference (POST)
    app.post('/account/theme', requireAuth, async (req, res) => {
        const rawTheme = String((req.body && req.body.theme) || '').trim().toLowerCase();

        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');

            const nextState = await applyPresetThemeForUser(user, rawTheme);
            updateSessionThemeState(req, nextState.nextTheme, nextState.customTheme);
            return res.redirect('/themes?success=' + encodeURIComponent('Theme updated successfully.'));
        } catch (err) {
            if (err && err.message === 'INVALID_THEME') {
                return res.redirect('/themes?error=' + encodeURIComponent('Invalid theme selected.'));
            }
            console.error('Failed to update theme:', err);
            return res.redirect('/themes?error=' + encodeURIComponent('Failed to update theme.'));
        }
    });

    // 2FA Routes
    app.get('/account/2fa/setup', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id);
            const secret = speakeasy.generateSecret({
                name: `CPanel (${user.username})`,
                issuer: 'CPanel',
                digits: 6
            });

            // Store secret temporarily in session
            req.session.temp2faSecret = secret.base32;

            const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

            res.json({
                qrCodeUrl,
                secret: secret.base32
            });
        } catch (error) {
            console.error("2FA Setup Error:", error);
            res.status(500).json({ error: 'Failed to setup 2FA' });
        }
    });

    app.post('/account/2fa/enable', requireAuth, async (req, res) => {
        const { code } = req.body;
        const secret = req.session.temp2faSecret;

        if (!secret) return res.status(400).json({ error: 'Setup session expired. Please refresh.' });

        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: code,
            digits: 6,
            window: 1
        });

        if (verified) {
            const user = await User.findByPk(req.session.user.id);
            user.twoFactorSecret = secret;
            user.twoFactorEnabled = true;
            await user.save();

            req.session.user.twoFactorEnabled = true;
            delete req.session.temp2faSecret;

            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Invalid 6-digit code' });
        }
    });

    app.post('/account/2fa/disable', requireAuth, async (req, res) => {
        const { password } = req.body;
        const user = await User.findByPk(req.session.user.id);

        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        user.twoFactorSecret = null;
        user.twoFactorEnabled = false;
        await user.save();

        req.session.user.twoFactorEnabled = false;
        res.json({ success: true });
    });

    // Admin force disable
    app.post('/admin/users/disable-2fa/:id', requireAuth, requireAdmin, async (req, res) => {
        const { id } = req.params;
        try {
            await User.update({
                twoFactorSecret: null,
                twoFactorEnabled: false
            }, { where: { id } });
            res.redirect('/admin/users?success=2FA disabled for user.');
        } catch (error) {
            console.error("Admin 2FA Disable Error:", error);
            res.redirect('/admin/users?error=Failed to disable 2FA.');
        }
    });

    // Update Password (POST)
    app.post('/account/password', requireAuth, async (req, res) => {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (newPassword !== confirmPassword) {
            return res.redirect('/account?error=' + encodeURIComponent('New passwords do not match.'));
        }

        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');

            // Verify current password
            if (!(await bcrypt.compare(currentPassword, user.password))) {
                return res.redirect('/account?error=' + encodeURIComponent('Current password is incorrect.'));
            }

            // Hash and save new password
            user.password = await bcrypt.hash(newPassword, 10);
            await user.save();

            // Destroy session and redirect to login
            req.session.destroy((err) => {
                if (err) console.error("Session destroy error:", err);
                res.redirect('/login?success=' + encodeURIComponent('Password changed successfully. Please log in again.'));
            });
        } catch (err) {
            console.error("Failed to update password:", err);
            return res.redirect('/account?error=' + encodeURIComponent('Failed to update password.'));
        }
    });

    app.get('/notifications', requireAuth, async (req, res) => {
        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user) return res.redirect('/login');
            const [notifications, unreadCount, notificationSettings, subscriptions] = await Promise.all([
                listNotifications(UserNotification, user.id, 100),
                countUnreadNotifications(UserNotification, user.id),
                getNotificationSettings(Settings),
                UserBrowserSubscription.findAll({
                    where: { userId: user.id, revokedAt: null },
                    order: [['updatedAt', 'DESC']],
                    limit: 10
                })
            ]);
            const reactPageData = {
                routePath: '/notifications',
                brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
                faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
                user: {
                    username: user.username,
                    email: user.email || '',
                    avatarUrl: user.avatarUrl || '',
                    avatarProvider: user.avatarProvider || 'gravatar',
                    gravatarHash: md5(String(user.email || '').trim().toLowerCase()),
                    notificationUnreadCount: unreadCount,
                    isAdmin: Boolean(user.isAdmin)
                },
                notifications,
                unreadCount,
                notificationSettings,
                browserSubscriptionCount: subscriptions.length,
                success: req.query.success || null,
                error: req.query.error || null
            };

            if (normalizeExperimentalViewMode(user.experimentalViewMode) === 'react') {
                return res.render('react/loader', {
                    title: 'Notifications',
                    reactEntry: 'notifications', // specific entry for clarity
                    reactPageData
                });
            }

            return res.render('notifications', {
                title: 'Notifications',
                path: '/notifications',
                user: user.toJSON(),
                notifications,
                unreadCount,
                notificationSettings,
                browserSubscriptionCount: subscriptions.length,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (error) {
            console.error('Failed to load notifications page:', error);
            return res.redirect('/account?error=' + encodeURIComponent('Failed to load notifications.'));
        }
    });

    app.get('/api/account/notifications', requireAuth, async (req, res) => {
        try {
            const userId = Number.parseInt(req.session.user.id, 10);
            const [notifications, unreadCount, subscriptions] = await Promise.all([
                listNotifications(UserNotification, userId, req.query.limit || 20),
                countUnreadNotifications(UserNotification, userId),
                UserBrowserSubscription.count({
                    where: { userId, revokedAt: null }
                })
            ]);
            return res.json({
                notifications,
                unreadCount,
                browserSubscriptionCount: subscriptions
            });
        } catch (error) {
            console.error('Failed to list account notifications:', error);
            return res.status(500).json({ error: 'Failed to load notifications.' });
        }
    });

    app.post('/api/account/notifications/:id/read', requireAuth, async (req, res) => {
        try {
            const userId = Number.parseInt(req.session.user.id, 10);
            const notificationId = Number.parseInt(req.params.id, 10);
            if (!Number.isInteger(notificationId) || notificationId <= 0) {
                return res.status(400).json({ error: 'Invalid notification.' });
            }
            const notification = await markNotificationRead(UserNotification, notificationId, userId);
            if (!notification) {
                return res.status(404).json({ error: 'Notification not found.' });
            }
            const unreadCount = await countUnreadNotifications(UserNotification, userId);
            sendToUserUI(userId, {
                type: 'notification:read',
                notificationId
            });
            sendToUserUI(userId, {
                type: 'notification:unread_count',
                unreadCount
            });
            return res.json({
                success: true,
                notificationId,
                unreadCount
            });
        } catch (error) {
            console.error('Failed to mark notification as read:', error);
            return res.status(500).json({ error: 'Failed to update notification.' });
        }
    });

    app.post('/api/account/notifications/read-all', requireAuth, async (req, res) => {
        try {
            const userId = Number.parseInt(req.session.user.id, 10);
            await markAllNotificationsRead(UserNotification, userId);
            sendToUserUI(userId, {
                type: 'notification:read',
                notificationId: null,
                all: true
            });
            sendToUserUI(userId, {
                type: 'notification:unread_count',
                unreadCount: 0
            });
            return res.json({ success: true, unreadCount: 0 });
        } catch (error) {
            console.error('Failed to mark all notifications as read:', error);
            return res.status(500).json({ error: 'Failed to update notifications.' });
        }
    });

    app.post('/api/account/browser-notifications/subscribe', requireAuth, async (req, res) => {
        try {
            const userId = Number.parseInt(req.session.user.id, 10);
            const permission = String(req.body && req.body.permission || '').trim().toLowerCase();
            if (permission !== 'granted') {
                return res.status(400).json({ error: 'Browser notification permission must be granted before subscribing.' });
            }
            const endpoint = String(req.body && req.body.endpoint || '').trim() || `web:${userId}:${Date.now()}`;
            const subscriptionKeys = req.body && req.body.keys && typeof req.body.keys === 'object'
                ? req.body.keys
                : {};
            await UserBrowserSubscription.upsert({
                userId,
                endpoint: endpoint.slice(0, 512),
                keys: subscriptionKeys,
                userAgent: String(req.headers['user-agent'] || '').slice(0, 512),
                lastSeenAt: new Date(),
                revokedAt: null
            });
            const count = await UserBrowserSubscription.count({
                where: { userId, revokedAt: null }
            });
            return res.json({ success: true, browserSubscriptionCount: count });
        } catch (error) {
            console.error('Failed to save browser notification subscription:', error);
            return res.status(500).json({ error: 'Failed to save browser notification preference.' });
        }
    });

    app.post('/api/account/browser-notifications/unsubscribe', requireAuth, async (req, res) => {
        try {
            const userId = Number.parseInt(req.session.user.id, 10);
            const endpoint = String(req.body && req.body.endpoint || '').trim();
            const where = {
                userId,
                revokedAt: null
            };
            if (endpoint) {
                where.endpoint = endpoint;
            }
            await UserBrowserSubscription.update({
                revokedAt: new Date()
            }, { where });
            const count = await UserBrowserSubscription.count({
                where: { userId, revokedAt: null }
            });
            return res.json({ success: true, browserSubscriptionCount: count });
        } catch (error) {
            console.error('Failed to revoke browser notification subscription:', error);
            return res.status(500).json({ error: 'Failed to remove browser notification preference.' });
        }
    });

    app.get('/account/device-login', requireAuth, async (req, res) => {
        try {
            const userId = Number.parseInt(req.session.user.id, 10);
            const user = await User.findByPk(userId);
            if (!user) return res.redirect('/login');

            const rows = await UserLoginEvent.findAll({
                where: { userId },
                order: [['createdAt', 'DESC']],
                limit: 120
            });

            const events = rows.map((entry) => {
                const data = entry.toJSON();
                return {
                    id: data.id,
                    username: String(data.usernameSnapshot || user.username || '').trim(),
                    operatingSystem: String(data.operatingSystem || 'Unknown OS').trim(),
                    loginType: formatLoginTypeLabel(data.loginType),
                    ipAddress: String(data.ipAddress || 'unknown').trim(),
                    location: String(data.location || 'Unknown').trim(),
                    createdAt: data.createdAt
                };
            });

            const reactPageData = {
                routePath: '/account/device-login',
                brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
                faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
                user: {
                    username: user.username,
                    email: user.email || '',
                    avatarUrl: user.avatarUrl || '',
                    avatarProvider: user.avatarProvider || 'gravatar',
                    gravatarHash: md5(String(user.email || '').trim().toLowerCase())
                },
                events
            };

            if (wantsReactPageData(req)) {
                return res.json(reactPageData);
            }

            if (normalizeExperimentalViewMode(user.experimentalViewMode) === 'react') {
                return res.render('react/loader', {
                    title: 'Device Login History',
                    reactEntry: 'app',
                    reactPageData
                });
            }

            return res.render('account-device-login', {
                title: 'Device Login History',
                user,
                events
            });
        } catch (err) {
            console.error('Error loading device login history:', err);
            return res.redirect('/account?error=' + encodeURIComponent('Failed to load device login history.'));
        }
    });
}

module.exports = {
    registerAccountRoutes
};
