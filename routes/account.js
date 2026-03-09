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
    bcrypt
}) {
    const allowedThemeIds = new Set(getThemeCatalog().map((entry) => entry.id));
    const defaultCustomTheme = normalizeUserCustomThemeConfig(DEFAULT_USER_CUSTOM_THEME);

    const parseToggle = (value) => {
        if (value === true || value === 'true' || value === 1 || value === '1' || value === 'on' || value === 'yes') return true;
        return false;
    };

    const updateSessionThemeState = (req, themeId, customTheme) => {
        if (!req || !req.session || !req.session.user) return;
        if (themeId) req.session.user.uiTheme = normalizeThemeId(themeId);
        if (customTheme) req.session.user.uiCustomTheme = normalizeUserCustomThemeConfig(customTheme);
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
            console.log(`[Account Debug] Linked Accounts:`, JSON.stringify(normalizedLinkedAccounts, null, 2));

            const activeTheme = getUserThemeId(userData);
            const activeCustomTheme = getUserCustomTheme(userData);
            if (req.session && req.session.user) {
                req.session.user.uiTheme = activeTheme;
                req.session.user.uiCustomTheme = activeCustomTheme;
            }

            res.render('account', {
                user: userData,
                linkedAccounts: normalizedLinkedAccounts,
                activeTheme,
                title: 'Account Settings',
                appUrl: APP_URL,
                success: req.query.success || null,
                error: req.query.error || null
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
