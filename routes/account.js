function registerAccountRoutes({
    app,
    requireAuth,
    requireAdmin,
    User,
    LinkedAccount,
    Op,
    md5,
    APP_URL,
    speakeasy,
    QRCode,
    bcrypt
}) {
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

            res.render('account', {
                user: userData,
                linkedAccounts: normalizedLinkedAccounts,
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
}

module.exports = {
    registerAccountRoutes
};
