function normalizeAdminApiPermissionInput(input, fallbackNormalize, wildcard) {
    const values = Array.isArray(input)
        ? input
        : [input].filter((entry) => entry !== undefined && entry !== null);
    const trimmed = values.map((entry) => String(entry || '').trim()).filter(Boolean);
    if (trimmed.includes(wildcard)) {
        return [wildcard];
    }
    return fallbackNormalize(trimmed);
}

function maskAdminApiKeyPrefix(prefix) {
    const raw = String(prefix || '').trim();
    if (!raw) return '********';
    if (raw.length <= 4) return `${raw}****`;
    return `${raw.slice(0, 4)}******`;
}

function formatAdminApiInactiveReason(reason) {
    const normalized = String(reason || '').trim().toLowerCase();
    if (normalized === 'revoked') return 'revoked';
    if (normalized === 'expired') return 'expired';
    if (normalized === 'rotation_required') return 'rotation required';
    if (normalized === 'missing') return 'missing';
    if (normalized) return normalized.replace(/_/g, ' ');
    return '';
}

const {
    getAdminApiRatePlanSettingKey,
    normalizeAdminApiRatePlan
} = require('../../core/helpers/admin-api-rate-plans');
const {
    buildAdminApiSwaggerSpec,
    buildAdminApiOpenApiSpec
} = require('../../core/helpers/admin-api-swagger');

function registerAdminApiKeyRoutes(deps) {
    const {
        app,
        requireAuth,
        requireAdmin,
        SECRET_KEY,
        AdminApiKey,
        AdminApiKeyAudit,
        Settings,
        User,
        ADMIN_API_KEY_PERMISSION_CATALOG,
        ADMIN_API_KEY_WILDCARD,
        normalizeAdminApiKeyPermissions,
        normalizeAdminApiIpAllowlist,
        normalizeAdminApiRotationDays,
        normalizeAdminApiKeyExpiresAt,
        generateAdminApiKeyToken,
        hashAdminApiKeyToken,
        getAdminApiKeyInactiveReason,
        isAdminApiKeyActive
    } = deps;

    app.get('/admin/api', requireAuth, requireAdmin, async (req, res) => {
        try {
            const keys = await AdminApiKey.findAll({
                include: [{ model: User, as: 'creator', attributes: ['id', 'username', 'email'], required: false }],
                order: [['createdAt', 'DESC']]
            });
            const ratePlansEnabled = (() => {
                const raw = String((res.locals.settings && res.locals.settings.featureAdminApiRatePlansEnabled) || 'false').trim().toLowerCase();
                return raw === 'true' || raw === '1' || raw === 'yes' || raw === 'on';
            })();
            const ratePlanMap = {};
            if (Settings && keys.length > 0) {
                const planKeys = keys.map((entry) => getAdminApiRatePlanSettingKey(entry.id));
                const rows = await Settings.findAll({
                    where: { key: planKeys },
                    attributes: ['key', 'value']
                });
                rows.forEach((row) => {
                    const rawKey = String(row.key || '');
                    const id = Number.parseInt(rawKey.replace(/^admin_api_rate_plan_/, ''), 10);
                    if (!Number.isInteger(id) || id <= 0) return;
                    ratePlanMap[id] = normalizeAdminApiRatePlan(row.value);
                });
            }

            let freshToken = null;
            const pending = req.session.newAdminApiKey;
            if (pending && pending.token) {
                freshToken = {
                    name: String(pending.name || 'New admin API key'),
                    token: String(pending.token || ''),
                    action: String(pending.action || 'created')
                };
                delete req.session.newAdminApiKey;
                await new Promise((resolve) => req.session.save(() => resolve()));
            }

            return res.render('admin/api-keys', {
                user: req.session.user,
                path: '/admin/api',
                title: 'Admin API Keys',
                permissionCatalog: ADMIN_API_KEY_PERMISSION_CATALOG,
                wildcardPermission: ADMIN_API_KEY_WILDCARD,
                freshToken,
                keys: keys.map((entry) => ({
                    id: entry.id,
                    name: entry.name,
                    keyPrefixMasked: maskAdminApiKeyPrefix(entry.keyPrefix),
                    permissions: normalizeAdminApiKeyPermissions(entry.permissions),
                    active: isAdminApiKeyActive(entry),
                    inactiveReason: formatAdminApiInactiveReason(
                        typeof getAdminApiKeyInactiveReason === 'function'
                            ? getAdminApiKeyInactiveReason(entry)
                            : null
                    ),
                    revokedAt: entry.revokedAt,
                    createdAt: entry.createdAt,
                    lastUsedAt: entry.lastUsedAt,
                    lastUsedIp: entry.lastUsedIp,
                    lastUsedGeo: entry.lastUsedGeo || null,
                    allowedIps: normalizeAdminApiIpAllowlist(entry.allowedIps),
                    expiresAt: entry.expiresAt || null,
                    rotationIntervalDays: normalizeAdminApiRotationDays(entry.rotationIntervalDays),
                    rotatedAt: entry.rotatedAt || null,
                    creator: entry.creator
                        ? {
                            id: entry.creator.id,
                            username: entry.creator.username,
                            email: entry.creator.email
                        }
                        : null,
                    ratePlan: ratePlanMap[entry.id] || normalizeAdminApiRatePlan({})
                })),
                ratePlansEnabled,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (error) {
            console.error('Error loading admin API keys page:', error);
            return res.redirect('/admin/overview?error=' + encodeURIComponent('Failed to load admin API keys.'));
        }
    });

    app.get('/admin/api/swagger', requireAuth, requireAdmin, async (req, res) => {
        try {
            const baseUrl = `${req.protocol}://${req.get('host')}`;
            const swagger = buildAdminApiSwaggerSpec(baseUrl);

            return res.render('admin/api-swagger', {
                user: req.session.user,
                path: '/admin/api',
                title: 'API Swagger',
                swagger,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (error) {
            console.error('Error loading admin API swagger page:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to load API Swagger page.'));
        }
    });

    app.get('/admin/api/swagger.json', requireAuth, requireAdmin, async (req, res) => {
        try {
            const baseUrl = `${req.protocol}://${req.get('host')}`;
            const format = String(req.query.format || '').trim().toLowerCase();
            const payload = format === 'openapi'
                ? buildAdminApiOpenApiSpec(baseUrl)
                : buildAdminApiSwaggerSpec(baseUrl);
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            return res.status(200).send(JSON.stringify(payload, null, 2));
        } catch (error) {
            console.error('Error loading admin API swagger JSON:', error);
            return res.status(500).json({ error: 'Failed to generate API Swagger JSON.' });
        }
    });

    app.get('/admin/api/openapi.json', requireAuth, requireAdmin, async (req, res) => {
        try {
            const baseUrl = `${req.protocol}://${req.get('host')}`;
            const payload = buildAdminApiOpenApiSpec(baseUrl);
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            return res.status(200).send(JSON.stringify(payload, null, 2));
        } catch (error) {
            console.error('Error loading OpenAPI JSON:', error);
            return res.status(500).json({ error: 'Failed to generate OpenAPI JSON.' });
        }
    });

    app.post('/admin/api', requireAuth, requireAdmin, async (req, res) => {
        try {
            const name = String(req.body.name || '').trim().slice(0, 120);
            if (!name) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('API key name is required.'));
            }
            if (name.includes('/')) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('API key name cannot contain "/" characters.'));
            }

            const permissions = normalizeAdminApiPermissionInput(
                req.body.permissions,
                normalizeAdminApiKeyPermissions,
                ADMIN_API_KEY_WILDCARD
            );
            if (!permissions.length) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Select at least one permission.'));
            }

            const rawAllowlist = req.body.allowedIps;
            const allowedIps = normalizeAdminApiIpAllowlist(rawAllowlist);
            if (String(rawAllowlist || '').trim() && !allowedIps.length) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('IP allowlist is invalid. Use IPs or CIDR values separated by comma/newline.'));
            }

            const rawExpiresAt = String(req.body.expiresAt || '').trim();
            const expiresAt = normalizeAdminApiKeyExpiresAt(rawExpiresAt);
            if (rawExpiresAt && !expiresAt) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Expiration date is invalid.'));
            }

            const rotationIntervalDays = normalizeAdminApiRotationDays(req.body.rotationIntervalDays);

            const generated = generateAdminApiKeyToken();
            if (!generated || !generated.token || !generated.keyPrefix) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to generate API key token.'));
            }

            const keyHash = hashAdminApiKeyToken(generated.token, SECRET_KEY);
            if (!keyHash) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to hash API key token.'));
            }

            await AdminApiKey.create({
                creatorUserId: req.session.user.id,
                name,
                keyPrefix: generated.keyPrefix,
                keyHash,
                permissions,
                allowedIps,
                expiresAt,
                rotationIntervalDays,
                rotatedAt: new Date(),
                revokedAt: null
            });

            req.session.newAdminApiKey = {
                name,
                action: 'created',
                token: generated.token
            };
            await new Promise((resolve) => req.session.save(() => resolve()));

            return res.redirect('/admin/api?success=' + encodeURIComponent('Admin API key created. Copy it now; it will not be shown again.'));
        } catch (error) {
            const message = String(error && error.message ? error.message : '').toLowerCase();
            if (message.includes('unique') || message.includes('duplicate')) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('An API key with this name already exists.'));
            }
            console.error('Error creating admin API key:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to create admin API key.'));
        }
    });

    app.post('/admin/api/:keyName/delete', requireAuth, requireAdmin, async (req, res) => {
        try {
            const keyName = String(req.params.keyName || '').trim();
            if (!keyName) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Invalid key name.'));
            }

            const key = await AdminApiKey.findOne({ where: { name: keyName } });
            if (!key) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Admin API key not found.'));
            }

            await key.destroy();
            return res.redirect('/admin/api?success=' + encodeURIComponent(`API key "${keyName}" deleted.`));
        } catch (error) {
            console.error('Error deleting admin API key:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to delete admin API key.'));
        }
    });

    app.post('/admin/api/:keyName/rotate', requireAuth, requireAdmin, async (req, res) => {
        try {
            const keyName = String(req.params.keyName || '').trim();
            if (!keyName) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Invalid key name.'));
            }

            const key = await AdminApiKey.findOne({ where: { name: keyName } });
            if (!key) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Admin API key not found.'));
            }

            const generated = generateAdminApiKeyToken();
            if (!generated || !generated.token || !generated.keyPrefix) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to generate rotated key token.'));
            }
            const keyHash = hashAdminApiKeyToken(generated.token, SECRET_KEY);
            if (!keyHash) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to hash rotated key token.'));
            }

            await key.update({
                keyPrefix: generated.keyPrefix,
                keyHash,
                rotatedAt: new Date(),
                revokedAt: null
            });

            req.session.newAdminApiKey = {
                name: key.name,
                action: 'rotated',
                token: generated.token
            };
            await new Promise((resolve) => req.session.save(() => resolve()));

            return res.redirect('/admin/api?success=' + encodeURIComponent(`API key "${key.name}" rotated successfully.`));
        } catch (error) {
            console.error('Error rotating admin API key:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to rotate admin API key.'));
        }
    });

    app.post('/admin/api/:keyName/rate-plan', requireAuth, requireAdmin, async (req, res) => {
        try {
            if (!Settings) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Settings model unavailable.'));
            }
            const keyName = String(req.params.keyName || '').trim();
            if (!keyName) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Invalid key name.'));
            }

            const key = await AdminApiKey.findOne({ where: { name: keyName } });
            if (!key) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Admin API key not found.'));
            }

            const plan = normalizeAdminApiRatePlan({
                enabled: req.body.enabled,
                perMinute: req.body.perMinute,
                perHour: req.body.perHour,
                perDay: req.body.perDay
            });
            await Settings.upsert({
                key: getAdminApiRatePlanSettingKey(key.id),
                value: JSON.stringify(plan)
            });

            return res.redirect('/admin/api?success=' + encodeURIComponent(`Rate plan updated for "${key.name}".`));
        } catch (error) {
            console.error('Error updating admin API rate plan:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to update admin API rate plan.'));
        }
    });

    app.post('/admin/api/:keyName/hardening', requireAuth, requireAdmin, async (req, res) => {
        try {
            const keyName = String(req.params.keyName || '').trim();
            if (!keyName) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Invalid key name.'));
            }

            const key = await AdminApiKey.findOne({ where: { name: keyName } });
            if (!key) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Admin API key not found.'));
            }

            const rawAllowlist = req.body.allowedIps;
            const allowedIps = normalizeAdminApiIpAllowlist(rawAllowlist);
            if (String(rawAllowlist || '').trim() && !allowedIps.length) {
                return res.redirect('/admin/api?error=' + encodeURIComponent(`Invalid allowlist for "${keyName}".`));
            }

            const rawExpiresAt = String(req.body.expiresAt || '').trim();
            const expiresAt = normalizeAdminApiKeyExpiresAt(rawExpiresAt);
            if (rawExpiresAt && !expiresAt) {
                return res.redirect('/admin/api?error=' + encodeURIComponent(`Invalid expiration date for "${keyName}".`));
            }

            const rotationIntervalDays = normalizeAdminApiRotationDays(req.body.rotationIntervalDays);
            await key.update({
                allowedIps,
                expiresAt,
                rotationIntervalDays
            });

            return res.redirect('/admin/api?success=' + encodeURIComponent(`Hardening updated for "${keyName}".`));
        } catch (error) {
            console.error('Error updating admin API key hardening:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to update API key hardening.'));
        }
    });

    app.get('/admin/api/:keyName/audit', requireAuth, requireAdmin, async (req, res) => {
        try {
            const keyName = String(req.params.keyName || '').trim();
            if (!keyName) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Invalid key name.'));
            }

            const key = await AdminApiKey.findOne({
                where: { name: keyName },
                include: [{ model: User, as: 'creator', attributes: ['id', 'username', 'email'], required: false }]
            });
            if (!key) {
                return res.redirect('/admin/api?error=' + encodeURIComponent('Admin API key not found.'));
            }

            const logs = await AdminApiKeyAudit.findAll({
                where: { adminApiKeyId: key.id },
                order: [['createdAt', 'DESC']],
                limit: 500
            });

            return res.render('admin/api-key-audit', {
                user: req.session.user,
                path: '/admin/api',
                title: `Admin API Audit ${key.name}`,
                key: {
                    id: key.id,
                    name: key.name,
                    keyPrefixMasked: maskAdminApiKeyPrefix(key.keyPrefix),
                    permissions: normalizeAdminApiKeyPermissions(key.permissions),
                    active: isAdminApiKeyActive(key),
                    inactiveReason: formatAdminApiInactiveReason(
                        typeof getAdminApiKeyInactiveReason === 'function'
                            ? getAdminApiKeyInactiveReason(key)
                            : null
                    ),
                    revokedAt: key.revokedAt,
                    createdAt: key.createdAt,
                    lastUsedAt: key.lastUsedAt,
                    lastUsedIp: key.lastUsedIp,
                    lastUsedGeo: key.lastUsedGeo || null,
                    allowedIps: normalizeAdminApiIpAllowlist(key.allowedIps),
                    expiresAt: key.expiresAt || null,
                    rotationIntervalDays: normalizeAdminApiRotationDays(key.rotationIntervalDays),
                    rotatedAt: key.rotatedAt || null,
                    creator: key.creator
                        ? {
                            id: key.creator.id,
                            username: key.creator.username,
                            email: key.creator.email
                        }
                        : null
                },
                logs,
                success: req.query.success || null,
                error: req.query.error || null
            });
        } catch (error) {
            console.error('Error loading admin API key audit page:', error);
            return res.redirect('/admin/api?error=' + encodeURIComponent('Failed to load API key audit.'));
        }
    });
}

module.exports = {
    registerAdminApiKeyRoutes
};
