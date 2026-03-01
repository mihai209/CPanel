function registerServerPagesRoutes(ctx) {
    const fs = require('fs');
    const nodeCrypto = require('crypto');
    const { pickSmartAllocation } = require('../../core/helpers/smart-allocation');
    const {
        STORE_DEALS_SETTING_KEY,
        normalizeStoreDealsCatalog,
        getStoreDealStatus,
        getStoreDealRemainingStock
    } = require('../../core/helpers/store-deals');
    const {
        STORE_REDEEM_CODES_SETTING_KEY,
        normalizeRedeemCodeValue,
        normalizeStoreRedeemCodesCatalog,
        getStoreRedeemCodeStatus,
        getStoreRedeemCodeRemainingUses,
        canUserRedeemStoreCode,
        applyStoreRedeemCodeUsage
    } = require('../../core/helpers/store-redeem-codes');
    const {
        REVENUE_PLAN_CATALOG_SETTING_KEY,
        normalizeRevenuePlanCatalog,
        normalizeUserRevenueProfile,
        getUserRevenueProfileSettingKey,
        estimateWalletRunwayDays,
        describeRunway
    } = require('../../core/helpers/revenue-mode');
    const {
        normalizeServerScheduledScalingConfig,
        normalizeScheduledScalingRule,
        getServerScheduledScalingSettingKey
    } = require('../../core/helpers/scheduled-scaling');
    for (const [key, value] of Object.entries(ctx || {})) {
        try {
            globalThis[key] = value;
        } catch {
            // Ignore non-writable globals (e.g. crypto on newer Node versions).
        }
    }
// ========== PAGE ROUTES ==========

// Login Page (GET)
app.get('/ratelimited', (req, res) => {
    res.render('ratelimited');
});

app.get('/status', async (req, res) => {
    try {
        const snapshot = await buildPublicStatusSnapshot();
        return res.render('public-status', {
            title: 'Status',
            path: '/status',
            user: req.session && req.session.user ? req.session.user : null,
            snapshot
        });
    } catch (error) {
        console.error('Error loading public status page:', error);
        return res.status(500).send('Failed to load status page.');
    }
});

app.get('/status.json', async (req, res) => {
    try {
        const snapshot = await buildPublicStatusSnapshot();
        return res.json({ success: true, ...snapshot });
    } catch (error) {
        console.error('Error loading public status JSON:', error);
        return res.status(500).json({ success: false, error: 'Failed to load status snapshot.' });
    }
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/');
    }
    res.render('login', {
        error: req.query.error || null,
        success: req.query.success || null,
        warning: req.query.warning || null
    });
});

// Login Page (POST) - WITH SECURITY MEASURES
app.post('/login',
    loginLimiter, // Apply strict rate limiting
    [
        // Input validation - relaxed to avoid false positives
        body('email')
            .trim()
            .notEmpty().withMessage('Email is required'),
        // Removed strict email validation that was rejecting valid emails like 1@1.ro
        body('password')
            .notEmpty().withMessage('Password is required')
        // Removed min length check - bcrypt handles any password length
    ],
    async (req, res) => {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.redirect('/login?error=' + encodeURIComponent('Invalid input provided'));
        }

        const { email, password, captcha } = req.body;

        // Captcha validation if enabled
        if (res.locals.settings.captchastatus === 'on') {
            if (!captcha || captcha.toLowerCase() !== req.session.captcha) {
                await appendSecurityCenterAlert(
                    'Login captcha validation failed',
                    `Email: ${email || 'unknown'}\nIP: ${req.ip || 'unknown'}`,
                    'warning',
                    'auth'
                );
                return res.redirect('/login?error=' + encodeURIComponent('Invalid captcha code'));
            }
            // Clear captcha after use
            delete req.session.captcha;
        }

        try {
            const user = await User.findOne({ where: { email } });

            if (!user || !(await bcrypt.compare(password, user.password))) {
                // Log failed login attempt
                console.warn(`Failed login attempt for email: ${email} from IP: ${req.ip}`);
                await appendSecurityCenterAlert(
                    'Invalid login credentials',
                    `Email: ${email || 'unknown'}\nIP: ${req.ip || 'unknown'}`,
                    'warning',
                    'auth'
                );
                return res.redirect('/login?error=' + encodeURIComponent('Invalid credentials'));
            }

            if (user.twoFactorEnabled) {
                // Redirect to 2FA page first
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

            // Successful login without 2FA - Save user in session
            req.session.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin,
                coins: Number.isFinite(Number(user.coins)) ? Number(user.coins) : 0,
                gravatarHash: md5(user.email.trim().toLowerCase()),
                avatarUrl: user.avatarUrl,
                avatarProvider: user.avatarProvider,
                twoFactorEnabled: user.twoFactorEnabled
            };

            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });

            console.log(`Successful login for user: ${user.username} (${user.email})`);
            res.redirect('/');
        } catch (err) {
            console.error('Login error:', err);
            return res.redirect('/login?error=' + encodeURIComponent('Login failed. Please try again.'));
        }
    }
);

// Login 2FA Verification (GET)
app.get('/login/2fa', (req, res) => {
    if (!req.session.login2faUser) return res.redirect('/login');
    res.render('login-2fa', { error: req.query.error });
});

// Login 2FA Verification (POST)
app.post('/login/2fa', loginLimiter, async (req, res) => {
    const { code, captcha } = req.body;
    const loginUser = req.session.login2faUser;

    if (!loginUser) return res.redirect('/login');

    // Captcha validation if enabled
    if (res.locals.settings.captchastatus === 'on') {
        if (!captcha || captcha.toLowerCase() !== req.session.captcha) {
            await appendSecurityCenterAlert(
                '2FA captcha validation failed',
                `Email: ${loginUser.email || 'unknown'}\nIP: ${req.ip || 'unknown'}`,
                'warning',
                'auth'
            );
            return res.redirect('/login/2fa?error=Invalid captcha code');
        }
        // Clear captcha after use
        delete req.session.captcha;
    }

    try {
        const user = await User.findByPk(loginUser.id);
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: code,
            digits: 6,
            window: 2 // Slightly larger window for login
        });

        if (verified) {
            // Upgrade temporary session to real session
            req.session.user = loginUser;
            req.session.user.twoFactorEnabled = true;
            delete req.session.login2faUser;

            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) return reject(err);
                    resolve();
                });
            });

            console.log(`Successful 2FA login for user: ${user.username}`);
            res.redirect('/');
        } else {
            await appendSecurityCenterAlert(
                'Invalid 2FA code submitted',
                `User: ${user && user.username ? user.username : 'unknown'}\nIP: ${req.ip || 'unknown'}`,
                'warning',
                'auth'
            );
            res.redirect('/login/2fa?error=Invalid 6-digit authentication code');
        }
    } catch (err) {
        console.error('2FA Login error:', err);
        res.redirect('/login/2fa?error=Verification failed');
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

function parseExtensionDashboardJson(raw, fallback) {
    if (raw === undefined || raw === null || raw === '') return fallback;
    try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (parsed === undefined || parsed === null) return fallback;
        return parsed;
    } catch {
        return fallback;
    }
}

function parseExtensionSeverity(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return ['normal', 'warning', 'critical'].includes(normalized) ? normalized : 'normal';
}

function parseDashboardTimestamp(value, fallback = 0) {
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
        if (value < 10_000_000_000) return Math.floor(value * 1000); // epoch seconds
        return Math.floor(value); // epoch milliseconds
    }
    const raw = String(value || '').trim();
    if (!raw) return fallback;
    if (/^\d+$/.test(raw)) {
        const numeric = Number.parseInt(raw, 10);
        if (Number.isInteger(numeric) && numeric > 0) {
            if (numeric < 10_000_000_000) return numeric * 1000;
            return numeric;
        }
    }
    const dateMs = new Date(raw).getTime();
    if (Number.isFinite(dateMs) && dateMs > 0) return dateMs;
    return fallback;
}

function buildExtensionSecurityRecordId() {
    try {
        return nodeCrypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }
}

async function appendSecurityCenterAlert(title, message, severity = 'warning', category = 'general') {
    try {
        const enabledRow = await Settings.findByPk('featureExtensionSecurityCenterEnabled');
        const isEnabled = String(enabledRow && enabledRow.value || 'false') === 'true';
        if (!isEnabled) return;

        const now = Date.now();
        const row = await Settings.findByPk('extensionSecurityAlertsRecords');
        const existing = normalizeDashboardSecurityAlerts(row && row.value ? row.value : '[]').map((entry) => ({
            id: entry.id || buildExtensionSecurityRecordId(),
            title: String(entry.title || '').trim().slice(0, 120),
            message: String(entry.message || '').trim().slice(0, 1200),
            severity: parseExtensionSeverity(entry.severity),
            category: String(entry.category || 'general').trim().slice(0, 60) || 'general',
            status: String(entry.status || '').trim().toLowerCase() === 'resolved' ? 'resolved' : 'open',
            createdAtMs: Number.parseInt(entry.createdAtMs, 10) || now,
            updatedAtMs: Number.parseInt(entry.updatedAtMs, 10) || now,
            resolvedAtMs: Number.parseInt(entry.resolvedAtMs, 10) || 0
        }));

        const cleanTitle = String(title || '').trim().slice(0, 120);
        if (!cleanTitle) return;
        const cleanMessage = String(message || '').trim().slice(0, 1200);
        const cleanCategory = String(category || 'general').trim().slice(0, 60) || 'general';
        const cleanSeverity = parseExtensionSeverity(severity);

        const latest = existing[0];
        if (latest
            && latest.title === cleanTitle
            && latest.message === cleanMessage
            && latest.category === cleanCategory
            && latest.status === 'open'
            && now - latest.createdAtMs < 60 * 1000) {
            return;
        }

        existing.unshift({
            id: buildExtensionSecurityRecordId(),
            title: cleanTitle,
            message: cleanMessage,
            severity: cleanSeverity,
            category: cleanCategory,
            status: 'open',
            createdAtMs: now,
            updatedAtMs: now,
            resolvedAtMs: 0
        });

        await Settings.upsert({
            key: 'extensionSecurityAlertsRecords',
            value: JSON.stringify(existing.slice(0, 300))
        });

        const webhooksModuleEnabledRow = await Settings.findByPk('featureExtensionWebhooksEnabled');
        const webhooksModuleEnabled = String(webhooksModuleEnabledRow && webhooksModuleEnabledRow.value || 'false') === 'true';
        if (!webhooksModuleEnabled) return;

        const webhooksConfigRow = await Settings.findByPk('extensionWebhooksConfig');
        const webhooksConfigRaw = parseExtensionDashboardJson(webhooksConfigRow && webhooksConfigRow.value ? webhooksConfigRow.value : '{}', {});
        const webhooksConfig = webhooksConfigRaw && typeof webhooksConfigRaw === 'object' ? webhooksConfigRaw : {};
        const events = webhooksConfig.events && typeof webhooksConfig.events === 'object' ? webhooksConfig.events : {};
        const webhooksEnabled = String(webhooksConfig.enabled || '').trim().toLowerCase() === 'true' || webhooksConfig.enabled === true || webhooksConfig.enabled === 1;
        const securityEventEnabled = String(events.securityAlertCreated || '').trim().toLowerCase() === 'true' || events.securityAlertCreated === true || events.securityAlertCreated === 1;
        const dispatchEnabled = webhooksEnabled && securityEventEnabled;
        if (!dispatchEnabled) return;

        const discordWebhook = String(webhooksConfig.discordWebhook || '').trim();
        const telegramBotToken = String(webhooksConfig.telegramBotToken || '').trim();
        const telegramChatId = String(webhooksConfig.telegramChatId || '').trim();
        const color = cleanSeverity === 'critical' ? '#ef4444' : cleanSeverity === 'warning' ? '#f59e0b' : '#10b981';
        const header = '[CPanel] Security Alert';
        const body = `${cleanTitle}\nCategory: ${cleanCategory}${cleanMessage ? `\n${cleanMessage}` : ''}`;

        if (discordWebhook && typeof sendDiscordSmartAlert === 'function') {
            await sendDiscordSmartAlert(discordWebhook, header, body, color);
        }
        if (telegramBotToken && telegramChatId && typeof sendTelegramSmartAlert === 'function') {
            await sendTelegramSmartAlert(telegramBotToken, telegramChatId, `${header}\n${body}`);
        }
    } catch (error) {
        console.warn('Failed to append Security Center alert:', error.message);
    }
}

function normalizeDashboardIncidents(raw) {
    const parsed = parseExtensionDashboardJson(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => ({
            id: String(entry && entry.id || '').trim(),
            title: String(entry && entry.title || '').trim().slice(0, 120),
            message: String(entry && entry.message || '').trim().slice(0, 1200),
            severity: parseExtensionSeverity(entry && entry.severity),
            status: String(entry && entry.status || '').trim().toLowerCase() === 'resolved' ? 'resolved' : 'open',
            createdAtMs: parseDashboardTimestamp(entry && entry.createdAtMs, 0),
            updatedAtMs: parseDashboardTimestamp(entry && entry.updatedAtMs, 0)
        }))
        .filter((entry) => entry.title.length > 0)
        .sort((a, b) => b.createdAtMs - a.createdAtMs);
}

function normalizeDashboardMaintenance(raw) {
    const parsed = parseExtensionDashboardJson(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => ({
            id: String(entry && entry.id || '').trim(),
            title: String(entry && entry.title || '').trim().slice(0, 120),
            message: String(entry && entry.message || '').trim().slice(0, 1200),
            severity: parseExtensionSeverity(entry && entry.severity),
            startsAtMs: parseDashboardTimestamp(entry && entry.startsAtMs, 0),
            endsAtMs: parseDashboardTimestamp(entry && entry.endsAtMs, 0),
            completed: Boolean(entry && entry.completed),
            createdAtMs: parseDashboardTimestamp(entry && entry.createdAtMs, 0)
        }))
        .filter((entry) => entry.title.length > 0)
        .sort((a, b) => b.createdAtMs - a.createdAtMs);
}

function normalizeDashboardSecurityAlerts(raw) {
    const parsed = parseExtensionDashboardJson(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => ({
            id: String(entry && entry.id || '').trim(),
            title: String(entry && entry.title || '').trim().slice(0, 120),
            message: String(entry && entry.message || '').trim().slice(0, 1200),
            category: String(entry && entry.category || 'general').trim().slice(0, 60) || 'general',
            severity: parseExtensionSeverity(entry && entry.severity),
            status: String(entry && entry.status || '').trim().toLowerCase() === 'resolved' ? 'resolved' : 'open',
            createdAtMs: parseDashboardTimestamp(entry && entry.createdAtMs, 0)
        }))
        .filter((entry) => entry.title.length > 0)
        .sort((a, b) => b.createdAtMs - a.createdAtMs);
}

// Dashboard (Home)
app.get('/', requireAuth, async (req, res) => {
    try {
        let where = {};
        if (!(req.session.user && req.session.user.isAdmin)) {
            const membershipRows = ServerSubuser
                ? await ServerSubuser.findAll({
                    where: { userId: req.session.user.id },
                    attributes: ['serverId']
                })
                : [];
            const membershipServerIds = membershipRows
                .map((row) => Number.parseInt(row.serverId, 10))
                .filter((id) => Number.isInteger(id) && id > 0);
            if (membershipServerIds.length > 0) {
                where = {
                    [Op.or]: [
                        { ownerId: req.session.user.id },
                        { id: membershipServerIds }
                    ]
                };
            } else {
                where = { ownerId: req.session.user.id };
            }
        }
        const servers = await Server.findAll({
            where,
            order: [['id', 'DESC']]
        });
        const settingsMap = res.locals.settings || {};
        const incidentsEnabled = String(settingsMap.featureExtensionIncidentsEnabled || 'false') === 'true';
        const maintenanceEnabled = String(settingsMap.featureExtensionMaintenanceEnabled || 'false') === 'true';
        const securityEnabled = String(settingsMap.featureExtensionSecurityCenterEnabled || 'false') === 'true';
        const incidentsRaw = normalizeDashboardIncidents(settingsMap.extensionIncidentsRecords || '[]');
        const maintenanceRaw = normalizeDashboardMaintenance(settingsMap.extensionMaintenanceRecords || '[]');
        const securityRaw = normalizeDashboardSecurityAlerts(settingsMap.extensionSecurityAlertsRecords || '[]');

        const openIncidents = incidentsEnabled ? incidentsRaw.filter((entry) => entry.status !== 'resolved').slice(0, 8) : [];
        const pendingMaintenance = maintenanceEnabled ? maintenanceRaw.filter((entry) => !entry.completed).slice(0, 8) : [];
        const openSecurityAlerts = securityEnabled ? securityRaw.filter((entry) => entry.status !== 'resolved').slice(0, 8) : [];

        res.render('dashboard', {
            user: req.session.user,
            servers,
            openIncidents,
            pendingMaintenance,
            openSecurityAlerts,
            dashboardNowMs: Date.now()
        });
    } catch (err) {
        console.error("Dashboard Error:", err);
        res.status(500).send('Error loading dashboard: ' + err.message);
    }
});

app.get('/connectors-check', requireAuth, async (req, res) => {
    try {
        const filterStatusRaw = String(req.query.status || 'all').trim().toLowerCase();
        const filterStatus = ['all', 'online', 'offline'].includes(filterStatusRaw) ? filterStatusRaw : 'all';
        const filterSearch = String(req.query.search || '').trim().toLowerCase().slice(0, 80);
        const minFreeRamGb = Math.max(0, Number.parseFloat(req.query.minFreeRamGb) || 0);
        const minFreeDiskGb = Math.max(0, Number.parseFloat(req.query.minFreeDiskGb) || 0);
        const minFreeAllocations = Math.max(0, Number.parseInt(req.query.minFreeAllocations, 10) || 0);

        const connectors = await Connector.findAll({
            include: [{ model: Location, as: 'location' }],
            order: [['name', 'ASC']]
        });

        const cards = await Promise.all(connectors.map(async (connector) => {
            const [allocatedUsage, totalAllocations, freeAllocations, cpuRows] = await Promise.all([
                getConnectorAllocatedUsage(connector.id),
                Allocation.count({ where: { connectorId: connector.id } }),
                Allocation.count({ where: { connectorId: connector.id, serverId: null } }),
                Server.findAll({
                    attributes: ['cpu'],
                    include: [{
                        model: Allocation,
                        as: 'allocation',
                        attributes: [],
                        where: { connectorId: connector.id }
                    }],
                    raw: true
                })
            ]);

            const cpuAllocatedPercent = cpuRows.reduce((sum, row) => {
                return sum + Math.max(0, Number.parseInt(row.cpu, 10) || 0);
            }, 0);
            const cpuAllocatedCores = cpuAllocatedPercent / 100;

            const memoryBaseGb = Math.max(0, Number(connector.totalMemory || 0));
            const diskBaseGb = Math.max(0, Number(connector.totalDisk || 0));
            const memoryCapGb = memoryBaseGb * (1 + (Math.max(0, Number(connector.memoryOverAllocation || 0)) / 100));
            const diskCapGb = diskBaseGb * (1 + (Math.max(0, Number(connector.diskOverAllocation || 0)) / 100));

            const memoryUsedGb = Math.max(0, Number(allocatedUsage.memoryGb || 0));
            const diskUsedGb = Math.max(0, Number(allocatedUsage.diskGb || 0));
            const memoryFreeGb = Math.max(0, memoryCapGb - memoryUsedGb);
            const diskFreeGb = Math.max(0, diskCapGb - diskUsedGb);

            const memoryUsagePct = memoryCapGb > 0 ? Math.min(100, (memoryUsedGb / memoryCapGb) * 100) : 0;
            const diskUsagePct = diskCapGb > 0 ? Math.min(100, (diskUsedGb / diskCapGb) * 100) : 0;

            const statusData = (global.connectorStatus && global.connectorStatus[connector.id]) || { status: 'offline', lastSeen: null, usage: null };
            const isOnline = statusData.status === 'online' && statusData.lastSeen && (new Date() - new Date(statusData.lastSeen)) < 30000;
            const serverUsage = statusData && statusData.usage && typeof statusData.usage === 'object' ? statusData.usage : null;

            return {
                connector: connector.toJSON(),
                isOnline,
                statusData,
                metrics: {
                    memoryUsedGb,
                    memoryCapGb,
                    memoryFreeGb,
                    memoryUsagePct,
                    diskUsedGb,
                    diskCapGb,
                    diskFreeGb,
                    diskUsagePct,
                    cpuAllocatedPercent,
                    cpuAllocatedCores,
                    cpuLivePercent: serverUsage ? Number(serverUsage.cpu || 0) : 0,
                    totalAllocations,
                    freeAllocations,
                    usedAllocations: Math.max(0, totalAllocations - freeAllocations)
                }
            };
        }));

        const filteredCards = cards.filter((item) => {
            if (filterStatus === 'online' && !item.isOnline) return false;
            if (filterStatus === 'offline' && item.isOnline) return false;
            if (item.metrics.memoryFreeGb < minFreeRamGb) return false;
            if (item.metrics.diskFreeGb < minFreeDiskGb) return false;
            if (item.metrics.freeAllocations < minFreeAllocations) return false;
            if (filterSearch) {
                const connector = item.connector || {};
                const haystack = `${String(connector.name || '').toLowerCase()} ${String(connector.fqdn || '').toLowerCase()} ${String(connector.location && connector.location.shortName || '').toLowerCase()}`;
                if (!haystack.includes(filterSearch)) return false;
            }
            return true;
        });

        return res.render('connectors-check', {
            user: req.session.user,
            title: 'Connectors Check',
            path: '/connectors-check',
            cards: filteredCards,
            totalCards: cards.length,
            filters: {
                status: filterStatus,
                search: filterSearch,
                minFreeRamGb,
                minFreeDiskGb,
                minFreeAllocations
            },
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading connectors-check page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load connectors check page.'));
    }
});

function clampInteger(value, fallback, min, max) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function normalizeEconomyUnit(value) {
    const clean = String(value || '').trim().slice(0, 16);
    return clean || 'Coins';
}

const SERVER_PERMISSIONS = Object.freeze([
    'server.view',
    'server.console',
    'server.power',
    'server.files',
    'server.startup',
    'server.minecraft',
    'server.backups.view',
    'server.backups.manage',
    'server.databases.view',
    'server.databases.manage',
    'server.schedules.view',
    'server.schedules.manage',
    'server.network.view',
    'server.network.manage',
    'server.users.view',
    'server.users.manage',
    'server.activity.view',
    'server.smartalerts',
    'server.policy'
]);
const SERVER_SCHEDULES_KEY_PREFIX = 'server_schedules_';
const SERVER_API_KEY_PERMISSIONS = Array.isArray(SERVER_API_KEY_PERMISSION_CATALOG)
    ? SERVER_API_KEY_PERMISSION_CATALOG
    : [
        'server.view',
        'server.console',
        'server.power',
        'server.files.read',
        'server.files.write',
        'server.files.download',
        'server.startup.read',
        'server.startup.write',
        'server.backups.view',
        'server.backups.manage',
        'server.databases.view',
        'server.databases.manage',
        'server.schedules.view',
        'server.schedules.manage',
        'server.network.view',
        'server.network.manage',
        'server.activity.view'
    ];

function normalizeServerApiPermissionList(input) {
    if (typeof normalizeServerApiKeyPermissions === 'function') {
        return normalizeServerApiKeyPermissions(input);
    }
    if (!Array.isArray(input)) return [];
    return Array.from(new Set(input
        .map((entry) => String(entry || '').trim())
        .filter((entry) => entry && SERVER_API_KEY_PERMISSIONS.includes(entry)))).sort();
}

function normalizeServerApiKeyExpiry(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const parsed = new Date(raw);
    if (!Number.isFinite(parsed.getTime())) return null;
    return parsed;
}

function formatServerApiKeyMaskedPrefix(prefix) {
    const head = String(prefix || '').trim();
    if (!head) return 'cp_srv_********';
    return `cp_srv_${head}********`;
}

function getRequestIp(req) {
    return req.headers['x-forwarded-for']
        || (req.socket && req.socket.remoteAddress)
        || req.ip
        || null;
}

function sanitizeAuditMetadata(input) {
    if (!input || typeof input !== 'object') return {};
    try {
        return JSON.parse(JSON.stringify(input));
    } catch {
        return {};
    }
}

async function createBillingAuditLog({
    actorUserId = null,
    action,
    targetType = null,
    targetId = null,
    req = null,
    metadata = {}
} = {}) {
    try {
        if (!AuditLog) return;
        const cleanAction = String(action || '').trim().slice(0, 120);
        if (!cleanAction) return;
        await AuditLog.create({
            actorUserId: Number.isInteger(Number(actorUserId)) && Number(actorUserId) > 0 ? Number(actorUserId) : null,
            action: cleanAction,
            targetType: targetType ? String(targetType).slice(0, 64) : null,
            targetId: targetId !== null && targetId !== undefined ? String(targetId).slice(0, 120) : null,
            method: req && req.method ? String(req.method).slice(0, 10) : 'SYSTEM',
            path: req && req.originalUrl ? String(req.originalUrl).slice(0, 255) : null,
            ip: req ? (String(getRequestIp(req) || '').slice(0, 120) || null) : null,
            userAgent: req && req.headers && req.headers['user-agent'] ? String(req.headers['user-agent']).slice(0, 1000) : null,
            metadata: sanitizeAuditMetadata(metadata)
        });
    } catch {
        // Ignore billing audit logging failures.
    }
}

function formatBillingActionLabel(action) {
    const map = {
        'billing.inventory.purchase': 'Inventory Purchase',
        'billing.inventory.sell': 'Inventory Sell',
        'billing.deal.purchase': 'Deal Purchase',
        'billing.server.create': 'Server Create Billing',
        'billing.server.renew': 'Server Renew',
        'billing.server.edit': 'Server Edit',
        'billing.server.delete': 'Server Delete',
        'billing.server.auto_suspend': 'Auto Suspend (Overdue)',
        'billing.server.auto_delete': 'Auto Delete (Overdue)',
        'billing.server.auto_unsuspend': 'Auto Unsuspend (Billing Disabled)'
    };
    const key = String(action || '').trim();
    return map[key] || key || 'Billing Event';
}

const QUOTA_FORECAST_V2_LOOKBACK_DAYS = 30;
const QUOTA_FORECAST_SPEND_ACTIONS = new Set([
    'billing.server.create',
    'billing.server.renew',
    'billing.inventory.purchase',
    'billing.deal.purchase',
    'billing.revenue.subscribe',
    'billing.revenue.renew_success'
]);
const SERVER_CONFIG_BASELINE_KEY_PREFIX = 'server_config_baseline_';
const PUBLIC_STATUS_INCIDENT_ACTIONS = Object.freeze([
    'server:debug.crash',
    'server:debug.install_fail',
    'server:debug.connector_error',
    'server:debug.event.die'
]);

function toFiniteNumber(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeAuditMetadata(raw) {
    if (!raw) return {};
    if (typeof raw === 'object') return raw;
    if (typeof raw !== 'string') return {};
    try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
        return {};
    }
}

function stableSerialize(value) {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableSerialize(entry)).join(',')}]`;
    }
    if (typeof value === 'object') {
        const keys = Object.keys(value).sort();
        return `{${keys.map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key])}`).join(',')}}`;
    }
    return JSON.stringify(String(value));
}

function hashStableValue(value) {
    try {
        return nodeCrypto.createHash('sha256').update(stableSerialize(value)).digest('hex');
    } catch {
        return '';
    }
}

function isQuotaForecastSpendAction(action) {
    const normalized = String(action || '').trim().toLowerCase();
    return QUOTA_FORECAST_SPEND_ACTIONS.has(normalized);
}

function computeQuotaObservedSpendStats(rows, ownerUserId, nowMs = Date.now()) {
    const list = Array.isArray(rows) ? rows : [];
    const ownerId = Number.parseInt(ownerUserId, 10) || 0;
    const cutoff30 = nowMs - (QUOTA_FORECAST_V2_LOOKBACK_DAYS * DAY_MS);
    const cutoff7 = nowMs - (7 * DAY_MS);

    let spend30 = 0;
    let spend7 = 0;
    let samples30 = 0;
    let samples7 = 0;

    for (const row of list) {
        if (!isQuotaForecastSpendAction(row && row.action)) continue;
        const metadata = normalizeAuditMetadata(row && row.metadata);
        const actorUserId = Number.parseInt(row && row.actorUserId, 10) || 0;
        const metaOwnerUserId = Number.parseInt(metadata.ownerUserId, 10) || 0;
        if (ownerId > 0 && actorUserId !== ownerId && metaOwnerUserId !== ownerId) continue;

        const amount = toFiniteNumber(metadata.amount, 0);
        if (amount <= 0) continue;

        const createdAtMs = new Date(row && row.createdAt ? row.createdAt : 0).getTime();
        if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) continue;
        if (createdAtMs < cutoff30) continue;

        spend30 += amount;
        samples30 += 1;
        if (createdAtMs >= cutoff7) {
            spend7 += amount;
            samples7 += 1;
        }
    }

    return {
        spend30,
        spend7,
        samples30,
        samples7,
        observedDailyBurn30: spend30 / QUOTA_FORECAST_V2_LOOKBACK_DAYS,
        observedDailyBurn7: spend7 / 7
    };
}

function buildQuotaForecastV2({
    enabled = false,
    walletCoins = 0,
    recurringDailyBurn = 0,
    revenueDailyBurn = 0,
    burnLogs = [],
    ownerUserId = 0
} = {}) {
    const baseRecurring = Math.max(0, toFiniteNumber(recurringDailyBurn, 0));
    const baseRevenue = Math.max(0, toFiniteNumber(revenueDailyBurn, 0));
    const baseTotal = baseRecurring + baseRevenue;

    if (!enabled) {
        return {
            enabled: false,
            modelVersion: 2,
            recurringDailyBurn: baseRecurring,
            revenueDailyBurn: baseRevenue,
            totalDailyBurn: baseTotal,
            observedDailyBurn30: 0,
            observedDailyBurn7: 0,
            projectedDailyBurn: baseTotal,
            projectedMonthlyBurn: baseTotal * 30,
            trendPercent: 0,
            confidencePercent: 0,
            runwayDays: null,
            runwayText: 'Disabled'
        };
    }

    const nowMs = Date.now();
    const observed = computeQuotaObservedSpendStats(burnLogs, ownerUserId, nowMs);
    const observedBlend = observed.observedDailyBurn30 > 0
        ? observed.observedDailyBurn30
        : observed.observedDailyBurn7;

    let projectedDailyBurn = baseTotal;
    if (baseTotal > 0 && observedBlend > 0) {
        projectedDailyBurn = (baseTotal * 0.65) + (observedBlend * 0.35);
    } else if (observedBlend > 0) {
        projectedDailyBurn = observedBlend;
    }
    projectedDailyBurn = Math.max(0, projectedDailyBurn);

    const trendPercent = baseTotal > 0 && observedBlend > 0
        ? ((observedBlend - baseTotal) / baseTotal) * 100
        : 0;

    const confidenceRaw = ((observed.samples30) + (observed.samples7 * 0.5)) / 20;
    const confidencePercent = Math.max(0, Math.min(100, Math.round(confidenceRaw * 100)));

    const runwayDays = estimateWalletRunwayDays(walletCoins, projectedDailyBurn);
    return {
        enabled: true,
        modelVersion: 2,
        recurringDailyBurn: baseRecurring,
        revenueDailyBurn: baseRevenue,
        totalDailyBurn: baseTotal,
        observedDailyBurn30: Math.max(0, observed.observedDailyBurn30),
        observedDailyBurn7: Math.max(0, observed.observedDailyBurn7),
        projectedDailyBurn,
        projectedMonthlyBurn: projectedDailyBurn * 30,
        trendPercent,
        confidencePercent,
        runwayDays,
        runwayText: describeRunway(runwayDays)
    };
}

function getServerConfigBaselineSettingKey(serverId) {
    return `${SERVER_CONFIG_BASELINE_KEY_PREFIX}${Number.parseInt(serverId, 10) || 0}`;
}

function normalizeServerConfigBaseline(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const variables = parsed.variables && typeof parsed.variables === 'object' ? parsed.variables : {};
    const variablesHash = String(parsed.variablesHash || '').trim() || hashStableValue(variables);
    const toInt = (value, fallback = 0) => Math.max(0, Number.parseInt(value, 10) || fallback);
    const toBool = (value) => value === true || String(value || '').trim().toLowerCase() === 'true';

    return {
        dockerImage: String(parsed.dockerImage || '').trim(),
        startup: String(parsed.startup || '').trim(),
        memory: toInt(parsed.memory, 0),
        cpu: toInt(parsed.cpu, 0),
        disk: toInt(parsed.disk, 0),
        swapLimit: toInt(parsed.swapLimit, 0),
        ioWeight: toInt(parsed.ioWeight, 0),
        pidsLimit: toInt(parsed.pidsLimit, 0),
        oomKillDisable: toBool(parsed.oomKillDisable),
        oomScoreAdj: Number.parseInt(parsed.oomScoreAdj, 10) || 0,
        variables,
        variablesHash,
        capturedAtMs: Number.parseInt(parsed.capturedAtMs, 10) || Date.now(),
        updatedAtMs: Number.parseInt(parsed.updatedAtMs, 10) || Date.now()
    };
}

function buildServerConfigSnapshot(server) {
    const variables = server && server.variables && typeof server.variables === 'object' ? server.variables : {};
    const now = Date.now();
    return normalizeServerConfigBaseline({
        dockerImage: String(server && server.dockerImage || '').trim(),
        startup: String(server && server.startup || '').trim(),
        memory: Number.parseInt(server && server.memory, 10) || 0,
        cpu: Number.parseInt(server && server.cpu, 10) || 0,
        disk: Number.parseInt(server && server.disk, 10) || 0,
        swapLimit: Number.parseInt(server && server.swapLimit, 10) || 0,
        ioWeight: Number.parseInt(server && server.ioWeight, 10) || 0,
        pidsLimit: Number.parseInt(server && server.pidsLimit, 10) || 0,
        oomKillDisable: Boolean(server && server.oomKillDisable),
        oomScoreAdj: Number.parseInt(server && server.oomScoreAdj, 10) || 0,
        variables,
        variablesHash: hashStableValue(variables),
        capturedAtMs: now,
        updatedAtMs: now
    });
}

async function getServerConfigBaseline(serverId) {
    const row = await Settings.findByPk(getServerConfigBaselineSettingKey(serverId));
    if (!row || !row.value) return null;
    return normalizeServerConfigBaseline(row.value);
}

async function setServerConfigBaseline(serverId, snapshot) {
    const normalized = normalizeServerConfigBaseline(snapshot);
    normalized.updatedAtMs = Date.now();
    await Settings.upsert({
        key: getServerConfigBaselineSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

function computeServerConfigDrift(server, baseline) {
    const current = buildServerConfigSnapshot(server);
    const base = baseline ? normalizeServerConfigBaseline(baseline) : null;
    if (!base) {
        return {
            hasBaseline: false,
            drifted: false,
            changedFields: [],
            baseline: null,
            current
        };
    }

    const changedFields = [];
    const addChanged = (key, label, baselineValue, currentValue) => {
        if (baselineValue === currentValue) return;
        changedFields.push({
            key,
            label,
            baseline: baselineValue,
            current: currentValue
        });
    };

    addChanged('dockerImage', 'Docker Image', base.dockerImage, current.dockerImage);
    addChanged('startup', 'Startup', base.startup, current.startup);
    addChanged('memory', 'Memory (MB)', base.memory, current.memory);
    addChanged('cpu', 'CPU (%)', base.cpu, current.cpu);
    addChanged('disk', 'Disk (MB)', base.disk, current.disk);
    addChanged('swapLimit', 'Swap (MB)', base.swapLimit, current.swapLimit);
    addChanged('ioWeight', 'IO Weight', base.ioWeight, current.ioWeight);
    addChanged('pidsLimit', 'PIDs Limit', base.pidsLimit, current.pidsLimit);
    addChanged('oomKillDisable', 'OOM Kill Disable', String(base.oomKillDisable), String(current.oomKillDisable));
    addChanged('oomScoreAdj', 'OOM Score Adj', base.oomScoreAdj, current.oomScoreAdj);
    if (base.variablesHash !== current.variablesHash) {
        changedFields.push({
            key: 'variables',
            label: 'Environment Variables',
            baseline: `hash:${base.variablesHash.slice(0, 12)}`,
            current: `hash:${current.variablesHash.slice(0, 12)}`
        });
    }

    return {
        hasBaseline: true,
        drifted: changedFields.length > 0,
        changedFields,
        baseline: base,
        current
    };
}

function computeServerHealthScore(server, debugLogs = [], configDrift = null) {
    const status = String(server && server.status || '').trim().toLowerCase();
    const logs = Array.isArray(debugLogs) ? debugLogs : [];
    const byAction = (action) => logs.filter((entry) => String(entry && entry.action || '') === action).length;
    const crashCount = byAction('server:debug.crash');
    const installFailCount = byAction('server:debug.install_fail');
    const connectorErrorCount = byAction('server:debug.connector_error');
    const dieCount = byAction('server:debug.event.die');

    let score = 100;
    const factors = [];
    if (status === 'error') {
        score -= 35;
        factors.push('Server status is error');
    } else if (status === 'offline' || status === 'stopped') {
        score -= 15;
        factors.push('Server is not running');
    } else if (status === 'installing' || status === 'starting') {
        score -= 10;
        factors.push('Server is in transition state');
    }

    if (crashCount > 0) {
        score -= Math.min(45, crashCount * 15);
        factors.push(`${crashCount} crash event(s) in last 24h`);
    }
    if (installFailCount > 0) {
        score -= Math.min(30, installFailCount * 15);
        factors.push(`${installFailCount} install fail event(s) in last 24h`);
    }
    if (connectorErrorCount > 0) {
        score -= Math.min(20, connectorErrorCount * 10);
        factors.push(`${connectorErrorCount} connector error event(s) in last 24h`);
    }
    if (dieCount > 0) {
        score -= Math.min(15, dieCount * 5);
        factors.push(`${dieCount} unexpected container die event(s) in last 24h`);
    }
    if (configDrift && configDrift.hasBaseline && configDrift.drifted) {
        score -= Math.min(20, configDrift.changedFields.length * 4);
        factors.push(`${configDrift.changedFields.length} config drift change(s) from baseline`);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));
    let grade = 'Critical';
    let badgeClass = 'bg-danger';
    if (score >= 90) {
        grade = 'Excellent';
        badgeClass = 'bg-success';
    } else if (score >= 75) {
        grade = 'Good';
        badgeClass = 'bg-primary';
    } else if (score >= 55) {
        grade = 'Warning';
        badgeClass = 'bg-warning text-dark';
    }

    return {
        score,
        grade,
        badgeClass,
        factors,
        incidents: {
            crashCount,
            installFailCount,
            connectorErrorCount,
            dieCount
        }
    };
}

function parseSmartAllocationToggle(value, fallback = true) {
    if (value === undefined || value === null || value === '') return fallback;
    const normalized = String(value).trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(normalized);
}

async function buildConnectorUsageMap(connectorIds = []) {
    const uniqueIds = Array.from(new Set((Array.isArray(connectorIds) ? connectorIds : [])
        .map((entry) => Number.parseInt(entry, 10))
        .filter((entry) => Number.isInteger(entry) && entry > 0)));
    const map = {};
    await Promise.all(uniqueIds.map(async (connectorId) => {
        try {
            map[connectorId] = await getConnectorAllocatedUsage(connectorId);
        } catch {
            map[connectorId] = { memoryMb: 0, diskMb: 0 };
        }
    }));
    return map;
}

function formatSmartAllocationResponse(result) {
    if (!result || !result.ok || !result.best || !result.best.allocation) {
        return null;
    }

    const best = result.best;
    const allocation = best.allocation;
    const connector = best.connector || allocation.connector || null;
    const location = connector && connector.location ? connector.location : null;

    return {
        id: Number.parseInt(allocation.id, 10) || 0,
        ip: String(allocation.ip || ''),
        port: Number.parseInt(allocation.port, 10) || 0,
        alias: allocation.alias || null,
        connectorId: Number.parseInt(allocation.connectorId, 10) || 0,
        connectorName: connector ? String(connector.name || `Connector #${allocation.connectorId}`) : `Connector #${allocation.connectorId}`,
        locationId: location ? (Number.parseInt(location.id, 10) || 0) : (Number.parseInt(connector && connector.locationId, 10) || 0),
        locationName: location ? String(location.shortName || location.name || `Location #${location.id}`) : null,
        score: Number(best.score || 0),
        estimatedCpuUsage: Number(best.cpuUsage || 0),
        projectedMemoryHeadroomMb: Number(best.cap && best.cap.memoryHeadroomMb || 0),
        projectedDiskHeadroomMb: Number(best.cap && best.cap.diskHeadroomMb || 0)
    };
}

function formatPublicIncident(entry) {
    const action = String(entry && entry.action || '').trim();
    const metadata = normalizeAuditMetadata(entry && entry.metadata);
    const actionLabelMap = {
        'server:debug.crash': 'Server crash detected',
        'server:debug.install_fail': 'Install failed',
        'server:debug.connector_error': 'Connector runtime error',
        'server:debug.event.die': 'Container stopped unexpectedly'
    };
    return {
        action,
        actionLabel: actionLabelMap[action] || action,
        targetType: String(entry && entry.targetType || ''),
        targetId: String(entry && entry.targetId || ''),
        createdAt: entry && entry.createdAt ? entry.createdAt : null,
        message: metadata && metadata.message ? String(metadata.message).slice(0, 240) : null,
        exitCode: Number.parseInt(metadata.exitCode, 10) || null
    };
}

async function buildPublicStatusSnapshot() {
    const nowMs = Date.now();
    const connectors = await Connector.findAll({
        include: [{ model: Allocation, as: 'allocations', attributes: ['id', 'serverId'] }],
        order: [['name', 'ASC']]
    });

    const usageByConnector = await buildConnectorUsageMap(connectors.map((entry) => entry.id));
    const connectorStatusMap = global.connectorStatus || {};

    const nodes = connectors.map((connector) => {
        const connectorId = Number.parseInt(connector.id, 10) || 0;
        const statusData = connectorStatusMap[connectorId] || { status: 'offline', lastSeen: null, usage: {} };
        const online = String(statusData.status || '').toLowerCase() === 'online'
            && (nowMs - new Date(statusData.lastSeen || 0).getTime()) < 30000;
        const usage = usageByConnector[connectorId] || { memoryMb: 0, diskMb: 0 };
        const totalMemoryGb = Number(connector.totalMemory || 0);
        const totalDiskGb = Number(connector.totalDisk || 0);
        const maxMemoryGb = totalMemoryGb * (1 + (Number(connector.memoryOverAllocation || 0) / 100));
        const maxDiskGb = totalDiskGb * (1 + (Number(connector.diskOverAllocation || 0) / 100));
        const memoryAllocatedGb = Number(usage.memoryMb || 0) / 1024;
        const diskAllocatedGb = Number(usage.diskMb || 0) / 1024;
        const memoryPercent = maxMemoryGb > 0 ? (memoryAllocatedGb / maxMemoryGb) * 100 : 0;
        const diskPercent = maxDiskGb > 0 ? (diskAllocatedGb / maxDiskGb) * 100 : 0;
        const allocations = Array.isArray(connector.allocations) ? connector.allocations : [];
        const servers = allocations.filter((alloc) => Number.parseInt(alloc.serverId, 10) > 0).length;
        const freeAllocations = allocations.filter((alloc) => !alloc.serverId).length;

        return {
            id: connectorId,
            name: String(connector.name || `Connector #${connectorId}`),
            fqdn: String(connector.fqdn || ''),
            online,
            cpuPercent: Math.max(0, Math.min(100, Number(statusData && statusData.usage && statusData.usage.cpu || 0))),
            memoryAllocatedGb: Number(memoryAllocatedGb.toFixed(2)),
            diskAllocatedGb: Number(diskAllocatedGb.toFixed(2)),
            memoryCapacityGb: Number(maxMemoryGb.toFixed(2)),
            diskCapacityGb: Number(maxDiskGb.toFixed(2)),
            memoryPercent: Math.max(0, Math.min(100, Number(memoryPercent.toFixed(2)))),
            diskPercent: Math.max(0, Math.min(100, Number(diskPercent.toFixed(2)))),
            servers,
            allocations: allocations.length,
            freeAllocations,
            lastSeen: statusData.lastSeen || null
        };
    });

    const onlineNodes = nodes.filter((entry) => entry.online).length;
    const overall = onlineNodes === nodes.length && nodes.length > 0
        ? { status: 'operational', label: 'Operational', className: 'success' }
        : onlineNodes > 0
            ? { status: 'degraded', label: 'Degraded', className: 'warning' }
            : { status: 'outage', label: 'Outage', className: 'danger' };

    let incidents = [];
    if (AuditLog) {
        const rawIncidents = await AuditLog.findAll({
            where: {
                action: { [Op.in]: PUBLIC_STATUS_INCIDENT_ACTIONS },
                createdAt: { [Op.gte]: new Date(nowMs - (48 * 60 * 60 * 1000)) }
            },
            attributes: ['action', 'targetType', 'targetId', 'createdAt', 'metadata'],
            order: [['createdAt', 'DESC']],
            limit: 40
        });
        incidents = rawIncidents.map(formatPublicIncident);
    }

    return {
        generatedAt: new Date(nowMs).toISOString(),
        overall,
        counts: {
            connectorsTotal: nodes.length,
            connectorsOnline: onlineNodes
        },
        nodes,
        incidents
    };
}

async function authenticateServerApiClientRequest(req, requiredPermission) {
    if (!ServerApiKey) {
        return { ok: false, status: 503, error: 'Server API keys are not available.' };
    }

    const server = await Server.findOne({
        where: { containerId: req.params.containerId },
        include: [
            { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] },
            { model: Image, as: 'image' }
        ]
    });

    if (!server) {
        return { ok: false, status: 404, error: 'Server not found.' };
    }

    const parsedBearer = typeof parseServerApiBearerToken === 'function'
        ? parseServerApiBearerToken(req.headers.authorization || '')
        : null;
    if (!parsedBearer || !parsedBearer.token) {
        return { ok: false, status: 401, error: 'Missing or invalid bearer token.' };
    }

    const tokenHash = typeof hashServerApiKeyToken === 'function'
        ? hashServerApiKeyToken(parsedBearer.token, SECRET_KEY)
        : '';
    if (!tokenHash) {
        return { ok: false, status: 500, error: 'Server API key hashing is unavailable.' };
    }

    const apiKey = await ServerApiKey.findOne({
        where: {
            serverId: server.id,
            keyHash: tokenHash
        }
    });

    if (!apiKey) {
        return { ok: false, status: 401, error: 'Invalid server API key.' };
    }

    const isActive = typeof isServerApiKeyActive === 'function'
        ? isServerApiKeyActive(apiKey)
        : !apiKey.revokedAt;
    if (!isActive) {
        return { ok: false, status: 401, error: 'Server API key is inactive or expired.' };
    }

    const hasPermission = typeof hasServerApiKeyPermission === 'function'
        ? hasServerApiKeyPermission(apiKey, requiredPermission)
        : normalizeServerApiPermissionList(apiKey.permissions).includes(requiredPermission);
    if (!hasPermission) {
        return { ok: false, status: 403, error: `Missing API key permission: ${requiredPermission}` };
    }

    await apiKey.update({
        lastUsedAt: new Date(),
        lastUsedIp: String(getRequestIp(req) || '').slice(0, 120) || null
    }).catch(() => {});

    return { ok: true, server, apiKey };
}

function waitForConnectorMessage(connectorWs, predicate, timeoutMs = 12000) {
    return new Promise((resolve) => {
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            connectorWs.removeListener('message', onMessage);
            resolve({ success: false, error: 'Timed out waiting for connector response.' });
        }, timeoutMs);

        function finish(payload) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            connectorWs.removeListener('message', onMessage);
            resolve(payload);
        }

        function onMessage(rawMessage) {
            try {
                const message = JSON.parse(rawMessage);
                const decision = predicate(message);
                if (!decision) return;
                finish(decision);
            } catch {
                // Ignore non-JSON/unrelated events.
            }
        }

        connectorWs.on('message', onMessage);
    });
}

function normalizeServerDirectoryInput(rawDirectory) {
    const directoryRaw = String(rawDirectory || '/').trim() || '/';
    return directoryRaw.startsWith('/') ? directoryRaw : `/${directoryRaw}`;
}

function isServerLikelyMinecraft(serverLike) {
    const image = serverLike && serverLike.image ? serverLike.image : {};
    const candidates = [
        image.name,
        image.description,
        image.startup,
        image.dockerImage,
        serverLike && serverLike.dockerImage
    ];
    const haystack = String(candidates.filter(Boolean).join(' ')).toLowerCase();
    if (!haystack) return false;
    const keywords = [
        'minecraft',
        'paper',
        'purpur',
        'spigot',
        'bukkit',
        'forge',
        'fabric',
        'neoforge',
        'quilt',
        'velocity',
        'bungeecord',
        'waterfall',
        'bedrock',
        'pufferfish'
    ];
    return keywords.some((keyword) => haystack.includes(keyword));
}

function sanitizeUploadFileName(rawName) {
    const name = String(rawName || '').trim();
    if (!name) return '';
    if (name === '.' || name === '..') return '';
    if (/[\\/]/.test(name)) return '';
    const cleaned = name.replace(/[^A-Za-z0-9._\-+()@{}\[\] ]/g, '_').slice(0, 200).trim();
    if (!cleaned || cleaned === '.' || cleaned === '..') return '';
    return cleaned;
}

function normalizeBufferToSearchableAscii(buffer, maxBytes = 2 * 1024 * 1024) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) return '';
    const targetBytes = Math.min(buffer.length, Math.max(1024, maxBytes));
    const headBytes = Math.floor(targetBytes * 0.7);
    const tailBytes = targetBytes - headBytes;
    const chunks = [];
    chunks.push(buffer.subarray(0, headBytes));
    if (tailBytes > 0 && buffer.length > headBytes) {
        chunks.push(buffer.subarray(buffer.length - tailBytes));
    }
    const slice = Buffer.concat(chunks);
    let out = '';
    for (let i = 0; i < slice.length; i += 1) {
        const byte = slice[i];
        if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
            out += String.fromCharCode(byte);
        } else {
            out += ' ';
        }
    }
    return out.toLowerCase();
}

function inspectUploadForMinerRisk(fileName, rawContent) {
    const safeName = String(fileName || '').toLowerCase();
    const ext = path.extname(safeName || '').toLowerCase();
    const searchable = normalizeBufferToSearchableAscii(rawContent);
    const isElf = Buffer.isBuffer(rawContent) && rawContent.length >= 4
        && rawContent[0] === 0x7f && rawContent[1] === 0x45 && rawContent[2] === 0x4c && rawContent[3] === 0x46;
    const isPe = Buffer.isBuffer(rawContent) && rawContent.length >= 2
        && rawContent[0] === 0x4d && rawContent[1] === 0x5a;
    const isExecutableSignature = isElf || isPe;
    const executableLikeExt = ['.exe', '.bin', '.elf', '.run', '.out'].includes(ext);

    const strongPatterns = [
        /\bxmrig\b/i,
        /\bxmr-stak\b/i,
        /\bcpuminer\b/i,
        /\bminerd\b/i,
        /\bstratum\+tcp\b/i,
        /\brandomx\b/i,
        /\bcryptonight\b/i,
        /\bmoneroocean\b/i,
        /\bminexmr\b/i
    ];
    const mediumPatterns = [
        /\bteamredminer\b/i,
        /\bethminer\b/i,
        /\bnbminer\b/i,
        /\bgminer\b/i,
        /\bsrbminer\b/i,
        /\bhashvault\b/i,
        /\b2miners\b/i,
        /\bnicehash\b/i
    ];

    let score = 0;
    const evidence = [];
    let hasStrongMatch = false;

    for (const pattern of strongPatterns) {
        if (pattern.test(searchable) || pattern.test(safeName)) {
            score += 6;
            hasStrongMatch = true;
            evidence.push(`strong:${pattern.source}`);
        }
    }
    for (const pattern of mediumPatterns) {
        if (pattern.test(searchable) || pattern.test(safeName)) {
            score += 3;
            evidence.push(`medium:${pattern.source}`);
        }
    }
    if (isExecutableSignature) {
        score += 2;
        evidence.push(isElf ? 'sig:elf' : 'sig:pe');
    }
    if (executableLikeExt) {
        score += 1;
        evidence.push(`ext:${ext}`);
    }

    const confidence = score >= 8 && (hasStrongMatch || isExecutableSignature);
    return {
        flagged: confidence,
        score,
        evidence: Array.from(new Set(evidence)).slice(0, 12),
        executableSignature: isExecutableSignature
    };
}

function isTruthySettingValue(value) {
    const normalized = String(value === undefined || value === null ? '' : value).trim().toLowerCase();
    return normalized === '1' || normalized === 'true' || normalized === 'on' || normalized === 'yes';
}

async function suspendServerForUploadThreat(server, connectorWs, reason, req) {
    if (!server || server.isSuspended) return false;

    try {
        if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
            try {
                rememberServerPowerIntent(server.id, 'kill');
            } catch {
                // Ignore intent cache errors.
            }
            connectorWs.send(JSON.stringify({
                type: 'server_power',
                serverId: server.id,
                action: 'kill',
                requestId: `upload_guard_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`
            }));
        }
    } catch {
        // Continue with DB suspend even if connector send fails.
    }

    await server.update({
        isSuspended: true,
        status: 'suspended',
        suspendReason: String(reason || 'Security policy: suspicious miner payload upload detected.').slice(0, 1000)
    });
    server.status = 'suspended';

    if (typeof sendServerSmartAlert === 'function') {
        sendServerSmartAlert(server, 'suspended', { reason: server.suspendReason });
    }
    if (typeof createBillingAuditLog === 'function') {
        await createBillingAuditLog({
            actorUserId: req && req.session && req.session.user ? req.session.user.id : null,
            action: 'server.security.upload_miner_suspended',
            targetType: 'server',
            targetId: server.id,
            req,
            metadata: {
                serverId: server.id,
                containerId: server.containerId,
                reason: server.suspendReason
            }
        });
    }
    return true;
}

function readBinaryRequestBody(req, maxBytes = 25 * 1024 * 1024) {
    return new Promise((resolve, reject) => {
        let totalBytes = 0;
        const chunks = [];

        req.on('data', (chunk) => {
            totalBytes += chunk.length;
            if (totalBytes > maxBytes) {
                reject(new Error(`File is too large. Max ${Math.round(maxBytes / (1024 * 1024))} MiB.`));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });

        req.on('end', () => {
            resolve(Buffer.concat(chunks));
        });

        req.on('error', (error) => {
            reject(error);
        });
    });
}

function normalizeServerPermissionList(input) {
    if (!Array.isArray(input)) return [];
    return Array.from(new Set(input
        .map((entry) => String(entry || '').trim())
        .filter((entry) => entry && SERVER_PERMISSIONS.includes(entry))));
}

async function resolveServerAccess(server, reqUser) {
    if (!server || !reqUser) {
        return { allowed: false, isAdmin: false, isOwner: false, permissions: new Set() };
    }

    const isAdmin = Boolean(reqUser.isAdmin);
    const isOwner = Number.parseInt(server.ownerId, 10) === Number.parseInt(reqUser.id, 10);
    if (isAdmin || isOwner) {
        return {
            allowed: true,
            isAdmin,
            isOwner,
            permissions: new Set(SERVER_PERMISSIONS)
        };
    }

    if (!ServerSubuser) {
        return { allowed: false, isAdmin: false, isOwner: false, permissions: new Set() };
    }

    const membership = await ServerSubuser.findOne({
        where: {
            serverId: server.id,
            userId: reqUser.id
        }
    });
    if (!membership) {
        return { allowed: false, isAdmin: false, isOwner: false, permissions: new Set() };
    }

    const permissions = new Set(normalizeServerPermissionList(membership.permissions));
    if (!permissions.has('server.view')) {
        permissions.add('server.view');
    }

    return {
        allowed: true,
        isAdmin: false,
        isOwner: false,
        permissions
    };
}

function hasServerPermission(access, permission) {
    if (!access || !access.allowed) return false;
    if (access.isAdmin || access.isOwner) return true;
    return access.permissions instanceof Set && access.permissions.has(permission);
}

function getServerSchedulesSettingKey(serverId) {
    return `${SERVER_SCHEDULES_KEY_PREFIX}${serverId}`;
}

async function getServerSchedules(serverId) {
    const row = await Settings.findByPk(getServerSchedulesSettingKey(serverId));
    if (!row || !row.value) return [];
    try {
        const parsed = JSON.parse(row.value);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

async function setServerSchedules(serverId, schedules) {
    const normalized = Array.isArray(schedules) ? schedules : [];
    await Settings.upsert({
        key: getServerSchedulesSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
}

function isLikelyCronExpression(value) {
    const raw = String(value || '').trim();
    if (!raw) return false;
    const parts = raw.split(/\s+/).filter(Boolean);
    if (parts.length !== 5) return false;

    return parts.every((part) => /^[\d*/,\-]+$/.test(part));
}

const AFK_PERIOD_SECONDS = {
    minute: 60,
    hour: 60 * 60,
    day: 60 * 60 * 24,
    week: 60 * 60 * 24 * 7,
    month: 60 * 60 * 24 * 30,
    year: 60 * 60 * 24 * 365
};
const STREAK_RESET_INACTIVITY_SECONDS = 60 * 60 * 24;

function normalizeAfkPeriod(value, fallback = 'minute') {
    const normalized = String(value || '').trim().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(AFK_PERIOD_SECONDS, normalized)) {
        return normalized;
    }
    return fallback;
}

const STORE_BILLING_REASON_PREFIX = '[STORE_BILLING]';
const STORE_BILLING_REASON_DEFAULT = `${STORE_BILLING_REASON_PREFIX} Renewal overdue`;
const DAY_MS = 24 * 60 * 60 * 1000;

function isStoreBillingSuspensionReason(reason) {
    return String(reason || '').startsWith(STORE_BILLING_REASON_PREFIX);
}

function getStoreBillingSettingKeySafe(serverId) {
    if (typeof getServerStoreBillingSettingKey === 'function') {
        return getServerStoreBillingSettingKey(serverId);
    }
    return `server_store_billing_${serverId}`;
}

function getServerRevenueManagedSettingKey(serverId) {
    return `server_revenue_managed_${serverId}`;
}

function normalizeServerRevenueManagedState(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const managed = Boolean(parsed.managed);
    const planId = String(parsed.planId || '').trim();
    const profileStatus = String(parsed.profileStatus || '').trim().toLowerCase();
    const createdAtMs = Math.max(0, Number.parseInt(parsed.createdAtMs, 10) || Date.now());
    const updatedAtMs = Math.max(createdAtMs, Number.parseInt(parsed.updatedAtMs, 10) || createdAtMs);

    return {
        managed,
        planId,
        profileStatus,
        createdAtMs,
        updatedAtMs
    };
}

async function getServerRevenueManagedState(serverId) {
    const row = await Settings.findByPk(getServerRevenueManagedSettingKey(serverId));
    if (!row || !row.value) return null;
    return normalizeServerRevenueManagedState(row.value);
}

async function setServerRevenueManagedState(serverId, state) {
    const normalized = normalizeServerRevenueManagedState({
        ...(state && typeof state === 'object' ? state : {}),
        updatedAtMs: Date.now()
    });
    await Settings.upsert({
        key: getServerRevenueManagedSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function removeServerRevenueManagedState(serverId) {
    await Settings.destroy({ where: { key: getServerRevenueManagedSettingKey(serverId) } });
}

function normalizeStoreBillingStateSafe(raw) {
    if (typeof normalizeServerStoreBillingState === 'function') {
        return normalizeServerStoreBillingState(raw);
    }
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const toTs = (value, fallback = 0) => {
        const parsedTs = Number.parseInt(String(value === undefined || value === null ? '' : value), 10);
        return Number.isInteger(parsedTs) && parsedTs > 0 ? parsedTs : fallback;
    };

    const renewDays = Math.max(1, Number.parseInt(parsed.renewDays, 10) || 30);
    const createdAtMs = toTs(parsed.createdAtMs, Date.now());
    const nextRenewAtMs = toTs(parsed.nextRenewAtMs, createdAtMs + renewDays * DAY_MS);
    return {
        status: String(parsed.status || '').toLowerCase() === 'suspended_due' ? 'suspended_due' : 'active',
        recurringCoins: Math.max(0, Math.ceil(Number(parsed.recurringCoins) || 0)),
        renewDays,
        createdAtMs,
        lastRenewAtMs: toTs(parsed.lastRenewAtMs, createdAtMs),
        nextRenewAtMs,
        suspendedAtMs: toTs(parsed.suspendedAtMs, 0),
        deleteAfterMs: toTs(parsed.deleteAfterMs, 0)
    };
}

async function getStoreBillingStateSafe(serverId) {
    if (typeof getServerStoreBillingState === 'function') {
        return getServerStoreBillingState(serverId);
    }
    const setting = await Settings.findByPk(getStoreBillingSettingKeySafe(serverId));
    if (!setting || !setting.value) return null;
    return normalizeStoreBillingStateSafe(setting.value);
}

async function setStoreBillingStateSafe(serverId, state) {
    if (typeof setServerStoreBillingState === 'function') {
        return setServerStoreBillingState(serverId, state);
    }
    const normalized = normalizeStoreBillingStateSafe(state);
    await Settings.upsert({
        key: getStoreBillingSettingKeySafe(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function removeStoreBillingStateSafe(serverId) {
    if (typeof removeServerStoreBillingState === 'function') {
        return removeServerStoreBillingState(serverId);
    }
    await Settings.destroy({ where: { key: getStoreBillingSettingKeySafe(serverId) } });
}

function calculateStoreCreateCostSafe(input, settingsMap = {}) {
    if (typeof calculateStoreCreateCoins === 'function') {
        return calculateStoreCreateCoins(input, settingsMap);
    }
    const features = getPanelFeatureFlagsFromMap(settingsMap);
    const memoryGb = Math.max(0, Number(input.memory || 0) / 1024);
    const cpuCores = Math.max(0, Number(input.cpu || 0) / 100);
    const diskGb = Math.max(0, Number(input.disk || 0) / 1024);
    const swapGb = Math.max(0, Number(input.swapLimit || 0) / 1024);
    const total = Math.max(0, Math.ceil(
        (memoryGb * features.storeRamPerGbCoins) +
        (cpuCores * features.storeCpuPerCoreCoins) +
        (diskGb * features.storeDiskPerGbCoins) +
        (swapGb * features.storeSwapPerGbCoins) +
        (input.hasAllocation ? features.storeAllocationCoins : 0) +
        (input.hasImage ? features.storeImageCoins : 0) +
        (input.hasPackage ? features.storePackageCoins : 0) +
        (Math.max(0, Number.parseInt(input.databaseLimit, 10) || 0) * Number(features.storeDatabaseCoins || 0))
    ));
    return { total, breakdown: {} };
}

function calculateStoreRenewCostSafe(serverLike, settingsMap = {}) {
    if (typeof calculateStoreRenewCoins === 'function') {
        return calculateStoreRenewCoins(serverLike, settingsMap);
    }
    const estimate = calculateServerCostEstimate(serverLike, settingsMap);
    if (!estimate) return 0;
    return Math.max(0, Math.ceil(Number(estimate.monthly) || 0));
}

function getUserInventorySettingKey(userId) {
    return `user_store_inventory_${userId}`;
}

function getServerInventoryProvisioningSettingKey(serverId) {
    return `server_inventory_provisioning_${serverId}`;
}

function defaultUserInventoryState() {
    return {
        ramMb: 0,
        cpuPercent: 0,
        diskMb: 0,
        swapMb: 0,
        allocations: 0,
        images: 0,
        databases: 0,
        packages: 0,
        updatedAtMs: 0
    };
}

function normalizeUserInventoryState(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};
    const base = defaultUserInventoryState();
    const toInt = (value) => Math.max(0, Number.parseInt(value, 10) || 0);
    return {
        ramMb: toInt(parsed.ramMb ?? base.ramMb),
        cpuPercent: toInt(parsed.cpuPercent ?? base.cpuPercent),
        diskMb: toInt(parsed.diskMb ?? base.diskMb),
        swapMb: toInt(parsed.swapMb ?? base.swapMb),
        allocations: toInt(parsed.allocations ?? base.allocations),
        images: toInt(parsed.images ?? base.images),
        databases: toInt(parsed.databases ?? base.databases),
        packages: toInt(parsed.packages ?? base.packages),
        updatedAtMs: toInt(parsed.updatedAtMs ?? Date.now())
    };
}

async function getUserInventoryState(userId) {
    const setting = await Settings.findByPk(getUserInventorySettingKey(userId));
    if (!setting || !setting.value) return defaultUserInventoryState();
    return normalizeUserInventoryState(setting.value);
}

async function setUserInventoryState(userId, state) {
    const normalized = normalizeUserInventoryState(state);
    normalized.updatedAtMs = Date.now();
    await Settings.upsert({
        key: getUserInventorySettingKey(userId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

function normalizeServerInventoryProvisioningState(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};
    const toInt = (value) => Math.max(0, Number.parseInt(value, 10) || 0);
    const mode = String(parsed.mode || '').trim().toLowerCase() === 'inventory' ? 'inventory' : 'none';
    const resourcesRaw = parsed.resources && typeof parsed.resources === 'object' ? parsed.resources : {};
    return {
        mode,
        resources: {
            ramMb: toInt(resourcesRaw.ramMb),
            cpuPercent: toInt(resourcesRaw.cpuPercent),
            diskMb: toInt(resourcesRaw.diskMb),
            swapMb: toInt(resourcesRaw.swapMb),
            allocations: toInt(resourcesRaw.allocations),
            images: toInt(resourcesRaw.images),
            databases: toInt(resourcesRaw.databases),
            packages: toInt(resourcesRaw.packages)
        },
        createdAtMs: toInt(parsed.createdAtMs) || Date.now(),
        updatedAtMs: Date.now()
    };
}

async function getServerInventoryProvisioningState(serverId) {
    const setting = await Settings.findByPk(getServerInventoryProvisioningSettingKey(serverId));
    if (!setting || !setting.value) return null;
    return normalizeServerInventoryProvisioningState(setting.value);
}

async function setServerInventoryProvisioningState(serverId, state) {
    const normalized = normalizeServerInventoryProvisioningState(state);
    await Settings.upsert({
        key: getServerInventoryProvisioningSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function removeServerInventoryProvisioningState(serverId) {
    await Settings.destroy({
        where: {
            key: getServerInventoryProvisioningSettingKey(serverId)
        }
    });
}

function buildServerInventoryRefundResources(serverLike) {
    const toInt = (value) => Math.max(0, Number.parseInt(value, 10) || 0);
    const hasPackageToken = Boolean(serverLike && serverLike.image && serverLike.image.packageId);
    return {
        ramMb: toInt(serverLike && serverLike.memory),
        cpuPercent: toInt(serverLike && serverLike.cpu),
        diskMb: toInt(serverLike && serverLike.disk),
        swapMb: toInt(serverLike && serverLike.swapLimit),
        allocations: (serverLike && serverLike.allocationId) ? 1 : 0,
        images: (serverLike && serverLike.imageId) ? 1 : 0,
        databases: Math.max(0, Number.parseInt(serverLike && serverLike.databaseLimit, 10) || 0),
        packages: hasPackageToken ? 1 : 0
    };
}

function buildScalingInventoryDelta(currentLimits, targetLimits) {
    const current = currentLimits && typeof currentLimits === 'object' ? currentLimits : {};
    const next = targetLimits && typeof targetLimits === 'object' ? targetLimits : {};
    const toInt = (value) => Math.max(0, Number.parseInt(value, 10) || 0);

    return {
        ramMb: toInt(next.memory) - toInt(current.memory),
        cpuPercent: toInt(next.cpu) - toInt(current.cpu),
        diskMb: toInt(next.disk) - toInt(current.disk),
        swapMb: toInt(next.swapLimit) - toInt(current.swapLimit)
    };
}

function getScalingInventoryMissingList(delta, inventoryState) {
    const deltaSafe = delta && typeof delta === 'object' ? delta : {};
    const inventory = normalizeUserInventoryState(inventoryState);
    const missing = [];

    if ((Number.parseInt(deltaSafe.ramMb, 10) || 0) > inventory.ramMb) {
        missing.push(`RAM ${deltaSafe.ramMb}MB (available ${inventory.ramMb}MB)`);
    }
    if ((Number.parseInt(deltaSafe.cpuPercent, 10) || 0) > inventory.cpuPercent) {
        missing.push(`CPU ${deltaSafe.cpuPercent}% (available ${inventory.cpuPercent}%)`);
    }
    if ((Number.parseInt(deltaSafe.diskMb, 10) || 0) > inventory.diskMb) {
        missing.push(`Disk ${deltaSafe.diskMb}MB (available ${inventory.diskMb}MB)`);
    }
    if ((Number.parseInt(deltaSafe.swapMb, 10) || 0) > inventory.swapMb) {
        missing.push(`Swap ${deltaSafe.swapMb}MB (available ${inventory.swapMb}MB)`);
    }

    return missing;
}

function getInventoryUnitCostAndDelta(resourceType, quantity, featureFlags) {
    const qty = Math.max(1, Math.min(10000, Number.parseInt(quantity, 10) || 1));
    const t = String(resourceType || '').trim().toLowerCase();
    const delta = {
        ramMb: 0,
        cpuPercent: 0,
        diskMb: 0,
        swapMb: 0,
        allocations: 0,
        images: 0,
        databases: 0,
        packages: 0
    };

    let unitCost = 0;
    switch (t) {
        case 'ram_gb':
            unitCost = Number(featureFlags.storeRamPerGbCoins || 0);
            delta.ramMb = qty * 1024;
            break;
        case 'cpu_core':
            unitCost = Number(featureFlags.storeCpuPerCoreCoins || 0);
            delta.cpuPercent = qty * 100;
            break;
        case 'disk_gb':
            unitCost = Number(featureFlags.storeDiskPerGbCoins || 0);
            delta.diskMb = qty * 1024;
            break;
        case 'swap_gb':
            unitCost = Number(featureFlags.storeSwapPerGbCoins || 0);
            delta.swapMb = qty * 1024;
            break;
        case 'allocation':
            unitCost = Number(featureFlags.storeAllocationCoins || 0);
            delta.allocations = qty;
            break;
        case 'image':
            unitCost = Number(featureFlags.storeImageCoins || 0);
            delta.images = qty;
            break;
        case 'database':
            unitCost = Number(featureFlags.storeDatabaseCoins || 0);
            delta.databases = qty;
            break;
        case 'package':
            unitCost = Number(featureFlags.storePackageCoins || 0);
            delta.packages = qty;
            break;
        default:
            return { ok: false, error: 'Unknown inventory resource type.' };
    }

    const totalCost = Math.max(0, Math.ceil(unitCost * qty));
    return {
        ok: true,
        resourceType: t,
        quantity: qty,
        unitCost,
        totalCost,
        delta
    };
}

function calculateInventoryResourceCoinValue(resources, featureFlags) {
    const toInt = (value) => Math.max(0, Number.parseInt(value, 10) || 0);
    const normalized = resources && typeof resources === 'object' ? resources : {};
    const ramGb = toInt(normalized.ramMb) / 1024;
    const cpuCores = toInt(normalized.cpuPercent) / 100;
    const diskGb = toInt(normalized.diskMb) / 1024;
    const swapGb = toInt(normalized.swapMb) / 1024;
    return Math.max(0, Math.ceil(
        (ramGb * Number(featureFlags.storeRamPerGbCoins || 0)) +
        (cpuCores * Number(featureFlags.storeCpuPerCoreCoins || 0)) +
        (diskGb * Number(featureFlags.storeDiskPerGbCoins || 0)) +
        (swapGb * Number(featureFlags.storeSwapPerGbCoins || 0)) +
        (toInt(normalized.allocations) * Number(featureFlags.storeAllocationCoins || 0)) +
        (toInt(normalized.images) * Number(featureFlags.storeImageCoins || 0)) +
        (toInt(normalized.databases) * Number(featureFlags.storeDatabaseCoins || 0)) +
        (toInt(normalized.packages) * Number(featureFlags.storePackageCoins || 0))
    ));
}

function getStoreBillingRemainingSeconds(state, nowMs = Date.now()) {
    if (!state || typeof state !== 'object') return 0;
    if (state.status === 'suspended_due') {
        const deleteAfterMs = Number.parseInt(state.deleteAfterMs, 10) || 0;
        if (deleteAfterMs <= 0) return 0;
        return Math.max(0, Math.ceil((deleteAfterMs - nowMs) / 1000));
    }
    const nextRenewAtMs = Number.parseInt(state.nextRenewAtMs, 10) || 0;
    if (nextRenewAtMs <= 0) return 0;
    return Math.max(0, Math.ceil((nextRenewAtMs - nowMs) / 1000));
}

async function getStoreDealsCatalogSafe() {
    const setting = await Settings.findByPk(STORE_DEALS_SETTING_KEY);
    if (!setting || !setting.value) return [];
    return normalizeStoreDealsCatalog(setting.value);
}

async function setStoreDealsCatalogSafe(catalog) {
    const normalized = normalizeStoreDealsCatalog(catalog);
    await Settings.upsert({
        key: STORE_DEALS_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function getStoreRedeemCodesCatalogSafe() {
    const setting = await Settings.findByPk(STORE_REDEEM_CODES_SETTING_KEY);
    if (!setting || !setting.value) return [];
    return normalizeStoreRedeemCodesCatalog(setting.value);
}

async function setStoreRedeemCodesCatalogSafe(catalog) {
    const normalized = normalizeStoreRedeemCodesCatalog(catalog);
    await Settings.upsert({
        key: STORE_REDEEM_CODES_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function getRevenuePlanCatalogSafe() {
    const setting = await Settings.findByPk(REVENUE_PLAN_CATALOG_SETTING_KEY);
    if (!setting || !setting.value) return [];
    return normalizeRevenuePlanCatalog(setting.value);
}

async function getUserRevenueProfileSafe(userId) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return null;
    const setting = await Settings.findByPk(getUserRevenueProfileSettingKey(parsedUserId));
    if (!setting || !setting.value) return null;
    return normalizeUserRevenueProfile(setting.value);
}

async function setUserRevenueProfileSafe(userId, profile) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return null;
    const normalized = normalizeUserRevenueProfile(profile || {}, Date.now());
    await Settings.upsert({
        key: getUserRevenueProfileSettingKey(parsedUserId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function getServerScheduledScalingConfigSafe(serverId) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) {
        return normalizeServerScheduledScalingConfig({});
    }
    const setting = await Settings.findByPk(getServerScheduledScalingSettingKey(parsedServerId));
    if (!setting || !setting.value) return normalizeServerScheduledScalingConfig({});
    return normalizeServerScheduledScalingConfig(setting.value);
}

async function setServerScheduledScalingConfigSafe(serverId, config) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) {
        return normalizeServerScheduledScalingConfig({});
    }
    const normalized = normalizeServerScheduledScalingConfig(config || {});
    await Settings.upsert({
        key: getServerScheduledScalingSettingKey(parsedServerId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

function resolveRevenuePlanById(catalog, planId) {
    const id = String(planId || '').trim();
    if (!id) return null;
    return (Array.isArray(catalog) ? catalog : []).find((entry) => String(entry.id || '') === id) || null;
}

function validateRevenuePlanConstraints(plan, serverCount, aggregateLimits, requestedLimits) {
    const activePlan = plan && typeof plan === 'object' ? plan : null;
    if (!activePlan) {
        return { ok: false, error: 'Revenue plan is missing.' };
    }
    if (activePlan.maxServers > 0 && serverCount >= activePlan.maxServers) {
        return { ok: false, error: `Plan limit reached: max ${activePlan.maxServers} server(s).` };
    }

    const nextMemory = Number(aggregateLimits.memory || 0) + Number(requestedLimits.memory || 0);
    const nextCpu = Number(aggregateLimits.cpu || 0) + Number(requestedLimits.cpu || 0);
    const nextDisk = Number(aggregateLimits.disk || 0) + Number(requestedLimits.disk || 0);

    if (activePlan.maxMemoryMb > 0 && nextMemory > activePlan.maxMemoryMb) {
        return { ok: false, error: `Plan RAM limit exceeded (${activePlan.maxMemoryMb} MB max).` };
    }
    if (activePlan.maxCpuPercent > 0 && nextCpu > activePlan.maxCpuPercent) {
        return { ok: false, error: `Plan CPU limit exceeded (${activePlan.maxCpuPercent}% max).` };
    }
    if (activePlan.maxDiskMb > 0 && nextDisk > activePlan.maxDiskMb) {
        return { ok: false, error: `Plan Disk limit exceeded (${activePlan.maxDiskMb} MB max).` };
    }

    return { ok: true };
}

function isRevenueProfileProvisioningAllowed(profile) {
    const status = String(profile && profile.status || '').trim().toLowerCase();
    return status === 'active' || status === 'trial';
}

async function getUserServerAggregateUsage(userId) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) {
        return {
            serverCount: 0,
            memory: 0,
            cpu: 0,
            disk: 0
        };
    }

    const servers = await Server.findAll({
        where: { ownerId: parsedUserId },
        attributes: ['id', 'memory', 'cpu', 'disk']
    });

    return servers.reduce((acc, entry) => {
        acc.serverCount += 1;
        acc.memory += Math.max(0, Number.parseInt(entry.memory, 10) || 0);
        acc.cpu += Math.max(0, Number.parseInt(entry.cpu, 10) || 0);
        acc.disk += Math.max(0, Number.parseInt(entry.disk, 10) || 0);
        return acc;
    }, {
        serverCount: 0,
        memory: 0,
        cpu: 0,
        disk: 0
    });
}

function resolveSafeTimezone(input, fallback = 'UTC') {
    const candidate = String(input || '').trim();
    if (!candidate) return fallback;
    try {
        Intl.DateTimeFormat('en-US', { timeZone: candidate }).format(new Date());
        return candidate;
    } catch {
        return fallback;
    }
}

function buildAfkRewardsMap(featureFlags) {
    return {
        minute: clampInteger(featureFlags.afkRewardMinuteCoins, 2, 0, 1000000),
        hour: clampInteger(featureFlags.afkRewardHourCoins, 20, 0, 1000000),
        day: clampInteger(featureFlags.afkRewardDayCoins, 120, 0, 1000000),
        week: clampInteger(featureFlags.afkRewardWeekCoins, 700, 0, 1000000),
        month: clampInteger(featureFlags.afkRewardMonthCoins, 3000, 0, 1000000),
        year: clampInteger(featureFlags.afkRewardYearCoins, 36000, 0, 1000000)
    };
}

function getUserAfkStateSettingKey(userId) {
    return `user_afk_state_${userId}`;
}

function parseAfkStateTimestamp(value) {
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) return value;
    if (typeof value === 'string' && value.trim()) {
        const asNum = Number.parseInt(value, 10);
        if (Number.isFinite(asNum) && asNum > 0) return asNum;
        const asDate = new Date(value).getTime();
        if (Number.isFinite(asDate) && asDate > 0) return asDate;
    }
    return 0;
}

function normalizeUserAfkState(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    let lastTimerRewardAt = parseAfkStateTimestamp(parsed.lastTimerRewardAt);
    if (lastTimerRewardAt <= 0 && parsed.lastRewardAtByPeriod && typeof parsed.lastRewardAtByPeriod === 'object') {
        const legacySelected = normalizeAfkPeriod(parsed.selectedPeriod, 'minute');
        lastTimerRewardAt = parseAfkStateTimestamp(parsed.lastRewardAtByPeriod[legacySelected]);
    }

    const normalized = {
        lastTimerRewardAt,
        lastSeenAt: parseAfkStateTimestamp(parsed.lastSeenAt)
    };

    return normalized;
}

async function getUserAfkState(userId) {
    const setting = await Settings.findByPk(getUserAfkStateSettingKey(userId));
    if (!setting || !setting.value) return normalizeUserAfkState({});
    return normalizeUserAfkState(setting.value);
}

async function setUserAfkState(userId, state) {
    await Settings.upsert({
        key: getUserAfkStateSettingKey(userId),
        value: JSON.stringify(normalizeUserAfkState(state))
    });
}

function getAfkRemainingSeconds(state, period, nowMs) {
    const periodKey = normalizeAfkPeriod(period, 'minute');
    const periodSeconds = AFK_PERIOD_SECONDS[periodKey];
    const lastRewardAt = parseAfkStateTimestamp(state.lastRewardAtByPeriod[periodKey]);
    if (lastRewardAt <= 0) return 0;
    const nextAt = lastRewardAt + (periodSeconds * 1000);
    return Math.max(0, Math.ceil((nextAt - nowMs) / 1000));
}

function pickFirstRewardablePeriod(rewardsMap, fallback = 'minute') {
    const entries = Object.entries(rewardsMap || {});
    const found = entries.find(([, reward]) => Number(reward) > 0);
    if (!found) return fallback;
    return normalizeAfkPeriod(found[0], fallback);
}

function getUserClaimStateSettingKey(userId) {
    return `user_claim_reward_state_${userId}`;
}

function normalizeUserClaimState(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const normalized = {
        selectedPeriod: normalizeAfkPeriod(parsed.selectedPeriod, 'day'),
        dailyStreak: Math.max(0, clampInteger(parsed.dailyStreak, 0, 0, 365)),
        lastDailyClaimAt: parseAfkStateTimestamp(parsed.lastDailyClaimAt),
        lastActivityAt: parseAfkStateTimestamp(parsed.lastActivityAt),
        lastClaimAtByPeriod: {}
    };

    Object.keys(AFK_PERIOD_SECONDS).forEach((period) => {
        const direct = parsed.lastClaimAtByPeriod ? parsed.lastClaimAtByPeriod[period] : 0;
        const legacy = parsed.lastRewardAtByPeriod ? parsed.lastRewardAtByPeriod[period] : 0;
        normalized.lastClaimAtByPeriod[period] = parseAfkStateTimestamp(direct || legacy);
    });

    return normalized;
}

async function getUserClaimState(userId) {
    const setting = await Settings.findByPk(getUserClaimStateSettingKey(userId));
    if (!setting || !setting.value) return normalizeUserClaimState({});
    return normalizeUserClaimState(setting.value);
}

async function setUserClaimState(userId, state) {
    await Settings.upsert({
        key: getUserClaimStateSettingKey(userId),
        value: JSON.stringify(normalizeUserClaimState(state))
    });
}

function getCountdownFromTimestamp(lastTimestampMs, cooldownSeconds, nowMs) {
    const last = parseAfkStateTimestamp(lastTimestampMs);
    if (last <= 0) return 0;
    const nextAt = last + (cooldownSeconds * 1000);
    return Math.max(0, Math.ceil((nextAt - nowMs) / 1000));
}

function getClaimActivityTimestamp(claimState) {
    return parseAfkStateTimestamp(
        (claimState && claimState.lastActivityAt) || (claimState && claimState.lastDailyClaimAt)
    );
}

function getStreakResetRemainingSeconds(claimState, nowMs) {
    const dailyStreak = Math.max(0, Number(claimState && claimState.dailyStreak) || 0);
    if (dailyStreak <= 0) return 0;
    const lastActivityAt = getClaimActivityTimestamp(claimState);
    if (lastActivityAt <= 0) return 0;
    return Math.max(0, Math.ceil((lastActivityAt + (STREAK_RESET_INACTIVITY_SECONDS * 1000) - nowMs) / 1000));
}

function resetClaimStreakForInactivity(claimState) {
    if (!claimState || typeof claimState !== 'object') return;
    claimState.dailyStreak = 0;
    claimState.lastDailyClaimAt = 0;
}

function applyClaimStreakInactivityReset(claimState, nowMs) {
    const lastActivityAt = getClaimActivityTimestamp(claimState);
    if (lastActivityAt <= 0) return false;
    if ((nowMs - lastActivityAt) < (STREAK_RESET_INACTIVITY_SECONDS * 1000)) return false;
    resetClaimStreakForInactivity(claimState);
    return true;
}

app.get('/afk', requireAuth, async (req, res) => {
    try {
        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'username', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        const afkTimerEnabled = Boolean(featureFlags.afkRewardsEnabled);
        const afkTimerCoins = clampInteger(featureFlags.afkTimerCoins, 2, 0, 1000000);
        const afkTimerCooldownSeconds = clampInteger(featureFlags.afkTimerCooldownSeconds, 60, 5, 86400);
        const afkState = await getUserAfkState(account.id);
        const economyUnit = normalizeEconomyUnit(featureFlags.economyUnit);

        const nowMs = Date.now();
        const timerLastRewardAt = parseAfkStateTimestamp(afkState.lastTimerRewardAt);
        let afkRemainingSeconds = getCountdownFromTimestamp(timerLastRewardAt, afkTimerCooldownSeconds, nowMs);
        if (timerLastRewardAt <= 0 && afkTimerEnabled) {
            afkRemainingSeconds = afkTimerCooldownSeconds;
        }

        req.session.user.coins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;

        return res.render('afk', {
            user: req.session.user,
            title: 'AFK Timer',
            path: '/afk',
            afkTimerEnabled,
            afkTimerCoins,
            afkTimerCooldownSeconds,
            afkRemainingSeconds,
            economyUnit,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading AFK page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load AFK page.'));
    }
});

app.post('/afk/ping', requireAuth, async (req, res) => {
    try {
        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            return res.status(401).json({ success: false, error: 'Session expired.' });
        }
        if (account.isSuspended) {
            return res.status(403).json({ success: false, error: 'Account suspended.' });
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        const afkTimerEnabled = Boolean(featureFlags.afkRewardsEnabled);
        const afkTimerCoins = clampInteger(featureFlags.afkTimerCoins, 2, 0, 1000000);
        const afkTimerCooldownSeconds = clampInteger(featureFlags.afkTimerCooldownSeconds, 60, 5, 86400);
        const economyUnit = normalizeEconomyUnit(featureFlags.economyUnit);

        if (!afkTimerEnabled) {
            return res.status(403).json({ success: false, error: 'AFK timer is disabled by admin.' });
        }

        const afkState = await getUserAfkState(account.id);
        const nowMs = Date.now();
        const lastTimerRewardAt = parseAfkStateTimestamp(afkState.lastTimerRewardAt);
        let remainingSeconds = getCountdownFromTimestamp(lastTimerRewardAt, afkTimerCooldownSeconds, nowMs);
        let awardedCoins = 0;
        let newCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;

        if (lastTimerRewardAt <= 0) {
            afkState.lastTimerRewardAt = nowMs;
            remainingSeconds = afkTimerCooldownSeconds;
        } else if (afkTimerCoins > 0 && remainingSeconds <= 0) {
            awardedCoins = afkTimerCoins;
            newCoins += awardedCoins;
            await account.update({
                coins: newCoins,
                lastAfkClaimAt: new Date(nowMs)
            });
            afkState.lastTimerRewardAt = nowMs;
            remainingSeconds = afkTimerCooldownSeconds;
        }

        afkState.lastSeenAt = nowMs;
        await setUserAfkState(account.id, afkState);

        req.session.user.coins = newCoins;
        if (awardedCoins > 0) {
            await new Promise((resolve) => req.session.save(resolve));
        }

        return res.json({
            success: true,
            awarded: awardedCoins > 0,
            awardedCoins,
            coins: newCoins,
            rewardCoins: afkTimerCoins,
            economyUnit,
            remainingSeconds,
            nextClaimAt: new Date(nowMs + (remainingSeconds * 1000)).toISOString()
        });
    } catch (error) {
        console.error('Error processing AFK ping:', error);
        return res.status(500).json({ success: false, error: 'Failed to process AFK ping.' });
    }
});

app.get('/rewards', requireAuth, async (req, res) => {
    try {
        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'username', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        const claimRewardsEnabled = Boolean(featureFlags.claimRewardsEnabled);
        const rewardsMap = buildAfkRewardsMap(featureFlags);
        const defaultPeriod = normalizeAfkPeriod(featureFlags.afkRewardActivePeriod, 'day');
        const claimState = await getUserClaimState(account.id);
        const nowMs = Date.now();

        const resetByInactivity = applyClaimStreakInactivityReset(claimState, nowMs);
        claimState.lastActivityAt = nowMs;
        if (resetByInactivity) {
            await setUserClaimState(account.id, claimState);
        } else {
            // Persist activity timestamp for 24h inactivity streak reset tracking.
            await setUserClaimState(account.id, claimState);
        }

        let selectedClaimPeriod = normalizeAfkPeriod(claimState.selectedPeriod, defaultPeriod);
        if ((rewardsMap[selectedClaimPeriod] || 0) <= 0) {
            selectedClaimPeriod = pickFirstRewardablePeriod(rewardsMap, defaultPeriod);
        }

        const claimRemainingByPeriod = {};
        Object.keys(AFK_PERIOD_SECONDS).forEach((period) => {
            claimRemainingByPeriod[period] = getCountdownFromTimestamp(claimState.lastClaimAtByPeriod[period], AFK_PERIOD_SECONDS[period], nowMs);
        });

        req.session.user.coins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;

        return res.render('rewards', {
            user: req.session.user,
            title: 'Rewards',
            path: '/rewards',
            claimRewardsEnabled,
            rewardsMap,
            selectedClaimPeriod,
            claimRemainingByPeriod,
            dailyStreak: claimState.dailyStreak || 0,
            claimDailyStreakBonusCoins: clampInteger(featureFlags.claimDailyStreakBonusCoins, 5, 0, 1000000),
            claimDailyStreakMax: clampInteger(featureFlags.claimDailyStreakMax, 30, 1, 365),
            streakResetSeconds: getStreakResetRemainingSeconds(claimState, nowMs),
            economyUnit: normalizeEconomyUnit(featureFlags.economyUnit),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading rewards page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load rewards page.'));
    }
});

const claimRewardsHandler = async (req, res) => {
    try {
        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            return res.status(401).json({ success: false, error: 'Session expired.' });
        }
        if (account.isSuspended) {
            return res.status(403).json({ success: false, error: 'Account suspended.' });
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!Boolean(featureFlags.claimRewardsEnabled)) {
            return res.status(403).json({ success: false, error: 'Claim rewards are disabled by admin.' });
        }

        const rewardsMap = buildAfkRewardsMap(featureFlags);
        const defaultPeriod = normalizeAfkPeriod(featureFlags.afkRewardActivePeriod, 'day');
        const requestedPeriod = normalizeAfkPeriod(req.body ? req.body.period : '', defaultPeriod);
        const rewardCoins = clampInteger(rewardsMap[requestedPeriod], 0, 0, 1000000);
        const periodSeconds = AFK_PERIOD_SECONDS[requestedPeriod] || 60;

        if (rewardCoins <= 0) {
            return res.status(400).json({ success: false, error: 'Reward for selected period is disabled.' });
        }

        const claimState = await getUserClaimState(account.id);
        const nowMs = Date.now();
        const resetByInactivity = applyClaimStreakInactivityReset(claimState, nowMs);

        const remainingSeconds = getCountdownFromTimestamp(
            claimState.lastClaimAtByPeriod[requestedPeriod],
            periodSeconds,
            nowMs
        );
        if (remainingSeconds > 0) {
            claimState.lastActivityAt = nowMs;
            await setUserClaimState(account.id, claimState);
            return res.status(429).json({
                success: false,
                error: `Reward cooldown active (${remainingSeconds}s).`,
                remainingSeconds,
                dailyStreak: claimState.dailyStreak || 0,
                resetByInactivity
            });
        }

        let awardedCoins = rewardCoins;
        let streakBonusCoins = 0;
        let dailyStreak = claimState.dailyStreak || 0;

        if (requestedPeriod === 'day') {
            const dailySeconds = AFK_PERIOD_SECONDS.day;
            const maxStreak = clampInteger(featureFlags.claimDailyStreakMax, 30, 1, 365);
            const streakBonusPerDay = clampInteger(featureFlags.claimDailyStreakBonusCoins, 5, 0, 1000000);
            const lastDailyClaimAt = parseAfkStateTimestamp(claimState.lastDailyClaimAt);

            if (lastDailyClaimAt > 0) {
                const elapsedSeconds = Math.floor((nowMs - lastDailyClaimAt) / 1000);
                if (elapsedSeconds >= dailySeconds && elapsedSeconds < (dailySeconds * 2)) {
                    dailyStreak += 1;
                } else if (elapsedSeconds >= (dailySeconds * 2)) {
                    dailyStreak = 1;
                } else {
                    dailyStreak = Math.max(1, dailyStreak);
                }
            } else {
                dailyStreak = 1;
            }

            dailyStreak = Math.max(1, Math.min(maxStreak, dailyStreak));
            streakBonusCoins = Math.max(0, dailyStreak - 1) * streakBonusPerDay;
            awardedCoins += streakBonusCoins;
            claimState.dailyStreak = dailyStreak;
            claimState.lastDailyClaimAt = nowMs;
        }

        claimState.selectedPeriod = requestedPeriod;
        claimState.lastClaimAtByPeriod[requestedPeriod] = nowMs;
        claimState.lastActivityAt = nowMs;
        await setUserClaimState(account.id, claimState);

        const currentCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        const newCoins = currentCoins + awardedCoins;
        await account.update({
            coins: newCoins,
            lastAfkClaimAt: new Date(nowMs)
        });

        req.session.user.coins = newCoins;
        await new Promise((resolve) => req.session.save(resolve));

        return res.json({
            success: true,
            period: requestedPeriod,
            baseRewardCoins: rewardCoins,
            streakBonusCoins,
            awardedCoins,
            coins: newCoins,
            dailyStreak: claimState.dailyStreak || 0,
            streakResetSeconds: STREAK_RESET_INACTIVITY_SECONDS,
            remainingSeconds: periodSeconds,
            nextClaimAt: new Date(nowMs + (periodSeconds * 1000)).toISOString(),
            economyUnit: normalizeEconomyUnit(featureFlags.economyUnit)
        });
    } catch (error) {
        console.error('Error claiming timed reward:', error);
        return res.status(500).json({ success: false, error: 'Failed to claim reward.' });
    }
};

app.post('/rewards/claim', requireAuth, claimRewardsHandler);
app.post('/afk/rewards/claim', requireAuth, claimRewardsHandler);

app.get('/store', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'username', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const [servers, inventoryState, dealsCatalog, revenuePlanCatalog, revenueProfileRaw, quotaBurnLogs] = await Promise.all([
            Server.findAll({
            where: { ownerId: account.id },
            include: [
                { model: Image, as: 'image', include: [{ model: Package, as: 'package', required: false }] },
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] }
            ],
            order: [['id', 'DESC']]
            }),
            getUserInventoryState(account.id),
            featureFlags.storeDealsEnabled ? getStoreDealsCatalogSafe() : Promise.resolve([]),
            featureFlags.revenueModeEnabled ? getRevenuePlanCatalogSafe() : Promise.resolve([]),
            featureFlags.revenueModeEnabled ? getUserRevenueProfileSafe(account.id) : Promise.resolve(null),
            featureFlags.quotaForecastingEnabled && AuditLog
                ? AuditLog.findAll({
                    where: {
                        action: { [Op.in]: Array.from(QUOTA_FORECAST_SPEND_ACTIONS) },
                        createdAt: { [Op.gte]: new Date(Date.now() - (QUOTA_FORECAST_V2_LOOKBACK_DAYS * DAY_MS)) }
                    },
                    attributes: ['actorUserId', 'action', 'createdAt', 'metadata'],
                    order: [['createdAt', 'DESC']],
                    limit: 2000
                })
                : Promise.resolve([])
        ]);

        const nowMs = Date.now();
        const storeRows = [];
        const serverIdStrings = [];
        const aggregateUsage = {
            serverCount: 0,
            memory: 0,
            cpu: 0,
            disk: 0
        };
        let recurringDailyBurn = 0;
        for (const server of servers) {
            serverIdStrings.push(String(server.id));
            const billingState = await getStoreBillingStateSafe(server.id);
            const revenueManagedState = await getServerRevenueManagedState(server.id);
            const recurringCoins = featureFlags.costPerServerEnabled
                ? calculateStoreRenewCostSafe(server, res.locals.settings || {})
                : 0;
            const billing = billingState ? {
                ...billingState,
                remainingSeconds: getStoreBillingRemainingSeconds(billingState, nowMs)
            } : null;
            storeRows.push({
                server,
                recurringCoins,
                billing,
                revenueManaged: Boolean(revenueManagedState && revenueManagedState.managed),
                revenueManagedMeta: revenueManagedState || null
            });
            aggregateUsage.serverCount += 1;
            aggregateUsage.memory += Math.max(0, Number.parseInt(server.memory, 10) || 0);
            aggregateUsage.cpu += Math.max(0, Number.parseInt(server.cpu, 10) || 0);
            aggregateUsage.disk += Math.max(0, Number.parseInt(server.disk, 10) || 0);
            if (featureFlags.costPerServerEnabled) {
                const renewPeriodDays = Math.max(1, Number.parseInt((billing && billing.renewDays) || featureFlags.storeRenewDays, 10) || 30);
                recurringDailyBurn += Number(recurringCoins || 0) / renewPeriodDays;
            }
        }

        let billingLogs = [];
        if (AuditLog) {
            const whereOr = [
                { actorUserId: account.id }
            ];
            if (serverIdStrings.length > 0) {
                whereOr.push({
                    targetType: 'server',
                    targetId: { [Op.in]: serverIdStrings }
                });
            }
            const rawLogs = await AuditLog.findAll({
                where: {
                    action: { [Op.like]: 'billing.%' },
                    [Op.or]: whereOr
                },
                include: [{ model: User, as: 'actor', attributes: ['id', 'username', 'email'], required: false }],
                order: [['createdAt', 'DESC']],
                limit: 120
            });
            billingLogs = rawLogs.map((entry) => {
                const meta = entry && entry.metadata && typeof entry.metadata === 'object' ? entry.metadata : {};
                return {
                    id: entry.id,
                    createdAt: entry.createdAt,
                    action: entry.action,
                    actionLabel: formatBillingActionLabel(entry.action),
                    actor: entry.actor || null,
                    targetType: entry.targetType || null,
                    targetId: entry.targetId || null,
                    metadata: meta,
                    amount: Number.isFinite(Number(meta.amount)) ? Number(meta.amount) : null,
                    currency: String(meta.currency || featureFlags.economyUnit || 'Coins')
                };
            });
        }

        req.session.user.coins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        const storeDealsCount = dealsCatalog.length;
        const storeDealsActiveCount = dealsCatalog.filter((deal) => getStoreDealStatus(deal) === 'active').length;
        const walletCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        const revenueProfile = normalizeUserRevenueProfile(revenueProfileRaw || {});
        const activeRevenuePlan = resolveRevenuePlanById(revenuePlanCatalog, revenueProfile.planId);
        const revenuePlans = Array.isArray(revenuePlanCatalog) ? revenuePlanCatalog : [];
        const runtimeRevenueManaged = Boolean(featureFlags.revenueModeEnabled) && Boolean(activeRevenuePlan) && isRevenueProfileProvisioningAllowed(revenueProfile);
        const storeRowsFinal = storeRows.map((row) => ({
            ...row,
            revenueManaged: Boolean((row && row.revenueManaged) || runtimeRevenueManaged)
        }));
        const revenuePlanPrice = activeRevenuePlan
            ? Math.max(0, Number.parseInt(activeRevenuePlan.priceCoins, 10) || 0)
            : Math.max(0, Number.parseInt(revenueProfile.priceCoins, 10) || 0);
        const revenuePlanPeriodDays = activeRevenuePlan
            ? Math.max(1, Number.parseInt(activeRevenuePlan.periodDays, 10) || 30)
            : Math.max(1, Number.parseInt(revenueProfile.periodDays, 10) || 30);
        const revenueDailyBurn = isRevenueProfileProvisioningAllowed(revenueProfile) || revenueProfile.status === 'past_due'
            ? (revenuePlanPrice / revenuePlanPeriodDays)
            : 0;
        const quotaForecastingEnabled = Boolean(featureFlags.quotaForecastingEnabled);
        const quotaForecast = buildQuotaForecastV2({
            enabled: quotaForecastingEnabled,
            walletCoins,
            recurringDailyBurn,
            revenueDailyBurn,
            burnLogs: quotaBurnLogs,
            ownerUserId: account.id
        });
        return res.render('store', {
            user: req.session.user,
            title: 'Store',
            path: '/store',
            economyUnit: normalizeEconomyUnit(featureFlags.economyUnit),
            featureCostPerServerEnabled: Boolean(featureFlags.costPerServerEnabled),
            featureInventoryEnabled: Boolean(featureFlags.inventoryEnabled),
            featureStoreDealsEnabled: Boolean(featureFlags.storeDealsEnabled),
            featureStoreRedeemCodesEnabled: Boolean(featureFlags.storeRedeemCodesEnabled),
            inventoryState,
            inventoryUnitCosts: {
                ramGb: Number(featureFlags.storeRamPerGbCoins || 0),
                cpuCore: Number(featureFlags.storeCpuPerCoreCoins || 0),
                diskGb: Number(featureFlags.storeDiskPerGbCoins || 0),
                swapGb: Number(featureFlags.storeSwapPerGbCoins || 0),
                allocation: Number(featureFlags.storeAllocationCoins || 0),
                image: Number(featureFlags.storeImageCoins || 0),
                database: Number(featureFlags.storeDatabaseCoins || 0),
                package: Number(featureFlags.storePackageCoins || 0)
            },
            storeRows: storeRowsFinal,
            storeDealsCount,
            storeDealsActiveCount,
            billingLogs,
            featureQuotaForecastingEnabled: quotaForecastingEnabled,
            quotaForecast,
            featureRevenueModeEnabled: Boolean(featureFlags.revenueModeEnabled),
            revenueProfile,
            revenuePlans,
            activeRevenuePlan,
            aggregateUsage,
            revenueCanStartTrial: Boolean(featureFlags.revenueModeEnabled)
                && revenuePlans.some((plan) => plan.enabled)
                && !String(revenueProfile.planId || '').trim(),
            revenueCanSubscribe: Boolean(featureFlags.revenueModeEnabled) && revenuePlans.some((plan) => plan.enabled),
            renewDays: Number.parseInt(featureFlags.storeRenewDays, 10) || 30,
            deleteGraceDays: Number.parseInt(featureFlags.storeDeleteGraceDays, 10) || 7,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading store:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load store page.'));
    }
});

app.post('/store/revenue/start-trial', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled || !featureFlags.revenueModeEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Revenue mode is disabled.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const planId = String(req.body.planId || '').trim();
        const plans = await getRevenuePlanCatalogSafe();
        const plan = resolveRevenuePlanById(plans, planId);
        if (!plan || !plan.enabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Selected revenue plan is not available.'));
        }

        const existingProfile = await getUserRevenueProfileSafe(account.id);
        if (existingProfile && String(existingProfile.planId || '').trim()) {
            return res.redirect('/store?error=' + encodeURIComponent('Trial is not available because a revenue plan profile already exists.'));
        }

        const trialDays = Math.max(1, Number.parseInt(featureFlags.revenueDefaultTrialDays, 10) || 3);
        const nowMs = Date.now();
        await setUserRevenueProfileSafe(account.id, {
            status: 'trial',
            planId: plan.id,
            planNameSnapshot: plan.name,
            periodDays: Math.max(1, Number.parseInt(plan.periodDays, 10) || 30),
            priceCoins: Math.max(0, Number.parseInt(plan.priceCoins, 10) || 0),
            trial: true,
            createdAtMs: nowMs,
            updatedAtMs: nowMs,
            lastRenewAtMs: nowMs,
            nextRenewAtMs: nowMs + (trialDays * DAY_MS),
            graceEndsAtMs: 0
        });

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.revenue.trial_start',
            targetType: 'user',
            targetId: account.id,
            req,
            metadata: {
                planId: plan.id,
                planName: plan.name,
                trialDays
            }
        });

        return res.redirect('/store?success=' + encodeURIComponent(`Trial started for plan "${plan.name}" (${trialDays} day(s)).`));
    } catch (error) {
        console.error('Error starting revenue trial:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to start trial.'));
    }
});

app.post('/store/revenue/subscribe', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled || !featureFlags.revenueModeEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Revenue mode is disabled.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const planId = String(req.body.planId || '').trim();
        const plans = await getRevenuePlanCatalogSafe();
        const plan = resolveRevenuePlanById(plans, planId);
        if (!plan || !plan.enabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Selected revenue plan is not available.'));
        }

        const planPrice = Math.max(0, Number.parseInt(plan.priceCoins, 10) || 0);
        const planPeriodDays = Math.max(1, Number.parseInt(plan.periodDays, 10) || 30);
        const walletBefore = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        if (walletBefore < planPrice) {
            return res.redirect('/store?error=' + encodeURIComponent(`Insufficient ${normalizeEconomyUnit(featureFlags.economyUnit)} to subscribe. Need ${planPrice}, have ${walletBefore}.`));
        }

        const nowMs = Date.now();
        const walletAfter = walletBefore - planPrice;
        if (planPrice > 0) {
            await account.update({ coins: walletAfter });
            req.session.user.coins = walletAfter;
            await new Promise((resolve) => req.session.save(resolve));
        }

        await setUserRevenueProfileSafe(account.id, {
            status: 'active',
            planId: plan.id,
            planNameSnapshot: plan.name,
            periodDays: planPeriodDays,
            priceCoins: planPrice,
            trial: false,
            updatedAtMs: nowMs,
            lastRenewAtMs: nowMs,
            nextRenewAtMs: nowMs + (planPeriodDays * DAY_MS),
            graceEndsAtMs: 0
        });

        await Server.update({
            isSuspended: false,
            status: 'offline',
            suspendReason: null
        }, {
            where: {
                ownerId: account.id,
                isSuspended: true,
                suspendReason: { [Op.like]: `${REVENUE_SUSPEND_REASON_PREFIX}%` }
            }
        });

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.revenue.subscribe',
            targetType: 'user',
            targetId: account.id,
            req,
            metadata: {
                planId: plan.id,
                planName: plan.name,
                amount: planPrice,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                walletBefore,
                walletAfter
            }
        });

        return res.redirect('/store?success=' + encodeURIComponent(`Subscribed to "${plan.name}". Next renewal in ${planPeriodDays} day(s).`));
    } catch (error) {
        console.error('Error subscribing to revenue plan:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to subscribe to revenue plan.'));
    }
});

app.get('/store/deals', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.storeDealsEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Deals are disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'username', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const inventoryEnabled = Boolean(featureFlags.inventoryEnabled);
        const dealsCatalog = await getStoreDealsCatalogSafe();
        const dealsView = dealsCatalog.map((deal) => {
            const status = getStoreDealStatus(deal);
            return {
                ...deal,
                status,
                remainingStock: getStoreDealRemainingStock(deal),
                canPurchase: status === 'active' && inventoryEnabled
            };
        });

        req.session.user.coins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        return res.render('store-deals', {
            user: req.session.user,
            title: 'Store Deals',
            path: '/store/deals',
            economyUnit: normalizeEconomyUnit(featureFlags.economyUnit),
            inventoryEnabled,
            storeDeals: dealsView,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading store deals:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to load store deals.'));
    }
});

app.get('/store/redeem', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.storeRedeemCodesEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Redeem codes are disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'username', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const catalog = await getStoreRedeemCodesCatalogSafe();
        const nowMs = Date.now();
        const visibleCodes = catalog
            .map((entry) => ({
                ...entry,
                status: getStoreRedeemCodeStatus(entry, nowMs),
                remainingUses: getStoreRedeemCodeRemainingUses(entry),
                userUses: entry.usageByUser && typeof entry.usageByUser === 'object'
                    ? (Number.parseInt(entry.usageByUser[String(account.id)] || 0, 10) || 0)
                    : 0
            }))
            .filter((entry) => entry.status === 'active' || entry.status === 'exhausted');

        req.session.user.coins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        return res.render('store-redeem', {
            user: req.session.user,
            title: 'Redeem Codes',
            path: '/store/redeem',
            economyUnit: normalizeEconomyUnit(featureFlags.economyUnit),
            inventoryEnabled: Boolean(featureFlags.inventoryEnabled),
            codes: visibleCodes,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading store redeem page:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to load redeem page.'));
    }
});

app.post('/store/redeem/claim', requireAuth, async (req, res) => {
    try {
        const redeemRedirectBase = '/store/redeem';
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.storeRedeemCodesEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Redeem codes are disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'username', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const codeInput = String(req.body.code || '').trim();
        const normalizedCode = normalizeRedeemCodeValue(codeInput);
        if (!normalizedCode) {
            return res.redirect(`${redeemRedirectBase}?error=${encodeURIComponent('Redeem code is required.')}`);
        }

        const catalog = await getStoreRedeemCodesCatalogSafe();
        const index = catalog.findIndex((entry) => String(entry.code || '').trim().toUpperCase() === normalizedCode);
        if (index === -1) {
            return res.redirect(`${redeemRedirectBase}?error=${encodeURIComponent('Redeem code not found.')}`);
        }

        const entry = catalog[index];
        const permission = canUserRedeemStoreCode(entry, account.id, Date.now());
        if (!permission.ok) {
            return res.redirect(`${redeemRedirectBase}?error=${encodeURIComponent(permission.error)}`);
        }

        const rewards = entry.rewards && typeof entry.rewards === 'object' ? entry.rewards : {};
        const rewardCoins = Math.max(0, Number.parseInt(rewards.coins, 10) || 0);
        const rewardResources = {
            ramMb: Math.max(0, Number.parseInt(rewards.ramMb, 10) || 0),
            cpuPercent: Math.max(0, Number.parseInt(rewards.cpuPercent, 10) || 0),
            diskMb: Math.max(0, Number.parseInt(rewards.diskMb, 10) || 0),
            swapMb: Math.max(0, Number.parseInt(rewards.swapMb, 10) || 0),
            allocations: Math.max(0, Number.parseInt(rewards.allocations, 10) || 0),
            images: Math.max(0, Number.parseInt(rewards.images, 10) || 0),
            databases: Math.max(0, Number.parseInt(rewards.databases, 10) || 0),
            packages: Math.max(0, Number.parseInt(rewards.packages, 10) || 0)
        };
        const rewardResourceTotal = rewardResources.ramMb
            + rewardResources.cpuPercent
            + rewardResources.diskMb
            + rewardResources.swapMb
            + rewardResources.allocations
            + rewardResources.images
            + rewardResources.databases
            + rewardResources.packages;

        if (rewardResourceTotal > 0 && !featureFlags.inventoryEnabled) {
            return res.redirect(`${redeemRedirectBase}?error=${encodeURIComponent('This code grants server resources but inventory mode is disabled.')}`);
        }

        let nextCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        const coinsBefore = nextCoins;
        if (rewardCoins > 0) {
            nextCoins += rewardCoins;
            await account.update({ coins: nextCoins });
            req.session.user.coins = nextCoins;
            await new Promise((resolve) => req.session.save(resolve));
        }

        let nextInventory = null;
        if (rewardResourceTotal > 0) {
            const inventory = await getUserInventoryState(account.id);
            nextInventory = normalizeUserInventoryState({
                ...inventory,
                ramMb: inventory.ramMb + rewardResources.ramMb,
                cpuPercent: inventory.cpuPercent + rewardResources.cpuPercent,
                diskMb: inventory.diskMb + rewardResources.diskMb,
                swapMb: inventory.swapMb + rewardResources.swapMb,
                allocations: inventory.allocations + rewardResources.allocations,
                images: inventory.images + rewardResources.images,
                databases: inventory.databases + rewardResources.databases,
                packages: inventory.packages + rewardResources.packages
            });
            await setUserInventoryState(account.id, nextInventory);
        }

        catalog[index] = applyStoreRedeemCodeUsage(entry, {
            userId: account.id,
            username: account.username,
            usedAtMs: Date.now()
        });
        await setStoreRedeemCodesCatalogSafe(catalog);

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.redeem_code.claim',
            targetType: 'user',
            targetId: account.id,
            req,
            metadata: {
                code: normalizedCode,
                amount: rewardCoins,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                walletBefore: coinsBefore,
                walletAfter: nextCoins,
                rewards: {
                    coins: rewardCoins,
                    ...rewardResources
                }
            }
        });

        const rewardParts = [];
        if (rewardCoins > 0) rewardParts.push(`${rewardCoins} ${normalizeEconomyUnit(featureFlags.economyUnit)}`);
        if (rewardResources.ramMb > 0) rewardParts.push(`${(rewardResources.ramMb / 1024).toFixed(2).replace(/\.00$/, '')} GB RAM`);
        if (rewardResources.cpuPercent > 0) rewardParts.push(`${(rewardResources.cpuPercent / 100).toFixed(2).replace(/\.00$/, '')} CPU`);
        if (rewardResources.diskMb > 0) rewardParts.push(`${(rewardResources.diskMb / 1024).toFixed(2).replace(/\.00$/, '')} GB Disk`);
        if (rewardResources.swapMb > 0) rewardParts.push(`${(rewardResources.swapMb / 1024).toFixed(2).replace(/\.00$/, '')} GB Swap`);
        if (rewardResources.allocations > 0) rewardParts.push(`${rewardResources.allocations} Allocation`);
        if (rewardResources.images > 0) rewardParts.push(`${rewardResources.images} Image`);
        if (rewardResources.packages > 0) rewardParts.push(`${rewardResources.packages} Package`);

        const summary = rewardParts.length ? rewardParts.join(' | ') : 'no rewards';
        return res.redirect(`${redeemRedirectBase}?success=${encodeURIComponent(`Code "${normalizedCode}" redeemed: ${summary}.`)}`);
    } catch (error) {
        console.error('Error redeeming code:', error);
        return res.redirect('/store/redeem?error=' + encodeURIComponent('Failed to redeem code.'));
    }
});

app.post('/store/deals/:dealId/purchase', requireAuth, async (req, res) => {
    try {
        const dealsRedirectBase = '/store/deals';
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.inventoryEnabled) {
            return res.redirect(`${dealsRedirectBase}?error=${encodeURIComponent('Inventory mode is disabled by admin.')}`);
        }
        if (!featureFlags.storeDealsEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Deals are disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const dealId = String(req.params.dealId || '').trim();
        const quantity = Math.max(1, Math.min(1000, Number.parseInt(req.body.quantity, 10) || 1));
        if (!dealId) {
            return res.redirect(`${dealsRedirectBase}?error=${encodeURIComponent('Invalid deal id.')}`);
        }

        const catalog = await getStoreDealsCatalogSafe();
        const index = catalog.findIndex((entry) => String(entry.id) === dealId);
        if (index === -1) {
            return res.redirect(`${dealsRedirectBase}?error=${encodeURIComponent('Deal not found.')}`);
        }

        const deal = catalog[index];
        const status = getStoreDealStatus(deal);
        if (status !== 'active') {
            return res.redirect(`${dealsRedirectBase}?error=${encodeURIComponent(`Deal is not purchasable (${status}).`)}`);
        }

        const remaining = getStoreDealRemainingStock(deal);
        if (remaining < quantity) {
            return res.redirect(`${dealsRedirectBase}?error=${encodeURIComponent(`Only ${remaining} unit(s) left for this deal.`)}`);
        }

        const totalPrice = Math.max(0, Math.ceil(Number(deal.priceCoins || 0) * quantity));
        const userCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        if (userCoins < totalPrice) {
            return res.redirect(`${dealsRedirectBase}?error=${encodeURIComponent(`Not enough ${normalizeEconomyUnit(featureFlags.economyUnit)}. Need ${totalPrice}.`)}`);
        }

        const inventory = await getUserInventoryState(account.id);
        const resources = deal.resources || {};
        const nextInventory = normalizeUserInventoryState({
            ...inventory,
            ramMb: inventory.ramMb + (Math.max(0, Number.parseInt(resources.ramMb, 10) || 0) * quantity),
            cpuPercent: inventory.cpuPercent + (Math.max(0, Number.parseInt(resources.cpuPercent, 10) || 0) * quantity),
            diskMb: inventory.diskMb + (Math.max(0, Number.parseInt(resources.diskMb, 10) || 0) * quantity),
            swapMb: inventory.swapMb + (Math.max(0, Number.parseInt(resources.swapMb, 10) || 0) * quantity),
            allocations: inventory.allocations + (Math.max(0, Number.parseInt(resources.allocations, 10) || 0) * quantity),
            images: inventory.images + (Math.max(0, Number.parseInt(resources.images, 10) || 0) * quantity),
            databases: inventory.databases + (Math.max(0, Number.parseInt(resources.databases, 10) || 0) * quantity),
            packages: inventory.packages + (Math.max(0, Number.parseInt(resources.packages, 10) || 0) * quantity)
        });
        await setUserInventoryState(account.id, nextInventory);

        const nextCoins = userCoins - totalPrice;
        await account.update({ coins: nextCoins });
        req.session.user.coins = nextCoins;
        await new Promise((resolve) => req.session.save(resolve));

        catalog[index] = {
            ...deal,
            stockSold: Math.max(0, Number.parseInt(deal.stockSold, 10) || 0) + quantity,
            updatedAtMs: Date.now()
        };
        await setStoreDealsCatalogSafe(catalog);

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.deal.purchase',
            targetType: 'user',
            targetId: account.id,
            req,
            metadata: {
                dealId: deal.id,
                dealName: deal.name,
                quantity,
                amount: totalPrice,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                walletBefore: userCoins,
                walletAfter: nextCoins,
                resourcesPerUnit: resources
            }
        });

        return res.redirect(`${dealsRedirectBase}?success=${encodeURIComponent(`Purchased ${quantity}x deal "${deal.name}" for ${totalPrice} ${normalizeEconomyUnit(featureFlags.economyUnit)}.`)}`);
    } catch (error) {
        console.error('Error purchasing deal:', error);
        return res.redirect('/store/deals?error=' + encodeURIComponent('Failed to purchase deal.'));
    }
});

app.post('/store/inventory/buy', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.inventoryEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Inventory mode is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const pricing = getInventoryUnitCostAndDelta(req.body.resourceType, req.body.quantity, featureFlags);
        if (!pricing.ok) {
            return res.redirect('/store?error=' + encodeURIComponent(pricing.error));
        }

        const userCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        if (userCoins < pricing.totalCost) {
            return res.redirect('/store?error=' + encodeURIComponent(`Not enough ${normalizeEconomyUnit(featureFlags.economyUnit)}. Need ${pricing.totalCost}.`));
        }

        const inventory = await getUserInventoryState(account.id);
        const nextInventory = normalizeUserInventoryState({
            ...inventory,
            ramMb: inventory.ramMb + pricing.delta.ramMb,
            cpuPercent: inventory.cpuPercent + pricing.delta.cpuPercent,
            diskMb: inventory.diskMb + pricing.delta.diskMb,
            swapMb: inventory.swapMb + pricing.delta.swapMb,
            allocations: inventory.allocations + pricing.delta.allocations,
            images: inventory.images + pricing.delta.images,
            databases: inventory.databases + pricing.delta.databases,
            packages: inventory.packages + pricing.delta.packages
        });
        await setUserInventoryState(account.id, nextInventory);

        const nextCoins = userCoins - pricing.totalCost;
        await account.update({ coins: nextCoins });
        req.session.user.coins = nextCoins;
        await new Promise((resolve) => req.session.save(resolve));

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.inventory.purchase',
            targetType: 'user',
            targetId: account.id,
            req,
            metadata: {
                resourceType: pricing.resourceType,
                quantity: pricing.quantity,
                amount: pricing.totalCost,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                delta: pricing.delta,
                walletBefore: userCoins,
                walletAfter: nextCoins
            }
        });

        return res.redirect('/store?success=' + encodeURIComponent(`Purchased ${pricing.quantity}x ${pricing.resourceType} for ${pricing.totalCost} ${normalizeEconomyUnit(featureFlags.economyUnit)}.`));
    } catch (error) {
        console.error('Error purchasing inventory resource:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to purchase inventory resource.'));
    }
});

app.post('/store/inventory/sell', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.inventoryEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Inventory mode is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const pricing = getInventoryUnitCostAndDelta(req.body.resourceType, req.body.quantity, featureFlags);
        if (!pricing.ok) {
            return res.redirect('/store?error=' + encodeURIComponent(pricing.error));
        }

        const inventory = await getUserInventoryState(account.id);
        const needs = [];
        if (pricing.delta.ramMb > 0 && inventory.ramMb < pricing.delta.ramMb) needs.push(`RAM ${pricing.delta.ramMb}MB (available ${inventory.ramMb}MB)`);
        if (pricing.delta.cpuPercent > 0 && inventory.cpuPercent < pricing.delta.cpuPercent) needs.push(`CPU ${pricing.delta.cpuPercent}% (available ${inventory.cpuPercent}%)`);
        if (pricing.delta.diskMb > 0 && inventory.diskMb < pricing.delta.diskMb) needs.push(`Disk ${pricing.delta.diskMb}MB (available ${inventory.diskMb}MB)`);
        if (pricing.delta.swapMb > 0 && inventory.swapMb < pricing.delta.swapMb) needs.push(`Swap ${pricing.delta.swapMb}MB (available ${inventory.swapMb}MB)`);
        if (pricing.delta.allocations > 0 && inventory.allocations < pricing.delta.allocations) needs.push(`Allocation tokens ${pricing.delta.allocations} (available ${inventory.allocations})`);
        if (pricing.delta.images > 0 && inventory.images < pricing.delta.images) needs.push(`Image tokens ${pricing.delta.images} (available ${inventory.images})`);
        if (pricing.delta.databases > 0 && inventory.databases < pricing.delta.databases) needs.push(`Database slots ${pricing.delta.databases} (available ${inventory.databases})`);
        if (pricing.delta.packages > 0 && inventory.packages < pricing.delta.packages) needs.push(`Package tokens ${pricing.delta.packages} (available ${inventory.packages})`);
        if (needs.length > 0) {
            return res.redirect('/store?error=' + encodeURIComponent(`Not enough inventory to sell: ${needs.join(', ')}`));
        }

        const nextInventory = normalizeUserInventoryState({
            ...inventory,
            ramMb: Math.max(0, inventory.ramMb - pricing.delta.ramMb),
            cpuPercent: Math.max(0, inventory.cpuPercent - pricing.delta.cpuPercent),
            diskMb: Math.max(0, inventory.diskMb - pricing.delta.diskMb),
            swapMb: Math.max(0, inventory.swapMb - pricing.delta.swapMb),
            allocations: Math.max(0, inventory.allocations - pricing.delta.allocations),
            images: Math.max(0, inventory.images - pricing.delta.images),
            databases: Math.max(0, inventory.databases - pricing.delta.databases),
            packages: Math.max(0, inventory.packages - pricing.delta.packages)
        });
        await setUserInventoryState(account.id, nextInventory);

        const sellTotal = Math.max(0, Math.floor((Number(pricing.unitCost || 0) * Number(pricing.quantity || 0)) / 2));
        if (sellTotal <= 0) {
            return res.redirect('/store?error=' + encodeURIComponent('Sell payout is 0 for this quantity. Increase quantity or unit price.'));
        }
        const userCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        const nextCoins = userCoins + sellTotal;
        await account.update({ coins: nextCoins });
        req.session.user.coins = nextCoins;
        await new Promise((resolve) => req.session.save(resolve));

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.inventory.sell',
            targetType: 'user',
            targetId: account.id,
            req,
            metadata: {
                resourceType: pricing.resourceType,
                quantity: pricing.quantity,
                amount: sellTotal,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                pricingMode: 'half',
                unitCost: Number(pricing.unitCost || 0),
                delta: pricing.delta,
                walletBefore: userCoins,
                walletAfter: nextCoins
            }
        });

        return res.redirect('/store?success=' + encodeURIComponent(`Sold ${pricing.quantity}x ${pricing.resourceType} for ${sellTotal} ${normalizeEconomyUnit(featureFlags.economyUnit)} (50% rate).`));
    } catch (error) {
        console.error('Error selling inventory resource:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to sell inventory resource.'));
    }
});

app.post('/store/renew/:containerId', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('Store is disabled by admin.'));
        }
        if (!featureFlags.costPerServerEnabled) {
            return res.redirect('/store?error=' + encodeURIComponent('Renew billing is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const server = await Server.findOne({
            where: { containerId: req.params.containerId, ownerId: account.id },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) {
            return res.redirect('/store?error=' + encodeURIComponent('Server not found.'));
        }

        const billingState = await getStoreBillingStateSafe(server.id);
        if (!billingState) {
            return res.redirect('/store?error=' + encodeURIComponent('This server has no active renew billing profile.'));
        }

        const recurringCoins = Math.max(0, calculateStoreRenewCostSafe(server, res.locals.settings || {}));
        const userCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        if (userCoins < recurringCoins) {
            return res.redirect('/store?error=' + encodeURIComponent(`Not enough ${normalizeEconomyUnit(featureFlags.economyUnit)} to renew. Need ${recurringCoins}.`));
        }

        const newCoins = userCoins - recurringCoins;
        await account.update({ coins: newCoins });
        req.session.user.coins = newCoins;
        await new Promise((resolve) => req.session.save(resolve));

        const nowMs = Date.now();
        const renewDays = Math.max(1, Number.parseInt(featureFlags.storeRenewDays, 10) || 30);
        await setStoreBillingStateSafe(server.id, {
            ...billingState,
            status: 'active',
            recurringCoins,
            renewDays,
            lastRenewAtMs: nowMs,
            nextRenewAtMs: nowMs + (renewDays * DAY_MS),
            suspendedAtMs: 0,
            deleteAfterMs: 0
        });

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.server.renew',
            targetType: 'server',
            targetId: server.id,
            req,
            metadata: {
                serverName: server.name,
                amount: recurringCoins,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                renewDays,
                walletBefore: userCoins,
                walletAfter: newCoins
            }
        });

        if (server.isSuspended && isStoreBillingSuspensionReason(server.suspendReason)) {
            await server.update({
                isSuspended: false,
                status: 'offline',
                suspendReason: null
            });
        }

        return res.redirect('/store?success=' + encodeURIComponent(`Server "${server.name}" renewed successfully for ${renewDays} day(s).`));
    } catch (error) {
        console.error('Error renewing server:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to renew server.'));
    }
});

app.get('/user/server/:containerId/edit', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('User server management is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const server = await Server.findOne({
            where: { containerId: req.params.containerId, ownerId: account.id },
            include: [
                { model: Image, as: 'image', required: false },
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector', required: false }], required: false }
            ]
        });
        if (!server) {
            return res.redirect('/store?error=' + encodeURIComponent('Server not found.'));
        }

        const revenueManaged = await getServerRevenueManagedState(server.id);
        let isRevenueManagedLocked = Boolean(revenueManaged && revenueManaged.managed);
        if (!isRevenueManagedLocked && featureFlags.revenueModeEnabled) {
            const [revenuePlanCatalog, revenueProfileRaw] = await Promise.all([
                getRevenuePlanCatalogSafe(),
                getUserRevenueProfileSafe(account.id)
            ]);
            const revenueProfile = normalizeUserRevenueProfile(revenueProfileRaw || {});
            const activeRevenuePlan = resolveRevenuePlanById(revenuePlanCatalog, revenueProfile.planId);
            isRevenueManagedLocked = Boolean(activeRevenuePlan) && isRevenueProfileProvisioningAllowed(revenueProfile);
        }
        if (isRevenueManagedLocked) {
            return res.redirect('/store?error=' + encodeURIComponent('Edit mode is disabled for revenue managed servers. Delete remains available.'));
        }

        return res.render('user-server-edit', {
            user: req.session.user,
            title: `Edit Server - ${server.name}`,
            path: '/store',
            server,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading user server edit page:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to load server edit page.'));
    }
});

app.post('/user/server/:containerId/edit', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('User server management is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const server = await Server.findOne({
            where: { containerId: req.params.containerId, ownerId: account.id }
        });
        if (!server) {
            return res.redirect('/store?error=' + encodeURIComponent('Server not found.'));
        }

        const revenueManaged = await getServerRevenueManagedState(server.id);
        let isRevenueManagedLocked = Boolean(revenueManaged && revenueManaged.managed);
        if (!isRevenueManagedLocked && featureFlags.revenueModeEnabled) {
            const [revenuePlanCatalog, revenueProfileRaw] = await Promise.all([
                getRevenuePlanCatalogSafe(),
                getUserRevenueProfileSafe(account.id)
            ]);
            const revenueProfile = normalizeUserRevenueProfile(revenueProfileRaw || {});
            const activeRevenuePlan = resolveRevenuePlanById(revenuePlanCatalog, revenueProfile.planId);
            isRevenueManagedLocked = Boolean(activeRevenuePlan) && isRevenueProfileProvisioningAllowed(revenueProfile);
        }
        if (isRevenueManagedLocked) {
            return res.redirect('/store?error=' + encodeURIComponent('Edit mode is disabled for revenue managed servers. Delete remains available.'));
        }

        const nextName = String(req.body.name || '').trim();
        if (!nextName) {
            return res.redirect(`/user/server/${server.containerId}/edit?error=${encodeURIComponent('Server name is required.')}`);
        }
        if (nextName.length > 100) {
            return res.redirect(`/user/server/${server.containerId}/edit?error=${encodeURIComponent('Server name must be at most 100 characters.')}`);
        }

        const prevName = String(server.name || '').trim();
        if (prevName === nextName) {
            return res.redirect(`/user/server/${server.containerId}/edit?success=${encodeURIComponent('No changes detected.')}`);
        }

        await server.update({ name: nextName });

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.server.edit',
            targetType: 'server',
            targetId: server.id,
            req,
            metadata: {
                previousName: prevName,
                newName: nextName
            }
        });

        return res.redirect('/store?success=' + encodeURIComponent(`Server renamed to "${nextName}".`));
    } catch (error) {
        console.error('Error editing user server:', error);
        return res.redirect(`/user/server/${req.params.containerId}/edit?error=${encodeURIComponent('Failed to edit server.')}`);
    }
});

app.post('/user/server/:containerId/delete', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('User server management is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const server = await Server.findOne({
            where: { containerId: req.params.containerId, ownerId: account.id },
            include: [
                { model: Allocation, as: 'allocation' },
                { model: Image, as: 'image', required: false }
            ]
        });
        if (!server) {
            return res.redirect('/store?error=' + encodeURIComponent('Server not found.'));
        }

        const requestedRefundModeRaw = String(req.body.refundMode || '').trim().toLowerCase();
        const requestedRefundMode = requestedRefundModeRaw === 'coins'
            ? 'coins'
            : (requestedRefundModeRaw === 'none' ? 'none' : 'inventory');
        const revenueManagedState = await getServerRevenueManagedState(server.id);
        const inventoryProvisioningState = await getServerInventoryProvisioningState(server.id);

        let refundResources = null;
        let refundSource = 'none';
        if (inventoryProvisioningState && inventoryProvisioningState.mode === 'inventory') {
            refundResources = { ...inventoryProvisioningState.resources };
            refundSource = 'provisioning_marker';
        } else if (featureFlags.inventoryEnabled && !(revenueManagedState && revenueManagedState.managed)) {
            refundResources = buildServerInventoryRefundResources(server);
            refundSource = 'legacy_fallback';
        }

        const refundResourceTotal = refundResources
            ? (Number(refundResources.ramMb || 0)
                + Number(refundResources.cpuPercent || 0)
                + Number(refundResources.diskMb || 0)
                + Number(refundResources.swapMb || 0)
                + Number(refundResources.allocations || 0)
                + Number(refundResources.images || 0)
                + Number(refundResources.databases || 0)
                + Number(refundResources.packages || 0))
            : 0;

        let connectorOnline = false;
        if (server.allocation && server.allocation.connectorId) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (connectorWs && connectorWs.readyState === 1) {
                connectorOnline = true;
            }
        }

        if (connectorOnline && server.allocation && server.allocation.connectorId) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (connectorWs && connectorWs.readyState === 1) {
                connectorWs.send(JSON.stringify({ type: 'delete_server', serverId: server.id }));
            }
        }

        if (server.allocationId) {
            await Allocation.update({ serverId: null }, { where: { id: server.allocationId } });
        }

        const settingsKeysToDelete = [
            getStoreBillingSettingKeySafe(server.id),
            getServerRevenueManagedSettingKey(server.id),
            getServerInventoryProvisioningSettingKey(server.id),
            getServerSchedulesSettingKey(server.id),
            getServerConfigBaselineSettingKey(server.id),
            typeof getServerScheduledScalingSettingKey === 'function' ? getServerScheduledScalingSettingKey(server.id) : null,
            typeof getServerSmartAlertsSettingKey === 'function' ? getServerSmartAlertsSettingKey(server.id) : null,
            typeof getServerStartupPresetSettingKey === 'function' ? getServerStartupPresetSettingKey(server.id) : null,
            typeof getServerPolicyEngineSettingKey === 'function' ? getServerPolicyEngineSettingKey(server.id) : null
        ].filter(Boolean);

        if (settingsKeysToDelete.length > 0) {
            await Settings.destroy({ where: { key: { [Op.in]: settingsKeysToDelete } } });
        }

        if (ServerSubuser) {
            await ServerSubuser.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (ServerApiKey) {
            await ServerApiKey.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (typeof ServerDatabase !== 'undefined' && ServerDatabase) {
            const serverDatabases = await ServerDatabase.findAll({
                where: { serverId: server.id },
                include: [{ model: DatabaseHost, as: 'host', required: false }]
            }).catch(() => []);
            if (Array.isArray(serverDatabases)) {
                for (const entry of serverDatabases) {
                    if (!entry || !entry.host) continue;
                    try {
                        await dropServerDatabaseFromHost(entry.host, {
                            databaseName: String(entry.name || ''),
                            databaseUser: String(entry.username || '')
                        });
                    } catch (databaseCleanupError) {
                        console.warn(`Failed to drop remote database during server delete (serverId=${server.id}, dbId=${entry.id}):`, databaseCleanupError.message);
                    }
                }
            }
            await ServerDatabase.destroy({ where: { serverId: server.id } }).catch(() => {});
        }

        if (typeof consumeServerPowerIntent === 'function') {
            consumeServerPowerIntent(server.id);
        }
        if (typeof RESOURCE_ANOMALY_STATE !== 'undefined' && RESOURCE_ANOMALY_STATE && typeof RESOURCE_ANOMALY_STATE.delete === 'function') {
            RESOURCE_ANOMALY_STATE.delete(server.id);
        }
        if (typeof RESOURCE_ANOMALY_SAMPLE_TS !== 'undefined' && RESOURCE_ANOMALY_SAMPLE_TS && typeof RESOURCE_ANOMALY_SAMPLE_TS.delete === 'function') {
            RESOURCE_ANOMALY_SAMPLE_TS.delete(server.id);
        }
        if (typeof PLUGIN_CONFLICT_STATE !== 'undefined' && PLUGIN_CONFLICT_STATE && typeof PLUGIN_CONFLICT_STATE.delete === 'function') {
            PLUGIN_CONFLICT_STATE.delete(server.id);
        }
        if (typeof serverLogCleanupScheduleState !== 'undefined' && serverLogCleanupScheduleState && typeof serverLogCleanupScheduleState.delete === 'function') {
            serverLogCleanupScheduleState.delete(server.id);
        }
        if (typeof pendingMigrationFileImports !== 'undefined' && pendingMigrationFileImports && typeof pendingMigrationFileImports.delete === 'function') {
            pendingMigrationFileImports.delete(server.id);
        }

        await server.destroy();

        let appliedRefundMode = 'none';
        let refundedCoins = 0;
        let refundCoinValue = 0;
        if (refundResources && refundResourceTotal > 0 && requestedRefundMode !== 'none') {
            if (requestedRefundMode === 'coins') {
                refundCoinValue = calculateInventoryResourceCoinValue(refundResources, featureFlags);
                refundedCoins = Math.max(0, Math.floor(refundCoinValue / 2));
                if (refundedCoins > 0) {
                    const userCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
                    const nextCoins = userCoins + refundedCoins;
                    await account.update({ coins: nextCoins });
                    req.session.user.coins = nextCoins;
                    await new Promise((resolve) => req.session.save(resolve));
                    appliedRefundMode = 'coins';
                }
            } else {
                const inventory = await getUserInventoryState(account.id);
                await setUserInventoryState(account.id, {
                    ...inventory,
                    ramMb: inventory.ramMb + Number(refundResources.ramMb || 0),
                    cpuPercent: inventory.cpuPercent + Number(refundResources.cpuPercent || 0),
                    diskMb: inventory.diskMb + Number(refundResources.diskMb || 0),
                    swapMb: inventory.swapMb + Number(refundResources.swapMb || 0),
                    allocations: inventory.allocations + Number(refundResources.allocations || 0),
                    images: inventory.images + Number(refundResources.images || 0),
                    databases: inventory.databases + Number(refundResources.databases || 0),
                    packages: inventory.packages + Number(refundResources.packages || 0)
                });
                appliedRefundMode = 'inventory';
            }
        }

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.server.delete',
            targetType: 'server',
            targetId: server.id,
            req,
            metadata: {
                serverName: server.name,
                containerId: server.containerId,
                connectorOnline,
                requestedRefundMode,
                appliedRefundMode,
                refundSource,
                refundedCoins,
                refundCoinValue,
                refundResources
            }
        });

        const refundSummaryParts = [];
        if (appliedRefundMode === 'inventory' && refundResources) {
            const toGb = (mb) => (Number(mb || 0) / 1024).toFixed(2).replace(/\.00$/, '');
            if (Number(refundResources.ramMb || 0) > 0) refundSummaryParts.push(`RAM ${toGb(refundResources.ramMb)} GB`);
            if (Number(refundResources.cpuPercent || 0) > 0) refundSummaryParts.push(`CPU ${(Number(refundResources.cpuPercent || 0) / 100).toFixed(2).replace(/\.00$/, '')}`);
            if (Number(refundResources.diskMb || 0) > 0) refundSummaryParts.push(`Disk ${toGb(refundResources.diskMb)} GB`);
            if (Number(refundResources.swapMb || 0) > 0) refundSummaryParts.push(`Swap ${toGb(refundResources.swapMb)} GB`);
            if (Number(refundResources.allocations || 0) > 0) refundSummaryParts.push(`Allocations ${refundResources.allocations}`);
            if (Number(refundResources.images || 0) > 0) refundSummaryParts.push(`Images ${refundResources.images}`);
            if (Number(refundResources.databases || 0) > 0) refundSummaryParts.push(`Databases ${refundResources.databases}`);
            if (Number(refundResources.packages || 0) > 0) refundSummaryParts.push(`Packages ${refundResources.packages}`);
        }
        const refundSummaryText = appliedRefundMode === 'coins'
            ? ` Refunded ${refundedCoins} ${normalizeEconomyUnit(featureFlags.economyUnit)} (convert mode, 50%).`
            : (appliedRefundMode === 'inventory'
                ? ` Resources returned to inventory${refundSummaryParts.length ? `: ${refundSummaryParts.join(', ')}` : ''}.`
                : (requestedRefundMode === 'none' ? '' : ' No refundable inventory resources were found for this server.'));
        const message = connectorOnline
            ? `Server "${server.name}" deleted successfully.${refundSummaryText}`
            : `Server "${server.name}" deleted from panel. Connector offline, so remote files may still exist.${refundSummaryText}`;
        return res.redirect('/store?success=' + encodeURIComponent(message));
    } catch (error) {
        console.error('Error deleting user server:', error);
        return res.redirect('/store?error=' + encodeURIComponent('Failed to delete server.'));
    }
});

app.get('/user/create', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('User server creation is disabled by admin.'));
        }

        const account = await User.findByPk(req.session.user.id, {
            attributes: ['id', 'coins', 'isSuspended']
        });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const [images, allocations, inventoryState, ownedUsage, revenuePlanCatalog, revenueProfileRaw, quotaBurnLogs] = await Promise.all([
            Image.findAll({
                include: [{ model: Package, as: 'package', required: false }],
                order: [['name', 'ASC']]
            }),
            Allocation.findAll({
                where: { serverId: null },
                include: [{ model: Connector, as: 'connector', include: [{ model: Location, as: 'location' }] }],
                order: [['id', 'ASC']]
            }),
            getUserInventoryState(req.session.user.id),
            getUserServerAggregateUsage(req.session.user.id),
            featureFlags.revenueModeEnabled ? getRevenuePlanCatalogSafe() : Promise.resolve([]),
            featureFlags.revenueModeEnabled ? getUserRevenueProfileSafe(req.session.user.id) : Promise.resolve(null),
            featureFlags.quotaForecastingEnabled && AuditLog
                ? AuditLog.findAll({
                    where: {
                        action: { [Op.in]: Array.from(QUOTA_FORECAST_SPEND_ACTIONS) },
                        createdAt: { [Op.gte]: new Date(Date.now() - (QUOTA_FORECAST_V2_LOOKBACK_DAYS * DAY_MS)) }
                    },
                    attributes: ['actorUserId', 'action', 'createdAt', 'metadata'],
                    order: [['createdAt', 'DESC']],
                    limit: 2000
                })
                : Promise.resolve([])
        ]);

        const allocationsView = allocations.map((allocation) => {
            const statusData = (global.connectorStatus && global.connectorStatus[allocation.connectorId]) || { status: 'offline', lastSeen: null };
            const isOnline = statusData.status === 'online' && (new Date() - new Date(statusData.lastSeen)) < 30000;
            const locationId = allocation.connector && allocation.connector.locationId ? Number(allocation.connector.locationId) : 0;
            return {
                ...allocation.toJSON(),
                locationId,
                isOnline
            };
        });

        const locationMap = new Map();
        const connectorMap = new Map();
        allocationsView.forEach((allocation) => {
            const connector = allocation && allocation.connector ? allocation.connector : null;
            const location = connector && connector.location ? connector.location : null;
            if (location && Number.isInteger(Number(location.id)) && !locationMap.has(Number(location.id))) {
                locationMap.set(Number(location.id), {
                    id: Number(location.id),
                    shortName: String(location.shortName || `Location #${location.id}`),
                    description: String(location.description || '').trim()
                });
            }
            if (connector && Number.isInteger(Number(connector.id)) && !connectorMap.has(Number(connector.id))) {
                connectorMap.set(Number(connector.id), {
                    id: Number(connector.id),
                    name: String(connector.name || `Connector #${connector.id}`),
                    locationId: Number(connector.locationId || 0),
                    online: Boolean(allocation.isOnline)
                });
            } else if (connector && Number.isInteger(Number(connector.id)) && allocation.isOnline) {
                const existing = connectorMap.get(Number(connector.id));
                if (existing) existing.online = true;
            }
        });

        const locations = Array.from(locationMap.values()).sort((a, b) => a.shortName.localeCompare(b.shortName));
        const connectors = Array.from(connectorMap.values()).sort((a, b) => a.name.localeCompare(b.name));
        const smartUsageByConnector = await buildConnectorUsageMap(connectors.map((entry) => entry.id));
        const smartSuggestionResult = pickSmartAllocation({
            allocations: allocationsView.filter((entry) => entry && !entry.serverId),
            connectorStatusMap: global.connectorStatus || {},
            usageByConnector: smartUsageByConnector,
            requestedMemoryMb: 1024,
            requestedDiskMb: 10240
        });
        const smartAllocationDefault = formatSmartAllocationResponse(smartSuggestionResult);
        const revenueProfile = normalizeUserRevenueProfile(revenueProfileRaw || {});
        const revenueActivePlan = resolveRevenuePlanById(revenuePlanCatalog, revenueProfile.planId);
        const revenuePlanSelected = Boolean(revenueActivePlan);
        const revenueProvisioningAllowed = !featureFlags.revenueModeEnabled || (revenuePlanSelected && isRevenueProfileProvisioningAllowed(revenueProfile));
        const revenueInventoryFallbackAllowed = Boolean(featureFlags.revenueModeEnabled) && !revenuePlanSelected && Boolean(featureFlags.inventoryEnabled);
        const revenueCreateLocked = Boolean(featureFlags.revenueModeEnabled) && !revenueProvisioningAllowed && !revenueInventoryFallbackAllowed;
        const revenueInventoryBypass = Boolean(featureFlags.revenueModeEnabled) && revenuePlanSelected && isRevenueProfileProvisioningAllowed(revenueProfile);
        const inventoryApplied = Boolean(featureFlags.inventoryEnabled) && !revenueInventoryBypass;
        const renewDays = Math.max(1, Number.parseInt(featureFlags.storeRenewDays, 10) || 30);
        const recurringEstimateCoins = featureFlags.costPerServerEnabled
            ? (
                (Number(ownedUsage.serverCount || 0) * Number(featureFlags.costBasePerServerMonthly || 0))
                + ((Number(ownedUsage.memory || 0) / 1024) * Number(featureFlags.costPerGbRamMonthly || 0))
                + ((Number(ownedUsage.cpu || 0) / 100) * Number(featureFlags.costPerCpuCoreMonthly || 0))
                + ((Number(ownedUsage.disk || 0) / 1024) * Number(featureFlags.costPerGbDiskMonthly || 0))
            )
            : 0;
        const revenuePrice = revenueActivePlan
            ? Math.max(0, Number.parseInt(revenueActivePlan.priceCoins, 10) || 0)
            : Math.max(0, Number.parseInt(revenueProfile.priceCoins, 10) || 0);
        const revenuePeriodDays = revenueActivePlan
            ? Math.max(1, Number.parseInt(revenueActivePlan.periodDays, 10) || 30)
            : Math.max(1, Number.parseInt(revenueProfile.periodDays, 10) || 30);
        const revenueDailyBurn = isRevenueProfileProvisioningAllowed(revenueProfile) || revenueProfile.status === 'past_due'
            ? (revenuePrice / revenuePeriodDays)
            : 0;
        const recurringDailyBurn = recurringEstimateCoins / renewDays;
        const quotaForecast = buildQuotaForecastV2({
            enabled: Boolean(featureFlags.quotaForecastingEnabled),
            walletCoins: Number(account.coins || 0),
            recurringDailyBurn,
            revenueDailyBurn,
            burnLogs: quotaBurnLogs,
            ownerUserId: req.session.user.id
        });

        return res.render('user-create', {
            user: req.session.user,
            title: 'Create Server',
            path: '/user/create',
            images,
            allocations: allocationsView,
            locations,
            connectors,
            featureInventoryEnabled: Boolean(featureFlags.inventoryEnabled),
            inventoryApplied,
            revenueInventoryBypass,
            inventoryState: normalizeUserInventoryState(inventoryState),
            featureQuotaForecastingEnabled: Boolean(featureFlags.quotaForecastingEnabled),
            featureRevenueModeEnabled: Boolean(featureFlags.revenueModeEnabled),
            revenueProfile,
            revenueActivePlan,
            revenueProvisioningAllowed,
            revenueInventoryFallbackAllowed,
            revenueCreateLocked,
            revenueUsage: ownedUsage,
            quotaForecast,
            smartAllocationDefault,
            economyUnit: normalizeEconomyUnit(featureFlags.economyUnit),
            pricing: {
                storeRamPerGbCoins: Number(featureFlags.storeRamPerGbCoins || 0),
                storeCpuPerCoreCoins: Number(featureFlags.storeCpuPerCoreCoins || 0),
                storeSwapPerGbCoins: Number(featureFlags.storeSwapPerGbCoins || 0),
                storeDiskPerGbCoins: Number(featureFlags.storeDiskPerGbCoins || 0),
                storeAllocationCoins: Number(featureFlags.storeAllocationCoins || 0),
                storeImageCoins: Number(featureFlags.storeImageCoins || 0),
                storeDatabaseCoins: Number(featureFlags.storeDatabaseCoins || 0),
                storePackageCoins: Number(featureFlags.storePackageCoins || 0),
                recurringEnabled: Boolean(featureFlags.costPerServerEnabled),
                recurringBase: Number(featureFlags.costBasePerServerMonthly || 0),
                recurringRam: Number(featureFlags.costPerGbRamMonthly || 0),
                recurringCpu: Number(featureFlags.costPerCpuCoreMonthly || 0),
                recurringDisk: Number(featureFlags.costPerGbDiskMonthly || 0)
            },
            renewDays,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading user create page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load create page.'));
    }
});

app.get('/user/create/smart-allocation', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.status(403).json({ success: false, error: 'User server creation is disabled by admin.' });
        }

        const account = await User.findByPk(req.session.user.id, { attributes: ['id', 'isSuspended'] });
        if (!account) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }
        if (account.isSuspended) {
            return res.status(403).json({ success: false, error: 'Account is suspended.' });
        }

        const requestedMemoryMb = Math.max(1, Number.parseInt(req.query.memory, 10) || 1024);
        const requestedDiskMb = Math.max(1, Number.parseInt(req.query.disk, 10) || 10240);
        const preferredConnectorId = Math.max(0, Number.parseInt(req.query.connectorId, 10) || 0);
        const preferredLocationId = Math.max(0, Number.parseInt(req.query.locationId, 10) || 0);
        if (preferredLocationId <= 0) {
            return res.status(400).json({ success: false, error: 'Select a location first.' });
        }

        const allocations = await Allocation.findAll({
            where: { serverId: null },
            include: [{ model: Connector, as: 'connector', include: [{ model: Location, as: 'location' }] }],
            order: [['id', 'ASC']]
        });
        const usageByConnector = await buildConnectorUsageMap(allocations.map((entry) => entry.connectorId));
        const result = pickSmartAllocation({
            allocations,
            connectorStatusMap: global.connectorStatus || {},
            usageByConnector,
            requestedMemoryMb,
            requestedDiskMb,
            preferredConnectorId,
            preferredLocationId
        });

        const allocation = formatSmartAllocationResponse(result);
        if (!allocation) {
            return res.status(409).json({
                success: false,
                error: result && result.reason ? result.reason : 'No eligible allocation found.',
                meta: result && result.meta ? result.meta : null
            });
        }

        return res.json({
            success: true,
            allocation,
            meta: result.meta || null
        });
    } catch (error) {
        console.error('Error running smart allocation suggestion for user create:', error);
        return res.status(500).json({ success: false, error: 'Failed to compute smart allocation suggestion.' });
    }
});

app.post('/user/create', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.userCreateEnabled) {
            return res.redirect('/?error=' + encodeURIComponent('User server creation is disabled by admin.'));
        }
        const inventoryFeatureEnabled = Boolean(featureFlags.inventoryEnabled);

        const account = await User.findByPk(req.session.user.id, { attributes: ['id', 'coins', 'isSuspended'] });
        if (!account) {
            req.session.destroy(() => {});
            return res.redirect('/login?error=' + encodeURIComponent('Session expired. Please login again.'));
        }
        if (account.isSuspended) {
            return res.redirect('/suspend');
        }

        const name = String(req.body.name || '').trim();
        const imageId = req.body.imageId;
        const requestedAllocationId = Number.parseInt(req.body.allocationId, 10);
        const smartAllocationEnabled = parseSmartAllocationToggle(req.body.smartAllocation, true);
        const selectedLocationId = Number.parseInt(req.body.locationId, 10);
        const selectedConnectorId = Number.parseInt(req.body.connectorId, 10);
        const parseResourceMb = (mbRaw, gbRaw, defaultMb = 0, minMb = 0) => {
            const parsedMb = Number.parseInt(mbRaw, 10);
            if (Number.isFinite(parsedMb)) {
                return Math.max(minMb, parsedMb);
            }
            const parsedGb = Number.parseFloat(gbRaw);
            if (Number.isFinite(parsedGb)) {
                return Math.max(minMb, Math.round(parsedGb * 1024));
            }
            return Math.max(minMb, defaultMb);
        };
        const memory = parseResourceMb(req.body.memory, req.body.memoryGb, 1024, 1);
        const cpu = Number.parseInt(req.body.cpu, 10);
        const disk = parseResourceMb(req.body.disk, req.body.diskGb, 10240, 1);
        const swapLimit = parseResourceMb(req.body.swapLimit, req.body.swapLimitGb, 0, 0);
        const databaseLimit = Math.max(0, Number.parseInt(req.body.databaseLimit, 10) || 0);
        const dockerImage = String(req.body.dockerImage || '').trim();

        if (!name) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Server name is required.'));
        }
        if (!imageId) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Image is required.'));
        }
        if (!Number.isInteger(selectedLocationId) || selectedLocationId <= 0) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Select a valid location.'));
        }
        if (!Number.isInteger(selectedConnectorId) || selectedConnectorId <= 0) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Select a valid connector.'));
        }
        if (!smartAllocationEnabled && (!Number.isInteger(requestedAllocationId) || requestedAllocationId <= 0)) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Select a valid allocation or enable Smart Allocation.'));
        }
        if (!Number.isInteger(memory) || !Number.isInteger(cpu) || !Number.isInteger(disk)) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Memory, CPU and Disk must be valid integers.'));
        }
        if (memory < 1 || cpu < 1 || disk < 1) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Resource limits must be greater than 0.'));
        }
        if (!Number.isInteger(databaseLimit) || databaseLimit < 0 || databaseLimit > 1000) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Database slots must be between 0 and 1000.'));
        }
        if (databaseLimit > 0) {
            const dbHostCount = await DatabaseHost.count({ where: { locationId: selectedLocationId } });
            if (dbHostCount <= 0) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Selected location has no database host configured by admin.'));
            }
        }

        let isRevenueManagedProvisioning = false;
        let revenueManagedPlanId = '';
        let revenueManagedProfileStatus = '';
        if (featureFlags.revenueModeEnabled) {
            const [revenuePlanCatalog, revenueProfileRaw, ownedUsage] = await Promise.all([
                getRevenuePlanCatalogSafe(),
                getUserRevenueProfileSafe(account.id),
                getUserServerAggregateUsage(account.id)
            ]);
            const revenueProfile = normalizeUserRevenueProfile(revenueProfileRaw || {});
            const activeRevenuePlan = resolveRevenuePlanById(revenuePlanCatalog, revenueProfile.planId);
            if (activeRevenuePlan) {
                if (!isRevenueProfileProvisioningAllowed(revenueProfile)) {
                    return res.redirect('/store?error=' + encodeURIComponent(`Revenue plan status "${revenueProfile.status}" does not allow creating new servers.`));
                }
                const planValidation = validateRevenuePlanConstraints(
                    activeRevenuePlan,
                    ownedUsage.serverCount,
                    ownedUsage,
                    { memory, cpu, disk }
                );
                if (!planValidation.ok) {
                    return res.redirect('/user/create?error=' + encodeURIComponent(planValidation.error));
                }
                isRevenueManagedProvisioning = true;
                revenueManagedPlanId = String(activeRevenuePlan.id || '').trim();
                revenueManagedProfileStatus = String(revenueProfile.status || '').trim().toLowerCase();
            } else if (!inventoryFeatureEnabled) {
                return res.redirect('/store?error=' + encodeURIComponent('No active revenue plan. Enable inventory or activate a revenue plan to create servers.'));
            }
        }

        const image = await Image.findByPk(imageId, { include: [{ model: Package, as: 'package', required: false }] });
        if (!image) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Selected image not found.'));
        }

        let allocation = null;
        if (smartAllocationEnabled) {
            const freeAllocations = await Allocation.findAll({
                where: { serverId: null },
                include: [{ model: Connector, as: 'connector', include: [{ model: Location, as: 'location' }] }],
                order: [['id', 'ASC']]
            });
            const usageByConnector = await buildConnectorUsageMap(freeAllocations.map((entry) => entry.connectorId));
            const suggestion = pickSmartAllocation({
                allocations: freeAllocations,
                connectorStatusMap: global.connectorStatus || {},
                usageByConnector,
                requestedMemoryMb: memory,
                requestedDiskMb: disk,
                preferredConnectorId: Number.isInteger(selectedConnectorId) && selectedConnectorId > 0 ? selectedConnectorId : 0,
                preferredLocationId: Number.isInteger(selectedLocationId) && selectedLocationId > 0 ? selectedLocationId : 0
            });

            if (!suggestion.ok || !suggestion.best || !suggestion.best.allocation) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Smart Allocation could not find a suitable online allocation for requested resources.'));
            }
            allocation = suggestion.best.allocation;
            if (allocation.connectorId !== selectedConnectorId) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Smart Allocation did not find an eligible allocation on the selected connector.'));
            }
            const allocationLocationId = allocation.connector && allocation.connector.locationId
                ? Number.parseInt(allocation.connector.locationId, 10)
                : 0;
            if (allocationLocationId !== selectedLocationId) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Smart Allocation did not find an eligible allocation in the selected location.'));
            }
        } else {
            allocation = await Allocation.findByPk(requestedAllocationId, {
                include: [{ model: Connector, as: 'connector', include: [{ model: Location, as: 'location' }] }]
            });
            if (!allocation || allocation.serverId) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Allocation invalid or already taken.'));
            }
            if (Number.isInteger(selectedConnectorId) && selectedConnectorId > 0 && allocation.connectorId !== selectedConnectorId) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Allocation does not belong to selected connector.'));
            }
            const allocationLocationId = allocation.connector && allocation.connector.locationId
                ? Number.parseInt(allocation.connector.locationId, 10)
                : 0;
            if (Number.isInteger(selectedLocationId) && selectedLocationId > 0 && allocationLocationId !== selectedLocationId) {
                return res.redirect('/user/create?error=' + encodeURIComponent('Allocation does not belong to selected location.'));
            }
        }

        const statusData = (global.connectorStatus && global.connectorStatus[allocation.connectorId]) || { status: 'offline', lastSeen: null };
        const isOnline = statusData.status === 'online' && (new Date() - new Date(statusData.lastSeen)) < 30000;
        if (!isOnline) {
            return res.redirect('/user/create?error=' + encodeURIComponent('Selected node is currently offline.'));
        }

        const currentUsage = await getConnectorAllocatedUsage(allocation.connectorId);
        const connectorMemoryMb = allocation.connector.totalMemory * 1024;
        const maxMemoryMb = connectorMemoryMb * (1 + (allocation.connector.memoryOverAllocation || 0) / 100);
        const connectorDiskMb = allocation.connector.totalDisk * 1024;
        const maxDiskMb = connectorDiskMb * (1 + (allocation.connector.diskOverAllocation || 0) / 100);
        if (currentUsage.memoryMb + memory > maxMemoryMb) {
            return res.redirect('/user/create?error=' + encodeURIComponent(`Not enough memory on selected node. Max allowed: ${maxMemoryMb} MB.`));
        }
        if (currentUsage.diskMb + disk > maxDiskMb) {
            return res.redirect('/user/create?error=' + encodeURIComponent(`Not enough disk on selected node. Max allowed: ${maxDiskMb} MB.`));
        }

        const oneTimeCostData = calculateStoreCreateCostSafe({
            memory,
            cpu,
            disk,
            swapLimit,
            databaseLimit,
            hasAllocation: true,
            hasImage: true,
            hasPackage: Boolean(image.packageId)
        }, res.locals.settings || {});
        const inventoryApplied = inventoryFeatureEnabled && !isRevenueManagedProvisioning;
        const inventoryState = inventoryApplied
            ? await getUserInventoryState(account.id)
            : defaultUserInventoryState();
        if (inventoryApplied) {
            const needs = [];
            if (inventoryState.ramMb < memory) needs.push(`RAM ${memory}MB (available ${inventoryState.ramMb}MB)`);
            if (inventoryState.cpuPercent < cpu) needs.push(`CPU ${cpu}% (available ${inventoryState.cpuPercent}%)`);
            if (inventoryState.diskMb < disk) needs.push(`Disk ${disk}MB (available ${inventoryState.diskMb}MB)`);
            if (inventoryState.swapMb < swapLimit) needs.push(`Swap ${swapLimit}MB (available ${inventoryState.swapMb}MB)`);
            if (inventoryState.allocations < 1) needs.push(`Allocation token x1 (available ${inventoryState.allocations})`);
            if (inventoryState.images < 1) needs.push(`Image token x1 (available ${inventoryState.images})`);
            if (inventoryState.databases < databaseLimit) needs.push(`Database slots ${databaseLimit} (available ${inventoryState.databases})`);
            if (image.packageId && inventoryState.packages < 1) needs.push(`Package token x1 (available ${inventoryState.packages})`);
            if (needs.length > 0) {
                return res.redirect('/user/create?error=' + encodeURIComponent(`Not enough inventory resources: ${needs.join(', ')}`));
            }
        }
        const renewCoins = featureFlags.costPerServerEnabled
            ? calculateStoreRenewCostSafe({ memory, cpu, disk, allocationId: allocation.id }, res.locals.settings || {})
            : 0;
        const oneTimeCharge = inventoryFeatureEnabled ? 0 : Number(oneTimeCostData.total || 0);
        const totalCost = Math.max(0, Number(oneTimeCharge) + Number(renewCoins || 0));

        const userCoins = Number.isFinite(Number(account.coins)) ? Number(account.coins) : 0;
        if (userCoins < totalCost) {
            return res.redirect('/user/create?error=' + encodeURIComponent(`Insufficient ${normalizeEconomyUnit(featureFlags.economyUnit)}. Need ${totalCost}, have ${userCoins}.`));
        }

        const imagePorts = resolveImagePorts(image.ports);
        const { resolvedVariables, env } = buildServerEnvironment(image, req.body.variables || {}, {
            SERVER_MEMORY: String(memory),
            SERVER_IP: allocation.ip,
            SERVER_PORT: String(allocation.port)
        });
        const startup = buildStartupCommand(image.startup, env);
        const deploymentPorts = buildDeploymentPorts({
            imagePorts,
            env,
            primaryAllocation: allocation,
            allocations: [allocation]
        });
        const startupMode = shouldUseCommandStartup(image) ? 'command' : 'environment';

        const containerId = nodeCrypto.randomBytes(4).toString('hex');
        const server = await Server.create({
            name,
            containerId,
            ownerId: account.id,
            imageId: image.id,
            allocationId: allocation.id,
            databaseLimit,
            memory,
            cpu,
            disk,
            swapLimit,
            ioWeight: 500,
            pidsLimit: 512,
            oomKillDisable: false,
            oomScoreAdj: 0,
            variables: resolvedVariables,
            dockerImage: dockerImage || image.dockerImage
        });

        await allocation.update({ serverId: server.id });

        let installJob;
        try {
            installJob = await jobQueue.enqueue({
                type: 'server.install.dispatch',
                payload: {
                    serverId: server.id,
                    reinstall: false,
                    clearSuspended: true,
                    resolvedVariables,
                    config: {
                        image: server.dockerImage,
                        memory: server.memory,
                        cpu: server.cpu,
                        disk: server.disk,
                        swapLimit: server.swapLimit,
                        ioWeight: server.ioWeight,
                        pidsLimit: server.pidsLimit,
                        oomKillDisable: Boolean(server.oomKillDisable),
                        oomScoreAdj: server.oomScoreAdj,
                        env,
                        startup,
                        startupMode,
                        eggConfig: image.eggConfig,
                        eggScripts: image.eggScripts,
                        installation: image.installation || null,
                        configFiles: image.configFiles || null,
                        brandName: String((res.locals.settings && res.locals.settings.brandName) || 'cpanel'),
                        ports: deploymentPorts
                    }
                },
                priority: 10,
                maxAttempts: 3,
                createdByUserId: account.id
            });
        } catch (queueError) {
            await allocation.update({ serverId: null }).catch(() => {});
            await server.destroy().catch(() => {});
            throw new Error(`Failed to queue deployment job: ${queueError.message}`);
        }

        await server.update({ status: 'installing' });

        if (isRevenueManagedProvisioning) {
            await setServerRevenueManagedState(server.id, {
                managed: true,
                planId: revenueManagedPlanId,
                profileStatus: revenueManagedProfileStatus,
                createdAtMs: Date.now()
            });
        } else {
            await removeServerRevenueManagedState(server.id);
        }

        if (inventoryApplied) {
            await setUserInventoryState(account.id, {
                ...inventoryState,
                ramMb: Math.max(0, inventoryState.ramMb - memory),
                cpuPercent: Math.max(0, inventoryState.cpuPercent - cpu),
                diskMb: Math.max(0, inventoryState.diskMb - disk),
                swapMb: Math.max(0, inventoryState.swapMb - swapLimit),
                allocations: Math.max(0, inventoryState.allocations - 1),
                images: Math.max(0, inventoryState.images - 1),
                databases: Math.max(0, inventoryState.databases - databaseLimit),
                packages: image.packageId ? Math.max(0, inventoryState.packages - 1) : inventoryState.packages
            });
        }

        try {
            if (inventoryApplied) {
                await setServerInventoryProvisioningState(server.id, {
                    mode: 'inventory',
                    resources: {
                        ramMb: memory,
                        cpuPercent: cpu,
                        diskMb: disk,
                        swapMb: swapLimit,
                        allocations: 1,
                        images: 1,
                        databases: databaseLimit,
                        packages: image.packageId ? 1 : 0
                    },
                    createdAtMs: Date.now()
                });
            } else {
                await removeServerInventoryProvisioningState(server.id);
            }
        } catch (inventoryProvisioningError) {
            console.warn(`Failed to persist inventory provisioning marker for server ${server.id}:`, inventoryProvisioningError.message);
        }

        const newCoins = userCoins - totalCost;
        await account.update({ coins: newCoins });
        req.session.user.coins = newCoins;
        await new Promise((resolve) => req.session.save(resolve));

        await createBillingAuditLog({
            actorUserId: account.id,
            action: 'billing.server.create',
            targetType: 'server',
            targetId: server.id,
            req,
            metadata: {
                serverName: server.name,
                containerId: server.containerId,
                inventoryMode: inventoryApplied,
                inventoryBypassReason: isRevenueManagedProvisioning ? 'revenue_plan' : null,
                revenueManagedProvisioning: isRevenueManagedProvisioning,
                revenuePlanId: isRevenueManagedProvisioning ? revenueManagedPlanId : null,
                oneTimeCharge,
                renewCharge: renewCoins,
                amount: totalCost,
                currency: normalizeEconomyUnit(featureFlags.economyUnit),
                walletBefore: userCoins,
                walletAfter: newCoins,
                resources: { memory, cpu, disk, swapLimit },
                databaseLimit,
                allocationId: allocation.id,
                imageId: image.id
            }
        });

        if (featureFlags.costPerServerEnabled) {
            const nowMs = Date.now();
            const renewDays = Math.max(1, Number.parseInt(featureFlags.storeRenewDays, 10) || 30);
            await setStoreBillingStateSafe(server.id, {
                status: 'active',
                recurringCoins: renewCoins,
                renewDays,
                createdAtMs: nowMs,
                lastRenewAtMs: nowMs,
                nextRenewAtMs: nowMs + (renewDays * DAY_MS),
                suspendedAtMs: 0,
                deleteAfterMs: 0
            });
        } else {
            await removeStoreBillingStateSafe(server.id);
        }

        const billingText = inventoryApplied
            ? `Used inventory resources${featureFlags.costPerServerEnabled ? ` + charged ${totalCost} ${normalizeEconomyUnit(featureFlags.economyUnit)} for renew cycle` : ''}.`
            : (isRevenueManagedProvisioning
                ? `Revenue plan provisioning active, inventory checks were skipped${featureFlags.costPerServerEnabled ? ` + charged ${totalCost} ${normalizeEconomyUnit(featureFlags.economyUnit)} for renew cycle` : ''}.`
                : `Charged ${totalCost} ${normalizeEconomyUnit(featureFlags.economyUnit)}.`);
        return res.redirect('/store?success=' + encodeURIComponent(`Server created. Deployment queued as job #${installJob.id}. ${billingText}`));
    } catch (error) {
        console.error('Error creating user server:', error);
        return res.redirect('/user/create?error=' + encodeURIComponent(error.message || 'Failed to create server.'));
    }
});

// Admin Page (GET) - Redirect to Overview
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
    res.redirect('/admin/overview');
});

// Server Error Pages
app.get('/server/notfound', (req, res) => {
    res.render('server/notfound', {
        user: req.session.user,
        title: 'Server Not Found',
        path: '/servers'
    });
});

app.get('/server/no-permissions', (req, res) => {
    res.render('server/no-permissions', {
        user: req.session.user,
        title: 'No Permissions',
        path: '/servers'
    });
});

// User Server Console
app.get('/server/:containerId', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] },
                { model: Image, as: 'image' }
            ]
        });

        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.console')) {
            return res.redirect('/server/no-permissions');
        }

        // Redirect suspended servers to their suspension notice page
        if (server.isSuspended) {
            return res.redirect(`/server/${server.containerId}/suspended`);
        }

        const wsToken = jwt.sign({
            serverId: server.id,
            userId: req.session.user.id,
            isAdmin: Boolean(req.session.user.isAdmin),
            serverPerms: Array.from(access.permissions || [])
        }, SECRET_KEY, { expiresIn: '1h' });

        res.render('server/console', {
            server,
            user: req.session.user,
            title: `Manage ${server.name}`,
            path: '/servers',
            wsToken,
            showMinecraftEulaModal: isServerLikelyMinecraft(server)
        });
    } catch (err) {
        console.error("Error fetching console:", err);
        res.redirect('/?error=Error loading server console');
    }
});

// Server Suspended Page
app.get('/server/:containerId/suspended', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId }
        });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.view')) {
            return res.redirect('/server/no-permissions');
        }
        // If somehow the server is not suspended, redirect to console
        if (!server.isSuspended) {
            return res.redirect(`/server/${server.containerId}`);
        }
        res.render('server/suspended', {
            server,
            user: req.session.user,
            title: `Server Suspended - ${server.name}`,
            path: '/servers'
        });
    } catch (err) {
        console.error('Error loading suspended page:', err);
        res.redirect('/?error=Error loading server page');
    }
});

// User Server Overview
app.get('/server/:containerId/overview', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                {
                    model: Allocation,
                    as: 'allocation',
                    include: [{
                        model: Connector,
                        as: 'connector',
                        include: [{ model: Location, as: 'location' }]
                    }]
                },
                { model: Image, as: 'image' }
            ]
        });

        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.view')) {
            return res.redirect('/server/no-permissions');
        }

        let resolvedStartup = server.image ? server.image.startup : '';
        try {
            if (server.image) {
                const runtimeValues = {
                    SERVER_MEMORY: String(server.memory),
                    SERVER_IP: server.allocation ? server.allocation.ip : '',
                    SERVER_PORT: server.allocation ? String(server.allocation.port) : ''
                };
                const built = buildServerEnvironment(server.image, server.variables || {}, runtimeValues);
                resolvedStartup = buildStartupCommand(server.startup || server.image.startup, built.env);
            }
        } catch (error) {
            resolvedStartup = server.startup || (server.image ? server.image.startup : '');
        }

        const wsToken = jwt.sign({
            serverId: server.id,
            userId: req.session.user.id,
            isAdmin: Boolean(req.session.user.isAdmin),
            serverPerms: Array.from(access.permissions || [])
        }, SECRET_KEY, { expiresIn: '1h' });

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        const serverCost = featureFlags.costPerServerEnabled
            ? calculateServerCostEstimate(server, res.locals.settings || {})
            : null;
        const configBaseline = await getServerConfigBaseline(server.id);
        const configDrift = computeServerConfigDrift(server, configBaseline);
        const since24h = new Date(Date.now() - DAY_MS);
        const debugEvents = AuditLog
            ? await AuditLog.findAll({
                where: {
                    targetType: 'server',
                    targetId: String(server.id),
                    action: { [Op.like]: 'server:debug.%' },
                    createdAt: { [Op.gte]: since24h }
                },
                attributes: ['action', 'createdAt', 'metadata'],
                order: [['createdAt', 'DESC']],
                limit: 300
            })
            : [];
        const healthScore = computeServerHealthScore(server, debugEvents, configDrift);

        res.render('server/overview', {
            server,
            user: req.session.user,
            title: `Overview ${server.name}`,
            path: '/servers',
            wsToken,
            resolvedStartup,
            serverCost,
            healthScore,
            configDrift,
            canManageConfigDrift: hasServerPermission(access, 'server.startup'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (err) {
        console.error("Error fetching overview:", err);
        res.redirect('/?error=Error loading server overview');
    }
});

app.post('/server/:containerId/config-drift/baseline', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }

        const snapshot = buildServerConfigSnapshot(server);
        await setServerConfigBaseline(server.id, snapshot);

        if (AuditLog) {
            await AuditLog.create({
                actorUserId: req.session.user.id,
                action: 'server:config_drift.baseline_set',
                targetType: 'server',
                targetId: String(server.id),
                method: req.method,
                path: req.originalUrl,
                ip: String(getRequestIp(req) || '').slice(0, 120) || null,
                userAgent: req.headers && req.headers['user-agent'] ? String(req.headers['user-agent']).slice(0, 1000) : null,
                metadata: {
                    containerId: server.containerId,
                    capturedAtMs: snapshot.capturedAtMs
                }
            }).catch(() => {});
        }

        return res.redirect(`/server/${server.containerId}/overview?success=${encodeURIComponent('Config drift baseline saved.')}`);
    } catch (error) {
        console.error('Error updating config drift baseline:', error);
        return res.redirect(`/server/${req.params.containerId}/overview?error=${encodeURIComponent('Failed to save config drift baseline.')}`);
    }
});

app.get('/server/:containerId/users', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Image, as: 'image' }]
        });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.users.view')) {
            return res.redirect('/server/no-permissions');
        }

        const [owner, memberships, allUsers] = await Promise.all([
            User.findByPk(server.ownerId, { attributes: ['id', 'username', 'email'] }),
            ServerSubuser.findAll({
                where: { serverId: server.id },
                include: [
                    { model: User, as: 'user', attributes: ['id', 'username', 'email'] },
                    { model: User, as: 'invitedBy', attributes: ['id', 'username'], required: false }
                ],
                order: [['id', 'DESC']]
            }),
            User.findAll({
                attributes: ['id', 'username', 'email'],
                order: [['username', 'ASC']]
            })
        ]);

        const membershipIds = new Set(memberships.map((entry) => Number.parseInt(entry.userId, 10)));
        const candidateUsers = allUsers.filter((entry) => Number.parseInt(entry.id, 10) !== Number.parseInt(server.ownerId, 10) && !membershipIds.has(Number.parseInt(entry.id, 10)));

        return res.render('server/users', {
            server,
            user: req.session.user,
            title: `Users ${server.name}`,
            path: '/servers',
            active: 'users',
            owner,
            memberships,
            candidateUsers,
            permissionCatalog: SERVER_PERMISSIONS,
            canManageUsers: hasServerPermission(access, 'server.users.manage'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading server users page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load server users page.'));
    }
});

app.post('/server/:containerId/users', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.users.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const userId = Number.parseInt(req.body.userId, 10);
        const identifier = String(req.body.identifier || '').trim();
        let targetUser = null;
        if (Number.isInteger(userId) && userId > 0) {
            targetUser = await User.findByPk(userId, { attributes: ['id', 'username', 'email'] });
        } else if (identifier) {
            targetUser = await User.findOne({
                where: {
                    [Op.or]: [
                        { username: identifier },
                        { email: identifier.toLowerCase() }
                    ]
                },
                attributes: ['id', 'username', 'email']
            });
        }

        if (!targetUser) {
            return res.redirect(`/server/${server.containerId}/users?error=${encodeURIComponent('User not found.')}`);
        }
        if (Number.parseInt(targetUser.id, 10) === Number.parseInt(server.ownerId, 10)) {
            return res.redirect(`/server/${server.containerId}/users?error=${encodeURIComponent('Server owner cannot be added as subuser.')}`);
        }

        const requestedPermissions = normalizeServerPermissionList(Array.isArray(req.body.permissions) ? req.body.permissions : [req.body.permissions].filter(Boolean));
        if (!requestedPermissions.includes('server.view')) {
            requestedPermissions.unshift('server.view');
        }

        const existing = await ServerSubuser.findOne({
            where: { serverId: server.id, userId: targetUser.id }
        });

        if (existing) {
            await existing.update({
                permissions: requestedPermissions,
                invitedByUserId: req.session.user.id
            });
        } else {
            await ServerSubuser.create({
                serverId: server.id,
                userId: targetUser.id,
                invitedByUserId: req.session.user.id,
                permissions: requestedPermissions
            });
        }

        return res.redirect(`/server/${server.containerId}/users?success=${encodeURIComponent(`Subuser updated for ${targetUser.username}.`)}`);
    } catch (error) {
        console.error('Error saving subuser:', error);
        return res.redirect(`/server/${req.params.containerId}/users?error=${encodeURIComponent('Failed to save subuser permissions.')}`);
    }
});

app.post('/server/:containerId/users/:subuserId/delete', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.users.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const subuserId = Number.parseInt(req.params.subuserId, 10);
        if (!Number.isInteger(subuserId) || subuserId <= 0) {
            return res.redirect(`/server/${server.containerId}/users?error=${encodeURIComponent('Invalid subuser id.')}`);
        }

        const membership = await ServerSubuser.findOne({
            where: { id: subuserId, serverId: server.id }
        });
        if (!membership) {
            return res.redirect(`/server/${server.containerId}/users?error=${encodeURIComponent('Subuser not found.')}`);
        }

        await membership.destroy();
        return res.redirect(`/server/${server.containerId}/users?success=${encodeURIComponent('Subuser removed successfully.')}`);
    } catch (error) {
        console.error('Error removing subuser:', error);
        return res.redirect(`/server/${req.params.containerId}/users?error=${encodeURIComponent('Failed to remove subuser.')}`);
    }
});

app.get('/server/:containerId/api', requireAuth, async (req, res) => {
    try {
        if (!ServerApiKey) {
            return res.redirect(`/server/${req.params.containerId}/overview?error=${encodeURIComponent('Server API keys are not available in this build.')}`);
        }

        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.users.view')) {
            return res.redirect('/server/no-permissions');
        }

        const [keys, owner] = await Promise.all([
            ServerApiKey.findAll({
                where: { serverId: server.id },
                include: [{ model: User, as: 'owner', attributes: ['id', 'username', 'email'] }],
                order: [['createdAt', 'DESC']]
            }),
            User.findByPk(server.ownerId, { attributes: ['id', 'username', 'email'] })
        ]);

        let freshToken = null;
        const pending = req.session.newServerApiKey;
        if (pending && Number.parseInt(pending.serverId, 10) === Number.parseInt(server.id, 10)) {
            freshToken = {
                name: String(pending.name || 'New API key'),
                token: String(pending.token || '')
            };
            delete req.session.newServerApiKey;
            await new Promise((resolve) => req.session.save(() => resolve()));
        }

        const apiKeys = keys.map((entry) => ({
            id: entry.id,
            name: entry.name,
            keyPrefixMasked: formatServerApiKeyMaskedPrefix(entry.keyPrefix),
            permissions: normalizeServerApiPermissionList(entry.permissions),
            revokedAt: entry.revokedAt,
            expiresAt: entry.expiresAt,
            lastUsedAt: entry.lastUsedAt,
            lastUsedIp: entry.lastUsedIp,
            createdAt: entry.createdAt,
            owner: entry.owner ? {
                id: entry.owner.id,
                username: entry.owner.username,
                email: entry.owner.email
            } : null,
            active: typeof isServerApiKeyActive === 'function'
                ? isServerApiKeyActive(entry)
                : !entry.revokedAt
        }));

        return res.render('server/api-keys', {
            server,
            user: req.session.user,
            title: `API Keys ${server.name}`,
            path: '/servers',
            active: 'api',
            owner,
            apiKeys,
            freshToken,
            apiPermissionCatalog: SERVER_API_KEY_PERMISSIONS,
            canManageApiKeys: hasServerPermission(access, 'server.users.manage'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading server API keys page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load server API keys page.'));
    }
});

app.post('/server/:containerId/api-keys', requireAuth, async (req, res) => {
    try {
        if (!ServerApiKey) {
            return res.redirect(`/server/${req.params.containerId}/api?error=${encodeURIComponent('Server API keys are not available in this build.')}`);
        }

        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.users.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const name = String(req.body.name || '').trim().slice(0, 120);
        if (!name) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('API key name is required.')}`);
        }

        const permissionsInput = Array.isArray(req.body.permissions)
            ? req.body.permissions
            : [req.body.permissions].filter(Boolean);
        const permissions = normalizeServerApiPermissionList(permissionsInput);
        if (!permissions.includes('server.view')) {
            permissions.unshift('server.view');
        }

        const expiresAt = normalizeServerApiKeyExpiry(req.body.expiresAt);
        if (req.body.expiresAt && !expiresAt) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('Invalid expiration date.')}`);
        }
        if (expiresAt && expiresAt.getTime() <= Date.now()) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('Expiration date must be in the future.')}`);
        }

        const generated = typeof generateServerApiKeyToken === 'function'
            ? generateServerApiKeyToken()
            : null;
        if (!generated || !generated.token) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('Failed to generate API key token.')}`);
        }
        const keyHash = typeof hashServerApiKeyToken === 'function'
            ? hashServerApiKeyToken(generated.token, SECRET_KEY)
            : '';
        if (!keyHash) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('Failed to hash API key token.')}`);
        }

        await ServerApiKey.create({
            serverId: server.id,
            ownerUserId: req.session.user.id,
            name,
            keyPrefix: generated.keyPrefix,
            keyHash,
            permissions,
            expiresAt: expiresAt || null
        });

        req.session.newServerApiKey = {
            serverId: server.id,
            name,
            token: generated.token
        };
        await new Promise((resolve) => req.session.save(() => resolve()));

        return res.redirect(`/server/${server.containerId}/api?success=${encodeURIComponent('Server API key created. Copy it now; it will not be shown again.')}`);
    } catch (error) {
        console.error('Error creating server API key:', error);
        return res.redirect(`/server/${req.params.containerId}/api?error=${encodeURIComponent('Failed to create server API key.')}`);
    }
});

app.post('/server/:containerId/api-keys/:keyId/revoke', requireAuth, async (req, res) => {
    try {
        if (!ServerApiKey) {
            return res.redirect(`/server/${req.params.containerId}/api?error=${encodeURIComponent('Server API keys are not available in this build.')}`);
        }

        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.users.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const keyId = Number.parseInt(req.params.keyId, 10);
        if (!Number.isInteger(keyId) || keyId <= 0) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('Invalid API key id.')}`);
        }

        const key = await ServerApiKey.findOne({
            where: {
                id: keyId,
                serverId: server.id
            }
        });
        if (!key) {
            return res.redirect(`/server/${server.containerId}/api?error=${encodeURIComponent('API key not found.')}`);
        }

        await key.update({ revokedAt: new Date() });
        return res.redirect(`/server/${server.containerId}/api?success=${encodeURIComponent('API key revoked successfully.')}`);
    } catch (error) {
        console.error('Error revoking server API key:', error);
        return res.redirect(`/server/${req.params.containerId}/api?error=${encodeURIComponent('Failed to revoke API key.')}`);
    }
});

app.get('/server/:containerId/activity', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.activity.view')) {
            return res.redirect('/server/no-permissions');
        }

        const logs = await AuditLog.findAll({
            where: {
                [Op.or]: [
                    { targetType: 'server', targetId: String(server.id) },
                    { targetId: String(server.id) },
                    { path: { [Op.like]: `%/server/${server.containerId}%` } }
                ]
            },
            include: [{ model: User, as: 'actor', attributes: ['id', 'username', 'email'], required: false }],
            order: [['createdAt', 'DESC']],
            limit: 250
        });

        return res.render('server/activity', {
            server,
            user: req.session.user,
            title: `Activity ${server.name}`,
            path: '/servers',
            active: 'activity',
            logs
        });
    } catch (error) {
        console.error('Error loading server activity:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load server activity.'));
    }
});

app.get('/server/:containerId/debug-logs', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.console') && !hasServerPermission(access, 'server.activity.view')) {
            return res.redirect('/server/no-permissions');
        }

        const rawLogs = await AuditLog.findAll({
            where: {
                targetType: 'server',
                targetId: String(server.id),
                action: { [Op.like]: 'server:debug.%' }
            },
            order: [['createdAt', 'DESC']],
            limit: 120
        });

        const logs = rawLogs.map((entry) => {
            const metadata = (entry && entry.metadata && typeof entry.metadata === 'object') ? entry.metadata : {};
            const action = String(entry.action || 'server:debug.unknown');
            const rawTail = typeof metadata.logTail === 'string' ? metadata.logTail : '';
            const logTail = rawTail.length > 128000 ? rawTail.slice(-128000) : rawTail;
            let severity = 'secondary';
            if (action.includes('.crash') || action.includes('.install_fail')) severity = 'danger';
            else if (action.includes('.connector_error') || action.includes('.event.die') || action.includes('.event.kill')) severity = 'warning';
            else if (action.includes('.stop')) severity = 'info';

            return {
                id: entry.id,
                createdAt: entry.createdAt,
                action,
                severity,
                metadata,
                logTail
            };
        });

        return res.render('server/debug-logs', {
            server,
            user: req.session.user,
            title: `Debug Logs ${server.name}`,
            path: '/servers',
            active: 'debuglogs',
            logs
        });
    } catch (error) {
        console.error('Error loading debug logs page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load server debug logs.'));
    }
});

app.get('/server/:containerId/backups', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{
                model: Allocation,
                as: 'allocation',
                include: [{ model: Connector, as: 'connector' }]
            }]
        });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.backups.view')) {
            return res.redirect('/server/no-permissions');
        }

        const connector = server.allocation && server.allocation.connector ? server.allocation.connector : null;
        const sftpHost = connector ? String(connector.fqdn || '').trim() : '';
        const parsedSftpPort = connector ? Number.parseInt(connector.sftpPort, 10) : NaN;
        const sftpEnabledRaw = String((res.locals.settings && res.locals.settings.featureSftpEnabled) || 'true').trim().toLowerCase();
        const sftpEnabled = sftpEnabledRaw === 'true' || sftpEnabledRaw === '1' || sftpEnabledRaw === 'on' || sftpEnabledRaw === 'yes';
        const sftpDetails = {
            host: sftpHost,
            port: Number.isInteger(parsedSftpPort) ? parsedSftpPort : null,
            username: buildSftpUsernameForServer(req.session.user, server),
            passwordHint: 'Use your account password from this panel.',
            available: sftpEnabled && !server.isSuspended && Boolean(sftpHost) && Number.isInteger(parsedSftpPort)
        };

        return res.render('server/backups', {
            server,
            user: req.session.user,
            title: `SFTP Backup ${server.name}`,
            path: '/servers',
            active: 'backups',
            sftpDetails,
            sftpFeatureEnabled: sftpEnabled,
            canManageBackups: hasServerPermission(access, 'server.backups.manage'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading backups page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load backups page.'));
    }
});

app.post('/server/:containerId/backups/policy', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.backups.manage')) {
            return res.redirect('/server/no-permissions');
        }
        return res.redirect(`/server/${server.containerId}/backups?error=${encodeURIComponent('Built-in backup policy is disabled. Use SFTP backup workflow instead.')}`);
    } catch (error) {
        console.error('Error updating backup policy:', error);
        return res.redirect(`/server/${req.params.containerId}/backups?error=${encodeURIComponent('Failed to update backup policy.')}`);
    }
});

app.post('/server/:containerId/backups/run', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.backups.manage')) {
            return res.redirect('/server/no-permissions');
        }
        return res.redirect(`/server/${server.containerId}/backups?error=${encodeURIComponent('Built-in backup jobs are disabled. Use SFTP backup workflow instead.')}`);
    } catch (error) {
        console.error('Error queuing backup:', error);
        return res.redirect(`/server/${req.params.containerId}/backups?error=${encodeURIComponent('Failed to queue backup.')}`);
    }
});

app.get('/server/:containerId/backups/download/:backupId', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.backups.view')) {
            return res.redirect('/server/no-permissions');
        }

        return res.redirect(`/server/${server.containerId}/backups?error=${encodeURIComponent('Built-in backup downloads are disabled. Use SFTP to download backup archives.')}`);
    } catch (error) {
        console.error('Error downloading backup:', error);
        return res.redirect(`/server/${req.params.containerId}/backups?error=${encodeURIComponent('Failed to download backup.')}`);
    }
});

app.post('/server/:containerId/backups/delete/:backupId', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.backups.manage')) {
            return res.redirect('/server/no-permissions');
        }

        return res.redirect(`/server/${server.containerId}/backups?error=${encodeURIComponent('Built-in backup delete is disabled. Manage backup files through SFTP.')}`);
    } catch (error) {
        console.error('Error deleting backup:', error);
        return res.redirect(`/server/${req.params.containerId}/backups?error=${encodeURIComponent('Failed to delete backup.')}`);
    }
});

app.get('/server/:containerId/network', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] }]
        });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.network.view')) {
            return res.redirect('/server/no-permissions');
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        const inventoryEnabled = Boolean(featureFlags.inventoryEnabled);
        const primaryAllocationId = Number.parseInt(server.allocationId, 10) || (server.allocation ? server.allocation.id : 0);
        const connectorId = server.allocation ? Number.parseInt(server.allocation.connectorId, 10) : 0;
        let assignedAllocations = [];
        let availableAllocations = [];
        if (Number.isInteger(server.id) && server.id > 0) {
            assignedAllocations = await Allocation.findAll({
                where: { serverId: server.id },
                order: [['port', 'ASC'], ['id', 'ASC']]
            });
        }
        if (Number.isInteger(connectorId) && connectorId > 0) {
            availableAllocations = await Allocation.findAll({
                where: { connectorId, serverId: null },
                order: [['port', 'ASC'], ['id', 'ASC']],
                limit: 1000
            });
        }

        assignedAllocations.sort((left, right) => {
            const leftPrimary = Number.parseInt(left.id, 10) === primaryAllocationId;
            const rightPrimary = Number.parseInt(right.id, 10) === primaryAllocationId;
            if (leftPrimary && !rightPrimary) return -1;
            if (!leftPrimary && rightPrimary) return 1;
            return (Number.parseInt(left.port, 10) || 0) - (Number.parseInt(right.port, 10) || 0);
        });

        const additionalAssignedCount = assignedAllocations.filter((entry) => Number.parseInt(entry.id, 10) !== primaryAllocationId).length;
        const ownerInventory = inventoryEnabled
            ? await getUserInventoryState(server.ownerId)
            : defaultUserInventoryState();
        const allocationTokens = inventoryEnabled ? Math.max(0, Number.parseInt(ownerInventory.allocations, 10) || 0) : 0;
        const remainingAssignable = inventoryEnabled ? Math.max(0, allocationTokens - additionalAssignedCount) : 0;
        const inventoryAssignBlockedReason = !inventoryEnabled
            ? 'Inventory mode is disabled by admin. Additional allocation assign is unavailable.'
            : (remainingAssignable <= 0
                ? `No allocation tokens left. Tokens: ${allocationTokens}, already assigned additional allocations: ${additionalAssignedCount}.`
                : '');

        if (inventoryEnabled && remainingAssignable >= 0 && availableAllocations.length > remainingAssignable) {
            availableAllocations = availableAllocations.slice(0, remainingAssignable);
        }

        return res.render('server/network', {
            server,
            user: req.session.user,
            title: `Network ${server.name}`,
            path: '/servers',
            active: 'network',
            canManageNetwork: hasServerPermission(access, 'server.network.manage'),
            assignedAllocations,
            availableAllocations,
            primaryAllocationId,
            inventoryEnabled,
            allocationTokens,
            additionalAssignedCount,
            remainingAssignable,
            inventoryAssignBlockedReason,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading network page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load network page.'));
    }
});

app.post('/server/:containerId/network/allocations', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.network.manage')) {
            return res.redirect('/server/no-permissions');
        }
        if (!server.allocation) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('No allocation linked to this server.')}`);
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.inventoryEnabled) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Inventory mode is disabled by admin. Additional allocation assign is unavailable.')}`);
        }

        const primaryAllocationId = Number.parseInt(server.allocationId, 10) || Number.parseInt(server.allocation.id, 10) || 0;
        const additionalAssignedCount = await Allocation.count({
            where: {
                serverId: server.id,
                id: { [Op.ne]: primaryAllocationId }
            }
        });
        const ownerInventory = await getUserInventoryState(server.ownerId);
        const allocationTokens = Math.max(0, Number.parseInt(ownerInventory.allocations, 10) || 0);
        if (additionalAssignedCount >= allocationTokens) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent(`No allocation tokens left. Tokens: ${allocationTokens}, already assigned additional allocations: ${additionalAssignedCount}.`)}`);
        }

        const allocationId = Number.parseInt(req.body.allocationId, 10);
        if (!Number.isInteger(allocationId) || allocationId <= 0) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Invalid allocation id.')}`);
        }

        const allocation = await Allocation.findByPk(allocationId);
        if (!allocation) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Allocation not found.')}`);
        }

        if (Number.parseInt(allocation.connectorId, 10) !== Number.parseInt(server.allocation.connectorId, 10)) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Allocation is not on this server node.')}`);
        }

        if (allocation.serverId && Number.parseInt(allocation.serverId, 10) !== Number.parseInt(server.id, 10)) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Allocation is already assigned to another server.')}`);
        }

        if (Number.parseInt(allocation.serverId, 10) === Number.parseInt(server.id, 10)) {
            return res.redirect(`/server/${server.containerId}/network?success=${encodeURIComponent('Allocation is already assigned to this server.')}`);
        }

        await allocation.update({ serverId: server.id });

        return res.redirect(`/server/${server.containerId}/network?success=${encodeURIComponent('Additional allocation assigned. Reinstall/restart may be required for full runtime apply.')}`);
    } catch (error) {
        console.error('Error assigning additional allocation:', error);
        return res.redirect(`/server/${req.params.containerId}/network?error=${encodeURIComponent('Failed to assign allocation.')}`);
    }
});

app.post('/server/:containerId/network/allocations/:allocationId/delete', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.network.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const allocationId = Number.parseInt(req.params.allocationId, 10);
        if (!Number.isInteger(allocationId) || allocationId <= 0) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Invalid allocation id.')}`);
        }

        const allocation = await Allocation.findOne({
            where: {
                id: allocationId,
                serverId: server.id
            }
        });
        if (!allocation) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Allocation is not assigned to this server.')}`);
        }

        const primaryAllocationId = Number.parseInt(server.allocationId, 10) || (server.allocation ? Number.parseInt(server.allocation.id, 10) : 0);
        if (primaryAllocationId === allocation.id) {
            return res.redirect(`/server/${server.containerId}/network?error=${encodeURIComponent('Primary allocation cannot be removed.')}`);
        }

        await allocation.update({ serverId: null });

        return res.redirect(`/server/${server.containerId}/network?success=${encodeURIComponent('Additional allocation removed.')}`);
    } catch (error) {
        console.error('Error removing additional allocation:', error);
        return res.redirect(`/server/${req.params.containerId}/network?error=${encodeURIComponent('Failed to remove allocation.')}`);
    }
});

function sanitizeDatabaseObjectName(value, fallback = 'db', maxLen = 48) {
    const source = String(value || '').trim().toLowerCase();
    const clean = source.replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    const normalized = (clean || String(fallback || 'db')).slice(0, Math.max(4, maxLen));
    return normalized || 'db';
}

function trimIdentifierLength(value, maxLen) {
    return String(value || '').slice(0, Math.max(4, Number.parseInt(maxLen, 10) || 32));
}

function buildUniqueDatabaseObjectName(baseValue, usedNames, maxLen) {
    const used = usedNames instanceof Set ? usedNames : new Set();
    const normalizedBase = trimIdentifierLength(sanitizeDatabaseObjectName(baseValue, 'db', maxLen), maxLen);
    if (!used.has(normalizedBase)) return normalizedBase;

    for (let i = 0; i < 24; i += 1) {
        const suffix = nodeCrypto.randomBytes(2).toString('hex');
        const candidateBase = trimIdentifierLength(normalizedBase, maxLen - (suffix.length + 1));
        const candidate = trimIdentifierLength(`${candidateBase}_${suffix}`, maxLen);
        if (!used.has(candidate)) return candidate;
    }

    return trimIdentifierLength(`${normalizedBase}_${Date.now().toString(36)}`, maxLen);
}

function getDatabaseHostDialect(hostType) {
    const normalized = String(hostType || '').trim().toLowerCase();
    if (normalized === 'postgres' || normalized === 'postgresql') return 'postgres';
    if (normalized === 'mariadb') return 'mariadb';
    return 'mysql';
}

function getDatabaseNameMaxLen(hostType) {
    return getDatabaseHostDialect(hostType) === 'postgres' ? 63 : 64;
}

function getDatabaseUserMaxLen(hostType) {
    return getDatabaseHostDialect(hostType) === 'postgres' ? 63 : 32;
}

function quoteMysqlIdentifier(value) {
    return `\`${String(value || '').replace(/`/g, '``')}\``;
}

function quotePgIdentifier(value) {
    return `"${String(value || '').replace(/"/g, '""')}"`;
}

function escapeSqlLiteral(value) {
    return `'${String(value === undefined || value === null ? '' : value)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "''")}'`;
}

async function withDatabaseHostConnection(host, callback) {
    const dialect = getDatabaseHostDialect(host && host.type);
    const hostPort = Math.max(1, Number.parseInt(host && host.port, 10) || (dialect === 'postgres' ? 5432 : 3306));
    const rootDatabase = String(host && host.database
        ? host.database
        : (dialect === 'postgres' ? 'postgres' : 'mysql')).trim();

    const dbClient = new Sequelize(
        rootDatabase,
        String(host && host.username ? host.username : ''),
        String(host && host.password ? host.password : ''),
        {
            host: String(host && host.host ? host.host : ''),
            port: hostPort,
            dialect,
            logging: false,
            dialectOptions: { connectTimeout: 10000 }
        }
    );

    try {
        await dbClient.authenticate();
        return await callback(dbClient, dialect);
    } finally {
        try {
            await dbClient.close();
        } catch {
            // Best effort cleanup.
        }
    }
}

async function provisionServerDatabaseOnHost(host, { databaseName, databaseUser, databasePassword }) {
    return withDatabaseHostConnection(host, async (dbClient, dialect) => {
        if (dialect === 'postgres') {
            const dbName = quotePgIdentifier(databaseName);
            const roleName = quotePgIdentifier(databaseUser);
            const roleNameLiteral = escapeSqlLiteral(databaseUser);
            const rolePassLiteral = escapeSqlLiteral(databasePassword);
            const dbNameLiteral = escapeSqlLiteral(databaseName);
            const rows = await dbClient.query(
                `SELECT 1 FROM pg_database WHERE datname = ${dbNameLiteral} LIMIT 1`,
                { type: Sequelize.QueryTypes.SELECT }
            );
            if (!Array.isArray(rows) || rows.length === 0) {
                await dbClient.query(`CREATE DATABASE ${dbName}`);
            }
            await dbClient.query(
                `DO $$ BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${roleNameLiteral}) THEN
                        CREATE ROLE ${roleName} LOGIN PASSWORD ${rolePassLiteral};
                    ELSE
                        ALTER ROLE ${roleName} WITH LOGIN PASSWORD ${rolePassLiteral};
                    END IF;
                END $$;`
            );
            await dbClient.query(`GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${roleName}`);
            return;
        }

        const dbName = quoteMysqlIdentifier(databaseName);
        const userLiteral = escapeSqlLiteral(databaseUser);
        const passLiteral = escapeSqlLiteral(databasePassword);
        await dbClient.query(`CREATE DATABASE IF NOT EXISTS ${dbName}`);
        await dbClient.query(`CREATE USER IF NOT EXISTS ${userLiteral}@'%' IDENTIFIED BY ${passLiteral}`);
        await dbClient.query(`ALTER USER ${userLiteral}@'%' IDENTIFIED BY ${passLiteral}`);
        await dbClient.query(`GRANT ALL PRIVILEGES ON ${dbName}.* TO ${userLiteral}@'%'`);
        await dbClient.query('FLUSH PRIVILEGES');
    });
}

async function rotateServerDatabaseUserPasswordOnHost(host, dbUser, nextPassword) {
    return withDatabaseHostConnection(host, async (dbClient, dialect) => {
        if (dialect === 'postgres') {
            await dbClient.query(
                `ALTER ROLE ${quotePgIdentifier(dbUser)} WITH LOGIN PASSWORD ${escapeSqlLiteral(nextPassword)}`
            );
            return;
        }

        const userLiteral = escapeSqlLiteral(dbUser);
        const passLiteral = escapeSqlLiteral(nextPassword);
        await dbClient.query(`ALTER USER ${userLiteral}@'%' IDENTIFIED BY ${passLiteral}`);
        await dbClient.query('FLUSH PRIVILEGES');
    });
}

async function dropServerDatabaseFromHost(host, { databaseName, databaseUser }) {
    return withDatabaseHostConnection(host, async (dbClient, dialect) => {
        if (dialect === 'postgres') {
            const dbNameLiteral = escapeSqlLiteral(databaseName);
            await dbClient.query(
                `SELECT pg_terminate_backend(pid)
                 FROM pg_stat_activity
                 WHERE datname = ${dbNameLiteral} AND pid <> pg_backend_pid()`
            );
            await dbClient.query(`DROP DATABASE IF EXISTS ${quotePgIdentifier(databaseName)}`);
            await dbClient.query(`DROP ROLE IF EXISTS ${quotePgIdentifier(databaseUser)}`);
            return;
        }

        await dbClient.query(`DROP DATABASE IF EXISTS ${quoteMysqlIdentifier(databaseName)}`);
        await dbClient.query(`DROP USER IF EXISTS ${escapeSqlLiteral(databaseUser)}@'%'`);
        await dbClient.query('FLUSH PRIVILEGES');
    });
}

async function resolveServerDatabasesState(containerId) {
    const server = await Server.findOne({
        where: { containerId },
        include: [
            {
                model: Allocation,
                as: 'allocation',
                include: [
                    {
                        model: Connector,
                        as: 'connector',
                        include: [{ model: Location, as: 'location' }]
                    }
                ]
            }
        ]
    });
    if (!server) return null;

    const locationId = Number.parseInt(server && server.allocation && server.allocation.connector
        ? server.allocation.connector.locationId
        : 0, 10) || 0;

    const [hosts, databases] = await Promise.all([
        locationId > 0
            ? DatabaseHost.findAll({
                where: { locationId },
                order: [['name', 'ASC']]
            })
            : Promise.resolve([]),
        ServerDatabase.findAll({
            where: { serverId: server.id },
            include: [{ model: DatabaseHost, as: 'host', required: false }],
            order: [['createdAt', 'DESC']]
        })
    ]);

    return { server, locationId, hosts, databases };
}

app.get('/server/:containerId/databases', requireAuth, async (req, res) => {
    try {
        const state = await resolveServerDatabasesState(req.params.containerId);
        if (!state || !state.server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(state.server, req.session.user);
        if (!hasServerPermission(access, 'server.databases.view') && !hasServerPermission(access, 'server.view')) {
            return res.redirect('/server/no-permissions');
        }

        const databaseLimit = Math.max(0, Number.parseInt(state.server.databaseLimit, 10) || 0);
        return res.render('server/databases', {
            server: state.server,
            user: req.session.user,
            title: `Databases ${state.server.name}`,
            path: '/servers',
            active: 'dbs',
            hosts: state.hosts,
            databases: state.databases,
            locationId: state.locationId,
            databaseLimit,
            canManageDatabases: hasServerPermission(access, 'server.databases.manage'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading databases page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load databases page.'));
    }
});

app.post('/server/:containerId/databases/create', requireAuth, async (req, res) => {
    try {
        const state = await resolveServerDatabasesState(req.params.containerId);
        if (!state || !state.server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(state.server, req.session.user);
        if (!hasServerPermission(access, 'server.databases.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const databaseLimit = Math.max(0, Number.parseInt(state.server.databaseLimit, 10) || 0);
        if (databaseLimit <= 0) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Database slots are 0 for this server. Increase limit from create/store first.')}`);
        }
        if (state.databases.length >= databaseLimit) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Database limit reached for this server.')}`);
        }
        if (!Array.isArray(state.hosts) || state.hosts.length === 0) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('No database host is configured for this server location.')}`);
        }

        const requestedHostId = Number.parseInt(req.body.databaseHostId, 10);
        const selectedHost = state.hosts.find((entry) => Number(entry.id) === requestedHostId) || state.hosts[0];
        if (!selectedHost) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Select a valid database host.')}`);
        }

        const maxDbNameLen = getDatabaseNameMaxLen(selectedHost.type);
        const maxDbUserLen = getDatabaseUserMaxLen(selectedHost.type);
        const requestedDatabaseName = sanitizeDatabaseObjectName(req.body.databaseName, 'db', 24);
        const requestedDatabaseUser = sanitizeDatabaseObjectName(req.body.databaseUser, 'user', 24);
        const dbNameBase = sanitizeDatabaseObjectName(`s${state.server.id}_${requestedDatabaseName}`, `s${state.server.id}_db`, maxDbNameLen);
        const dbUserBase = sanitizeDatabaseObjectName(`u${state.server.id}_${requestedDatabaseUser}`, `u${state.server.id}_user`, maxDbUserLen);

        const hostEntries = await ServerDatabase.findAll({
            where: { databaseHostId: selectedHost.id },
            attributes: ['name', 'username']
        });
        const usedNames = new Set(hostEntries.map((entry) => String(entry.name || '').toLowerCase()));
        const usedUsers = new Set(hostEntries.map((entry) => String(entry.username || '').toLowerCase()));
        const databaseName = buildUniqueDatabaseObjectName(dbNameBase, usedNames, maxDbNameLen);
        const databaseUser = buildUniqueDatabaseObjectName(dbUserBase, usedUsers, maxDbUserLen);
        const providedPassword = String(req.body.databasePassword || '').trim();
        const databasePassword = providedPassword
            ? providedPassword.slice(0, 128)
            : nodeCrypto.randomBytes(12).toString('base64url').slice(0, 20);

        await provisionServerDatabaseOnHost(selectedHost, {
            databaseName,
            databaseUser,
            databasePassword
        });

        await ServerDatabase.create({
            serverId: state.server.id,
            databaseHostId: selectedHost.id,
            name: databaseName,
            username: databaseUser,
            password: databasePassword,
            remoteDatabaseId: `${selectedHost.type}:${selectedHost.host}:${selectedHost.port}:${databaseName}`
        });

        await createBillingAuditLog({
            actorUserId: req.session.user.id,
            action: 'server.database.create',
            targetType: 'server',
            targetId: state.server.id,
            req,
            metadata: {
                serverId: state.server.id,
                serverContainerId: state.server.containerId,
                databaseHostId: selectedHost.id,
                databaseName,
                databaseUser
            }
        });

        return res.redirect(`/server/${state.server.containerId}/databases?success=${encodeURIComponent(`Database ${databaseName} created on host ${selectedHost.name}.`)}`);
    } catch (error) {
        console.error('Error creating server database:', error);
        return res.redirect(`/server/${req.params.containerId}/databases?error=${encodeURIComponent(error.message || 'Failed to create database.')}`);
    }
});

app.post('/server/:containerId/databases/:databaseId/password', requireAuth, async (req, res) => {
    try {
        const state = await resolveServerDatabasesState(req.params.containerId);
        if (!state || !state.server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(state.server, req.session.user);
        if (!hasServerPermission(access, 'server.databases.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const databaseId = Number.parseInt(req.params.databaseId, 10);
        if (!Number.isInteger(databaseId) || databaseId <= 0) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Invalid database id.')}`);
        }

        const entry = await ServerDatabase.findOne({
            where: { id: databaseId, serverId: state.server.id },
            include: [{ model: DatabaseHost, as: 'host', required: false }]
        });
        if (!entry || !entry.host) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Database entry not found.')}`);
        }

        const nextPasswordRaw = String(req.body.newPassword || '').trim();
        const nextPassword = nextPasswordRaw
            ? nextPasswordRaw.slice(0, 128)
            : nodeCrypto.randomBytes(12).toString('base64url').slice(0, 20);

        await rotateServerDatabaseUserPasswordOnHost(entry.host, entry.username, nextPassword);
        await entry.update({ password: nextPassword });

        await createBillingAuditLog({
            actorUserId: req.session.user.id,
            action: 'server.database.password_rotate',
            targetType: 'server',
            targetId: state.server.id,
            req,
            metadata: {
                serverId: state.server.id,
                serverContainerId: state.server.containerId,
                databaseId: entry.id,
                databaseName: entry.name,
                databaseUser: entry.username
            }
        });

        return res.redirect(`/server/${state.server.containerId}/databases?success=${encodeURIComponent(`Password rotated for ${entry.name}.`)}`);
    } catch (error) {
        console.error('Error rotating database password:', error);
        return res.redirect(`/server/${req.params.containerId}/databases?error=${encodeURIComponent(error.message || 'Failed to rotate password.')}`);
    }
});

app.post('/server/:containerId/databases/:databaseId/delete', requireAuth, async (req, res) => {
    try {
        const state = await resolveServerDatabasesState(req.params.containerId);
        if (!state || !state.server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(state.server, req.session.user);
        if (!hasServerPermission(access, 'server.databases.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const databaseId = Number.parseInt(req.params.databaseId, 10);
        if (!Number.isInteger(databaseId) || databaseId <= 0) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Invalid database id.')}`);
        }

        const entry = await ServerDatabase.findOne({
            where: { id: databaseId, serverId: state.server.id },
            include: [{ model: DatabaseHost, as: 'host', required: false }]
        });
        if (!entry || !entry.host) {
            return res.redirect(`/server/${state.server.containerId}/databases?error=${encodeURIComponent('Database entry not found.')}`);
        }

        await dropServerDatabaseFromHost(entry.host, {
            databaseName: entry.name,
            databaseUser: entry.username
        });
        await entry.destroy();

        await createBillingAuditLog({
            actorUserId: req.session.user.id,
            action: 'server.database.delete',
            targetType: 'server',
            targetId: state.server.id,
            req,
            metadata: {
                serverId: state.server.id,
                serverContainerId: state.server.containerId,
                databaseId,
                databaseName: entry.name,
                databaseUser: entry.username
            }
        });

        return res.redirect(`/server/${state.server.containerId}/databases?success=${encodeURIComponent(`Database ${entry.name} deleted.`)}`);
    } catch (error) {
        console.error('Error deleting server database:', error);
        return res.redirect(`/server/${req.params.containerId}/databases?error=${encodeURIComponent(error.message || 'Failed to delete database.')}`);
    }
});

app.get('/server/:containerId/schedules', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.schedules.view')) {
            return res.redirect('/server/no-permissions');
        }

        const schedules = await getServerSchedules(server.id);
        return res.render('server/schedules', {
            server,
            user: req.session.user,
            title: `Schedules ${server.name}`,
            path: '/servers',
            active: 'schedules',
            schedules,
            canManageSchedules: hasServerPermission(access, 'server.schedules.manage'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading schedules page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load schedules page.'));
    }
});

app.post('/server/:containerId/schedules', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.schedules.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const name = String(req.body.name || '').trim().slice(0, 80);
        const action = String(req.body.action || '').trim().toLowerCase();
        const cron = String(req.body.cron || '* * * * *').trim().slice(0, 120);
        const payload = String(req.body.payload || '').trim().slice(0, 1024);
        const enabled = parseBooleanInput(req.body.enabled, true);
        const onlyWhenOnline = parseBooleanInput(req.body.onlyWhenOnline, false);

        if (!name) {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Schedule name is required.')}`);
        }
        if (!['command', 'power'].includes(action)) {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Invalid schedule action.')}`);
        }
        if (!isLikelyCronExpression(cron)) {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Invalid cron expression format. Use 5 fields (e.g. */5 * * * *).')}`);
        }
        if (action === 'command' && !payload) {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Command payload is required for command schedules.')}`);
        }
        if (action === 'power' && !['start', 'stop', 'restart', 'kill'].includes(payload)) {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Power payload must be start, stop, restart or kill.')}`);
        }

        const current = await getServerSchedules(server.id);
        current.unshift({
            id: nodeCrypto.randomBytes(6).toString('hex'),
            name,
            action,
            cron,
            payload,
            enabled,
            onlyWhenOnline,
            createdByUserId: req.session.user.id,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            lastRunAt: null
        });
        await setServerSchedules(server.id, current.slice(0, 200));

        return res.redirect(`/server/${server.containerId}/schedules?success=${encodeURIComponent('Schedule saved successfully.')}`);
    } catch (error) {
        console.error('Error saving schedule:', error);
        return res.redirect(`/server/${req.params.containerId}/schedules?error=${encodeURIComponent('Failed to save schedule.')}`);
    }
});

app.post('/server/:containerId/schedules/:scheduleId/run', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.schedules.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const schedules = await getServerSchedules(server.id);
        const schedule = schedules.find((entry) => String(entry.id) === String(req.params.scheduleId));
        if (!schedule) {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Schedule not found.')}`);
        }

        if (schedule.action === 'backup') {
            return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Backup schedule action is disabled. Use command/power schedules and SFTP for backup workflows.')}`);
        } else {
            if (!server.allocation || !server.allocation.connectorId) {
                return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Server allocation is missing.')}`);
            }
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
                return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Connector is offline.')}`);
            }
            if (schedule.action === 'command') {
                const command = String(schedule.payload || '').trim();
                connectorWs.send(JSON.stringify({
                    type: 'server_schedule_action',
                    serverId: server.id,
                    scheduleAction: 'command',
                    payload: command,
                    command
                }));
            } else if (schedule.action === 'power') {
                const action = String(schedule.payload || '').trim().toLowerCase();
                if (!['start', 'stop', 'restart', 'kill'].includes(action)) {
                    return res.redirect(`/server/${server.containerId}/schedules?error=${encodeURIComponent('Invalid power action payload.')}`);
                }
                connectorWs.send(JSON.stringify({
                    type: 'server_schedule_action',
                    serverId: server.id,
                    scheduleAction: 'power',
                    payload: action,
                    powerAction: action
                }));
            }
        }

        schedule.lastRunAt = new Date().toISOString();
        schedule.updatedAt = new Date().toISOString();
        await setServerSchedules(server.id, schedules);
        return res.redirect(`/server/${server.containerId}/schedules?success=${encodeURIComponent(`Schedule "${schedule.name}" executed.`)}`);
    } catch (error) {
        console.error('Error running schedule:', error);
        return res.redirect(`/server/${req.params.containerId}/schedules?error=${encodeURIComponent('Failed to run schedule.')}`);
    }
});

app.post('/server/:containerId/schedules/:scheduleId/delete', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.schedules.manage')) {
            return res.redirect('/server/no-permissions');
        }

        const schedules = await getServerSchedules(server.id);
        const next = schedules.filter((entry) => String(entry.id) !== String(req.params.scheduleId));
        await setServerSchedules(server.id, next);
        return res.redirect(`/server/${server.containerId}/schedules?success=${encodeURIComponent('Schedule deleted successfully.')}`);
    } catch (error) {
        console.error('Error deleting schedule:', error);
        return res.redirect(`/server/${req.params.containerId}/schedules?error=${encodeURIComponent('Failed to delete schedule.')}`);
    }
});

app.get('/server/:containerId/scaling', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.scheduledScalingEnabled) {
            return res.redirect(`/server/${req.params.containerId}/overview?error=${encodeURIComponent('Scheduled scaling is disabled by admin.')}`);
        }

        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }

        const scalingConfig = await getServerScheduledScalingConfigSafe(server.id);
        const inventoryEnabled = Boolean(featureFlags.inventoryEnabled);
        const ownerInventory = inventoryEnabled
            ? await getUserInventoryState(server.ownerId)
            : defaultUserInventoryState();
        return res.render('server/scaling', {
            server,
            user: req.session.user,
            title: `Scaling ${server.name}`,
            path: '/servers',
            active: 'scaling',
            scalingConfig,
            inventoryEnabled,
            ownerInventory,
            canManageScaling: hasServerPermission(access, 'server.startup'),
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading scheduled scaling page:', error);
        return res.redirect('/?error=' + encodeURIComponent('Failed to load scheduled scaling page.'));
    }
});

app.post('/server/:containerId/scaling/settings', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.scheduledScalingEnabled) {
            return res.redirect(`/server/${req.params.containerId}/overview?error=${encodeURIComponent('Scheduled scaling is disabled by admin.')}`);
        }

        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }

        const current = await getServerScheduledScalingConfigSafe(server.id);
        const timezone = resolveSafeTimezone(req.body.timezone, current.timezone || 'UTC');
        await setServerScheduledScalingConfigSafe(server.id, {
            ...current,
            enabled: parseBooleanInput(req.body.enabled, false),
            timezone
        });

        return res.redirect(`/server/${server.containerId}/scaling?success=${encodeURIComponent('Scheduled scaling settings updated.')}`);
    } catch (error) {
        console.error('Error updating scheduled scaling settings:', error);
        return res.redirect(`/server/${req.params.containerId}/scaling?error=${encodeURIComponent('Failed to update scaling settings.')}`);
    }
});

app.post('/server/:containerId/scaling/rules', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.scheduledScalingEnabled) {
            return res.redirect(`/server/${req.params.containerId}/overview?error=${encodeURIComponent('Scheduled scaling is disabled by admin.')}`);
        }

        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }

        const current = await getServerScheduledScalingConfigSafe(server.id);
        const daysOfWeekInput = Array.isArray(req.body.daysOfWeek)
            ? req.body.daysOfWeek
            : [req.body.daysOfWeek].filter(Boolean);
        const timezone = resolveSafeTimezone(req.body.timezone, current.timezone || 'UTC');
        const rule = normalizeScheduledScalingRule({
            name: req.body.name,
            enabled: req.body.enabled,
            timezone,
            daysOfWeek: daysOfWeekInput,
            hour: req.body.hour,
            minute: req.body.minute,
            memory: req.body.memory,
            cpu: req.body.cpu,
            disk: req.body.disk,
            swapLimit: req.body.swapLimit,
            ioWeight: req.body.ioWeight,
            pidsLimit: req.body.pidsLimit,
            oomKillDisable: req.body.oomKillDisable,
            oomScoreAdj: req.body.oomScoreAdj
        });

        const hasAnyLimit = ['memory', 'cpu', 'disk', 'swapLimit', 'ioWeight', 'pidsLimit', 'oomScoreAdj']
            .some((field) => String(req.body[field] || '').trim() !== '')
            || parseBooleanInput(req.body.oomKillDisable, false);
        if (!hasAnyLimit) {
            return res.redirect(`/server/${server.containerId}/scaling?error=${encodeURIComponent('Rule must define at least one target limit.')}`);
        }

        if (featureFlags.inventoryEnabled) {
            const nextLimits = {
                memory: Number.parseInt(rule.memory, 10) > 0 ? Number.parseInt(rule.memory, 10) : server.memory,
                cpu: Number.parseInt(rule.cpu, 10) > 0 ? Number.parseInt(rule.cpu, 10) : server.cpu,
                disk: Number.parseInt(rule.disk, 10) > 0 ? Number.parseInt(rule.disk, 10) : server.disk,
                swapLimit: Number.parseInt(rule.swapLimit, 10) >= 0 ? Number.parseInt(rule.swapLimit, 10) : server.swapLimit
            };
            const scalingDelta = buildScalingInventoryDelta(server, nextLimits);
            const ownerInventory = await getUserInventoryState(server.ownerId);
            const missingInventory = getScalingInventoryMissingList(scalingDelta, ownerInventory);

            if (missingInventory.length > 0) {
                return res.redirect(`/server/${server.containerId}/scaling?error=${encodeURIComponent(`Not enough inventory for this rule: ${missingInventory.join(', ')}`)}`);
            }
        }

        const nextRules = [rule, ...(Array.isArray(current.rules) ? current.rules : [])].slice(0, 200);
        await setServerScheduledScalingConfigSafe(server.id, {
            ...current,
            timezone,
            rules: nextRules
        });

        return res.redirect(`/server/${server.containerId}/scaling?success=${encodeURIComponent(`Scaling rule "${rule.name}" added.`)}`);
    } catch (error) {
        console.error('Error adding scheduled scaling rule:', error);
        return res.redirect(`/server/${req.params.containerId}/scaling?error=${encodeURIComponent('Failed to add scaling rule.')}`);
    }
});

app.post('/server/:containerId/scaling/rules/:ruleId/delete', requireAuth, async (req, res) => {
    try {
        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.scheduledScalingEnabled) {
            return res.redirect(`/server/${req.params.containerId}/overview?error=${encodeURIComponent('Scheduled scaling is disabled by admin.')}`);
        }

        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }

        const current = await getServerScheduledScalingConfigSafe(server.id);
        const ruleId = String(req.params.ruleId || '').trim();
        const nextRules = (Array.isArray(current.rules) ? current.rules : []).filter((entry) => String(entry.id || '') !== ruleId);
        await setServerScheduledScalingConfigSafe(server.id, {
            ...current,
            rules: nextRules
        });

        return res.redirect(`/server/${server.containerId}/scaling?success=${encodeURIComponent('Scaling rule deleted.')}`);
    } catch (error) {
        console.error('Error deleting scheduled scaling rule:', error);
        return res.redirect(`/server/${req.params.containerId}/scaling?error=${encodeURIComponent('Failed to delete scaling rule.')}`);
    }
});

function sanitizeSftpLoginBase(username) {
    const normalized = String(username || '')
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '')
        .slice(0, 24);
    return normalized || 'user';
}

function createStableSftpSuffix(seed, length = 5) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const digest = nodeCrypto.createHash('sha256').update(String(seed || '')).digest();
    let suffix = '';

    for (let i = 0; suffix.length < length; i += 1) {
        const byte = digest[i % digest.length];
        suffix += alphabet[byte % alphabet.length];
    }

    return suffix;
}

function buildSftpUsernameForServer(user, server) {
    const base = sanitizeSftpLoginBase(user && user.username);
    const serverId = server && server.id ? server.id : '0';
    const containerId = server && server.containerId ? server.containerId : '';
    const seed = `${user && user.id ? user.id : '0'}:${user && user.email ? user.email : ''}:${serverId}:${containerId}:${SECRET_KEY}`;
    return `${base}.${createStableSftpSuffix(seed, 5)}`;
}

app.post('/api/connector/sftp-auth', async (req, res) => {
    try {
        const recordSftpAttempt = async (status, metadata = {}) => {
            try {
                await AuditLog.create({
                    actorUserId: null,
                    action: status === 'success' ? 'sftp:auth_success' : 'sftp:auth_failed',
                    targetType: 'sftp',
                    targetId: metadata.serverId ? String(metadata.serverId) : null,
                    method: req.method,
                    path: req.originalUrl || req.url,
                    ip: req.headers['x-forwarded-for'] || req.ip || null,
                    userAgent: req.headers['user-agent'] || null,
                    metadata: {
                        status,
                        connectorId: metadata.connectorId || null,
                        username: metadata.username || null,
                        reason: metadata.reason || null
                    }
                });
            } catch {
                // Ignore audit write failures for auth requests.
            }
        };

        const connectorId = Number.parseInt(req.body.connectorId, 10);
        const token = String(req.body.token || '');
        const presentedUsername = String(req.body.username || '').trim().toLowerCase();
        const presentedPassword = String(req.body.password || '');

        if (!Number.isInteger(connectorId) || !token || !presentedUsername || !presentedPassword) {
            await recordSftpAttempt('failed', { connectorId, username: presentedUsername, reason: 'missing_fields' });
            return res.status(400).json({ success: false, error: 'Missing required auth fields.' });
        }

        const sftpEnabledRaw = String((res.locals.settings && res.locals.settings.featureSftpEnabled) || 'true').trim().toLowerCase();
        const sftpEnabled = sftpEnabledRaw === 'true' || sftpEnabledRaw === '1' || sftpEnabledRaw === 'on' || sftpEnabledRaw === 'yes';
        if (!sftpEnabled) {
            await recordSftpAttempt('failed', { connectorId, username: presentedUsername, reason: 'sftp_feature_disabled' });
            return res.status(403).json({ success: false, error: 'SFTP access is disabled by panel admin.' });
        }

        const connector = await Connector.findByPk(connectorId);
        if (!connector || connector.token !== token) {
            await recordSftpAttempt('failed', { connectorId, username: presentedUsername, reason: 'invalid_connector_token' });
            return res.status(401).json({ success: false, error: 'Invalid connector authentication.' });
        }

        const users = await User.findAll({
            attributes: ['id', 'username', 'email', 'password', 'isAdmin', 'isSuspended']
        });
        const servers = await Server.findAll({
            where: { isSuspended: false },
            attributes: ['id', 'containerId', 'name', 'ownerId'],
            include: [{
                model: Allocation,
                as: 'allocation',
                attributes: ['id', 'connectorId'],
                required: true,
                where: { connectorId }
            }]
        });
        const serverIds = servers.map((server) => server.id);
        const serverMemberships = serverIds.length > 0
            ? await ServerSubuser.findAll({
                where: { serverId: serverIds },
                attributes: ['serverId', 'userId', 'permissions']
            })
            : [];
        const subuserServerAccess = new Map();
        for (const membership of serverMemberships) {
            const membershipPerms = new Set(normalizeServerPermissionList(membership.permissions));
            if (!membershipPerms.has('server.files')) continue;
            const userId = Number.parseInt(membership.userId, 10);
            if (!subuserServerAccess.has(userId)) {
                subuserServerAccess.set(userId, new Set());
            }
            subuserServerAccess.get(userId).add(Number.parseInt(membership.serverId, 10));
        }

        const prefix = sanitizeSftpLoginBase(presentedUsername.split('.', 1)[0] || '');
        const ownedServers = new Map();
        for (const server of servers) {
            const ownerId = Number.parseInt(server.ownerId, 10);
            if (!ownedServers.has(ownerId)) ownedServers.set(ownerId, []);
            ownedServers.get(ownerId).push(server);
        }

        let matchedUser = null;
        let matchedServer = null;
        for (const user of users) {
            if (user.isSuspended) continue;
            if (sanitizeSftpLoginBase(user.username) !== prefix) continue;

            const ownerServers = ownedServers.get(Number.parseInt(user.id, 10)) || [];
            const subuserAllowedIds = subuserServerAccess.get(Number.parseInt(user.id, 10)) || new Set();
            const allowedServers = user.isAdmin
                ? servers
                : servers.filter((entry) => ownerServers.includes(entry) || subuserAllowedIds.has(Number.parseInt(entry.id, 10)));
            for (const server of allowedServers) {
                if (buildSftpUsernameForServer(user, server) === presentedUsername) {
                    matchedUser = user;
                    matchedServer = server;
                    break;
                }
            }

            if (matchedUser && matchedServer) break;
        }

        if (!matchedUser || !matchedServer) {
            await recordSftpAttempt('failed', { connectorId, username: presentedUsername, reason: 'unknown_user_or_server' });
            return res.status(401).json({ success: false, error: 'Invalid SFTP credentials.' });
        }

        const passwordValid = await bcrypt.compare(presentedPassword, matchedUser.password);
        if (!passwordValid) {
            await recordSftpAttempt('failed', { connectorId, username: presentedUsername, serverId: matchedServer.id, reason: 'password_mismatch' });
            return res.status(401).json({ success: false, error: 'Invalid SFTP credentials.' });
        }

        await recordSftpAttempt('success', { connectorId, username: presentedUsername, serverId: matchedServer.id });
        return res.json({
            success: true,
            user: {
                id: matchedUser.id,
                username: matchedUser.username,
                isAdmin: Boolean(matchedUser.isAdmin)
            },
            servers: [{
                id: matchedServer.id,
                containerId: matchedServer.containerId,
                name: matchedServer.name
            }]
        });
    } catch (error) {
        console.error('SFTP auth error:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

// User Server File Manager
app.get('/server/:containerId/files', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                {
                    model: Allocation,
                    as: 'allocation',
                    include: [{
                        model: Connector,
                        as: 'connector',
                        include: [{ model: Location, as: 'location' }]
                    }]
                },
                { model: Image, as: 'image' }
            ]
        });

        if (!server) return res.redirect('/server/notfound');

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.files')) {
            return res.redirect('/server/no-permissions');
        }

        let initialPath = req.query.path || '/';

        // Security: Basic path sanitization
        if (initialPath.includes('..')) {
            return res.redirect(`/server/${server.containerId}/files?error=Invalid directory path`);
        }

        // Ensure it starts with / and normalize
        if (!initialPath.startsWith('/')) initialPath = '/' + initialPath;
        initialPath = path.normalize(initialPath).replace(/\\/g, '/'); // Normalize and fix windows slashes if any

        const wsToken = jwt.sign({
            serverId: server.id,
            userId: req.session.user.id,
            isAdmin: Boolean(req.session.user.isAdmin),
            serverPerms: Array.from(access.permissions || [])
        }, SECRET_KEY, { expiresIn: '1h' });

        const connector = server.allocation && server.allocation.connector ? server.allocation.connector : null;
        const sftpHost = connector ? String(connector.fqdn || '').trim() : '';
        const parsedSftpPort = connector ? Number.parseInt(connector.sftpPort, 10) : NaN;
        const sftpEnabledRaw = String((res.locals.settings && res.locals.settings.featureSftpEnabled) || 'true').trim().toLowerCase();
        const sftpEnabled = sftpEnabledRaw === 'true' || sftpEnabledRaw === '1' || sftpEnabledRaw === 'on' || sftpEnabledRaw === 'yes';
        const sftpDetails = {
            host: sftpHost,
            port: Number.isInteger(parsedSftpPort) ? parsedSftpPort : null,
            username: buildSftpUsernameForServer(req.session.user, server),
            passwordHint: 'Use your account password from this panel.',
            available: sftpEnabled && !server.isSuspended && Boolean(sftpHost) && Number.isInteger(parsedSftpPort)
        };

        const uploadEnabledRaw = String((res.locals.settings && res.locals.settings.featureWebUploadEnabled) || 'true').trim().toLowerCase();
        const webUploadEnabled = uploadEnabledRaw === 'true' || uploadEnabledRaw === '1' || uploadEnabledRaw === 'on' || uploadEnabledRaw === 'yes';
        const uploadMaxMbRaw = Number.parseInt(String((res.locals.settings && res.locals.settings.featureWebUploadMaxMb) || '50').trim(), 10);
        const webUploadMaxMb = Math.max(1, Math.min(2048, Number.isInteger(uploadMaxMbRaw) ? uploadMaxMbRaw : 50));

        res.render('server/files', {
            server,
            user: req.session.user,
            title: `Files ${server.name}`,
            path: '/servers',
            wsToken,
            initialPath,
            sftpDetails,
            sftpFeatureEnabled: sftpEnabled,
            webUploadEnabled,
            webUploadMaxMb
        });
    } catch (err) {
        console.error("Error fetching file manager:", err);
        res.redirect('/?error=Error loading file manager');
    }
});

// User Server Minecraft Addons (Modrinth)
app.get('/server/:containerId/minecraft', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] },
                { model: Image, as: 'image' }
            ]
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.minecraft')) {
            return res.redirect('/server/no-permissions');
        }
        if (server.isSuspended) {
            return res.redirect(`/server/${server.containerId}/suspended`);
        }

        const defaults = inferMinecraftDefaults(server);
        const defaultKind = normalizeMinecraftProjectKind(req.query.kind || defaults.kind);
        const defaultLoader = normalizeMinecraftLoader(req.query.loader || defaults.loader, defaultKind);
        const defaultVersion = normalizeMinecraftVersion(req.query.version || defaults.version || '');

        res.render('server/minecraft', {
            server,
            user: req.session.user,
            title: `Minecraft ${server.name}`,
            path: '/servers',
            minecraftDefaults: {
                kind: defaultKind,
                loader: defaultLoader,
                version: defaultVersion,
                targetDirectory: resolveMinecraftTargetDirectory(defaultKind, req.query.targetDirectory)
            },
            minecraftCatalog: {
                plugins: MODRINTH_PLUGIN_LOADERS,
                mods: MODRINTH_MOD_LOADERS
            }
        });
    } catch (err) {
        console.error('Error loading minecraft addons page:', err);
        res.redirect('/?error=Error loading Minecraft addons page');
    }
});

app.get('/server/:containerId/minecraft/search', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            attributes: ['id', 'containerId', 'ownerId', 'isSuspended']
        });

        if (!server) return res.status(404).json({ success: false, error: 'Server not found.' });
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.minecraft')) {
            return res.status(403).json({ success: false, error: 'Forbidden.' });
        }
        if (server.isSuspended) {
            return res.status(423).json({ success: false, error: 'Server is suspended.' });
        }

        const query = String(req.query.q || '').trim().slice(0, 100);
        const kind = normalizeMinecraftProjectKind(req.query.kind);
        const loader = normalizeMinecraftLoader(req.query.loader, kind);
        const gameVersion = normalizeMinecraftVersion(req.query.version);
        const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 12, 1), MODRINTH_MAX_SEARCH_LIMIT);
        const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);

        const executeModrinthSearch = async (includeVersionFacet) => {
            const facets = [[`project_type:${kind}`]];
            if (loader) facets.push([`categories:${loader}`]);
            if (includeVersionFacet && gameVersion) facets.push([`versions:${gameVersion}`]);
            const response = await axios.get(`${MODRINTH_API_BASE_URL}/search`, {
                params: {
                    query,
                    limit,
                    offset,
                    index: 'downloads',
                    facets: JSON.stringify(facets)
                },
                timeout: MODRINTH_REQUEST_TIMEOUT_MS,
                headers: {
                    'User-Agent': buildModrinthUserAgent(res.locals.settings)
                }
            });
            const payload = response.data || {};
            const hits = Array.isArray(payload.hits) ? payload.hits : [];
            return { payload, hits };
        };

        let relaxedVersionFilter = false;
        let searchResult = await executeModrinthSearch(true);
        if (gameVersion && searchResult.hits.length === 0) {
            const relaxedResult = await executeModrinthSearch(false);
            if (relaxedResult.hits.length > 0) {
                searchResult = relaxedResult;
                relaxedVersionFilter = true;
            }
        }

        const payload = searchResult.payload;
        const hits = searchResult.hits;

        const results = hits.map((hit) => ({
            id: String(hit.project_id || hit.id || ''),
            slug: String(hit.slug || ''),
            title: String(hit.title || hit.name || 'Unknown project'),
            description: String(hit.description || ''),
            author: String(hit.author || ''),
            iconUrl: String(hit.icon_url || ''),
            downloads: Number.parseInt(hit.downloads, 10) || 0,
            categories: Array.isArray(hit.categories) ? hit.categories : [],
            latestVersionId: String(hit.latest_version || ''),
            dateModified: String(hit.date_modified || ''),
            projectType: String(hit.project_type || kind)
        })).filter((result) => result.id);

        return res.json({
            success: true,
            query,
            kind,
            loader,
            version: gameVersion,
            relaxedVersionFilter,
            pagination: {
                total: Number.parseInt(payload.total_hits, 10) || 0,
                offset,
                limit
            },
            results
        });
    } catch (err) {
        const remoteError = err && err.response && err.response.data && err.response.data.description
            ? String(err.response.data.description)
            : 'Failed to fetch results from Modrinth.';
        console.error('Error searching Modrinth:', err.message || err);
        return res.status(502).json({ success: false, error: remoteError });
    }
});

app.get('/server/:containerId/minecraft/installed', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }],
            attributes: ['id', 'containerId', 'ownerId', 'isSuspended']
        });

        if (!server) return res.status(404).json({ success: false, error: 'Server not found.' });
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.minecraft')) {
            return res.status(403).json({ success: false, error: 'Forbidden.' });
        }
        if (server.isSuspended) {
            return res.status(423).json({ success: false, error: 'Server is suspended.' });
        }
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(400).json({ success: false, error: 'Server allocation is missing.' });
        }

        const kind = normalizeMinecraftProjectKind(req.query.kind);
        const directory = resolveMinecraftTargetDirectory(kind, req.query.targetDirectory);
        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const listing = await runConnectorFileAction(connectorWs, {
            type: 'list_files',
            serverId: server.id,
            directory
        }, directory, server.id, 12000);

        if (!listing.success) {
            return res.status(500).json({ success: false, error: listing.error || 'Failed to load installed addons.' });
        }

        const trackedRecords = await getServerMinecraftInstallRecords(server.id);
        const trackedByPath = new Map(trackedRecords.map((record) => [record.path, record]));

        const installed = (listing.files || [])
            .filter((entry) => {
                if (!entry || entry.isDirectory) return false;
                const name = String(entry.name || '').trim();
                return /\.(jar|zip)$/i.test(name);
            })
            .map((entry) => {
                const fileName = sanitizeDownloadFileName(entry.name || '', '');
                if (!fileName) return null;
                const filePath = directory === '/' ? `/${fileName}` : `${directory}/${fileName}`;
                const tracked = trackedByPath.get(filePath) || null;

                return {
                    name: fileName,
                    path: filePath,
                    directory,
                    size: Number.parseInt(entry.size, 10) || 0,
                    mtime: entry.mtime || null,
                    permissions: String(entry.permissions || ''),
                    tracked: Boolean(tracked),
                    canUpdate: Boolean(tracked && tracked.projectId),
                    source: tracked ? 'modrinth' : 'manual',
                    projectId: tracked ? tracked.projectId : '',
                    projectTitle: tracked ? tracked.projectTitle : '',
                    loader: tracked ? tracked.loader : '',
                    kind: tracked ? tracked.kind : kind,
                    gameVersion: tracked ? tracked.gameVersion : '',
                    versionId: tracked ? tracked.versionId : '',
                    versionNumber: tracked ? tracked.versionNumber : '',
                    installedAt: tracked ? tracked.installedAt : null
                };
            })
            .filter(Boolean)
            .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));

        return res.json({
            success: true,
            kind,
            directory,
            count: installed.length,
            installed
        });
    } catch (err) {
        console.error('Error loading installed minecraft addons:', err);
        return res.status(500).json({ success: false, error: 'Failed to load installed addons.' });
    }
});

app.post('/server/:containerId/minecraft/delete', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }],
            attributes: ['id', 'containerId', 'ownerId', 'isSuspended']
        });

        if (!server) return res.status(404).json({ success: false, error: 'Server not found.' });
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.minecraft')) {
            return res.status(403).json({ success: false, error: 'Forbidden.' });
        }
        if (server.isSuspended) {
            return res.status(423).json({ success: false, error: 'Server is suspended.' });
        }
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(400).json({ success: false, error: 'Server allocation is missing.' });
        }

        const pathInfo = parseServerAddonPath(req.body.path);
        if (!pathInfo) {
            return res.status(400).json({ success: false, error: 'Invalid addon path.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const result = await runConnectorFileAction(connectorWs, {
            type: 'delete_files',
            serverId: server.id,
            directory: pathInfo.directory,
            files: [pathInfo.fileName]
        }, pathInfo.directory, server.id, 12000);

        if (!result.success) {
            return res.status(500).json({ success: false, error: result.error || 'Failed to delete addon.' });
        }

        await removeServerMinecraftInstallRecord(server.id, pathInfo.path);

        return res.json({
            success: true,
            message: 'Addon deleted successfully.',
            deleted: {
                path: pathInfo.path,
                fileName: pathInfo.fileName
            }
        });
    } catch (err) {
        console.error('Error deleting minecraft addon:', err);
        return res.status(500).json({ success: false, error: 'Failed to delete addon.' });
    }
});

app.post('/server/:containerId/minecraft/update', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }],
            attributes: ['id', 'containerId', 'ownerId', 'isSuspended']
        });

        if (!server) return res.status(404).json({ success: false, error: 'Server not found.' });
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.minecraft')) {
            return res.status(403).json({ success: false, error: 'Forbidden.' });
        }
        if (server.isSuspended) {
            return res.status(423).json({ success: false, error: 'Server is suspended.' });
        }
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(400).json({ success: false, error: 'Server allocation is missing.' });
        }

        const pathInfo = parseServerAddonPath(req.body.path);
        if (!pathInfo) {
            return res.status(400).json({ success: false, error: 'Invalid addon path.' });
        }

        const records = await getServerMinecraftInstallRecords(server.id);
        const existingRecord = records.find((record) => record.path === pathInfo.path);
        if (!existingRecord || !existingRecord.projectId) {
            return res.status(400).json({
                success: false,
                error: 'Update is only available for addons installed from this panel.'
            });
        }

        const kind = normalizeMinecraftProjectKind(req.body.kind || existingRecord.kind);
        const loader = normalizeMinecraftLoader(req.body.loader || existingRecord.loader, kind);
        const gameVersion = normalizeMinecraftVersion(req.body.version || existingRecord.gameVersion);

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const versionData = await resolveModrinthVersionForInstall({
            projectId: existingRecord.projectId,
            versionId: '',
            loader,
            gameVersion,
            userAgent: buildModrinthUserAgent(res.locals.settings)
        });

        const requestId = createWsRequestId();
        connectorWs.send(JSON.stringify({
            type: 'download_file',
            serverId: server.id,
            requestId,
            directory: pathInfo.directory,
            url: versionData.fileUrl,
            fileName: versionData.fileName
        }));

        const installResult = await waitForConnectorDownloadResult(connectorWs, server.id, requestId, 45000);
        if (!installResult.success) {
            return res.status(500).json({
                success: false,
                error: installResult.error || 'Connector failed to update addon.'
            });
        }

        const nextPathInfo = parseServerAddonPath(installResult.path || `${pathInfo.directory}/${versionData.fileName}`) || {
            directory: pathInfo.directory,
            fileName: versionData.fileName,
            path: pathInfo.directory === '/' ? `/${versionData.fileName}` : `${pathInfo.directory}/${versionData.fileName}`
        };

        let warning = '';
        if (nextPathInfo.path !== pathInfo.path) {
            const deleteOldResult = await runConnectorFileAction(connectorWs, {
                type: 'delete_files',
                serverId: server.id,
                directory: pathInfo.directory,
                files: [pathInfo.fileName]
            }, pathInfo.directory, server.id, 12000);

            if (!deleteOldResult.success) {
                warning = 'New version installed, but old file could not be removed automatically.';
            }
        }

        await removeServerMinecraftInstallRecord(server.id, pathInfo.path);
        await upsertServerMinecraftInstallRecord(server.id, {
            path: nextPathInfo.path,
            directory: nextPathInfo.directory,
            fileName: nextPathInfo.fileName,
            kind,
            loader,
            gameVersion,
            projectId: existingRecord.projectId,
            projectTitle: existingRecord.projectTitle,
            versionId: versionData.versionId,
            versionNumber: versionData.versionNumber,
            installedAt: new Date().toISOString()
        });

        return res.json({
            success: true,
            message: 'Addon updated successfully.',
            warning,
            updated: {
                oldPath: pathInfo.path,
                newPath: nextPathInfo.path,
                fileName: nextPathInfo.fileName,
                versionId: versionData.versionId,
                versionNumber: versionData.versionNumber
            }
        });
    } catch (err) {
        console.error('Error updating minecraft addon:', err);
        return res.status(500).json({
            success: false,
            error: err && err.message ? String(err.message) : 'Failed to update addon.'
        });
    }
});

app.post('/server/:containerId/minecraft/install', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });

        if (!server) return res.status(404).json({ success: false, error: 'Server not found.' });
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.minecraft')) {
            return res.status(403).json({ success: false, error: 'Forbidden.' });
        }
        if (server.isSuspended) {
            return res.status(423).json({ success: false, error: 'Server is suspended.' });
        }
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(400).json({ success: false, error: 'Server allocation is missing.' });
        }

        const kind = normalizeMinecraftProjectKind(req.body.kind);
        const projectId = String(req.body.projectId || '').trim();
        const versionId = String(req.body.versionId || '').trim();
        const loader = normalizeMinecraftLoader(req.body.loader, kind);
        const gameVersion = normalizeMinecraftVersion(req.body.version);
        const targetDirectory = resolveMinecraftTargetDirectory(kind, req.body.targetDirectory);
        const projectTitle = String(req.body.projectTitle || '').trim().slice(0, 120);

        if (!/^[A-Za-z0-9_-]{2,64}$/.test(projectId)) {
            return res.status(400).json({ success: false, error: 'Invalid Modrinth project ID.' });
        }

        const installJob = await jobQueue.enqueue({
            type: 'server.minecraft.install',
            payload: {
                serverId: server.id,
                kind,
                projectId,
                versionId,
                loader,
                gameVersion,
                targetDirectory,
                projectTitle,
                userAgent: buildModrinthUserAgent(res.locals.settings)
            },
            priority: 8,
            maxAttempts: 2,
            createdByUserId: req.session.user.id
        });

        const completion = await jobQueue.waitForCompletion(installJob.id, 55000, 350);
        if (!completion.completed) {
            return res.status(202).json({
                success: true,
                queued: true,
                jobId: installJob.id,
                message: 'Install queued and still processing. Check again shortly.'
            });
        }

        if (completion.status !== 'completed') {
            return res.status(500).json({
                success: false,
                queued: false,
                jobId: installJob.id,
                error: completion.error || 'Failed to install addon.'
            });
        }

        const result = completion.job && completion.job.result && typeof completion.job.result === 'object'
            ? completion.job.result
            : { success: true, message: 'Addon installed successfully.' };
        return res.json({
            ...result,
            queued: false,
            jobId: installJob.id
        });
    } catch (err) {
        console.error('Error installing Modrinth addon:', err);
        return res.status(500).json({
            success: false,
            error: err && err.message ? String(err.message) : 'Failed to install addon.'
        });
    }
});

// User Server Startup
app.get('/server/:containerId/startup', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] },
                { model: Image, as: 'image' }
            ]
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }
        if (server.isSuspended) {
            return res.redirect(`/server/${server.containerId}/suspended`);
        }

        const image = server.image;
        const dockerChoices = resolveImageDockerChoices(image);
        const variableDefinitions = resolveImageVariableDefinitions(image).filter((v) => {
            const key = String(v.env_variable || '');
            if (!key) return false;
            if (key === 'SERVER_MEMORY' || key === 'SERVER_IP' || key === 'SERVER_PORT') return false;
            return true;
        });
        const startupPresets = getStartupPresetsForImage(image, variableDefinitions);
        const selectedStartupPresetId = await getServerStartupPresetSelection(server.id);

        const runtimeValues = {
            SERVER_MEMORY: String(server.memory),
            SERVER_IP: server.allocation ? server.allocation.ip : '',
            SERVER_PORT: server.allocation ? String(server.allocation.port) : ''
        };

        let resolvedVariables = {};
        let resolvedStartup = image.startup;
        try {
            const built = buildServerEnvironment(image, server.variables || {}, runtimeValues);
            resolvedVariables = built.resolvedVariables;
            resolvedStartup = buildStartupCommand(server.startup || image.startup, built.env);
        } catch (error) {
            resolvedVariables = normalizeClientVariables(server.variables || {});
        }

        const selectedDockerImage = server.dockerImage || image.dockerImage;

        res.render('server/startup', {
            server,
            user: req.session.user,
            title: `Startup ${server.name}`,
            path: '/servers',
            image,
            dockerChoices,
            variableDefinitions,
            resolvedVariables,
            selectedDockerImage,
            resolvedStartup,
            startupPresets,
            selectedStartupPresetId
        });
    } catch (err) {
        console.error('Error loading startup page:', err);
        res.redirect('/?error=Error loading startup settings');
    }
});

app.post('/server/:containerId/startup', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] },
                { model: Image, as: 'image' }
            ]
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.startup')) {
            return res.redirect('/server/no-permissions');
        }
        if (server.isSuspended) {
            return res.redirect(`/server/${server.containerId}/suspended`);
        }

        const image = server.image;
        const runtimeValues = {
            SERVER_MEMORY: String(server.memory),
            SERVER_IP: server.allocation ? server.allocation.ip : '',
            SERVER_PORT: server.allocation ? String(server.allocation.port) : ''
        };
        const imagePorts = resolveImagePorts(image.ports);
        const startupMode = shouldUseCommandStartup(image) ? 'command' : 'environment';
        const variableDefinitions = resolveImageVariableDefinitions(image).filter((v) => {
            const key = String(v.env_variable || '');
            if (!key) return false;
            if (key === 'SERVER_MEMORY' || key === 'SERVER_IP' || key === 'SERVER_PORT') return false;
            return true;
        });
        const startupPresets = getStartupPresetsForImage(image, variableDefinitions);

        const requestedVariables = normalizeClientVariables(req.body.variables || {});
        const existingVariables = normalizeClientVariables(server.variables || {});
        let mergedVariables = { ...existingVariables, ...requestedVariables };

        const requestedPresetId = String(req.body.startupPreset || '').trim();
        let selectedPresetId = '';
        if (requestedPresetId && requestedPresetId !== 'custom') {
            const preset = startupPresets.find((entry) => entry.id === requestedPresetId);
            if (!preset) {
                return res.redirect(`/server/${server.containerId}/startup?error=${encodeURIComponent('Selected startup preset is not available for this image.')}`);
            }
            const presetApplied = applyStartupPresetVariables(mergedVariables, preset, variableDefinitions);
            mergedVariables = presetApplied.variables;
            selectedPresetId = preset.id;
        }

        const { resolvedVariables, env } = buildServerEnvironment(image, mergedVariables, runtimeValues);
        const startup = buildStartupCommand(server.startup || image.startup, env);

        const dockerChoices = resolveImageDockerChoices(image);
        const allowedDockerTags = new Set(dockerChoices.map((choice) => choice.tag));
        const requestedDocker = typeof req.body.dockerImage === 'string' ? req.body.dockerImage.trim() : '';
        const nextDockerImage = requestedDocker && allowedDockerTags.has(requestedDocker)
            ? requestedDocker
            : (server.dockerImage || image.dockerImage);

        const action = String(req.body.action || 'save').toLowerCase();
        const shouldApply = action === 'apply';

        const updatePayload = {
            variables: resolvedVariables,
            dockerImage: nextDockerImage
        };

        if (!shouldApply) {
            await server.update(updatePayload);
            await setServerStartupPresetSelection(server.id, selectedPresetId);
            const savedMessage = selectedPresetId
                ? `Startup settings saved with preset "${selectedPresetId}". Use "Save and Reinstall" to apply changes.`
                : 'Startup settings saved. Use "Save and Reinstall" to apply changes.';
            return res.redirect(`/server/${server.containerId}/startup?success=${encodeURIComponent(savedMessage)}`);
        }

        if (!server.allocation || !server.allocation.connectorId) {
            return res.redirect(`/server/${server.containerId}/startup?error=Server allocation is missing.`);
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            await server.update(updatePayload);
            return res.redirect(`/server/${server.containerId}/startup?error=Connector is offline. Saved settings, but reinstall could not start.`);
        }

        const assignedAllocations = await Allocation.findAll({
            where: { serverId: server.id },
            attributes: ['id', 'ip', 'port'],
            order: [['port', 'ASC']]
        });
        const deploymentPorts = buildDeploymentPorts({
            imagePorts,
            env,
            primaryAllocation: server.allocation,
            allocations: assignedAllocations
        });

        const installJob = await jobQueue.enqueue({
            type: 'server.install.dispatch',
            payload: {
                serverId: server.id,
                reinstall: true,
                clearSuspended: true,
                resolvedVariables,
                config: {
                    image: nextDockerImage || image.dockerImage,
                    memory: server.memory,
                    cpu: server.cpu,
                    disk: server.disk,
                    swapLimit: server.swapLimit,
                    ioWeight: server.ioWeight,
                    pidsLimit: server.pidsLimit,
                    oomKillDisable: Boolean(server.oomKillDisable),
                    oomScoreAdj: server.oomScoreAdj,
                    env,
                    startup,
                    startupMode,
                    eggConfig: image.eggConfig,
                    eggScripts: image.eggScripts,
                    installation: image.installation || null,
                    configFiles: image.configFiles || null,
                    brandName: String((res.locals.settings && res.locals.settings.brandName) || 'cpanel'),
                    ports: deploymentPorts
                }
            },
            priority: 10,
            maxAttempts: 3,
            createdByUserId: req.session.user.id
        });

        await server.update({
            ...updatePayload,
            status: 'installing',
            isSuspended: false
        });
        await setServerStartupPresetSelection(server.id, selectedPresetId);

        const applyMessage = selectedPresetId
            ? `Startup settings saved with preset "${selectedPresetId}" and reinstall queued (job #${installJob.id}).`
            : `Startup settings saved and reinstall queued (job #${installJob.id}).`;
        return res.redirect(`/server/${server.containerId}/startup?success=${encodeURIComponent(applyMessage)}`);
    } catch (err) {
        console.error('Error updating startup settings:', err);
        return res.redirect(`/server/${req.params.containerId}/startup?error=${encodeURIComponent(err.message)}`);
    }
});

app.get('/server/:containerId/smartalerts', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Image, as: 'image' }]
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.smartalerts')) {
            return res.redirect('/server/no-permissions');
        }

        const smartAlerts = await getServerSmartAlertsConfig(server.id);

        res.render('server/smartalerts', {
            server,
            user: req.session.user,
            title: `Smart Alerts ${server.name}`,
            path: '/servers',
            smartAlerts,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (err) {
        console.error('Error loading smart alerts page:', err);
        return res.redirect('/?error=Error loading smart alerts page');
    }
});

app.post('/server/:containerId/smartalerts', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId }
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.smartalerts')) {
            return res.redirect('/server/no-permissions');
        }

        const discordWebhookRaw = String(req.body.discordWebhook || '').trim();
        const discordWebhook = sanitizeHttpUrl(discordWebhookRaw);
        if (discordWebhookRaw && !discordWebhook) {
            return res.redirect(`/server/${server.containerId}/smartalerts?error=${encodeURIComponent('Discord webhook must be a valid HTTP/HTTPS URL.')}`);
        }

        const telegramBotToken = String(req.body.telegramBotToken || '').trim();
        const telegramChatId = String(req.body.telegramChatId || '').trim();
        if ((telegramBotToken && !telegramChatId) || (!telegramBotToken && telegramChatId)) {
            return res.redirect(`/server/${server.containerId}/smartalerts?error=${encodeURIComponent('For Telegram alerts, provide both bot token and chat ID.')}`);
        }

        const updatedConfig = await setServerSmartAlertsConfig(server.id, {
            enabled: parseBooleanInput(req.body.enabled, false),
            discordWebhook,
            telegramBotToken,
            telegramChatId,
            events: {
                started: parseBooleanInput(req.body.eventStarted, false),
                stopped: parseBooleanInput(req.body.eventStopped, false),
                crashed: parseBooleanInput(req.body.eventCrashed, false),
                reinstallSuccess: parseBooleanInput(req.body.eventReinstallSuccess, false),
                reinstallFailed: parseBooleanInput(req.body.eventReinstallFailed, false),
                suspended: parseBooleanInput(req.body.eventSuspended, false),
                unsuspended: parseBooleanInput(req.body.eventUnsuspended, false),
                resourceAnomaly: parseBooleanInput(req.body.eventResourceAnomaly, false),
                pluginConflict: parseBooleanInput(req.body.eventPluginConflict, false)
            },
            anomaly: {
                enabled: parseBooleanInput(req.body.anomalyEnabled, false),
                cpuThreshold: req.body.anomalyCpuThreshold,
                memoryThreshold: req.body.anomalyMemoryThreshold,
                durationSamples: req.body.anomalyDurationSamples,
                cooldownSeconds: req.body.anomalyCooldownSeconds
            },
            logCleanup: {
                enabled: parseBooleanInput(req.body.logCleanupEnabled, false),
                directory: req.body.logCleanupDirectory,
                maxFileSizeMB: req.body.logCleanupMaxFileSizeMB,
                keepFiles: req.body.logCleanupKeepFiles,
                maxAgeDays: req.body.logCleanupMaxAgeDays,
                compressOld: parseBooleanInput(req.body.logCleanupCompressOld, false)
            }
        });

        if (updatedConfig && updatedConfig.logCleanup && updatedConfig.logCleanup.enabled) {
            const serverWithAllocation = await Server.findByPk(server.id, {
                include: [{ model: Allocation, as: 'allocation' }]
            });
            if (serverWithAllocation) {
                await dispatchServerLogCleanup(serverWithAllocation, true);
            }
        }

        return res.redirect(`/server/${server.containerId}/smartalerts?success=${encodeURIComponent('Smart alerts updated successfully.')}`);
    } catch (err) {
        console.error('Error saving smart alerts:', err);
        return res.redirect(`/server/${req.params.containerId}/smartalerts?error=${encodeURIComponent('Failed to save smart alerts settings.')}`);
    }
});

app.get('/server/:containerId/policy', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Image, as: 'image' }]
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.policy')) {
            return res.redirect('/server/no-permissions');
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.policyEngineEnabled) {
            return res.redirect(`/server/${server.containerId}/overview?error=${encodeURIComponent('Policy engine is disabled by admin.')}`);
        }

        const policyConfig = await getServerPolicyEngineConfig(server.id);

        return res.render('server/policy', {
            server,
            user: req.session.user,
            title: `Policy Engine ${server.name}`,
            path: '/servers',
            policyConfig,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (err) {
        console.error('Error loading policy engine page:', err);
        return res.redirect('/?error=Error loading policy engine page');
    }
});

app.post('/server/:containerId/policy', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId }
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.policy')) {
            return res.redirect('/server/no-permissions');
        }

        const featureFlags = getPanelFeatureFlagsFromMap(res.locals.settings || {});
        if (!featureFlags.policyEngineEnabled) {
            return res.redirect(`/server/${server.containerId}/overview?error=${encodeURIComponent('Policy engine is disabled by admin.')}`);
        }

        const anomalyActionRaw = String(req.body.anomalyAction || 'none').trim().toLowerCase();
        const anomalyAction = ['none', 'restart', 'stop'].includes(anomalyActionRaw) ? anomalyActionRaw : 'none';

        await setServerPolicyEngineConfig(server.id, {
            enabled: parseBooleanInput(req.body.enabled, false),
            restartOnCrash: parseBooleanInput(req.body.restartOnCrash, true),
            anomalyAction,
            anomalyCpuThreshold: req.body.anomalyCpuThreshold,
            anomalyMemoryThreshold: req.body.anomalyMemoryThreshold,
            anomalyDurationSamples: req.body.anomalyDurationSamples,
            maxRemediationsPerHour: req.body.maxRemediationsPerHour
        });

        return res.redirect(`/server/${server.containerId}/policy?success=${encodeURIComponent('Policy engine updated successfully.')}`);
    } catch (err) {
        console.error('Error saving policy engine settings:', err);
        return res.redirect(`/server/${req.params.containerId}/policy?error=${encodeURIComponent('Failed to save policy engine settings.')}`);
    }
});

// File Editor
app.get('/server/:containerId/files/edit', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Image, as: 'image' }]
        });

        if (!server) return res.redirect('/server/notfound');
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.files')) {
            return res.redirect('/server/no-permissions');
        }

        const wsToken = jwt.sign({
            serverId: server.id,
            userId: req.session.user.id,
            isAdmin: Boolean(req.session.user.isAdmin),
            serverPerms: Array.from(access.permissions || [])
        }, SECRET_KEY, { expiresIn: '1h' });

        res.render('server/edit', {
            server,
            user: req.session.user,
            title: `File Editor - ${server.name}`,
            path: '/servers',
            wsToken
        });
    } catch (err) {
        console.error('Error loading file editor:', err);
        res.redirect('/?error=Error loading editor');
    }
});


app.get('/api/client/servers/:containerId', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.view');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const server = auth.server;
        const allocation = server.allocation || null;
        const connector = allocation ? allocation.connector : null;

        return res.json({
            success: true,
            server: {
                id: server.id,
                containerId: server.containerId,
                name: server.name,
                status: server.status,
                suspended: Boolean(server.isSuspended),
                resources: {
                    memory: server.memory,
                    cpu: server.cpu,
                    disk: server.disk,
                    swapLimit: server.swapLimit,
                    ioWeight: server.ioWeight,
                    pidsLimit: server.pidsLimit
                },
                allocation: allocation ? {
                    ip: allocation.ip,
                    port: allocation.port,
                    alias: allocation.alias || null
                } : null,
                connector: connector ? {
                    id: connector.id,
                    name: connector.name
                } : null
            }
        });
    } catch (error) {
        console.error('Server API metadata endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/power', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.power');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const action = String(req.body.signal || req.body.action || '').trim().toLowerCase();
        if (!['start', 'stop', 'restart', 'kill'].includes(action)) {
            return res.status(400).json({ success: false, error: 'Invalid power signal.' });
        }

        if (action === 'stop' || action === 'restart' || action === 'kill') {
            rememberServerPowerIntent(server.id, action);
        }
        if (action === 'start') {
            consumeServerPowerIntent(server.id);
        }
        const requestId = `api_pwr_${Date.now()}_${nodeCrypto.randomBytes(3).toString('hex')}`;

        connectorWs.send(JSON.stringify({
            type: 'server_power',
            serverId: server.id,
            action,
            stopCommand: server.image && server.image.eggConfig ? server.image.eggConfig.stop : null,
            requestId
        }));

        return res.json({ success: true, signal: action, requestId });
    } catch (error) {
        console.error('Server API power endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/command', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.console');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const command = String(req.body.command || '').trim();
        if (!command) {
            return res.status(400).json({ success: false, error: 'Command is required.' });
        }
        if (command.length > 1024) {
            return res.status(400).json({ success: false, error: 'Command exceeds 1024 characters.' });
        }
        const requestId = `api_cmd_${Date.now()}_${nodeCrypto.randomBytes(3).toString('hex')}`;

        connectorWs.send(JSON.stringify({
            type: 'server_command',
            serverId: server.id,
            command,
            requestId
        }));

        return res.json({ success: true, command, requestId });
    } catch (error) {
        console.error('Server API command endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.get('/api/client/servers/:containerId/files/list', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.read');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const directoryRaw = String(req.query.directory || '/').trim() || '/';
        const directory = directoryRaw.startsWith('/') ? directoryRaw : `/${directoryRaw}`;
        const result = await runConnectorFileAction(connectorWs, {
            type: 'list_files',
            serverId: server.id,
            directory
        }, directory, server.id, 12000);

        if (!result || !result.success) {
            return res.status(502).json({ success: false, error: result && result.error ? result.error : 'Failed to fetch file list.' });
        }

        return res.json({
            success: true,
            directory: result.directory || directory,
            files: Array.isArray(result.files) ? result.files : []
        });
    } catch (error) {
        console.error('Server API file list endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.get('/api/client/servers/:containerId/files/content', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.read');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const filePathRaw = String(req.query.file || req.query.path || '').trim();
        if (!filePathRaw) {
            return res.status(400).json({ success: false, error: 'Query parameter "file" is required.' });
        }
        const filePath = filePathRaw.startsWith('/') ? filePathRaw : `/${filePathRaw}`;

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        connectorWs.send(JSON.stringify({
            type: 'read_file',
            serverId: server.id,
            filePath
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'file_content' && String(message.filePath || '') === filePath) {
                return {
                    success: true,
                    filePath,
                    content: String(message.content || '')
                };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 12000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to read file.' });
        }

        return res.json({
            success: true,
            filePath,
            content: result.content
        });
    } catch (error) {
        console.error('Server API file content endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/files/write', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.write');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const filePathRaw = String(req.body.file || req.body.path || '').trim();
        if (!filePathRaw) {
            return res.status(400).json({ success: false, error: 'Field "file" is required.' });
        }
        const filePath = filePathRaw.startsWith('/') ? filePathRaw : `/${filePathRaw}`;

        const content = typeof req.body.content === 'string' ? req.body.content : String(req.body.content || '');
        if (Buffer.byteLength(content, 'utf8') > 2 * 1024 * 1024) {
            return res.status(413).json({ success: false, error: 'File content exceeds 2 MiB limit for API write.' });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        connectorWs.send(JSON.stringify({
            type: 'write_file',
            serverId: server.id,
            filePath,
            content
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'write_success' && String(message.filePath || '') === filePath) {
                return { success: true };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 15000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to write file.' });
        }

        return res.json({
            success: true,
            filePath
        });
    } catch (error) {
        console.error('Server API file write endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.get('/api/client/servers/:containerId/files/download', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.download');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const filePathRaw = String(req.query.file || '').trim();
        if (!filePathRaw) {
            return res.status(400).json({ success: false, error: 'Query parameter "file" is required.' });
        }
        const filePath = filePathRaw.startsWith('/') ? filePathRaw : `/${filePathRaw}`;

        const server = auth.server;
        const connector = server.allocation && server.allocation.connector ? server.allocation.connector : null;
        if (!connector) {
            return res.status(500).json({ success: false, error: 'Connector not available for this server.' });
        }

        const protocol = connector.ssl ? 'https://' : 'http://';
        const connectorUrl = `${protocol}${connector.fqdn}:${connector.port}/api/servers/${server.id}/files/read`;

        const response = await fetch(connectorUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${connector.token}`
            },
            body: JSON.stringify({ path: filePath })
        });

        if (!response.ok) {
            if (response.status === 404) return res.status(404).json({ success: false, error: 'File not found.' });
            return res.status(response.status).json({ success: false, error: 'Connector read failed.' });
        }

        const fileName = path.basename(filePath);
        res.setHeader('Content-Disposition', `attachment; filename=${encodeURIComponent(fileName)}`);
        res.setHeader('Content-Type', 'application/octet-stream');

        if (response.body && typeof response.body.pipe === 'function') {
            response.body.pipe(res);
            return;
        }
        if (response.body && typeof response.body.getReader === 'function') {
            Readable.fromWeb(response.body).pipe(res);
            return;
        }

        const buffer = Buffer.from(await response.arrayBuffer());
        return res.send(buffer);
    } catch (error) {
        console.error('Server API file download endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/files/create-folder', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.write');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const directoryRaw = String(req.body.directory || '/').trim() || '/';
        const directory = directoryRaw.startsWith('/') ? directoryRaw : `/${directoryRaw}`;
        const name = String(req.body.name || '').trim();
        if (!name) {
            return res.status(400).json({ success: false, error: 'Field "name" is required.' });
        }
        if (name === '.' || name === '..' || /[\\/]/.test(name)) {
            return res.status(400).json({ success: false, error: 'Invalid folder name.' });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        connectorWs.send(JSON.stringify({
            type: 'create_folder',
            serverId: server.id,
            directory,
            name
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'file_list' && String(message.directory || '') === directory) {
                return {
                    success: true,
                    directory,
                    files: Array.isArray(message.files) ? message.files : []
                };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 12000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to create folder.' });
        }

        return res.json({
            success: true,
            directory,
            files: result.files
        });
    } catch (error) {
        console.error('Server API create folder endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/files/rename', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.write');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const directoryRaw = String(req.body.directory || '/').trim() || '/';
        const directory = directoryRaw.startsWith('/') ? directoryRaw : `/${directoryRaw}`;
        const name = String(req.body.name || '').trim();
        const newName = String(req.body.newName || '').trim();
        if (!name || !newName) {
            return res.status(400).json({ success: false, error: 'Fields "name" and "newName" are required.' });
        }
        if ([name, newName].some((value) => value === '.' || value === '..' || /[\\/]/.test(value))) {
            return res.status(400).json({ success: false, error: 'Invalid file/folder name.' });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        connectorWs.send(JSON.stringify({
            type: 'rename_file',
            serverId: server.id,
            directory,
            name,
            newName
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'file_list' && String(message.directory || '') === directory) {
                return {
                    success: true,
                    directory,
                    files: Array.isArray(message.files) ? message.files : []
                };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 12000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to rename file/folder.' });
        }

        return res.json({
            success: true,
            directory,
            files: result.files
        });
    } catch (error) {
        console.error('Server API rename endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/files/delete', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.write');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const directoryRaw = String(req.body.directory || '/').trim() || '/';
        const directory = directoryRaw.startsWith('/') ? directoryRaw : `/${directoryRaw}`;
        const rawFiles = Array.isArray(req.body.files)
            ? req.body.files
            : String(req.body.files || req.body.file || '').split(',').map((entry) => entry.trim());
        const files = Array.from(new Set(rawFiles
            .map((entry) => String(entry || '').trim())
            .filter((entry) => entry && entry !== '.' && entry !== '..' && !/[\\/]/.test(entry))));

        if (files.length === 0) {
            return res.status(400).json({ success: false, error: 'Field "files" must contain at least one valid entry.' });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        connectorWs.send(JSON.stringify({
            type: 'delete_files',
            serverId: server.id,
            directory,
            files
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'file_list' && String(message.directory || '') === directory) {
                return {
                    success: true,
                    directory,
                    files: Array.isArray(message.files) ? message.files : []
                };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 12000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to delete files/folders.' });
        }

        return res.json({
            success: true,
            directory,
            files: result.files
        });
    } catch (error) {
        console.error('Server API delete endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.post('/api/client/servers/:containerId/files/chmod', async (req, res) => {
    try {
        const auth = await authenticateServerApiClientRequest(req, 'server.files.write');
        if (!auth.ok) {
            return res.status(auth.status).json({ success: false, error: auth.error });
        }

        const directoryRaw = String(req.body.directory || '/').trim() || '/';
        const directory = directoryRaw.startsWith('/') ? directoryRaw : `/${directoryRaw}`;
        const name = String(req.body.name || '').trim();
        const permissions = String(req.body.permissions || '').trim();

        if (!name) {
            return res.status(400).json({ success: false, error: 'Field "name" is required.' });
        }
        if (name === '.' || name === '..' || /[\\/]/.test(name)) {
            return res.status(400).json({ success: false, error: 'Invalid file/folder name.' });
        }
        if (!/^[0-7]{3,4}$/.test(permissions)) {
            return res.status(400).json({ success: false, error: 'Field "permissions" must match octal format (e.g. 644, 755, 0755).' });
        }

        const server = auth.server;
        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        connectorWs.send(JSON.stringify({
            type: 'set_permissions',
            serverId: server.id,
            directory,
            name,
            permissions
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'file_list' && String(message.directory || '') === directory) {
                return {
                    success: true,
                    directory,
                    files: Array.isArray(message.files) ? message.files : []
                };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 12000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to apply file permissions.' });
        }

        return res.json({
            success: true,
            directory,
            files: result.files
        });
    } catch (error) {
        console.error('Server API chmod endpoint failed:', error);
        return res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

// API: Check server connector status
app.get('/server/:containerId/status', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });

        if (!server) return res.status(404).json({ error: 'Server not found' });

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.files')) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        const online = connectorConnections.has(server.allocation.connectorId);
        res.json({ online });
    } catch (err) {
        console.error("Error checking server status:", err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// File Download API
app.get('/server/:containerId/files/download', requireAuth, async (req, res) => {
    try {
        const filePath = req.query.file;
        if (!filePath) {
            return res.status(400).send('File path is required');
        }

        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] }]
        });

        if (!server) {
            return res.status(403).send('Forbidden');
        }
        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.files')) {
            return res.status(403).send('Forbidden');
        }

        const connector = server.allocation ? server.allocation.connector : null;
        if (!connector) return res.status(500).send('No connector error');

        const protocol = connector.ssl ? 'https://' : 'http://';
        const connectorUrl = `${protocol}${connector.fqdn}:${connector.port}/api/servers/${server.id}/files/read`;

        const response = await fetch(connectorUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${connector.token}`
            },
            body: JSON.stringify({ path: filePath })
        });

        if (!response.ok) {
            if (response.status === 404) return res.status(404).send('File not found');
            return res.status(response.status).send('Connector error');
        }

        const fileName = path.basename(filePath);
        // Set appropriate headers for file download
        res.setHeader('Content-disposition', `attachment; filename=${encodeURIComponent(fileName)}`);
        res.setHeader('Content-type', 'application/octet-stream');

        // Pipe download stream regardless of whether fetch returns a Node stream or a Web stream.
        if (response.body && typeof response.body.pipe === 'function') {
            response.body.pipe(res);
            return;
        }
        if (response.body && typeof response.body.getReader === 'function') {
            Readable.fromWeb(response.body).pipe(res);
            return;
        }

        const buffer = Buffer.from(await response.arrayBuffer());
        res.send(buffer);
    } catch (err) {
        console.error('Download file error:', err);
        res.status(500).send('Internal server error during download');
    }
});

// File Upload API (binary upload with progress from panel UI)
app.post('/server/:containerId/files/upload', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });

        if (!server) {
            return res.status(404).json({ success: false, error: 'Server not found.' });
        }

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.files')) {
            return res.status(403).json({ success: false, error: 'Forbidden' });
        }

        const uploadEnabledRaw = String((res.locals.settings && res.locals.settings.featureWebUploadEnabled) || 'true').trim().toLowerCase();
        const uploadEnabled = uploadEnabledRaw === 'true' || uploadEnabledRaw === '1' || uploadEnabledRaw === 'on' || uploadEnabledRaw === 'yes';
        if (!uploadEnabled) {
            return res.status(403).json({ success: false, error: 'Web upload is disabled by admin.' });
        }

        const uploadMaxMbRaw = Number.parseInt(String((res.locals.settings && res.locals.settings.featureWebUploadMaxMb) || '50').trim(), 10);
        const uploadMaxMb = Math.max(1, Math.min(2048, Number.isInteger(uploadMaxMbRaw) ? uploadMaxMbRaw : 50));
        const uploadMaxBytes = uploadMaxMb * 1024 * 1024;

        if (!server.allocation || !server.allocation.connectorId) {
            return res.status(409).json({ success: false, error: 'Server allocation is missing.' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ success: false, error: 'Connector is offline.' });
        }

        const fileNameRaw = req.headers['x-file-name'] || req.query.name || '';
        const fileName = sanitizeUploadFileName(fileNameRaw);
        if (!fileName) {
            return res.status(400).json({ success: false, error: 'Invalid file name.' });
        }

        const directory = normalizeServerDirectoryInput(req.query.path || '/');
        const rawContent = await readBinaryRequestBody(req, uploadMaxBytes);
        const filePath = directory === '/' ? `/${fileName}` : `${directory}/${fileName}`;
        const threatCheck = inspectUploadForMinerRisk(fileName, rawContent);

        if (threatCheck.flagged) {
            const securityReason = `Upload blocked by anti-miner guard: score=${threatCheck.score}; evidence=${threatCheck.evidence.join(', ') || 'n/a'}; file=${fileName}`;
            await appendSecurityCenterAlert(
                'Suspicious upload blocked (anti-miner)',
                `Server: ${server.name} (#${server.id}, ${server.containerId})\nUser ID: ${req.session.user.id}\nPath: ${filePath}\n${securityReason}`,
                'critical',
                'security'
            );

            const antiMinerEnabled = isTruthySettingValue(res.locals.settings && res.locals.settings.featureAntiMinerEnabled);
            if (antiMinerEnabled) {
                await suspendServerForUploadThreat(
                    server,
                    connectorWs,
                    `Security policy: anti-miner upload detection triggered (${fileName}).`,
                    req
                );
            } else if (typeof createBillingAuditLog === 'function') {
                await createBillingAuditLog({
                    actorUserId: req.session.user.id,
                    action: 'server.security.upload_miner_blocked',
                    targetType: 'server',
                    targetId: server.id,
                    req,
                    metadata: {
                        serverId: server.id,
                        containerId: server.containerId,
                        filePath,
                        score: threatCheck.score,
                        evidence: threatCheck.evidence,
                        suspended: false
                    }
                });
            }

            return res.status(422).json({
                success: false,
                error: antiMinerEnabled
                    ? 'Upload blocked: suspicious miner payload detected. Server was suspended automatically.'
                    : 'Upload blocked: suspicious miner payload detected.'
            });
        }

        connectorWs.send(JSON.stringify({
            type: 'write_file',
            serverId: server.id,
            filePath,
            encoding: 'base64',
            contentBase64: rawContent.toString('base64')
        }));

        const result = await waitForConnectorMessage(connectorWs, (message) => {
            if (Number.parseInt(message.serverId, 10) !== Number.parseInt(server.id, 10)) return null;
            if (String(message.type || '') === 'write_success' && String(message.filePath || '') === filePath) {
                return { success: true };
            }
            if (String(message.type || '') === 'error') {
                return {
                    success: false,
                    error: String(message.message || 'Connector returned an error.')
                };
            }
            return null;
        }, 20000);

        if (!result.success) {
            return res.status(502).json({ success: false, error: result.error || 'Failed to upload file.' });
        }

        return res.json({
            success: true,
            filePath,
            size: rawContent.length
        });
    } catch (err) {
        console.error('Upload file error:', err);
        const message = String(err && err.message ? err.message : 'Upload failed.');
        const statusCode = message.toLowerCase().includes('max') || message.toLowerCase().includes('too large')
            ? 413
            : 500;
        return res.status(statusCode).json({ success: false, error: message });
    }
});


// API: Fetch file list (JSON) for auto-refresh
app.get('/server/:containerId/files-fetch', requireAuth, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });

        if (!server) return res.status(404).json({ error: 'Server not found' });

        const access = await resolveServerAccess(server, req.session.user);
        if (!hasServerPermission(access, 'server.files')) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        const connectorWs = connectorConnections.get(server.allocation.connectorId);
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.status(503).json({ error: 'Connector is offline' });
        }

        const directory = req.query.path || '/';

        // Send request to connector
        connectorWs.send(JSON.stringify({
            type: 'list_files',
            serverId: server.id,
            directory: directory
        }));

        // Wait for response (timeout 3.5s)
        const response = await new Promise((resolve) => {
            const timer = setTimeout(() => {
                connectorWs.removeListener('message', handleMessage);
                resolve({ error: 'Timeout waiting for connector' });
            }, 3500);

            function handleMessage(messageData) {
                try {
                    const data = JSON.parse(messageData);
                    if (data.type === 'file_list' && data.serverId === server.id && data.directory === directory) {
                        clearTimeout(timer);
                        connectorWs.removeListener('message', handleMessage);
                        resolve(data);
                    } else if (data.type === 'error' && data.serverId === server.id) {
                        clearTimeout(timer);
                        connectorWs.removeListener('message', handleMessage);
                        resolve({ error: data.message });
                    }
                } catch (e) { }
            }

            connectorWs.on('message', handleMessage);
        });

        if (response.error) {
            return res.status(500).json({ error: response.error });
        }

        res.json(response);
    } catch (err) {
        console.error("Error in files-fetch:", err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

}

module.exports = { registerServerPagesRoutes };
