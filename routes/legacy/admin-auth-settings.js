function registerAdminAuthSettingsRoutes(ctx) {
    const nodeCrypto = require('crypto');
    const {
        STORE_DEALS_SETTING_KEY,
        normalizeStoreDealsCatalog,
        normalizeStoreDeal,
        getStoreDealStatus,
        getStoreDealRemainingStock
    } = require('../../core/helpers/store-deals');
    const {
        STORE_REDEEM_CODES_SETTING_KEY,
        normalizeRedeemCodeValue,
        normalizeStoreRedeemCode,
        normalizeStoreRedeemCodesCatalog,
        getStoreRedeemCodeStatus,
        getStoreRedeemCodeRemainingUses
    } = require('../../core/helpers/store-redeem-codes');
    const {
        REVENUE_PLAN_CATALOG_SETTING_KEY,
        normalizeRevenuePlan,
        normalizeRevenuePlanCatalog,
        toSafeInt: revenueToSafeInt
    } = require('../../core/helpers/revenue-mode');
    const {
        getAdminApiRatePlanSettingKey,
        normalizeAdminApiRatePlan
    } = require('../../core/helpers/admin-api-rate-plans');
    for (const [key, value] of Object.entries(ctx || {})) {
        try {
            globalThis[key] = value;
        } catch {
            // Ignore non-writable globals (e.g. crypto on newer Node versions).
        }
    }
const toBooleanString = (value) => (value === 'on' || value === true || value === 'true' || value === 1 || value === '1' ? 'true' : 'false');
const toNumberString = (value, fallback, min = 0, max = 1_000_000) => {
    const parsed = Number.parseFloat(String(value === undefined || value === null ? '' : value).trim());
    if (!Number.isFinite(parsed)) return String(fallback);
    const clamped = Math.min(max, Math.max(min, parsed));
    return String(clamped);
};
const normalizeAfkPeriod = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    return ['minute', 'hour', 'day', 'week', 'month', 'year'].includes(normalized) ? normalized : 'minute';
};
const normalizeAnnouncerSeverity = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    return ['normal', 'warning', 'critical'].includes(normalized) ? normalized : 'normal';
};
const EXTENSION_WEBHOOKS_SETTING_KEY = 'extensionWebhooksConfig';
const EXTENSION_INCIDENTS_SETTING_KEY = 'extensionIncidentsRecords';
const EXTENSION_MAINTENANCE_SETTING_KEY = 'extensionMaintenanceRecords';
const EXTENSION_SECURITY_ALERTS_SETTING_KEY = 'extensionSecurityAlertsRecords';
const MAX_EXTENSION_RECORDS = 300;

const normalizeStatusSeverity = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    return ['normal', 'warning', 'critical'].includes(normalized) ? normalized : 'normal';
};

const sanitizeHttpUrlSafe = (value) => {
    if (typeof sanitizeHttpUrl === 'function') {
        return sanitizeHttpUrl(value);
    }
    const raw = String(value || '').trim();
    if (!raw) return '';
    try {
        const parsed = new URL(raw);
        const protocol = String(parsed.protocol || '').toLowerCase();
        if (protocol !== 'http:' && protocol !== 'https:') return '';
        return parsed.toString();
    } catch {
        return '';
    }
};

const parseJsonSafely = (raw, fallback) => {
    if (raw === undefined || raw === null || raw === '') return fallback;
    try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return parsed === undefined || parsed === null ? fallback : parsed;
    } catch {
        return fallback;
    }
};

const parseTimestampInput = (value, fallbackMs) => {
    const minReasonableMs = 946684800000; // 2000-01-01T00:00:00.000Z
    const fallback = Number.isFinite(Number(fallbackMs)) && Number(fallbackMs) > 0 ? Number(fallbackMs) : Date.now();

    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
        const ts = value < 10_000_000_000 ? Math.floor(value * 1000) : Math.floor(value);
        return ts >= minReasonableMs ? ts : fallback;
    }

    const raw = String(value || '').trim();
    if (/^\d+$/.test(raw)) {
        const direct = Number.parseInt(raw, 10);
        if (Number.isInteger(direct) && direct > 0) {
            const ts = direct < 10_000_000_000 ? direct * 1000 : direct;
            return ts >= minReasonableMs ? ts : fallback;
        }
    }

    const dateMs = new Date(raw).getTime();
    if (Number.isFinite(dateMs) && dateMs >= minReasonableMs) return dateMs;
    return fallback;
};

const buildRecordId = () => {
    try {
        return nodeCrypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }
};

const normalizeExtensionWebhooksConfig = (raw) => {
    const parsed = parseJsonSafely(raw, {});
    const events = parsed && typeof parsed.events === 'object' ? parsed.events : {};
    const eventEnabledOrDefault = (key) => {
        if (events[key] === undefined || events[key] === null) return true;
        return toBooleanString(events[key]) === 'true';
    };
    return {
        enabled: toBooleanString(parsed.enabled) === 'true',
        discordWebhook: sanitizeHttpUrlSafe(parsed.discordWebhook),
        telegramBotToken: String(parsed.telegramBotToken || '').trim(),
        telegramChatId: String(parsed.telegramChatId || '').trim(),
        events: {
            incidentCreated: eventEnabledOrDefault('incidentCreated'),
            incidentResolved: eventEnabledOrDefault('incidentResolved'),
            maintenanceScheduled: eventEnabledOrDefault('maintenanceScheduled'),
            maintenanceCompleted: eventEnabledOrDefault('maintenanceCompleted'),
            securityAlertCreated: eventEnabledOrDefault('securityAlertCreated'),
            securityAlertResolved: eventEnabledOrDefault('securityAlertResolved'),
            serverStarted: eventEnabledOrDefault('serverStarted'),
            serverStopped: eventEnabledOrDefault('serverStopped'),
            serverCrashed: eventEnabledOrDefault('serverCrashed'),
            serverInstallFailed: eventEnabledOrDefault('serverInstallFailed'),
            connectorError: eventEnabledOrDefault('connectorError'),
            commandFailed: eventEnabledOrDefault('commandFailed'),
            runtimeIncidentCreated: eventEnabledOrDefault('runtimeIncidentCreated')
        }
    };
};

const defaultExtensionWebhooksConfig = () => normalizeExtensionWebhooksConfig({
    enabled: false,
    discordWebhook: '',
    telegramBotToken: '',
    telegramChatId: '',
    events: {
        incidentCreated: true,
        incidentResolved: true,
        maintenanceScheduled: true,
        maintenanceCompleted: true,
        securityAlertCreated: true,
        securityAlertResolved: true,
        serverStarted: true,
        serverStopped: true,
        serverCrashed: true,
        serverInstallFailed: true,
        connectorError: true,
        commandFailed: true,
        runtimeIncidentCreated: true
    }
});

const normalizeIncidentRecords = (raw) => {
    const parsed = parseJsonSafely(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => {
            const now = Date.now();
            const status = String(entry && entry.status || '').trim().toLowerCase() === 'resolved' ? 'resolved' : 'open';
            const createdAtMs = parseTimestampInput(entry && entry.createdAtMs, now);
            const updatedAtMs = parseTimestampInput(entry && entry.updatedAtMs, createdAtMs);
            const resolvedAtMs = status === 'resolved' ? parseTimestampInput(entry && entry.resolvedAtMs, updatedAtMs) : 0;
            return {
                id: String(entry && entry.id || '').trim() || buildRecordId(),
                title: String(entry && entry.title || '').trim().slice(0, 120),
                message: String(entry && entry.message || '').trim().slice(0, 1200),
                severity: normalizeStatusSeverity(entry && entry.severity),
                status,
                createdAtMs,
                updatedAtMs,
                resolvedAtMs
            };
        })
        .filter((entry) => entry.title.length > 0)
        .sort((a, b) => b.createdAtMs - a.createdAtMs)
        .slice(0, MAX_EXTENSION_RECORDS);
};

const normalizeMaintenanceRecords = (raw) => {
    const parsed = parseJsonSafely(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => {
            const now = Date.now();
            const createdAtMs = parseTimestampInput(entry && entry.createdAtMs, now);
            const updatedAtMs = parseTimestampInput(entry && entry.updatedAtMs, createdAtMs);
            const startsAtMs = parseTimestampInput(entry && entry.startsAtMs, createdAtMs);
            const endsAtMs = parseTimestampInput(entry && entry.endsAtMs, startsAtMs + (60 * 60 * 1000));
            const completed = toBooleanString(entry && entry.completed) === 'true';
            return {
                id: String(entry && entry.id || '').trim() || buildRecordId(),
                title: String(entry && entry.title || '').trim().slice(0, 120),
                message: String(entry && entry.message || '').trim().slice(0, 1200),
                severity: normalizeStatusSeverity(entry && entry.severity),
                startsAtMs,
                endsAtMs: Math.max(startsAtMs, endsAtMs),
                completed,
                completedAtMs: completed ? parseTimestampInput(entry && entry.completedAtMs, updatedAtMs) : 0,
                createdAtMs,
                updatedAtMs
            };
        })
        .filter((entry) => entry.title.length > 0)
        .sort((a, b) => b.createdAtMs - a.createdAtMs)
        .slice(0, MAX_EXTENSION_RECORDS);
};

const normalizeSecurityAlertRecords = (raw) => {
    const parsed = parseJsonSafely(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => {
            const now = Date.now();
            const status = String(entry && entry.status || '').trim().toLowerCase() === 'resolved' ? 'resolved' : 'open';
            const createdAtMs = parseTimestampInput(entry && entry.createdAtMs, now);
            const updatedAtMs = parseTimestampInput(entry && entry.updatedAtMs, createdAtMs);
            return {
                id: String(entry && entry.id || '').trim() || buildRecordId(),
                title: String(entry && entry.title || '').trim().slice(0, 120),
                message: String(entry && entry.message || '').trim().slice(0, 1200),
                severity: normalizeStatusSeverity(entry && entry.severity),
                category: String(entry && entry.category || 'general').trim().slice(0, 60) || 'general',
                status,
                createdAtMs,
                updatedAtMs,
                resolvedAtMs: status === 'resolved' ? parseTimestampInput(entry && entry.resolvedAtMs, updatedAtMs) : 0
            };
        })
        .filter((entry) => entry.title.length > 0)
        .sort((a, b) => b.createdAtMs - a.createdAtMs)
        .slice(0, MAX_EXTENSION_RECORDS);
};

const saveJsonSetting = async (key, value) => {
    await Settings.upsert({ key, value: JSON.stringify(value) });
};

const getJsonSetting = async (key, fallback) => {
    const row = await Settings.findByPk(key);
    if (!row || !row.value) return fallback;
    return parseJsonSafely(row.value, fallback);
};

const getExtensionWebhooksConfig = async () => {
    const stored = await getJsonSetting(EXTENSION_WEBHOOKS_SETTING_KEY, defaultExtensionWebhooksConfig());
    return normalizeExtensionWebhooksConfig(stored);
};

const setExtensionWebhooksConfig = async (config) => {
    const normalized = normalizeExtensionWebhooksConfig(config);
    await saveJsonSetting(EXTENSION_WEBHOOKS_SETTING_KEY, normalized);
    return normalized;
};

const getIncidentRecords = async () => {
    const stored = await getJsonSetting(EXTENSION_INCIDENTS_SETTING_KEY, []);
    return normalizeIncidentRecords(stored);
};

const setIncidentRecords = async (records) => {
    const normalized = normalizeIncidentRecords(records);
    await saveJsonSetting(EXTENSION_INCIDENTS_SETTING_KEY, normalized);
    return normalized;
};

const getMaintenanceRecords = async () => {
    const stored = await getJsonSetting(EXTENSION_MAINTENANCE_SETTING_KEY, []);
    return normalizeMaintenanceRecords(stored);
};

const setMaintenanceRecords = async (records) => {
    const normalized = normalizeMaintenanceRecords(records);
    await saveJsonSetting(EXTENSION_MAINTENANCE_SETTING_KEY, normalized);
    return normalized;
};

const getSecurityAlertRecords = async () => {
    const stored = await getJsonSetting(EXTENSION_SECURITY_ALERTS_SETTING_KEY, []);
    return normalizeSecurityAlertRecords(stored);
};

const setSecurityAlertRecords = async (records) => {
    const normalized = normalizeSecurityAlertRecords(records);
    await saveJsonSetting(EXTENSION_SECURITY_ALERTS_SETTING_KEY, normalized);
    return normalized;
};

const getStoreDealsCatalog = async () => {
    const row = await Settings.findByPk(STORE_DEALS_SETTING_KEY);
    if (!row || !row.value) return [];
    return normalizeStoreDealsCatalog(row.value);
};

const setStoreDealsCatalog = async (catalog) => {
    const normalized = normalizeStoreDealsCatalog(catalog);
    await Settings.upsert({
        key: STORE_DEALS_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
};

const getStoreRedeemCodesCatalog = async () => {
    const row = await Settings.findByPk(STORE_REDEEM_CODES_SETTING_KEY);
    if (!row || !row.value) return [];
    return normalizeStoreRedeemCodesCatalog(row.value);
};

const setStoreRedeemCodesCatalog = async (catalog) => {
    const normalized = normalizeStoreRedeemCodesCatalog(catalog);
    await Settings.upsert({
        key: STORE_REDEEM_CODES_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
};

const getRevenuePlanCatalog = async () => {
    const row = await Settings.findByPk(REVENUE_PLAN_CATALOG_SETTING_KEY);
    if (!row || !row.value) return [];
    return normalizeRevenuePlanCatalog(row.value);
};

const setRevenuePlanCatalog = async (catalog) => {
    const normalized = normalizeRevenuePlanCatalog(catalog);
    await Settings.upsert({
        key: REVENUE_PLAN_CATALOG_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
};

const parseDealFloat = (value, fallback = 0, min = 0, max = 1000000) => {
    const parsed = Number.parseFloat(String(value === undefined || value === null ? '' : value).trim());
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
};

const parseDealInteger = (value, fallback = 0, min = 0, max = 1000000000) => {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
};

const parseDealFormInput = (body, existingDeal = null) => {
    const name = String(body.name || '').trim().slice(0, 120);
    if (!name) {
        return { ok: false, error: 'Deal name is required.' };
    }
    const description = String(body.description || '').trim().slice(0, 1200);
    const imageUrlRaw = String(body.imageUrl || '').trim();
    const imageUrl = imageUrlRaw ? sanitizeHttpUrlSafe(imageUrlRaw) : '';
    if (imageUrlRaw && !imageUrl) {
        return { ok: false, error: 'Image URL must be valid HTTP/HTTPS.' };
    }

    const priceCoins = parseDealInteger(body.priceCoins, 0, 0, 1000000000);
    const requestedStockTotal = parseDealInteger(body.stockTotal, existingDeal ? existingDeal.stockTotal : 1, 1, 1000000000);
    const existingSold = existingDeal ? parseDealInteger(existingDeal.stockSold, 0, 0, 1000000000) : 0;
    const stockTotal = Math.max(existingSold, requestedStockTotal);
    const enabled = toBooleanString(body.enabled) === 'true';
    const featured = toBooleanString(body.featured) === 'true';

    const resources = {
        ramMb: Math.max(0, Math.round(parseDealFloat(body.resourceRamGb, 0, 0, 1000000) * 1024)),
        cpuPercent: Math.max(0, Math.round(parseDealFloat(body.resourceCpuCores, 0, 0, 1000000) * 100)),
        diskMb: Math.max(0, Math.round(parseDealFloat(body.resourceDiskGb, 0, 0, 1000000) * 1024)),
        swapMb: Math.max(0, Math.round(parseDealFloat(body.resourceSwapGb, 0, 0, 1000000) * 1024)),
        allocations: parseDealInteger(body.resourceAllocations, 0, 0, 1000000000),
        images: parseDealInteger(body.resourceImages, 0, 0, 1000000000),
        databases: parseDealInteger(body.resourceDatabases, 0, 0, 1000000000),
        packages: parseDealInteger(body.resourcePackages, 0, 0, 1000000000)
    };
    const totalResourceUnits = resources.ramMb + resources.cpuPercent + resources.diskMb + resources.swapMb + resources.allocations + resources.images + resources.databases + resources.packages;
    if (totalResourceUnits <= 0) {
        return { ok: false, error: 'Deal must include at least one resource.' };
    }

    const nowMs = Date.now();
    const normalized = normalizeStoreDeal({
        id: existingDeal ? existingDeal.id : undefined,
        name,
        description,
        imageUrl,
        priceCoins,
        stockTotal,
        stockSold: existingSold,
        enabled,
        featured,
        createdAtMs: existingDeal ? existingDeal.createdAtMs : nowMs,
        updatedAtMs: nowMs,
        resources
    });

    return { ok: true, deal: normalized };
};

const parseRedeemFormInput = (body, existingCode = null, catalog = []) => {
    const existing = existingCode && typeof existingCode === 'object' ? existingCode : null;
    const rawCode = String(body.code || (existing ? existing.code : '') || '').trim();
    const code = normalizeRedeemCodeValue(rawCode);
    if (!code) {
        return { ok: false, error: 'Code is required and must contain A-Z, 0-9, "_" or "-".' };
    }

    const name = String(body.name || '').trim().slice(0, 120) || code;
    const description = String(body.description || '').trim().slice(0, 1200);
    const enabled = toBooleanString(body.enabled) === 'true';

    const duplicate = (Array.isArray(catalog) ? catalog : []).find((entry) => {
        if (!entry || typeof entry !== 'object') return false;
        if (existing && String(entry.id) === String(existing.id)) return false;
        return String(entry.code || '').trim().toUpperCase() === code;
    });
    if (duplicate) {
        return { ok: false, error: `Code "${code}" already exists.` };
    }

    const expiresAtRaw = String(body.expiresAt || '').trim();
    let expiresAtMs = 0;
    if (expiresAtRaw) {
        const parsed = new Date(expiresAtRaw).getTime();
        if (!Number.isFinite(parsed) || parsed <= 0) {
            return { ok: false, error: 'Expiration date is invalid.' };
        }
        expiresAtMs = Math.floor(parsed);
    }

    const maxUses = parseDealInteger(body.maxUses, existing ? existing.maxUses : 0, 0, 1000000000);
    const perUserLimit = parseDealInteger(body.perUserLimit, existing ? existing.perUserLimit : 1, 0, 1000000000);
    const rewards = {
        coins: parseDealInteger(body.rewardCoins, existing && existing.rewards ? existing.rewards.coins : 0, 0, 1000000000),
        ramMb: Math.max(0, Math.round(parseDealFloat(body.rewardRamGb, existing && existing.rewards ? (Number(existing.rewards.ramMb || 0) / 1024) : 0, 0, 1000000) * 1024)),
        cpuPercent: Math.max(0, Math.round(parseDealFloat(body.rewardCpuCores, existing && existing.rewards ? (Number(existing.rewards.cpuPercent || 0) / 100) : 0, 0, 1000000) * 100)),
        diskMb: Math.max(0, Math.round(parseDealFloat(body.rewardDiskGb, existing && existing.rewards ? (Number(existing.rewards.diskMb || 0) / 1024) : 0, 0, 1000000) * 1024)),
        swapMb: Math.max(0, Math.round(parseDealFloat(body.rewardSwapGb, existing && existing.rewards ? (Number(existing.rewards.swapMb || 0) / 1024) : 0, 0, 1000000) * 1024)),
        allocations: parseDealInteger(body.rewardAllocations, existing && existing.rewards ? existing.rewards.allocations : 0, 0, 1000000000),
        images: parseDealInteger(body.rewardImages, existing && existing.rewards ? existing.rewards.images : 0, 0, 1000000000),
        databases: parseDealInteger(body.rewardDatabases, existing && existing.rewards ? existing.rewards.databases : 0, 0, 1000000000),
        packages: parseDealInteger(body.rewardPackages, existing && existing.rewards ? existing.rewards.packages : 0, 0, 1000000000)
    };

    const rewardTotal = Number(rewards.coins || 0)
        + Number(rewards.ramMb || 0)
        + Number(rewards.cpuPercent || 0)
        + Number(rewards.diskMb || 0)
        + Number(rewards.swapMb || 0)
        + Number(rewards.allocations || 0)
        + Number(rewards.images || 0)
        + Number(rewards.databases || 0)
        + Number(rewards.packages || 0);
    if (rewardTotal <= 0) {
        return { ok: false, error: 'Redeem code must provide at least one reward.' };
    }

    const nowMs = Date.now();
    const normalized = normalizeStoreRedeemCode({
        id: existing ? existing.id : undefined,
        code,
        name,
        description,
        enabled,
        expiresAtMs,
        maxUses,
        perUserLimit,
        usesCount: existing ? existing.usesCount : 0,
        usageByUser: existing ? existing.usageByUser : {},
        recentUses: existing ? existing.recentUses : [],
        createdAtMs: existing ? existing.createdAtMs : nowMs,
        updatedAtMs: nowMs,
        rewards
    });

    return { ok: true, codeEntry: normalized };
};

const parseRevenuePlanFormInput = (body, existingPlan = null, catalog = []) => {
    const existing = existingPlan && typeof existingPlan === 'object' ? existingPlan : null;
    const name = String(body.name || '').trim().slice(0, 120);
    if (!name) {
        return { ok: false, error: 'Plan name is required.' };
    }

    const duplicate = (Array.isArray(catalog) ? catalog : []).find((entry) => {
        if (!entry || typeof entry !== 'object') return false;
        if (existing && String(entry.id) === String(existing.id)) return false;
        return String(entry.name || '').trim().toLowerCase() === name.toLowerCase();
    });
    if (duplicate) {
        return { ok: false, error: `A revenue plan named "${name}" already exists.` };
    }

    const nowMs = Date.now();
    const normalized = normalizeRevenuePlan({
        id: existing ? existing.id : undefined,
        name,
        description: String(body.description || '').trim().slice(0, 500),
        enabled: toBooleanString(body.enabled) === 'true',
        periodDays: revenueToSafeInt(body.periodDays, existing ? existing.periodDays : 30, 1, 3650),
        priceCoins: revenueToSafeInt(body.priceCoins, existing ? existing.priceCoins : 0, 0, 1000000000),
        maxServers: revenueToSafeInt(body.maxServers, existing ? existing.maxServers : 0, 0, 1000000),
        maxMemoryMb: Math.max(0, Math.round(parseDealFloat(body.maxMemoryGb, existing ? (Number(existing.maxMemoryMb || 0) / 1024) : 0, 0, 1000000) * 1024)),
        maxCpuPercent: Math.max(0, Math.round(parseDealFloat(body.maxCpuCores, existing ? (Number(existing.maxCpuPercent || 0) / 100) : 0, 0, 1000000) * 100)),
        maxDiskMb: Math.max(0, Math.round(parseDealFloat(body.maxDiskGb, existing ? (Number(existing.maxDiskMb || 0) / 1024) : 0, 0, 1000000) * 1024)),
        createdAtMs: existing ? existing.createdAtMs : nowMs,
        updatedAtMs: nowMs
    });

    return { ok: true, plan: normalized };
};

const sendExtensionWebhookEvent = async (settingsMap, eventKey, title, description, colorHex = '#3b82f6') => {
    try {
        const moduleEnabled = toBooleanString(settingsMap && settingsMap.featureExtensionWebhooksEnabled) === 'true';
        if (!moduleEnabled) return;
        const cfg = await getExtensionWebhooksConfig();
        if (!cfg.enabled) return;
        if (!cfg.events || !cfg.events[eventKey]) return;
        if (!cfg.discordWebhook && (!cfg.telegramBotToken || !cfg.telegramChatId)) return;

        if (cfg.discordWebhook) {
            await sendDiscordSmartAlert(cfg.discordWebhook, title, description, colorHex);
        }
        if (cfg.telegramBotToken && cfg.telegramChatId) {
            await sendTelegramSmartAlert(cfg.telegramBotToken, cfg.telegramChatId, `${title}\n${description}`);
        }
    } catch (error) {
        console.warn(`Extension webhook event ${eventKey} failed:`, error.message);
    }
};
// Admin Settings
app.get('/admin/settings', requireAuth, requireAdmin, (req, res) => {
    res.render('admin/settings', {
        user: req.session.user,
        path: '/admin/settings',
        success: req.query.success || null,
        error: req.query.error || null
    });
});

app.post('/admin/settings', requireAuth, requireAdmin, [
    body('brandName').trim().notEmpty().withMessage('Brand Name is required'),
    body('faviconUrl').trim().notEmpty().withMessage('Favicon URL is required')
], async (req, res) => {
    const { brandName, faviconUrl } = req.body;

    const nextSettings = {
        brandName: String(brandName || '').trim(),
        faviconUrl: String(faviconUrl || '').trim(),
        featureAutoRemediationEnabled: toBooleanString(req.body.featureAutoRemediationEnabled),
        featurePolicyEngineEnabled: toBooleanString(req.body.featurePolicyEngineEnabled),
        featureSftpEnabled: toBooleanString(req.body.featureSftpEnabled),
        featureWebUploadEnabled: toBooleanString(req.body.featureWebUploadEnabled),
        featureAfkRewardsEnabled: toBooleanString(req.body.featureAfkRewardsEnabled),
        featureClaimRewardsEnabled: toBooleanString(req.body.featureClaimRewardsEnabled),
        featureWebUploadMaxMb: toNumberString(req.body.featureWebUploadMaxMb, 50, 1, 2048),
        economyUnit: String(req.body.economyUnit || 'Coins').trim().slice(0, 16) || 'Coins',
        afkTimerCoins: toNumberString(req.body.afkTimerCoins, 2, 0, 1000000),
        afkTimerCooldownSeconds: toNumberString(req.body.afkTimerCooldownSeconds, 60, 5, 86400),
        afkRewardActivePeriod: normalizeAfkPeriod(req.body.afkRewardActivePeriod),
        afkRewardMinuteCoins: toNumberString(req.body.afkRewardMinuteCoins, 2, 0, 1000000),
        afkRewardHourCoins: toNumberString(req.body.afkRewardHourCoins, 20, 0, 1000000),
        afkRewardDayCoins: toNumberString(req.body.afkRewardDayCoins, 120, 0, 1000000),
        afkRewardWeekCoins: toNumberString(req.body.afkRewardWeekCoins, 700, 0, 1000000),
        afkRewardMonthCoins: toNumberString(req.body.afkRewardMonthCoins, 3000, 0, 1000000),
        afkRewardYearCoins: toNumberString(req.body.afkRewardYearCoins, 36000, 0, 1000000),
        claimDailyStreakBonusCoins: toNumberString(req.body.claimDailyStreakBonusCoins, 5, 0, 1000000),
        claimDailyStreakMax: toNumberString(req.body.claimDailyStreakMax, 30, 1, 365),
        autoRemediationCooldownSeconds: toNumberString(req.body.autoRemediationCooldownSeconds, 300, 10, 86400)
    };

    try {
        for (const [key, value] of Object.entries(nextSettings)) {
            await Settings.upsert({ key, value });
            res.locals.settings[key] = value;
        }

        // Update locals for the current request
        res.locals.settings.brandName = nextSettings.brandName;
        res.locals.settings.faviconUrl = nextSettings.faviconUrl;

        return res.redirect('/admin/settings?success=' + encodeURIComponent('Settings updated successfully!'));
    } catch (error) {
        console.error("Error updating settings:", error);
        return res.redirect('/admin/settings?error=' + encodeURIComponent('Failed to update settings.'));
    }
});

app.get('/admin/let-user-create', requireAuth, requireAdmin, (req, res) => {
    res.render('admin/let-user-create', {
        user: req.session.user,
        path: '/admin/let-user-create',
        success: req.query.success || null,
        error: req.query.error || null
    });
});

app.post('/admin/let-user-create', requireAuth, requireAdmin, async (req, res) => {
    const nextSettings = {
        featureUserCreateEnabled: toBooleanString(req.body.featureUserCreateEnabled),
        featureCostPerServerEnabled: toBooleanString(req.body.featureCostPerServerEnabled),
        featureInventoryEnabled: toBooleanString(req.body.featureInventoryEnabled),
        featureStoreDealsEnabled: toBooleanString(req.body.featureStoreDealsEnabled),
        featureStoreRedeemCodesEnabled: toBooleanString(req.body.featureStoreRedeemCodesEnabled),
        featureQuotaForecastingEnabled: toBooleanString(req.body.featureQuotaForecastingEnabled),
        featureScheduledScalingEnabled: toBooleanString(req.body.featureScheduledScalingEnabled),
        featureAdminApiRatePlansEnabled: toBooleanString(req.body.featureAdminApiRatePlansEnabled),
        featureRevenueModeEnabled: toBooleanString(req.body.featureRevenueModeEnabled),
        economyUnit: String(req.body.economyUnit || 'Coins').trim().slice(0, 16) || 'Coins',
        revenueDefaultTrialDays: toNumberString(req.body.revenueDefaultTrialDays, 3, 0, 365),
        revenueGraceDays: toNumberString(req.body.revenueGraceDays, 2, 0, 365),
        costBasePerServerMonthly: toNumberString(req.body.costBasePerServerMonthly, 0, 0, 100000),
        costPerGbRamMonthly: toNumberString(req.body.costPerGbRamMonthly, 1.5, 0, 100000),
        costPerCpuCoreMonthly: toNumberString(req.body.costPerCpuCoreMonthly, 2.5, 0, 100000),
        costPerGbDiskMonthly: toNumberString(req.body.costPerGbDiskMonthly, 0.2, 0, 100000),
        storeRamPerGbCoins: toNumberString(req.body.storeRamPerGbCoins, 10, 0, 100000),
        storeCpuPerCoreCoins: toNumberString(req.body.storeCpuPerCoreCoins, 20, 0, 100000),
        storeSwapPerGbCoins: toNumberString(req.body.storeSwapPerGbCoins, 3, 0, 100000),
        storeDiskPerGbCoins: toNumberString(req.body.storeDiskPerGbCoins, 2, 0, 100000),
        storeAllocationCoins: toNumberString(req.body.storeAllocationCoins, 5, 0, 100000),
        storeImageCoins: toNumberString(req.body.storeImageCoins, 15, 0, 100000),
        storeDatabaseCoins: toNumberString(req.body.storeDatabaseCoins, 5, 0, 100000),
        storePackageCoins: toNumberString(req.body.storePackageCoins, 25, 0, 100000),
        storeRenewDays: toNumberString(req.body.storeRenewDays, 30, 1, 3650),
        storeDeleteGraceDays: toNumberString(req.body.storeDeleteGraceDays, 7, 1, 3650)
    };

    try {
        for (const [key, value] of Object.entries(nextSettings)) {
            await Settings.upsert({ key, value });
            res.locals.settings[key] = value;
        }
        return res.redirect('/admin/let-user-create?success=' + encodeURIComponent('Let user create settings updated successfully.'));
    } catch (error) {
        console.error('Error updating let-user-create settings:', error);
        return res.redirect('/admin/let-user-create?error=' + encodeURIComponent('Failed to update settings.'));
    }
});

app.get('/admin/store/deals', requireAuth, requireAdmin, async (req, res) => {
    try {
        const deals = await getStoreDealsCatalog();
        const nowMs = Date.now();
        const dealsView = deals.map((deal) => ({
            ...deal,
            status: getStoreDealStatus(deal),
            remainingStock: getStoreDealRemainingStock(deal)
        }));
        return res.render('admin/store-deals', {
            user: req.session.user,
            path: '/admin/store/deals',
            title: 'Store Deals',
            success: req.query.success || null,
            error: req.query.error || null,
            deals: dealsView,
            nowMs,
            economyUnit: String(res.locals.settings.economyUnit || 'Coins')
        });
    } catch (error) {
        console.error('Error loading store deals page:', error);
        return res.render('admin/store-deals', {
            user: req.session.user,
            path: '/admin/store/deals',
            title: 'Store Deals',
            success: null,
            error: 'Failed to load deals.',
            deals: [],
            nowMs: Date.now(),
            economyUnit: String(res.locals.settings.economyUnit || 'Coins')
        });
    }
});

app.post('/admin/store/deals', requireAuth, requireAdmin, async (req, res) => {
    try {
        const parsed = parseDealFormInput(req.body, null);
        if (!parsed.ok) {
            return res.redirect('/admin/store/deals?error=' + encodeURIComponent(parsed.error));
        }

        const catalog = await getStoreDealsCatalog();
        catalog.unshift(parsed.deal);
        await setStoreDealsCatalog(catalog);
        return res.redirect('/admin/store/deals?success=' + encodeURIComponent(`Deal "${parsed.deal.name}" created.`));
    } catch (error) {
        console.error('Error creating store deal:', error);
        return res.redirect('/admin/store/deals?error=' + encodeURIComponent('Failed to create deal.'));
    }
});

app.post('/admin/store/deals/:dealId/update', requireAuth, requireAdmin, async (req, res) => {
    try {
        const dealId = String(req.params.dealId || '').trim();
        if (!dealId) {
            return res.redirect('/admin/store/deals?error=' + encodeURIComponent('Invalid deal id.'));
        }

        const catalog = await getStoreDealsCatalog();
        const index = catalog.findIndex((entry) => String(entry.id) === dealId);
        if (index === -1) {
            return res.redirect('/admin/store/deals?error=' + encodeURIComponent('Deal not found.'));
        }

        const parsed = parseDealFormInput(req.body, catalog[index]);
        if (!parsed.ok) {
            return res.redirect('/admin/store/deals?error=' + encodeURIComponent(parsed.error));
        }

        catalog[index] = parsed.deal;
        await setStoreDealsCatalog(catalog);
        return res.redirect('/admin/store/deals?success=' + encodeURIComponent(`Deal "${parsed.deal.name}" updated.`));
    } catch (error) {
        console.error('Error updating store deal:', error);
        return res.redirect('/admin/store/deals?error=' + encodeURIComponent('Failed to update deal.'));
    }
});

app.get('/admin/store/redeem-codes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const codes = await getStoreRedeemCodesCatalog();
        const nowMs = Date.now();
        const codesView = codes.map((entry) => ({
            ...entry,
            status: getStoreRedeemCodeStatus(entry, nowMs),
            remainingUses: getStoreRedeemCodeRemainingUses(entry)
        }));
        return res.render('admin/store-redeem-codes', {
            user: req.session.user,
            path: '/admin/store/redeem-codes',
            title: 'Store Redeem Codes',
            success: req.query.success || null,
            error: req.query.error || null,
            codes: codesView,
            nowMs,
            economyUnit: String(res.locals.settings.economyUnit || 'Coins')
        });
    } catch (error) {
        console.error('Error loading store redeem codes page:', error);
        return res.render('admin/store-redeem-codes', {
            user: req.session.user,
            path: '/admin/store/redeem-codes',
            title: 'Store Redeem Codes',
            success: null,
            error: 'Failed to load redeem codes.',
            codes: [],
            nowMs: Date.now(),
            economyUnit: String(res.locals.settings.economyUnit || 'Coins')
        });
    }
});

app.post('/admin/store/redeem-codes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const catalog = await getStoreRedeemCodesCatalog();
        const parsed = parseRedeemFormInput(req.body, null, catalog);
        if (!parsed.ok) {
            return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent(parsed.error));
        }

        catalog.unshift(parsed.codeEntry);
        await setStoreRedeemCodesCatalog(catalog);
        return res.redirect('/admin/store/redeem-codes?success=' + encodeURIComponent(`Redeem code "${parsed.codeEntry.code}" created.`));
    } catch (error) {
        console.error('Error creating redeem code:', error);
        return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Failed to create redeem code.'));
    }
});

app.post('/admin/store/redeem-codes/:redeemId/update', requireAuth, requireAdmin, async (req, res) => {
    try {
        const redeemId = String(req.params.redeemId || '').trim();
        if (!redeemId) {
            return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Invalid redeem code id.'));
        }

        const catalog = await getStoreRedeemCodesCatalog();
        const index = catalog.findIndex((entry) => String(entry.id || '') === redeemId);
        if (index === -1) {
            return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Redeem code not found.'));
        }

        const parsed = parseRedeemFormInput(req.body, catalog[index], catalog);
        if (!parsed.ok) {
            return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent(parsed.error));
        }

        catalog[index] = parsed.codeEntry;
        await setStoreRedeemCodesCatalog(catalog);
        return res.redirect('/admin/store/redeem-codes?success=' + encodeURIComponent(`Redeem code "${parsed.codeEntry.code}" updated.`));
    } catch (error) {
        console.error('Error updating redeem code:', error);
        return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Failed to update redeem code.'));
    }
});

app.post('/admin/store/redeem-codes/:redeemId/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const redeemId = String(req.params.redeemId || '').trim();
        if (!redeemId) {
            return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Invalid redeem code id.'));
        }

        const catalog = await getStoreRedeemCodesCatalog();
        const index = catalog.findIndex((entry) => String(entry.id || '') === redeemId);
        if (index === -1) {
            return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Redeem code not found.'));
        }

        const removed = catalog[index];
        catalog.splice(index, 1);
        await setStoreRedeemCodesCatalog(catalog);
        return res.redirect('/admin/store/redeem-codes?success=' + encodeURIComponent(`Redeem code "${removed.code}" deleted.`));
    } catch (error) {
        console.error('Error deleting redeem code:', error);
        return res.redirect('/admin/store/redeem-codes?error=' + encodeURIComponent('Failed to delete redeem code.'));
    }
});

app.get('/admin/revenue-plans', requireAuth, requireAdmin, async (req, res) => {
    try {
        const plans = await getRevenuePlanCatalog();
        return res.render('admin/revenue-plans', {
            user: req.session.user,
            path: '/admin/revenue-plans',
            title: 'Revenue Plans',
            plans,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading revenue plans page:', error);
        return res.render('admin/revenue-plans', {
            user: req.session.user,
            path: '/admin/revenue-plans',
            title: 'Revenue Plans',
            plans: [],
            success: null,
            error: 'Failed to load revenue plans.'
        });
    }
});

app.post('/admin/revenue-plans', requireAuth, requireAdmin, async (req, res) => {
    try {
        const catalog = await getRevenuePlanCatalog();
        const parsed = parseRevenuePlanFormInput(req.body, null, catalog);
        if (!parsed.ok) {
            return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent(parsed.error));
        }
        catalog.unshift(parsed.plan);
        await setRevenuePlanCatalog(catalog);
        return res.redirect('/admin/revenue-plans?success=' + encodeURIComponent(`Revenue plan "${parsed.plan.name}" created.`));
    } catch (error) {
        console.error('Error creating revenue plan:', error);
        return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Failed to create revenue plan.'));
    }
});

app.post('/admin/revenue-plans/:planId/update', requireAuth, requireAdmin, async (req, res) => {
    try {
        const planId = String(req.params.planId || '').trim();
        if (!planId) {
            return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Invalid plan id.'));
        }
        const catalog = await getRevenuePlanCatalog();
        const index = catalog.findIndex((entry) => String(entry.id || '') === planId);
        if (index === -1) {
            return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Revenue plan not found.'));
        }
        const parsed = parseRevenuePlanFormInput(req.body, catalog[index], catalog);
        if (!parsed.ok) {
            return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent(parsed.error));
        }
        catalog[index] = parsed.plan;
        await setRevenuePlanCatalog(catalog);
        return res.redirect('/admin/revenue-plans?success=' + encodeURIComponent(`Revenue plan "${parsed.plan.name}" updated.`));
    } catch (error) {
        console.error('Error updating revenue plan:', error);
        return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Failed to update revenue plan.'));
    }
});

app.post('/admin/revenue-plans/:planId/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const planId = String(req.params.planId || '').trim();
        if (!planId) {
            return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Invalid plan id.'));
        }
        const catalog = await getRevenuePlanCatalog();
        const index = catalog.findIndex((entry) => String(entry.id || '') === planId);
        if (index === -1) {
            return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Revenue plan not found.'));
        }
        const [removed] = catalog.splice(index, 1);
        await setRevenuePlanCatalog(catalog);
        return res.redirect('/admin/revenue-plans?success=' + encodeURIComponent(`Revenue plan "${removed.name}" deleted.`));
    } catch (error) {
        console.error('Error deleting revenue plan:', error);
        return res.redirect('/admin/revenue-plans?error=' + encodeURIComponent('Failed to delete revenue plan.'));
    }
});

app.get('/admin/extensions', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [webhooksConfig, incidents, maintenanceItems, securityAlerts] = await Promise.all([
            getExtensionWebhooksConfig(),
            getIncidentRecords(),
            getMaintenanceRecords(),
            getSecurityAlertRecords()
        ]);
        res.render('admin/extensions', {
            user: req.session.user,
            path: '/admin/extensions',
            success: req.query.success || null,
            error: req.query.error || null,
            webhooksConfig,
            incidents,
            maintenanceItems,
            securityAlerts,
            nowMs: Date.now()
        });
    } catch (error) {
        console.error('Error loading extensions page:', error);
        res.render('admin/extensions', {
            user: req.session.user,
            path: '/admin/extensions',
            success: null,
            error: 'Failed to load extensions page.',
            webhooksConfig: defaultExtensionWebhooksConfig(),
            incidents: [],
            maintenanceItems: [],
            securityAlerts: [],
            nowMs: Date.now()
        });
    }
});

app.post('/admin/extensions/announcer', requireAuth, requireAdmin, async (req, res) => {
    const nextSettings = {
        extensionAnnouncerEnabled: toBooleanString(req.body.extensionAnnouncerEnabled),
        extensionAnnouncerSeverity: normalizeAnnouncerSeverity(req.body.extensionAnnouncerSeverity),
        extensionAnnouncerMessage: String(req.body.extensionAnnouncerMessage || '').trim().slice(0, 500)
    };

    try {
        for (const [key, value] of Object.entries(nextSettings)) {
            await Settings.upsert({ key, value });
            res.locals.settings[key] = value;
        }
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Announcer updated successfully.'));
    } catch (error) {
        console.error('Error updating announcer settings:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update announcer settings.'));
    }
});

app.post('/admin/extensions/webhooks', requireAuth, requireAdmin, async (req, res) => {
    const discordWebhookRaw = String(req.body.discordWebhook || '').trim();
    const discordWebhook = sanitizeHttpUrlSafe(discordWebhookRaw);
    if (discordWebhookRaw && !discordWebhook) {
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Webhook URL must be valid HTTP/HTTPS.'));
    }

    const telegramBotToken = String(req.body.telegramBotToken || '').trim();
    const telegramChatId = String(req.body.telegramChatId || '').trim();
    if ((telegramBotToken && !telegramChatId) || (!telegramBotToken && telegramChatId)) {
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('For Telegram, provide both bot token and chat ID.'));
    }

    const nextSettings = {
        featureExtensionWebhooksEnabled: toBooleanString(req.body.featureExtensionWebhooksEnabled)
    };

    const nextConfig = {
        enabled: toBooleanString(req.body.extensionWebhooksEnabled) === 'true',
        discordWebhook,
        telegramBotToken,
        telegramChatId,
        events: {
            incidentCreated: toBooleanString(req.body.webhookEventIncidentCreated) === 'true',
            incidentResolved: toBooleanString(req.body.webhookEventIncidentResolved) === 'true',
            maintenanceScheduled: toBooleanString(req.body.webhookEventMaintenanceScheduled) === 'true',
            maintenanceCompleted: toBooleanString(req.body.webhookEventMaintenanceCompleted) === 'true',
            securityAlertCreated: toBooleanString(req.body.webhookEventSecurityAlertCreated) === 'true',
            securityAlertResolved: toBooleanString(req.body.webhookEventSecurityAlertResolved) === 'true',
            serverStarted: toBooleanString(req.body.webhookEventServerStarted) === 'true',
            serverStopped: toBooleanString(req.body.webhookEventServerStopped) === 'true',
            serverCrashed: toBooleanString(req.body.webhookEventServerCrashed) === 'true',
            serverInstallFailed: toBooleanString(req.body.webhookEventServerInstallFailed) === 'true',
            connectorError: toBooleanString(req.body.webhookEventConnectorError) === 'true',
            commandFailed: toBooleanString(req.body.webhookEventCommandFailed) === 'true',
            runtimeIncidentCreated: toBooleanString(req.body.webhookEventRuntimeIncidentCreated) === 'true'
        }
    };

    try {
        for (const [key, value] of Object.entries(nextSettings)) {
            await Settings.upsert({ key, value });
            res.locals.settings[key] = value;
        }
        await setExtensionWebhooksConfig(nextConfig);
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Webhooks module updated successfully.'));
    } catch (error) {
        console.error('Error updating webhooks module:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update webhooks module.'));
    }
});

app.post('/admin/extensions/webhooks/test', requireAuth, requireAdmin, async (req, res) => {
    try {
        const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
        const actor = req.session && req.session.user ? req.session.user.username : 'admin';
        await sendExtensionWebhookEvent(
            res.locals.settings,
            'incidentCreated',
            `[${brandName}] Webhook Test`,
            `Manual webhook test triggered by ${actor} from Admin -> Extensions.`,
            '#3b82f6'
        );
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Webhook test event sent.'));
    } catch (error) {
        console.error('Error testing webhooks module:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to send webhook test.'));
    }
});

app.post('/admin/extensions/incidents/settings', requireAuth, requireAdmin, async (req, res) => {
    try {
        const value = toBooleanString(req.body.featureExtensionIncidentsEnabled);
        await Settings.upsert({ key: 'featureExtensionIncidentsEnabled', value });
        res.locals.settings.featureExtensionIncidentsEnabled = value;
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Incidents module settings updated.'));
    } catch (error) {
        console.error('Error updating incidents module settings:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update incidents module settings.'));
    }
});

app.post('/admin/extensions/incidents/create', requireAuth, requireAdmin, async (req, res) => {
    const title = String(req.body.incidentTitle || '').trim().slice(0, 120);
    const message = String(req.body.incidentMessage || '').trim().slice(0, 1200);
    if (!title) {
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Incident title is required.'));
    }

    try {
        const severity = normalizeStatusSeverity(req.body.incidentSeverity);
        const now = Date.now();
        const records = await getIncidentRecords();
        records.unshift({
            id: buildRecordId(),
            title,
            message,
            severity,
            status: 'open',
            createdAtMs: now,
            updatedAtMs: now,
            resolvedAtMs: 0
        });
        await setIncidentRecords(records);

        const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
        await sendExtensionWebhookEvent(
            res.locals.settings,
            'incidentCreated',
            `[${brandName}] Incident Created`,
            `${title}${message ? `\n${message}` : ''}`,
            severity === 'critical' ? '#ef4444' : severity === 'warning' ? '#f59e0b' : '#10b981'
        );

        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Incident created.'));
    } catch (error) {
        console.error('Error creating incident:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to create incident.'));
    }
});

app.post('/admin/extensions/incidents/:id/toggle', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id || '').trim();
        const now = Date.now();
        const records = await getIncidentRecords();
        const target = records.find((entry) => entry.id === id);
        if (!target) return res.redirect('/admin/extensions?error=' + encodeURIComponent('Incident not found.'));

        target.status = target.status === 'resolved' ? 'open' : 'resolved';
        target.updatedAtMs = now;
        target.resolvedAtMs = target.status === 'resolved' ? now : 0;
        await setIncidentRecords(records);

        if (target.status === 'resolved') {
            const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
            await sendExtensionWebhookEvent(
                res.locals.settings,
                'incidentResolved',
                `[${brandName}] Incident Resolved`,
                `${target.title}${target.message ? `\n${target.message}` : ''}`,
                '#10b981'
            );
        }
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Incident state updated.'));
    } catch (error) {
        console.error('Error toggling incident state:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update incident.'));
    }
});

app.post('/admin/extensions/incidents/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id || '').trim();
        const records = await getIncidentRecords();
        const filtered = records.filter((entry) => entry.id !== id);
        await setIncidentRecords(filtered);
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Incident deleted.'));
    } catch (error) {
        console.error('Error deleting incident:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to delete incident.'));
    }
});

app.post('/admin/extensions/maintenance/settings', requireAuth, requireAdmin, async (req, res) => {
    try {
        const value = toBooleanString(req.body.featureExtensionMaintenanceEnabled);
        await Settings.upsert({ key: 'featureExtensionMaintenanceEnabled', value });
        res.locals.settings.featureExtensionMaintenanceEnabled = value;
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Maintenance module settings updated.'));
    } catch (error) {
        console.error('Error updating maintenance module settings:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update maintenance module settings.'));
    }
});

app.post('/admin/extensions/maintenance/create', requireAuth, requireAdmin, async (req, res) => {
    const title = String(req.body.maintenanceTitle || '').trim().slice(0, 120);
    const message = String(req.body.maintenanceMessage || '').trim().slice(0, 1200);
    if (!title) return res.redirect('/admin/extensions?error=' + encodeURIComponent('Maintenance title is required.'));

    const now = Date.now();
    const startsAtMs = parseTimestampInput(req.body.maintenanceStartAt, now);
    const endsAtMs = parseTimestampInput(req.body.maintenanceEndAt, startsAtMs + (60 * 60 * 1000));
    if (endsAtMs < startsAtMs) {
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Maintenance end time must be after start time.'));
    }

    try {
        const severity = normalizeStatusSeverity(req.body.maintenanceSeverity);
        const records = await getMaintenanceRecords();
        records.unshift({
            id: buildRecordId(),
            title,
            message,
            severity,
            startsAtMs,
            endsAtMs,
            completed: false,
            completedAtMs: 0,
            createdAtMs: now,
            updatedAtMs: now
        });
        await setMaintenanceRecords(records);

        const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
        const startLabel = new Date(startsAtMs).toISOString();
        const endLabel = new Date(endsAtMs).toISOString();
        await sendExtensionWebhookEvent(
            res.locals.settings,
            'maintenanceScheduled',
            `[${brandName}] Maintenance Scheduled`,
            `${title}\nStart: ${startLabel}\nEnd: ${endLabel}${message ? `\n${message}` : ''}`,
            severity === 'critical' ? '#ef4444' : severity === 'warning' ? '#f59e0b' : '#10b981'
        );

        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Maintenance entry created.'));
    } catch (error) {
        console.error('Error creating maintenance entry:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to create maintenance entry.'));
    }
});

app.post('/admin/extensions/maintenance/:id/toggle-complete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id || '').trim();
        const records = await getMaintenanceRecords();
        const target = records.find((entry) => entry.id === id);
        if (!target) return res.redirect('/admin/extensions?error=' + encodeURIComponent('Maintenance entry not found.'));

        const now = Date.now();
        target.completed = !target.completed;
        target.completedAtMs = target.completed ? now : 0;
        target.updatedAtMs = now;
        await setMaintenanceRecords(records);

        if (target.completed) {
            const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
            await sendExtensionWebhookEvent(
                res.locals.settings,
                'maintenanceCompleted',
                `[${brandName}] Maintenance Completed`,
                `${target.title}${target.message ? `\n${target.message}` : ''}`,
                '#10b981'
            );
        }
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Maintenance state updated.'));
    } catch (error) {
        console.error('Error toggling maintenance state:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update maintenance state.'));
    }
});

app.post('/admin/extensions/maintenance/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id || '').trim();
        const records = await getMaintenanceRecords();
        const filtered = records.filter((entry) => entry.id !== id);
        await setMaintenanceRecords(filtered);
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Maintenance entry deleted.'));
    } catch (error) {
        console.error('Error deleting maintenance entry:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to delete maintenance entry.'));
    }
});

app.post('/admin/extensions/security/settings', requireAuth, requireAdmin, async (req, res) => {
    try {
        const value = toBooleanString(req.body.featureExtensionSecurityCenterEnabled);
        await Settings.upsert({ key: 'featureExtensionSecurityCenterEnabled', value });
        res.locals.settings.featureExtensionSecurityCenterEnabled = value;
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Security Center settings updated.'));
    } catch (error) {
        console.error('Error updating Security Center settings:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update Security Center settings.'));
    }
});

app.post('/admin/extensions/security/create', requireAuth, requireAdmin, async (req, res) => {
    const title = String(req.body.securityTitle || '').trim().slice(0, 120);
    const message = String(req.body.securityMessage || '').trim().slice(0, 1200);
    if (!title) return res.redirect('/admin/extensions?error=' + encodeURIComponent('Security alert title is required.'));

    try {
        const severity = normalizeStatusSeverity(req.body.securitySeverity);
        const category = String(req.body.securityCategory || 'general').trim().slice(0, 60) || 'general';
        const now = Date.now();
        const records = await getSecurityAlertRecords();
        records.unshift({
            id: buildRecordId(),
            title,
            message,
            severity,
            category,
            status: 'open',
            createdAtMs: now,
            updatedAtMs: now,
            resolvedAtMs: 0
        });
        await setSecurityAlertRecords(records);

        const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
        await sendExtensionWebhookEvent(
            res.locals.settings,
            'securityAlertCreated',
            `[${brandName}] Security Alert`,
            `${title}\nCategory: ${category}${message ? `\n${message}` : ''}`,
            severity === 'critical' ? '#ef4444' : severity === 'warning' ? '#f59e0b' : '#10b981'
        );

        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Security alert created.'));
    } catch (error) {
        console.error('Error creating security alert:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to create security alert.'));
    }
});

app.post('/admin/extensions/security/:id/toggle', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id || '').trim();
        const now = Date.now();
        const records = await getSecurityAlertRecords();
        const target = records.find((entry) => entry.id === id);
        if (!target) return res.redirect('/admin/extensions?error=' + encodeURIComponent('Security alert not found.'));

        target.status = target.status === 'resolved' ? 'open' : 'resolved';
        target.updatedAtMs = now;
        target.resolvedAtMs = target.status === 'resolved' ? now : 0;
        await setSecurityAlertRecords(records);

        if (target.status === 'resolved') {
            const brandName = String(res.locals.settings.brandName || 'CPanel').trim() || 'CPanel';
            await sendExtensionWebhookEvent(
                res.locals.settings,
                'securityAlertResolved',
                `[${brandName}] Security Alert Resolved`,
                `${target.title}${target.message ? `\n${target.message}` : ''}`,
                '#10b981'
            );
        }
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Security alert state updated.'));
    } catch (error) {
        console.error('Error toggling security alert state:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to update security alert.'));
    }
});

app.post('/admin/extensions/security/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id || '').trim();
        const records = await getSecurityAlertRecords();
        const filtered = records.filter((entry) => entry.id !== id);
        await setSecurityAlertRecords(filtered);
        return res.redirect('/admin/extensions?success=' + encodeURIComponent('Security alert deleted.'));
    } catch (error) {
        console.error('Error deleting security alert:', error);
        return res.redirect('/admin/extensions?error=' + encodeURIComponent('Failed to delete security alert.'));
    }
});

// Admin Auth Providers
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '');

app.get('/admin/auth-providers', requireAuth, requireAdmin, (req, res) => {
    res.render('admin/auth-providers', {
        user: req.session.user,
        path: '/admin/auth-providers',
        appUrl: APP_URL,
        success: req.query.success || null,
        error: req.query.error || null
    });
});

app.post('/admin/auth-providers', requireAuth, requireAdmin, async (req, res) => {
    const keys = [
        'authStandardEnabled',
        'authDiscordEnabled', 'authDiscordClientId', 'authDiscordClientSecret',
        'authGoogleEnabled', 'authGoogleClientId', 'authGoogleClientSecret',
        'authRedditEnabled', 'authRedditClientId', 'authRedditClientSecret',
        'authGithubEnabled', 'authGithubClientId', 'authGithubClientSecret'
    ];

    try {
        for (const key of keys) {
            let value = req.body[key];
            if (key.endsWith('Enabled')) {
                value = value === 'on' ? 'true' : 'false';
            } else {
                value = String(value || '').trim();
            }

            await Settings.upsert({ key, value });
            res.locals.settings[key] = value;
        }

        return res.redirect('/admin/auth-providers?success=' + encodeURIComponent('Auth provider settings updated successfully!'));
    } catch (error) {
        console.error('Error updating auth provider settings:', error);
        return res.redirect('/admin/auth-providers?error=' + encodeURIComponent('Failed to update auth provider settings.'));
    }
});
}

module.exports = { registerAdminAuthSettingsRoutes };
