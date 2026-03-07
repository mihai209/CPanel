const path = require('path');
const crypto = require('crypto');
const {
    REVENUE_PLAN_CATALOG_SETTING_KEY,
    USER_REVENUE_PROFILE_KEY_PREFIX,
    DAY_MS,
    REVENUE_SUSPEND_REASON_PREFIX,
    normalizeRevenuePlanCatalog,
    normalizeUserRevenueProfile,
    getUserRevenueProfileSettingKey
} = require('../revenue-mode');
const {
    SERVER_SCHEDULED_SCALING_KEY_PREFIX,
    getServerScheduledScalingSettingKey,
    normalizeServerScheduledScalingConfig,
    isRuleDueNow
} = require('../scheduled-scaling');

function createLegacyRuntimeHelpers(deps) {
    const {
        Settings,
        User,
        Server,
        Image,
        Allocation,
        AuditLog,
        Mount,
        ServerMount,
        Op,
        axios,
        WebSocket,
        connectorConnections,
        normalizeClientVariables,
        buildServerEnvironment,
        buildStartupCommand,
        resolveImagePorts,
        buildDeploymentPorts,
        shouldUseCommandStartup
    } = deps;

const SERVER_SMART_ALERTS_KEY_PREFIX = 'server_smart_alerts_';
const SERVER_STARTUP_PRESET_KEY_PREFIX = 'server_startup_preset_';
const serverPowerActionIntent = new Map(); // serverId -> { action, ts }
const MODRINTH_API_BASE_URL = 'https://api.modrinth.com/v2';
const MODRINTH_MAX_SEARCH_LIMIT = 30;
const MODRINTH_REQUEST_TIMEOUT_MS = 12000;
const MODRINTH_PLUGIN_LOADERS = ['paper', 'purpur', 'spigot', 'bukkit', 'folia', 'velocity', 'bungeecord', 'waterfall'];
const MODRINTH_MOD_LOADERS = ['fabric', 'forge', 'neoforge', 'quilt', 'liteloader', 'rift'];
const MINECRAFT_INSTALL_TRACKER_PREFIX = 'server_minecraft_installed_';
const RESOURCE_ANOMALY_STATE = new Map(); // serverId -> { cpuHits, memoryHits, lastAlertAt }
const RESOURCE_ANOMALY_SAMPLE_TS = new Map(); // serverId -> ts
const PLUGIN_CONFLICT_STATE = new Map(); // serverId -> { lastAlertAt, fingerprint }
const DEFAULT_STATS_ALERT_COOLDOWN_MS = 5 * 60 * 1000;
const DEFAULT_PLUGIN_ALERT_COOLDOWN_MS = 10 * 60 * 1000;
const pendingMigrationFileImports = new Map(); // serverId -> { connectorId, host, port, username, password, remotePath, cleanTarget }
const SERVER_MIGRATION_TRANSFER_KEY_PREFIX = 'server_migration_transfer_';
const MIGRATION_TRANSFER_STATUSES = new Set(['queued', 'running', 'completed', 'failed', 'skipped']);
const SERVER_POLICY_ENGINE_KEY_PREFIX = 'server_policy_engine_';
const POLICY_REMEDIATION_STATE = new Map(); // serverId -> remediation counters, cooldown and anomaly hits
const FEATURE_FLAGS_CACHE_TTL_MS = 10 * 1000;
const SERVER_POLICY_CACHE_TTL_MS = 10 * 1000;
let featureFlagsCache = null;
let featureFlagsCacheTs = 0;
const serverPolicyCache = new Map(); // serverId -> { ts, config }
const FEATURE_FLAG_SETTING_KEYS = [
    'featureUserCreateEnabled',
    'featureCostPerServerEnabled',
    'featureInventoryEnabled',
    'featureStoreDealsEnabled',
    'featureStoreRedeemCodesEnabled',
    'featureBillingInvoicesEnabled',
    'featureBillingStatementsEnabled',
    'featureBillingInvoiceWebhookEnabled',
    'featureQuotaForecastingEnabled',
    'featureAbuseScoreEnabled',
    'abuseScoreWindowHours',
    'abuseScoreAlertThreshold',
    'featureServiceHealthChecksEnabled',
    'serviceHealthCheckIntervalSeconds',
    'featureRemoteDownloadEnabled',
    'featureScheduledScalingEnabled',
    'featureAdminApiRatePlansEnabled',
    'featureRevenueModeEnabled',
    'featureAutoRemediationEnabled',
    'featureAntiMinerEnabled',
    'featurePolicyEngineEnabled',
    'featureSftpEnabled',
    'featureWebUploadEnabled',
    'featureWebUploadMaxMb',
    'economyUnit',
    'revenueDefaultTrialDays',
    'revenueGraceDays',
    'featureAfkRewardsEnabled',
    'featureClaimRewardsEnabled',
    'afkTimerCoins',
    'afkTimerCooldownSeconds',
    'afkRewardActivePeriod',
    'afkRewardMinuteCoins',
    'afkRewardHourCoins',
    'afkRewardDayCoins',
    'afkRewardWeekCoins',
    'afkRewardMonthCoins',
    'afkRewardYearCoins',
    'claimDailyStreakBonusCoins',
    'claimDailyStreakMax',
    'costBasePerServerMonthly',
    'costPerGbRamMonthly',
    'costPerCpuCoreMonthly',
    'costPerGbDiskMonthly',
    'autoRemediationCooldownSeconds',
    'antiMinerSuspendScore',
    'antiMinerHighCpuPercent',
    'antiMinerHighCpuSamples',
    'antiMinerDecayMinutes',
    'antiMinerCooldownSeconds',
    'storeRamPerGbCoins',
    'storeCpuPerCoreCoins',
    'storeSwapPerGbCoins',
    'storeDiskPerGbCoins',
    'storeAllocationCoins',
    'storeImageCoins',
    'storeDatabaseCoins',
    'storePackageCoins',
    'storeRenewDays',
    'storeDeleteGraceDays'
];

function parseIntegerInput(value, fallback) {
    if (value === undefined || value === null || String(value).trim() === '') {
        return { valid: true, value: fallback };
    }

    const parsed = Number.parseInt(String(value).trim(), 10);
    if (!Number.isInteger(parsed)) {
        return { valid: false, error: 'Expected an integer value.' };
    }
    return { valid: true, value: parsed };
}

function parseBooleanInput(value, fallback = false) {
    if (value === undefined || value === null) return fallback;
    if (Array.isArray(value)) {
        for (const entry of value) {
            if (parseBooleanInput(entry, false)) return true;
        }
        return false;
    }
    const normalized = String(value).trim().toLowerCase();
    return normalized === '1' || normalized === 'true' || normalized === 'on' || normalized === 'yes';
}

function parseFiniteNumberInput(value, fallback = 0, min = 0, max = Number.MAX_SAFE_INTEGER) {
    const parsed = Number.parseFloat(String(value === undefined || value === null ? '' : value).trim());
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function parseMigrationTimestamp(value, fallback = 0) {
    const numeric = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (Number.isInteger(numeric) && numeric > 0) return numeric;
    if (typeof value === 'string' && value.trim()) {
        const dateValue = new Date(value).getTime();
        if (Number.isFinite(dateValue) && dateValue > 0) return dateValue;
    }
    return fallback;
}

function getServerMigrationTransferSettingKey(serverId) {
    return `${SERVER_MIGRATION_TRANSFER_KEY_PREFIX}${serverId}`;
}

function normalizeServerMigrationTransferState(raw) {
    let parsed = raw;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const now = Date.now();
    const statusRaw = String(parsed.status || '').trim().toLowerCase();
    const status = MIGRATION_TRANSFER_STATUSES.has(statusRaw) ? statusRaw : 'queued';
    const createdAtMs = parseMigrationTimestamp(parsed.createdAtMs, now);
    const updatedAtMs = parseMigrationTimestamp(parsed.updatedAtMs, createdAtMs);

    return {
        status,
        message: String(parsed.message || '').trim(),
        connectorId: Math.max(0, Number.parseInt(parsed.connectorId, 10) || 0),
        jobId: Math.max(0, Number.parseInt(parsed.jobId, 10) || 0),
        startedAtMs: parseMigrationTimestamp(parsed.startedAtMs, 0),
        finishedAtMs: parseMigrationTimestamp(parsed.finishedAtMs, 0),
        createdAtMs,
        updatedAtMs,
        files: Math.max(0, Number.parseInt(parsed.files, 10) || 0),
        directories: Math.max(0, Number.parseInt(parsed.directories, 10) || 0),
        bytes: Math.max(0, Number.parseInt(parsed.bytes, 10) || 0),
        error: String(parsed.error || '').trim()
    };
}

async function getServerMigrationTransferState(serverId) {
    const setting = await Settings.findByPk(getServerMigrationTransferSettingKey(serverId));
    if (!setting || !setting.value) return null;
    return normalizeServerMigrationTransferState(setting.value);
}

async function setServerMigrationTransferState(serverId, statePatch = {}) {
    const existing = await getServerMigrationTransferState(serverId);
    const now = Date.now();
    const merged = {
        ...(existing || {
            status: 'queued',
            message: '',
            connectorId: 0,
            jobId: 0,
            startedAtMs: 0,
            finishedAtMs: 0,
            createdAtMs: now,
            updatedAtMs: now,
            files: 0,
            directories: 0,
            bytes: 0,
            error: ''
        }),
        ...(statePatch && typeof statePatch === 'object' ? statePatch : {}),
        updatedAtMs: now
    };

    if (!merged.createdAtMs || merged.createdAtMs <= 0) {
        merged.createdAtMs = now;
    }
    if (merged.status === 'running' && !merged.startedAtMs) {
        merged.startedAtMs = now;
    }
    if ((merged.status === 'completed' || merged.status === 'failed' || merged.status === 'skipped') && !merged.finishedAtMs) {
        merged.finishedAtMs = now;
    }
    if (merged.status === 'running') {
        merged.finishedAtMs = 0;
    }

    const normalized = normalizeServerMigrationTransferState(merged);
    await Settings.upsert({
        key: getServerMigrationTransferSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function removeServerMigrationTransferState(serverId) {
    await Settings.destroy({ where: { key: getServerMigrationTransferSettingKey(serverId) } });
}

function defaultPanelFeatureFlags() {
    return {
        userCreateEnabled: false,
        costPerServerEnabled: false,
        inventoryEnabled: false,
        storeDealsEnabled: false,
        storeRedeemCodesEnabled: false,
        billingInvoicesEnabled: true,
        billingStatementsEnabled: true,
        billingInvoiceWebhookEnabled: false,
        quotaForecastingEnabled: true,
        abuseScoreEnabled: false,
        abuseScoreWindowHours: 72,
        abuseScoreAlertThreshold: 80,
        serviceHealthChecksEnabled: false,
        serviceHealthCheckIntervalSeconds: 300,
        scheduledScalingEnabled: false,
        adminApiRatePlansEnabled: false,
        revenueModeEnabled: false,
        autoRemediationEnabled: false,
        antiMinerEnabled: false,
        policyEngineEnabled: false,
        sftpEnabled: true,
        webUploadEnabled: true,
        remoteDownloadEnabled: true,
        webUploadMaxMb: 50,
        economyUnit: 'Coins',
        revenueDefaultTrialDays: 3,
        revenueGraceDays: 2,
        afkRewardsEnabled: false,
        claimRewardsEnabled: false,
        afkTimerCoins: 2,
        afkTimerCooldownSeconds: 60,
        afkRewardActivePeriod: 'minute',
        afkRewardMinuteCoins: 2,
        afkRewardHourCoins: 20,
        afkRewardDayCoins: 120,
        afkRewardWeekCoins: 700,
        afkRewardMonthCoins: 3000,
        afkRewardYearCoins: 36000,
        claimDailyStreakBonusCoins: 5,
        claimDailyStreakMax: 30,
        costBasePerServerMonthly: 0,
        costPerGbRamMonthly: 1.5,
        costPerCpuCoreMonthly: 2.5,
        costPerGbDiskMonthly: 0.2,
        autoRemediationCooldownSeconds: 300,
        antiMinerSuspendScore: 10,
        antiMinerHighCpuPercent: 95,
        antiMinerHighCpuSamples: 8,
        antiMinerDecayMinutes: 20,
        antiMinerCooldownSeconds: 600,
        storeRamPerGbCoins: 10,
        storeCpuPerCoreCoins: 20,
        storeSwapPerGbCoins: 3,
        storeDiskPerGbCoins: 2,
        storeAllocationCoins: 5,
        storeImageCoins: 15,
        storeDatabaseCoins: 5,
        storePackageCoins: 25,
        storeRenewDays: 30,
        storeDeleteGraceDays: 7
    };
}

function getPanelFeatureFlagsFromMap(settingsMap) {
    const source = settingsMap && typeof settingsMap === 'object' ? settingsMap : {};
    const base = defaultPanelFeatureFlags();

    const rawActivePeriod = String(source.afkRewardActivePeriod || base.afkRewardActivePeriod).trim().toLowerCase();
    const afkRewardActivePeriod = ['minute', 'hour', 'day', 'week', 'month', 'year'].includes(rawActivePeriod)
        ? rawActivePeriod
        : base.afkRewardActivePeriod;

    return {
        userCreateEnabled: parseBooleanInput(source.featureUserCreateEnabled, base.userCreateEnabled),
        costPerServerEnabled: parseBooleanInput(source.featureCostPerServerEnabled, base.costPerServerEnabled),
        inventoryEnabled: parseBooleanInput(source.featureInventoryEnabled, base.inventoryEnabled),
        storeDealsEnabled: parseBooleanInput(source.featureStoreDealsEnabled, base.storeDealsEnabled),
        storeRedeemCodesEnabled: parseBooleanInput(source.featureStoreRedeemCodesEnabled, base.storeRedeemCodesEnabled),
        billingInvoicesEnabled: parseBooleanInput(source.featureBillingInvoicesEnabled, base.billingInvoicesEnabled),
        billingStatementsEnabled: parseBooleanInput(
            source.featureBillingStatementsEnabled,
            parseBooleanInput(source.featureBillingInvoicesEnabled, base.billingStatementsEnabled)
        ),
        billingInvoiceWebhookEnabled: parseBooleanInput(source.featureBillingInvoiceWebhookEnabled, base.billingInvoiceWebhookEnabled),
        quotaForecastingEnabled: parseBooleanInput(source.featureQuotaForecastingEnabled, base.quotaForecastingEnabled),
        abuseScoreEnabled: parseBooleanInput(source.featureAbuseScoreEnabled, base.abuseScoreEnabled),
        abuseScoreWindowHours: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.abuseScoreWindowHours, base.abuseScoreWindowHours, 1, 24 * 30), 10) || base.abuseScoreWindowHours),
        abuseScoreAlertThreshold: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.abuseScoreAlertThreshold, base.abuseScoreAlertThreshold, 1, 1000), 10) || base.abuseScoreAlertThreshold),
        serviceHealthChecksEnabled: parseBooleanInput(source.featureServiceHealthChecksEnabled, base.serviceHealthChecksEnabled),
        serviceHealthCheckIntervalSeconds: Math.max(30, Number.parseInt(parseFiniteNumberInput(source.serviceHealthCheckIntervalSeconds, base.serviceHealthCheckIntervalSeconds, 30, 86400), 10) || base.serviceHealthCheckIntervalSeconds),
        scheduledScalingEnabled: parseBooleanInput(source.featureScheduledScalingEnabled, base.scheduledScalingEnabled),
        adminApiRatePlansEnabled: parseBooleanInput(source.featureAdminApiRatePlansEnabled, base.adminApiRatePlansEnabled),
        revenueModeEnabled: parseBooleanInput(source.featureRevenueModeEnabled, base.revenueModeEnabled),
        autoRemediationEnabled: parseBooleanInput(source.featureAutoRemediationEnabled, base.autoRemediationEnabled),
        antiMinerEnabled: parseBooleanInput(source.featureAntiMinerEnabled, base.antiMinerEnabled),
        policyEngineEnabled: parseBooleanInput(source.featurePolicyEngineEnabled, base.policyEngineEnabled),
        sftpEnabled: parseBooleanInput(source.featureSftpEnabled, base.sftpEnabled),
        webUploadEnabled: parseBooleanInput(source.featureWebUploadEnabled, base.webUploadEnabled),
        remoteDownloadEnabled: parseBooleanInput(source.featureRemoteDownloadEnabled, base.remoteDownloadEnabled),
        webUploadMaxMb: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.featureWebUploadMaxMb, base.webUploadMaxMb, 1, 2048), 10) || base.webUploadMaxMb),
        economyUnit: String(source.economyUnit || source.costCurrency || base.economyUnit).trim().slice(0, 16) || base.economyUnit,
        revenueDefaultTrialDays: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.revenueDefaultTrialDays, base.revenueDefaultTrialDays, 0, 365), 10) || base.revenueDefaultTrialDays),
        revenueGraceDays: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.revenueGraceDays, base.revenueGraceDays, 0, 365), 10) || base.revenueGraceDays),
        afkRewardsEnabled: parseBooleanInput(source.featureAfkRewardsEnabled, base.afkRewardsEnabled),
        claimRewardsEnabled: parseBooleanInput(source.featureClaimRewardsEnabled, base.claimRewardsEnabled),
        afkTimerCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkTimerCoins, base.afkTimerCoins, 0, 1000000), 10) || base.afkTimerCoins),
        afkTimerCooldownSeconds: Math.max(5, Number.parseInt(parseFiniteNumberInput(source.afkTimerCooldownSeconds, base.afkTimerCooldownSeconds, 5, 86400), 10) || base.afkTimerCooldownSeconds),
        afkRewardActivePeriod,
        afkRewardMinuteCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkRewardMinuteCoins, base.afkRewardMinuteCoins, 0, 1000000), 10) || base.afkRewardMinuteCoins),
        afkRewardHourCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkRewardHourCoins, base.afkRewardHourCoins, 0, 1000000), 10) || base.afkRewardHourCoins),
        afkRewardDayCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkRewardDayCoins, base.afkRewardDayCoins, 0, 1000000), 10) || base.afkRewardDayCoins),
        afkRewardWeekCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkRewardWeekCoins, base.afkRewardWeekCoins, 0, 1000000), 10) || base.afkRewardWeekCoins),
        afkRewardMonthCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkRewardMonthCoins, base.afkRewardMonthCoins, 0, 1000000), 10) || base.afkRewardMonthCoins),
        afkRewardYearCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.afkRewardYearCoins, base.afkRewardYearCoins, 0, 1000000), 10) || base.afkRewardYearCoins),
        claimDailyStreakBonusCoins: Math.max(0, Number.parseInt(parseFiniteNumberInput(source.claimDailyStreakBonusCoins, base.claimDailyStreakBonusCoins, 0, 1000000), 10) || base.claimDailyStreakBonusCoins),
        claimDailyStreakMax: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.claimDailyStreakMax, base.claimDailyStreakMax, 1, 365), 10) || base.claimDailyStreakMax),
        costBasePerServerMonthly: parseFiniteNumberInput(source.costBasePerServerMonthly, base.costBasePerServerMonthly, 0, 1_000_000),
        costPerGbRamMonthly: parseFiniteNumberInput(source.costPerGbRamMonthly, base.costPerGbRamMonthly, 0, 1_000_000),
        costPerCpuCoreMonthly: parseFiniteNumberInput(source.costPerCpuCoreMonthly, base.costPerCpuCoreMonthly, 0, 1_000_000),
        costPerGbDiskMonthly: parseFiniteNumberInput(source.costPerGbDiskMonthly, base.costPerGbDiskMonthly, 0, 1_000_000),
        autoRemediationCooldownSeconds: parseFiniteNumberInput(source.autoRemediationCooldownSeconds, base.autoRemediationCooldownSeconds, 10, 86400),
        antiMinerSuspendScore: Math.max(5, Number.parseInt(parseFiniteNumberInput(source.antiMinerSuspendScore, base.antiMinerSuspendScore, 5, 100), 10) || base.antiMinerSuspendScore),
        antiMinerHighCpuPercent: Math.max(70, Number.parseInt(parseFiniteNumberInput(source.antiMinerHighCpuPercent, base.antiMinerHighCpuPercent, 70, 100), 10) || base.antiMinerHighCpuPercent),
        antiMinerHighCpuSamples: Math.max(3, Number.parseInt(parseFiniteNumberInput(source.antiMinerHighCpuSamples, base.antiMinerHighCpuSamples, 3, 120), 10) || base.antiMinerHighCpuSamples),
        antiMinerDecayMinutes: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.antiMinerDecayMinutes, base.antiMinerDecayMinutes, 1, 720), 10) || base.antiMinerDecayMinutes),
        antiMinerCooldownSeconds: Math.max(30, Number.parseInt(parseFiniteNumberInput(source.antiMinerCooldownSeconds, base.antiMinerCooldownSeconds, 30, 86400), 10) || base.antiMinerCooldownSeconds),
        storeRamPerGbCoins: parseFiniteNumberInput(source.storeRamPerGbCoins, base.storeRamPerGbCoins, 0, 1_000_000),
        storeCpuPerCoreCoins: parseFiniteNumberInput(source.storeCpuPerCoreCoins, base.storeCpuPerCoreCoins, 0, 1_000_000),
        storeSwapPerGbCoins: parseFiniteNumberInput(source.storeSwapPerGbCoins, base.storeSwapPerGbCoins, 0, 1_000_000),
        storeDiskPerGbCoins: parseFiniteNumberInput(source.storeDiskPerGbCoins, base.storeDiskPerGbCoins, 0, 1_000_000),
        storeAllocationCoins: parseFiniteNumberInput(source.storeAllocationCoins, base.storeAllocationCoins, 0, 1_000_000),
        storeImageCoins: parseFiniteNumberInput(source.storeImageCoins, base.storeImageCoins, 0, 1_000_000),
        storeDatabaseCoins: parseFiniteNumberInput(source.storeDatabaseCoins, base.storeDatabaseCoins, 0, 1_000_000),
        storePackageCoins: parseFiniteNumberInput(source.storePackageCoins, base.storePackageCoins, 0, 1_000_000),
        storeRenewDays: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.storeRenewDays, base.storeRenewDays, 1, 3650), 10) || base.storeRenewDays),
        storeDeleteGraceDays: Math.max(1, Number.parseInt(parseFiniteNumberInput(source.storeDeleteGraceDays, base.storeDeleteGraceDays, 1, 3650), 10) || base.storeDeleteGraceDays)
    };
}

async function getPanelFeatureFlags(forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh && featureFlagsCache && now - featureFlagsCacheTs <= FEATURE_FLAGS_CACHE_TTL_MS) {
        return featureFlagsCache;
    }

    const rows = await Settings.findAll({
        where: { key: { [Op.in]: FEATURE_FLAG_SETTING_KEYS } },
        attributes: ['key', 'value']
    });
    const map = {};
    rows.forEach((row) => {
        map[row.key] = row.value;
    });

    featureFlagsCache = getPanelFeatureFlagsFromMap(map);
    featureFlagsCacheTs = now;
    return featureFlagsCache;
}

async function getServerMountsForInstall(serverId) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) return [];
    if (!ServerMount || !Mount) return [];

    const rows = await ServerMount.findAll({
        where: { serverId: parsedServerId },
        include: [{ model: Mount, as: 'mount' }]
    });

    const mounts = [];
    for (const row of rows) {
        if (!row || !row.mount) continue;
        const mount = row.mount;
        const source = String(mount.sourcePath || '').trim();
        const target = String(mount.targetPath || '').trim();
        if (!source || !target) continue;
        mounts.push({
            source,
            target,
            readOnly: row.readOnly === null || row.readOnly === undefined
                ? Boolean(mount.readOnly)
                : Boolean(row.readOnly)
        });
    }
    return mounts;
}

function calculateServerCostEstimate(server, settingsMap = {}) {
    const features = getPanelFeatureFlagsFromMap(settingsMap);
    if (!features.costPerServerEnabled) return null;
    if (!server) return null;

    const memoryMb = Math.max(0, Number.parseInt(server.memory, 10) || 0);
    const diskMb = Math.max(0, Number.parseInt(server.disk, 10) || 0);
    const cpuPercent = Math.max(0, Number.parseInt(server.cpu, 10) || 0);

    const memoryGb = memoryMb / 1024;
    const diskGb = diskMb / 1024;
    const cpuCores = cpuPercent / 100;

    const monthly = (
        features.costBasePerServerMonthly +
        (memoryGb * features.costPerGbRamMonthly) +
        (cpuCores * features.costPerCpuCoreMonthly) +
        (diskGb * features.costPerGbDiskMonthly)
    );
    const roundedMonthly = Math.round(monthly * 100) / 100;
    const roundedHourly = Math.round((roundedMonthly / (30 * 24)) * 10000) / 10000;

    return {
        currency: features.economyUnit,
        monthly: roundedMonthly,
        hourly: roundedHourly,
        breakdown: {
            baseMonthly: features.costBasePerServerMonthly,
            memoryGb,
            diskGb,
            cpuCores,
            rates: {
                perGbRamMonthly: features.costPerGbRamMonthly,
                perGbDiskMonthly: features.costPerGbDiskMonthly,
                perCpuCoreMonthly: features.costPerCpuCoreMonthly
            }
        }
    };
}

const SERVER_STORE_BILLING_KEY_PREFIX = 'server_store_billing_';
const STORE_BILLING_SUSPEND_REASON_PREFIX = '[STORE_BILLING]';
const STORE_BILLING_SUSPEND_REASON = `${STORE_BILLING_SUSPEND_REASON_PREFIX} Renewal overdue`;
const REVENUE_SUSPEND_REASON = `${REVENUE_SUSPEND_REASON_PREFIX} Subscription overdue`;
const USER_INVENTORY_KEY_PREFIX = 'user_store_inventory_';

function sanitizeBillingAuditMetadata(input) {
    if (!input || typeof input !== 'object') return {};
    try {
        return JSON.parse(JSON.stringify(input));
    } catch {
        return {};
    }
}

async function createSystemBillingAuditLog({
    action,
    targetServerId = null,
    ownerUserId = null,
    metadata = {}
} = {}) {
    try {
        if (!AuditLog) return;
        const cleanAction = String(action || '').trim().slice(0, 120);
        if (!cleanAction) return;
        await AuditLog.create({
            actorUserId: null,
            action: cleanAction,
            targetType: targetServerId ? 'server' : 'system',
            targetId: targetServerId ? String(targetServerId) : null,
            method: 'SYSTEM',
            path: null,
            ip: null,
            userAgent: 'system:billing-sweep',
            metadata: sanitizeBillingAuditMetadata({
                ownerUserId: Number.isInteger(Number(ownerUserId)) && Number(ownerUserId) > 0 ? Number(ownerUserId) : null,
                ...metadata
            })
        });
    } catch {
        // Ignore billing audit write errors in sweep.
    }
}

function getUserInventorySettingKey(userId) {
    return `${USER_INVENTORY_KEY_PREFIX}${Number.parseInt(userId, 10) || 0}`;
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
    const key = getUserInventorySettingKey(userId);
    const setting = await Settings.findByPk(key);
    if (!setting || !setting.value) return defaultUserInventoryState();
    return normalizeUserInventoryState(setting.value);
}

async function setUserInventoryState(userId, state) {
    const key = getUserInventorySettingKey(userId);
    const normalized = normalizeUserInventoryState(state);
    normalized.updatedAtMs = Date.now();
    await Settings.upsert({
        key,
        value: JSON.stringify(normalized)
    });
    return normalized;
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

function applyScalingInventoryDelta(inventoryState, delta) {
    const inventory = normalizeUserInventoryState(inventoryState);
    const deltaSafe = delta && typeof delta === 'object' ? delta : {};
    const int = (value) => Number.parseInt(value, 10) || 0;

    const spendRam = Math.max(0, int(deltaSafe.ramMb));
    const spendCpu = Math.max(0, int(deltaSafe.cpuPercent));
    const spendDisk = Math.max(0, int(deltaSafe.diskMb));
    const spendSwap = Math.max(0, int(deltaSafe.swapMb));

    const refundRam = Math.max(0, -int(deltaSafe.ramMb));
    const refundCpu = Math.max(0, -int(deltaSafe.cpuPercent));
    const refundDisk = Math.max(0, -int(deltaSafe.diskMb));
    const refundSwap = Math.max(0, -int(deltaSafe.swapMb));

    return normalizeUserInventoryState({
        ...inventory,
        ramMb: Math.max(0, inventory.ramMb - spendRam + refundRam),
        cpuPercent: Math.max(0, inventory.cpuPercent - spendCpu + refundCpu),
        diskMb: Math.max(0, inventory.diskMb - spendDisk + refundDisk),
        swapMb: Math.max(0, inventory.swapMb - spendSwap + refundSwap)
    });
}

function getServerStoreBillingSettingKey(serverId) {
    return `${SERVER_STORE_BILLING_KEY_PREFIX}${serverId}`;
}

function normalizeServerStoreBillingState(raw) {
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

    const recurringCoins = Math.max(0, Math.ceil(parseFiniteNumberInput(parsed.recurringCoins, 0, 0, 1_000_000_000)));
    const renewDays = Math.max(1, Number.parseInt(parseFiniteNumberInput(parsed.renewDays, 30, 1, 3650), 10) || 30);
    const createdAtMs = toTs(parsed.createdAtMs, Date.now());
    const nextRenewAtMs = toTs(parsed.nextRenewAtMs, createdAtMs + (renewDays * 24 * 60 * 60 * 1000));
    const suspendedAtMs = toTs(parsed.suspendedAtMs, 0);
    const deleteAfterMs = toTs(parsed.deleteAfterMs, 0);
    const status = String(parsed.status || '').trim().toLowerCase() === 'suspended_due' ? 'suspended_due' : 'active';

    return {
        status,
        recurringCoins,
        renewDays,
        createdAtMs,
        lastRenewAtMs: toTs(parsed.lastRenewAtMs, createdAtMs),
        nextRenewAtMs,
        suspendedAtMs,
        deleteAfterMs
    };
}

async function getServerStoreBillingState(serverId) {
    const setting = await Settings.findByPk(getServerStoreBillingSettingKey(serverId));
    if (!setting || !setting.value) return null;
    return normalizeServerStoreBillingState(setting.value);
}

async function setServerStoreBillingState(serverId, state) {
    const normalized = normalizeServerStoreBillingState(state);
    await Settings.upsert({
        key: getServerStoreBillingSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function removeServerStoreBillingState(serverId) {
    await Settings.destroy({ where: { key: getServerStoreBillingSettingKey(serverId) } });
}

async function getRevenuePlanCatalog() {
    const setting = await Settings.findByPk(REVENUE_PLAN_CATALOG_SETTING_KEY);
    if (!setting || !setting.value) return [];
    return normalizeRevenuePlanCatalog(setting.value);
}

async function setRevenuePlanCatalog(catalog) {
    const normalized = normalizeRevenuePlanCatalog(catalog);
    await Settings.upsert({
        key: REVENUE_PLAN_CATALOG_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function getUserRevenueProfile(userId) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return null;
    const key = getUserRevenueProfileSettingKey(parsedUserId);
    const setting = await Settings.findByPk(key);
    if (!setting || !setting.value) return null;
    return normalizeUserRevenueProfile(setting.value);
}

async function setUserRevenueProfile(userId, profilePatch = {}) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return null;

    const existing = await getUserRevenueProfile(parsedUserId);
    const nowMs = Date.now();
    const merged = normalizeUserRevenueProfile({
        ...(existing || {
            status: 'inactive',
            planId: '',
            planNameSnapshot: '',
            periodDays: 30,
            priceCoins: 0,
            trial: false,
            createdAtMs: nowMs,
            updatedAtMs: nowMs,
            lastRenewAtMs: 0,
            nextRenewAtMs: 0,
            graceEndsAtMs: 0
        }),
        ...(profilePatch && typeof profilePatch === 'object' ? profilePatch : {}),
        updatedAtMs: nowMs
    }, nowMs);

    await Settings.upsert({
        key: getUserRevenueProfileSettingKey(parsedUserId),
        value: JSON.stringify(merged)
    });
    return merged;
}

async function removeUserRevenueProfile(userId) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return;
    await Settings.destroy({ where: { key: getUserRevenueProfileSettingKey(parsedUserId) } });
}

async function listUserRevenueProfiles() {
    const rows = await Settings.findAll({
        where: {
            key: {
                [Op.like]: `${USER_REVENUE_PROFILE_KEY_PREFIX}%`
            }
        },
        attributes: ['key', 'value']
    });

    return rows.map((row) => {
        const key = String(row.key || '');
        const userId = Number.parseInt(key.slice(USER_REVENUE_PROFILE_KEY_PREFIX.length), 10) || 0;
        return {
            userId,
            key,
            profile: normalizeUserRevenueProfile(row.value)
        };
    }).filter((entry) => Number.isInteger(entry.userId) && entry.userId > 0);
}

async function setUserRevenueSuspendedState(userId, suspended, reason) {
    const parsedUserId = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return;

    const servers = await Server.findAll({
        where: { ownerId: parsedUserId },
        include: [{ model: Allocation, as: 'allocation' }]
    });

    for (const server of servers) {
        if (suspended) {
            if (server.isSuspended && String(server.suspendReason || '').startsWith(REVENUE_SUSPEND_REASON_PREFIX)) {
                continue;
            }

            if (server.allocation && server.allocation.connectorId) {
                const connectorWs = connectorConnections.get(server.allocation.connectorId);
                if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
                    try {
                        rememberServerPowerIntent(server.id, 'stop');
                        connectorWs.send(JSON.stringify({ type: 'server_power', serverId: server.id, action: 'stop' }));
                    } catch {
                        // Best effort.
                    }
                }
            }

            await server.update({
                isSuspended: true,
                status: 'suspended',
                suspendReason: reason || REVENUE_SUSPEND_REASON
            });
        } else if (server.isSuspended && String(server.suspendReason || '').startsWith(REVENUE_SUSPEND_REASON_PREFIX)) {
            await server.update({
                isSuspended: false,
                status: 'offline',
                suspendReason: null
            });
        }
    }
}

async function runRevenueModeSweep() {
    if (!User || typeof User.findByPk !== 'function') {
        console.warn('Revenue mode sweep skipped: User model is unavailable in legacy runtime helpers.');
        return;
    }
    if (!Server || typeof Server.findAll !== 'function') {
        console.warn('Revenue mode sweep skipped: Server model is unavailable in legacy runtime helpers.');
        return;
    }

    const features = await getPanelFeatureFlags();
    const nowMs = Date.now();
    const graceDays = Math.max(0, Number.parseInt(features.revenueGraceDays, 10) || 0);

    if (!features.userCreateEnabled || !features.revenueModeEnabled) {
        const suspendedServers = await Server.findAll({
            where: {
                isSuspended: true,
                suspendReason: { [Op.like]: `${REVENUE_SUSPEND_REASON_PREFIX}%` }
            }
        });
        for (const server of suspendedServers) {
            await server.update({
                isSuspended: false,
                status: 'offline',
                suspendReason: null
            }).catch(() => {});
        }
        return;
    }

    const plans = await getRevenuePlanCatalog();
    const planMap = new Map(plans.map((plan) => [String(plan.id), plan]));
    const profiles = await listUserRevenueProfiles();

    for (const entry of profiles) {
        const userId = entry.userId;
        const profile = normalizeUserRevenueProfile(entry.profile, nowMs);
        if (profile.status === 'inactive' || profile.status === 'expired') {
            continue;
        }

        const user = await User.findByPk(userId, { attributes: ['id', 'coins', 'isSuspended'] });
        if (!user) {
            await removeUserRevenueProfile(userId);
            continue;
        }

        const plan = planMap.get(String(profile.planId));
        const planPrice = plan ? Math.max(0, Number.parseInt(plan.priceCoins, 10) || 0) : Math.max(0, Number.parseInt(profile.priceCoins, 10) || 0);
        const planPeriodDays = plan ? Math.max(1, Number.parseInt(plan.periodDays, 10) || 30) : Math.max(1, Number.parseInt(profile.periodDays, 10) || 30);

        if (profile.status === 'past_due') {
            const graceEndsAtMs = Number.parseInt(profile.graceEndsAtMs, 10) || 0;
            if (graceEndsAtMs > 0 && nowMs >= graceEndsAtMs) {
                await setUserRevenueProfile(userId, {
                    ...profile,
                    status: 'expired'
                });
                continue;
            }
        }

        const nextRenewAtMs = Number.parseInt(profile.nextRenewAtMs, 10) || 0;
        if (nextRenewAtMs <= 0 || nowMs < nextRenewAtMs) {
            continue;
        }

        const walletCoins = Number.isFinite(Number(user.coins)) ? Number(user.coins) : 0;
        if (planPrice <= 0 || walletCoins >= planPrice) {
            const walletAfter = Math.max(0, walletCoins - planPrice);
            if (planPrice > 0) {
                await user.update({ coins: walletAfter });
            }
            await setUserRevenueProfile(userId, {
                ...profile,
                status: 'active',
                priceCoins: planPrice,
                periodDays: planPeriodDays,
                trial: false,
                lastRenewAtMs: nowMs,
                nextRenewAtMs: nowMs + (planPeriodDays * DAY_MS),
                graceEndsAtMs: 0,
                planNameSnapshot: plan ? String(plan.name || '').trim().slice(0, 120) : profile.planNameSnapshot
            });
            await setUserRevenueSuspendedState(userId, false, null);
            await createSystemBillingAuditLog({
                action: 'billing.revenue.renew_success',
                ownerUserId: userId,
                metadata: {
                    planId: profile.planId,
                    amount: planPrice,
                    walletBefore: walletCoins,
                    walletAfter,
                    nextRenewAtMs: nowMs + (planPeriodDays * DAY_MS)
                }
            });
            continue;
        }

        const graceEndsAtMs = graceDays > 0 ? nowMs + (graceDays * DAY_MS) : nowMs;
        await setUserRevenueProfile(userId, {
            ...profile,
            status: 'past_due',
            graceEndsAtMs
        });
        await setUserRevenueSuspendedState(userId, true, REVENUE_SUSPEND_REASON);
        await createSystemBillingAuditLog({
            action: 'billing.revenue.renew_failed',
            ownerUserId: userId,
            metadata: {
                planId: profile.planId,
                amount: planPrice,
                walletBefore: walletCoins,
                walletAfter: walletCoins,
                graceEndsAtMs
            }
        });
    }
}

async function getServerScheduledScalingConfig(serverId) {
    const setting = await Settings.findByPk(getServerScheduledScalingSettingKey(serverId));
    if (!setting || !setting.value) return normalizeServerScheduledScalingConfig({});
    return normalizeServerScheduledScalingConfig(setting.value);
}

async function setServerScheduledScalingConfig(serverId, config) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) {
        return normalizeServerScheduledScalingConfig({});
    }
    const normalized = normalizeServerScheduledScalingConfig(config);
    await Settings.upsert({
        key: getServerScheduledScalingSettingKey(parsedServerId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function removeServerScheduledScalingConfig(serverId) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) return;
    await Settings.destroy({ where: { key: getServerScheduledScalingSettingKey(parsedServerId) } });
}

async function runServerScheduledScalingSweep() {
    const features = await getPanelFeatureFlags();
    if (!features.scheduledScalingEnabled) return;
    const inventoryEnabled = Boolean(features.inventoryEnabled);

    const rows = await Settings.findAll({
        where: {
            key: {
                [Op.like]: `${SERVER_SCHEDULED_SCALING_KEY_PREFIX}%`
            }
        },
        attributes: ['key', 'value']
    });

    const nowMs = Date.now();
    for (const row of rows) {
        const key = String(row.key || '');
        const serverId = Number.parseInt(key.slice(SERVER_SCHEDULED_SCALING_KEY_PREFIX.length), 10);
        if (!Number.isInteger(serverId) || serverId <= 0) continue;

        const config = normalizeServerScheduledScalingConfig(row.value);
        if (!config.enabled || !Array.isArray(config.rules) || config.rules.length === 0) continue;

        const server = await Server.findByPk(serverId, {
            include: [
                { model: Allocation, as: 'allocation' },
                { model: Image, as: 'image' }
            ]
        });
        if (!server) {
            await removeServerScheduledScalingConfig(serverId);
            continue;
        }
        if (!server.image || !server.allocation) continue;

        let hasConfigChanges = false;
        const nextRules = [];
        for (const rawRule of config.rules) {
            const rule = { ...rawRule };
            const due = isRuleDueNow(rule, nowMs);
            if (!due.due) {
                nextRules.push(rule);
                continue;
            }

            const nextLimits = {
                memory: Number.parseInt(rule.memory, 10) > 0 ? Number.parseInt(rule.memory, 10) : server.memory,
                cpu: Number.parseInt(rule.cpu, 10) > 0 ? Number.parseInt(rule.cpu, 10) : server.cpu,
                disk: Number.parseInt(rule.disk, 10) > 0 ? Number.parseInt(rule.disk, 10) : server.disk,
                swapLimit: Number.parseInt(rule.swapLimit, 10) >= 0 ? Number.parseInt(rule.swapLimit, 10) : server.swapLimit,
                ioWeight: Number.parseInt(rule.ioWeight, 10) > 0 ? Number.parseInt(rule.ioWeight, 10) : server.ioWeight,
                pidsLimit: Number.parseInt(rule.pidsLimit, 10) >= 0 ? Number.parseInt(rule.pidsLimit, 10) : server.pidsLimit,
                oomKillDisable: rule.oomKillDisable === true,
                oomScoreAdj: Number.isInteger(Number.parseInt(rule.oomScoreAdj, 10)) ? Number.parseInt(rule.oomScoreAdj, 10) : server.oomScoreAdj
            };

            const changed = nextLimits.memory !== server.memory
                || nextLimits.cpu !== server.cpu
                || nextLimits.disk !== server.disk
                || nextLimits.swapLimit !== server.swapLimit
                || nextLimits.ioWeight !== server.ioWeight
                || nextLimits.pidsLimit !== server.pidsLimit
                || nextLimits.oomKillDisable !== Boolean(server.oomKillDisable)
                || nextLimits.oomScoreAdj !== server.oomScoreAdj;

            if (changed) {
                let ownerIdForInventory = 0;
                let inventoryDelta = null;
                let inventoryBefore = null;
                let inventoryAfter = null;
                if (inventoryEnabled) {
                    ownerIdForInventory = Number.parseInt(server.ownerId, 10) || 0;
                    if (ownerIdForInventory <= 0) {
                        await createSystemBillingAuditLog({
                            action: 'billing.server.scheduled_scale_skipped_inventory',
                            targetServerId: server.id,
                            ownerUserId: server.ownerId,
                            metadata: {
                                ruleId: rule.id,
                                ruleName: rule.name,
                                slot: due.slot,
                                reason: 'missing_owner'
                            }
                        });
                        rule.lastAppliedSlot = due.slot;
                        nextRules.push(rule);
                        continue;
                    }

                    inventoryBefore = await getUserInventoryState(ownerIdForInventory);
                    inventoryDelta = buildScalingInventoryDelta(server, nextLimits);
                    const missingInventory = getScalingInventoryMissingList(inventoryDelta, inventoryBefore);
                    if (missingInventory.length > 0) {
                        await createSystemBillingAuditLog({
                            action: 'billing.server.scheduled_scale_skipped_inventory',
                            targetServerId: server.id,
                            ownerUserId: ownerIdForInventory,
                            metadata: {
                                ruleId: rule.id,
                                ruleName: rule.name,
                                slot: due.slot,
                                missingInventory,
                                inventoryDelta
                            }
                        });
                        rule.lastAppliedSlot = due.slot;
                        nextRules.push(rule);
                        continue;
                    }

                    if (inventoryDelta.ramMb !== 0 || inventoryDelta.cpuPercent !== 0 || inventoryDelta.diskMb !== 0 || inventoryDelta.swapMb !== 0) {
                        inventoryAfter = applyScalingInventoryDelta(inventoryBefore, inventoryDelta);
                    }
                }

                await server.update(nextLimits);
                hasConfigChanges = true;

                if (inventoryEnabled && ownerIdForInventory > 0 && inventoryAfter && inventoryDelta) {
                    try {
                        await setUserInventoryState(ownerIdForInventory, inventoryAfter);
                        await createSystemBillingAuditLog({
                            action: 'billing.server.scheduled_scale_inventory',
                            targetServerId: server.id,
                            ownerUserId: ownerIdForInventory,
                            metadata: {
                                ruleId: rule.id,
                                ruleName: rule.name,
                                slot: due.slot,
                                inventoryDelta,
                                inventoryBefore: {
                                    ramMb: inventoryBefore.ramMb,
                                    cpuPercent: inventoryBefore.cpuPercent,
                                    diskMb: inventoryBefore.diskMb,
                                    swapMb: inventoryBefore.swapMb
                                },
                                inventoryAfter: {
                                    ramMb: inventoryAfter.ramMb,
                                    cpuPercent: inventoryAfter.cpuPercent,
                                    diskMb: inventoryAfter.diskMb,
                                    swapMb: inventoryAfter.swapMb
                                }
                            }
                        });
                    } catch {
                        await createSystemBillingAuditLog({
                            action: 'billing.server.scheduled_scale_inventory_failed',
                            targetServerId: server.id,
                            ownerUserId: ownerIdForInventory,
                            metadata: {
                                ruleId: rule.id,
                                ruleName: rule.name,
                                slot: due.slot,
                                inventoryDelta
                            }
                        });
                    }
                }

                const primaryAllocationId = Number.parseInt(server.allocationId, 10);
                const primaryAllocation = Number.isInteger(primaryAllocationId) && primaryAllocationId > 0
                    ? await Allocation.findOne({
                        where: {
                            id: primaryAllocationId,
                            serverId: server.id
                        },
                        attributes: ['id', 'ip', 'port', 'connectorId']
                    })
                    : null;

                if (!primaryAllocation || !primaryAllocation.connectorId) {
                    continue;
                }

                const connectorWs = connectorConnections.get(primaryAllocation.connectorId);
                if (connectorWs && connectorWs.readyState === WebSocket.OPEN && typeof buildServerEnvironment === 'function' && typeof buildStartupCommand === 'function' && typeof resolveImagePorts === 'function') {
                    try {
                        const runtimeValues = {
                            SERVER_MEMORY: String(nextLimits.memory),
                            SERVER_IP: '0.0.0.0',
                            SERVER_PORT: String(primaryAllocation.port || '')
                        };
                        const built = buildServerEnvironment(server.image, server.variables || {}, runtimeValues);
                        const startup = buildStartupCommand(server.startup || server.image.startup, built.env);
                        const imagePorts = resolveImagePorts(server.image.ports);
                        const startupMode = typeof shouldUseCommandStartup === 'function' && shouldUseCommandStartup(server.image) ? 'command' : 'environment';
                        const assignedAllocations = await Allocation.findAll({
                            where: { serverId: server.id },
                            attributes: ['id', 'ip', 'port'],
                            order: [['port', 'ASC']]
                        });
                        const deploymentPorts = buildDeploymentPorts({
                            imagePorts,
                            env: built.env,
                            primaryAllocation,
                            allocations: assignedAllocations
                        });
                        const mountConfig = typeof getServerMountsForInstall === 'function'
                            ? await getServerMountsForInstall(server.id)
                            : [];

                        connectorWs.send(JSON.stringify({
                            type: 'install_server',
                            serverId: server.id,
                            reinstall: false,
                            config: {
                                image: server.dockerImage || server.image.dockerImage,
                                memory: nextLimits.memory,
                                cpu: nextLimits.cpu,
                                disk: nextLimits.disk,
                                swapLimit: nextLimits.swapLimit,
                                ioWeight: nextLimits.ioWeight,
                                pidsLimit: nextLimits.pidsLimit,
                                oomKillDisable: nextLimits.oomKillDisable,
                                oomScoreAdj: nextLimits.oomScoreAdj,
                                env: built.env,
                                startup,
                                startupMode,
                                eggConfig: server.image.eggConfig,
                                eggScripts: server.image.eggScripts,
                                installation: server.image.installation || null,
                                configFiles: server.image.configFiles || null,
                                brandName: 'cpanel',
                                ports: deploymentPorts,
                                mounts: mountConfig
                            }
                        }));
                        await server.update({ status: 'installing' });
                    } catch {
                        // Keep DB changes even if live apply fails.
                    }
                }

                await createSystemBillingAuditLog({
                    action: 'billing.server.scheduled_scale',
                    targetServerId: server.id,
                    ownerUserId: server.ownerId,
                    metadata: {
                        ruleId: rule.id,
                        ruleName: rule.name,
                        slot: due.slot,
                        limits: nextLimits
                    }
                });
            }

            rule.lastAppliedSlot = due.slot;
            nextRules.push(rule);
        }

        if (hasConfigChanges || JSON.stringify(nextRules) !== JSON.stringify(config.rules)) {
            await setServerScheduledScalingConfig(server.id, {
                ...config,
                rules: nextRules,
                updatedAtMs: nowMs
            });
        }
    }
}

function calculateStoreCreateCoins(input, settingsMap = {}) {
    const source = input && typeof input === 'object' ? input : {};
    const features = getPanelFeatureFlagsFromMap(settingsMap);

    const memoryMb = Math.max(0, Number.parseInt(source.memory, 10) || 0);
    const cpuPercent = Math.max(0, Number.parseInt(source.cpu, 10) || 0);
    const diskMb = Math.max(0, Number.parseInt(source.disk, 10) || 0);
    const swapMb = Math.max(0, Number.parseInt(source.swapLimit, 10) || 0);

    const memoryGb = memoryMb / 1024;
    const diskGb = diskMb / 1024;
    const swapGb = swapMb / 1024;
    const cpuCores = cpuPercent / 100;

    const resourcesCost = (
        (memoryGb * features.storeRamPerGbCoins) +
        (cpuCores * features.storeCpuPerCoreCoins) +
        (swapGb * features.storeSwapPerGbCoins) +
        (diskGb * features.storeDiskPerGbCoins)
    );
    const allocationCost = source.hasAllocation ? features.storeAllocationCoins : 0;
    const imageCost = source.hasImage ? features.storeImageCoins : 0;
    const databaseSlots = Math.max(0, Number.parseInt(source.databaseLimit, 10) || 0);
    const databaseCost = databaseSlots * Number(features.storeDatabaseCoins || 0);
    const packageCost = source.hasPackage ? features.storePackageCoins : 0;
    const total = Math.max(0, Math.ceil(resourcesCost + allocationCost + imageCost + databaseCost + packageCost));

    return {
        total,
        breakdown: {
            resourcesCost: Math.max(0, Math.ceil(resourcesCost)),
            allocationCost: Math.max(0, Math.ceil(allocationCost)),
            imageCost: Math.max(0, Math.ceil(imageCost)),
            databaseCost: Math.max(0, Math.ceil(databaseCost)),
            packageCost: Math.max(0, Math.ceil(packageCost))
        }
    };
}

function calculateStoreRenewCoins(server, settingsMap = {}) {
    const estimate = calculateServerCostEstimate(server, settingsMap);
    if (!estimate) return 0;
    const base = Number.isFinite(Number(estimate.monthly)) ? Number(estimate.monthly) : 0;
    return Math.max(0, Math.ceil(base));
}

async function runServerStoreBillingSweep() {
    const features = await getPanelFeatureFlags();
    const now = Date.now();
    const billingRows = await Settings.findAll({
        where: {
            key: {
                [Op.like]: `${SERVER_STORE_BILLING_KEY_PREFIX}%`
            }
        },
        attributes: ['key', 'value']
    });
    const billingEnabled = features.userCreateEnabled && features.costPerServerEnabled;

    // If billing is disabled in admin, restore any server suspended by store billing and keep state active.
    if (!billingEnabled) {
        for (const row of billingRows) {
            const key = String(row.key || '');
            const idRaw = key.slice(SERVER_STORE_BILLING_KEY_PREFIX.length);
            const serverId = Number.parseInt(idRaw, 10);
            if (!Number.isInteger(serverId) || serverId <= 0) {
                continue;
            }

            const state = normalizeServerStoreBillingState(row.value);
            const server = await Server.findByPk(serverId);
            if (!server) {
                await Settings.destroy({ where: { key } });
                continue;
            }

            const renewDays = Math.max(1, Number.parseInt(state.renewDays, 10) || 30);
            await Settings.upsert({
                key,
                value: JSON.stringify({
                    ...state,
                    status: 'active',
                    lastRenewAtMs: now,
                    nextRenewAtMs: now + (renewDays * 24 * 60 * 60 * 1000),
                    suspendedAtMs: 0,
                    deleteAfterMs: 0
                })
            });

            if (server.isSuspended && String(server.suspendReason || '').startsWith(STORE_BILLING_SUSPEND_REASON_PREFIX)) {
                await server.update({
                    isSuspended: false,
                    status: 'offline',
                    suspendReason: null
                });
                await createSystemBillingAuditLog({
                    action: 'billing.server.auto_unsuspend',
                    targetServerId: server.id,
                    ownerUserId: server.ownerId,
                    metadata: {
                        reason: 'billing_disabled',
                        nextRenewAtMs: now + (renewDays * 24 * 60 * 60 * 1000)
                    }
                });
            }
        }
        return;
    }

    const deleteGraceDays = Math.max(1, Number.parseInt(features.storeDeleteGraceDays, 10) || 7);

    for (const row of billingRows) {
        const key = String(row.key || '');
        const idRaw = key.slice(SERVER_STORE_BILLING_KEY_PREFIX.length);
        const serverId = Number.parseInt(idRaw, 10);
        if (!Number.isInteger(serverId) || serverId <= 0) {
            continue;
        }

        const state = normalizeServerStoreBillingState(row.value);
        const server = await Server.findByPk(serverId, {
            include: [{ model: Allocation, as: 'allocation' }]
        });

        if (!server) {
            await Settings.destroy({ where: { key } });
            continue;
        }

        if (state.status !== 'suspended_due' && now >= state.nextRenewAtMs) {
            if (server.allocation && server.allocation.connectorId) {
                const connectorWs = connectorConnections.get(server.allocation.connectorId);
                if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
                    try {
                        rememberServerPowerIntent(server.id, 'stop');
                        connectorWs.send(JSON.stringify({ type: 'server_power', serverId: server.id, action: 'stop' }));
                    } catch {
                        // Best effort stop.
                    }
                }
            }

            await server.update({
                isSuspended: true,
                status: 'suspended',
                suspendReason: STORE_BILLING_SUSPEND_REASON
            });

            state.status = 'suspended_due';
            state.suspendedAtMs = now;
            state.deleteAfterMs = now + (deleteGraceDays * 24 * 60 * 60 * 1000);
            await Settings.upsert({ key, value: JSON.stringify(state) });
            await createSystemBillingAuditLog({
                action: 'billing.server.auto_suspend',
                targetServerId: server.id,
                ownerUserId: server.ownerId,
                metadata: {
                    reason: 'renew_overdue',
                    recurringCoins: state.recurringCoins,
                    nextRenewAtMs: state.nextRenewAtMs,
                    deleteAfterMs: state.deleteAfterMs
                }
            });
            continue;
        }

        if (state.status === 'suspended_due' && state.deleteAfterMs > 0 && now >= state.deleteAfterMs) {
            const deletionMetadata = {
                reason: 'delete_grace_expired',
                recurringCoins: state.recurringCoins,
                suspendedAtMs: state.suspendedAtMs,
                deleteAfterMs: state.deleteAfterMs,
                allocationId: server.allocationId || null,
                containerId: server.containerId || null
            };
            if (server.allocationId) {
                await Allocation.update({ serverId: null }, { where: { id: server.allocationId } });
            }

            await Settings.destroy({ where: { key: getServerSmartAlertsSettingKey(server.id) } });
            await Settings.destroy({ where: { key: `${SERVER_STARTUP_PRESET_KEY_PREFIX}${server.id}` } });
            await Settings.destroy({ where: { key: getServerPolicyEngineSettingKey(server.id) } });
            await Settings.destroy({ where: { key: getServerStoreBillingSettingKey(server.id) } });

            consumeServerPowerIntent(server.id);
            RESOURCE_ANOMALY_STATE.delete(server.id);
            RESOURCE_ANOMALY_SAMPLE_TS.delete(server.id);
            PLUGIN_CONFLICT_STATE.delete(server.id);
            serverLogCleanupScheduleState.delete(server.id);
            pendingMigrationFileImports.delete(server.id);

            await createSystemBillingAuditLog({
                action: 'billing.server.auto_delete',
                targetServerId: server.id,
                ownerUserId: server.ownerId,
                metadata: deletionMetadata
            });
            await server.destroy();
        }
    }
}

function normalizeMinecraftProjectKind(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'plugins' || normalized === 'plugin') return 'plugin';
    if (normalized === 'mods' || normalized === 'mod') return 'mod';
    if (normalized === 'datapacks' || normalized === 'datapack') return 'datapack';
    if (normalized === 'worlds' || normalized === 'world') return 'world';
    return 'plugin';
}

function getMinecraftLoaderCatalog(kind) {
    if (kind === 'mod') return MODRINTH_MOD_LOADERS;
    if (kind === 'plugin') return MODRINTH_PLUGIN_LOADERS;
    return [];
}

function normalizeMinecraftLoader(value, kind) {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized) return '';
    const catalog = getMinecraftLoaderCatalog(kind);
    return catalog.includes(normalized) ? normalized : '';
}

function normalizeMinecraftVersion(value) {
    const normalized = String(value || '').trim();
    if (!normalized) return '';
    if (!/^[A-Za-z0-9._+\-]{1,40}$/.test(normalized)) return '';

    const lower = normalized.toLowerCase();
    const placeholders = new Set(['latest', 'release', 'stable', 'recommended', 'auto', 'default', 'current']);
    if (placeholders.has(lower)) return '';

    // Prefer explicit Minecraft versions if present inside mixed strings (e.g. "paper-1.20.4").
    const explicitVersionMatch = lower.match(/\b\d+\.\d+(?:\.\d+)?\b/);
    if (explicitVersionMatch) return explicitVersionMatch[0];

    // Keep common snapshot/pre-release formats.
    if (/^\d{2}w\d{2}[a-z]$/i.test(lower)) return lower;
    if (/^\d+\.\d+(?:\.\d+)?-(?:pre|rc)\d+$/i.test(lower)) return lower;

    // Unknown token: skip version facet instead of forcing zero-result searches.
    return '';
}

function sanitizeServerDirectoryPath(value, fallback = '/') {
    const initial = String(value || fallback).trim() || fallback;
    let normalized = initial.replace(/\\/g, '/');
    if (!normalized.startsWith('/')) normalized = `/${normalized}`;
    normalized = path.posix.normalize(normalized);
    if (!normalized.startsWith('/')) normalized = `/${normalized}`;
    if (normalized === '/.') normalized = '/';
    if (normalized.includes('..')) return fallback;
    return normalized;
}

function sanitizeDownloadFileName(value, fallback = 'download.jar') {
    const raw = String(value || '').trim();
    const base = path.basename(raw).replace(/[^A-Za-z0-9._\-+]/g, '_');
    const clean = base.replace(/^_+/, '').slice(0, 128);
    if (!clean || clean === '.' || clean === '..') return fallback;
    return clean;
}

function inferMinecraftDefaults(server) {
    const variables = normalizeClientVariables(server && server.variables ? server.variables : {});
    const imageContext = String([
        server && server.image ? server.image.name : '',
        server && server.image ? server.image.description : '',
        server && server.image ? server.image.startup : '',
        server && server.image ? server.image.dockerImage : ''
    ].join(' ')).toLowerCase();

    const knownVersionKeys = ['MINECRAFT_VERSION', 'MC_VERSION', 'SERVER_VERSION', 'VERSION'];
    let version = '';
    for (const key of knownVersionKeys) {
        const candidate = normalizeMinecraftVersion(variables[key]);
        if (candidate) {
            version = candidate;
            break;
        }
    }

    let kind = 'plugin';
    let loader = 'paper';
    if (imageContext.includes('neoforge')) {
        kind = 'mod';
        loader = 'neoforge';
    } else if (imageContext.includes('forge')) {
        kind = 'mod';
        loader = 'forge';
    } else if (imageContext.includes('fabric')) {
        kind = 'mod';
        loader = 'fabric';
    } else if (imageContext.includes('quilt')) {
        kind = 'mod';
        loader = 'quilt';
    } else if (imageContext.includes('velocity')) {
        loader = 'velocity';
    } else if (imageContext.includes('spigot')) {
        loader = 'spigot';
    } else if (imageContext.includes('bukkit')) {
        loader = 'bukkit';
    } else if (imageContext.includes('purpur')) {
        loader = 'purpur';
    } else if (imageContext.includes('folia')) {
        loader = 'folia';
    }

    return { kind, loader, version };
}

function buildModrinthUserAgent(settings) {
    const brand = String((settings && settings.brandName) || 'CPanel').trim() || 'CPanel';
    return `${brand.replace(/\s+/g, '-')}/1.0 (+https://cpanel-rocky.netlify.app)`;
}

function createWsRequestId() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    return crypto.randomBytes(16).toString('hex');
}

function resolveMinecraftTargetDirectory(kind, requestedDirectory) {
    let fallback = '/plugins';
    if (kind === 'mod') fallback = '/mods';
    if (kind === 'datapack') fallback = '/world/datapacks';
    if (kind === 'world') fallback = '/';
    return sanitizeServerDirectoryPath(requestedDirectory, fallback);
}

function getMinecraftInstallTrackerSettingKey(serverId) {
    return `${MINECRAFT_INSTALL_TRACKER_PREFIX}${serverId}`;
}

function parseServerAddonPath(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;

    let normalized = raw.replace(/\\/g, '/');
    if (!normalized.startsWith('/')) normalized = `/${normalized}`;
    normalized = path.posix.normalize(normalized);

    if (!normalized.startsWith('/') || normalized.includes('..') || normalized.endsWith('/') || normalized === '/') {
        return null;
    }

    const directory = sanitizeServerDirectoryPath(path.posix.dirname(normalized), '/');
    const fileName = sanitizeDownloadFileName(path.posix.basename(normalized), '');
    if (!fileName) return null;

    const filePath = directory === '/' ? `/${fileName}` : `${directory}/${fileName}`;
    return { directory, fileName, path: filePath };
}

function normalizeMinecraftInstallRecord(rawRecord) {
    if (!rawRecord || typeof rawRecord !== 'object') return null;

    const pathParts = parseServerAddonPath(rawRecord.path || rawRecord.filePath || '');
    if (!pathParts) return null;

    const kind = normalizeMinecraftProjectKind(rawRecord.kind);
    const loader = normalizeMinecraftLoader(rawRecord.loader, kind);
    const gameVersion = normalizeMinecraftVersion(rawRecord.gameVersion || rawRecord.version || '');

    const projectIdRaw = String(rawRecord.projectId || '').trim();
    const projectId = /^[A-Za-z0-9_-]{2,64}$/.test(projectIdRaw) ? projectIdRaw : '';

    return {
        path: pathParts.path,
        directory: pathParts.directory,
        fileName: pathParts.fileName,
        kind,
        loader,
        gameVersion,
        projectId,
        projectTitle: String(rawRecord.projectTitle || '').trim().slice(0, 120),
        versionId: String(rawRecord.versionId || '').trim().slice(0, 64),
        versionNumber: String(rawRecord.versionNumber || '').trim().slice(0, 64),
        installedAt: rawRecord.installedAt ? new Date(rawRecord.installedAt).toISOString() : new Date().toISOString()
    };
}

function normalizeMinecraftInstallRecords(rawValue) {
    let parsed = rawValue;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = [];
        }
    }
    if (!Array.isArray(parsed)) return [];

    const byPath = new Map();
    for (const record of parsed) {
        const normalized = normalizeMinecraftInstallRecord(record);
        if (!normalized) continue;
        byPath.set(normalized.path, normalized);
    }
    return Array.from(byPath.values());
}

async function getServerMinecraftInstallRecords(serverId) {
    const setting = await Settings.findByPk(getMinecraftInstallTrackerSettingKey(serverId));
    if (!setting || !setting.value) return [];
    return normalizeMinecraftInstallRecords(setting.value);
}

async function setServerMinecraftInstallRecords(serverId, records) {
    const normalized = normalizeMinecraftInstallRecords(records);
    await Settings.upsert({
        key: getMinecraftInstallTrackerSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function upsertServerMinecraftInstallRecord(serverId, record) {
    const normalized = normalizeMinecraftInstallRecord(record);
    if (!normalized) return null;

    const records = await getServerMinecraftInstallRecords(serverId);
    const filtered = records.filter((entry) => entry.path !== normalized.path);
    filtered.push(normalized);
    await setServerMinecraftInstallRecords(serverId, filtered);
    return normalized;
}

async function removeServerMinecraftInstallRecord(serverId, targetPath) {
    const pathParts = parseServerAddonPath(targetPath);
    if (!pathParts) return false;

    const records = await getServerMinecraftInstallRecords(serverId);
    const filtered = records.filter((entry) => entry.path !== pathParts.path);
    if (filtered.length === records.length) return false;
    await setServerMinecraftInstallRecords(serverId, filtered);
    return true;
}

async function resolveModrinthVersionForInstall({
    projectId,
    versionId,
    loader,
    gameVersion,
    userAgent
}) {
    let selectedVersion = null;

    if (versionId) {
        const versionResponse = await axios.get(`${MODRINTH_API_BASE_URL}/version/${encodeURIComponent(versionId)}`, {
            timeout: MODRINTH_REQUEST_TIMEOUT_MS,
            headers: {
                'User-Agent': userAgent
            }
        });
        const resolved = versionResponse.data || {};
        if (resolved.project_id !== projectId) {
            throw new Error('Selected version does not belong to requested project.');
        }
        selectedVersion = resolved;
    } else {
        const params = {};
        if (loader) params.loaders = JSON.stringify([loader]);
        if (gameVersion) params.game_versions = JSON.stringify([gameVersion]);

        const versionsResponse = await axios.get(`${MODRINTH_API_BASE_URL}/project/${encodeURIComponent(projectId)}/version`, {
            params,
            timeout: MODRINTH_REQUEST_TIMEOUT_MS,
            headers: {
                'User-Agent': userAgent
            }
        });

        const versions = Array.isArray(versionsResponse.data) ? versionsResponse.data : [];
        if (!versions.length) {
            throw new Error('No compatible versions found for selected filters.');
        }
        selectedVersion = versions[0];
    }

    const files = Array.isArray(selectedVersion.files) ? selectedVersion.files : [];
    const selectedFile = files.find((file) => file && file.primary) || files[0];
    if (!selectedFile || !selectedFile.url) {
        throw new Error('Selected Modrinth version has no downloadable file.');
    }

    return {
        versionId: String(selectedVersion.id || ''),
        versionNumber: String(selectedVersion.version_number || ''),
        fileName: sanitizeDownloadFileName(selectedFile.filename || '', 'download.jar'),
        fileUrl: String(selectedFile.url || ''),
        projectId: String(selectedVersion.project_id || projectId)
    };
}

function waitForConnectorDownloadResult(connectorWs, serverId, requestId, timeoutMs = 45000) {
    return new Promise((resolve) => {
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            connectorWs.removeListener('message', onMessage);
            resolve({ success: false, error: 'Timed out waiting for connector download result.' });
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
                if (message.type !== 'download_file_result') return;
                if (Number.parseInt(message.serverId, 10) !== serverId) return;
                if (String(message.requestId || '') !== requestId) return;
                finish({
                    success: Boolean(message.success),
                    error: String(message.error || ''),
                    path: String(message.path || ''),
                    fileName: String(message.fileName || ''),
                    size: Number.parseInt(message.size, 10) || 0
                });
            } catch (error) {
                // Ignore unrelated/non-JSON messages.
            }
        }

        connectorWs.on('message', onMessage);
    });
}

function runConnectorFileAction(connectorWs, payload, expectedDirectory, expectedServerId, timeoutMs = 12000) {
    return new Promise((resolve) => {
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            connectorWs.removeListener('message', onMessage);
            resolve({ success: false, error: 'Timed out waiting for connector file action result.' });
        }, timeoutMs);

        function finish(response) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            connectorWs.removeListener('message', onMessage);
            resolve(response);
        }

        function onMessage(rawMessage) {
            try {
                const message = JSON.parse(rawMessage);
                if (Number.parseInt(message.serverId, 10) !== expectedServerId) return;

                if (message.type === 'file_list' && String(message.directory || '') === expectedDirectory) {
                    finish({
                        success: true,
                        files: Array.isArray(message.files) ? message.files : [],
                        directory: String(message.directory || expectedDirectory)
                    });
                    return;
                }

                if (message.type === 'error') {
                    finish({
                        success: false,
                        error: String(message.message || 'Connector returned an error.')
                    });
                }
            } catch (error) {
                // Ignore unrelated/non-JSON payloads.
            }
        }

        connectorWs.on('message', onMessage);
        try {
            connectorWs.send(JSON.stringify(payload));
        } catch (error) {
            finish({
                success: false,
                error: error && error.message ? error.message : 'Failed to send file action to connector.'
            });
        }
    });
}

function normalizeServerAdvancedLimits(input, fallback = {}) {
    const defaults = {
        swapLimit: Number.isInteger(fallback.swapLimit) ? fallback.swapLimit : 0,
        ioWeight: Number.isInteger(fallback.ioWeight) ? fallback.ioWeight : 500,
        pidsLimit: Number.isInteger(fallback.pidsLimit) ? fallback.pidsLimit : 512,
        oomKillDisable: typeof fallback.oomKillDisable === 'boolean' ? fallback.oomKillDisable : false,
        oomScoreAdj: Number.isInteger(fallback.oomScoreAdj) ? fallback.oomScoreAdj : 0
    };

    const parsedSwap = parseIntegerInput(input.swapLimit, defaults.swapLimit);
    if (!parsedSwap.valid || parsedSwap.value < -1) {
        return { valid: false, error: 'Swap limit must be -1 (unlimited) or a positive value.' };
    }

    const parsedIoWeight = parseIntegerInput(input.ioWeight, defaults.ioWeight);
    if (!parsedIoWeight.valid || parsedIoWeight.value < 10 || parsedIoWeight.value > 1000) {
        return { valid: false, error: 'I/O weight must be between 10 and 1000.' };
    }

    const parsedPids = parseIntegerInput(input.pidsLimit, defaults.pidsLimit);
    if (!parsedPids.valid || parsedPids.value < 0 || parsedPids.value > 4194304) {
        return { valid: false, error: 'PIDs limit must be between 0 and 4194304.' };
    }

    const parsedOomScoreAdj = parseIntegerInput(input.oomScoreAdj, defaults.oomScoreAdj);
    if (!parsedOomScoreAdj.valid || parsedOomScoreAdj.value < -1000 || parsedOomScoreAdj.value > 1000) {
        return { valid: false, error: 'OOM score adjustment must be between -1000 and 1000.' };
    }

    return {
        valid: true,
        values: {
            swapLimit: parsedSwap.value,
            ioWeight: parsedIoWeight.value,
            pidsLimit: parsedPids.value,
            oomKillDisable: parseBooleanInput(input.oomKillDisable, defaults.oomKillDisable),
            oomScoreAdj: parsedOomScoreAdj.value
        }
    };
}

function getServerSmartAlertsSettingKey(serverId) {
    return `${SERVER_SMART_ALERTS_KEY_PREFIX}${serverId}`;
}

function defaultServerSmartAlerts() {
    return {
        enabled: false,
        discordWebhook: '',
        telegramBotToken: '',
        telegramChatId: '',
        events: {
            started: true,
            stopped: true,
            crashed: true,
            reinstallSuccess: true,
            reinstallFailed: true,
            suspended: true,
            unsuspended: true,
            resourceAnomaly: true,
            pluginConflict: true
        },
        anomaly: {
            enabled: false,
            cpuThreshold: 95,
            memoryThreshold: 90,
            durationSamples: 3,
            cooldownSeconds: 300
        },
        logCleanup: {
            enabled: false,
            directory: '/logs',
            maxFileSizeMB: 25,
            keepFiles: 20,
            maxAgeDays: 14,
            compressOld: false
        }
    };
}

function sanitizeHttpUrl(value) {
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
}

function normalizeServerSmartAlertsConfig(raw) {
    const base = defaultServerSmartAlerts();
    let parsed = raw;

    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const events = parsed.events && typeof parsed.events === 'object' ? parsed.events : {};
    const anomalyRaw = parsed.anomaly && typeof parsed.anomaly === 'object' ? parsed.anomaly : {};
    const logCleanupRaw = parsed.logCleanup && typeof parsed.logCleanup === 'object' ? parsed.logCleanup : {};

    const cpuThreshold = parseIntegerInput(anomalyRaw.cpuThreshold, base.anomaly.cpuThreshold);
    const memoryThreshold = parseIntegerInput(anomalyRaw.memoryThreshold, base.anomaly.memoryThreshold);
    const durationSamples = parseIntegerInput(anomalyRaw.durationSamples, base.anomaly.durationSamples);
    const cooldownSeconds = parseIntegerInput(anomalyRaw.cooldownSeconds, base.anomaly.cooldownSeconds);

    const maxFileSizeMB = parseIntegerInput(logCleanupRaw.maxFileSizeMB, base.logCleanup.maxFileSizeMB);
    const keepFiles = parseIntegerInput(logCleanupRaw.keepFiles, base.logCleanup.keepFiles);
    const maxAgeDays = parseIntegerInput(logCleanupRaw.maxAgeDays, base.logCleanup.maxAgeDays);

    return {
        enabled: parseBooleanInput(parsed.enabled, base.enabled),
        discordWebhook: sanitizeHttpUrl(parsed.discordWebhook),
        telegramBotToken: String(parsed.telegramBotToken || '').trim(),
        telegramChatId: String(parsed.telegramChatId || '').trim(),
        events: {
            started: parseBooleanInput(events.started, base.events.started),
            stopped: parseBooleanInput(events.stopped, base.events.stopped),
            crashed: parseBooleanInput(events.crashed, base.events.crashed),
            reinstallSuccess: parseBooleanInput(events.reinstallSuccess, base.events.reinstallSuccess),
            reinstallFailed: parseBooleanInput(events.reinstallFailed, base.events.reinstallFailed),
            suspended: parseBooleanInput(events.suspended, base.events.suspended),
            unsuspended: parseBooleanInput(events.unsuspended, base.events.unsuspended),
            resourceAnomaly: parseBooleanInput(events.resourceAnomaly, base.events.resourceAnomaly),
            pluginConflict: parseBooleanInput(events.pluginConflict, base.events.pluginConflict)
        },
        anomaly: {
            enabled: parseBooleanInput(anomalyRaw.enabled, base.anomaly.enabled),
            cpuThreshold: Math.min(1000, Math.max(1, cpuThreshold.valid ? cpuThreshold.value : base.anomaly.cpuThreshold)),
            memoryThreshold: Math.min(1000, Math.max(1, memoryThreshold.valid ? memoryThreshold.value : base.anomaly.memoryThreshold)),
            durationSamples: Math.min(20, Math.max(1, durationSamples.valid ? durationSamples.value : base.anomaly.durationSamples)),
            cooldownSeconds: Math.min(86400, Math.max(10, cooldownSeconds.valid ? cooldownSeconds.value : base.anomaly.cooldownSeconds))
        },
        logCleanup: {
            enabled: parseBooleanInput(logCleanupRaw.enabled, base.logCleanup.enabled),
            directory: (() => {
                const rawDirectory = String(logCleanupRaw.directory || base.logCleanup.directory || '/logs').trim() || '/logs';
                if (!rawDirectory.startsWith('/')) return `/${rawDirectory}`;
                return rawDirectory;
            })(),
            maxFileSizeMB: Math.min(1024, Math.max(1, maxFileSizeMB.valid ? maxFileSizeMB.value : base.logCleanup.maxFileSizeMB)),
            keepFiles: Math.min(500, Math.max(0, keepFiles.valid ? keepFiles.value : base.logCleanup.keepFiles)),
            maxAgeDays: Math.min(3650, Math.max(0, maxAgeDays.valid ? maxAgeDays.value : base.logCleanup.maxAgeDays)),
            compressOld: parseBooleanInput(logCleanupRaw.compressOld, base.logCleanup.compressOld)
        }
    };
}

async function getServerSmartAlertsConfig(serverId) {
    const setting = await Settings.findByPk(getServerSmartAlertsSettingKey(serverId));
    if (!setting || !setting.value) return defaultServerSmartAlerts();
    return normalizeServerSmartAlertsConfig(setting.value);
}

async function setServerSmartAlertsConfig(serverId, config) {
    const normalized = normalizeServerSmartAlertsConfig(config);
    await Settings.upsert({
        key: getServerSmartAlertsSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    return normalized;
}

function getServerPolicyEngineSettingKey(serverId) {
    return `${SERVER_POLICY_ENGINE_KEY_PREFIX}${serverId}`;
}

function defaultServerPolicyEngineConfig() {
    return {
        enabled: false,
        restartOnCrash: true,
        anomalyAction: 'none', // none|restart|stop
        anomalyCpuThreshold: 95,
        anomalyMemoryThreshold: 95,
        anomalyDurationSamples: 3,
        maxRemediationsPerHour: 3
    };
}

function normalizeServerPolicyEngineConfig(raw) {
    const base = defaultServerPolicyEngineConfig();
    let parsed = raw;

    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        } catch {
            parsed = {};
        }
    }
    if (!parsed || typeof parsed !== 'object') parsed = {};

    const actionRaw = String(parsed.anomalyAction || base.anomalyAction).trim().toLowerCase();
    const anomalyAction = ['none', 'restart', 'stop'].includes(actionRaw) ? actionRaw : base.anomalyAction;

    return {
        enabled: parseBooleanInput(parsed.enabled, base.enabled),
        restartOnCrash: parseBooleanInput(parsed.restartOnCrash, base.restartOnCrash),
        anomalyAction,
        anomalyCpuThreshold: Math.min(1000, Math.max(1, parseFiniteNumberInput(parsed.anomalyCpuThreshold, base.anomalyCpuThreshold, 1, 1000))),
        anomalyMemoryThreshold: Math.min(1000, Math.max(1, parseFiniteNumberInput(parsed.anomalyMemoryThreshold, base.anomalyMemoryThreshold, 1, 1000))),
        anomalyDurationSamples: Math.min(20, Math.max(1, Number.parseInt(parseFiniteNumberInput(parsed.anomalyDurationSamples, base.anomalyDurationSamples, 1, 20), 10) || base.anomalyDurationSamples)),
        maxRemediationsPerHour: Math.min(100, Math.max(1, Number.parseInt(parseFiniteNumberInput(parsed.maxRemediationsPerHour, base.maxRemediationsPerHour, 1, 100), 10) || base.maxRemediationsPerHour))
    };
}

async function getServerPolicyEngineConfig(serverId, forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh) {
        const cached = serverPolicyCache.get(serverId);
        if (cached && now - cached.ts <= SERVER_POLICY_CACHE_TTL_MS) {
            return cached.config;
        }
    }

    const setting = await Settings.findByPk(getServerPolicyEngineSettingKey(serverId));
    const config = (!setting || !setting.value)
        ? defaultServerPolicyEngineConfig()
        : normalizeServerPolicyEngineConfig(setting.value);

    serverPolicyCache.set(serverId, { ts: now, config });
    return config;
}

async function setServerPolicyEngineConfig(serverId, config) {
    const normalized = normalizeServerPolicyEngineConfig(config);
    await Settings.upsert({
        key: getServerPolicyEngineSettingKey(serverId),
        value: JSON.stringify(normalized)
    });
    serverPolicyCache.set(serverId, { ts: Date.now(), config: normalized });
    return normalized;
}

function getPolicyRemediationState(serverId) {
    const now = Date.now();
    const existing = POLICY_REMEDIATION_STATE.get(serverId) || {
        windowStart: now,
        actionsInWindow: 0,
        lastActionAt: 0,
        anomalyCpuHits: 0,
        anomalyMemoryHits: 0
    };

    if (now - existing.windowStart >= 60 * 60 * 1000) {
        existing.windowStart = now;
        existing.actionsInWindow = 0;
    }

    return existing;
}

async function dispatchAutoRemediation(serverId, requestedAction, reason, details = {}) {
    const server = await Server.findByPk(serverId, {
        attributes: ['id', 'name', 'containerId', 'status', 'isSuspended'],
        include: [{ model: Allocation, as: 'allocation', attributes: ['connectorId'] }]
    });
    if (!server || server.isSuspended || !server.allocation || !server.allocation.connectorId) {
        return { dispatched: false, reason: 'server_unavailable' };
    }

    const connectorWs = connectorConnections.get(server.allocation.connectorId);
    if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
        return { dispatched: false, reason: 'connector_offline' };
    }

    const requested = String(requestedAction || '').trim().toLowerCase();
    let action = ['start', 'stop', 'restart'].includes(requested) ? requested : 'start';
    const status = String(server.status || '').trim().toLowerCase();
    if (action === 'restart' && status !== 'running') {
        action = 'start';
    }

    if (action === 'stop' || action === 'restart') {
        rememberServerPowerIntent(server.id, action);
    } else if (action === 'start') {
        consumeServerPowerIntent(server.id);
    }

    connectorWs.send(JSON.stringify({
        type: 'server_power',
        serverId: server.id,
        action
    }));

    const reasonLine = String(reason || '').trim();
    const detailLine = details && details.message ? String(details.message).trim() : '';
    const message = [detailLine, reasonLine ? `Remediation action: ${action} (reason: ${reasonLine})` : `Remediation action: ${action}`]
        .filter(Boolean)
        .join(' | ');

    await sendServerSmartAlert(server, 'resourceAnomaly', { message }).catch(() => {});

    return { dispatched: true, action, connectorId: server.allocation.connectorId };
}

async function handleCrashAutoRemediation(serverId) {
    try {
        if (!Number.isInteger(serverId) || serverId <= 0) return { handled: false, reason: 'invalid_server' };

        const flags = await getPanelFeatureFlags(false);
        if (!flags.policyEngineEnabled || !flags.autoRemediationEnabled) {
            return { handled: false, reason: 'feature_disabled' };
        }

        const policy = await getServerPolicyEngineConfig(serverId, false);
        if (!policy.enabled || !policy.restartOnCrash) {
            return { handled: false, reason: 'policy_disabled' };
        }

        const state = getPolicyRemediationState(serverId);
        const now = Date.now();
        const cooldownMs = Math.max(10000, Number.parseInt(flags.autoRemediationCooldownSeconds, 10) * 1000);
        if (state.lastActionAt > 0 && now - state.lastActionAt < cooldownMs) {
            POLICY_REMEDIATION_STATE.set(serverId, state);
            return { handled: false, reason: 'cooldown' };
        }
        if (state.actionsInWindow >= policy.maxRemediationsPerHour) {
            POLICY_REMEDIATION_STATE.set(serverId, state);
            return { handled: false, reason: 'rate_limited' };
        }

        const result = await dispatchAutoRemediation(serverId, 'start', 'crash', {
            message: 'Server crashed and automatic recovery policy is enabled.'
        });
        if (result.dispatched) {
            state.actionsInWindow += 1;
            state.lastActionAt = now;
        }
        POLICY_REMEDIATION_STATE.set(serverId, state);
        return { handled: Boolean(result.dispatched), action: result.action || null, reason: result.reason || null };
    } catch (error) {
        console.warn(`Crash auto-remediation failed for server ${serverId}:`, error.message);
        return { handled: false, reason: 'error' };
    }
}

async function handlePolicyAnomalyRemediation(serverId, cpuRaw, memoryRaw) {
    try {
        if (!Number.isInteger(serverId) || serverId <= 0) return { handled: false, reason: 'invalid_server' };

        const flags = await getPanelFeatureFlags(false);
        if (!flags.policyEngineEnabled || !flags.autoRemediationEnabled) {
            return { handled: false, reason: 'feature_disabled' };
        }

        const policy = await getServerPolicyEngineConfig(serverId, false);
        if (!policy.enabled || policy.anomalyAction === 'none') {
            return { handled: false, reason: 'policy_disabled' };
        }

        const server = await Server.findByPk(serverId, {
            attributes: ['id', 'memory']
        });
        if (!server) return { handled: false, reason: 'server_missing' };

        const memoryLimit = Math.max(0, Number.parseInt(server.memory, 10) || 0);
        if (memoryLimit <= 0) return { handled: false, reason: 'invalid_memory_limit' };

        const cpuUsage = parseStatNumber(cpuRaw, 0);
        const memoryMB = parseStatNumber(memoryRaw, 0);
        const memoryPercent = (memoryMB / memoryLimit) * 100;

        const state = getPolicyRemediationState(serverId);
        state.anomalyCpuHits = cpuUsage >= policy.anomalyCpuThreshold ? state.anomalyCpuHits + 1 : 0;
        state.anomalyMemoryHits = memoryPercent >= policy.anomalyMemoryThreshold ? state.anomalyMemoryHits + 1 : 0;

        const requiredHits = Math.max(1, Number.parseInt(policy.anomalyDurationSamples, 10) || 1);
        const triggered = state.anomalyCpuHits >= requiredHits || state.anomalyMemoryHits >= requiredHits;
        if (!triggered) {
            POLICY_REMEDIATION_STATE.set(serverId, state);
            return { handled: false, reason: 'not_triggered' };
        }

        const now = Date.now();
        const cooldownMs = Math.max(10000, Number.parseInt(flags.autoRemediationCooldownSeconds, 10) * 1000);
        if (state.lastActionAt > 0 && now - state.lastActionAt < cooldownMs) {
            POLICY_REMEDIATION_STATE.set(serverId, state);
            return { handled: false, reason: 'cooldown' };
        }
        if (state.actionsInWindow >= policy.maxRemediationsPerHour) {
            POLICY_REMEDIATION_STATE.set(serverId, state);
            return { handled: false, reason: 'rate_limited' };
        }

        const reasonParts = [];
        if (state.anomalyCpuHits >= requiredHits) {
            reasonParts.push(`CPU ${cpuUsage.toFixed(1)}% >= ${policy.anomalyCpuThreshold}%`);
        }
        if (state.anomalyMemoryHits >= requiredHits) {
            reasonParts.push(`RAM ${memoryMB.toFixed(0)}MB (${memoryPercent.toFixed(1)}%) >= ${policy.anomalyMemoryThreshold}%`);
        }

        const result = await dispatchAutoRemediation(serverId, policy.anomalyAction, 'resource_anomaly', {
            message: reasonParts.join(' | ')
        });
        if (result.dispatched) {
            state.actionsInWindow += 1;
            state.lastActionAt = now;
            state.anomalyCpuHits = 0;
            state.anomalyMemoryHits = 0;
        }
        POLICY_REMEDIATION_STATE.set(serverId, state);
        return { handled: Boolean(result.dispatched), action: result.action || null, reason: result.reason || null };
    } catch (error) {
        console.warn(`Anomaly auto-remediation failed for server ${serverId}:`, error.message);
        return { handled: false, reason: 'error' };
    }
}

const serverLogCleanupScheduleState = new Map(); // serverId -> ts
const LOG_CLEANUP_MIN_INTERVAL_MS = 10 * 60 * 1000;

async function dispatchServerLogCleanup(server, force = false) {
    if (!server || !server.id) return false;
    if (!server.allocation || !server.allocation.connectorId) return false;

    const cfg = await getServerSmartAlertsConfig(server.id);
    if (!cfg || !cfg.logCleanup || !cfg.logCleanup.enabled) return false;

    const now = Date.now();
    const last = serverLogCleanupScheduleState.get(server.id) || 0;
    if (!force && now - last < LOG_CLEANUP_MIN_INTERVAL_MS) return false;

    const connectorWs = connectorConnections.get(server.allocation.connectorId);
    if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) return false;

    connectorWs.send(JSON.stringify({
        type: 'log_cleanup',
        serverId: server.id,
        directory: cfg.logCleanup.directory || '/logs',
        maxFileSizeMB: cfg.logCleanup.maxFileSizeMB,
        keepFiles: cfg.logCleanup.keepFiles,
        maxAgeDays: cfg.logCleanup.maxAgeDays,
        compressOld: Boolean(cfg.logCleanup.compressOld)
    }));

    serverLogCleanupScheduleState.set(server.id, now);
    return true;
}

async function runScheduledLogCleanupSweep() {
    try {
        const servers = await Server.findAll({
            include: [{ model: Allocation, as: 'allocation' }],
            attributes: ['id']
        });

        for (const server of servers) {
            try {
                await dispatchServerLogCleanup(server, false);
            } catch (error) {
                console.warn(`Scheduled log cleanup failed for server ${server.id}:`, error.message);
            }
        }
    } catch (error) {
        console.warn('Scheduled log cleanup sweep failed:', error.message);
    }
}

function rememberServerPowerIntent(serverId, action) {
    if (!Number.isInteger(serverId) || serverId <= 0) return;
    serverPowerActionIntent.set(serverId, {
        action: String(action || '').toLowerCase(),
        ts: Date.now()
    });
}

function consumeServerPowerIntent(serverId, maxAgeMs = 120000) {
    if (!Number.isInteger(serverId) || serverId <= 0) return null;
    const data = serverPowerActionIntent.get(serverId);
    serverPowerActionIntent.delete(serverId);
    if (!data) return null;
    if ((Date.now() - data.ts) > maxAgeMs) return null;
    return data;
}

const SMART_ALERT_EVENT_LABELS = {
    started: 'Server Started',
    stopped: 'Server Stopped',
    crashed: 'Server Crashed',
    reinstallSuccess: 'Reinstall Completed',
    reinstallFailed: 'Reinstall Failed',
    suspended: 'Server Suspended',
    unsuspended: 'Server Unsuspended',
    resourceAnomaly: 'Resource Anomaly',
    pluginConflict: 'Plugin/Mod Conflict'
};

async function getBrandNameForAlerts() {
    try {
        const setting = await Settings.findByPk('brandName');
        const value = setting ? String(setting.value || '').trim() : '';
        return value || 'CPanel';
    } catch {
        return 'CPanel';
    }
}

async function sendDiscordSmartAlert(webhookUrl, title, description, colorHex) {
    if (!webhookUrl) return;
    const color = Number.parseInt(String(colorHex || '').replace('#', ''), 16) || 3447003;
    await axios.post(webhookUrl, {
        embeds: [{
            title,
            description,
            color,
            timestamp: new Date().toISOString()
        }]
    }, { timeout: 7000 });
}

async function sendTelegramSmartAlert(botToken, chatId, message) {
    if (!botToken || !chatId) return;
    const endpoint = `https://api.telegram.org/bot${botToken}/sendMessage`;
    await axios.post(endpoint, {
        chat_id: chatId,
        text: message,
        disable_web_page_preview: true
    }, { timeout: 7000 });
}

async function sendServerSmartAlert(server, eventKey, details) {
    try {
        if (!server || !server.id) return;
        const cfg = await getServerSmartAlertsConfig(server.id);
        if (!cfg.enabled) return;
        if (!cfg.events || !cfg.events[eventKey]) return;
        if (!cfg.discordWebhook && (!cfg.telegramBotToken || !cfg.telegramChatId)) return;

        const brandName = await getBrandNameForAlerts();
        const title = `[${brandName}] ${SMART_ALERT_EVENT_LABELS[eventKey] || 'Server Alert'}`;
        const lines = [
            `Server: ${server.name} (${server.containerId || `#${server.id}`})`,
            `Status: ${String(server.status || '').toUpperCase() || 'UNKNOWN'}`
        ];

        if (details && details.message) lines.push(`Details: ${details.message}`);
        if (details && details.reason) lines.push(`Reason: ${details.reason}`);
        if (details && details.previousStatus) lines.push(`Previous: ${String(details.previousStatus).toUpperCase()}`);

        const description = lines.join('\n');
        const color = eventKey === 'reinstallFailed' || eventKey === 'crashed'
            ? '#ef4444'
            : eventKey === 'suspended'
                ? '#f59e0b'
                : '#10b981';

        if (cfg.discordWebhook) {
            await sendDiscordSmartAlert(cfg.discordWebhook, title, description, color);
        }
        if (cfg.telegramBotToken && cfg.telegramChatId) {
            await sendTelegramSmartAlert(cfg.telegramBotToken, cfg.telegramChatId, `${title}\n${description}`);
        }
    } catch (error) {
        console.warn(`Smart alert delivery failed for server ${server && server.id ? server.id : 'unknown'}:`, error.message);
    }
}

function parseStatNumber(value, fallback = 0) {
    const parsed = Number.parseFloat(String(value === undefined || value === null ? '' : value).trim());
    if (!Number.isFinite(parsed)) return fallback;
    return parsed;
}

async function handleResourceAnomalyAlert(serverId, cpuRaw, memoryRaw) {
    try {
        if (!Number.isInteger(serverId) || serverId <= 0) return;
        const now = Date.now();
        const lastSample = RESOURCE_ANOMALY_SAMPLE_TS.get(serverId) || 0;
        if (now - lastSample < 1500) return;
        RESOURCE_ANOMALY_SAMPLE_TS.set(serverId, now);

        const [server, cfg] = await Promise.all([
            Server.findByPk(serverId, { attributes: ['id', 'name', 'containerId', 'status', 'memory'] }),
            getServerSmartAlertsConfig(serverId)
        ]);
        if (!server || !cfg || !cfg.enabled || !cfg.events || !cfg.events.resourceAnomaly) return;
        if (!cfg.anomaly || !cfg.anomaly.enabled) return;

        const cpuUsage = parseStatNumber(cpuRaw, 0);
        const memoryMB = parseStatNumber(memoryRaw, 0);
        const memoryLimit = Number.parseInt(server.memory, 10) || 0;
        if (memoryLimit <= 0) return;
        const memoryPercent = (memoryMB / memoryLimit) * 100;

        const state = RESOURCE_ANOMALY_STATE.get(serverId) || { cpuHits: 0, memoryHits: 0, lastAlertAt: 0 };
        state.cpuHits = cpuUsage >= cfg.anomaly.cpuThreshold ? state.cpuHits + 1 : 0;
        state.memoryHits = memoryPercent >= cfg.anomaly.memoryThreshold ? state.memoryHits + 1 : 0;

        const requiredHits = Math.max(1, Number.parseInt(cfg.anomaly.durationSamples, 10) || 1);
        const cooldownMs = Math.max(10000, (Number.parseInt(cfg.anomaly.cooldownSeconds, 10) * 1000) || DEFAULT_STATS_ALERT_COOLDOWN_MS);

        const cpuTriggered = state.cpuHits >= requiredHits;
        const memoryTriggered = state.memoryHits >= requiredHits;
        if ((cpuTriggered || memoryTriggered) && now - state.lastAlertAt >= cooldownMs) {
            const parts = [];
            if (cpuTriggered) {
                parts.push(`CPU ${cpuUsage.toFixed(1)}% >= ${cfg.anomaly.cpuThreshold}% for ${state.cpuHits} samples`);
            }
            if (memoryTriggered) {
                parts.push(`RAM ${memoryMB.toFixed(0)}MB (${memoryPercent.toFixed(1)}%) >= ${cfg.anomaly.memoryThreshold}% for ${state.memoryHits} samples`);
            }

            await sendServerSmartAlert(server, 'resourceAnomaly', {
                message: parts.join(' | ')
            });
            state.lastAlertAt = now;
            state.cpuHits = 0;
            state.memoryHits = 0;
        }

        RESOURCE_ANOMALY_STATE.set(serverId, state);
    } catch (error) {
        console.warn(`Resource anomaly detector failed for server ${serverId}:`, error.message);
    }
}

function detectPluginConflict(output) {
    if (typeof output !== 'string' || !output.trim()) return null;
    const lowered = output.toLowerCase();

    const conflictPatterns = [
        /nosuchmethoderror/i,
        /noclassdeffounderror/i,
        /classnotfoundexception/i,
        /unsupportedclassversionerror/i,
        /failed to load plugin/i,
        /could not load 'plugins\/.+\.jar'/i,
        /mixin apply failed/i,
        /encountered an unexpected exception/i
    ];

    const matched = conflictPatterns.some((pattern) => pattern.test(lowered));
    if (!matched) return null;

    const jarMatches = Array.from(output.matchAll(/([A-Za-z0-9_.-]+\.jar)/g)).map((match) => match[1]);
    const uniqueJars = [...new Set(jarMatches)].slice(0, 6);

    const pluginMatches = Array.from(output.matchAll(/\[([A-Za-z0-9_. -]{2,64})\]/g))
        .map((match) => match[1].trim())
        .filter((name) => name && !/info|warn|error|debug|server/i.test(name));
    const uniquePlugins = [...new Set(pluginMatches)].slice(0, 6);

    const summaryParts = [];
    if (uniquePlugins.length > 0) summaryParts.push(`Plugins: ${uniquePlugins.join(', ')}`);
    if (uniqueJars.length > 0) summaryParts.push(`JARs: ${uniqueJars.join(', ')}`);
    summaryParts.push(`Log hint: ${output.trim().slice(0, 220)}`);

    return {
        fingerprint: `${uniquePlugins.join('|')}|${uniqueJars.join('|')}|${output.trim().slice(0, 80)}`,
        summary: summaryParts.join(' | ')
    };
}

async function handlePluginConflictAlert(serverId, output) {
    try {
        if (!Number.isInteger(serverId) || serverId <= 0) return;
        const conflict = detectPluginConflict(output);
        if (!conflict) return;

        const [server, cfg] = await Promise.all([
            Server.findByPk(serverId, { attributes: ['id', 'name', 'containerId', 'status'] }),
            getServerSmartAlertsConfig(serverId)
        ]);
        if (!server || !cfg || !cfg.enabled || !cfg.events || !cfg.events.pluginConflict) return;

        const state = PLUGIN_CONFLICT_STATE.get(serverId) || { lastAlertAt: 0, fingerprint: '' };
        const now = Date.now();
        if (state.fingerprint === conflict.fingerprint && now - state.lastAlertAt < DEFAULT_PLUGIN_ALERT_COOLDOWN_MS) {
            return;
        }
        if (now - state.lastAlertAt < DEFAULT_PLUGIN_ALERT_COOLDOWN_MS) {
            return;
        }

        let metadataHint = '';
        try {
            const installs = await getServerMinecraftInstallRecords(serverId);
            if (Array.isArray(installs) && installs.length > 0) {
                const loweredSummary = conflict.summary.toLowerCase();
                const matched = installs
                    .filter((entry) => {
                        const fileName = String(entry.fileName || '').toLowerCase();
                        const title = String(entry.projectTitle || '').toLowerCase();
                        return (fileName && loweredSummary.includes(fileName)) || (title && loweredSummary.includes(title));
                    })
                    .slice(0, 4)
                    .map((entry) => `${entry.projectTitle || entry.fileName} (${entry.versionNumber || 'unknown'})`);
                if (matched.length > 0) {
                    metadataHint = ` | Installed metadata matches: ${matched.join(', ')}`;
                }
            }
        } catch {
            // Ignore metadata failures; conflict detection still works on log heuristics.
        }

        await sendServerSmartAlert(server, 'pluginConflict', {
            message: `${conflict.summary}${metadataHint}`
        });

        PLUGIN_CONFLICT_STATE.set(serverId, {
            lastAlertAt: now,
            fingerprint: conflict.fingerprint
        });
    } catch (error) {
        console.warn(`Plugin conflict detector failed for server ${serverId}:`, error.message);
    }
}

const CONNECTOR_ALLOWED_ORIGINS_KEY_PREFIX = 'connector_allowed_origins_';

function normalizeOriginCandidate(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;

    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
    try {
        const parsed = new URL(withScheme);
        const protocol = String(parsed.protocol || '').toLowerCase();
        if (protocol !== 'http:' && protocol !== 'https:') return null;
        if (!parsed.host) return null;
        return `${protocol}//${parsed.host.toLowerCase()}`;
    } catch {
        return null;
    }
}

function normalizeBaseUrlCandidate(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    try {
        const parsed = new URL(raw);
        const protocol = String(parsed.protocol || '').toLowerCase();
        if (protocol !== 'http:' && protocol !== 'https:') return null;
        if (!parsed.host) return null;
        const cleanPath = String(parsed.pathname || '/').replace(/\/+$/, '');
        const basePath = cleanPath && cleanPath !== '/' ? cleanPath : '';
        return `${protocol}//${parsed.host}${basePath}`;
    } catch {
        return null;
    }
}

function isLocalhostBaseUrl(value) {
    const normalized = normalizeBaseUrlCandidate(value);
    if (!normalized) return false;
    try {
        const parsed = new URL(normalized);
        const host = String(parsed.hostname || '').toLowerCase();
        return host === 'localhost' || host === '127.0.0.1' || host === '::1';
    } catch {
        return false;
    }
}

function resolvePanelBaseUrl(req) {
    const envBase = normalizeBaseUrlCandidate(process.env.APP_URL || '');
    if (envBase && !isLocalhostBaseUrl(envBase)) {
        return envBase;
    }

    const headers = (req && req.headers) ? req.headers : {};
    const forwardedProto = String(headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    const forwardedHost = String(headers['x-forwarded-host'] || '').split(',')[0].trim();

    const protocol = forwardedProto
        || (req && req.protocol)
        || (req && req.socket && req.socket.encrypted ? 'https' : 'http');
    const host = forwardedHost
        || (req && typeof req.get === 'function' ? req.get('host') : '')
        || String(headers.host || '').trim();

    if (host) {
        return `${protocol}://${host}`;
    }

    if (envBase) {
        return envBase;
    }

    return `http://localhost:${process.env.APP_PORT || 3000}`;
}

function extractOriginFromUrl(value) {
    const normalized = normalizeBaseUrlCandidate(value);
    if (!normalized) return null;
    try {
        const parsed = new URL(normalized);
        return `${String(parsed.protocol || '').toLowerCase()}//${String(parsed.host || '').toLowerCase()}`;
    } catch {
        return null;
    }
}

function parseStoredAllowedOrigins(value) {
    const raw = String(value || '').trim();
    if (!raw) return [];

    let input = [];
    try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
            input = parsed;
        } else if (typeof parsed === 'string') {
            input = parsed.split(/[\n,;]+/g);
        }
    } catch {
        input = raw.split(/[\n,;]+/g);
    }

    const normalized = [];
    const seen = new Set();
    for (const candidate of input) {
        const origin = normalizeOriginCandidate(candidate);
        if (!origin || seen.has(origin)) continue;
        seen.add(origin);
        normalized.push(origin);
    }
    return normalized;
}

function parseAllowedOriginsInput(value, fallbackOrigin) {
    const parts = String(value || '').split(/[\n,;]+/g);
    const origins = [];
    const invalid = [];
    const seen = new Set();

    for (const part of parts) {
        const raw = String(part || '').trim();
        if (!raw) continue;
        const origin = normalizeOriginCandidate(raw);
        if (!origin) {
            invalid.push(raw);
            continue;
        }
        if (seen.has(origin)) continue;
        seen.add(origin);
        origins.push(origin);
    }

    if (origins.length === 0 && fallbackOrigin) {
        const fallback = normalizeOriginCandidate(fallbackOrigin);
        if (fallback) origins.push(fallback);
    }

    return { origins, invalid };
}

function getConnectorAllowedOriginsSettingKey(connectorId) {
    return `${CONNECTOR_ALLOWED_ORIGINS_KEY_PREFIX}${connectorId}`;
}

async function getConnectorAllowedOrigins(connectorId, fallbackOrigin) {
    const key = getConnectorAllowedOriginsSettingKey(connectorId);
    const row = await Settings.findByPk(key);
    const parsed = parseStoredAllowedOrigins(row ? row.value : '');
    if (parsed.length > 0) return parsed;

    const fallback = normalizeOriginCandidate(fallbackOrigin);
    return fallback ? [fallback] : [];
}

async function setConnectorAllowedOrigins(connectorId, origins) {
    const key = getConnectorAllowedOriginsSettingKey(connectorId);
    await Settings.upsert({
        key,
        value: JSON.stringify(Array.isArray(origins) ? origins : [])
    });
}

async function getConnectorAllowedOriginsMap(connectorIds, fallbackOrigin) {
    const ids = Array.from(new Set((connectorIds || []).map((id) => Number.parseInt(id, 10)).filter(Number.isInteger)));
    const map = {};
    const fallback = normalizeOriginCandidate(fallbackOrigin);

    if (ids.length === 0) return map;

    const keys = ids.map((id) => getConnectorAllowedOriginsSettingKey(id));
    const rows = await Settings.findAll({
        where: { key: { [Op.in]: keys } },
        attributes: ['key', 'value']
    });

    rows.forEach((row) => {
        const key = String(row.key || '');
        if (!key.startsWith(CONNECTOR_ALLOWED_ORIGINS_KEY_PREFIX)) return;
        const connectorId = Number.parseInt(key.slice(CONNECTOR_ALLOWED_ORIGINS_KEY_PREFIX.length), 10);
        if (!Number.isInteger(connectorId)) return;
        map[connectorId] = parseStoredAllowedOrigins(row.value);
    });

    ids.forEach((id) => {
        if (!Array.isArray(map[id]) || map[id].length === 0) {
            map[id] = fallback ? [fallback] : [];
        }
    });

    return map;
}


    return {
        parseIntegerInput,
        parseBooleanInput,
        parseFiniteNumberInput,
        parseMigrationTimestamp,
        getServerMigrationTransferSettingKey,
        normalizeServerMigrationTransferState,
        getServerMigrationTransferState,
        setServerMigrationTransferState,
        removeServerMigrationTransferState,
        defaultPanelFeatureFlags,
        getPanelFeatureFlagsFromMap,
        getPanelFeatureFlags,
        getServerMountsForInstall,
        calculateServerCostEstimate,
        getServerStoreBillingSettingKey,
        normalizeServerStoreBillingState,
        getServerStoreBillingState,
        setServerStoreBillingState,
        removeServerStoreBillingState,
        getRevenuePlanCatalog,
        setRevenuePlanCatalog,
        getUserRevenueProfile,
        setUserRevenueProfile,
        removeUserRevenueProfile,
        listUserRevenueProfiles,
        runRevenueModeSweep,
        getServerScheduledScalingConfig,
        setServerScheduledScalingConfig,
        removeServerScheduledScalingConfig,
        runServerScheduledScalingSweep,
        calculateStoreCreateCoins,
        calculateStoreRenewCoins,
        runServerStoreBillingSweep,
        normalizeMinecraftProjectKind,
        getMinecraftLoaderCatalog,
        normalizeMinecraftLoader,
        normalizeMinecraftVersion,
        sanitizeServerDirectoryPath,
        sanitizeDownloadFileName,
        inferMinecraftDefaults,
        buildModrinthUserAgent,
        createWsRequestId,
        resolveMinecraftTargetDirectory,
        getMinecraftInstallTrackerSettingKey,
        parseServerAddonPath,
        normalizeMinecraftInstallRecord,
        normalizeMinecraftInstallRecords,
        getServerMinecraftInstallRecords,
        setServerMinecraftInstallRecords,
        upsertServerMinecraftInstallRecord,
        removeServerMinecraftInstallRecord,
        resolveModrinthVersionForInstall,
        waitForConnectorDownloadResult,
        runConnectorFileAction,
        normalizeServerAdvancedLimits,
        getServerSmartAlertsSettingKey,
        defaultServerSmartAlerts,
        sanitizeHttpUrl,
        normalizeServerSmartAlertsConfig,
        getServerSmartAlertsConfig,
        setServerSmartAlertsConfig,
        getServerPolicyEngineSettingKey,
        defaultServerPolicyEngineConfig,
        normalizeServerPolicyEngineConfig,
        getServerPolicyEngineConfig,
        setServerPolicyEngineConfig,
        handleCrashAutoRemediation,
        handlePolicyAnomalyRemediation,
        dispatchServerLogCleanup,
        runScheduledLogCleanupSweep,
        rememberServerPowerIntent,
        consumeServerPowerIntent,
        getBrandNameForAlerts,
        sendDiscordSmartAlert,
        sendTelegramSmartAlert,
        sendServerSmartAlert,
        parseStatNumber,
        handleResourceAnomalyAlert,
        detectPluginConflict,
        handlePluginConflictAlert,
        normalizeOriginCandidate,
        normalizeBaseUrlCandidate,
        isLocalhostBaseUrl,
        resolvePanelBaseUrl,
        extractOriginFromUrl,
        parseStoredAllowedOrigins,
        parseAllowedOriginsInput,
        getConnectorAllowedOriginsSettingKey,
        getConnectorAllowedOrigins,
        setConnectorAllowedOrigins,
        getConnectorAllowedOriginsMap,
        SERVER_SMART_ALERTS_KEY_PREFIX,
        SERVER_STARTUP_PRESET_KEY_PREFIX,
        serverPowerActionIntent,
        MODRINTH_API_BASE_URL,
        MODRINTH_MAX_SEARCH_LIMIT,
        MODRINTH_REQUEST_TIMEOUT_MS,
        MODRINTH_PLUGIN_LOADERS,
        MODRINTH_MOD_LOADERS,
        MINECRAFT_INSTALL_TRACKER_PREFIX,
        RESOURCE_ANOMALY_STATE,
        RESOURCE_ANOMALY_SAMPLE_TS,
        PLUGIN_CONFLICT_STATE,
        DEFAULT_STATS_ALERT_COOLDOWN_MS,
        DEFAULT_PLUGIN_ALERT_COOLDOWN_MS,
        pendingMigrationFileImports,
        SERVER_MIGRATION_TRANSFER_KEY_PREFIX,
        MIGRATION_TRANSFER_STATUSES,
        SERVER_POLICY_ENGINE_KEY_PREFIX,
        POLICY_REMEDIATION_STATE,
        serverLogCleanupScheduleState,
        SERVER_STORE_BILLING_KEY_PREFIX,
        STORE_BILLING_SUSPEND_REASON_PREFIX,
        STORE_BILLING_SUSPEND_REASON,
        REVENUE_PLAN_CATALOG_SETTING_KEY,
        USER_REVENUE_PROFILE_KEY_PREFIX,
        REVENUE_SUSPEND_REASON_PREFIX,
        REVENUE_SUSPEND_REASON,
        SERVER_SCHEDULED_SCALING_KEY_PREFIX,
        LOG_CLEANUP_MIN_INTERVAL_MS,
        SMART_ALERT_EVENT_LABELS,
        CONNECTOR_ALLOWED_ORIGINS_KEY_PREFIX
    };
}

module.exports = { createLegacyRuntimeHelpers };
