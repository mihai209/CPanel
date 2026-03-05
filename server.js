require('dotenv').config();
const { Sequelize, Op } = require('sequelize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const { body, validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { Readable } = require('stream');
const WebSocket = require('ws');
const { app, server } = require('./core/app');
const { bootstrapApp } = require('./core/bootstrap');
const { printStartupBoot, bootInfo, bootWarn } = require('./core/boot');
const {
    createRedisClient,
    getRedisClient,
    reconfigureRedis,
    testRedisConnection,
    getRedisRuntimeInfo,
    normalizeRedisConfig,
    getEnvRedisConfig
} = require('./core/redis');
const { createSettingsCache, bindSettingsInvalidation } = require('./core/settings-cache');
const { registerAuditMiddleware } = require('./core/audit');
const { createRequirePermission } = require('./core/rbac');
const { createJobQueue } = require('./core/jobs/queue');
const { registerDefaultJobHandlers } = require('./core/jobs/handlers');
const { startBackupPolicyScheduler } = require('./core/backups/scheduler');
const { startServerScheduleRunner } = require('./core/schedules/scheduler');
const {
    sequelize,
    dbConnection,
    User,
    LinkedAccount,
    Package,
    Image,
    Server,
    Settings,
    Location,
    DatabaseHost,
    ServerDatabase,
    Connector,
    Allocation,
    Job,
    AuditLog,
    ServerBackupPolicy,
    ServerBackup,
    Mount,
    ServerMount,
    Mount,
    ServerMount,
    ServerSubuser,
    ServerApiKey,
    AdminApiKey,
    AdminApiKeyAudit
} = require('./core/db');
const { registerSecurityMiddleware } = require('./core/middleware/security');
const { registerLocalsMiddleware } = require('./core/middleware/locals');
const { createSessionAuthGuards, createTokenAuthenticator } = require('./core/middleware/auth');
const { createRequireAdminApiPermission } = require('./core/middleware/admin-api');
const { registerInternalApiRoutes } = require('./routes/internal/api');
const { registerSystemRoutes } = require('./routes/internal/system');
const { registerPlatformRoutes } = require('./routes/internal/platform');
const { registerAdminApiKeyRoutes } = require('./routes/internal/admin-api-keys');
const { registerOAuthRoutes } = require('./routes/oauth');
const { registerAccountRoutes } = require('./routes/account');
const { registerAdminServersRoutes } = require('./routes/legacy/admin-servers');
const { registerServerPagesRoutes } = require('./routes/legacy/server-pages');
const { registerAdminAuthSettingsRoutes } = require('./routes/legacy/admin-auth-settings');
const { registerAdminCoreRoutes } = require('./routes/legacy/admin-core');
const { registerAdminConnectorsOverviewRoutes } = require('./routes/legacy/admin-connectors-overview');
const { createLegacyHelpers } = require('./core/helpers/legacy-helpers');
const { registerWebSocketRuntime } = require('./core/websocket-runtime');
const {
    SERVER_API_KEY_PERMISSION_CATALOG,
    normalizeServerApiKeyPermissions,
    generateServerApiKeyToken,
    parseServerApiBearerToken,
    hashServerApiKeyToken,
    isServerApiKeyActive,
    hasServerApiKeyPermission
} = require('./core/server-api-keys');
const {
    ADMIN_API_KEY_PERMISSION_CATALOG,
    ADMIN_API_KEY_WILDCARD,
    normalizeAdminApiKeyPermissions,
    generateAdminApiKeyToken,
    parseAdminApiBearerToken,
    hashAdminApiKeyToken,
    normalizeAdminApiIpAllowlist,
    normalizeAdminApiRotationDays,
    normalizeAdminApiKeyExpiresAt,
    isAdminApiKeyIpAllowed,
    getAdminApiKeyInactiveReason,
    isAdminApiKeyActive,
    hasAdminApiKeyPermission
} = require('./core/admin-api-keys');

const PORT = process.env.APP_PORT || 3000;
const SECRET_KEY = process.env.APP_SECRET || "UNSECURE_DEFAULT_KEY";
const CONNECTOR_SECRET = process.env.CONNECTOR_SECRET || "UNSECURE_CONNECTOR_KEY";
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '');
const passport = require('passport');
const md5 = require('blueimp-md5');
const DEBUG_ENABLED = ['1', 'true', 'yes', 'on'].includes(String(process.env.DEBUG || '').trim().toLowerCase());

printStartupBoot({
    appUrl: APP_URL,
    port: PORT,
    dbConnection,
    configFile: '.env',
    debugEnabled: DEBUG_ENABLED
});

const redisClient = createRedisClient(getEnvRedisConfig(), 'env');
const settingsCache = createSettingsCache({
    Settings,
    redisClient,
    getRedisClient
});
bindSettingsInvalidation(Settings, settingsCache);

const REDIS_SETTINGS_KEYS = [
    'redisEnabled',
    'redisUrl',
    'redisHost',
    'redisPort',
    'redisDb',
    'redisUsername',
    'redisPassword',
    'redisTls',
    'redisSessionPrefix'
];

async function loadRedisConfigFromSettings() {
    const rows = await Settings.findAll({
        where: { key: REDIS_SETTINGS_KEYS }
    });
    const map = {};
    rows.forEach((row) => {
        if (!row || !row.key) return;
        map[row.key] = row.value;
    });
    const hasAny = REDIS_SETTINGS_KEYS.some((key) => map[key] !== undefined && map[key] !== null && String(map[key]).trim() !== '');
    if (!hasAny) return null;
    return normalizeRedisConfig({
        enabled: map.redisEnabled,
        url: map.redisUrl,
        host: map.redisHost,
        port: map.redisPort,
        db: map.redisDb,
        username: map.redisUsername,
        password: map.redisPassword,
        tls: map.redisTls,
        sessionPrefix: map.redisSessionPrefix
    }, { fallbackToEnv: false });
}

const { loginLimiter } = bootstrapApp({
    app,
    sequelize,
    redisClient,
    settingsCache,
    settingsModel: Settings,
    userModel: User,
    secretKey: SECRET_KEY,
    passport,
    registerSecurityMiddleware,
    registerLocalsMiddleware
});

const authenticateToken = createTokenAuthenticator({
    jwt,
    secretKey: SECRET_KEY
});

const { requireAuth, requireAdmin } = createSessionAuthGuards({ User });
const requirePermission = createRequirePermission({ User, Settings });
const requireAdminApiPermission = createRequireAdminApiPermission({
    User,
    AdminApiKey,
    AdminApiKeyAudit,
    Settings,
    secretKey: SECRET_KEY,
    parseAdminApiBearerToken,
    hashAdminApiKeyToken,
    isAdminApiKeyIpAllowed,
    getAdminApiKeyInactiveReason,
    isAdminApiKeyActive,
    hasAdminApiKeyPermission
});

registerAuditMiddleware({ app, AuditLog });

registerInternalApiRoutes({
    app,
    User,
    Server,
    bcrypt,
    jwt,
    secretKey: SECRET_KEY,
    axios,
    connectorSecret: CONNECTOR_SECRET,
    authenticateToken
});

registerSystemRoutes({
    app,
    User,
    Settings,
    requireAuth,
    requireAdmin
});

const connectorConnections = new Map(); // connectorId -> ws

const legacyHelpers = createLegacyHelpers({
    Settings,
    User,
    Server,
    Mount,
    ServerMount,
    Image,
    Allocation,
    AuditLog,
    Op,
    axios,
    WebSocket,
    connectorConnections
});

const {
    rememberServerPowerIntent,
    consumeServerPowerIntent,
    sendServerSmartAlert,
    handlePluginConflictAlert,
    handleResourceAnomalyAlert,
    handleCrashAutoRemediation,
    handlePolicyAnomalyRemediation,
    getConnectorAllowedOrigins,
    normalizeOriginCandidate,
    extractOriginFromUrl,
    resolvePanelBaseUrl,
    runScheduledLogCleanupSweep,
    runServerStoreBillingSweep,
    runRevenueModeSweep,
    runServerScheduledScalingSweep,
    pendingMigrationFileImports,
    RESOURCE_ANOMALY_STATE,
    RESOURCE_ANOMALY_SAMPLE_TS,
    PLUGIN_CONFLICT_STATE
} = legacyHelpers;

const jobQueue = createJobQueue({
    Job,
    AuditLog,
    pollIntervalMs: 2000,
    logger: console
});

registerDefaultJobHandlers(jobQueue, {
    Server,
    Allocation,
    Connector,
    ServerBackupPolicy,
    ServerBackup,
    Settings,
    connectorConnections,
    pendingMigrationFileImports,
    dispatchServerLogCleanup: legacyHelpers.dispatchServerLogCleanup,
    getPanelFeatureFlagsFromMap: legacyHelpers.getPanelFeatureFlagsFromMap,
    resolveModrinthVersionForInstall: legacyHelpers.resolveModrinthVersionForInstall,
    createWsRequestId: legacyHelpers.createWsRequestId,
    waitForConnectorDownloadResult: legacyHelpers.waitForConnectorDownloadResult,
    parseServerAddonPath: legacyHelpers.parseServerAddonPath,
    upsertServerMinecraftInstallRecord: legacyHelpers.upsertServerMinecraftInstallRecord,
    bootInfo
});

jobQueue.start();

const stopBackupPolicyScheduler = startBackupPolicyScheduler({
    ServerBackupPolicy,
    jobQueue,
    intervalMs: 60 * 1000,
    bootInfo
});

const stopServerScheduleRunner = startServerScheduleRunner({
    Settings,
    Op,
    Server,
    Allocation,
    ServerBackupPolicy,
    jobQueue,
    connectorConnections,
    intervalMs: 30 * 1000,
    bootInfo,
    bootWarn
});


registerPlatformRoutes({
    app,
    requireAuth,
    requireAdmin,
    requirePermission,
    requireAdminApiPermission,
    Job,
    AuditLog,
    Server,
    User,
    Connector,
    Settings,
    ServerSubuser,
    ServerBackupPolicy,
    ServerBackup,
    jobQueue,
    bootInfo,
    sequelize
});

registerAdminApiKeyRoutes({
    app,
    requireAuth,
    requireAdmin,
    SECRET_KEY,
    Settings,
    AdminApiKey,
    AdminApiKeyAudit,
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
});

const legacyRouteContextData = {
    app,
    sequelize,
    Sequelize,
    Op,
    jwt,
    bcrypt,
    axios,
    body,
    validationResult,
    speakeasy,
    QRCode,
    Readable,
    WebSocket,
    crypto,
    path,
    PORT,
    SECRET_KEY,
    CONNECTOR_SECRET,
    APP_URL,
    passport,
    md5,
    DEBUG_ENABLED,
    User,
    LinkedAccount,
    Package,
    Image,
    Server,
    Settings,
    Location,
    DatabaseHost,
    ServerDatabase,
    Connector,
    Allocation,
    Job,
    AuditLog,
    ServerBackupPolicy,
    ServerBackup,
    ServerSubuser,
    ServerApiKey,
    AdminApiKey,
    AdminApiKeyAudit,
    SERVER_API_KEY_PERMISSION_CATALOG,
    normalizeServerApiKeyPermissions,
    generateServerApiKeyToken,
    parseServerApiBearerToken,
    hashServerApiKeyToken,
    isServerApiKeyActive,
    hasServerApiKeyPermission,
    ADMIN_API_KEY_PERMISSION_CATALOG,
    ADMIN_API_KEY_WILDCARD,
    normalizeAdminApiKeyPermissions,
    normalizeAdminApiIpAllowlist,
    normalizeAdminApiRotationDays,
    normalizeAdminApiKeyExpiresAt,
    generateAdminApiKeyToken,
    parseAdminApiBearerToken,
    hashAdminApiKeyToken,
    isAdminApiKeyIpAllowed,
    getAdminApiKeyInactiveReason,
    isAdminApiKeyActive,
    hasAdminApiKeyPermission,
    authenticateToken,
    requireAuth,
    requireAdmin,
    requirePermission,
    loginLimiter,
    connectorConnections,
    jobQueue,
    getRedisClient,
    reconfigureRedis,
    testRedisConnection,
    getRedisRuntimeInfo,
    normalizeRedisConfig,
    getEnvRedisConfig,
    ...legacyHelpers
};

const legacyRouteContext = new Proxy(legacyRouteContextData, {
    has: () => true,
    get: (target, prop) => {
        if (Object.prototype.hasOwnProperty.call(target, prop)) {
            return target[prop];
        }
        if (Object.prototype.hasOwnProperty.call(globalThis, prop)) {
            return globalThis[prop];
        }
        return undefined;
    }
});

registerAdminServersRoutes(legacyRouteContext);

registerServerPagesRoutes(legacyRouteContext);

registerAdminAuthSettingsRoutes(legacyRouteContext);

registerOAuthRoutes({
    app,
    passport,
    User,
    LinkedAccount,
    md5
});
registerAdminCoreRoutes(legacyRouteContext);

registerAdminConnectorsOverviewRoutes(legacyRouteContext);

loadRedisConfigFromSettings().then(async (storedRedisConfig) => {
    if (!storedRedisConfig) return;
    const envRedisEnabled = ['1', 'true', 'yes', 'on'].includes(String(process.env.REDIS_ENABLED || '').trim().toLowerCase());
    if (envRedisEnabled) {
        bootInfo('redis env configuration detected; skipping auto-apply from database settings');
        return;
    }
    const applyResult = await reconfigureRedis(storedRedisConfig, 'settings');
    if (!applyResult.ok && storedRedisConfig.enabled) {
        bootWarn('redis settings from database failed to apply error=%s', applyResult.error || 'unknown');
    } else {
        bootInfo('redis configuration source set to settings enabled=%s', applyResult.enabled ? 'true' : 'false');
    }
}).catch((error) => {
    bootWarn('failed to load redis settings from database error=%s', error.message || error);
});

registerAccountRoutes({
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
});

// 404 Handler - Catch all other routes
app.use((req, res) => {
    res.status(404).render('404', {
        user: req.session.user || null,
        path: req.path
    });
});

server.listen(PORT, () => {
    bootInfo('panel backend running on url=%s', `http://localhost:${PORT}`);
    bootInfo('websocket server enabled routes=%j', ['/ws/connector', '/ws/ui', '/ws/server/:containerId']);
});

registerWebSocketRuntime({
    server,
    WebSocket,
    jwt,
    SECRET_KEY,
    Server,
    ServerSubuser,
    AuditLog,
    Allocation,
    Image,
    Connector,
    Settings,
    connectorConnections,
    rememberServerPowerIntent,
    consumeServerPowerIntent,
    sendServerSmartAlert,
    sendDiscordSmartAlert: legacyHelpers.sendDiscordSmartAlert,
    sendTelegramSmartAlert: legacyHelpers.sendTelegramSmartAlert,
    handlePluginConflictAlert,
    handleResourceAnomalyAlert,
    handleCrashAutoRemediation,
    handlePolicyAnomalyRemediation,
    pendingMigrationFileImports,
    getServerMigrationTransferState: legacyHelpers.getServerMigrationTransferState,
    setServerMigrationTransferState: legacyHelpers.setServerMigrationTransferState,
    removeServerMigrationTransferState: legacyHelpers.removeServerMigrationTransferState,
    runScheduledLogCleanupSweep,
    runServerStoreBillingSweep,
    runRevenueModeSweep,
    runServerScheduledScalingSweep,
    normalizeOriginCandidate,
    getConnectorAllowedOrigins,
    extractOriginFromUrl,
    resolvePanelBaseUrl,
    RESOURCE_ANOMALY_STATE,
    RESOURCE_ANOMALY_SAMPLE_TS,
    PLUGIN_CONFLICT_STATE
});

function gracefulShutdown() {
    try {
        jobQueue.stop();
    } catch {
        // ignore
    }
    try {
        stopBackupPolicyScheduler();
    } catch {
        // ignore
    }
    try {
        stopServerScheduleRunner();
    } catch {
        // ignore
    }
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
