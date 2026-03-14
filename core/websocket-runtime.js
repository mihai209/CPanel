const { appendIncidentCenterRecord } = require('./incidents');
const { Op } = require('sequelize');

function registerWebSocketRuntime(deps) {
    const {
        server,
        WebSocket,
        jwt,
        SECRET_KEY,
        Server,
        ServerSubuser,
        AuditLog,
        ServerResourceSample,
        Allocation,
        Image,
        Connector,
        Settings,
        connectorConnections,
        rememberServerPowerIntent,
        consumeServerPowerIntent,
        sendServerSmartAlert,
        sendDiscordSmartAlert,
        sendTelegramSmartAlert,
        handlePluginConflictAlert,
        handleResourceAnomalyAlert,
        handlePolicyPlaybooksOnStop,
        handleCrashAutoRemediation,
        handlePolicyAnomalyRemediation,
        pendingMigrationFileImports,
        getServerMigrationTransferState,
        setServerMigrationTransferState,
        removeServerMigrationTransferState,
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
    } = deps;

// WebSocket Server for Connectors & UI
const wss = new WebSocket.Server({ noServer: true, maxPayload: 2 * 1024 * 1024 });
const uiClients = new Set();
const serverConsoleClients = new Map(); // serverId -> Set<ws>
const recentConsolePayloads = new Map(); // serverId -> { output: string, ts: number }
const serverConsoleBuffers = new Map(); // serverId -> { lines: string[], bytes: number }
const SERVER_CONSOLE_BUFFER_MAX_LINES = 1200;
const SERVER_CONSOLE_BUFFER_MAX_BYTES = 1024 * 1024;
const SERVER_DEBUG_LOG_TAIL_MAX_CHARS = 32 * 1024;
const CONNECTOR_WS_READ_LIMIT_MIN_MB = 8;
const CONNECTOR_WS_READ_LIMIT_MAX_MB = 1024;
const CONNECTOR_WS_READ_LIMIT_DEFAULT_UPLOAD_MB = 50;
const WEBHOOKS_SETTING_KEY = 'extensionWebhooksConfig';
const ANTI_MINER_STATE = new Map(); // serverId -> runtime detection state
const ANTI_MINER_CONFIG_CACHE_TTL_MS = 15 * 1000;
const ANTI_MINER_CONFIG_CACHE = {
    ts: 0,
    config: null
};
const ANTI_MINER_CONFIG_SETTING_KEYS = [
    'featureAntiMinerEnabled',
    'antiMinerSuspendScore',
    'antiMinerHighCpuPercent',
    'antiMinerHighCpuSamples',
    'antiMinerDecayMinutes',
    'antiMinerCooldownSeconds'
];
const CRASH_POLICY_CACHE_TTL_MS = 10 * 1000;
const CRASH_POLICY_SETTING_KEYS = [
    'crashDetectionEnabled',
    'crashDetectCleanExitAsCrash',
    'crashDetectionCooldownSeconds'
];
let crashPolicyCache = { ts: 0, config: null };
const SERVER_CRASH_COOLDOWN_STATE = new Map(); // serverId -> last crash ts
const RESOURCE_TIMELINE_LAST_WRITE_TS = new Map(); // serverId -> timestamp
const RESOURCE_TIMELINE_WRITE_INTERVAL_MS = 10 * 1000;
const RESOURCE_TIMELINE_RETENTION_MS = 12 * 60 * 60 * 1000;
let resourceTimelineLastCleanupTs = 0;

const parseCrashBool = (value, fallback = false) => {
    if (value === undefined || value === null || value === '') return fallback;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
};
const parseCrashNumber = (value, fallback, min, max) => {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
};

const parseUploadToggle = (value, fallback = true) => {
    if (value === undefined || value === null || value === '') return fallback;
    const normalized = String(value).trim().toLowerCase();
    return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
};

const parseUploadMaxMb = (value, fallback = CONNECTOR_WS_READ_LIMIT_DEFAULT_UPLOAD_MB) => {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.max(1, Math.min(2048, parsed));
};

const clampConnectorWSReadLimitMb = (value) => {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return CONNECTOR_WS_READ_LIMIT_MIN_MB;
    return Math.max(CONNECTOR_WS_READ_LIMIT_MIN_MB, Math.min(CONNECTOR_WS_READ_LIMIT_MAX_MB, parsed));
};

const deriveConnectorWSReadLimitMb = (uploadMaxMb, uploadEnabled = true) => {
    if (!uploadEnabled) return clampConnectorWSReadLimitMb(16);
    const normalizedUpload = parseUploadMaxMb(uploadMaxMb, CONNECTOR_WS_READ_LIMIT_DEFAULT_UPLOAD_MB);
    // WS payload is base64 + JSON envelope, so keep headroom above raw upload limit.
    const estimatedLimit = Math.ceil((normalizedUpload * 4) / 3) + 16;
    return clampConnectorWSReadLimitMb(estimatedLimit);
};

async function getConnectorWSReadLimitMbFromSettings() {
    if (!Settings || typeof Settings.findAll !== 'function') {
        return deriveConnectorWSReadLimitMb(CONNECTOR_WS_READ_LIMIT_DEFAULT_UPLOAD_MB, true);
    }
    const rows = await Settings.findAll({
        where: { key: ['featureWebUploadEnabled', 'featureWebUploadMaxMb'] },
        attributes: ['key', 'value']
    });
    const map = {};
    rows.forEach((row) => {
        map[row.key] = row.value;
    });
    return deriveConnectorWSReadLimitMb(
        parseUploadMaxMb(map.featureWebUploadMaxMb, CONNECTOR_WS_READ_LIMIT_DEFAULT_UPLOAD_MB),
        parseUploadToggle(map.featureWebUploadEnabled, true)
    );
}

function pushConnectorWSReadLimitToSocket(ws, connectorId, limitMb, source = 'panel') {
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    try {
        ws.send(JSON.stringify({
            type: 'connector_set_ws_read_limit',
            limitMb: clampConnectorWSReadLimitMb(limitMb),
            source
        }));
        if (Number.isInteger(Number(connectorId))) {
            console.log(`Pushed connector WS read limit to connector ${connectorId}: ${clampConnectorWSReadLimitMb(limitMb)} MB`);
        }
        return true;
    } catch (error) {
        console.warn(`Failed to push WS read limit to connector ${connectorId || 'unknown'}:`, error.message || error);
        return false;
    }
}

async function getCrashPolicySettings() {
    const now = Date.now();
    if (crashPolicyCache.config && now - crashPolicyCache.ts < CRASH_POLICY_CACHE_TTL_MS) {
        return crashPolicyCache.config;
    }
    const defaults = {
        enabled: true,
        detectCleanExitAsCrash: true,
        cooldownSeconds: 60
    };
    if (!Settings || typeof Settings.findAll !== 'function') {
        crashPolicyCache = { ts: now, config: defaults };
        return defaults;
    }
    const rows = await Settings.findAll({
        where: { key: CRASH_POLICY_SETTING_KEYS },
        attributes: ['key', 'value']
    });
    const map = {};
    rows.forEach((row) => {
        map[row.key] = row.value;
    });
    const config = {
        enabled: parseCrashBool(map.crashDetectionEnabled, defaults.enabled),
        detectCleanExitAsCrash: parseCrashBool(map.crashDetectCleanExitAsCrash, defaults.detectCleanExitAsCrash),
        cooldownSeconds: parseCrashNumber(map.crashDetectionCooldownSeconds, defaults.cooldownSeconds, 0, 3600)
    };
    crashPolicyCache = { ts: now, config };
    return config;
}
const ANTI_MINER_STRONG_PATTERNS = [
    /\b(?:xmrig|xmr-stak|cpuminer|minerd|nanominer|teamredminer|ethminer|nbminer|gminer|srbminer|wildrig)\b/i,
    /\b(?:stratum\+tcp|stratum2\+tcp)\b/i,
    /\b(?:cryptonight|randomx)\b/i
];
const ANTI_MINER_MEDIUM_PATTERNS = [
    /\b(?:minexmr|supportxmr|moneroocean|herominers|hashvault|2miners|f2pool|nicehash|nanopool)\b/i,
    /\b(?:coinhive|minergate)\b/i,
    /--donate-level\b/i
];
const ANTI_MINER_WEAK_PATTERNS = [
    /\b(?:wallet|payout)\b/i,
    /\b(?:monero|xmr|bitcoin|btc|ethereum|eth)\b/i
];

const webhooksConfigCache = {
    ts: 0,
    config: null,
    moduleEnabled: false,
    brandName: 'CPanel'
};
const auditStrictCache = {
    ts: 0,
    enabled: false
};
const serverMinecraftEligibilityCache = new Map(); // serverId -> boolean
const connectorServerOwnershipCache = new Map(); // serverId -> { connectorId: number|null, ts: number }
const CONNECTOR_SERVER_OWNERSHIP_CACHE_TTL_MS = Math.max(
    5000,
    Number.parseInt(process.env.CONNECTOR_SERVER_SCOPE_CACHE_TTL_MS || '15000', 10) || 15000
);
const CONNECTOR_HEARTBEAT_STALE_MS = Math.max(
    15000,
    Number.parseInt(process.env.CONNECTOR_HEARTBEAT_STALE_MS || '45000', 10) || 45000
);
const CONNECTOR_HEARTBEAT_SWEEP_MS = Math.max(
    5000,
    Number.parseInt(process.env.CONNECTOR_HEARTBEAT_SWEEP_MS || '15000', 10) || 15000
);
const CONNECTOR_SERVER_SCOPED_MESSAGE_TYPES = new Set([
    'install_success',
    'install_fail',
    'console_output',
    'server_status_update',
    'server_debug_event',
    'server_action_ack',
    'eula_status',
    'server_stats',
    'file_list',
    'file_content',
    'write_success',
    'extract_started',
    'extract_complete',
    'file_versions',
    'file_version_content',
    'resource_limits_result',
    'log_cleanup_result',
    'sftp_import_progress',
    'sftp_import_result',
    'error',
    'delete_success',
    'delete_fail'
]);
const MINECRAFT_DETECTION_KEYWORDS = [
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

function parseBoolean(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function clampInteger(value, fallback, min, max) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
}

function parseCpuPercentValue(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    const normalized = String(value === undefined || value === null ? '' : value).replace('%', '').trim();
    const parsed = Number.parseFloat(normalized);
    return Number.isFinite(parsed) ? parsed : 0;
}

function detectMinerSignalsInText(textValue) {
    const text = String(textValue || '');
    if (!text.trim()) {
        return { score: 0, evidence: [], hasSignature: false };
    }

    const evidence = [];
    let score = 0;

    for (const pattern of ANTI_MINER_STRONG_PATTERNS) {
        if (pattern.test(text)) {
            evidence.push(`strong:${pattern.source}`);
            score += 5;
        }
    }
    for (const pattern of ANTI_MINER_MEDIUM_PATTERNS) {
        if (pattern.test(text)) {
            evidence.push(`medium:${pattern.source}`);
            score += 3;
        }
    }
    for (const pattern of ANTI_MINER_WEAK_PATTERNS) {
        if (pattern.test(text)) {
            evidence.push(`weak:${pattern.source}`);
            score += 1;
        }
    }

    return {
        score,
        evidence: Array.from(new Set(evidence)).slice(0, 12),
        hasSignature: evidence.some((entry) => entry.startsWith('strong:') || entry.startsWith('medium:'))
    };
}

function getOrCreateAntiMinerState(serverId) {
    const now = Date.now();
    const existing = ANTI_MINER_STATE.get(serverId);
    if (existing) return existing;

    const state = {
        score: 0,
        evidence: [],
        hasSignature: false,
        highCpuHits: 0,
        lastHitAtMs: now,
        lastSuspendAtMs: 0,
        startupCheckedAtMs: 0
    };
    ANTI_MINER_STATE.set(serverId, state);
    return state;
}

function applyAntiMinerScoreDecay(state, decayMinutes) {
    if (!state || !Number.isFinite(state.lastHitAtMs) || decayMinutes <= 0) return;
    const now = Date.now();
    const elapsedMs = Math.max(0, now - state.lastHitAtMs);
    const decayStepMs = decayMinutes * 60 * 1000;
    if (decayStepMs <= 0) return;
    const decayPoints = Math.floor(elapsedMs / decayStepMs);
    if (decayPoints <= 0) return;
    state.score = Math.max(0, state.score - decayPoints);
    state.lastHitAtMs = now;
}

async function getAntiMinerGuardConfig(forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh && ANTI_MINER_CONFIG_CACHE.config && (now - ANTI_MINER_CONFIG_CACHE.ts) <= ANTI_MINER_CONFIG_CACHE_TTL_MS) {
        return ANTI_MINER_CONFIG_CACHE.config;
    }

    const defaults = {
        enabled: false,
        suspendScore: 10,
        highCpuPercent: 95,
        highCpuSamples: 8,
        decayMinutes: 20,
        cooldownSeconds: 600
    };

    if (!Settings || typeof Settings.findAll !== 'function') {
        ANTI_MINER_CONFIG_CACHE.ts = now;
        ANTI_MINER_CONFIG_CACHE.config = defaults;
        return defaults;
    }

    const rows = await Settings.findAll({
        where: { key: ANTI_MINER_CONFIG_SETTING_KEYS },
        attributes: ['key', 'value']
    }).catch(() => []);

    const map = {};
    if (Array.isArray(rows)) {
        rows.forEach((row) => {
            map[row.key] = row.value;
        });
    }

    const config = {
        enabled: parseBoolean(map.featureAntiMinerEnabled),
        suspendScore: clampInteger(map.antiMinerSuspendScore, defaults.suspendScore, 5, 100),
        highCpuPercent: clampInteger(map.antiMinerHighCpuPercent, defaults.highCpuPercent, 70, 100),
        highCpuSamples: clampInteger(map.antiMinerHighCpuSamples, defaults.highCpuSamples, 3, 120),
        decayMinutes: clampInteger(map.antiMinerDecayMinutes, defaults.decayMinutes, 1, 720),
        cooldownSeconds: clampInteger(map.antiMinerCooldownSeconds, defaults.cooldownSeconds, 30, 86400)
    };

    ANTI_MINER_CONFIG_CACHE.ts = now;
    ANTI_MINER_CONFIG_CACHE.config = config;
    return config;
}

function isServerLikelyMinecraft(serverLike) {
    if (!serverLike || typeof serverLike !== 'object') return false;
    const image = serverLike.image && typeof serverLike.image === 'object' ? serverLike.image : {};
    const candidates = [
        image.name,
        image.description,
        image.startup,
        image.dockerImage,
        serverLike.dockerImage
    ];
    const haystack = String(candidates.filter(Boolean).join(' ')).toLowerCase();
    if (!haystack) return false;
    return MINECRAFT_DETECTION_KEYWORDS.some((keyword) => haystack.includes(keyword));
}

async function canHandleMinecraftEula(serverOrId) {
    if (serverOrId && typeof serverOrId === 'object') {
        const id = Number.parseInt(serverOrId.id, 10);
        const value = isServerLikelyMinecraft(serverOrId);
        if (Number.isInteger(id) && id > 0) {
            serverMinecraftEligibilityCache.set(id, value);
        }
        return value;
    }

    const serverId = Number.parseInt(serverOrId, 10);
    if (!Number.isInteger(serverId) || serverId <= 0) return false;
    if (serverMinecraftEligibilityCache.has(serverId)) {
        return Boolean(serverMinecraftEligibilityCache.get(serverId));
    }

    try {
        const serverRecord = await Server.findByPk(serverId, {
            attributes: ['id', 'dockerImage'],
            include: [{ model: Image, as: 'image', attributes: ['name', 'description', 'startup', 'dockerImage'], required: false }]
        });
        const value = isServerLikelyMinecraft(serverRecord);
        serverMinecraftEligibilityCache.set(serverId, value);
        return value;
    } catch {
        return false;
    }
}

function parseServerIdFromConnectorPayload(data) {
    const parsed = Number.parseInt(data && data.serverId, 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

async function getServerConnectorOwnerCached(serverId) {
    const nowMs = Date.now();
    const cached = connectorServerOwnershipCache.get(serverId);
    if (cached && Number.isFinite(cached.ts) && (nowMs - cached.ts) < CONNECTOR_SERVER_OWNERSHIP_CACHE_TTL_MS) {
        return cached.connectorId;
    }

    const serverRecord = await Server.findByPk(serverId, {
        attributes: ['id'],
        include: [{ model: Allocation, as: 'allocation', attributes: ['connectorId'], required: false }]
    }).catch(() => null);

    let connectorId = null;
    if (serverRecord && serverRecord.allocation) {
        const parsed = Number.parseInt(serverRecord.allocation.connectorId, 10);
        if (Number.isInteger(parsed) && parsed > 0) {
            connectorId = parsed;
        }
    }

    connectorServerOwnershipCache.set(serverId, { connectorId, ts: nowMs });
    if (connectorServerOwnershipCache.size > 5000) {
        const firstKey = connectorServerOwnershipCache.keys().next();
        if (!firstKey.done) connectorServerOwnershipCache.delete(firstKey.value);
    }

    return connectorId;
}

async function validateConnectorServerScope(connectorId, data) {
    const type = String((data && data.type) || '').trim().toLowerCase();
    if (!type || !CONNECTOR_SERVER_SCOPED_MESSAGE_TYPES.has(type)) {
        return { ok: true, serverId: null };
    }

    const serverId = parseServerIdFromConnectorPayload(data);
    if (!serverId) {
        return { ok: false, reason: 'missing_server_id', serverId: null, type };
    }

    const ownerConnectorId = await getServerConnectorOwnerCached(serverId);
    if (!Number.isInteger(ownerConnectorId) || ownerConnectorId <= 0) {
        return { ok: false, reason: 'server_not_bound', serverId, type };
    }

    if (Number.parseInt(connectorId, 10) !== ownerConnectorId) {
        return { ok: false, reason: 'connector_mismatch', serverId, type, ownerConnectorId };
    }

    return { ok: true, serverId, type };
}

function parseConnectorId(rawId) {
    const parsed = Number.parseInt(rawId, 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function markConnectorOffline(connectorId, reason = 'stale_heartbeat') {
    if (!global.connectorStatus) global.connectorStatus = {};
    const current = global.connectorStatus[connectorId] || {};
    const wasOnline = String(current.status || '').toLowerCase() === 'online';

    global.connectorStatus[connectorId] = {
        ...current,
        status: 'offline',
        lastSeen: current.lastSeen || new Date(),
        usage: current.usage || null
    };

    if (wasOnline) {
        broadcastToUI({
            type: 'status_update',
            connectorId,
            status: 'offline',
            reason,
            lastSeen: global.connectorStatus[connectorId].lastSeen
        });
    }
}

function sweepStaleConnectorHeartbeats() {
    if (!global.connectorStatus || typeof global.connectorStatus !== 'object') return;

    const nowMs = Date.now();
    const entries = Object.entries(global.connectorStatus);
    for (const [rawConnectorId, statusData] of entries) {
        const connectorId = parseConnectorId(rawConnectorId);
        if (!connectorId) continue;

        const status = String((statusData && statusData.status) || '').toLowerCase();
        const lastSeenMs = new Date(statusData && statusData.lastSeen ? statusData.lastSeen : 0).getTime();
        if (!Number.isFinite(lastSeenMs) || lastSeenMs <= 0) continue;

        const stale = (nowMs - lastSeenMs) > CONNECTOR_HEARTBEAT_STALE_MS;
        if (!stale || status !== 'online') continue;

        markConnectorOffline(connectorId, 'heartbeat_timeout');

        const socket = connectorConnections.get(connectorId);
        if (socket && socket.readyState === WebSocket.OPEN) {
            try {
                socket.close(4000, 'Heartbeat timeout');
            } catch (error) {
                console.warn(`Failed closing stale connector socket ${connectorId}:`, error.message);
            }
        }
        connectorConnections.delete(connectorId);
    }
}

function normalizeWebhooksRuntimeConfig(raw) {
    let parsed = {};
    try {
        parsed = typeof raw === 'string' ? JSON.parse(raw) : (raw || {});
    } catch {
        parsed = {};
    }
    const events = parsed && typeof parsed.events === 'object' ? parsed.events : {};
    const eventEnabledOrDefault = (key) => {
        if (events[key] === undefined || events[key] === null) return true;
        return parseBoolean(events[key]);
    };
    return {
        enabled: parseBoolean(parsed.enabled),
        discordWebhook: String(parsed.discordWebhook || '').trim(),
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
}

function normalizePermissionList(value) {
    if (!Array.isArray(value)) return [];
    return Array.from(new Set(value.map((entry) => String(entry || '').trim()).filter(Boolean)));
}

function rejectUpgrade(socket, statusCode, statusText) {
    socket.write(`HTTP/1.1 ${statusCode} ${statusText}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
}

async function authorizeConsoleUpgrade(request, pathname) {
    const parts = pathname.split('/');
    const containerId = parts[3];

    if (!containerId) {
        return { ok: false, code: 400, text: 'Bad Request' };
    }

    const requestUrl = new URL(request.url, `http://${request.headers.host}`);
    const token = requestUrl.searchParams.get('token');
    if (!token) {
        return { ok: false, code: 401, text: 'Unauthorized' };
    }

    let payload;
    try {
        payload = jwt.verify(token, SECRET_KEY);
    } catch (error) {
        return { ok: false, code: 401, text: 'Unauthorized' };
    }

    const tokenServerId = Number.parseInt(payload.serverId, 10);
    const tokenUserId = Number.parseInt(payload.userId, 10);
    const tokenIsAdmin = payload.isAdmin === true;

    if (!Number.isInteger(tokenServerId) || !Number.isInteger(tokenUserId)) {
        return { ok: false, code: 401, text: 'Unauthorized' };
    }

    const serverRecord = await Server.findOne({
        where: { containerId: containerId },
        attributes: ['id', 'ownerId']
    });

    if (!serverRecord) {
        return { ok: false, code: 404, text: 'Not Found' };
    }

    // Compare token serverId with actual server record id
    if (tokenServerId !== serverRecord.id) {
        return { ok: false, code: 401, text: 'Unauthorized' };
    }

    if (tokenIsAdmin || serverRecord.ownerId === tokenUserId) {
        return { ok: true };
    }

    const subuser = await ServerSubuser.findOne({
        where: {
            serverId: serverRecord.id,
            userId: tokenUserId
        },
        attributes: ['permissions']
    });
    if (!subuser) {
        return { ok: false, code: 401, text: 'Unauthorized' };
    }

    const permissions = new Set(normalizePermissionList(subuser.permissions));
    if (!permissions.has('server.console')) {
        return { ok: false, code: 403, text: 'Forbidden' };
    }

    return { ok: true };
}

server.on('upgrade', (request, socket, head) => {
    const requestUrl = new URL(request.url, `http://${request.headers.host}`);
    const pathname = requestUrl.pathname;

    if (pathname.startsWith('/ws/server/')) {
        (async () => {
            try {
                const authResult = await authorizeConsoleUpgrade(request, pathname);
                if (!authResult.ok) {
                    rejectUpgrade(socket, authResult.code, authResult.text);
                    return;
                }

                wss.handleUpgrade(request, socket, head, (ws) => {
                    wss.emit('connection', ws, request);
                });
            } catch (error) {
                console.error('Failed to authorize console websocket upgrade:', error);
                rejectUpgrade(socket, 500, 'Internal Server Error');
            }
        })();
        return;
    }

    if (pathname === '/ws/connector' || pathname === '/ws/ui') {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else {
        socket.destroy();
    }
});

function broadcastToUI(data) {
    const message = JSON.stringify(data);
    uiClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// Function to send messages to specific server console clients
function sendToServerConsole(serverId, data) {
    const clients = serverConsoleClients.get(serverId);
    if (clients) {
        const message = JSON.stringify(data);
        clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    }
}

function shouldForwardConsoleOutput(serverId, output) {
    if (typeof output !== 'string') {
        return true;
    }

    const now = Date.now();
    const previous = recentConsolePayloads.get(serverId);
    if (previous && previous.output === output && (now - previous.ts) <= 200) {
        return false;
    }

    recentConsolePayloads.set(serverId, { output, ts: now });
    return true;
}

function appendToServerConsoleBuffer(serverId, output) {
    if (typeof output !== 'string' || !output) return;

    const buffer = serverConsoleBuffers.get(serverId) || { lines: [], bytes: 0 };
    const lines = output.split('\n');

    lines.forEach((line, index) => {
        const isLastLine = index === lines.length - 1;
        const entry = isLastLine ? line : `${line}\n`;
        if (!entry) return;

        const entryBytes = Buffer.byteLength(entry, 'utf8');
        buffer.lines.push(entry);
        buffer.bytes += entryBytes;
    });

    while (buffer.lines.length > SERVER_CONSOLE_BUFFER_MAX_LINES || buffer.bytes > SERVER_CONSOLE_BUFFER_MAX_BYTES) {
        const removed = buffer.lines.shift();
        if (!removed) break;
        buffer.bytes -= Buffer.byteLength(removed, 'utf8');
    }

    serverConsoleBuffers.set(serverId, buffer);
}

function getServerConsoleBuffer(serverId) {
    const buffer = serverConsoleBuffers.get(serverId);
    if (!buffer || buffer.lines.length === 0) return '';
    return buffer.lines.join('');
}

function getServerConsoleTailForDebug(serverId) {
    const full = getServerConsoleBuffer(serverId);
    if (!full) return '';
    if (full.length <= SERVER_DEBUG_LOG_TAIL_MAX_CHARS) return full;
    const droppedChars = full.length - SERVER_DEBUG_LOG_TAIL_MAX_CHARS;
    return `[... truncated ${droppedChars} chars ...]\n${full.slice(-SERVER_DEBUG_LOG_TAIL_MAX_CHARS)}`;
}

function clearServerConsoleBuffer(serverId) {
    serverConsoleBuffers.delete(serverId);
    recentConsolePayloads.delete(serverId);
    RESOURCE_ANOMALY_STATE.delete(serverId);
    RESOURCE_ANOMALY_SAMPLE_TS.delete(serverId);
    PLUGIN_CONFLICT_STATE.delete(serverId);
    ANTI_MINER_STATE.delete(serverId);
    RESOURCE_TIMELINE_LAST_WRITE_TS.delete(serverId);
}

async function getAuditStrictState(forceRefresh = false) {
    if (!Settings) return { enabled: false };
    const now = Date.now();
    if (!forceRefresh && (now - auditStrictCache.ts) < 15_000) {
        return { enabled: Boolean(auditStrictCache.enabled) };
    }
    try {
        const row = await Settings.findByPk('featureStrictAuditEnabled');
        const enabled = ['1', 'true', 'yes', 'on'].includes(String(row && row.value || '').trim().toLowerCase());
        auditStrictCache.ts = now;
        auditStrictCache.enabled = enabled;
        return { enabled };
    } catch {
        return { enabled: false };
    }
}

async function writeServerAuditLog(payload) {
    try {
        if (!AuditLog) return;
        await AuditLog.create({
            actorUserId: payload.actorUserId || null,
            action: String(payload.action || '').slice(0, 120) || 'server:event',
            targetType: 'server',
            targetId: payload.serverId ? String(payload.serverId) : null,
            method: null,
            path: null,
            ip: payload.ip || null,
            userAgent: payload.userAgent || null,
            metadata: payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {}
        });
    } catch (error) {
        const strictState = await getAuditStrictState();
        if (strictState.enabled) {
            throw error;
        }
        // Ignore audit write errors when strict audit is disabled.
    }
}

async function getWebhooksRuntimeState(forceRefresh = false) {
    if (!Settings) {
        return {
            moduleEnabled: false,
            brandName: 'CPanel',
            config: normalizeWebhooksRuntimeConfig({})
        };
    }

    const now = Date.now();
    if (!forceRefresh && webhooksConfigCache.config && (now - webhooksConfigCache.ts) < 15_000) {
        return {
            moduleEnabled: webhooksConfigCache.moduleEnabled,
            brandName: webhooksConfigCache.brandName,
            config: webhooksConfigCache.config
        };
    }

    const [moduleEnabledRow, cfgRow, brandNameRow] = await Promise.all([
        Settings.findByPk('featureExtensionWebhooksEnabled'),
        Settings.findByPk(WEBHOOKS_SETTING_KEY),
        Settings.findByPk('brandName')
    ]);

    const moduleEnabled = parseBoolean(moduleEnabledRow && moduleEnabledRow.value);
    const brandName = String(brandNameRow && brandNameRow.value || 'CPanel').trim() || 'CPanel';
    const config = normalizeWebhooksRuntimeConfig(cfgRow && cfgRow.value ? cfgRow.value : '{}');

    webhooksConfigCache.ts = now;
    webhooksConfigCache.moduleEnabled = moduleEnabled;
    webhooksConfigCache.brandName = brandName;
    webhooksConfigCache.config = config;

    return { moduleEnabled, brandName, config };
}

async function emitRuntimeWebhookEvent(eventKey, title, description, colorHex = '#3b82f6') {
    try {
        const state = await getWebhooksRuntimeState();
        if (!state.moduleEnabled || !state.config.enabled) return;
        if (!state.config.events || state.config.events[eventKey] !== true) return;

        if (state.config.discordWebhook && typeof sendDiscordSmartAlert === 'function') {
            await sendDiscordSmartAlert(state.config.discordWebhook, title, description, colorHex);
        }
        if (state.config.telegramBotToken && state.config.telegramChatId && typeof sendTelegramSmartAlert === 'function') {
            await sendTelegramSmartAlert(state.config.telegramBotToken, state.config.telegramChatId, `${title}\n${description}`);
        }
    } catch (error) {
        console.warn(`Runtime webhook event ${eventKey} failed:`, error.message);
    }
}

async function createRuntimeIncident({
    title,
    message,
    severity = 'warning',
    source = 'runtime',
    serverId = null,
    connectorId = null,
    action = '',
    metadata = {}
}) {
    if (!Settings) return null;

    const record = await appendIncidentCenterRecord(Settings, {
        title,
        message,
        severity,
        source,
        serverId,
        connectorId,
        action,
        metadata,
        status: 'open'
    }).catch(() => null);

    if (record) {
        const state = await getWebhooksRuntimeState();
        const titlePrefix = `[${state.brandName}] Runtime Incident`;
        await emitRuntimeWebhookEvent(
            'runtimeIncidentCreated',
            titlePrefix,
            `${record.title}${record.message ? `\n${record.message}` : ''}`,
            severity === 'critical' ? '#ef4444' : severity === 'warning' ? '#f59e0b' : '#10b981'
        );
    }

    return record;
}

async function getServerStartupSnapshotForAntiMiner(serverId) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) return '';

    const serverRecord = await Server.findByPk(parsedServerId, {
        attributes: ['id', 'name', 'dockerImage', 'variables'],
        include: [
            { model: Image, as: 'image', attributes: ['name', 'description', 'startup', 'dockerImage'], required: false }
        ]
    }).catch(() => null);
    if (!serverRecord) return '';

    const variables = serverRecord.variables && typeof serverRecord.variables === 'object'
        ? serverRecord.variables
        : {};
    return [
        serverRecord.name,
        serverRecord.dockerImage,
        variables.STARTUP,
        variables.startup,
        variables.start_command,
        serverRecord.image ? serverRecord.image.name : '',
        serverRecord.image ? serverRecord.image.description : '',
        serverRecord.image ? serverRecord.image.startup : '',
        serverRecord.image ? serverRecord.image.dockerImage : ''
    ].filter(Boolean).join('\n');
}

async function suspendServerForAntiMinerDetection(serverId, detectionState, triggerMetadata = {}) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) return;

    const serverRecord = await Server.findByPk(parsedServerId, {
        attributes: ['id', 'name', 'status', 'isSuspended', 'suspendReason'],
        include: [{ model: Allocation, as: 'allocation', attributes: ['connectorId'], required: false }]
    }).catch(() => null);
    if (!serverRecord) return;
    if (serverRecord.isSuspended) return;

    const reasonSummary = Array.isArray(detectionState && detectionState.evidence)
        ? detectionState.evidence.slice(0, 6).join(', ')
        : 'multiple miner indicators';
    const suspendReason = `Anti-miner detection triggered (score ${Number(detectionState && detectionState.score || 0)}): ${reasonSummary}`.slice(0, 900);

    await serverRecord.update({
        isSuspended: true,
        status: 'suspended',
        suspendReason
    });

    const requestId = `antiminer_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
    const connectorId = serverRecord.allocation ? Number.parseInt(serverRecord.allocation.connectorId, 10) : 0;
    if (Number.isInteger(connectorId) && connectorId > 0) {
        const connectorWs = connectorConnections.get(connectorId);
        if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
            rememberServerPowerIntent(parsedServerId, 'kill');
            connectorWs.send(JSON.stringify({
                type: 'server_power',
                serverId: parsedServerId,
                action: 'kill',
                stopCommand: null,
                requestId
            }));
        }
    }

    sendToServerConsole(parsedServerId, {
        type: 'server_status_update',
        status: 'suspended'
    });
    sendToServerConsole(parsedServerId, {
        type: 'console_output',
        output: `[!] Anti-miner guard suspended this server automatically. Reason: ${reasonSummary}\n`
    });

    await writeServerAuditLog({
        serverId: parsedServerId,
        action: 'server:security.anti_miner_suspend',
        metadata: {
            score: Number(detectionState && detectionState.score || 0),
            evidence: Array.isArray(detectionState && detectionState.evidence) ? detectionState.evidence : [],
            trigger: triggerMetadata,
            suspendReason,
            capturedAt: new Date().toISOString(),
            logTail: getServerConsoleTailForDebug(parsedServerId) || null
        }
    });

    await createRuntimeIncident({
        title: `Anti-miner suspension: ${serverRecord.name}`,
        message: `Server #${serverRecord.id} was suspended automatically after miner indicators exceeded threshold.`,
        severity: 'critical',
        source: 'security',
        serverId: parsedServerId,
        connectorId: Number.isInteger(connectorId) && connectorId > 0 ? connectorId : null,
        action: 'security.anti_miner.suspend',
        metadata: {
            score: Number(detectionState && detectionState.score || 0),
            evidence: Array.isArray(detectionState && detectionState.evidence) ? detectionState.evidence : [],
            trigger: triggerMetadata
        }
    });
}

async function evaluateAntiMinerGuardScore(serverId, signal, triggerMetadata = {}) {
    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) return;

    const config = await getAntiMinerGuardConfig();
    if (!config.enabled) return;
    if (!signal || Number(signal.score || 0) <= 0) return;

    const state = getOrCreateAntiMinerState(parsedServerId);
    applyAntiMinerScoreDecay(state, config.decayMinutes);

    const now = Date.now();
    state.score = Math.max(0, Number(state.score || 0) + Number(signal.score || 0));
    state.lastHitAtMs = now;
    state.hasSignature = Boolean(state.hasSignature || signal.hasSignature);
    if (Array.isArray(signal.evidence) && signal.evidence.length) {
        state.evidence = Array.from(new Set([...(state.evidence || []), ...signal.evidence])).slice(0, 16);
    }
    ANTI_MINER_STATE.set(parsedServerId, state);

    const cooldownMs = Math.max(30, Number(config.cooldownSeconds || 600)) * 1000;
    const inCooldown = Number.isFinite(state.lastSuspendAtMs) && state.lastSuspendAtMs > 0 && (now - state.lastSuspendAtMs) < cooldownMs;
    if (inCooldown) return;

    if (state.score >= Number(config.suspendScore || 10) && state.hasSignature) {
        state.lastSuspendAtMs = now;
        ANTI_MINER_STATE.set(parsedServerId, state);
        await suspendServerForAntiMinerDetection(parsedServerId, state, triggerMetadata);
    }
}

function parseResourceNumber(value, fallback = 0) {
    const parsed = Number.parseFloat(value);
    if (!Number.isFinite(parsed)) return fallback;
    return parsed;
}

async function persistResourceTimelineSample(serverId, cpu, memory, disk) {
    try {
        if (!ServerResourceSample || !Number.isInteger(Number.parseInt(serverId, 10))) return;
        const parsedServerId = Number.parseInt(serverId, 10);
        if (parsedServerId <= 0) return;

        const now = Date.now();
        const lastWrite = RESOURCE_TIMELINE_LAST_WRITE_TS.get(parsedServerId) || 0;
        if (now - lastWrite < RESOURCE_TIMELINE_WRITE_INTERVAL_MS) return;
        RESOURCE_TIMELINE_LAST_WRITE_TS.set(parsedServerId, now);

        await ServerResourceSample.create({
            serverId: parsedServerId,
            cpuPercent: Math.max(0, Math.min(1000, parseResourceNumber(cpu, 0))),
            memoryMb: Math.max(0, Math.round(parseResourceNumber(memory, 0))),
            diskMb: Math.max(0, Math.round(parseResourceNumber(disk, 0))),
            collectedAt: new Date(now)
        });

        if (now - resourceTimelineLastCleanupTs > 15 * 60 * 1000) {
            resourceTimelineLastCleanupTs = now;
            const threshold = new Date(now - RESOURCE_TIMELINE_RETENTION_MS);
            await ServerResourceSample.destroy({
                where: { collectedAt: { [Op.lt]: threshold } }
            }).catch(() => {});
        }
    } catch {
        // Ignore timeline persistence failures.
    }
}

async function handleAntiMinerFromConsoleOutput(serverId, output) {
    const signal = detectMinerSignalsInText(output);
    if (signal.score <= 0) return;
    await evaluateAntiMinerGuardScore(serverId, signal, {
        source: 'console_output'
    });
}

async function handleAntiMinerFromStats(serverId, cpu) {
    const config = await getAntiMinerGuardConfig();
    if (!config.enabled) return;

    const parsedServerId = Number.parseInt(serverId, 10);
    if (!Number.isInteger(parsedServerId) || parsedServerId <= 0) return;

    const cpuValue = parseCpuPercentValue(cpu);
    const state = getOrCreateAntiMinerState(parsedServerId);
    applyAntiMinerScoreDecay(state, config.decayMinutes);

    if (cpuValue >= Number(config.highCpuPercent || 95)) {
        state.highCpuHits = Number(state.highCpuHits || 0) + 1;
    } else {
        state.highCpuHits = Math.max(0, Number(state.highCpuHits || 0) - 1);
    }
    ANTI_MINER_STATE.set(parsedServerId, state);

    if (state.highCpuHits < Number(config.highCpuSamples || 8)) {
        return;
    }

    const now = Date.now();
    if (!state.startupCheckedAtMs || (now - state.startupCheckedAtMs) > (5 * 60 * 1000)) {
        const snapshot = await getServerStartupSnapshotForAntiMiner(parsedServerId);
        const startupSignal = detectMinerSignalsInText(snapshot);
        state.startupCheckedAtMs = now;
        if (startupSignal.score > 0) {
            state.hasSignature = Boolean(state.hasSignature || startupSignal.hasSignature);
            state.evidence = Array.from(new Set([...(state.evidence || []), ...startupSignal.evidence])).slice(0, 16);
        }
        ANTI_MINER_STATE.set(parsedServerId, state);
    }

    if (!state.hasSignature) {
        // High CPU alone is not enough to suspend, avoids false positives on legit workloads.
        return;
    }

    await evaluateAntiMinerGuardScore(parsedServerId, {
        score: 2,
        evidence: [`cpu:sustained>=${Number(config.highCpuPercent || 95)}%`],
        hasSignature: true
    }, {
        source: 'server_stats',
        cpu: cpuValue
    });
}

wss.on('connection', (ws, request) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    const pathname = url.pathname;

    if (pathname === '/ws/ui') {
        uiClients.add(ws);
        ws.on('close', () => uiClients.delete(ws));
        ws.send(JSON.stringify({ type: 'connected' }));
        return;
    }

    let connectorId = null;
    let authenticated = false;
    let authenticatedToken = null;
    let serverId = null; // For server console connections

    // Handle server console connections
    if (pathname.startsWith('/ws/server/')) {
        const containerIdParam = pathname.split('/')[3]; // /ws/server/:containerId
        let consolePerms = new Set();
        let consoleUserId = null;
        let consoleUserAgent = String(request.headers['user-agent'] || '');
        let consoleIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress || null;

        try {
            const token = new URL(request.url, `http://${request.headers.host}`).searchParams.get('token');
            if (token) {
                const payload = jwt.verify(token, SECRET_KEY);
                const parsedUserId = Number.parseInt(payload.userId, 10);
                if (Number.isInteger(parsedUserId) && parsedUserId > 0) {
                    consoleUserId = parsedUserId;
                }
                const rawPerms = normalizePermissionList(payload.serverPerms);
                if (payload && payload.isAdmin === true) {
                    rawPerms.push('*');
                }
                consolePerms = new Set(rawPerms);
            }
        } catch {
            // Ignore malformed token payload here; upgrade auth already handles validity.
        }

        const hasConsolePermission = (permission) => {
            if (consolePerms.has('*')) return true;
            return consolePerms.has(permission);
        };

        (async () => {
            const server = await Server.findOne({ where: { containerId: containerIdParam } });
            if (!server) {
                ws.close(1008, 'Server not found');
                return;
            }

            serverId = server.id;
            const isFirstConsoleClient = !serverConsoleClients.has(serverId);

            if (isFirstConsoleClient) {
                serverConsoleClients.set(serverId, new Set());
            }
            serverConsoleClients.get(serverId).add(ws);

            // Always initialize each client with current status + buffered console.
            setTimeout(async () => {
                const serverObj = await Server.findByPk(serverId, {
                    include: [
                        { model: Allocation, as: 'allocation' },
                        { model: Image, as: 'image', required: false }
                    ]
                });
                if (!serverObj || !serverObj.allocation || ws.readyState !== WebSocket.OPEN) {
                    return;
                }
                const supportsMinecraftEula = await canHandleMinecraftEula(serverObj);

                const connectorWs = connectorConnections.get(serverObj.allocation.connectorId);
                const isOnline = connectorWs && connectorWs.readyState === WebSocket.OPEN;

                ws.send(JSON.stringify({
                    type: 'connector_status',
                    online: isOnline
                }));

                ws.send(JSON.stringify({
                    type: 'server_status_update',
                    status: serverObj.status
                }));

                const normalizedStatus = String(serverObj.status || '').toLowerCase();
                if (normalizedStatus !== 'stopped') {
                    const bufferedOutput = getServerConsoleBuffer(serverId);
                    if (bufferedOutput) {
                        ws.send(JSON.stringify({
                            type: 'console_output',
                            output: bufferedOutput
                        }));
                    }
                }

                if (isOnline) {
                    // Keep status and EULA synced for every new browser session.
                    connectorWs.send(JSON.stringify({ type: 'check_server_status', serverId }));
                    if (supportsMinecraftEula) {
                        connectorWs.send(JSON.stringify({ type: 'check_eula', serverId }));
                    }

                    // Ensure log stream is attached when first browser client connects.
                    if (isFirstConsoleClient) {
                        connectorWs.send(JSON.stringify({ type: 'server_logs', serverId }));
                    }
                } else {
                    ws.send(JSON.stringify({
                        type: 'server_stats',
                        cpu: '0.0',
                        memory: '0',
                        disk: '0'
                    }));
                }
            }, 350);

            console.log(`UI client connected to server console for server ${serverId} (${containerIdParam})`);

            ws.on('close', () => {
                const clients = serverConsoleClients.get(serverId);
                if (clients) {
                    clients.delete(ws);
                    if (clients.size === 0) {
                        serverConsoleClients.delete(serverId);
                    }
                }
                console.log(`UI client disconnected from server console for server ${serverId}`);
            });

            // For server console, we need to handle messages from the UI client
            ws.on('message', async (message) => {
                try {
                    const data = JSON.parse(message);
                    const serverObj = await Server.findByPk(serverId, {
                        include: [
                            { model: Allocation, as: 'allocation' },
                            { model: Image, as: 'image' }
                        ]
                    });

                    if (!serverObj || !serverObj.allocation || !serverObj.allocation.connectorId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Server or connector not found.' }));
                        return;
                    }
                    const supportsMinecraftEula = await canHandleMinecraftEula(serverObj);

                    if (serverObj.isSuspended && (data.type === 'power_action' || data.type === 'console_input')) {
                        ws.send(JSON.stringify({ type: 'error', message: 'This server is suspended and cannot be controlled.' }));
                        return;
                    }

                    const connectorWs = connectorConnections.get(serverObj.allocation.connectorId);
                    if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Connector is offline.' }));
                        return;
                    }

                    if (data.type === 'console_input') {
                        if (!hasConsolePermission('server.console')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.console' }));
                            return;
                        }
                        await writeServerAuditLog({
                            actorUserId: consoleUserId,
                            serverId,
                            action: 'server:console.command',
                            ip: consoleIp,
                            userAgent: consoleUserAgent,
                            metadata: {
                                command: String(data.command || '').slice(0, 1024)
                            }
                        });
                        const requestId = `cmd_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
                        connectorWs.send(JSON.stringify({
                            type: 'server_command',
                            serverId: serverId,
                            command: data.command,
                            requestId
                        }));
                    } else if (data.type === 'power_action') {
                        if (!hasConsolePermission('server.power')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.power' }));
                            return;
                        }
                        await writeServerAuditLog({
                            actorUserId: consoleUserId,
                            serverId,
                            action: 'server:power.action',
                            ip: consoleIp,
                            userAgent: consoleUserAgent,
                            metadata: {
                                powerAction: String(data.action || '').toLowerCase()
                            }
                        });
                        const normalizedAction = String(data.action || '').toLowerCase();
                        if (normalizedAction === 'stop' || normalizedAction === 'kill' || normalizedAction === 'restart') {
                            rememberServerPowerIntent(serverId, normalizedAction);
                        }
                        if (normalizedAction === 'start') {
                            consumeServerPowerIntent(serverId);
                        }
                        const requestId = `pwr_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
                        connectorWs.send(JSON.stringify({
                            type: 'server_power',
                            serverId: serverId,
                            action: data.action,
                            stopCommand: serverObj.image && serverObj.image.eggConfig ? serverObj.image.eggConfig.stop : null,
                            requestId
                        }));
                    } else if (data.type === 'accept_eula') {
                        if (!hasConsolePermission('server.power')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.power' }));
                            return;
                        }
                        if (!supportsMinecraftEula) {
                            ws.send(JSON.stringify({ type: 'error', message: 'EULA is available only for Minecraft servers.' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'accept_eula',
                            serverId: serverId
                        }));
                    } else if (data.type === 'list_files') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'list_files',
                            serverId: serverId,
                            directory: data.directory,
                            requestId: data.requestId || null
                        }));
                    } else if (data.type === 'create_folder') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'create_folder',
                            serverId: serverId,
                            directory: data.directory,
                            name: data.name
                        }));
                    } else if (data.type === 'create_file') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'create_file',
                            serverId: serverId,
                            directory: data.directory,
                            name: data.name
                        }));
                    } else if (data.type === 'rename_file') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'rename_file',
                            serverId: serverId,
                            directory: data.directory,
                            name: data.name,
                            newName: data.newName
                        }));
                    } else if (data.type === 'delete_files') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'delete_files',
                            serverId: serverId,
                            directory: data.directory,
                            files: data.files
                        }));
                    } else if (data.type === 'set_permissions') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'set_permissions',
                            serverId: serverId,
                            directory: data.directory,
                            name: data.name,
                            permissions: data.permissions
                        }));
                    } else if (data.type === 'extract_archive') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'extract_archive',
                            serverId: serverId,
                            directory: data.directory,
                            name: data.name,
                            targetDirectory: data.targetDirectory
                        }));
                    } else if (data.type === 'read_file') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'read_file',
                            serverId: serverId,
                            filePath: data.filePath
                        }));
                    } else if (data.type === 'write_file') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'write_file',
                            serverId: serverId,
                            filePath: data.filePath,
                            content: data.content,
                            encoding: data.encoding,
                            contentBase64: data.contentBase64
                        }));
                    } else if (data.type === 'list_file_versions') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'list_file_versions',
                            serverId: serverId,
                            filePath: data.filePath
                        }));
                    } else if (data.type === 'read_file_version') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'read_file_version',
                            serverId: serverId,
                            filePath: data.filePath,
                            versionId: data.versionId
                        }));
                    } else if (data.type === 'run_log_cleanup') {
                        if (!hasConsolePermission('server.files')) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing permission: server.files' }));
                            return;
                        }
                        connectorWs.send(JSON.stringify({
                            type: 'log_cleanup',
                            serverId: serverId,
                            directory: data.directory,
                            maxFileSizeMB: data.maxFileSizeMB,
                            keepFiles: data.keepFiles,
                            maxAgeDays: data.maxAgeDays,
                            compressOld: data.compressOld
                        }));
                    }
                } catch (err) {
                    console.error(`Error handling server console message for server ${serverId}:`, err);
                    ws.send(JSON.stringify({ type: 'error', message: 'Failed to process command.' }));
                }
            });
        })();
        return; // Stop processing for server console connections
    }


    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            // Authentication for connectors
            if (data.type === 'auth') {
                const connector = await Connector.findOne({ where: { id: data.id, token: data.token } });
                if (connector) {
                    const requestOrigin = normalizeOriginCandidate(request.headers.origin || '');
                    if (requestOrigin) {
                        const panelOrigin = extractOriginFromUrl(resolvePanelBaseUrl(request));
                        const allowedOrigins = await getConnectorAllowedOrigins(connector.id, panelOrigin);
                        if (!allowedOrigins.includes(requestOrigin)) {
                            ws.send(JSON.stringify({ type: 'auth_fail', error: `Origin not allowed: ${requestOrigin}` }));
                            ws.close(4003, 'Connector origin not allowed');
                            return;
                        }
                    }

                    const existingSocket = connectorConnections.get(data.id);
                    if (existingSocket && existingSocket !== ws && existingSocket.readyState === WebSocket.OPEN) {
                        try {
                            existingSocket.close(4001, 'Superseded by a newer connector session');
                        } catch (closeError) {
                            console.warn(`Failed to close previous connector session for ${data.id}:`, closeError.message);
                        }
                    }

                    authenticated = true;
                    connectorId = data.id;
                    authenticatedToken = String(data.token || '');
                    connectorConnections.set(connectorId, ws);
                    if (!global.connectorStatus) global.connectorStatus = {};
                    global.connectorStatus[connectorId] = {
                        status: 'online',
                        lastSeen: new Date(),
                        usage: null
                    };
                    ws.send(JSON.stringify({ type: 'auth_success' }));
                    try {
                        const limitMb = await getConnectorWSReadLimitMbFromSettings();
                        pushConnectorWSReadLimitToSocket(ws, connectorId, limitMb, 'auth_sync');
                    } catch (limitError) {
                        console.warn(`Failed to sync WS read limit for connector ${connectorId}:`, limitError.message || limitError);
                    }
                    console.log(`Connector ${connectorId} authenticated via WebSocket`);
                } else {
                    ws.send(JSON.stringify({ type: 'auth_fail', error: 'Invalid token' }));
                    ws.close();
                }
                return;
            }

            if (!authenticated) {
                ws.send(JSON.stringify({ type: 'error', error: 'Not authenticated' }));
                return;
            }

            // Ignore messages from stale connector sockets after a reconnect/re-auth race.
            if (connectorId && connectorConnections.get(connectorId) !== ws) {
                return;
            }

            const scopeValidation = await validateConnectorServerScope(connectorId, data);
            if (!scopeValidation.ok) {
                console.warn(`[WS] Connector ${connectorId} blocked from message type=${scopeValidation.type || 'unknown'} serverId=${scopeValidation.serverId || 'n/a'} reason=${scopeValidation.reason}`);
                if (scopeValidation.reason === 'connector_mismatch' && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        serverId: scopeValidation.serverId,
                        message: `Connector mismatch: server ${scopeValidation.serverId} belongs to connector ${scopeValidation.ownerConnectorId}`
                    }));
                }
                return;
            }

            // Re-validate connector token on heartbeat so rotated/revoked tokens are forced offline.
            if (data.type === 'heartbeat' && connectorId) {
                const connector = await Connector.findByPk(connectorId, { attributes: ['id', 'token'] });
                if (!connector || connector.token !== authenticatedToken) {
                    ws.send(JSON.stringify({
                        type: 'auth_fail',
                        error: 'Connector token is no longer valid. Update config and restart connector.'
                    }));
                    ws.close(4003, 'Connector token invalid');
                    return;
                }
            }

            // Heartbeat/Status Update
            if (data.type === 'heartbeat') {
                if (!global.connectorStatus) global.connectorStatus = {};
                global.connectorStatus[connectorId] = {
                    status: 'online',
                    lastSeen: new Date(),
                    usage: data.usage
                };

                broadcastToUI({
                    type: 'status_update',
                    connectorId: connectorId,
                    status: 'online',
                    lastSeen: new Date(),
                    usage: data.usage
                });
            }

            // Handle Install Results
            if (data.type === 'install_success') {
                const server = await Server.findByPk(data.serverId);
                if (server) {
                    const previousStatus = String(server.status || '').toLowerCase();
                    const started = !(data.started === false || String(data.status || '').toLowerCase() === 'offline');
                    const nextStatus = started ? 'running' : 'offline';
                    await server.update({
                        status: nextStatus
                    });
                    server.status = nextStatus;
                    console.log(`Server ${data.serverId} installed (status: ${nextStatus}): ${data.containerId}`);
                    sendToServerConsole(data.serverId, { type: 'server_status_update', status: nextStatus, containerId: data.containerId });
                    if (started && previousStatus !== 'running') {
                        sendServerSmartAlert(server, 'reinstallSuccess', {
                            previousStatus
                        });
                    }
                }

                const pendingFileImport = pendingMigrationFileImports.get(data.serverId);
                if (pendingFileImport) {
                    pendingMigrationFileImports.delete(data.serverId);
                    const sameConnector = !pendingFileImport.connectorId || pendingFileImport.connectorId === connectorId;
                    if (sameConnector && ws.readyState === WebSocket.OPEN) {
                        if (typeof setServerMigrationTransferState === 'function') {
                            await setServerMigrationTransferState(data.serverId, {
                                status: 'running',
                                connectorId: connectorId,
                                message: 'Import started after successful install.',
                                error: '',
                                files: 0,
                                directories: 0,
                                bytes: 0
                            }).catch(() => {});
                        }
                        ws.send(JSON.stringify({
                            type: 'import_sftp_files',
                            serverId: data.serverId,
                            host: pendingFileImport.host,
                            port: pendingFileImport.port,
                            username: pendingFileImport.username,
                            password: pendingFileImport.password,
                            remotePath: pendingFileImport.remotePath,
                            cleanTarget: Boolean(pendingFileImport.cleanTarget)
                        }));
                        sendToServerConsole(data.serverId, {
                            type: 'console_output',
                            output: '[*] Migration file import queued. Pulling content from source SFTP...\n'
                        });
                    } else {
                        if (typeof setServerMigrationTransferState === 'function') {
                            await setServerMigrationTransferState(data.serverId, {
                                status: 'failed',
                                connectorId: connectorId,
                                message: 'Import could not start automatically due to connector mismatch/offline.',
                                error: 'Connector mismatch/offline before file import dispatch.'
                            }).catch(() => {});
                        }
                        sendToServerConsole(data.serverId, {
                            type: 'console_output',
                            output: '[!] Migration file import could not start automatically: connector mismatch/offline.\n'
                        });
                    }
                } else if (typeof getServerMigrationTransferState === 'function') {
                    const transferState = await getServerMigrationTransferState(data.serverId).catch(() => null);
                    if (transferState && transferState.status === 'queued' && typeof setServerMigrationTransferState === 'function') {
                        await setServerMigrationTransferState(data.serverId, {
                            status: 'skipped',
                            connectorId: connectorId,
                            message: 'No pending in-memory import payload found (panel restart or state reset).',
                            error: 'Pending migration payload unavailable; re-run migration import if files are required.'
                        }).catch(() => {});
                    }
                }
            }

            if (data.type === 'install_fail') {
                const server = await Server.findByPk(data.serverId);
                if (server) {
                    const previousStatus = String(server.status || '').toLowerCase();
                    await server.update({ status: 'error' });
                    server.status = 'error';
                    console.log(`Server ${data.serverId} installation FAILED: ${data.error}`);
                    sendToServerConsole(data.serverId, { type: 'server_status_update', status: 'error', error: data.error });
                    sendServerSmartAlert(server, 'reinstallFailed', {
                        previousStatus,
                        message: data.error
                    });
                    await writeServerAuditLog({
                        serverId: data.serverId,
                        action: 'server:debug.install_fail',
                        metadata: {
                            previousStatus,
                            error: String(data.error || 'Server installation failed.'),
                            capturedAt: new Date().toISOString(),
                            logTail: getServerConsoleTailForDebug(data.serverId) || null
                        }
                    });
                    await createRuntimeIncident({
                        title: `Install failed: ${server.name}`,
                        message: String(data.error || 'Server installation failed.'),
                        severity: 'critical',
                        source: 'connector',
                        serverId: data.serverId,
                        connectorId: connectorId || null,
                        action: 'server.install_fail',
                        metadata: {
                            previousStatus,
                            logTail: getServerConsoleTailForDebug(data.serverId) || null
                        }
                    });
                    const hooksState = await getWebhooksRuntimeState();
                    await emitRuntimeWebhookEvent(
                        'serverInstallFailed',
                        `[${hooksState.brandName}] Server Install Failed`,
                        `${server.name}\n${String(data.error || 'Server installation failed.')}`,
                        '#ef4444'
                    );
                }
                pendingMigrationFileImports.delete(data.serverId);
                if (typeof setServerMigrationTransferState === 'function') {
                    const previousTransfer = typeof getServerMigrationTransferState === 'function'
                        ? await getServerMigrationTransferState(data.serverId).catch(() => null)
                        : null;
                    if (previousTransfer && (previousTransfer.status === 'queued' || previousTransfer.status === 'running')) {
                        await setServerMigrationTransferState(data.serverId, {
                            status: 'failed',
                            connectorId: connectorId,
                            message: 'Install failed before file import could complete.',
                            error: String(data.error || 'Server installation failed.')
                        }).catch(() => {});
                    }
                }
            }

            // Handle console output from connector
            if (data.type === 'console_output') {
                if (shouldForwardConsoleOutput(data.serverId, data.output)) {
                    appendToServerConsoleBuffer(data.serverId, data.output);
                    sendToServerConsole(data.serverId, { type: 'console_output', output: data.output });
                    handlePluginConflictAlert(data.serverId, data.output);
                    await handleAntiMinerFromConsoleOutput(data.serverId, data.output);
                }
            }

            // Handle server status updates from connector
            if (data.type === 'server_status_update') {
                const server = await Server.findByPk(data.serverId);
                if (server) {
                    const previousStatus = String(server.status || '').toLowerCase();
                    await server.update({ status: data.status });
                    server.status = data.status;
                    sendToServerConsole(data.serverId, { type: 'server_status_update', status: data.status });

                    const normalizedStatus = String(data.status || '').toLowerCase();
                    if (normalizedStatus === 'running' && previousStatus !== 'running') {
                        consumeServerPowerIntent(data.serverId);
                        SERVER_CRASH_COOLDOWN_STATE.delete(data.serverId);
                        sendServerSmartAlert(server, 'started', {
                            previousStatus
                        });
                        const hooksState = await getWebhooksRuntimeState();
                        await emitRuntimeWebhookEvent(
                            'serverStarted',
                            `[${hooksState.brandName}] Server Started`,
                            `${server.name} (#${server.id}) is running.`,
                            '#10b981'
                        );
                    } else if (normalizedStatus === 'stopped' && previousStatus !== 'stopped') {
                        const intent = consumeServerPowerIntent(data.serverId);
                        const crashPolicy = await getCrashPolicySettings();
                        const exitCode = Number.isInteger(Number.parseInt(data.exitCode, 10))
                            ? Number.parseInt(data.exitCode, 10)
                            : null;
                        const oomKilled = Boolean(data.oomKilled);
                        let expectedStop = Boolean(intent && (intent.action === 'stop' || intent.action === 'kill' || intent.action === 'restart'));
                        let crashSuppressed = false;

                        if (!crashPolicy.enabled) {
                            expectedStop = true;
                            crashSuppressed = true;
                        } else if (!expectedStop) {
                            if (!crashPolicy.detectCleanExitAsCrash && exitCode === 0 && !oomKilled) {
                                expectedStop = true;
                                crashSuppressed = true;
                            }
                            if (!expectedStop && crashPolicy.cooldownSeconds > 0) {
                                const now = Date.now();
                                const lastCrash = SERVER_CRASH_COOLDOWN_STATE.get(data.serverId) || 0;
                                if (lastCrash && now - lastCrash < crashPolicy.cooldownSeconds * 1000) {
                                    expectedStop = true;
                                    crashSuppressed = true;
                                } else {
                                    SERVER_CRASH_COOLDOWN_STATE.set(data.serverId, now);
                                }
                            }
                        }
                        await writeServerAuditLog({
                            serverId: data.serverId,
                            action: expectedStop ? 'server:debug.stop' : 'server:debug.crash',
                            metadata: {
                                previousStatus,
                                currentStatus: normalizedStatus,
                                expectedStop,
                                crashSuppressed,
                                powerIntent: intent && intent.action ? String(intent.action) : null,
                                exitCode,
                                oomKilled,
                                capturedAt: new Date().toISOString(),
                                logTail: getServerConsoleTailForDebug(data.serverId) || null
                            }
                        });
                        if (previousStatus === 'running') {
                            sendServerSmartAlert(server, expectedStop ? 'stopped' : 'crashed', {
                                previousStatus
                            });
                            const hooksState = await getWebhooksRuntimeState();
                            await emitRuntimeWebhookEvent(
                                expectedStop ? 'serverStopped' : 'serverCrashed',
                                `[${hooksState.brandName}] ${expectedStop ? 'Server Stopped' : 'Server Crashed'}`,
                                `${server.name} (#${server.id}) ${expectedStop ? 'stopped gracefully' : 'stopped unexpectedly'}.`,
                                expectedStop ? '#f59e0b' : '#ef4444'
                            );
                            if (!expectedStop) {
                                await createRuntimeIncident({
                                    title: `Server crashed: ${server.name}`,
                                    message: `Server #${server.id} stopped unexpectedly.`,
                                    severity: 'critical',
                                    source: 'connector',
                                    serverId: data.serverId,
                                    connectorId: connectorId || null,
                                    action: 'server.crash',
                                    metadata: {
                                        previousStatus,
                                        intent: intent && intent.action ? String(intent.action) : null,
                                        logTail: getServerConsoleTailForDebug(data.serverId) || null
                                    }
                                });
                            }
                            let playbookHandled = false;
                            if (typeof handlePolicyPlaybooksOnStop === 'function') {
                                const playbook = await handlePolicyPlaybooksOnStop(data.serverId, {
                                    expectedStop,
                                    oomKilled,
                                    exitCode,
                                    previousStatus
                                });
                                if (playbook && playbook.handled) {
                                    playbookHandled = true;
                                    sendToServerConsole(data.serverId, {
                                        type: 'console_output',
                                        output: `[!] Automated playbook triggered (${playbook.playbook || 'policy'}): ${playbook.action || 'unknown'}\n`
                                    });
                                }
                            }
                            if (!playbookHandled && !expectedStop && typeof handleCrashAutoRemediation === 'function') {
                                const remediation = await handleCrashAutoRemediation(data.serverId);
                                if (remediation && remediation.handled) {
                                    sendToServerConsole(data.serverId, {
                                        type: 'console_output',
                                        output: `[!] Auto-remediation policy triggered after crash: ${remediation.action || 'start'}\n`
                                    });
                                }
                            }
                        }
                        clearServerConsoleBuffer(data.serverId);
                    } else if (normalizedStatus === 'stopped') {
                        clearServerConsoleBuffer(data.serverId);
                    }
                }
            }

            if (data.type === 'server_debug_event') {
                const parsedServerId = Number.parseInt(data.serverId, 10);
                if (Number.isInteger(parsedServerId) && parsedServerId > 0) {
                    const eventAction = String(data.event || 'unknown').trim().toLowerCase().slice(0, 48) || 'unknown';
                    const state = (data.state && typeof data.state === 'object') ? data.state : null;
                    const connectorLogTail = typeof data.logTail === 'string' ? data.logTail.slice(-SERVER_DEBUG_LOG_TAIL_MAX_CHARS) : '';
                    const bufferedTail = getServerConsoleTailForDebug(parsedServerId) || '';
                    const debugTail = connectorLogTail || bufferedTail || null;
                    await writeServerAuditLog({
                        serverId: parsedServerId,
                        action: `server:debug.event.${eventAction}`,
                        metadata: {
                            event: eventAction,
                            connectorId: connectorId || null,
                            state,
                            logSource: connectorLogTail ? String(data.logSource || 'docker') : (bufferedTail ? 'buffer' : null),
                            capturedAt: new Date().toISOString(),
                            logTail: debugTail
                        }
                    });
                }
            }

            if (data.type === 'server_action_ack') {
                const parsedServerId = Number.parseInt(data.serverId, 10);
                if (Number.isInteger(parsedServerId) && parsedServerId > 0) {
                    sendToServerConsole(parsedServerId, {
                        type: 'server_action_ack',
                        actionType: String(data.actionType || '').trim(),
                        phase: String(data.phase || '').trim(),
                        message: String(data.message || '').trim(),
                        requestId: String(data.requestId || '').trim(),
                        timestamp: data.timestamp || new Date().toISOString(),
                        action: data.action || null
                    });

                    const phase = String(data.phase || '').trim().toLowerCase();
                    const actionType = String(data.actionType || '').trim().toLowerCase();
                    const actionLabel = actionType ? `${actionType}.${phase || 'unknown'}` : `unknown.${phase || 'unknown'}`;
                    await writeServerAuditLog({
                        serverId: parsedServerId,
                        action: `server:ack.${actionLabel}`.slice(0, 120),
                        metadata: {
                            connectorId: connectorId || null,
                            actionType,
                            phase,
                            message: String(data.message || ''),
                            requestId: String(data.requestId || '').trim() || null
                        }
                    });

                    if (phase === 'failed') {
                        if (actionType === 'command') {
                            const hooksState = await getWebhooksRuntimeState();
                            await emitRuntimeWebhookEvent(
                                'commandFailed',
                                `[${hooksState.brandName}] Command Failed`,
                                `Server #${parsedServerId}: ${String(data.message || 'Command execution failed.')}`,
                                '#ef4444'
                            );
                        }
                        await createRuntimeIncident({
                            title: `Action failed (${actionType || 'unknown'})`,
                            message: `Server #${parsedServerId}: ${String(data.message || 'Action failed')}`,
                            severity: actionType === 'command' ? 'warning' : 'critical',
                            source: 'connector',
                            serverId: parsedServerId,
                            connectorId: connectorId || null,
                            action: `server.ack.${actionType || 'unknown'}.failed`,
                            metadata: {
                                requestId: String(data.requestId || '').trim() || null
                            }
                        });
                    }
                }
            }

            // Handle EULA status from connector
            if (data.type === 'eula_status') {
                const supportsMinecraftEula = await canHandleMinecraftEula(data.serverId);
                if (supportsMinecraftEula) {
                    sendToServerConsole(data.serverId, { type: 'eula_status', accepted: data.accepted });
                }
            }

            // Handle server stats from connector (NEW)
            if (data.type === 'server_stats') {
                sendToServerConsole(data.serverId, {
                    type: 'server_stats',
                    cpu: data.cpu,
                    memory: data.memory,
                    disk: data.disk || '0'
                });
                await persistResourceTimelineSample(data.serverId, data.cpu, data.memory, data.disk || '0');
                await handleResourceAnomalyAlert(data.serverId, data.cpu, data.memory, data.disk);
                await handleAntiMinerFromStats(data.serverId, data.cpu);
                if (typeof handlePolicyAnomalyRemediation === 'function') {
                    const remediation = await handlePolicyAnomalyRemediation(data.serverId, data.cpu, data.memory);
                    if (remediation && remediation.handled) {
                        sendToServerConsole(data.serverId, {
                            type: 'console_output',
                            output: `[!] Auto-remediation policy triggered on anomaly: ${remediation.action || 'unknown'}\n`
                        });
                    }
                }
            }

            // Handle file list from connector
            if (data.type === 'file_list') {
                sendToServerConsole(data.serverId, {
                    type: 'file_list',
                    directory: data.directory,
                    files: data.files,
                    requestId: data.requestId || null
                });
            }

            // Handle file editor content and save success
            if (data.type === 'file_content') {
                sendToServerConsole(data.serverId, {
                    type: 'file_content',
                    filePath: data.filePath,
                    content: data.content
                });
            }
            if (data.type === 'write_success') {
                sendToServerConsole(data.serverId, {
                    type: 'write_success',
                    filePath: data.filePath
                });
            }
            if (data.type === 'extract_started') {
                sendToServerConsole(data.serverId, {
                    type: 'extract_started',
                    archivePath: data.archivePath || '',
                    directory: data.directory || '/',
                    targetDirectory: data.targetDirectory || data.directory || '/',
                    operationId: data.operationId || ''
                });
            }
            if (data.type === 'extract_complete') {
                sendToServerConsole(data.serverId, {
                    type: 'extract_complete',
                    success: Boolean(data.success),
                    archivePath: data.archivePath || '',
                    directory: data.directory || '/',
                    targetDirectory: data.targetDirectory || data.directory || '/',
                    operationId: data.operationId || '',
                    error: String(data.error || '')
                });
            }
            if (data.type === 'file_versions') {
                sendToServerConsole(data.serverId, {
                    type: 'file_versions',
                    filePath: data.filePath,
                    versions: data.versions || []
                });
            }
            if (data.type === 'file_version_content') {
                sendToServerConsole(data.serverId, {
                    type: 'file_version_content',
                    filePath: data.filePath,
                    versionId: data.versionId,
                    content: data.content || ''
                });
            }
            if (data.type === 'resource_limits_result') {
                sendToServerConsole(data.serverId, {
                    type: 'resource_limits_result',
                    success: Boolean(data.success),
                    error: String(data.error || ''),
                    requestId: String(data.requestId || '').trim() || null,
                    applied: data.applied && typeof data.applied === 'object' ? data.applied : {}
                });
            }
            if (data.type === 'log_cleanup_result') {
                sendToServerConsole(data.serverId, {
                    type: 'log_cleanup_result',
                    directory: data.directory || '/logs',
                    rotated: Number.parseInt(data.rotated, 10) || 0,
                    deleted: Number.parseInt(data.deleted, 10) || 0,
                    kept: Number.parseInt(data.kept, 10) || 0
                });
            }
            if (data.type === 'sftp_import_progress') {
                const files = Number.parseInt(data.files, 10) || 0;
                const directories = Number.parseInt(data.directories, 10) || 0;
                const bytes = Number.parseInt(data.bytes, 10) || 0;
                sendToServerConsole(data.serverId, {
                    type: 'sftp_import_progress',
                    files,
                    directories,
                    bytes
                });
                if (typeof setServerMigrationTransferState === 'function') {
                    await setServerMigrationTransferState(data.serverId, {
                        status: 'running',
                        files,
                        directories,
                        bytes,
                        connectorId: connectorId || 0,
                        message: 'Import in progress.'
                    }).catch(() => {});
                }
            }
            if (data.type === 'sftp_import_result') {
                const success = Boolean(data.success);
                const files = Number.parseInt(data.files, 10) || 0;
                const directories = Number.parseInt(data.directories, 10) || 0;
                const bytes = Number.parseInt(data.bytes, 10) || 0;
                const error = String(data.error || '');
                sendToServerConsole(data.serverId, {
                    type: 'sftp_import_result',
                    success,
                    files,
                    directories,
                    bytes,
                    error
                });
                if (typeof setServerMigrationTransferState === 'function') {
                    await setServerMigrationTransferState(data.serverId, {
                        status: success ? 'completed' : 'failed',
                        files,
                        directories,
                        bytes,
                        connectorId: connectorId || 0,
                        message: success ? 'File import completed successfully.' : 'File import failed.',
                        error: success ? '' : error
                    }).catch(() => {});
                }
            }

            // Handle errors from connector
            if (data.type === 'error') {
                sendToServerConsole(data.serverId, {
                    type: 'error',
                    message: data.message
                });
                const parsedServerId = Number.parseInt(data.serverId, 10);
                if (Number.isInteger(parsedServerId) && parsedServerId > 0) {
                    await writeServerAuditLog({
                        serverId: parsedServerId,
                        action: 'server:debug.connector_error',
                        metadata: {
                            message: String(data.message || 'Connector error'),
                            connectorId: connectorId || null,
                            capturedAt: new Date().toISOString(),
                            logTail: getServerConsoleTailForDebug(parsedServerId) || null
                        }
                    });
                    await createRuntimeIncident({
                        title: `Connector error on server #${parsedServerId}`,
                        message: String(data.message || 'Connector returned an error'),
                        severity: 'warning',
                        source: 'connector',
                        serverId: parsedServerId,
                        connectorId: connectorId || null,
                        action: 'connector.error',
                        metadata: {
                            logTail: getServerConsoleTailForDebug(parsedServerId) || null
                        }
                    });
                    const hooksState = await getWebhooksRuntimeState();
                    await emitRuntimeWebhookEvent(
                        'connectorError',
                        `[${hooksState.brandName}] Connector Error`,
                        `Server #${parsedServerId}: ${String(data.message || 'Connector returned an error.')}`,
                        '#f59e0b'
                    );
                }
            }

        } catch (err) {
            console.error("WS Message Error:", err);
        }
    });

    ws.on('close', () => {
        if (connectorId && connectorConnections.get(connectorId) === ws) {
            connectorConnections.delete(connectorId);
            console.log(`Connector ${connectorId} disconnected from WebSocket`);
            markConnectorOffline(connectorId, 'socket_closed');
        }
    });
});

setInterval(() => {
    runScheduledLogCleanupSweep();
    runServerStoreBillingSweep();
    if (typeof runRevenueModeSweep === 'function') runRevenueModeSweep();
    if (typeof runServerScheduledScalingSweep === 'function') runServerScheduledScalingSweep();
}, 5 * 60 * 1000);

setInterval(() => {
    if (typeof runServerScheduledScalingSweep === 'function') runServerScheduledScalingSweep();
}, 60 * 1000);

setInterval(() => {
    sweepStaleConnectorHeartbeats();
}, CONNECTOR_HEARTBEAT_SWEEP_MS);

setTimeout(() => {
    runScheduledLogCleanupSweep();
    runServerStoreBillingSweep();
    if (typeof runRevenueModeSweep === 'function') runRevenueModeSweep();
    if (typeof runServerScheduledScalingSweep === 'function') runServerScheduledScalingSweep();
}, 15 * 1000);

setTimeout(() => {
    sweepStaleConnectorHeartbeats();
}, Math.min(CONNECTOR_HEARTBEAT_SWEEP_MS, 10000));

    return { wss };
}

module.exports = { registerWebSocketRuntime };
