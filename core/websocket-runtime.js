const { appendIncidentCenterRecord } = require('./incidents');

function registerWebSocketRuntime(deps) {
    const {
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
        sendDiscordSmartAlert,
        sendTelegramSmartAlert,
        handlePluginConflictAlert,
        handleResourceAnomalyAlert,
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
const wss = new WebSocket.Server({ noServer: true });
const uiClients = new Set();
const serverConsoleClients = new Map(); // serverId -> Set<ws>
const recentConsolePayloads = new Map(); // serverId -> { output: string, ts: number }
const serverConsoleBuffers = new Map(); // serverId -> { lines: string[], bytes: number }
const SERVER_CONSOLE_BUFFER_MAX_LINES = 1200;
const SERVER_CONSOLE_BUFFER_MAX_BYTES = 1024 * 1024;
const SERVER_DEBUG_LOG_TAIL_MAX_CHARS = 32 * 1024;
const WEBHOOKS_SETTING_KEY = 'extensionWebhooksConfig';

const webhooksConfigCache = {
    ts: 0,
    config: null,
    moduleEnabled: false,
    brandName: 'CPanel'
};
const serverMinecraftEligibilityCache = new Map(); // serverId -> boolean
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
    } catch {
        // Ignore audit write errors inside websocket runtime.
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
                            directory: data.directory
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
                    await server.update({
                        status: 'running'
                    });
                    server.status = 'running';
                    console.log(`Server ${data.serverId} installed and running: ${data.containerId}`);
                    sendToServerConsole(data.serverId, { type: 'server_status_update', status: 'running', containerId: data.containerId });
                    if (previousStatus !== 'running') {
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
                        const expectedStop = Boolean(intent && (intent.action === 'stop' || intent.action === 'kill' || intent.action === 'restart'));
                        await writeServerAuditLog({
                            serverId: data.serverId,
                            action: expectedStop ? 'server:debug.stop' : 'server:debug.crash',
                            metadata: {
                                previousStatus,
                                currentStatus: normalizedStatus,
                                expectedStop,
                                powerIntent: intent && intent.action ? String(intent.action) : null,
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
                            if (!expectedStop && typeof handleCrashAutoRemediation === 'function') {
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
                await handleResourceAnomalyAlert(data.serverId, data.cpu, data.memory);
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
                    files: data.files
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
            if (global.connectorStatus && global.connectorStatus[connectorId]) {
                global.connectorStatus[connectorId].status = 'offline';

                broadcastToUI({
                    type: 'status_update',
                    connectorId: connectorId,
                    status: 'offline',
                    lastSeen: new Date()
                });
            }
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

setTimeout(() => {
    runScheduledLogCleanupSweep();
    runServerStoreBillingSweep();
    if (typeof runRevenueModeSweep === 'function') runRevenueModeSweep();
    if (typeof runServerScheduledScalingSweep === 'function') runServerScheduledScalingSweep();
}, 15 * 1000);

    return { wss };
}

module.exports = { registerWebSocketRuntime };
