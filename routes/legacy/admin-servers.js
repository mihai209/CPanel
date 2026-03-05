function registerAdminServersRoutes(ctx) {
    const nodeCrypto = require('node:crypto');
    const { pickSmartAllocation } = require('../../core/helpers/smart-allocation');
    const {
        app,
        WebSocket,
        crypto,
        Server,
        ServerApiKey,
        User,
        Image,
        Settings,
        Connector,
        Allocation,
        requireAuth,
        requireAdmin,
        connectorConnections,
        jobQueue,
        fetchPterodactylApplicationServer,
        normalizePterodactylServerForMigration,
        encodeMigrationSnapshot,
        inferSftpHostFromPanelUrl,
        decodeMigrationSnapshot,
        parseBooleanInput,
        getConnectorAllocatedUsage,
        resolveImagePorts,
        buildDeploymentPorts,
        resolveImageVariableDefinitions,
        normalizeClientVariables,
        buildServerEnvironment,
        buildStartupCommand,
        shouldUseCommandStartup,
        resolveImageDockerChoices,
        normalizeServerAdvancedLimits,
        getServerSmartAlertsSettingKey,
        getServerStartupPresetSettingKey,
        getServerPolicyEngineSettingKey,
        consumeServerPowerIntent,
        RESOURCE_ANOMALY_STATE,
        RESOURCE_ANOMALY_SAMPLE_TS,
        PLUGIN_CONFLICT_STATE,
        serverLogCleanupScheduleState,
        pendingMigrationFileImports,
        getServerMigrationTransferState,
        setServerMigrationTransferState,
        removeServerMigrationTransferState,
        rememberServerPowerIntent,
        sendServerSmartAlert
    } = ctx;

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
    if (!result || !result.ok || !result.best || !result.best.allocation) return null;
    const best = result.best;
    const allocation = best.allocation;
    const connector = best.connector || allocation.connector || null;
    return {
        id: Number.parseInt(allocation.id, 10) || 0,
        connectorId: Number.parseInt(allocation.connectorId, 10) || 0,
        connectorName: connector ? String(connector.name || `Connector #${allocation.connectorId}`) : `Connector #${allocation.connectorId}`,
        ip: String(allocation.ip || ''),
        port: Number.parseInt(allocation.port, 10) || 0,
        alias: allocation.alias || null,
        notes: allocation.notes || null,
        score: Number(best.score || 0),
        estimatedCpuUsage: Number(best.cpuUsage || 0),
        projectedMemoryHeadroomMb: Number(best.cap && best.cap.memoryHeadroomMb || 0),
        projectedDiskHeadroomMb: Number(best.cap && best.cap.diskHeadroomMb || 0)
    };
}

const CONNECTOR_STATUS_STALE_MS = Math.max(
    30000,
    Number.parseInt(process.env.CONNECTOR_ONLINE_STALE_MS || '120000', 10) || 120000
);

function getConnectorSocket(connectorId) {
    if (!connectorConnections || !connectorConnections.get) return null;
    return connectorConnections.get(connectorId) || connectorConnections.get(String(connectorId)) || null;
}

function getConnectorStatusEntry(connectorStatusMap, connectorId) {
    const source = connectorStatusMap && typeof connectorStatusMap === 'object'
        ? connectorStatusMap
        : (global.connectorStatus || {});
    if (!source || typeof source !== 'object') return null;
    return source[connectorId] || source[String(connectorId)] || null;
}

function buildEffectiveConnectorStatus(connectorId, connectorStatusMap = null) {
    const parsedConnectorId = Number.parseInt(connectorId, 10);
    const nowMs = Date.now();
    const statusEntry = getConnectorStatusEntry(connectorStatusMap, parsedConnectorId);
    const socket = getConnectorSocket(parsedConnectorId);
    const socketOnline = Boolean(socket && socket.readyState === WebSocket.OPEN);
    const lastSeenMs = new Date(statusEntry && statusEntry.lastSeen ? statusEntry.lastSeen : 0).getTime();
    const heartbeatOnline = Boolean(
        statusEntry
        && String(statusEntry.status || '').toLowerCase() === 'online'
        && Number.isFinite(lastSeenMs)
        && lastSeenMs > 0
        && (nowMs - lastSeenMs) < CONNECTOR_STATUS_STALE_MS
    );
    const isOnline = socketOnline || heartbeatOnline;

    return {
        status: isOnline ? 'online' : 'offline',
        lastSeen: Number.isFinite(lastSeenMs) && lastSeenMs > 0
            ? new Date(lastSeenMs).toISOString()
            : (isOnline ? new Date(nowMs).toISOString() : null),
        usage: statusEntry && statusEntry.usage ? statusEntry.usage : null
    };
}

function buildEffectiveConnectorStatusMap(connectorIds = []) {
    const map = {};
    const source = global.connectorStatus || {};
    Object.keys(source).forEach((key) => {
        const parsedConnectorId = Number.parseInt(key, 10);
        if (!Number.isInteger(parsedConnectorId) || parsedConnectorId <= 0) return;
        map[parsedConnectorId] = buildEffectiveConnectorStatus(parsedConnectorId, source);
    });
    (Array.isArray(connectorIds) ? connectorIds : []).forEach((entry) => {
        const parsedConnectorId = Number.parseInt(entry, 10);
        if (!Number.isInteger(parsedConnectorId) || parsedConnectorId <= 0) return;
        map[parsedConnectorId] = buildEffectiveConnectorStatus(parsedConnectorId, source);
    });
    return map;
}

async function resolvePrimaryAllocationForServer(server, options = {}) {
    if (!server) return null;
    const serverId = Number.parseInt(server.id, 10);
    const allocationId = Number.parseInt(server.allocationId, 10);
    if (!Number.isInteger(serverId) || serverId <= 0) return null;
    if (!Number.isInteger(allocationId) || allocationId <= 0) return null;

    const query = {
        where: {
            id: allocationId,
            serverId
        }
    };
    if (options.includeConnector) {
        query.include = [{ model: Connector, as: 'connector' }];
    }
    return Allocation.findOne(query);
}

function extractStartupPlaceholders(startup) {
    const text = String(startup || '');
    const regex = /\{\{\s*([A-Z0-9_]+)\s*\}\}/g;
    const found = new Set();
    let match;
    while ((match = regex.exec(text)) !== null) {
        if (match && match[1]) {
            found.add(String(match[1]).trim());
        }
    }
    return Array.from(found);
}

function normalizeDockerCandidate(value) {
    return String(value || '').trim().toLowerCase();
}

function splitDockerCandidate(value) {
    const normalized = normalizeDockerCandidate(value);
    if (!normalized) {
        return { normalized: '', repo: '', tag: '' };
    }
    const parts = normalized.split(':');
    if (parts.length === 1) {
        return { normalized, repo: normalized, tag: '' };
    }
    const tag = parts.pop();
    return {
        normalized,
        repo: parts.join(':'),
        tag: String(tag || '')
    };
}

function computeDockerSimilarity(remoteDocker, localDocker) {
    const remote = splitDockerCandidate(remoteDocker);
    const local = splitDockerCandidate(localDocker);
    if (!remote.normalized || !local.normalized) return { score: 0, match: 'none' };
    if (remote.normalized === local.normalized) return { score: 25, match: 'exact' };
    if (remote.repo && local.repo && remote.repo === local.repo) return { score: 18, match: 'repo' };
    if (remote.repo.includes('java') && local.repo.includes('java')) return { score: 12, match: 'family' };
    if (remote.repo.includes('node') && local.repo.includes('node')) return { score: 12, match: 'family' };
    if (remote.repo.includes('python') && local.repo.includes('python')) return { score: 12, match: 'family' };
    return { score: 0, match: 'none' };
}

function buildMigrationPrecheckMatrix(snapshot, images) {
    const remoteVariables = normalizeClientVariables(snapshot && snapshot.environment ? snapshot.environment : {});
    const remoteVariableKeys = Object.keys(remoteVariables);
    const remoteVariableSet = new Set(remoteVariableKeys);
    const remoteDocker = normalizeDockerCandidate(snapshot && snapshot.dockerImage ? snapshot.dockerImage : '');
    const remoteStartup = String(snapshot && snapshot.startup ? snapshot.startup : '').trim();

    const matrixRows = (Array.isArray(images) ? images : []).map((image) => {
        const imageVariableDefs = resolveImageVariableDefinitions(image);
        const imageVariableKeys = imageVariableDefs
            .map((entry) => String(entry && entry.env_variable ? entry.env_variable : '').trim())
            .filter(Boolean);
        const imageVariableSet = new Set(imageVariableKeys);

        const supportedVariables = remoteVariableKeys.filter((key) => imageVariableSet.has(key));
        const unsupportedVariables = remoteVariableKeys.filter((key) => !imageVariableSet.has(key));
        const placeholderKeys = extractStartupPlaceholders(image && image.startup ? image.startup : '');
        const unresolvedPlaceholders = placeholderKeys.filter((key) => {
            if (remoteVariableSet.has(key)) return false;
            if (key === 'SERVER_MEMORY' || key === 'SERVER_PORT' || key === 'SERVER_IP') return false;
            return true;
        });

        let startupPreviewError = '';
        try {
            const defaultPort = Number.parseInt(snapshot && snapshot.defaultAllocation ? snapshot.defaultAllocation.port : '', 10) || 25565;
            const defaultMemory = Number.parseInt(snapshot && snapshot.memory ? snapshot.memory : '', 10) || 1024;
            const { env: previewEnv } = buildServerEnvironment(image, remoteVariables, {
                SERVER_MEMORY: String(defaultMemory),
                SERVER_IP: '0.0.0.0',
                SERVER_PORT: String(defaultPort)
            });
            buildStartupCommand(image && image.startup ? image.startup : '', previewEnv);
        } catch (error) {
            startupPreviewError = String(error && error.message ? error.message : '').slice(0, 240);
        }

        const dockerSimilarity = computeDockerSimilarity(remoteDocker, image && image.dockerImage ? image.dockerImage : '');
        const remoteVariableCount = remoteVariableKeys.length;
        const supportRatio = remoteVariableCount > 0
            ? supportedVariables.length / remoteVariableCount
            : 1;

        let score = 0;
        score += Math.round(supportRatio * 55);
        score += dockerSimilarity.score;
        score -= Math.min(18, unsupportedVariables.length * 2);
        score -= Math.min(30, unresolvedPlaceholders.length * 10);
        if (startupPreviewError) score -= 18;
        score = Math.max(0, Math.min(100, score));

        const warnings = [];
        if (unsupportedVariables.length > 0) {
            warnings.push(`Ignored vars: ${unsupportedVariables.slice(0, 6).join(', ')}${unsupportedVariables.length > 6 ? ', ...' : ''}`);
        }
        if (unresolvedPlaceholders.length > 0) {
            warnings.push(`Unresolved startup placeholders: ${unresolvedPlaceholders.join(', ')}`);
        }
        if (startupPreviewError) {
            warnings.push(startupPreviewError);
        }
        if (!remoteStartup) {
            warnings.push('Remote startup command was empty.');
        }

        const status = score >= 80
            ? 'recommended'
            : score >= 60
                ? 'compatible'
                : score >= 40
                    ? 'warning'
                    : 'risky';

        return {
            imageId: image.id,
            imageName: String(image.name || 'Unnamed image'),
            dockerImage: String(image.dockerImage || '').trim(),
            status,
            score,
            dockerMatch: dockerSimilarity.match,
            remoteVariableCount,
            supportedVariableCount: supportedVariables.length,
            unsupportedVariableCount: unsupportedVariables.length,
            unsupportedVariables: unsupportedVariables.slice(0, 20),
            unresolvedPlaceholders,
            startupPreviewError,
            warnings
        };
    });

    matrixRows.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        return a.imageName.localeCompare(b.imageName);
    });

    const recommended = matrixRows.length > 0 ? matrixRows[0] : null;
    return {
        generatedAt: new Date().toISOString(),
        remoteVariableCount: remoteVariableKeys.length,
        recommendedImageId: recommended ? recommended.imageId : null,
        recommendedImageName: recommended ? recommended.imageName : '',
        rows: matrixRows
    };
}
// Admin Servers

app.get('/admin/servers', requireAuth, requireAdmin, async (req, res) => {
    try {
        const servers = await Server.findAll({
            include: [
                { model: User, as: 'owner', attributes: ['id', 'username', 'email'] },
                { model: Image, as: 'image', attributes: ['id', 'name'] },
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector', attributes: ['name'] }] }
            ]
        });
        res.render('admin/servers', {
            servers,
            user: req.session.user,
            title: 'Manage Servers',
            path: '/admin/servers'
        });
    } catch (err) {
        console.error("Error fetching servers:", err);
        res.redirect('/admin/overview?error=Error fetching servers');
    }
});

app.get('/admin/servers/create', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({ attributes: ['id', 'username', 'email'], order: [['username', 'ASC']] });
        const images = await Image.findAll({ order: [['name', 'ASC']] });
        const connectors = await Connector.findAll({
            include: [{
                model: Allocation,
                as: 'allocations'
            }],
            order: [['name', 'ASC']]
        });

        console.log(`[DEBUG] Rendering create-server. Found ${users.length} users, ${images.length} images, ${connectors.length} connectors.`);
        // Log first connector allocations count for debug
        if (connectors.length > 0) {
            console.log(`[DEBUG] Connector 0 (${connectors[0].name}) has ${connectors[0].allocations ? connectors[0].allocations.length : 'NO'} allocations.`);
        }

        res.render('admin/create-server', {
            users,
            images,
            connectors,
            connectorStatus: buildEffectiveConnectorStatusMap(connectors.map((connector) => connector.id)),
            user: req.session.user,
            title: 'Create Server',
            path: '/admin/servers'
        });
    } catch (err) {
        console.error("Error loading server creation page:", err);
        res.redirect('/admin/servers?error=Error loading creation page');
    }
});

app.get('/api/admin/servers/smart-allocation', requireAuth, requireAdmin, async (req, res) => {
    try {
        const requestedMemoryMb = Math.max(64, Number.parseInt(req.query.memory, 10) || 1024);
        const requestedDiskMb = Math.max(512, Number.parseInt(req.query.disk, 10) || 10240);
        const preferredConnectorId = Math.max(0, Number.parseInt(req.query.connectorId, 10) || 0);

        const allocations = await Allocation.findAll({
            where: { serverId: null },
            include: [{ model: Connector, as: 'connector' }],
            order: [['id', 'ASC']]
        });
        const usageByConnector = await buildConnectorUsageMap(allocations.map((entry) => entry.connectorId));
        const result = pickSmartAllocation({
            allocations,
            connectorStatusMap: buildEffectiveConnectorStatusMap(allocations.map((entry) => entry.connectorId)),
            usageByConnector,
            requestedMemoryMb,
            requestedDiskMb,
            preferredConnectorId
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
        console.error('Error computing admin smart allocation:', error);
        return res.status(500).json({ success: false, error: 'Failed to compute smart allocation.' });
    }
});

app.get('/admin/migrations/pterodactyl', requireAuth, requireAdmin, async (req, res) => {
    try {
        const migrationDraft = req.session && req.session.pterodactylMigrationDraft && typeof req.session.pterodactylMigrationDraft === 'object'
            ? req.session.pterodactylMigrationDraft
            : null;
        const [users, images, allocations] = await Promise.all([
            User.findAll({ attributes: ['id', 'username', 'email'], order: [['username', 'ASC']] }),
            Image.findAll({ order: [['name', 'ASC']] }),
            Allocation.findAll({
                where: { serverId: null },
                include: [{ model: Connector, as: 'connector' }],
                order: [['id', 'ASC']]
            })
        ]);

        res.render('admin/migration-pterodactyl', {
            user: req.session.user,
            title: 'Pterodactyl Migration',
            path: '/admin/migrations/pterodactyl',
            users,
            images,
            allocations,
            connectorStatus: buildEffectiveConnectorStatusMap(allocations.map((allocation) => allocation.connectorId)),
            remotePanelUrl: migrationDraft ? String(migrationDraft.remotePanelUrl || '') : '',
            remoteServerRef: migrationDraft ? String(migrationDraft.remoteServerRef || '') : '',
            remoteSftpHost: migrationDraft ? String(migrationDraft.remoteSftpHost || '') : '',
            remoteSftpPort: migrationDraft && Number.isInteger(Number.parseInt(migrationDraft.remoteSftpPort, 10))
                ? Number.parseInt(migrationDraft.remoteSftpPort, 10)
                : 2022,
            remoteSftpPath: migrationDraft ? String(migrationDraft.remoteSftpPath || '/') : '/',
            migrationSnapshot: migrationDraft ? (migrationDraft.migrationSnapshot || null) : null,
            migrationPrecheck: migrationDraft ? (migrationDraft.migrationPrecheck || null) : null,
            migrationToken: migrationDraft ? String(migrationDraft.migrationToken || '') : '',
            jobId: req.query.jobId || null,
            serverId: req.query.serverId || null,
            fileImport: req.query.fileImport || '0',
            success: req.query.success || null,
            error: req.query.error || null,
            warning: req.query.warning || null
        });
    } catch (error) {
        console.error('Error loading migration wizard:', error);
        res.redirect('/admin/overview?error=Failed to load migration wizard.');
    }
});

app.get('/api/admin/migrations/pterodactyl/status', requireAuth, requireAdmin, async (req, res) => {
    try {
        const serverId = Number.parseInt(req.query.serverId, 10);
        const jobId = Number.parseInt(req.query.jobId, 10);

        const [server, fileImportState, job] = await Promise.all([
            Number.isInteger(serverId) && serverId > 0
                ? Server.findByPk(serverId, {
                    attributes: ['id', 'name', 'containerId', 'status', 'isSuspended']
                })
                : null,
            Number.isInteger(serverId) && serverId > 0 && typeof getServerMigrationTransferState === 'function'
                ? getServerMigrationTransferState(serverId)
                : null,
            Number.isInteger(jobId) && jobId > 0
                ? jobQueue.getById(jobId)
                : null
        ]);

        return res.json({
            success: true,
            server,
            job,
            fileImport: fileImportState
        });
    } catch (error) {
        console.error('Failed to fetch migration status:', error);
        return res.status(500).json({
            success: false,
            error: 'Failed to fetch migration status.'
        });
    }
});

app.post('/admin/migrations/pterodactyl/fetch', requireAuth, requireAdmin, async (req, res) => {
    const remotePanelUrl = String(req.body.remotePanelUrl || '').trim();
    const remoteApiKey = String(req.body.remoteApiKey || '').trim();
    const remoteServerRef = String(req.body.remoteServerRef || '').trim();

    try {
        const [users, images, allocations] = await Promise.all([
            User.findAll({ attributes: ['id', 'username', 'email'], order: [['username', 'ASC']] }),
            Image.findAll({ order: [['name', 'ASC']] }),
            Allocation.findAll({
                where: { serverId: null },
                include: [{ model: Connector, as: 'connector' }],
                order: [['id', 'ASC']]
            })
        ]);

        const remoteRaw = await fetchPterodactylApplicationServer(remotePanelUrl, remoteApiKey, remoteServerRef);
        const migrationSnapshot = normalizePterodactylServerForMigration(remoteRaw);
        const migrationPrecheck = buildMigrationPrecheckMatrix(migrationSnapshot, images);
        const migrationToken = encodeMigrationSnapshot(migrationSnapshot);
        const inferredSftpHost = inferSftpHostFromPanelUrl(remotePanelUrl);

        req.session.pterodactylMigrationDraft = {
            remotePanelUrl,
            remoteServerRef,
            remoteSftpHost: inferredSftpHost,
            remoteSftpPort: 2022,
            remoteSftpPath: '/',
            migrationSnapshot,
            migrationPrecheck,
            migrationToken
        };
        await new Promise((resolve) => req.session.save(resolve));
        return res.redirect('/admin/migrations/pterodactyl?success=' + encodeURIComponent('Remote server fetched successfully. Continue with import step.'));
    } catch (error) {
        console.error('Failed to fetch Pterodactyl server for migration:', error);
        return res.redirect(`/admin/migrations/pterodactyl?error=${encodeURIComponent(error.message || 'Failed to fetch remote server data.')}`);
    }
});

app.post('/admin/migrations/pterodactyl/import', requireAuth, requireAdmin, async (req, res) => {
    try {
        const snapshot = decodeMigrationSnapshot(req.body.migrationToken);
        const ownerId = Number.parseInt(req.body.ownerId, 10);
        const imageId = req.body.imageId;
        const allocationId = Number.parseInt(req.body.allocationId, 10);
        const importFiles = parseBooleanInput(req.body.importFiles, false);
        const sourceSftpHost = String(req.body.sourceSftpHost || '').trim();
        const sourceSftpPort = Number.parseInt(req.body.sourceSftpPort, 10) || 2022;
        const sourceSftpUsername = String(req.body.sourceSftpUsername || '').trim();
        const sourceSftpPassword = String(req.body.sourceSftpPassword || '').trim();
        const sourceSftpPathRaw = String(req.body.sourceSftpPath || '').trim();
        const sourceSftpPath = sourceSftpPathRaw ? sourceSftpPathRaw : '/';
        const sourceCleanTarget = parseBooleanInput(req.body.sourceCleanTarget, false);

        if (!Number.isInteger(ownerId) || ownerId <= 0) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Select a valid local owner.'));
        }
        if (!imageId) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Select a local image.'));
        }
        if (!Number.isInteger(allocationId) || allocationId <= 0) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Select a free allocation.'));
        }
        if (importFiles) {
            if (!sourceSftpHost || !sourceSftpUsername || !sourceSftpPassword) {
                return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('SFTP file import is enabled, but host/username/password is missing.'));
            }
            if (!Number.isInteger(sourceSftpPort) || sourceSftpPort < 1 || sourceSftpPort > 65535) {
                return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('SFTP port must be between 1 and 65535.'));
            }
        }

        const image = await Image.findByPk(imageId);
        if (!image) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected image does not exist.'));
        }

        const allocation = await Allocation.findByPk(allocationId, {
            include: [{ model: Connector, as: 'connector' }]
        });
        if (!allocation || allocation.serverId) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected allocation is no longer free.'));
        }

        const effectiveConnectorStatus = buildEffectiveConnectorStatus(allocation.connectorId);
        if (effectiveConnectorStatus.status !== 'online') {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected connector is offline.'));
        }

        const memory = Number.parseInt(req.body.memory, 10) || Number.parseInt(snapshot.memory, 10) || 1024;
        const cpu = Number.parseInt(req.body.cpu, 10) || Number.parseInt(snapshot.cpu, 10) || 100;
        const disk = Number.parseInt(req.body.disk, 10) || Number.parseInt(snapshot.disk, 10) || 10240;

        if (memory < 64 || cpu < 10 || disk < 512) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Resource limits are too low. Check memory/cpu/disk values.'));
        }

        const currentUsage = await getConnectorAllocatedUsage(allocation.connectorId);
        const connectorMemoryMb = allocation.connector.totalMemory * 1024;
        const maxMemoryMb = connectorMemoryMb * (1 + (allocation.connector.memoryOverAllocation || 0) / 100);
        const connectorDiskMb = allocation.connector.totalDisk * 1024;
        const maxDiskMb = connectorDiskMb * (1 + (allocation.connector.diskOverAllocation || 0) / 100);

        if (currentUsage.memoryMb + memory > maxMemoryMb) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent(`Not enough memory on selected connector. Max allowed: ${maxMemoryMb} MB.`));
        }
        if (currentUsage.diskMb + disk > maxDiskMb) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent(`Not enough disk on selected connector. Max allowed: ${maxDiskMb} MB.`));
        }

        const imagePorts = resolveImagePorts(image.ports);
        const variableDefinitions = resolveImageVariableDefinitions(image);
        const remoteVariables = normalizeClientVariables(snapshot.environment || {});
        const allowedVariableKeys = new Set(variableDefinitions.map((entry) => String(entry.env_variable || '').trim()).filter(Boolean));
        const migratedVariables = {};
        const ignoredVariables = [];
        Object.entries(remoteVariables).forEach(([key, value]) => {
            if (allowedVariableKeys.has(key)) {
                migratedVariables[key] = value;
            } else {
                ignoredVariables.push(key);
            }
        });

        const { resolvedVariables, env } = buildServerEnvironment(image, migratedVariables, {
            SERVER_MEMORY: String(memory),
            SERVER_IP: '0.0.0.0',
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

        const dockerChoices = resolveImageDockerChoices(image);
        const allowedDockerTags = new Set(dockerChoices.map((choice) => choice.tag));
        const dockerOverride = String(req.body.dockerImage || '').trim()
            || String(snapshot.dockerImage || '').trim();
        const nextDockerImage = dockerOverride && (allowedDockerTags.size === 0 || allowedDockerTags.has(dockerOverride))
            ? dockerOverride
            : (image.dockerImage || dockerOverride);

        const containerId = nodeCrypto.randomBytes(4).toString('hex');
        const createdServer = await Server.create({
            name: String(req.body.name || snapshot.name || 'Imported Server').trim() || 'Imported Server',
            containerId,
            ownerId,
            imageId: image.id,
            allocationId: allocation.id,
            memory,
            cpu,
            disk,
            swapLimit: Number.parseInt(snapshot.swap, 10) || 0,
            ioWeight: Number.parseInt(snapshot.io, 10) || 500,
            pidsLimit: 512,
            oomKillDisable: false,
            oomScoreAdj: 0,
            variables: resolvedVariables,
            dockerImage: nextDockerImage
        });

        await allocation.update({ serverId: createdServer.id });

        const pendingFileImport = importFiles ? {
            connectorId: allocation.connectorId,
            host: sourceSftpHost,
            port: sourceSftpPort,
            username: sourceSftpUsername,
            password: sourceSftpPassword,
            remotePath: sourceSftpPath.startsWith('/') ? sourceSftpPath : `/${sourceSftpPath}`,
            cleanTarget: sourceCleanTarget
        } : null;
        const fileImportQueued = Boolean(pendingFileImport);

        const installConfig = {
            image: createdServer.dockerImage,
            memory: createdServer.memory,
            cpu: createdServer.cpu,
            disk: createdServer.disk,
            swapLimit: createdServer.swapLimit,
            ioWeight: createdServer.ioWeight,
            pidsLimit: createdServer.pidsLimit,
            oomKillDisable: Boolean(createdServer.oomKillDisable),
            oomScoreAdj: createdServer.oomScoreAdj,
            env,
            startup,
            startupMode,
            eggConfig: image.eggConfig,
            eggScripts: image.eggScripts,
            installation: image.installation || null,
            configFiles: image.configFiles || null,
            brandName: String((res.locals.settings && res.locals.settings.brandName) || 'cpanel'),
            ports: deploymentPorts,
            mounts: []
        };

        let installJob;
        try {
            installJob = await jobQueue.enqueue({
                type: 'server.install.dispatch',
                payload: {
                    serverId: createdServer.id,
                    reinstall: false,
                    clearSuspended: true,
                    resolvedVariables,
                    pendingFileImport,
                    config: installConfig
                },
                priority: 10,
                maxAttempts: 3,
                createdByUserId: req.session.user.id
            });
        } catch (queueError) {
            await allocation.update({ serverId: null }).catch(() => {});
            await createdServer.destroy().catch(() => {});
            throw new Error(`Failed to queue deployment job: ${queueError.message}`);
        }

        await createdServer.update({ status: 'installing' });

        if (typeof setServerMigrationTransferState === 'function') {
            if (fileImportQueued) {
                await setServerMigrationTransferState(createdServer.id, {
                    status: 'queued',
                    connectorId: allocation.connectorId,
                    jobId: installJob.id,
                    message: 'Waiting for install to finish before SFTP import starts.',
                    error: '',
                    files: 0,
                    directories: 0,
                    bytes: 0
                }).catch(() => {});
            } else if (typeof removeServerMigrationTransferState === 'function') {
                await removeServerMigrationTransferState(createdServer.id).catch(() => {});
            }
        }

        const warning = ignoredVariables.length > 0
            ? `Imported with warnings. Ignored ${ignoredVariables.length} variables not supported by selected image: ${ignoredVariables.slice(0, 8).join(', ')}`
            : '';
        const fileImportNotice = fileImportQueued
            ? ' File import via SFTP is queued and will start automatically after install finishes.'
            : '';
        const jobNotice = ` Deployment job #${installJob.id} queued.`;
        delete req.session.pterodactylMigrationDraft;
        await new Promise((resolve) => req.session.save(resolve));
        const query = [
            `success=${encodeURIComponent(`Server "${createdServer.name}" imported and deployment started.${jobNotice}${fileImportNotice}`)}`,
            warning ? `warning=${encodeURIComponent(warning)}` : '',
            `jobId=${encodeURIComponent(String(installJob.id))}`,
            `serverId=${encodeURIComponent(String(createdServer.id))}`,
            `fileImport=${fileImportQueued ? '1' : '0'}`
        ].filter(Boolean).join('&');
        return res.redirect(`/admin/migrations/pterodactyl?${query}`);
    } catch (error) {
        console.error('Failed to import migrated server:', error);
        return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent(error.message || 'Failed to import migrated server.'));
    }
});

app.post('/admin/servers', requireAuth, requireAdmin, async (req, res) => {
    const { name, ownerId, imageId, memory, cpu, disk, allocationId, connectorId, dockerImage } = req.body;

    try {
        const parsedMemory = Number.parseInt(memory, 10);
        const parsedCpu = Number.parseInt(cpu, 10);
        const parsedDisk = Number.parseInt(disk, 10);
        const parsedAllocationId = Number.parseInt(allocationId, 10);
        const parsedConnectorId = Number.parseInt(connectorId, 10);
        const smartAllocationEnabled = parseSmartAllocationToggle(req.body.smartAllocation, true);
        const advancedLimits = normalizeServerAdvancedLimits(req.body);

        if (![parsedMemory, parsedCpu, parsedDisk].every(Number.isInteger)) {
            return res.redirect('/admin/servers?error=Memory, CPU, and Disk must be valid numbers.');
        }
        if (!advancedLimits.valid) {
            return res.redirect(`/admin/servers?error=${encodeURIComponent(advancedLimits.error)}`);
        }

        // Validate Image exists
        const image = await Image.findByPk(imageId);
        if (!image) return res.redirect('/admin/servers?error=Image not found.');

        let allocation = null;
        if (smartAllocationEnabled) {
            const freeAllocations = await Allocation.findAll({
                where: { serverId: null },
                include: [{ model: Connector, as: 'connector' }],
                order: [['id', 'ASC']]
            });
            const usageByConnector = await buildConnectorUsageMap(freeAllocations.map((entry) => entry.connectorId));
            const result = pickSmartAllocation({
                allocations: freeAllocations,
                connectorStatusMap: buildEffectiveConnectorStatusMap(freeAllocations.map((entry) => entry.connectorId)),
                usageByConnector,
                requestedMemoryMb: parsedMemory,
                requestedDiskMb: parsedDisk,
                preferredConnectorId: Number.isInteger(parsedConnectorId) && parsedConnectorId > 0 ? parsedConnectorId : 0
            });
            if (!result.ok || !result.best || !result.best.allocation) {
                return res.redirect('/admin/servers?error=' + encodeURIComponent('Smart Allocation could not find a suitable online allocation for requested resources.'));
            }
            allocation = result.best.allocation;
        } else {
            if (!Number.isInteger(parsedAllocationId) || parsedAllocationId <= 0) {
                return res.redirect('/admin/servers?error=Allocation is required when Smart Allocation is disabled.');
            }
            allocation = await Allocation.findByPk(parsedAllocationId, {
                include: [{ model: Connector, as: 'connector' }]
            });
            if (!allocation || allocation.serverId) return res.redirect('/admin/servers?error=Allocation invalid or already taken.');
        }

        // Validate Connector is online
        const effectiveConnectorStatus = buildEffectiveConnectorStatus(allocation.connectorId);
        if (effectiveConnectorStatus.status !== 'online') {
            return res.redirect('/admin/servers?error=Selected node is currently offline. Cannot deploy server.');
        }

        const currentUsage = await getConnectorAllocatedUsage(allocation.connectorId);
        const connectorMemoryMb = allocation.connector.totalMemory * 1024;
        const maxMemoryMb = connectorMemoryMb * (1 + (allocation.connector.memoryOverAllocation || 0) / 100);
        const connectorDiskMb = allocation.connector.totalDisk * 1024;
        const maxDiskMb = connectorDiskMb * (1 + (allocation.connector.diskOverAllocation || 0) / 100);

        if (currentUsage.memoryMb + parsedMemory > maxMemoryMb) {
            return res.redirect(`/admin/servers?error=Not enough memory on the selected node. Max allowed is ${maxMemoryMb} MB.`);
        }

        if (currentUsage.diskMb + parsedDisk > maxDiskMb) {
            return res.redirect(`/admin/servers?error=Not enough disk space on the selected node. Max allowed is ${maxDiskMb} MB.`);
        }

        const imagePorts = resolveImagePorts(image.ports);
        const { resolvedVariables, env } = buildServerEnvironment(image, req.body.variables, {
            SERVER_MEMORY: parsedMemory.toString(),
            SERVER_IP: '0.0.0.0',
            SERVER_PORT: allocation.port.toString()
        });
        const startup = buildStartupCommand(image.startup, env);
        const deploymentPorts = buildDeploymentPorts({
            imagePorts,
            env,
            primaryAllocation: allocation,
            allocations: [allocation]
        });
        const startupMode = shouldUseCommandStartup(image) ? 'command' : 'environment';

        // Create Server
        const containerId = nodeCrypto.randomBytes(4).toString('hex');
        const server = await Server.create({
            name,
            containerId,
            ownerId,
            imageId,
            allocationId: allocation.id,
            memory: parsedMemory,
            cpu: parsedCpu,
            disk: parsedDisk,
            swapLimit: advancedLimits.values.swapLimit,
            ioWeight: advancedLimits.values.ioWeight,
            pidsLimit: advancedLimits.values.pidsLimit,
            oomKillDisable: advancedLimits.values.oomKillDisable,
            oomScoreAdj: advancedLimits.values.oomScoreAdj,
            variables: resolvedVariables,
            dockerImage: dockerImage || image.dockerImage // Use chosen tag or default
        });

        // Link Allocation to Server
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
                        ports: deploymentPorts,
                        mounts: []
                    }
                },
                priority: 10,
                maxAttempts: 3,
                createdByUserId: req.session.user.id
            });
        } catch (queueError) {
            await allocation.update({ serverId: null }).catch(() => {});
            await server.destroy().catch(() => {});
            throw new Error(`Failed to queue deployment job: ${queueError.message}`);
        }

        await server.update({ status: 'installing' });

        res.redirect('/admin/servers?success=' + encodeURIComponent(`Server created and deployment queued as job #${installJob.id}.`));
    } catch (err) {
        console.error("Error creating server:", err);
        res.redirect('/admin/servers?error=Failed to create server: ' + encodeURIComponent(err.message));
    }
});

app.get('/admin/servers/:containerId/manage', requireAuth, requireAdmin, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                { model: User, as: 'owner' },
                { model: Image, as: 'image' },
                { model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] }
            ]
        });

        if (!server) return res.redirect('/admin/servers?error=Server not found.');

        const users = await User.findAll({ attributes: ['id', 'username', 'email'], order: [['username', 'ASC']] });
        const images = await Image.findAll({ order: [['name', 'ASC']] });
        const connectors = await Connector.findAll({
            include: [{ model: Allocation, as: 'allocations' }],
            order: [['name', 'ASC']]
        });

        let connectorStatus = 'offline';
        if (server.allocation && server.allocation.connectorId) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
                connectorStatus = 'online';
            }
        }

        res.render('admin/manage-server', {
            server,
            users,
            images,
            connectors,
            connectorStatus,
            user: req.session.user,
            title: `Manage Server: ${server.name}`,
            path: '/admin/servers'
        });
    } catch (err) {
        console.error("Error fetching server management details:", err);
        res.redirect('/admin/servers?error=Error fetching server details');
    }
});

app.post('/api/admin/servers/:containerId/resource-caps', requireAuth, requireAdmin, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation', include: [{ model: Connector, as: 'connector' }] }]
        });
        if (!server) {
            return res.status(404).json({ success: false, error: 'Server not found.' });
        }

        const parsedMemory = Number.parseInt(req.body.memory, 10);
        const parsedCpu = Number.parseInt(req.body.cpu, 10);
        const parsedDisk = Number.parseInt(req.body.disk, 10);
        if (![parsedMemory, parsedCpu, parsedDisk].every(Number.isInteger)) {
            return res.status(400).json({ success: false, error: 'Memory, CPU and Disk must be valid integers.' });
        }
        if (parsedMemory < 64 || parsedCpu < 10 || parsedDisk < 512) {
            return res.status(400).json({ success: false, error: 'Resource limits are too low.' });
        }

        const advancedLimits = normalizeServerAdvancedLimits({
            swapLimit: req.body.swapLimit,
            ioWeight: req.body.ioWeight,
            pidsLimit: req.body.pidsLimit,
            oomKillDisable: req.body.oomKillDisable,
            oomScoreAdj: req.body.oomScoreAdj
        }, {
            swapLimit: Number.parseInt(server.swapLimit, 10),
            ioWeight: Number.parseInt(server.ioWeight, 10),
            pidsLimit: Number.parseInt(server.pidsLimit, 10),
            oomKillDisable: Boolean(server.oomKillDisable),
            oomScoreAdj: Number.parseInt(server.oomScoreAdj, 10)
        });
        if (!advancedLimits.valid) {
            return res.status(400).json({ success: false, error: advancedLimits.error });
        }

        if (server.allocation && server.allocation.connector) {
            const currentUsage = await getConnectorAllocatedUsage(server.allocation.connectorId);
            const memoryDiff = parsedMemory - (Number.parseInt(server.memory, 10) || 0);
            const diskDiff = parsedDisk - (Number.parseInt(server.disk, 10) || 0);
            const connectorMemoryMb = server.allocation.connector.totalMemory * 1024;
            const maxMemoryMb = connectorMemoryMb * (1 + (server.allocation.connector.memoryOverAllocation || 0) / 100);
            const connectorDiskMb = server.allocation.connector.totalDisk * 1024;
            const maxDiskMb = connectorDiskMb * (1 + (server.allocation.connector.diskOverAllocation || 0) / 100);

            if (memoryDiff > 0 && (currentUsage.memoryMb + memoryDiff) > maxMemoryMb) {
                return res.status(409).json({ success: false, error: `Not enough memory on node. Max allowed is ${Math.floor(maxMemoryMb)} MB.` });
            }
            if (diskDiff > 0 && (currentUsage.diskMb + diskDiff) > maxDiskMb) {
                return res.status(409).json({ success: false, error: `Not enough disk on node. Max allowed is ${Math.floor(maxDiskMb)} MB.` });
            }
        }

        await server.update({
            memory: parsedMemory,
            cpu: parsedCpu,
            disk: parsedDisk,
            swapLimit: advancedLimits.values.swapLimit,
            ioWeight: advancedLimits.values.ioWeight,
            pidsLimit: advancedLimits.values.pidsLimit,
            oomKillDisable: advancedLimits.values.oomKillDisable,
            oomScoreAdj: advancedLimits.values.oomScoreAdj
        });

        let liveApplyDispatched = false;
        if (server.allocation && server.allocation.connectorId) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
                const requestId = `limits_${Date.now()}_${nodeCrypto.randomBytes(3).toString('hex')}`;
                connectorWs.send(JSON.stringify({
                    type: 'apply_resource_limits',
                    serverId: server.id,
                    requestId,
                    memory: parsedMemory,
                    cpu: parsedCpu,
                    disk: parsedDisk,
                    swapLimit: advancedLimits.values.swapLimit,
                    ioWeight: advancedLimits.values.ioWeight,
                    pidsLimit: advancedLimits.values.pidsLimit,
                    oomKillDisable: advancedLimits.values.oomKillDisable,
                    oomScoreAdj: advancedLimits.values.oomScoreAdj
                }));
                liveApplyDispatched = true;
            }
        }

        return res.json({
            success: true,
            message: liveApplyDispatched
                ? 'Resource caps updated and live apply was dispatched to connector.'
                : 'Resource caps updated in panel. Live apply could not be dispatched (connector offline).',
            server: {
                id: server.id,
                containerId: server.containerId,
                memory: server.memory,
                cpu: server.cpu,
                disk: server.disk,
                swapLimit: server.swapLimit,
                ioWeight: server.ioWeight,
                pidsLimit: server.pidsLimit,
                oomKillDisable: Boolean(server.oomKillDisable),
                oomScoreAdj: server.oomScoreAdj
            }
        });
    } catch (error) {
        console.error('Error updating live resource caps:', error);
        return res.status(500).json({ success: false, error: 'Failed to update resource caps.' });
    }
});

app.post('/admin/servers/delete/:containerId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { force } = req.query;
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/admin/servers?error=Server not found.');

        let connectorOnline = false;
        if (server.allocation && server.allocation.connectorId) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
                connectorOnline = true;
            }
        }

        // If not forced and connector is offline, block deletion
        if (force !== 'true' && server.allocation && server.allocation.connectorId && !connectorOnline) {
            return res.redirect(`/admin/servers/${server.containerId}/manage?error=Connector is offline. Delete aborted to prevent residual files. Use forced deletion if absolutely necessary.`);
        }

        // Notify Connector to delete resources if online
        if (connectorOnline) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            connectorWs.send(JSON.stringify({ type: 'delete_server', serverId: server.id }));
            console.log(`Sent delete_server command for server ${server.id} to connector ${server.allocation.connectorId}`);
        } else {
            console.warn(`Connector ${server.allocation && server.allocation.connectorId} is offline, skipping resource deletion command.`);
        }

        // Unlink all allocations assigned to this server.
        await Allocation.update({ serverId: null }, { where: { serverId: server.id } });

        await Settings.destroy({ where: { key: getServerSmartAlertsSettingKey(server.id) } });
        await Settings.destroy({ where: { key: getServerStartupPresetSettingKey(server.id) } });
        await Settings.destroy({ where: { key: getServerPolicyEngineSettingKey(server.id) } });
        consumeServerPowerIntent(server.id);
        RESOURCE_ANOMALY_STATE.delete(server.id);
        RESOURCE_ANOMALY_SAMPLE_TS.delete(server.id);
        PLUGIN_CONFLICT_STATE.delete(server.id);
        serverLogCleanupScheduleState.delete(server.id);
        pendingMigrationFileImports.delete(server.id);
        if (ServerApiKey) {
            await ServerApiKey.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (typeof removeServerMigrationTransferState === 'function') {
            await removeServerMigrationTransferState(server.id).catch(() => {});
        }
        await server.destroy();
        const msg = connectorOnline
            ? 'Server and resources deleted successfully!'
            : 'Server deleted from panel. Resources on connector might remain as it was offline (Forced Delete).';
        res.redirect('/admin/servers?success=' + encodeURIComponent(msg));
    } catch (err) {
        console.error("Error deleting server:", err);
        res.redirect('/admin/servers?error=Failed to delete server.');
    }
});

app.post('/admin/servers/edit/:containerId', requireAuth, requireAdmin, async (req, res) => {
    const { name, ownerId, imageId, allocationId, memory, cpu, disk, dockerImage, startup } = req.body;
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/admin/servers?error=Server not found.');
        const advancedLimits = normalizeServerAdvancedLimits(req.body, {
            swapLimit: Number.parseInt(server.swapLimit, 10),
            ioWeight: Number.parseInt(server.ioWeight, 10),
            pidsLimit: Number.parseInt(server.pidsLimit, 10),
            oomKillDisable: Boolean(server.oomKillDisable),
            oomScoreAdj: Number.parseInt(server.oomScoreAdj, 10)
        });
        if (!advancedLimits.valid) {
            return res.redirect(`/admin/servers/${req.params.containerId}/manage?error=${encodeURIComponent(advancedLimits.error)}`);
        }

        // Validate Image exists if imageId is changed
        let image;
        if (imageId && server.imageId !== parseInt(imageId)) {
            image = await Image.findByPk(imageId);
            if (!image) return res.redirect(`/admin/servers/${req.params.containerId}/manage?error=Image not found.`);
        } else {
            image = await Image.findByPk(server.imageId); // Get current image for defaults
        }

        const parsedMemory = parseInt(memory, 10);
        const parsedCpu = parseInt(cpu, 10);
        const parsedDisk = parseInt(disk, 10);

        const allocation = await Allocation.findOne({
            where: { serverId: server.id },
            include: [{ model: Connector, as: 'connector' }]
        });

        if (allocation && allocation.connector) {
            const currentUsage = await getConnectorAllocatedUsage(allocation.connectorId);
            const memoryDiff = parsedMemory - parseInt(server.memory, 10);
            const diskDiff = parsedDisk - parseInt(server.disk, 10);

            const connectorMemoryMb = allocation.connector.totalMemory * 1024;
            const maxMemoryMb = connectorMemoryMb * (1 + (allocation.connector.memoryOverAllocation || 0) / 100);
            const connectorDiskMb = allocation.connector.totalDisk * 1024;
            const maxDiskMb = connectorDiskMb * (1 + (allocation.connector.diskOverAllocation || 0) / 100);

            if (memoryDiff > 0 && currentUsage.memoryMb + memoryDiff > maxMemoryMb) {
                return res.redirect(`/admin/servers/${req.params.containerId}/manage?error=Not enough memory on the selected node. Max allowed is ${maxMemoryMb} MB.`);
            }

            if (diskDiff > 0 && currentUsage.diskMb + diskDiff > maxDiskMb) {
                return res.redirect(`/admin/servers/${req.params.containerId}/manage?error=Not enough disk space on the selected node. Max allowed is ${maxDiskMb} MB.`);
            }
        }

        await server.update({
            name,
            ownerId,
            imageId,
            memory: parsedMemory,
            cpu: parsedCpu,
            disk: parsedDisk,
            swapLimit: advancedLimits.values.swapLimit,
            ioWeight: advancedLimits.values.ioWeight,
            pidsLimit: advancedLimits.values.pidsLimit,
            oomKillDisable: advancedLimits.values.oomKillDisable,
            oomScoreAdj: advancedLimits.values.oomScoreAdj,
            startup: startup || null
        });

        res.redirect(`/admin/servers/${server.containerId}/manage?success=Server updated successfully!`);
    } catch (err) {
        console.error("Error updating server:", err);
        res.redirect(`/admin/servers/${req.params.containerId}/manage?error=Failed to update server.`);
    }
});

// Suspend Server
app.post('/admin/servers/suspend/:containerId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { reason } = req.body;
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) return res.redirect('/admin/servers?error=Server not found.');
        if (server.isSuspended) return res.redirect(`/admin/servers/${server.containerId}/manage?error=Server is already suspended.`);

        // If the server is running, stop it
        if (server.allocation && server.allocation.connectorId) {
            const connectorWs = connectorConnections.get(server.allocation.connectorId);
            if (connectorWs && connectorWs.readyState === WebSocket.OPEN) {
                rememberServerPowerIntent(server.id, 'stop');
                connectorWs.send(JSON.stringify({ type: 'server_power', serverId: server.id, action: 'stop' }));
            }
        }

        await server.update({ isSuspended: true, status: 'suspended', suspendReason: reason || null });
        server.status = 'suspended';
        sendServerSmartAlert(server, 'suspended', { reason: reason || null });
        res.redirect(`/admin/servers/${server.containerId}/manage?success=Server suspended successfully.`);
    } catch (err) {
        console.error('Error suspending server:', err);
        res.redirect('/admin/servers?error=Failed to suspend server.');
    }
});

// Unsuspend Server
app.post('/admin/servers/unsuspend/:containerId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/admin/servers?error=Server not found.');
        if (!server.isSuspended) return res.redirect(`/admin/servers/${server.containerId}/manage?error=Server is not suspended.`);

        await server.update({ isSuspended: false, status: 'offline' });
        server.status = 'offline';
        sendServerSmartAlert(server, 'unsuspended');
        res.redirect(`/admin/servers/${server.containerId}/manage?success=Server unsuspended successfully.`);
    } catch (err) {
        console.error('Error unsuspending server:', err);
        res.redirect('/admin/servers?error=Failed to unsuspend server.');
    }
});

// Reinstall Server
app.post('/admin/servers/reinstall/:containerId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [
                { model: Allocation, as: 'allocation' },
                { model: Image, as: 'image' }
            ]
        });
        if (!server) return res.redirect('/admin/servers?error=Server not found.');
        if (!server.image) return res.redirect(`/admin/servers/${server.containerId}/manage?error=Server is missing image configuration.`);

        const primaryAllocation = await resolvePrimaryAllocationForServer(server, { includeConnector: true });
        if (!primaryAllocation) return res.redirect(`/admin/servers/${server.containerId}/manage?error=Server primary allocation is missing.`);

        const connectorWs = primaryAllocation.connectorId ? connectorConnections.get(primaryAllocation.connectorId) : null;
        if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
            return res.redirect(`/admin/servers/${server.containerId}/manage?error=Connector is offline. Cannot start reinstall.`);
        }

        const image = server.image;
        const imagePorts = resolveImagePorts(image.ports);
        const { resolvedVariables, env } = buildServerEnvironment(image, server.variables, {
            SERVER_MEMORY: String(server.memory),
            SERVER_IP: '0.0.0.0',
            SERVER_PORT: String(primaryAllocation.port)
        });
        const startup = buildStartupCommand(server.startup || image.startup, env);
        const assignedAllocations = await Allocation.findAll({
            where: { serverId: server.id },
            attributes: ['id', 'ip', 'port'],
            order: [['port', 'ASC']]
        });
        const deploymentPorts = buildDeploymentPorts({
            imagePorts,
            env,
            primaryAllocation,
            allocations: assignedAllocations
        });
        const startupMode = shouldUseCommandStartup(image) ? 'command' : 'environment';
        const mountConfig = typeof getServerMountsForInstall === 'function'
            ? await getServerMountsForInstall(server.id)
            : [];

        const installJob = await jobQueue.enqueue({
            type: 'server.install.dispatch',
            payload: {
                serverId: server.id,
                reinstall: true,
                clearSuspended: true,
                resolvedVariables,
                config: {
                    image: server.dockerImage || image.dockerImage,
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
                    ports: deploymentPorts,
                    mounts: mountConfig
                }
            },
            priority: 10,
            maxAttempts: 3,
            createdByUserId: req.session.user.id
        });

        await server.update({ variables: resolvedVariables, status: 'installing', isSuspended: false });
        res.redirect(`/admin/servers/${server.containerId}/manage?success=${encodeURIComponent(`Reinstall queued as job #${installJob.id}.`)}`);
    } catch (err) {
        console.error('Error reinstalling server:', err);
        res.redirect('/admin/servers?error=Failed to start server reinstall.');
    }
});

}

module.exports = { registerAdminServersRoutes };
