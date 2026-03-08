function registerAdminServersRoutes(ctx) {
    const nodeCrypto = require('node:crypto');
    const nodeFs = require('node:fs');
    const nodePath = require('node:path');
    const { spawn } = require('node:child_process');
    const { Sequelize } = require('sequelize');
    const { pickSmartAllocation } = require('../../core/helpers/smart-allocation');
    const {
        app,
        WebSocket,
        crypto,
        Server,
        ServerApiKey,
        ServerCommandMacro,
        ServerResourceSample,
        ServerSubuser,
        ServerBackupPolicy,
        ServerBackup,
        ServerMount,
        User,
        Image,
        Settings,
        DatabaseHost,
        ServerDatabase,
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

function extractSqlErrorCode(error) {
    if (!error || typeof error !== 'object') return '';
    return String(
        error.code
        || (error.parent && error.parent.code)
        || (error.original && error.original.code)
        || ''
    ).trim();
}

function wrapDatabaseProvisioningError(error, host, dialect) {
    const code = extractSqlErrorCode(error);
    const hostUser = String(host && host.username ? host.username : '').trim() || 'configured-user';
    const hostName = String(host && host.host ? host.host : '').trim() || 'database-host';
    const dbDialect = getDatabaseHostDialect(dialect || (host && host.type));

    if (dbDialect === 'postgres' && (code === '42501' || code.toLowerCase() === 'insufficient_privilege')) {
        return new Error(
            `Database host user "${hostUser}" on ${hostName} lacks PostgreSQL privileges. ` +
            `Required privileges: CREATEDB and CREATEROLE (or a superuser role).`
        );
    }

    if (dbDialect !== 'postgres' && (
        code === 'ER_DBACCESS_DENIED_ERROR'
        || code === 'ER_ACCESS_DENIED_ERROR'
        || code === 'ER_SPECIFIC_ACCESS_DENIED_ERROR'
    )) {
        return new Error(
            `Database host user "${hostUser}" on ${hostName} lacks MySQL/MariaDB privileges to provision databases/users. ` +
            `Use an admin user or grant CREATE, ALTER, DROP, CREATE USER, and GRANT OPTION.`
        );
    }

    return error;
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
        try {
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
        } catch (error) {
            throw wrapDatabaseProvisioningError(error, host, dialect);
        }
    });
}

function sanitizeMigrationExportName(value, fallback = 'database-export') {
    const clean = String(value || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9._-]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, '');
    return clean || fallback;
}

function getMigrationExportDirectory() {
    return nodePath.join(process.cwd(), 'storage', 'migration-db-exports');
}

function resolveMigrationExportPath(filePath) {
    const rawPath = String(filePath || '').trim();
    if (!rawPath) return null;
    const resolvedPath = nodePath.resolve(rawPath);
    const exportRoot = nodePath.resolve(getMigrationExportDirectory());
    if (resolvedPath !== exportRoot && !resolvedPath.startsWith(`${exportRoot}${nodePath.sep}`)) {
        return null;
    }
    return resolvedPath;
}

async function cleanupMigrationExportFiles(entries) {
    if (!Array.isArray(entries) || entries.length === 0) return;
    const seenPaths = new Set();
    for (const entry of entries) {
        const resolvedPath = resolveMigrationExportPath(entry && entry.filePath);
        if (!resolvedPath || seenPaths.has(resolvedPath)) continue;
        seenPaths.add(resolvedPath);
        await nodeFs.promises.unlink(resolvedPath).catch(() => {});
    }
}

async function runSpawnToFile(command, args, outputPath, extraEnv = {}) {
    await nodeFs.promises.mkdir(nodePath.dirname(outputPath), { recursive: true });

    return new Promise((resolve, reject) => {
        const env = { ...process.env, ...extraEnv };
        const child = spawn(command, args, {
            env,
            stdio: ['ignore', 'pipe', 'pipe']
        });

        let stderr = '';
        const output = nodeFs.createWriteStream(outputPath);
        child.stdout.pipe(output);
        child.stderr.on('data', (chunk) => {
            stderr += String(chunk || '');
        });

        const rejectWith = (prefix, error) => {
            output.end(() => {
                reject(new Error(`${prefix}: ${error && error.message ? error.message : error}`));
            });
        };

        child.on('error', (error) => {
            rejectWith(`Failed to run "${command}"`, error);
        });

        child.on('close', (code) => {
            output.end(() => {
                if (code === 0) {
                    resolve();
                    return;
                }
                reject(new Error(`${command} exited with code ${code}. ${stderr.trim()}`.trim()));
            });
        });
    });
}

async function runSpawnFromFile(command, args, inputPath, extraEnv = {}) {
    return new Promise((resolve, reject) => {
        const env = { ...process.env, ...extraEnv };
        const child = spawn(command, args, {
            env,
            stdio: ['pipe', 'ignore', 'pipe']
        });

        let stderr = '';
        child.stderr.on('data', (chunk) => {
            stderr += String(chunk || '');
        });

        const input = nodeFs.createReadStream(inputPath);
        input.on('error', (error) => {
            try {
                child.kill('SIGKILL');
            } catch {
                // ignore
            }
            reject(new Error(`Failed to read SQL file: ${error.message || error}`));
        });
        input.pipe(child.stdin);

        child.on('error', (error) => {
            reject(new Error(`Failed to run "${command}": ${error.message || error}`));
        });

        child.on('close', (code) => {
            if (code === 0) {
                resolve();
                return;
            }
            reject(new Error(`${command} exited with code ${code}. ${stderr.trim()}`.trim()));
        });
    });
}

async function dumpDatabaseToSqlFile(sourceConfig, outputPath) {
    const dialect = getDatabaseHostDialect(sourceConfig && sourceConfig.type);
    const host = String(sourceConfig && sourceConfig.host ? sourceConfig.host : '').trim();
    const username = String(sourceConfig && sourceConfig.username ? sourceConfig.username : '').trim();
    const password = String(sourceConfig && sourceConfig.password ? sourceConfig.password : '');
    const database = String(sourceConfig && sourceConfig.database ? sourceConfig.database : '').trim();
    const port = Math.max(1, Number.parseInt(sourceConfig && sourceConfig.port, 10) || (dialect === 'postgres' ? 5432 : 3306));

    if (!host || !username || !database) {
        throw new Error('Missing source database connection details for SQL export.');
    }

    if (dialect === 'postgres') {
        const args = [
            '--host', host,
            '--port', String(port),
            '--username', username,
            '--format', 'plain',
            '--no-owner',
            '--no-privileges',
            database
        ];
        await runSpawnToFile('pg_dump', args, outputPath, { PGPASSWORD: password });
        return;
    }

    const args = [
        '--host', host,
        '--port', String(port),
        '--user', username,
        '--single-transaction',
        '--quick',
        '--routines',
        '--events',
        '--triggers',
        database
    ];
    await runSpawnToFile('mysqldump', args, outputPath, { MYSQL_PWD: password });
}

async function importSqlFileToDatabase(destinationConfig, inputPath) {
    const dialect = getDatabaseHostDialect(destinationConfig && destinationConfig.type);
    const host = String(destinationConfig && destinationConfig.host ? destinationConfig.host : '').trim();
    const username = String(destinationConfig && destinationConfig.username ? destinationConfig.username : '').trim();
    const password = String(destinationConfig && destinationConfig.password ? destinationConfig.password : '');
    const database = String(destinationConfig && destinationConfig.database ? destinationConfig.database : '').trim();
    const port = Math.max(1, Number.parseInt(destinationConfig && destinationConfig.port, 10) || (dialect === 'postgres' ? 5432 : 3306));

    if (!host || !username || !database) {
        throw new Error('Missing destination database connection details for SQL import.');
    }

    if (dialect === 'postgres') {
        const args = [
            '--host', host,
            '--port', String(port),
            '--username', username,
            '--dbname', database,
            '--set', 'ON_ERROR_STOP=1'
        ];
        await runSpawnFromFile('psql', args, inputPath, { PGPASSWORD: password });
        return;
    }

    const args = [
        '--host', host,
        '--port', String(port),
        '--user', username,
        database
    ];
    await runSpawnFromFile('mysql', args, inputPath, { MYSQL_PWD: password });
}

async function exportDatabaseDataForManualImport({
    sourceConfig,
    exportLabel
}) {
    const exportId = `${Date.now().toString(36)}_${nodeCrypto.randomBytes(4).toString('hex')}`;
    const safeLabel = sanitizeMigrationExportName(exportLabel, 'database');
    const exportFileName = `${safeLabel}-${exportId}.sql`;
    const exportPath = nodePath.join(getMigrationExportDirectory(), exportFileName);

    try {
        await dumpDatabaseToSqlFile(sourceConfig, exportPath);
        return {
            copied: false,
            exportGenerated: true,
            manualImportRequired: true,
            exportId,
            exportPath,
            exportFileName,
            error: null
        };
    } catch (error) {
        await nodeFs.promises.unlink(exportPath).catch(() => {});
        return {
            copied: false,
            exportGenerated: false,
            manualImportRequired: false,
            exportId: null,
            exportPath: null,
            exportFileName: null,
            error: error && error.message ? error.message : String(error)
        };
    }
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
    const found = new Set();
    const patterns = [
        /\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g,
        /\{([A-Za-z0-9_]+)\}/g
    ];

    patterns.forEach((regex) => {
        let match;
        while ((match = regex.exec(text)) !== null) {
            if (match && match[1]) {
                found.add(String(match[1]).trim());
            }
        }
    });
    return Array.from(found);
}

function buildMigrationStartupEnv({ startupTemplate, baseEnv, remoteVariables, remoteStartupCommand }) {
    const env = {
        ...(baseEnv && typeof baseEnv === 'object' ? baseEnv : {})
    };
    const remoteEnv = remoteVariables && typeof remoteVariables === 'object'
        ? remoteVariables
        : {};
    const remoteEnvCi = new Map();
    Object.entries(remoteEnv).forEach(([rawKey, rawValue]) => {
        const normalizedKey = String(rawKey || '').trim().toUpperCase();
        if (!normalizedKey) return;
        remoteEnvCi.set(normalizedKey, rawValue === null || rawValue === undefined ? '' : String(rawValue));
    });
    const startupFromRemote = String(remoteStartupCommand || '').trim();
    const injectedKeys = [];
    const placeholders = extractStartupPlaceholders(startupTemplate);

    placeholders.forEach((key) => {
        const normalizedKey = String(key || '').trim().toUpperCase();
        const directCurrentValue = Object.prototype.hasOwnProperty.call(env, key)
            ? String(env[key] || '').trim()
            : '';
        const ciCurrentValue = directCurrentValue
            || (() => {
                const matchingKey = Object.keys(env).find((candidateKey) => {
                    return String(candidateKey || '').trim().toUpperCase() === normalizedKey;
                });
                if (!matchingKey) return '';
                return String(env[matchingKey] || '').trim();
            })();
        const currentValue = ciCurrentValue;
        if (currentValue) return;

        const remoteValue = Object.prototype.hasOwnProperty.call(remoteEnv, key)
            ? String(remoteEnv[key] || '').trim()
            : (remoteEnvCi.get(normalizedKey) || '').trim();
        if (remoteValue) {
            env[key] = remoteValue;
            injectedKeys.push(key);
            return;
        }

        if ((normalizedKey === 'STARTUPSCRIPT' || normalizedKey === 'STARTUP') && startupFromRemote) {
            env[key] = startupFromRemote;
            injectedKeys.push(key);
        }
    });

    return {
        env,
        injectedKeys: Array.from(new Set(injectedKeys))
    };
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
    const remoteVariableSetCi = new Set(
        remoteVariableKeys.map((key) => String(key || '').trim().toUpperCase()).filter(Boolean)
    );
    const remoteDocker = normalizeDockerCandidate(snapshot && snapshot.dockerImage ? snapshot.dockerImage : '');
    const remoteStartup = String(snapshot && snapshot.startup ? snapshot.startup : '').trim();

    const matrixRows = (Array.isArray(images) ? images : []).map((image) => {
        const imageVariableDefs = resolveImageVariableDefinitions(image);
        const imageVariableKeys = imageVariableDefs
            .map((entry) => String(entry && entry.env_variable ? entry.env_variable : '').trim())
            .filter(Boolean);
        const imageVariableMapCi = new Map();
        imageVariableKeys.forEach((key) => {
            const normalizedKey = String(key || '').trim().toUpperCase();
            if (!normalizedKey || imageVariableMapCi.has(normalizedKey)) return;
            imageVariableMapCi.set(normalizedKey, key);
        });

        const supportedVariables = [];
        const unsupportedVariables = [];
        const previewVariables = {};
        remoteVariableKeys.forEach((remoteKey) => {
            const normalizedRemoteKey = String(remoteKey || '').trim().toUpperCase();
            const mappedImageKey = imageVariableMapCi.get(normalizedRemoteKey);
            if (!mappedImageKey) {
                unsupportedVariables.push(remoteKey);
                return;
            }
            supportedVariables.push(remoteKey);
            previewVariables[mappedImageKey] = remoteVariables[remoteKey];
        });
        const placeholderKeys = extractStartupPlaceholders(image && image.startup ? image.startup : '');
        const unresolvedPlaceholders = placeholderKeys.filter((key) => {
            const normalizedKey = String(key || '').trim().toUpperCase();
            if (remoteVariableSetCi.has(normalizedKey)) return false;
            if (normalizedKey === 'SERVER_MEMORY' || normalizedKey === 'SERVER_PORT' || normalizedKey === 'SERVER_IP') return false;
            if ((normalizedKey === 'STARTUPSCRIPT' || normalizedKey === 'STARTUP') && remoteStartup) return false;
            return true;
        });

        let startupPreviewError = '';
        try {
            const defaultPort = Number.parseInt(snapshot && snapshot.defaultAllocation ? snapshot.defaultAllocation.port : '', 10) || 25565;
            const defaultMemory = Number.parseInt(snapshot && snapshot.memory ? snapshot.memory : '', 10) || 1024;
            const { env: previewEnv } = buildServerEnvironment(image, previewVariables, {
                SERVER_MEMORY: String(defaultMemory),
                SERVER_IP: '0.0.0.0',
                SERVER_PORT: String(defaultPort)
            });
            const { env: previewStartupEnv } = buildMigrationStartupEnv({
                startupTemplate: image && image.startup ? image.startup : '',
                baseEnv: previewEnv,
                remoteVariables,
                remoteStartupCommand: remoteStartup
            });
            buildStartupCommand(image && image.startup ? image.startup : '', previewStartupEnv);
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
        const migrationExports = req.session && Array.isArray(req.session.pterodactylMigrationExports)
            ? req.session.pterodactylMigrationExports
                .filter((entry) => entry && typeof entry === 'object')
                .map((entry) => ({
                    id: String(entry.id || '').trim(),
                    fileName: String(entry.fileName || '').trim(),
                    databaseName: String(entry.databaseName || '').trim(),
                    createdAt: entry.createdAt || null
                }))
                .filter((entry) => entry.id && entry.fileName)
            : [];
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
            migrationExports,
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

app.get('/admin/migrations/pterodactyl/exports/:exportId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const exportId = String(req.params.exportId || '').trim();
        if (!exportId) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Invalid export id.'));
        }

        const exportsList = req.session && Array.isArray(req.session.pterodactylMigrationExports)
            ? req.session.pterodactylMigrationExports
            : [];
        const entry = exportsList.find((item) => String(item && item.id || '').trim() === exportId);
        if (!entry) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Export file is no longer available in this session.'));
        }

        const filePath = resolveMigrationExportPath(entry.filePath);
        const fileName = String(entry.fileName || '').trim() || `database-export-${exportId}.sql`;
        if (!filePath) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Export file path is invalid or outside export directory.'));
        }
        await nodeFs.promises.access(filePath, nodeFs.constants.R_OK);
        return res.download(filePath, fileName);
    } catch (error) {
        return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent(error.message || 'Failed to download SQL export.'));
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
        await cleanupMigrationExportFiles(req.session.pterodactylMigrationExports || []);
        req.session.pterodactylMigrationExports = [];
        await new Promise((resolve) => req.session.save(resolve));
        return res.redirect('/admin/migrations/pterodactyl?success=' + encodeURIComponent('Remote server fetched successfully. Continue with import step.'));
    } catch (error) {
        console.error('Failed to fetch Pterodactyl server for migration:', error);
        return res.redirect(`/admin/migrations/pterodactyl?error=${encodeURIComponent(error.message || 'Failed to fetch remote server data.')}`);
    }
});

app.post('/admin/migrations/pterodactyl/import', requireAuth, requireAdmin, async (req, res) => {
    let createdServer = null;
    let installJobQueued = false;
    const claimedAllocationIds = new Set();
    try {
        const requestedMigrationToken = String(req.body.migrationToken || '').trim();
        const sessionDraft = req.session && req.session.pterodactylMigrationDraft && typeof req.session.pterodactylMigrationDraft === 'object'
            ? req.session.pterodactylMigrationDraft
            : null;
        const sessionMigrationToken = sessionDraft ? String(sessionDraft.migrationToken || '').trim() : '';

        if (sessionMigrationToken) {
            if (!requestedMigrationToken) {
                return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Migration token is missing. Please re-run fetch step.'));
            }
            if (requestedMigrationToken !== sessionMigrationToken) {
                return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Migration token mismatch. Please fetch remote server again.'));
            }
        }

        const snapshot = sessionDraft && sessionDraft.migrationSnapshot && typeof sessionDraft.migrationSnapshot === 'object'
            ? sessionDraft.migrationSnapshot
            : decodeMigrationSnapshot(requestedMigrationToken);
        const ownerId = Number.parseInt(req.body.ownerId, 10);
        const imageId = req.body.imageId;
        const connectorId = Number.parseInt(req.body.connectorId, 10);
        const allocationId = Number.parseInt(req.body.allocationId, 10);
        const importFiles = parseBooleanInput(req.body.importFiles, false);
        const sourceSftpHost = String(req.body.sourceSftpHost || '').trim();
        const sourceSftpPort = Number.parseInt(req.body.sourceSftpPort, 10) || 2022;
        const sourceSftpUsername = String(req.body.sourceSftpUsername || '').trim();
        const sourceSftpPassword = String(req.body.sourceSftpPassword || '').trim();
        const sourceSftpPathRaw = String(req.body.sourceSftpPath || '').trim();
        const sourceSftpPath = sourceSftpPathRaw ? sourceSftpPathRaw : '/';
        const sourceCleanTarget = parseBooleanInput(req.body.sourceCleanTarget, false);
        const copyDatabaseData = parseBooleanInput(req.body.copyDatabaseData, false);
        const sourceDbHostFallback = String(req.body.sourceDbHost || '').trim();
        const parsedSourceDbPortFallback = Number.parseInt(req.body.sourceDbPort, 10);
        const sourceDbPortFallback = Number.isInteger(parsedSourceDbPortFallback) && parsedSourceDbPortFallback > 0
            ? parsedSourceDbPortFallback
            : null;
        const sourceDbAdminUser = String(req.body.sourceDbAdminUser || '').trim();
        const sourceDbAdminPassword = String(req.body.sourceDbAdminPassword || '').trim();

        if (!snapshot || typeof snapshot !== 'object') {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Migration snapshot is invalid. Please re-fetch the remote server first.'));
        }

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
        if (copyDatabaseData) {
            if (!sourceDbAdminUser || !sourceDbAdminPassword) {
                return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Database SQL export is enabled, but source DB admin username/password is missing.'));
            }
            if (sourceDbPortFallback !== null && (sourceDbPortFallback < 1 || sourceDbPortFallback > 65535)) {
                return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Source DB port must be between 1 and 65535.'));
            }
        }

        const owner = await User.findByPk(ownerId, { attributes: ['id'] });
        if (!owner) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected owner user does not exist.'));
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
        if (Number.isInteger(connectorId) && connectorId > 0 && Number.parseInt(allocation.connectorId, 10) !== connectorId) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected allocation does not belong to selected connector.'));
        }

        const effectiveConnectorStatus = buildEffectiveConnectorStatus(allocation.connectorId);
        if (effectiveConnectorStatus.status !== 'online') {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected connector is offline.'));
        }

        const memory = Number.parseInt(req.body.memory, 10) || Number.parseInt(snapshot.memory, 10) || 1024;
        const cpu = Number.parseInt(req.body.cpu, 10) || Number.parseInt(snapshot.cpu, 10) || 100;
        const disk = Number.parseInt(req.body.disk, 10) || Number.parseInt(snapshot.disk, 10) || 10240;
        const remoteAllocations = Array.isArray(snapshot.allocations) ? snapshot.allocations : [];
        const remoteDatabases = Array.isArray(snapshot.databases) ? snapshot.databases : [];
        const remoteDatabaseLimit = Math.max(
            remoteDatabases.length,
            Number.parseInt(snapshot && snapshot.featureLimits && snapshot.featureLimits.databases, 10) || 0
        );

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
        const allowedVariableKeyMapCi = new Map();
        variableDefinitions.forEach((entry) => {
            const key = String(entry && entry.env_variable ? entry.env_variable : '').trim();
            if (!key) return;
            const normalizedKey = key.toUpperCase();
            if (!allowedVariableKeyMapCi.has(normalizedKey)) {
                allowedVariableKeyMapCi.set(normalizedKey, key);
            }
        });
        const migratedVariables = {};
        const ignoredVariables = [];
        Object.entries(remoteVariables).forEach(([key, value]) => {
            const normalizedKey = String(key || '').trim().toUpperCase();
            const mappedKey = allowedVariableKeyMapCi.get(normalizedKey);
            if (mappedKey) {
                migratedVariables[mappedKey] = value;
            } else {
                ignoredVariables.push(key);
            }
        });

        const remoteStartup = String(snapshot.startup || '').trim();
        const startupVariableFallbackKeys = [];
        if (remoteStartup) {
            variableDefinitions.forEach((entry) => {
                const key = String(entry && entry.env_variable ? entry.env_variable : '').trim();
                if (!key) return;
                const normalizedKey = key.toUpperCase();
                if (normalizedKey !== 'STARTUP' && normalizedKey !== 'STARTUPSCRIPT') return;

                const currentValue = Object.prototype.hasOwnProperty.call(migratedVariables, key)
                    ? String(migratedVariables[key] || '').trim()
                    : '';
                if (currentValue) return;

                migratedVariables[key] = remoteStartup;
                startupVariableFallbackKeys.push(key);
            });
        }

        const { resolvedVariables, env } = buildServerEnvironment(image, migratedVariables, {
            SERVER_MEMORY: String(memory),
            SERVER_IP: '0.0.0.0',
            SERVER_PORT: String(allocation.port)
        });
        const startupTemplate = String(image.startup || '').trim() || String(snapshot.startup || '').trim();
        if (!startupTemplate) {
            return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent('Selected image has no startup template and remote startup is empty.'));
        }
        const { env: startupEnv, injectedKeys: startupTemplateFallbackKeys } = buildMigrationStartupEnv({
            startupTemplate,
            baseEnv: env,
            remoteVariables,
            remoteStartupCommand: snapshot.startup
        });
        const injectedStartupFallbackKeys = Array.from(new Set([
            ...startupVariableFallbackKeys,
            ...startupTemplateFallbackKeys
        ]));
        const startup = buildStartupCommand(startupTemplate, startupEnv);
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
        createdServer = await Server.create({
            name: String(req.body.name || snapshot.name || 'Imported Server').trim() || 'Imported Server',
            containerId,
            ownerId,
            imageId: image.id,
            allocationId: allocation.id,
            memory,
            cpu,
            disk,
            databaseLimit: remoteDatabaseLimit,
            swapLimit: Number.parseInt(snapshot.swap, 10) || 0,
            ioWeight: Number.parseInt(snapshot.io, 10) || 500,
            pidsLimit: 512,
            oomKillDisable: false,
            oomScoreAdj: 0,
            variables: resolvedVariables,
            dockerImage: nextDockerImage
        });

        await allocation.update({ serverId: createdServer.id });
        claimedAllocationIds.add(Number.parseInt(allocation.id, 10));

        const allocationAssignmentSummary = {
            assigned: 0,
            skipped: 0
        };
        if (remoteAllocations.length > 0) {
            const seenRemote = new Set();
            for (const remoteAlloc of remoteAllocations) {
                if (!remoteAlloc) continue;
                const ip = String(remoteAlloc.ip || '').trim();
                const port = Number.parseInt(remoteAlloc.port, 10);
                if (!ip || !Number.isInteger(port)) continue;
                const signature = `${ip}:${port}`;
                if (seenRemote.has(signature)) continue;
                seenRemote.add(signature);

                const isDefault = Boolean(remoteAlloc.isDefault)
                    || (allocation.ip === ip && Number.parseInt(allocation.port, 10) === port);
                if (isDefault) continue;

                const localAlloc = await Allocation.findOne({
                    where: {
                        connectorId: allocation.connectorId,
                        ip,
                        port
                    }
                });
                if (!localAlloc || (localAlloc.serverId && Number.parseInt(localAlloc.serverId, 10) !== Number.parseInt(createdServer.id, 10))) {
                    allocationAssignmentSummary.skipped += 1;
                    continue;
                }

                if (Number.parseInt(localAlloc.id, 10) === Number.parseInt(createdServer.allocationId, 10)) {
                    continue;
                }

                await localAlloc.update({ serverId: createdServer.id });
                claimedAllocationIds.add(Number.parseInt(localAlloc.id, 10));
                allocationAssignmentSummary.assigned += 1;
            }
        }

        const generatedDbExports = [];
        const databaseProvisionSummary = {
            created: 0,
            skipped: 0,
            errors: [],
            renamed: 0,
            passwordGenerated: 0,
            dataCopied: 0,
            dataCopyFailed: 0,
            dataExported: 0
        };
        if (remoteDatabases.length > 0 && DatabaseHost && ServerDatabase) {
            const locationId = allocation.connector ? Number.parseInt(allocation.connector.locationId, 10) : 0;
            const hosts = locationId > 0
                ? await DatabaseHost.findAll({ where: { locationId }, order: [['name', 'ASC']] })
                : [];

            if (!hosts || hosts.length === 0) {
                databaseProvisionSummary.skipped = remoteDatabases.length;
                databaseProvisionSummary.errors.push('No database host configured for the selected connector location.');
            } else {
                const hostUsageCache = new Map();

                for (const remoteDb of remoteDatabases) {
                    const remoteName = String(remoteDb && remoteDb.name ? remoteDb.name : '').trim();
                    if (!remoteName) continue;

                    const preferredType = String(remoteDb && remoteDb.host && remoteDb.host.type ? remoteDb.host.type : '').trim().toLowerCase();
                    const selectedHost = preferredType
                        ? (hosts.find((host) => getDatabaseHostDialect(host.type) === getDatabaseHostDialect(preferredType)) || hosts[0])
                        : hosts[0];
                    if (!selectedHost) {
                        databaseProvisionSummary.skipped += 1;
                        continue;
                    }

                    if (!hostUsageCache.has(selectedHost.id)) {
                        const entries = await ServerDatabase.findAll({
                            where: { databaseHostId: selectedHost.id },
                            attributes: ['name', 'username']
                        });
                        hostUsageCache.set(selectedHost.id, {
                            usedNames: new Set(entries.map((entry) => String(entry.name || '').toLowerCase())),
                            usedUsers: new Set(entries.map((entry) => String(entry.username || '').toLowerCase()))
                        });
                    }

                    const cache = hostUsageCache.get(selectedHost.id);
                    const maxDbNameLen = getDatabaseNameMaxLen(selectedHost.type);
                    const maxDbUserLen = getDatabaseUserMaxLen(selectedHost.type);

                    const remotePreferredName = sanitizeDatabaseObjectName(remoteName, `s${createdServer.id}_db`, maxDbNameLen);
                    const remotePreferredUser = sanitizeDatabaseObjectName(remoteDb.username || remoteName, `u${createdServer.id}_user`, maxDbUserLen);

                    const databaseName = buildUniqueDatabaseObjectName(remotePreferredName, cache.usedNames, maxDbNameLen);
                    const databaseUser = buildUniqueDatabaseObjectName(remotePreferredUser, cache.usedUsers, maxDbUserLen);
                    if (String(databaseName).toLowerCase() !== String(remotePreferredName).toLowerCase()
                        || String(databaseUser).toLowerCase() !== String(remotePreferredUser).toLowerCase()) {
                        databaseProvisionSummary.renamed += 1;
                    }
                    cache.usedNames.add(String(databaseName).toLowerCase());
                    cache.usedUsers.add(String(databaseUser).toLowerCase());

                    const remotePassword = String(remoteDb && remoteDb.password ? remoteDb.password : '').trim();
                    const databasePassword = remotePassword || nodeCrypto.randomBytes(12).toString('base64url').slice(0, 20);
                    if (!remotePassword) {
                        databaseProvisionSummary.passwordGenerated += 1;
                    }

                    try {
                        await provisionServerDatabaseOnHost(selectedHost, {
                            databaseName,
                            databaseUser,
                            databasePassword
                        });

                        await ServerDatabase.create({
                            serverId: createdServer.id,
                            databaseHostId: selectedHost.id,
                            name: databaseName,
                            username: databaseUser,
                            password: databasePassword,
                            remoteDatabaseId: remoteDb && remoteDb.id ? `pterodactyl:${remoteDb.id}` : null
                        });
                        databaseProvisionSummary.created += 1;

                        if (copyDatabaseData) {
                            const sourceHost = String(
                                (remoteDb && remoteDb.host && remoteDb.host.host)
                                || sourceDbHostFallback
                                || ''
                            ).trim();
                            const sourcePort = Math.max(
                                1,
                                Number.parseInt(
                                    (remoteDb && remoteDb.host && remoteDb.host.port)
                                    || sourceDbPortFallback
                                    || (getDatabaseHostDialect(remoteDb && remoteDb.host && remoteDb.host.type) === 'postgres' ? 5432 : 3306),
                                    10
                                ) || (getDatabaseHostDialect(remoteDb && remoteDb.host && remoteDb.host.type) === 'postgres' ? 5432 : 3306)
                            );
                            const sourceType = getDatabaseHostDialect(
                                remoteDb && remoteDb.host && remoteDb.host.type
                                    ? remoteDb.host.type
                                    : selectedHost.type
                            );

                            if (!sourceHost) {
                                databaseProvisionSummary.dataCopyFailed += 1;
                                databaseProvisionSummary.errors.push(`Database "${remoteName}" SQL export failed: source DB host is missing.`);
                            } else {
                                const sourceConfig = {
                                    type: sourceType,
                                    host: sourceHost,
                                    port: sourcePort,
                                    username: sourceDbAdminUser,
                                    password: sourceDbAdminPassword,
                                    database: remoteName
                                };
                                const result = await exportDatabaseDataForManualImport({
                                    sourceConfig,
                                    exportLabel: `${createdServer.id}-${remoteName}`
                                }).catch((copyError) => ({
                                    copied: false,
                                    exportGenerated: false,
                                    manualImportRequired: false,
                                    exportId: null,
                                    exportPath: null,
                                    exportFileName: null,
                                    error: copyError && copyError.message ? copyError.message : String(copyError)
                                }));

                                if (result.exportGenerated && result.exportId && result.exportPath && result.exportFileName) {
                                    const stat = await nodeFs.promises.stat(result.exportPath).catch(() => null);
                                    generatedDbExports.push({
                                        id: result.exportId,
                                        filePath: result.exportPath,
                                        fileName: result.exportFileName,
                                        databaseName: remoteName,
                                        sizeBytes: stat ? Number(stat.size || 0) : 0,
                                        createdAt: new Date().toISOString()
                                    });
                                    databaseProvisionSummary.dataExported += 1;
                                } else {
                                    databaseProvisionSummary.dataCopyFailed += 1;
                                    databaseProvisionSummary.errors.push(`Database "${remoteName}" SQL export failed: ${result.error || 'unknown error'}`);
                                }
                            }
                        }
                    } catch (dbError) {
                        databaseProvisionSummary.errors.push(`Database "${remoteName}" failed: ${dbError.message || dbError}`);
                        databaseProvisionSummary.skipped += 1;
                    }
                }
            }
        }

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
            skipInstallationScript: fileImportQueued,
            configFiles: image.configFiles || null,
            brandName: String((res.locals.settings && res.locals.settings.brandName) || 'cpanel'),
            startAfterInstall: false,
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
            installJobQueued = true;
        } catch (queueError) {
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

        const warningFragments = [];
        if (ignoredVariables.length > 0) {
            warningFragments.push(`Ignored ${ignoredVariables.length} variables not supported by selected image: ${ignoredVariables.slice(0, 8).join(', ')}`);
        }
        if (injectedStartupFallbackKeys.length > 0) {
            warningFragments.push(`Startup fallback variables injected during migration: ${injectedStartupFallbackKeys.join(', ')}`);
        }
        if (allocationAssignmentSummary.assigned > 0 || allocationAssignmentSummary.skipped > 0) {
            warningFragments.push(`Additional allocations migrated: ${allocationAssignmentSummary.assigned} assigned, ${allocationAssignmentSummary.skipped} skipped.`);
        }
        if (databaseProvisionSummary.created > 0 || databaseProvisionSummary.skipped > 0 || databaseProvisionSummary.errors.length > 0) {
            warningFragments.push(`Databases migrated: ${databaseProvisionSummary.created} created, ${databaseProvisionSummary.skipped} skipped.`);
            if (databaseProvisionSummary.renamed > 0) {
                warningFragments.push(`Database credentials renamed for ${databaseProvisionSummary.renamed} entry/entries (name or username conflict on destination host).`);
            }
            if (databaseProvisionSummary.passwordGenerated > 0) {
                warningFragments.push(`Generated new password for ${databaseProvisionSummary.passwordGenerated} database user(s) because source password was not available via API.`);
            }
            if (copyDatabaseData) {
                warningFragments.push(`Database SQL exports: ${databaseProvisionSummary.dataExported} generated, ${databaseProvisionSummary.dataCopyFailed} failed.`);
                if (databaseProvisionSummary.dataExported > 0) {
                    warningFragments.push('Import exported SQL files manually from the migration page.');
                }
            }
            if (databaseProvisionSummary.errors.length > 0) {
                warningFragments.push(databaseProvisionSummary.errors.slice(0, 2).join(' | '));
            }
        }
        const warning = warningFragments.length > 0
            ? `Imported with warnings. ${warningFragments.join(' ')}`
            : '';
        const fileImportNotice = fileImportQueued
            ? ' File import via SFTP is queued and will start automatically after install finishes.'
            : '';
        const jobNotice = ` Deployment job #${installJob.id} queued.`;
        const startNotice = ' Server was imported in stopped state (no auto-start).';
        delete req.session.pterodactylMigrationDraft;
        await cleanupMigrationExportFiles(req.session.pterodactylMigrationExports || []);
        req.session.pterodactylMigrationExports = generatedDbExports;
        await new Promise((resolve) => req.session.save(resolve));
        const query = [
            `success=${encodeURIComponent(`Server "${createdServer.name}" imported and deployment prepared.${jobNotice}${startNotice}${fileImportNotice}`)}`,
            warning ? `warning=${encodeURIComponent(warning)}` : '',
            `jobId=${encodeURIComponent(String(installJob.id))}`,
            `serverId=${encodeURIComponent(String(createdServer.id))}`,
            `fileImport=${fileImportQueued ? '1' : '0'}`
        ].filter(Boolean).join('&');
        return res.redirect(`/admin/migrations/pterodactyl?${query}`);
    } catch (error) {
        if (createdServer && !installJobQueued) {
            const serverId = Number.parseInt(createdServer.id, 10);
            if (Number.isInteger(serverId) && serverId > 0) {
                if (ServerDatabase && typeof ServerDatabase.destroy === 'function') {
                    await ServerDatabase.destroy({
                        where: { serverId }
                    }).catch(() => {});
                }

                if (Allocation && typeof Allocation.update === 'function') {
                    for (const allocationId of claimedAllocationIds) {
                        const parsedAllocationId = Number.parseInt(allocationId, 10);
                        if (!Number.isInteger(parsedAllocationId) || parsedAllocationId <= 0) continue;
                        await Allocation.update(
                            { serverId: null },
                            {
                                where: {
                                    id: parsedAllocationId,
                                    serverId
                                }
                            }
                        ).catch(() => {});
                    }
                }

                if (typeof removeServerMigrationTransferState === 'function') {
                    await removeServerMigrationTransferState(serverId).catch(() => {});
                }
            }

            if (createdServer && typeof createdServer.destroy === 'function') {
                await createdServer.destroy().catch(() => {});
            }
        }

        console.error('Failed to import migrated server:', error);
        return res.redirect('/admin/migrations/pterodactyl?error=' + encodeURIComponent(error.message || 'Failed to import migrated server.'));
    }
});

app.post('/admin/servers', requireAuth, requireAdmin, async (req, res) => {
    const { name, description, ownerId, imageId, memory, cpu, disk, allocationId, connectorId, dockerImage } = req.body;

    try {
        const safeDescriptionRaw = String(description || '').trim();
        const safeDescription = safeDescriptionRaw.length > 0 ? safeDescriptionRaw : null;
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
        if (safeDescriptionRaw.length > 50) {
            return res.redirect('/admin/servers?error=' + encodeURIComponent('Description must be at most 50 characters.'));
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
            description: safeDescription,
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

app.get('/api/admin/servers/:containerId/delete-preview', requireAuth, requireAdmin, async (req, res) => {
    try {
        const server = await Server.findOne({
            where: { containerId: req.params.containerId },
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) {
            return res.status(404).json({ success: false, error: 'Server not found.' });
        }

        const connectorOnline = Boolean(
            server.allocation
            && server.allocation.connectorId
            && connectorConnections.has(server.allocation.connectorId)
            && connectorConnections.get(server.allocation.connectorId).readyState === WebSocket.OPEN
        );

        const [
            subusersCount,
            backupsCount,
            databasesCount,
            apiKeysCount,
            macrosCount,
            timelineSamplesCount
        ] = await Promise.all([
            ServerSubuser ? ServerSubuser.count({ where: { serverId: server.id } }) : 0,
            ServerBackup ? ServerBackup.count({ where: { serverId: server.id } }) : 0,
            ServerDatabase ? ServerDatabase.count({ where: { serverId: server.id } }) : 0,
            ServerApiKey ? ServerApiKey.count({ where: { serverId: server.id } }) : 0,
            ServerCommandMacro ? ServerCommandMacro.count({ where: { serverId: server.id } }) : 0,
            ServerResourceSample ? ServerResourceSample.count({ where: { serverId: server.id } }) : 0
        ]);

        return res.json({
            success: true,
            server: {
                id: server.id,
                containerId: server.containerId,
                name: server.name || `Server #${server.id}`
            },
            connectorOnline,
            canSafeDelete: connectorOnline,
            counts: {
                subusers: subusersCount,
                backups: backupsCount,
                databases: databasesCount,
                apiKeys: apiKeysCount,
                macros: macrosCount,
                timelineSamples: timelineSamplesCount
            }
        });
    } catch (error) {
        console.error('Error loading delete preview:', error);
        return res.status(500).json({ success: false, error: 'Failed to load delete preview.' });
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
        if (ServerCommandMacro) {
            await ServerCommandMacro.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (ServerResourceSample) {
            await ServerResourceSample.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (ServerMount) {
            await ServerMount.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (ServerSubuser) {
            await ServerSubuser.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (ServerBackupPolicy) {
            await ServerBackupPolicy.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (ServerBackup) {
            await ServerBackup.destroy({ where: { serverId: server.id } }).catch(() => {});
        }
        if (typeof ServerDatabase !== 'undefined' && ServerDatabase) {
            await ServerDatabase.destroy({ where: { serverId: server.id } }).catch(() => {});
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
    const { name, description, ownerId, imageId, allocationId, memory, cpu, disk, dockerImage, startup } = req.body;
    try {
        const safeDescriptionRaw = String(description || '').trim();
        const safeDescription = safeDescriptionRaw.length > 0 ? safeDescriptionRaw : null;
        const server = await Server.findOne({ where: { containerId: req.params.containerId } });
        if (!server) return res.redirect('/admin/servers?error=Server not found.');
        if (safeDescriptionRaw.length > 50) {
            return res.redirect(`/admin/servers/${req.params.containerId}/manage?error=${encodeURIComponent('Description must be at most 50 characters.')}`);
        }
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
            description: safeDescription,
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
