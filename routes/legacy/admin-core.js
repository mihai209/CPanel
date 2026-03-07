function registerAdminCoreRoutes(ctx) {
    for (const [key, value] of Object.entries(ctx || {})) {
        try {
            globalThis[key] = value;
        } catch {
            // Ignore non-writable globals (e.g. crypto on newer Node versions).
        }
    }
const REDIS_SETTING_KEYS = [
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
const nodeFs = require('fs');
const nodeFsPromises = nodeFs.promises;
const nodePath = require('path');
const getGoogleTokenSettingKey = (userId) => {
    const parsed = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsed) || parsed <= 0) return '';
    return `oauth_google_tokens_user_${parsed}`;
};
const LANG_DIRECTORY = nodePath.join(process.cwd(), 'public', 'lang');
const MAX_LANGUAGE_JSON_SIZE_BYTES = 2 * 1024 * 1024;

const toRedisBoolString = (value) => (
    value === true || value === 'true' || value === '1' || value === 1 || value === 'on'
        ? 'true'
        : 'false'
);

const toRedisInt = (value, fallback, min, max) => {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
};

const sanitizeLanguageCode = (value) => {
    const trimmed = String(value || '').trim().replace(/\.json$/i, '');
    const normalized = trimmed.toLowerCase();
    if (!/^[a-z0-9_-]{2,40}$/.test(normalized)) return '';
    return normalized;
};

const sanitizeLanguageFilename = (value) => {
    const base = nodePath.basename(String(value || '').trim());
    if (!/^[a-z0-9_-]{2,40}\.json$/i.test(base)) return '';
    return base.toLowerCase();
};

const ensureLanguageDirectory = async () => {
    await nodeFsPromises.mkdir(LANG_DIRECTORY, { recursive: true });
};

const readLanguageCatalog = async () => {
    await ensureLanguageDirectory();
    const entries = await nodeFsPromises.readdir(LANG_DIRECTORY, { withFileTypes: true });
    const files = entries
        .filter((entry) => entry && entry.isFile() && entry.name && entry.name.toLowerCase().endsWith('.json'))
        .map((entry) => entry.name)
        .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

    const languages = [];
    for (const fileName of files) {
        const filePath = nodePath.join(LANG_DIRECTORY, fileName);
        const stat = await nodeFsPromises.stat(filePath);
        let valid = true;
        let keyCount = 0;
        try {
            const parsed = JSON.parse(await nodeFsPromises.readFile(filePath, 'utf8'));
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                keyCount = Object.keys(parsed).length;
            } else {
                valid = false;
            }
        } catch {
            valid = false;
        }
        languages.push({
            fileName,
            languageCode: fileName.replace(/\.json$/i, ''),
            sizeBytes: Number(stat.size || 0),
            updatedAtMs: Number(stat.mtimeMs || Date.now()),
            valid,
            keyCount
        });
    }
    return languages;
};

const normalizeRedisSessionPrefix = (value) => {
    const normalized = String(value || '').trim();
    return normalized || 'cpanel:sess:';
};

const getStoredRedisConfig = async () => {
    const rows = await Settings.findAll({ where: { key: REDIS_SETTING_KEYS } });
    const map = {};
    rows.forEach((row) => {
        if (!row || !row.key) return;
        map[row.key] = row.value;
    });

    const hasAny = REDIS_SETTING_KEYS.some((key) => map[key] !== undefined && map[key] !== null && String(map[key]).trim() !== '');
    if (!hasAny) return null;

    if (typeof normalizeRedisConfig === 'function') {
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

    return {
        enabled: toRedisBoolString(map.redisEnabled) === 'true',
        url: String(map.redisUrl || '').trim(),
        host: String(map.redisHost || '127.0.0.1').trim(),
        port: toRedisInt(map.redisPort, 6379, 1, 65535),
        db: toRedisInt(map.redisDb, 0, 0, 16),
        username: String(map.redisUsername || '').trim(),
        password: String(map.redisPassword || '').trim(),
        tls: toRedisBoolString(map.redisTls) === 'true',
        sessionPrefix: normalizeRedisSessionPrefix(map.redisSessionPrefix),
        mode: String(map.redisUrl || '').trim() ? 'url' : 'host'
    };
};

const persistRedisConfig = async (config) => {
    const payload = {
        redisEnabled: toRedisBoolString(config && config.enabled),
        redisUrl: String(config && config.url || '').trim(),
        redisHost: String(config && config.host || '127.0.0.1').trim(),
        redisPort: String(toRedisInt(config && config.port, 6379, 1, 65535)),
        redisDb: String(toRedisInt(config && config.db, 0, 0, 16)),
        redisUsername: String(config && config.username || '').trim(),
        redisPassword: String(config && config.password || '').trim(),
        redisTls: toRedisBoolString(config && config.tls),
        redisSessionPrefix: normalizeRedisSessionPrefix(config && config.sessionPrefix)
    };

    for (const [key, value] of Object.entries(payload)) {
        await Settings.upsert({ key, value });
    }
    return payload;
};

const buildRedisConfigFromBody = (body, existingConfig = null) => {
    const existing = existingConfig && typeof existingConfig === 'object' ? existingConfig : {};
    const keepExistingPassword = String(body.redisKeepPassword || '1').trim() !== '0';
    const clearPassword = toRedisBoolString(body.redisClearPassword) === 'true';
    const passwordInput = String(body.redisPassword || '').trim();
    let password = passwordInput;

    if (!passwordInput && keepExistingPassword) {
        password = String(existing.password || '').trim();
    }
    if (clearPassword) {
        password = '';
    }

    const payload = {
        enabled: body.redisEnabled,
        url: body.redisUrl,
        host: body.redisHost,
        port: body.redisPort,
        db: body.redisDb,
        username: body.redisUsername,
        password,
        tls: body.redisTls,
        sessionPrefix: body.redisSessionPrefix
    };

    if (typeof normalizeRedisConfig === 'function') {
        return normalizeRedisConfig(payload, { fallbackToEnv: false });
    }

    const url = String(payload.url || '').trim();
    return {
        enabled: toRedisBoolString(payload.enabled) === 'true',
        url,
        host: String(payload.host || '127.0.0.1').trim(),
        port: toRedisInt(payload.port, 6379, 1, 65535),
        db: toRedisInt(payload.db, 0, 0, 16),
        username: String(payload.username || '').trim(),
        password: String(payload.password || '').trim(),
        tls: toRedisBoolString(payload.tls) === 'true',
        sessionPrefix: normalizeRedisSessionPrefix(payload.sessionPrefix),
        mode: url ? 'url' : 'host'
    };
};

const findRedisServerSuggestions = async () => {
    try {
        const servers = await Server.findAll({
            attributes: ['id', 'name', 'containerId'],
            include: [
                { model: Image, as: 'image', attributes: ['name', 'dockerImage'] },
                {
                    model: Allocation,
                    as: 'allocation',
                    attributes: ['ip', 'port'],
                    include: [{ model: Connector, as: 'connector', attributes: ['fqdn'] }]
                }
            ],
            order: [['createdAt', 'DESC']]
        });

        return servers
            .map((server) => {
                const imageName = String(server && server.image && server.image.name || '').toLowerCase();
                const dockerImage = String(server && server.image && server.image.dockerImage || '').toLowerCase();
                const isRedis = imageName.includes('redis') || dockerImage.includes('redis');
                if (!isRedis) return null;

                const allocationIp = String(server && server.allocation && server.allocation.ip || '').trim();
                const connectorFqdn = String(
                    server && server.allocation && server.allocation.connector && server.allocation.connector.fqdn || ''
                ).trim();
                const host = connectorFqdn || allocationIp;
                const port = Number.parseInt(server && server.allocation && server.allocation.port, 10) || 6379;
                if (!host) return null;

                return {
                    id: server.id,
                    name: server.name,
                    containerId: server.containerId,
                    host,
                    port,
                    label: `${server.name} (${host}:${port})`
                };
            })
            .filter(Boolean)
            .slice(0, 50);
    } catch {
        return [];
    }
};

const SERVICE_HEALTH_HISTORY_KEY = 'serviceHealthChecksHistory';
const SERVICE_HEALTH_HISTORY_LIMIT = 120;
const ABUSE_ACTION_WEIGHTS = Object.freeze({
    'server:security.anti_miner_suspend': 60,
    'server.security.upload_miner_suspended': 55,
    'server.security.upload_miner_blocked': 25,
    'server:debug.crash': 20,
    'server:debug.event.die': 12,
    'server:debug.install_fail': 18,
    'server:debug.connector_error': 10,
    'server:action.command': 2
});

const parseJsonSafe = (raw, fallback) => {
    if (!raw) return fallback;
    try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return parsed === undefined || parsed === null ? fallback : parsed;
    } catch {
        return fallback;
    }
};

const resolveHealthStatus = (checks) => {
    if (!Array.isArray(checks) || checks.length === 0) return 'unknown';
    if (checks.some((item) => item.status === 'fail')) return 'fail';
    if (checks.some((item) => item.status === 'warn')) return 'warn';
    return 'ok';
};

const withTimeout = async (promise, timeoutMs, timeoutMessage) => {
    let timer = null;
    try {
        return await Promise.race([
            promise,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error(timeoutMessage || 'Timeout')), timeoutMs);
            })
        ]);
    } finally {
        if (timer) clearTimeout(timer);
    }
};

const getServiceHealthHistory = async (limit = 30) => {
    const row = await Settings.findByPk(SERVICE_HEALTH_HISTORY_KEY);
    const parsed = parseJsonSafe(row && row.value ? row.value : '[]', []);
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, Math.max(1, Math.min(500, Number.parseInt(limit, 10) || 30)));
};

const appendServiceHealthHistory = async (entry) => {
    const existing = await getServiceHealthHistory(SERVICE_HEALTH_HISTORY_LIMIT);
    const next = [entry, ...existing].slice(0, SERVICE_HEALTH_HISTORY_LIMIT);
    await Settings.upsert({
        key: SERVICE_HEALTH_HISTORY_KEY,
        value: JSON.stringify(next)
    });
    return next;
};

const runServiceHealthSnapshot = async (settingsMap = {}) => {
    const startedAt = Date.now();
    const checks = [];

    checks.push({
        id: 'panel_runtime',
        label: 'Panel Runtime',
        status: process.uptime() > 0 ? 'ok' : 'warn',
        message: `Uptime ${Math.round(process.uptime())}s`
    });

    try {
        await withTimeout(sequelize.authenticate(), 4000, 'DB auth timed out');
        checks.push({ id: 'database', label: 'Database', status: 'ok', message: 'Connection healthy' });
    } catch (error) {
        checks.push({ id: 'database', label: 'Database', status: 'fail', message: error.message || 'Database unreachable' });
    }

    const redisRuntime = typeof getRedisRuntimeInfo === 'function'
        ? getRedisRuntimeInfo()
        : { enabled: false, ready: false, source: 'none', lastError: '' };
    if (redisRuntime.enabled) {
        checks.push({
            id: 'redis',
            label: 'Redis',
            status: redisRuntime.ready ? 'ok' : 'warn',
            message: redisRuntime.ready ? `Ready (${redisRuntime.source || 'runtime'})` : (redisRuntime.lastError || 'Redis not ready')
        });
    } else {
        checks.push({
            id: 'redis',
            label: 'Redis',
            status: 'warn',
            message: 'Redis disabled'
        });
    }

    const connectors = await Connector.findAll({ attributes: ['id'] }).catch(() => []);
    const connectorStatusMap = global.connectorStatus || {};
    const onlineConnectors = Array.isArray(connectors)
        ? connectors.filter((connector) => {
            const data = connectorStatusMap[connector.id] || null;
            if (!data || data.status !== 'online' || !data.lastSeen) return false;
            return (Date.now() - new Date(data.lastSeen).getTime()) < 30000;
        }).length
        : 0;
    checks.push({
        id: 'connectors',
        label: 'Connectors',
        status: connectors.length > 0 && onlineConnectors === 0 ? 'warn' : 'ok',
        message: `${onlineConnectors}/${connectors.length} online`
    });

    const [queueFailed, queueRetrying] = await Promise.all([
        Job.count({ where: { status: 'failed' } }).catch(() => 0),
        Job.count({ where: { status: 'retrying' } }).catch(() => 0)
    ]);
    checks.push({
        id: 'job_queue',
        label: 'Background Queue',
        status: queueFailed > 0 ? 'warn' : 'ok',
        message: `${queueRetrying} retrying, ${queueFailed} failed`
    });

    const snapshot = {
        id: `hc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
        createdAtMs: Date.now(),
        durationMs: Math.max(1, Date.now() - startedAt),
        status: resolveHealthStatus(checks),
        checks,
        settings: {
            enabled: String(settingsMap.featureServiceHealthChecksEnabled || 'false') === 'true',
            intervalSeconds: Number.parseInt(settingsMap.serviceHealthCheckIntervalSeconds, 10) || 300
        }
    };
    return snapshot;
};

const buildAbuseScoreReport = async (settingsMap = {}) => {
    const enabled = String(settingsMap.featureAbuseScoreEnabled || 'false') === 'true';
    const windowHours = Math.max(1, Math.min(720, Number.parseInt(settingsMap.abuseScoreWindowHours, 10) || 72));
    const threshold = Math.max(1, Math.min(1000, Number.parseInt(settingsMap.abuseScoreAlertThreshold, 10) || 80));
    const since = new Date(Date.now() - (windowHours * 60 * 60 * 1000));

    const logs = await AuditLog.findAll({
        where: {
            createdAt: { [Op.gte]: since }
        },
        include: [
            { model: User, as: 'actor', attributes: ['id', 'username'], required: false }
        ],
        order: [['createdAt', 'DESC']],
        limit: 3000
    }).catch(() => []);

    const serverScores = new Map();
    const userScores = new Map();

    const pushHit = (container, key, base) => {
        const current = container.get(key) || { score: 0, hits: 0, recentAt: 0, reasons: [] };
        current.score += base.score;
        current.hits += 1;
        current.recentAt = Math.max(current.recentAt, base.ts);
        if (base.reason) {
            current.reasons.push(base.reason);
            if (current.reasons.length > 6) current.reasons.shift();
        }
        container.set(key, current);
    };

    for (const row of logs) {
        const action = String(row.action || '').trim();
        const metadata = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
        const createdAtMs = new Date(row.createdAt).getTime();
        let score = 0;

        if (Object.prototype.hasOwnProperty.call(ABUSE_ACTION_WEIGHTS, action)) {
            score += ABUSE_ACTION_WEIGHTS[action];
        }
        if (action.startsWith('billing.') && Number(metadata.amount || 0) > 0) {
            score += 0.5; // billing churn contributes lightly
        }
        if (action === 'server:debug.event.die') {
            const exitCode = Number.parseInt(metadata.exitCode, 10);
            if (Number.isInteger(exitCode) && exitCode !== 0) {
                score += Math.min(20, Math.max(0, exitCode));
            }
        }
        if (action.includes('anti_miner') || action.includes('upload_miner')) {
            score += 10;
        }

        if (score <= 0) continue;

        const targetServerId = row.targetType === 'server' ? Number.parseInt(row.targetId, 10) : NaN;
        if (Number.isInteger(targetServerId) && targetServerId > 0) {
            pushHit(serverScores, targetServerId, {
                score,
                ts: createdAtMs,
                reason: action
            });
        }

        const actorUserId = Number.isInteger(Number(row.actorUserId)) ? Number(row.actorUserId) : 0;
        if (actorUserId > 0) {
            pushHit(userScores, actorUserId, {
                score,
                ts: createdAtMs,
                reason: action
            });
        }
    }

    const [servers, users] = await Promise.all([
        Server.findAll({ attributes: ['id', 'name', 'containerId', 'ownerId'] }),
        User.findAll({ attributes: ['id', 'username', 'email'] })
    ]);
    const serverMap = new Map(servers.map((server) => [Number(server.id), server]));
    const userMap = new Map(users.map((user) => [Number(user.id), user]));

    const topServers = Array.from(serverScores.entries())
        .map(([serverId, data]) => {
            const server = serverMap.get(Number(serverId));
            return {
                serverId: Number(serverId),
                score: Math.round((data.score || 0) * 10) / 10,
                hits: data.hits || 0,
                recentAtMs: data.recentAt || 0,
                reasons: data.reasons || [],
                serverName: server ? server.name : `Server #${serverId}`,
                containerId: server && server.containerId ? server.containerId : null,
                ownerId: server ? Number(server.ownerId || 0) : 0
            };
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, 100);

    const topUsers = Array.from(userScores.entries())
        .map(([userId, data]) => {
            const user = userMap.get(Number(userId));
            return {
                userId: Number(userId),
                score: Math.round((data.score || 0) * 10) / 10,
                hits: data.hits || 0,
                recentAtMs: data.recentAt || 0,
                reasons: data.reasons || [],
                username: user ? user.username : `User #${userId}`,
                email: user ? user.email : null
            };
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, 100);

    return {
        enabled,
        windowHours,
        threshold,
        generatedAtMs: Date.now(),
        topServers,
        topUsers,
        flaggedServers: topServers.filter((entry) => entry.score >= threshold).length,
        flaggedUsers: topUsers.filter((entry) => entry.score >= threshold).length
    };
};

const buildForecastingReport = async (settingsMap = {}) => {
    const enabled = String(settingsMap.featureQuotaForecastingEnabled || 'true') === 'true';
    const lookbackDays = 30;
    const since = new Date(Date.now() - (lookbackDays * 24 * 60 * 60 * 1000));
    const economyUnit = String(settingsMap.economyUnit || 'Coins').trim() || 'Coins';

    const [users, servers, billingLogs] = await Promise.all([
        User.findAll({ attributes: ['id', 'username', 'coins', 'isSuspended'] }),
        Server.findAll({ attributes: ['id', 'ownerId', 'memory', 'cpu', 'disk'] }),
        AuditLog.findAll({
            where: {
                action: { [Op.like]: 'billing.%' },
                createdAt: { [Op.gte]: since }
            },
            attributes: ['id', 'actorUserId', 'action', 'createdAt', 'metadata'],
            order: [['createdAt', 'DESC']],
            limit: 4000
        })
    ]);

    const serverUsageByOwner = new Map();
    for (const server of servers) {
        const ownerId = Number.parseInt(server.ownerId, 10);
        if (!Number.isInteger(ownerId) || ownerId <= 0) continue;
        const current = serverUsageByOwner.get(ownerId) || { serverCount: 0, memoryMb: 0, cpuPercent: 0, diskMb: 0 };
        current.serverCount += 1;
        current.memoryMb += Math.max(0, Number.parseInt(server.memory, 10) || 0);
        current.cpuPercent += Math.max(0, Number.parseInt(server.cpu, 10) || 0);
        current.diskMb += Math.max(0, Number.parseInt(server.disk, 10) || 0);
        serverUsageByOwner.set(ownerId, current);
    }

    const spendByUser = new Map();
    for (const row of billingLogs) {
        const userId = Number.parseInt(row.actorUserId, 10);
        if (!Number.isInteger(userId) || userId <= 0) continue;
        const meta = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
        const amount = Number(meta.amount || 0);
        if (!Number.isFinite(amount) || amount <= 0) continue;
        spendByUser.set(userId, (spendByUser.get(userId) || 0) + amount);
    }

    const rows = users.map((user) => {
        const userId = Number.parseInt(user.id, 10);
        const wallet = Number.isFinite(Number(user.coins)) ? Number(user.coins) : 0;
        const usage = serverUsageByOwner.get(userId) || { serverCount: 0, memoryMb: 0, cpuPercent: 0, diskMb: 0 };
        const observedDailyBurn = (spendByUser.get(userId) || 0) / lookbackDays;
        const recurringEnabled = String(settingsMap.featureCostPerServerEnabled || 'false') === 'true';
        const renewDays = Math.max(1, Number.parseInt(settingsMap.storeRenewDays, 10) || 30);
        const recurringEstimate = recurringEnabled
            ? (
                (usage.serverCount * (Number(settingsMap.costBasePerServerMonthly || 0))) +
                ((usage.memoryMb / 1024) * Number(settingsMap.costPerGbRamMonthly || 0)) +
                ((usage.cpuPercent / 100) * Number(settingsMap.costPerCpuCoreMonthly || 0)) +
                ((usage.diskMb / 1024) * Number(settingsMap.costPerGbDiskMonthly || 0))
            ) / renewDays
            : 0;
        const projectedDailyBurn = Math.max(observedDailyBurn, recurringEstimate);
        const runwayDays = projectedDailyBurn > 0 ? (wallet / projectedDailyBurn) : null;
        return {
            userId,
            username: user.username,
            suspended: Boolean(user.isSuspended),
            wallet,
            serverCount: usage.serverCount,
            observedDailyBurn: Math.round(observedDailyBurn * 100) / 100,
            recurringDailyBurn: Math.round(recurringEstimate * 100) / 100,
            projectedDailyBurn: Math.round(projectedDailyBurn * 100) / 100,
            projectedMonthlyBurn: Math.round(projectedDailyBurn * 30 * 100) / 100,
            runwayDays: Number.isFinite(runwayDays) ? Math.round(runwayDays * 10) / 10 : null
        };
    }).sort((a, b) => {
        const aRunway = Number.isFinite(a.runwayDays) ? a.runwayDays : Number.POSITIVE_INFINITY;
        const bRunway = Number.isFinite(b.runwayDays) ? b.runwayDays : Number.POSITIVE_INFINITY;
        return aRunway - bRunway;
    });

    return {
        enabled,
        generatedAtMs: Date.now(),
        economyUnit,
        rows
    };
};

let serviceHealthSweepInFlight = false;
let serviceHealthSweepLastRunAtMs = 0;

const maybeRunServiceHealthSweep = async () => {
    if (serviceHealthSweepInFlight) return;
    serviceHealthSweepInFlight = true;
    try {
        const [enabledRow, intervalRow] = await Promise.all([
            Settings.findByPk('featureServiceHealthChecksEnabled'),
            Settings.findByPk('serviceHealthCheckIntervalSeconds')
        ]);
        const enabled = String(enabledRow && enabledRow.value || 'false').trim().toLowerCase() === 'true';
        if (!enabled) return;
        const intervalSeconds = Math.max(30, Number.parseInt(intervalRow && intervalRow.value, 10) || 300);
        const now = Date.now();
        if ((now - serviceHealthSweepLastRunAtMs) < (intervalSeconds * 1000)) return;

        const settingsMap = {
            featureServiceHealthChecksEnabled: enabled ? 'true' : 'false',
            serviceHealthCheckIntervalSeconds: String(intervalSeconds)
        };
        const snapshot = await runServiceHealthSnapshot(settingsMap);
        await appendServiceHealthHistory(snapshot);
        serviceHealthSweepLastRunAtMs = now;
    } catch (error) {
        console.warn('Service health sweep failed:', error.message || error);
    } finally {
        serviceHealthSweepInFlight = false;
    }
};

if (!global.__cpanelServiceHealthSweepTimer) {
    global.__cpanelServiceHealthSweepTimer = setInterval(() => {
        maybeRunServiceHealthSweep().catch(() => {});
    }, 30_000);
}

// Admin Redis
app.get('/admin/redis', requireAuth, requireAdmin, async (req, res) => {
    try {
        const storedConfig = await getStoredRedisConfig();
        const runtimeInfo = typeof getRedisRuntimeInfo === 'function'
            ? getRedisRuntimeInfo()
            : { enabled: false, ready: false, source: 'unknown', lastError: '', config: {} };
        const fallbackConfig = typeof getEnvRedisConfig === 'function'
            ? getEnvRedisConfig()
            : {
                enabled: false,
                url: '',
                host: '127.0.0.1',
                port: 6379,
                db: 0,
                username: '',
                password: '',
                tls: false,
                sessionPrefix: 'cpanel:sess:',
                mode: 'host'
            };
        const redisConfig = storedConfig || fallbackConfig;
        const suggestions = await findRedisServerSuggestions();

        res.render('admin/redis', {
            user: req.session.user,
            path: '/admin/redis',
            title: 'Redis',
            success: req.query.success || null,
            warning: req.query.warning || null,
            error: req.query.error || null,
            redisConfig,
            redisRuntime: runtimeInfo,
            redisSuggestions: suggestions,
            hasStoredRedisConfig: Boolean(storedConfig),
            nowMs: Date.now()
        });
    } catch (error) {
        console.error('Error loading redis admin page:', error);
        res.render('admin/redis', {
            user: req.session.user,
            path: '/admin/redis',
            title: 'Redis',
            success: null,
            warning: null,
            error: 'Failed to load Redis settings.',
            redisConfig: {
                enabled: false,
                url: '',
                host: '127.0.0.1',
                port: 6379,
                db: 0,
                username: '',
                password: '',
                tls: false,
                sessionPrefix: 'cpanel:sess:',
                mode: 'host'
            },
            redisRuntime: { enabled: false, ready: false, source: 'unknown', lastError: '', config: {} },
            redisSuggestions: [],
            hasStoredRedisConfig: false,
            nowMs: Date.now()
        });
    }
});

app.get('/admin/forecasting', requireAuth, requireAdmin, async (req, res) => {
    try {
        const report = await buildForecastingReport(res.locals.settings || {});
        return res.render('admin/forecasting', {
            user: req.session.user,
            path: '/admin/forecasting',
            title: 'Forecasting',
            success: req.query.success || null,
            error: req.query.error || null,
            report
        });
    } catch (error) {
        console.error('Error loading forecasting page:', error);
        return res.render('admin/forecasting', {
            user: req.session.user,
            path: '/admin/forecasting',
            title: 'Forecasting',
            success: null,
            error: 'Failed to load forecasting data.',
            report: {
                enabled: false,
                generatedAtMs: Date.now(),
                economyUnit: String((res.locals.settings && res.locals.settings.economyUnit) || 'Coins'),
                rows: []
            }
        });
    }
});

app.get('/admin/forecasting.json', requireAuth, requireAdmin, async (req, res) => {
    try {
        const report = await buildForecastingReport(res.locals.settings || {});
        return res.json({ success: true, report });
    } catch {
        return res.status(500).json({ success: false, error: 'Failed to build forecasting report.' });
    }
});

app.get('/admin/abuse-scores', requireAuth, requireAdmin, async (req, res) => {
    try {
        const report = await buildAbuseScoreReport(res.locals.settings || {});
        return res.render('admin/abuse-scores', {
            user: req.session.user,
            path: '/admin/abuse-scores',
            title: 'Abuse Scores',
            success: req.query.success || null,
            error: req.query.error || null,
            report
        });
    } catch (error) {
        console.error('Error loading abuse scores page:', error);
        return res.render('admin/abuse-scores', {
            user: req.session.user,
            path: '/admin/abuse-scores',
            title: 'Abuse Scores',
            success: null,
            error: 'Failed to build abuse score report.',
            report: { enabled: false, generatedAtMs: Date.now(), windowHours: 72, threshold: 80, topServers: [], topUsers: [], flaggedServers: 0, flaggedUsers: 0 }
        });
    }
});

app.get('/admin/abuse-scores.json', requireAuth, requireAdmin, async (req, res) => {
    try {
        const report = await buildAbuseScoreReport(res.locals.settings || {});
        return res.json({ success: true, report });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'Failed to build abuse report.' });
    }
});

app.get('/admin/service-health-checks', requireAuth, requireAdmin, async (req, res) => {
    try {
        const shouldRun = String(req.query.run || '').trim() === '1';
        let latest = null;
        if (shouldRun) {
            latest = await runServiceHealthSnapshot(res.locals.settings || {});
            await appendServiceHealthHistory(latest);
        }
        const history = await getServiceHealthHistory(50);
        if (!latest && history.length > 0) {
            latest = history[0];
        }
        return res.render('admin/service-health-checks', {
            user: req.session.user,
            path: '/admin/service-health-checks',
            title: 'Service Health Checks',
            success: req.query.success || null,
            error: req.query.error || null,
            latest,
            history
        });
    } catch (error) {
        console.error('Error loading service health checks page:', error);
        return res.render('admin/service-health-checks', {
            user: req.session.user,
            path: '/admin/service-health-checks',
            title: 'Service Health Checks',
            success: null,
            error: 'Failed to load service health checks.',
            latest: null,
            history: []
        });
    }
});

app.post('/admin/service-health-checks/run', requireAuth, requireAdmin, async (req, res) => {
    try {
        const snapshot = await runServiceHealthSnapshot(res.locals.settings || {});
        await appendServiceHealthHistory(snapshot);
        return res.redirect('/admin/service-health-checks?success=' + encodeURIComponent(`Health check finished with status: ${String(snapshot.status || 'unknown').toUpperCase()}`));
    } catch (error) {
        console.error('Error running service health checks:', error);
        return res.redirect('/admin/service-health-checks?error=' + encodeURIComponent('Failed to run health checks.'));
    }
});

app.get('/admin/service-health-checks.json', requireAuth, requireAdmin, async (req, res) => {
    try {
        const history = await getServiceHealthHistory(50);
        return res.json({ success: true, latest: history[0] || null, history });
    } catch {
        return res.status(500).json({ success: false, error: 'Failed to load service health history.' });
    }
});

app.post('/admin/redis', requireAuth, requireAdmin, async (req, res) => {
    try {
        const existingConfig = await getStoredRedisConfig();
        const nextConfig = buildRedisConfigFromBody(req.body, existingConfig);
        await persistRedisConfig(nextConfig);

        const envRedisEnabled = ['1', 'true', 'yes', 'on'].includes(String(process.env.REDIS_ENABLED || '').trim().toLowerCase());
        if (envRedisEnabled) {
            return res.redirect(
                '/admin/redis?success=' + encodeURIComponent('Redis settings saved to database.') +
                '&warning=' + encodeURIComponent('Redis is currently booted from environment config. Restart panel or disable REDIS_ENABLED in .env to apply DB-managed Redis.')
            );
        }

        if (typeof reconfigureRedis === 'function') {
            const applyResult = await reconfigureRedis(nextConfig, 'settings');
            if (nextConfig.enabled && !applyResult.ok) {
                return res.redirect(
                    '/admin/redis?success=' + encodeURIComponent('Redis settings saved to database.') +
                    '&warning=' + encodeURIComponent(`Redis apply warning: ${applyResult.error || 'connection timeout'}`)
                );
            }
        }

        return res.redirect('/admin/redis?success=' + encodeURIComponent('Redis settings saved and applied.'));
    } catch (error) {
        console.error('Error saving redis settings:', error);
        return res.redirect('/admin/redis?error=' + encodeURIComponent('Failed to save Redis settings.'));
    }
});

app.post('/admin/redis/test', requireAuth, requireAdmin, async (req, res) => {
    try {
        const existingConfig = await getStoredRedisConfig();
        const nextConfig = buildRedisConfigFromBody(req.body, existingConfig);

        if (typeof testRedisConnection !== 'function') {
            return res.redirect('/admin/redis?error=' + encodeURIComponent('Redis test runtime is not available.'));
        }

        const testResult = await testRedisConnection(nextConfig);
        if (!testResult.ok) {
            return res.redirect('/admin/redis?error=' + encodeURIComponent(`Redis test failed: ${testResult.message}`));
        }

        return res.redirect('/admin/redis?success=' + encodeURIComponent(`Redis test success: ${testResult.message}`));
    } catch (error) {
        console.error('Error testing redis connection:', error);
        return res.redirect('/admin/redis?error=' + encodeURIComponent('Failed to test Redis connection.'));
    }
});

// Admin Languages
app.get('/admin/lang', requireAuth, requireAdmin, async (req, res) => {
    try {
        const selectedFileQuery = sanitizeLanguageFilename(req.query.file);
        const languages = await readLanguageCatalog();

        let selectedLanguage = null;
        if (selectedFileQuery) {
            const selectedPath = nodePath.join(LANG_DIRECTORY, selectedFileQuery);
            if (nodeFs.existsSync(selectedPath)) {
                const contentRaw = await nodeFsPromises.readFile(selectedPath, 'utf8');
                selectedLanguage = {
                    fileName: selectedFileQuery,
                    languageCode: selectedFileQuery.replace(/\.json$/i, ''),
                    contentRaw
                };
            }
        } else if (languages.length > 0) {
            const defaultFile = languages[0].fileName;
            const defaultPath = nodePath.join(LANG_DIRECTORY, defaultFile);
            const contentRaw = await nodeFsPromises.readFile(defaultPath, 'utf8');
            selectedLanguage = {
                fileName: defaultFile,
                languageCode: defaultFile.replace(/\.json$/i, ''),
                contentRaw
            };
        }

        return res.render('admin/lang', {
            user: req.session.user,
            path: '/admin/lang',
            title: 'Languages',
            success: req.query.success || null,
            warning: req.query.warning || null,
            error: req.query.error || null,
            languages,
            selectedLanguage
        });
    } catch (error) {
        console.error('Error loading language admin page:', error);
        return res.render('admin/lang', {
            user: req.session.user,
            path: '/admin/lang',
            title: 'Languages',
            success: null,
            warning: null,
            error: 'Failed to load language files.',
            languages: [],
            selectedLanguage: null
        });
    }
});

app.post('/admin/lang/save', requireAuth, requireAdmin, async (req, res) => {
    try {
        const languageCode = sanitizeLanguageCode(req.body.languageCode);
        if (!languageCode) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('Language code must contain only a-z, 0-9, "_" or "-".'));
        }

        const jsonPayload = String(req.body.jsonPayload || '').trim();
        if (!jsonPayload) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('JSON payload is required.'));
        }
        if (Buffer.byteLength(jsonPayload, 'utf8') > MAX_LANGUAGE_JSON_SIZE_BYTES) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('JSON file is too large (max 2 MB).'));
        }

        let parsed;
        try {
            parsed = JSON.parse(jsonPayload);
        } catch (error) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('Invalid JSON format.'));
        }

        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('Language file must be a JSON object with key/value pairs.'));
        }

        const pretty = JSON.stringify(parsed, null, 2) + '\n';
        await ensureLanguageDirectory();
        const fileName = `${languageCode}.json`;
        const filePath = nodePath.join(LANG_DIRECTORY, fileName);
        await nodeFsPromises.writeFile(filePath, pretty, 'utf8');

        return res.redirect('/admin/lang?success=' + encodeURIComponent(`Language "${fileName}" saved.`) + '&file=' + encodeURIComponent(fileName));
    } catch (error) {
        console.error('Error saving language file:', error);
        return res.redirect('/admin/lang?error=' + encodeURIComponent('Failed to save language file.'));
    }
});

app.post('/admin/lang/delete/:fileName', requireAuth, requireAdmin, async (req, res) => {
    try {
        const fileName = sanitizeLanguageFilename(req.params.fileName);
        if (!fileName) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('Invalid language filename.'));
        }

        const filePath = nodePath.join(LANG_DIRECTORY, fileName);
        if (!nodeFs.existsSync(filePath)) {
            return res.redirect('/admin/lang?error=' + encodeURIComponent('Language file not found.'));
        }

        await nodeFsPromises.unlink(filePath);
        return res.redirect('/admin/lang?success=' + encodeURIComponent(`Language "${fileName}" deleted.`));
    } catch (error) {
        console.error('Error deleting language file:', error);
        return res.redirect('/admin/lang?error=' + encodeURIComponent('Failed to delete language file.'));
    }
});

// Admin Locations
app.get('/admin/locations', requireAuth, requireAdmin, async (req, res) => {
    try {
        const locations = await Location.findAll({
            include: [
                { model: DatabaseHost, as: 'databaseHosts' },
                { model: Connector, as: 'connectors' }
            ]
        });
        res.render('admin/locations', {
            user: req.session.user,
            locations,
            path: '/admin/locations',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Error fetching locations:", error);
        res.render('admin/locations', {
            user: req.session.user,
            locations: [],
            path: '/admin/locations',
            success: null,
            error: 'Failed to fetch locations.'
        });
    }
});

app.post('/admin/locations', requireAuth, requireAdmin, [
    body('shortName').trim().notEmpty().withMessage('Short Name is required'),
    body('description').trim().isLength({ max: 30 }).withMessage('Description must be 30 characters or less'),
    body('imageUrl').trim().optional({ checkFalsy: true }).isURL().withMessage('Invalid Image URL')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect('/admin/locations?error=' + encodeURIComponent(errors.array()[0].msg));
    }

    const { shortName, description, imageUrl } = req.body;
    try {
        await Location.create({ shortName, description, imageUrl });
        res.redirect('/admin/locations?success=Location created successfully!');
    } catch (error) {
        console.error("Error creating location:", error);
        return res.redirect('/admin/locations?error=' + encodeURIComponent(
            error.name === 'SequelizeUniqueConstraintError' ? 'Short Name already exists' : 'Failed to create location.'
        ));
    }
});

app.post('/admin/locations/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        // Check if location is used by any DatabaseHost
        const dbHostCount = await DatabaseHost.count({ where: { locationId: req.params.id } });
        if (dbHostCount > 0) {
            return res.redirect(`/admin/locations?error=Cannot delete location because it is currently used by ${dbHostCount} database host(s).`);
        }

        // Check if location is used by any Connector
        const connectorCount = await Connector.count({ where: { locationId: req.params.id } });
        if (connectorCount > 0) {
            return res.redirect(`/admin/locations?error=Cannot delete location because it is currently used by ${connectorCount} connector(s).`);
        }

        await Location.destroy({ where: { id: req.params.id } });
        res.redirect('/admin/locations?success=Location deleted successfully!');
    } catch (error) {
        console.error("Error deleting location:", error);
        res.redirect('/admin/locations?error=Failed to delete location.');
    }
});

// Admin Users
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({
            include: [{ model: LinkedAccount, as: 'linkedAccounts' }]
        });
        res.render('admin/users', {
            user: req.session.user,
            users,
            md5, // Pass md5 for gravatar hashing in the view
            path: '/admin/users',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Error fetching users:", error);
        res.render('admin/users', {
            user: req.session.user,
            users: [],
            path: '/admin/users',
            success: null,
            error: 'Failed to fetch users.'
        });
    }
});

// Admin Force Unlink OAuth Account
app.post('/admin/users/:id/unlink/:provider', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id, provider } = req.params;
        const targetUser = await User.findByPk(id);
        if (!targetUser) return res.redirect('/admin/users?error=User not found.');

        await LinkedAccount.destroy({ where: { userId: id, provider } });

        // Clear legacy field if it matches
        if (targetUser.oauthProvider === provider) {
            await targetUser.update({ oauthProvider: null, oauthId: null });
        }
        if (String(provider || '').trim().toLowerCase() === 'google' && Settings && typeof Settings.destroy === 'function') {
            const tokenKey = getGoogleTokenSettingKey(id);
            if (tokenKey) await Settings.destroy({ where: { key: tokenKey } }).catch(() => {});
        }

        res.redirect(`/admin/users?success=Successfully unlinked ${provider} from ${targetUser.username}.`);
    } catch (err) {
        console.error('Error in admin unlink:', err);
        res.redirect('/admin/users?error=Failed to unlink account.');
    }
});

app.post('/admin/users', requireAuth, requireAdmin, [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('email').trim().isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect('/admin/users?error=' + encodeURIComponent(errors.array()[0].msg));
    }

    const { username, email, password, avatarUrl, avatarProvider, isAdmin } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            username,
            email,
            password: hashedPassword,
            firstName: username, // Default to username as requested form doesn't have these
            lastName: '',
            avatarUrl: avatarUrl || null,
            avatarProvider: avatarProvider || 'gravatar',
            isAdmin: isAdmin === 'on' || isAdmin === true,
            isSuspended: false // Default to active
        });
        res.redirect('/admin/users?success=User created successfully!');
    } catch (error) {
        console.error("Error creating user:", error);
        return res.redirect('/admin/users?error=' + encodeURIComponent('Failed to create user. Username or email might already exist.'));
    }
});

app.post('/admin/users/edit/:id', requireAuth, requireAdmin, [
    body('email').trim().isEmail().withMessage('Valid email is required'),
    body('password').optional({ checkFalsy: true }).isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    const { id } = req.params;
    const { email, username, avatarUrl, avatarProvider, isAdmin, password } = req.body;

    try {
        const updateData = {
            email,
            username,
            avatarUrl: avatarUrl || null,
            avatarProvider: avatarProvider || 'gravatar',
            isAdmin: isAdmin === 'on' || isAdmin === true || isAdmin === 'true',
            isSuspended: req.body.isSuspended === 'on' || req.body.isSuspended === true || req.body.isSuspended === 'true'
        };

        // Prevent self-suspension
        if (parseInt(id) === req.session.user.id && updateData.isSuspended) {
            // If trying to suspend self, force it to false
            updateData.isSuspended = false;
        }

        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        await User.update(updateData, { where: { id } });
        res.redirect('/admin/users?success=User updated successfully!');
    } catch (error) {
        console.error("Error updating user:", error);
        res.redirect(`/admin/users?error=Failed to update user.`);
    }
});

app.post('/admin/users/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;

    // Prevent self-deletion
    if (parseInt(id) === req.session.user.id) {
        return res.redirect('/admin/users?error=You cannot delete your own account!');
    }

    try {
        await LinkedAccount.destroy({ where: { userId: id } });
        if (Settings && typeof Settings.destroy === 'function') {
            const tokenKey = getGoogleTokenSettingKey(id);
            if (tokenKey) await Settings.destroy({ where: { key: tokenKey } }).catch(() => {});
        }
        await User.destroy({ where: { id } });
        res.redirect('/admin/users?success=User deleted successfully!');
    } catch (error) {
        console.error("Error deleting user:", error);
        res.redirect('/admin/users?error=Failed to delete user.');
    }
});

app.post('/admin/locations/edit/:id', requireAuth, requireAdmin, [
    body('shortName').trim().notEmpty().withMessage('Short Name is required'),
    body('description').trim().isLength({ max: 30 }).withMessage('Description must be 30 characters or less'),
    body('imageUrl').trim().optional({ checkFalsy: true }).isURL().withMessage('Invalid Image URL')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(`/admin/locations?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    const { shortName, description, imageUrl } = req.body;
    try {
        await Location.update({ shortName, description, imageUrl }, { where: { id: req.params.id } });
        res.redirect('/admin/locations?success=Location updated successfully!');
    } catch (error) {
        console.error("Error updating location:", error);
        res.redirect('/admin/locations?error=Failed to update location.');
    }
});

// Admin Packages (List)
app.get('/admin/packages', requireAuth, requireAdmin, async (req, res) => {
    try {
        const packages = await Package.findAll({
            include: [{ model: Image, as: 'images' }],
            order: [['name', 'ASC']]
        });
        res.render('admin/packages', {
            user: req.session.user,
            packages,
            path: '/admin/packages',
            title: 'Packages',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading packages admin page:', error);
        res.redirect('/admin/overview?error=Failed to load packages.');
    }
});

// Admin Packages (Create)
app.post('/admin/packages', requireAuth, requireAdmin, async (req, res) => {
    const { name, description, imageUrl, redirect } = req.body;
    const redirectPath = redirect || '/admin/packages';
    try {
        if (!name) return res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'error=Package name is required.');
        if (description && description.length > 150) {
            return res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'error=Description must be at most 150 characters.');
        }

        await Package.create({ name, description, imageUrl });
        res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'success=Package created successfully!');
    } catch (error) {
        console.error('Error creating package:', error);
        res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'error=Failed to create package.');
    }
});

// Admin Packages (Edit)
app.post('/admin/packages/edit/:id', requireAuth, requireAdmin, async (req, res) => {
    const { name, description, imageUrl } = req.body;
    try {
        const pkg = await Package.findByPk(req.params.id);
        if (!pkg) return res.redirect('/admin/packages?error=Package not found.');

        if (!name) return res.redirect('/admin/packages?error=Package name is required.');
        if (description && description.length > 150) {
            return res.redirect('/admin/packages?error=Description must be at most 150 characters.');
        }

        await pkg.update({ name, description, imageUrl });
        res.redirect('/admin/packages?success=Package updated successfully!');
    } catch (error) {
        console.error('Error updating package:', error);
        res.redirect('/admin/packages?error=Failed to update package.');
    }
});

// Admin Packages (Delete)
app.get('/admin/packages/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const pkg = await Package.findByPk(req.params.id, {
            include: [{ model: Image, as: 'images' }]
        });
        if (!pkg) return res.redirect('/admin/packages?error=Package not found.');

        if (pkg.images && pkg.images.length > 0) {
            return res.redirect('/admin/packages?error=Cannot delete package with assigned images.');
        }

        await pkg.destroy();
        res.redirect('/admin/packages?success=Package deleted successfully!');
    } catch (error) {
        console.error('Error deleting package:', error);
        res.redirect('/admin/packages?error=Failed to delete package.');
    }
});

// API: Get Packages JSON (For modals)
app.get('/api/admin/packages', requireAuth, requireAdmin, async (req, res) => {
    try {
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.json(packages);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch packages' });
    }
});

// Admin Images
app.get('/admin/images', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { packageId } = req.query;
        const where = {};
        if (packageId) where.packageId = packageId;

        const images = await Image.findAll({
            where,
            include: [{ model: Package, as: 'package' }],
            order: [['name', 'ASC']]
        });
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.render('admin/images', {
            user: req.session.user,
            images,
            packages,
            path: '/admin/images',
            title: 'Images',
            currentPackageId: packageId || '',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading images admin page:', error);
        res.render('admin/images', {
            user: req.session.user,
            images: [],
            packages: [],
            path: '/admin/images',
            title: 'Images',
            currentPackageId: req.query.packageId || '',
            success: null,
            error: 'Failed to load images.'
        });
    }
});

app.post('/admin/images/import', requireAuth, requireAdmin, async (req, res) => {
    try {
        const jsonPayload = (req.body.jsonPayload || '').trim();
        const packageIdRaw = req.body.packageId;
        const packageId = Number.parseInt(packageIdRaw, 10);
        const isPublicSubmitted = ['1', 'true', 'on', 'yes'].includes(String(req.body.isPublicSubmitted || '').trim().toLowerCase());
        const isPublic = !isPublicSubmitted
            ? true
            : ['1', 'true', 'on', 'yes'].includes(String(req.body.isPublic || '').trim().toLowerCase());

        if (!Number.isInteger(packageId) || packageId <= 0) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('You must select a package for the imported image.'));
        }
        const selectedPackage = await Package.findByPk(packageId);
        if (!selectedPackage) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('Selected package does not exist anymore. Please refresh and try again.'));
        }

        if (!jsonPayload) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('Please upload or paste a JSON file first.'));
        }

        let parsedJson;
        try {
            parsedJson = JSON.parse(jsonPayload);
        } catch (error) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('Invalid JSON format.'));
        }

        const payloadItems = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
        if (payloadItems.length === 0) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('No image objects found in the provided JSON payload.'));
        }

        let createdCount = 0;
        let updatedCount = 0;
        const failedItems = [];

        for (const [index, item] of payloadItems.entries()) {
            try {
                if (!item || typeof item !== 'object' || Array.isArray(item)) {
                    throw new Error('Entry is not a JSON object.');
                }

                const normalized = parseImportedImageJson(item);
                normalized.packageId = packageId;
                normalized.isPublic = isPublic;

                const [image, created] = await Image.findOrCreate({
                    where: { name: normalized.name },
                    defaults: normalized
                });

                if (!created) {
                    await image.update(normalized);
                    updatedCount += 1;
                } else {
                    createdCount += 1;
                }
            } catch (entryError) {
                const entryName = item && typeof item === 'object'
                    ? String(item.name || (item.attributes && item.attributes.name) || `entry_${index + 1}`)
                    : `entry_${index + 1}`;
                failedItems.push(`${entryName}: ${entryError.message || 'invalid payload'}`);
            }
        }

        if ((createdCount + updatedCount) === 0) {
            const errorMessage = failedItems.length > 0
                ? `Image import failed. ${failedItems.slice(0, 3).join(' | ')}`
                : 'Image import failed.';
            return res.redirect('/admin/images?error=' + encodeURIComponent(errorMessage));
        }

        const summary = `Import complete. Created: ${createdCount}, Updated: ${updatedCount}, Failed: ${failedItems.length}.`;
        if (failedItems.length > 0) {
            return res.redirect('/admin/images?success=' + encodeURIComponent(summary) + '&warning=' + encodeURIComponent(failedItems.slice(0, 3).join(' | ')));
        }
        return res.redirect('/admin/images?success=' + encodeURIComponent(summary));
    } catch (error) {
        console.error('Failed to import image JSON:', error);
        res.redirect('/admin/images?error=' + encodeURIComponent(error.message || 'Image import failed.'));
    }
});

// Admin Images (Edit - GET)
app.get('/admin/images/edit/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.render('admin/edit-image', {
            user: req.session.user,
            image,
            packages,
            path: '/admin/images',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading edit image page:', error);
        res.redirect('/admin/images?error=Failed to load image.');
    }
});

// Admin Images (Edit - POST)
app.post('/admin/images/edit/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { name, description, dockerImage, startup, environment, dockerImages, packageId } = req.body;
        const isPublicSubmitted = ['1', 'true', 'on', 'yes'].includes(String(req.body.isPublicSubmitted || '').trim().toLowerCase());
        const isPublic = !isPublicSubmitted
            ? true
            : ['1', 'true', 'on', 'yes'].includes(String(req.body.isPublic || '').trim().toLowerCase());

        let envParsed = {};
        try {
            envParsed = JSON.parse(environment);
        } catch (e) {
            return res.redirect(`/admin/images/edit/${req.params.id}?error=Invalid JSON for Environment Variables`);
        }

        let imagesParsed = {};
        try {
            imagesParsed = JSON.parse(dockerImages);
        } catch (e) {
            return res.redirect(`/admin/images/edit/${req.params.id}?error=Invalid JSON for Docker Images`);
        }

        await Image.update({
            name,
            description,
            dockerImage,
            startup,
            environment: envParsed,
            dockerImages: imagesParsed,
            isPublic,
            packageId: packageId || null
        }, { where: { id: req.params.id } });

        res.redirect(`/admin/images/edit/${req.params.id}?success=Image updated successfully!`);
    } catch (error) {
        console.error('Error updating image:', error);
        res.redirect(`/admin/images/edit/${req.params.id}?error=Failed to update image.`);
    }
});

// Admin Images (Visibility Toggle - POST)
app.post('/admin/images/visibility/:id', requireAuth, requireAdmin, async (req, res) => {
    const packageId = Number.parseInt(req.body.packageId || req.query.packageId, 10);
    const redirectBase = Number.isInteger(packageId) && packageId > 0
        ? `/admin/images?packageId=${encodeURIComponent(String(packageId))}`
        : '/admin/images';
    const redirectWith = (key, value) => `${redirectBase}${redirectBase.includes('?') ? '&' : '?'}${key}=${encodeURIComponent(value)}`;
    const wantsJson = (req.headers.accept || '').includes('application/json');

    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            if (wantsJson) return res.status(404).json({ ok: false, error: 'Image not found.' });
            return res.redirect(redirectWith('error', 'Image not found.'));
        }

        const rawVisibility = String(req.body.isPublic || '').trim().toLowerCase();
        const isPublic = ['1', 'true', 'on', 'yes'].includes(rawVisibility);
        await image.update({ isPublic });

        if (wantsJson) {
            return res.json({
                ok: true,
                imageId: image.id,
                isPublic,
                label: isPublic ? 'Public' : 'Private'
            });
        }

        res.redirect(redirectWith('success', `Image "${image.name}" visibility updated to ${isPublic ? 'Public' : 'Private'}.`));
    } catch (error) {
        console.error('Error toggling image visibility:', error);
        if (wantsJson) return res.status(500).json({ ok: false, error: 'Failed to update visibility.' });
        res.redirect(redirectWith('error', 'Failed to update image visibility.'));
    }
});

// Admin Images (Delete - POST)
app.post('/admin/images/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    const packageId = Number.parseInt(req.body.packageId || req.query.packageId, 10);
    const redirectBase = Number.isInteger(packageId) && packageId > 0
        ? `/admin/images?packageId=${encodeURIComponent(String(packageId))}`
        : '/admin/images';
    const redirectWith = (key, value) => `${redirectBase}${redirectBase.includes('?') ? '&' : '?'}${key}=${encodeURIComponent(value)}`;

    try {
        const usageCount = await Server.count({ where: { imageId: req.params.id } });
        if (usageCount > 0) {
            return res.redirect(redirectWith('error', `Cannot delete image because it is used by ${usageCount} server(s).`));
        }

        await Image.destroy({ where: { id: req.params.id } });
        res.redirect(redirectWith('success', 'Image deleted successfully!'));
    } catch (error) {
        console.error('Error deleting image:', error);
        res.redirect(redirectWith('error', 'Failed to delete image.'));
    }
});

// Admin Images (Export JSON)
app.get('/admin/images/export/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }

        const exportData = image.toJSON();
        res.setHeader('Content-disposition', `attachment; filename=${image.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`);
        res.setHeader('Content-type', 'application/json');
        res.send(JSON.stringify(exportData, null, 2));
    } catch (error) {
        console.error('Error exporting image:', error);
        res.redirect('/admin/images?error=Failed to export image.');
    }
});

// Admin Images (Edit JSON - GET)
app.get('/admin/images/edit-json/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.render('admin/edit-image-json', {
            user: req.session.user,
            image,
            packages,
            path: '/admin/images',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading edit image json page:', error);
        res.redirect('/admin/images?error=Failed to load image.');
    }
});

// Admin Images (Edit JSON - POST)
app.post('/admin/images/edit-json/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { jsonPayload, packageId } = req.body;
        const isPublicSubmitted = ['1', 'true', 'on', 'yes'].includes(String(req.body.isPublicSubmitted || '').trim().toLowerCase());
        const isPublic = !isPublicSubmitted
            ? true
            : ['1', 'true', 'on', 'yes'].includes(String(req.body.isPublic || '').trim().toLowerCase());
        let parsed;
        try {
            parsed = JSON.parse(jsonPayload);
        } catch (e) {
            return res.redirect(`/admin/images/edit-json/${req.params.id}?error=Invalid JSON format.`);
        }

        if (Array.isArray(parsed)) {
            if (parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object') {
                return res.redirect(`/admin/images/edit-json/${req.params.id}?error=JSON array payload must contain exactly one image object.`);
            }
            parsed = parsed[0];
        }

        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }

        const normalized = parseImportedImageJson(parsed);
        normalized.configPath = image.configPath || normalized.configPath;
        normalized.packageId = packageId || image.packageId;
        normalized.isPublic = isPublic;
        await image.update(normalized);
        res.redirect(`/admin/images/edit-json/${req.params.id}?success=Image JSON updated successfully!`);
    } catch (error) {
        console.error('Error updating image via JSON:', error);
        res.redirect(`/admin/images/edit-json/${req.params.id}?error=${encodeURIComponent(error.message || 'Failed to update image.')}`);
    }
});

// Admin Databases
app.get('/admin/databases', requireAuth, requireAdmin, async (req, res) => {
    try {
        const hosts = await DatabaseHost.findAll({
            include: [{ model: Location, as: 'location' }]
        });
        const locations = await Location.findAll();
        res.render('admin/databases', {
            user: req.session.user,
            hosts,
            locations,
            path: '/admin/databases',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Error fetching database hosts:", error);
        res.render('admin/databases', {
            user: req.session.user,
            hosts: [],
            path: '/admin/databases',
            success: null,
            error: 'Failed to fetch database hosts.'
        });
    }
});

app.post('/admin/databases', requireAuth, requireAdmin, [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('host').trim().notEmpty().withMessage('Host is required'),
    body('port').isInt().withMessage('Port must be a number'),
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').trim().notEmpty().withMessage('Password is required'),
    body('database').trim().notEmpty().withMessage('Database name is required'),
    body('locationId').isInt().withMessage('Location is required'),
    body('type').isIn(['mysql', 'postgres', 'mariadb']).withMessage('Invalid database type')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect('/admin/databases?error=' + encodeURIComponent(errors.array()[0].msg));
    }

    const { name, host, port, username, password, database, locationId, type } = req.body;
    try {
        await DatabaseHost.create({ name, host, port, username, password, database, locationId, type });
        res.redirect('/admin/databases?success=Database host created successfully!');
    } catch (error) {
        console.error("Error creating database host:", error);
        return res.redirect('/admin/databases?error=' + encodeURIComponent('Failed to create database host.'));
    }
});

app.post('/admin/databases/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (typeof ServerDatabase !== 'undefined' && ServerDatabase && typeof ServerDatabase.count === 'function') {
            const linkedCount = await ServerDatabase.count({ where: { databaseHostId: req.params.id } });
            if (linkedCount > 0) {
                return res.redirect('/admin/databases?error=' + encodeURIComponent(`Cannot delete host: it is assigned to ${linkedCount} server database entr${linkedCount === 1 ? 'y' : 'ies'}.`));
            }
        }
        await DatabaseHost.destroy({ where: { id: req.params.id } });
        res.redirect('/admin/databases?success=Database host deleted successfully!');
    } catch (error) {
        console.error("Error deleting database host:", error);
        res.redirect('/admin/databases?error=Failed to delete database host.');
    }
});

app.post('/admin/databases/edit/:id', requireAuth, requireAdmin, [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('host').trim().notEmpty().withMessage('Host is required'),
    body('port').isInt().withMessage('Port must be a number'),
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').trim().notEmpty().withMessage('Password is required'),
    body('database').trim().notEmpty().withMessage('Database name is required'),
    body('locationId').isInt().withMessage('Location is required'),
    body('type').isIn(['mysql', 'postgres', 'mariadb']).withMessage('Invalid database type')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(`/admin/databases?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    const { name, host, port, username, password, database, locationId, type } = req.body;
    try {
        await DatabaseHost.update({ name, host, port, username, password, database, locationId, type }, { where: { id: req.params.id } });
        res.redirect('/admin/databases?success=Database host updated successfully!');
    } catch (error) {
        console.error("Error updating database host:", error);
        res.redirect('/admin/databases?error=Failed to update database host.');
    }
});

app.post('/admin/databases/ping/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const host = await DatabaseHost.findByPk(req.params.id);
        if (!host) {
            return res.status(404).json({ success: false, error: 'Database host not found' });
        }

        // Create a temporary sequelize instance to test connection
        const testSequelize = new Sequelize(
            host.database || (host.type === 'mysql' ? 'mysql' : 'postgres'),
            host.username,
            host.password,
            {
                host: host.host,
                port: host.port,
                dialect: host.type === 'postgres' ? 'postgres' : 'mysql',
                logging: false,
                dialectOptions: {
                    connectTimeout: 5000 // 5 seconds timeout
                }
            }
        );

        try {
            await testSequelize.authenticate();
            await testSequelize.close();
            return res.json({ success: true });
        } catch (err) {
            console.error("Ping failed:", err);
            return res.json({ success: false, error: err.message });
        }
    } catch (error) {
        console.error("Error in ping route:", error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.get('/admin/mounts', requireAuth, requireAdmin, async (req, res) => {
    try {
        const mounts = await Mount.findAll({
            include: [{ model: Connector, as: 'connector', attributes: ['id', 'name'] }],
            order: [['name', 'ASC']]
        });
        const connectors = await Connector.findAll({ attributes: ['id', 'name'], order: [['name', 'ASC']] });

        res.render('admin/mounts', {
            user: req.session.user,
            path: '/admin/mounts',
            mounts: mounts.map((mount) => ({
                ...mount.toJSON(),
                connectorName: mount.connector ? mount.connector.name : null
            })),
            connectors,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading mounts page:', error);
        res.redirect('/admin/overview?error=Failed to load mounts.');
    }
});

app.post('/admin/mounts', requireAuth, requireAdmin, async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const description = String(req.body.description || '').trim();
        const sourcePath = String(req.body.sourcePath || '').trim();
        let targetPath = String(req.body.targetPath || '').trim();
        const connectorId = Number.parseInt(req.body.connectorId, 10);
        const readOnly = ['1', 'true', 'yes', 'on'].includes(String(req.body.readOnly || '').trim().toLowerCase());

        if (!name || !sourcePath || !targetPath) {
            return res.redirect('/admin/mounts?error=' + encodeURIComponent('Name, source path, and target path are required.'));
        }
        if (!targetPath.startsWith('/')) {
            targetPath = '/' + targetPath.replace(/^\/+/, '');
        }

        await Mount.create({
            name,
            description: description || null,
            sourcePath,
            targetPath,
            readOnly,
            connectorId: Number.isInteger(connectorId) && connectorId > 0 ? connectorId : null
        });

        return res.redirect('/admin/mounts?success=' + encodeURIComponent('Mount created successfully.'));
    } catch (error) {
        console.error('Error creating mount:', error);
        return res.redirect('/admin/mounts?error=' + encodeURIComponent('Failed to create mount.'));
    }
});

app.post('/admin/mounts/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const mountId = Number.parseInt(req.params.id, 10);
        if (!Number.isInteger(mountId) || mountId <= 0) {
            return res.redirect('/admin/mounts?error=' + encodeURIComponent('Invalid mount id.'));
        }
        await ServerMount.destroy({ where: { mountId } });
        await Mount.destroy({ where: { id: mountId } });
        return res.redirect('/admin/mounts?success=' + encodeURIComponent('Mount deleted.'));
    } catch (error) {
        console.error('Error deleting mount:', error);
        return res.redirect('/admin/mounts?error=' + encodeURIComponent('Failed to delete mount.'));
    }
});

}

module.exports = { registerAdminCoreRoutes };
