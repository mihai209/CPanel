const WebSocket = require('ws');

const SERVER_SCHEDULES_KEY_PREFIX = 'server_schedules_';
const VALID_POWER_ACTIONS = new Set(['start', 'stop', 'restart', 'kill']);

function parseJsonArray(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    if (typeof value !== 'string') return [];
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function parseInteger(value) {
    const parsed = Number.parseInt(String(value || '').trim(), 10);
    return Number.isInteger(parsed) ? parsed : null;
}

function isWildcardField(field) {
    return String(field || '').trim() === '*';
}

function fieldMatches(field, value, min, max) {
    const normalized = String(field || '').trim();
    if (!normalized) return false;

    const parts = normalized.split(',');
    for (const rawPart of parts) {
        const part = rawPart.trim();
        if (!part) continue;

        let base = part;
        let step = 1;
        if (part.includes('/')) {
            const split = part.split('/');
            if (split.length !== 2) continue;
            base = split[0].trim();
            const parsedStep = parseInteger(split[1]);
            if (!Number.isInteger(parsedStep) || parsedStep <= 0) continue;
            step = parsedStep;
        }

        if (base === '*') {
            if ((value - min) % step === 0) return true;
            continue;
        }

        if (base.includes('-')) {
            const splitRange = base.split('-');
            if (splitRange.length !== 2) continue;
            const start = parseInteger(splitRange[0]);
            const end = parseInteger(splitRange[1]);
            if (!Number.isInteger(start) || !Number.isInteger(end)) continue;
            if (start < min || end > max || start > end) continue;
            if (value < start || value > end) continue;
            if ((value - start) % step === 0) return true;
            continue;
        }

        const exact = parseInteger(base);
        if (!Number.isInteger(exact) || exact < min || exact > max) continue;
        if (value === exact) return true;
    }

    return false;
}

function cronMatchesNow(expr, now) {
    const parts = String(expr || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length !== 5) return false;

    const minute = now.getMinutes();
    const hour = now.getHours();
    const dayOfMonth = now.getDate();
    const month = now.getMonth() + 1;
    const dayOfWeek = now.getDay();

    const minuteOk = fieldMatches(parts[0], minute, 0, 59);
    const hourOk = fieldMatches(parts[1], hour, 0, 23);
    const monthOk = fieldMatches(parts[3], month, 1, 12);
    if (!minuteOk || !hourOk || !monthOk) return false;

    const domOk = fieldMatches(parts[2], dayOfMonth, 1, 31);
    const dowOk = fieldMatches(parts[4], dayOfWeek, 0, 6) || fieldMatches(parts[4], dayOfWeek === 0 ? 7 : dayOfWeek, 1, 7);

    const domWildcard = isWildcardField(parts[2]);
    const dowWildcard = isWildcardField(parts[4]);

    if (!domWildcard && !dowWildcard) {
        return domOk || dowOk;
    }
    return domOk && dowOk;
}

function isSameMinuteIso(lastRunAt, now) {
    if (!lastRunAt) return false;
    const parsed = new Date(lastRunAt);
    if (Number.isNaN(parsed.getTime())) return false;
    return parsed.getUTCFullYear() === now.getUTCFullYear()
        && parsed.getUTCMonth() === now.getUTCMonth()
        && parsed.getUTCDate() === now.getUTCDate()
        && parsed.getUTCHours() === now.getUTCHours()
        && parsed.getUTCMinutes() === now.getUTCMinutes();
}

function isServerOnlineStatus(status) {
    const normalized = String(status || '').trim().toLowerCase();
    return normalized === 'running' || normalized === 'online' || normalized === 'starting';
}

async function dispatchScheduleAction({
    schedule,
    server,
    ServerBackupPolicy,
    jobQueue,
    connectorConnections
}) {
    const action = String(schedule.action || '').trim().toLowerCase();
    if (action === 'backup') {
        return { ok: false, detail: 'backup action disabled; use sftp backup workflow' };
    }

    if (!server.allocation || !server.allocation.connectorId) {
        return { ok: false, detail: 'missing allocation connector' };
    }

    const connectorWs = connectorConnections.get(server.allocation.connectorId);
    if (!connectorWs || connectorWs.readyState !== WebSocket.OPEN) {
        return { ok: false, detail: `connector ${server.allocation.connectorId} offline` };
    }

    if (action === 'command') {
        const command = String(schedule.payload || '').trim();
        if (!command) return { ok: false, detail: 'missing command payload' };
        connectorWs.send(JSON.stringify({
            type: 'server_schedule_action',
            serverId: server.id,
            scheduleAction: 'command',
            payload: command,
            command
        }));
        return { ok: true, detail: 'command sent' };
    }

    if (action === 'power') {
        const powerAction = String(schedule.payload || '').trim().toLowerCase();
        if (!VALID_POWER_ACTIONS.has(powerAction)) {
            return { ok: false, detail: 'invalid power payload' };
        }
        connectorWs.send(JSON.stringify({
            type: 'server_schedule_action',
            serverId: server.id,
            scheduleAction: 'power',
            payload: powerAction,
            powerAction
        }));
        return { ok: true, detail: `power action ${powerAction} sent` };
    }

    return { ok: false, detail: 'unsupported action' };
}

function startServerScheduleRunner({
    Settings,
    Op,
    Server,
    Allocation,
    ServerBackupPolicy,
    jobQueue,
    connectorConnections,
    intervalMs = 30 * 1000,
    bootInfo,
    bootWarn
}) {
    let timer = null;
    let running = false;

    async function tick() {
        if (running) return;
        running = true;

        try {
            const now = new Date();
            const rows = await Settings.findAll({
                where: {
                    key: {
                        [Op.like]: `${SERVER_SCHEDULES_KEY_PREFIX}%`
                    }
                },
                attributes: ['key', 'value']
            });

            for (const row of rows) {
                const key = String(row.key || '');
                const serverIdRaw = key.slice(SERVER_SCHEDULES_KEY_PREFIX.length);
                const serverId = Number.parseInt(serverIdRaw, 10);
                if (!Number.isInteger(serverId) || serverId <= 0) continue;

                const schedules = parseJsonArray(row.value);
                if (!schedules.length) continue;

                const server = await Server.findByPk(serverId, {
                    include: [{ model: Allocation, as: 'allocation' }]
                });
                if (!server) continue;

                let changed = false;
                for (const entry of schedules) {
                    const schedule = entry && typeof entry === 'object' ? entry : null;
                    if (!schedule) continue;
                    if (schedule.enabled === false) continue;

                    const cron = String(schedule.cron || '').trim();
                    if (!cron || !cronMatchesNow(cron, now)) continue;
                    if (isSameMinuteIso(schedule.lastRunAt, now)) continue;

                    const onlyWhenOnline = Boolean(schedule.onlyWhenOnline);
                    if (onlyWhenOnline && !isServerOnlineStatus(server.status)) {
                        continue;
                    }

                    const dispatch = await dispatchScheduleAction({
                        schedule,
                        server,
                        ServerBackupPolicy,
                        jobQueue,
                        connectorConnections
                    });

                    if (!dispatch.ok) {
                        if (typeof bootWarn === 'function') {
                            bootWarn(
                                'schedule dispatch skipped server_id=%s schedule_id=%s reason=%s',
                                server.id,
                                String(schedule.id || 'n/a'),
                                dispatch.detail
                            );
                        }
                        continue;
                    }

                    schedule.lastRunAt = now.toISOString();
                    schedule.updatedAt = now.toISOString();
                    changed = true;

                    if (typeof bootInfo === 'function') {
                        bootInfo(
                            'schedule executed server_id=%s schedule_id=%s action=%s detail=%s',
                            server.id,
                            String(schedule.id || 'n/a'),
                            String(schedule.action || ''),
                            dispatch.detail
                        );
                    }
                }

                if (changed) {
                    await Settings.upsert({
                        key,
                        value: JSON.stringify(schedules)
                    });
                }
            }
        } catch (error) {
            if (typeof bootWarn === 'function') {
                bootWarn('server schedule runner tick failed error=%s', error && error.message ? error.message : String(error));
            }
        } finally {
            running = false;
        }
    }

    timer = setInterval(() => {
        tick().catch(() => {});
    }, intervalMs);

    tick().catch(() => {});

    return function stop() {
        if (!timer) return;
        clearInterval(timer);
        timer = null;
    };
}

module.exports = {
    startServerScheduleRunner
};
