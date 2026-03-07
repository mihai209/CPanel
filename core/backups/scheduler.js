const { Op } = require('sequelize');
const { GOOGLE_DRIVE_BACKUP_DEST } = require('./google-drive');

function startBackupPolicyScheduler({
    ServerBackupPolicy,
    Job,
    jobQueue,
    intervalMs = 60 * 1000,
    bootInfo,
    bootWarn
}) {
    if (!ServerBackupPolicy || !jobQueue || !Job) {
        if (typeof bootWarn === 'function') {
            bootWarn('backup policy scheduler unavailable (missing dependencies)');
        }
        return function stop() {};
    }

    let timer = null;
    let running = false;

    function parseIntervalMinutes(raw) {
        const value = Number.parseInt(raw, 10);
        if (!Number.isInteger(value) || value <= 0) return 720;
        return Math.max(5, Math.min(10080, value));
    }

    function isDue(policy, nowTs) {
        const intervalMinutes = parseIntervalMinutes(policy && policy.intervalMinutes);
        const lastRunTs = policy && policy.lastRunAt ? Date.parse(String(policy.lastRunAt)) : NaN;
        if (!Number.isFinite(lastRunTs)) return true;
        const elapsedMs = nowTs - lastRunTs;
        return elapsedMs >= intervalMinutes * 60 * 1000;
    }

    async function tick() {
        if (running) return;
        running = true;
        try {
            const nowTs = Date.now();
            const pendingJobs = await Job.findAll({
                where: {
                    type: { [Op.in]: ['server.backup.create', 'server.backup.google_drive'] },
                    status: { [Op.in]: ['queued', 'running', 'retrying'] }
                },
                attributes: ['payload']
            });
            const pendingServerIds = new Set();
            pendingJobs.forEach((job) => {
                const payload = job && job.payload && typeof job.payload === 'object' ? job.payload : {};
                const serverId = Number.parseInt(payload.serverId, 10);
                if (Number.isInteger(serverId) && serverId > 0) {
                    pendingServerIds.add(serverId);
                }
            });

            const policies = await ServerBackupPolicy.findAll({
                where: {
                    enabled: true,
                    destinationPath: GOOGLE_DRIVE_BACKUP_DEST
                },
                attributes: ['id', 'serverId', 'intervalMinutes', 'lastRunAt']
            });

            for (const policy of policies) {
                const serverId = Number.parseInt(policy && policy.serverId, 10);
                if (!Number.isInteger(serverId) || serverId <= 0) continue;
                if (!isDue(policy, nowTs)) continue;
                if (pendingServerIds.has(serverId)) continue;

                await jobQueue.enqueue({
                    type: 'server.backup.create',
                    payload: {
                        serverId,
                        trigger: 'auto'
                    },
                    priority: -10,
                    maxAttempts: 3
                });
            }
        } catch (error) {
            if (typeof bootWarn === 'function') {
                bootWarn('backup policy scheduler tick failed error=%s', error && error.message ? error.message : error);
            }
        } finally {
            running = false;
        }
    }

    timer = setInterval(() => {
        tick().catch(() => {});
    }, Math.max(10000, Number.parseInt(intervalMs, 10) || 60000));
    tick().catch(() => {});

    if (typeof bootInfo === 'function') {
        bootInfo('backup policy scheduler enabled mode=google_drive interval_ms=%s', Math.max(10000, Number.parseInt(intervalMs, 10) || 60000));
    }

    return function stop() {
        if (timer) {
            clearInterval(timer);
            timer = null;
        }
    };
}

module.exports = {
    startBackupPolicyScheduler
};
