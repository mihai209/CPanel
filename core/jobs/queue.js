const os = require('os');
const crypto = require('crypto');
const { Op } = require('sequelize');

function createJobQueue({ Job, AuditLog, pollIntervalMs = 2000, lockTimeoutMs = 120000, logger = console }) {
    const handlers = new Map();
    const workerId = `${os.hostname()}-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;

    let running = false;
    let timer = null;
    let processing = false;

    function registerHandler(type, handler) {
        handlers.set(String(type), handler);
    }

    async function enqueue({ type, payload = {}, priority = 0, maxAttempts = 3, runAt = new Date(), createdByUserId = null }) {
        const job = await Job.create({
            type: String(type),
            status: 'queued',
            payload,
            priority: Number.parseInt(priority, 10) || 0,
            maxAttempts: Math.max(1, Number.parseInt(maxAttempts, 10) || 3),
            runAt: runAt instanceof Date ? runAt : new Date(runAt),
            createdByUserId
        });
        return job;
    }

    async function lockNextJob() {
        const now = new Date();
        const staleBefore = new Date(Date.now() - Math.max(30000, Number.parseInt(lockTimeoutMs, 10) || 120000));
        const candidate = await Job.findOne({
            where: {
                status: { [Op.in]: ['queued', 'retrying', 'running'] },
                runAt: { [Op.lte]: now },
                [Op.or]: [
                    { lockedAt: null },
                    { lockedAt: { [Op.lte]: staleBefore } }
                ]
            },
            order: [['priority', 'DESC'], ['runAt', 'ASC'], ['createdAt', 'ASC']]
        });

        if (!candidate) return null;

        const [updated] = await Job.update({
            status: 'running',
            lockedAt: now,
            lockOwner: workerId,
            startedAt: candidate.startedAt || now,
            lastError: candidate.lockedAt && candidate.lockedAt <= staleBefore
                ? `Recovered stale lock from ${candidate.lockOwner || 'unknown worker'}.`
                : candidate.lastError
        }, {
            where: {
                id: candidate.id,
                status: { [Op.in]: ['queued', 'retrying', 'running'] },
                [Op.or]: [
                    { lockedAt: null },
                    { lockedAt: { [Op.lte]: staleBefore } }
                ]
            }
        });

        if (!updated) return null;

        return Job.findByPk(candidate.id);
    }

    function buildRetryDelayMs(attempts) {
        const base = 15000;
        const cappedAttempt = Math.min(6, Math.max(1, attempts));
        return base * Math.pow(2, cappedAttempt - 1);
    }

    async function processOneJob() {
        if (processing) return;
        processing = true;

        try {
            const job = await lockNextJob();
            if (!job) return;

            const handler = handlers.get(String(job.type));
            if (!handler) {
                await job.update({
                    status: 'failed',
                    lastError: `No handler registered for job type: ${job.type}`,
                    attempts: job.attempts + 1,
                    finishedAt: new Date(),
                    lockedAt: null,
                    lockOwner: null
                });
                return;
            }

            try {
                const result = await handler(job);
                await job.update({
                    status: 'completed',
                    result: result || {},
                    attempts: job.attempts + 1,
                    finishedAt: new Date(),
                    lockedAt: null,
                    lockOwner: null,
                    lastError: null
                });
            } catch (error) {
                const nextAttempts = job.attempts + 1;
                const canRetry = nextAttempts < job.maxAttempts;
                const retryAt = new Date(Date.now() + buildRetryDelayMs(nextAttempts));

                await job.update({
                    status: canRetry ? 'retrying' : 'failed',
                    attempts: nextAttempts,
                    lastError: error && error.message ? error.message : String(error),
                    runAt: canRetry ? retryAt : job.runAt,
                    finishedAt: canRetry ? null : new Date(),
                    lockedAt: null,
                    lockOwner: null
                });

                if (!canRetry && AuditLog) {
                    await AuditLog.create({
                        actorUserId: job.createdByUserId || null,
                        action: 'JOB_FAILED',
                        targetType: 'job',
                        targetId: String(job.id),
                        metadata: {
                            type: job.type,
                            error: error && error.message ? error.message : String(error)
                        }
                    }).catch(() => {});
                }
            }
        } catch (error) {
            logger.warn('Job queue iteration failed:', error.message);
        } finally {
            processing = false;
        }
    }

    function start() {
        if (running) return;
        running = true;
        timer = setInterval(processOneJob, pollIntervalMs);
        processOneJob().catch(() => {});
    }

    function stop() {
        running = false;
        if (timer) {
            clearInterval(timer);
            timer = null;
        }
    }

    async function getStats() {
        const rows = await Job.findAll({ attributes: ['status'] });
        const stats = {
            queued: 0,
            running: 0,
            retrying: 0,
            completed: 0,
            failed: 0,
            cancelled: 0
        };

        for (const row of rows) {
            const status = String(row.status || '');
            if (Object.prototype.hasOwnProperty.call(stats, status)) {
                stats[status] += 1;
            }
        }

        return {
            workerId,
            running,
            pollIntervalMs,
            lockTimeoutMs,
            stats
        };
    }

    async function getById(jobId) {
        const id = Number.parseInt(jobId, 10);
        if (!Number.isInteger(id) || id <= 0) return null;
        return Job.findByPk(id);
    }

    async function waitForCompletion(jobId, timeoutMs = 60000, pollMs = 400) {
        const id = Number.parseInt(jobId, 10);
        if (!Number.isInteger(id) || id <= 0) {
            return { completed: true, status: 'failed', error: 'Invalid job id.', job: null };
        }

        const startedAt = Date.now();
        while (Date.now() - startedAt < timeoutMs) {
            const job = await Job.findByPk(id);
            if (!job) {
                return { completed: true, status: 'failed', error: 'Job not found.', job: null };
            }

            const status = String(job.status || '');
            if (status === 'completed' || status === 'failed' || status === 'cancelled') {
                return {
                    completed: true,
                    status,
                    error: job.lastError || null,
                    job
                };
            }

            await new Promise((resolve) => setTimeout(resolve, pollMs));
        }

        return { completed: false, status: 'timeout', error: null, job: await Job.findByPk(id) };
    }

    return {
        registerHandler,
        enqueue,
        start,
        stop,
        getStats,
        processOneJob,
        getById,
        waitForCompletion
    };
}

module.exports = {
    createJobQueue
};
