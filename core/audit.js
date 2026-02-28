const SENSITIVE_KEYS = new Set([
    'password',
    'newPassword',
    'confirmPassword',
    'currentPassword',
    'token',
    'clientSecret',
    'secret',
    'twoFactorSecret',
    'telegramBotToken',
    'discordWebhook'
]);

function redactValue(value) {
    if (Array.isArray(value)) {
        return value.map((entry) => redactValue(entry));
    }

    if (value && typeof value === 'object') {
        const output = {};
        for (const [key, entry] of Object.entries(value)) {
            if (SENSITIVE_KEYS.has(key)) {
                output[key] = '[REDACTED]';
            } else {
                output[key] = redactValue(entry);
            }
        }
        return output;
    }

    return value;
}

function shouldAuditRequest(req) {
    const method = String(req.method || '').toUpperCase();
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return false;

    const path = String(req.path || '');
    return path.startsWith('/admin')
        || path.startsWith('/server')
        || path.startsWith('/api/servers')
        || path.startsWith('/account');
}

function extractAuditAction(req) {
    const method = String(req.method || '').toUpperCase();
    const path = String(req.path || '');
    return `${method} ${path}`;
}

function registerAuditMiddleware({ app, AuditLog }) {
    app.use((req, res, next) => {
        if (!shouldAuditRequest(req)) return next();

        const startedAt = Date.now();
        const actorUserId = req.session && req.session.user ? req.session.user.id : null;
        const action = extractAuditAction(req);

        res.on('finish', () => {
            if (res.statusCode < 200 || res.statusCode >= 500) return;

            AuditLog.create({
                actorUserId,
                action,
                targetType: null,
                targetId: null,
                method: req.method,
                path: req.originalUrl || req.url,
                ip: req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || null,
                userAgent: req.headers['user-agent'] || null,
                metadata: {
                    statusCode: res.statusCode,
                    durationMs: Date.now() - startedAt,
                    body: redactValue(req.body || {}),
                    query: redactValue(req.query || {}),
                    params: redactValue(req.params || {})
                }
            }).catch((error) => {
                console.warn('Audit middleware failed to persist log:', error.message);
            });
        });

        next();
    });
}

module.exports = {
    registerAuditMiddleware,
    shouldAuditRequest,
    redactValue
};
