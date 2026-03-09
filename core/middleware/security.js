const helmet = require('helmet');
const cors = require('cors');
const express = require('express');
const crypto = require('crypto');
const { Op } = require('sequelize');

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const BLOCK_SIGNATURES = [
    { id: 'path_traversal', pattern: /(\.\.[\\/]|%2e%2e%2f|%2e%2e%5c)/i },
    { id: 'null_byte', pattern: /%00|\u0000/i },
    { id: 'jndi_injection', pattern: /\$\{jndi:/i }
];
const SUSPICIOUS_SIGNATURES = [
    { id: 'sqli_union', pattern: /\bunion\b[\s\S]{0,20}\bselect\b/i },
    { id: 'sqli_tautology', pattern: /(?:'|%27)\s*or\s*(?:'|%27)?1(?:'|%27)?\s*=\s*(?:'|%27)?1/i },
    { id: 'xss_script', pattern: /<script\b/i },
    { id: 'scanner_path', pattern: /(wp-login\.php|xmlrpc\.php|phpmyadmin|\/cgi-bin\/)/i }
];
const SUSPICIOUS_USER_AGENTS = /(sqlmap|nikto|nmap|masscan|zgrab|wpscan|acunetix|dirbuster|gobuster|nessus)/i;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);

function normalizeOrigin(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    try {
        const parsed = new URL(raw);
        return `${parsed.protocol}//${parsed.host}`.toLowerCase();
    } catch {
        return '';
    }
}

function parseAllowedOrigins() {
    const list = new Set();
    const fromEnv = String(process.env.CORS_ALLOWED_ORIGINS || '')
        .split(',')
        .map((entry) => normalizeOrigin(entry))
        .filter(Boolean);
    fromEnv.forEach((entry) => list.add(entry));

    const appUrl = normalizeOrigin(process.env.APP_URL || '');
    if (appUrl) list.add(appUrl);

    const appPort = Number.parseInt(process.env.APP_PORT || '3000', 10) || 3000;
    list.add(`http://localhost:${appPort}`);
    list.add(`http://127.0.0.1:${appPort}`);

    return list;
}

function extractIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const raw = Array.isArray(forwarded)
        ? forwarded[0]
        : String(forwarded || '').split(',')[0];
    const value = String(raw || req.ip || (req.socket && req.socket.remoteAddress) || '').trim();
    return value.replace(/^::ffff:/, '') || null;
}

function truncate(value, max = 255) {
    const text = String(value === undefined || value === null ? '' : value);
    if (text.length <= max) return text;
    return `${text.slice(0, max - 3)}...`;
}

function sanitizeMetadata(value, depth = 0) {
    if (depth > 4) return '[DEPTH_LIMIT]';
    if (Array.isArray(value)) {
        return value.slice(0, 40).map((entry) => sanitizeMetadata(entry, depth + 1));
    }
    if (value && typeof value === 'object') {
        const out = {};
        for (const [key, entry] of Object.entries(value).slice(0, 50)) {
            out[String(key)] = sanitizeMetadata(entry, depth + 1);
        }
        return out;
    }
    if (typeof value === 'string') return truncate(value, 1000);
    if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
    return String(value);
}

function flattenValues(value, out = [], depth = 0) {
    if (out.length >= 200 || depth > 5 || value === undefined || value === null) return out;
    if (Array.isArray(value)) {
        value.forEach((entry) => flattenValues(entry, out, depth + 1));
        return out;
    }
    if (typeof value === 'object') {
        Object.entries(value).slice(0, 100).forEach(([key, entry]) => {
            out.push(String(key));
            flattenValues(entry, out, depth + 1);
        });
        return out;
    }
    out.push(String(value));
    return out;
}

function findSignature(samples, signatures) {
    for (const signature of signatures) {
        if (samples.some((sample) => signature.pattern.test(sample))) {
            return signature.id;
        }
    }
    return '';
}

function registerSecurityMiddleware(app, options = {}) {
    const SecurityEvent = options.SecurityEvent || null;
    const allowedOrigins = parseAllowedOrigins();
    const maxBodyMb = Math.max(1, Math.min(10, Number.parseInt(process.env.SECURITY_MAX_BODY_MB || '2', 10) || 2));
    const requestLimit = `${maxBodyMb}mb`;
    let lastRetentionSweepMs = 0;
    let retentionSweepRunning = false;
    const retentionDays = Math.max(1, Math.min(365, Number.parseInt(process.env.SENTRY_SEEKER_RETENTION_DAYS || '30', 10) || 30));

    const logSecurityEvent = (req, payload) => {
        if (!SecurityEvent || typeof SecurityEvent.create !== 'function') return;
        const userId = req && req.session && req.session.user && Number.isInteger(Number(req.session.user.id))
            ? Number(req.session.user.id)
            : null;
        SecurityEvent.create({
            userId,
            severity: truncate(payload && payload.severity ? payload.severity : 'medium', 16),
            category: truncate(payload && payload.category ? payload.category : 'request', 40),
            eventType: truncate(payload && payload.eventType ? payload.eventType : 'unknown', 120),
            message: truncate(payload && payload.message ? payload.message : 'Security event', 255),
            source: truncate(payload && payload.source ? payload.source : 'panel', 40),
            method: truncate(req && req.method ? req.method : (payload && payload.method) || '', 10) || null,
            path: truncate((req && (req.originalUrl || req.url)) || (payload && payload.path) || '', 255) || null,
            ip: truncate((req && extractIp(req)) || (payload && payload.ip) || '', 120) || null,
            userAgent: truncate((req && req.headers && req.headers['user-agent']) || (payload && payload.userAgent) || '', 2000) || null,
            requestId: truncate((req && req.requestId) || (payload && payload.requestId) || '', 64) || null,
            metadata: sanitizeMetadata(payload && payload.metadata ? payload.metadata : {})
        }).then(() => {
            const now = Date.now();
            if (retentionSweepRunning || now - lastRetentionSweepMs < (60 * 60 * 1000)) return;
            retentionSweepRunning = true;
            lastRetentionSweepMs = now;
            const cutoff = new Date(now - (retentionDays * 24 * 60 * 60 * 1000));
            SecurityEvent.destroy({
                where: {
                    createdAt: { [Op.lt]: cutoff }
                }
            }).catch(() => {}).finally(() => {
                retentionSweepRunning = false;
            });
        }).catch(() => {});
    };

    app.disable('x-powered-by');

    app.use((req, res, next) => {
        req.requestId = typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : crypto.randomBytes(16).toString('hex');
        res.setHeader('X-Request-Id', req.requestId);
        next();
    });

    app.use(helmet({
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        crossOriginResourcePolicy: { policy: 'cross-origin' },
        hsts: {
            maxAge: 15552000,
            includeSubDomains: true,
            preload: false
        },
        contentSecurityPolicy: {
            directives: {
                ...helmet.contentSecurityPolicy.getDefaultDirectives(),
                "img-src": ["'self'", "data:", "https:", "http:", "blob:"],
                "script-src": ["'self'", "'unsafe-inline'", "blob:", "https://cdn.jsdelivr.net", "https://storage.ko-fi.com"],
                "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
                "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
                "connect-src": ["'self'", "https://cdn.jsdelivr.net", "https://storage.ko-fi.com", "https://ko-fi.com", "ws:", "wss:"],
                "frame-src": ["'self'", "https://storage.ko-fi.com", "https://ko-fi.com"],
                "worker-src": ["'self'", "blob:"],
            },
        },
    }));

    app.use(cors({
        origin: (origin, cb) => {
            if (!origin) return cb(null, true);
            const normalized = normalizeOrigin(origin);
            if (!normalized || allowedOrigins.has(normalized)) return cb(null, true);
            return cb(null, false);
        },
        credentials: true,
        methods: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'],
        optionsSuccessStatus: 204
    }));

    app.use(express.json({ limit: requestLimit, strict: true }));
    app.use(express.urlencoded({ extended: false, limit: requestLimit, parameterLimit: 300 }));

    app.use((err, req, res, next) => {
        if (err && err.type === 'entity.too.large') {
            logSecurityEvent(req, {
                severity: 'high',
                category: 'request',
                eventType: 'request.body_too_large',
                message: `Rejected request body larger than ${requestLimit}.`,
                metadata: {
                    contentLength: req.headers['content-length'] || null
                }
            });
            return res.status(413).send('Payload too large');
        }
        if (err && err instanceof SyntaxError && Object.prototype.hasOwnProperty.call(err, 'body')) {
            logSecurityEvent(req, {
                severity: 'medium',
                category: 'request',
                eventType: 'request.invalid_json',
                message: 'Invalid JSON payload rejected.'
            });
            return res.status(400).send('Invalid JSON payload');
        }
        return next(err);
    });

    app.use((req, res, next) => {
        const method = String(req.method || '').toUpperCase();
        if (!SAFE_METHODS.has(method)) {
            logSecurityEvent(req, {
                severity: 'high',
                category: 'request',
                eventType: 'request.invalid_method',
                message: `Blocked unsupported HTTP method: ${method}`
            });
            return res.status(405).send('Method Not Allowed');
        }

        const secFetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
        const requestOrigin = normalizeOrigin(req.headers.origin || '');
        const requestReferer = normalizeOrigin(req.headers.referer || '');
        const currentOrigin = normalizeOrigin(`${req.protocol}://${req.get('host')}`);
        const trustedOrigins = new Set([currentOrigin, ...allowedOrigins].filter(Boolean));

        if (MUTATING_METHODS.has(method)) {
            if (secFetchSite === 'cross-site') {
                logSecurityEvent(req, {
                    severity: 'high',
                    category: 'csrf',
                    eventType: 'csrf.sec_fetch_site_block',
                    message: 'Blocked cross-site mutating request by Sec-Fetch-Site.',
                    metadata: { secFetchSite }
                });
                return res.status(403).send('Forbidden');
            }

            if (requestOrigin && !trustedOrigins.has(requestOrigin)) {
                logSecurityEvent(req, {
                    severity: 'high',
                    category: 'csrf',
                    eventType: 'csrf.origin_block',
                    message: 'Blocked mutating request from untrusted Origin header.',
                    metadata: { origin: requestOrigin }
                });
                return res.status(403).send('Forbidden');
            }

            if (!requestOrigin && requestReferer && !trustedOrigins.has(requestReferer)) {
                logSecurityEvent(req, {
                    severity: 'high',
                    category: 'csrf',
                    eventType: 'csrf.referer_block',
                    message: 'Blocked mutating request from untrusted Referer header.',
                    metadata: { referer: requestReferer }
                });
                return res.status(403).send('Forbidden');
            }
        }

        const queryKeyCount = req.query && typeof req.query === 'object' ? Object.keys(req.query).length : 0;
        if (queryKeyCount > 200) {
            logSecurityEvent(req, {
                severity: 'high',
                category: 'request',
                eventType: 'request.query_overflow',
                message: `Blocked request with excessive query parameters (${queryKeyCount}).`
            });
            return res.status(400).send('Bad Request');
        }

        const scanSamples = flattenValues({
            path: String(req.originalUrl || req.url || ''),
            query: req.query || {},
            body: req.body || {}
        });
        const blockSignature = findSignature(scanSamples, BLOCK_SIGNATURES);
        if (blockSignature) {
            logSecurityEvent(req, {
                severity: 'critical',
                category: 'request',
                eventType: 'request.blocked_signature',
                message: `Blocked request due to signature: ${blockSignature}.`,
                metadata: { signature: blockSignature }
            });
            return res.status(403).send('Request blocked by security policy');
        }

        const suspiciousSignature = findSignature(scanSamples, SUSPICIOUS_SIGNATURES);
        if (suspiciousSignature) {
            logSecurityEvent(req, {
                severity: 'medium',
                category: 'request',
                eventType: 'request.suspicious_signature',
                message: `Suspicious request signature detected: ${suspiciousSignature}.`,
                metadata: { signature: suspiciousSignature }
            });
        }

        const userAgent = String(req.headers['user-agent'] || '');
        if (userAgent && SUSPICIOUS_USER_AGENTS.test(userAgent)) {
            logSecurityEvent(req, {
                severity: 'medium',
                category: 'request',
                eventType: 'request.suspicious_user_agent',
                message: 'Suspicious user-agent fingerprint detected.',
                metadata: { userAgent: truncate(userAgent, 220) }
            });
        }

        res.on('finish', () => {
            const statusCode = Number(res.statusCode || 0);
            const path = String(req.path || '');
            const isSensitivePath =
                path.startsWith('/admin')
                || path.startsWith('/api/admin')
                || path.startsWith('/server')
                || path.startsWith('/account')
                || path.startsWith('/login');

            if (statusCode >= 500) {
                logSecurityEvent(req, {
                    severity: 'high',
                    category: 'response',
                    eventType: 'response.server_error',
                    message: `Server responded with ${statusCode}.`,
                    metadata: { statusCode }
                });
                return;
            }

            if (statusCode === 429) {
                if (req.__securityRateLimitedLogged) return;
                logSecurityEvent(req, {
                    severity: 'medium',
                    category: 'rate_limit',
                    eventType: 'rate_limit.hit',
                    message: 'Request was rate-limited.',
                    metadata: { statusCode }
                });
                return;
            }

            if (isSensitivePath && (statusCode === 401 || statusCode === 403)) {
                logSecurityEvent(req, {
                    severity: 'medium',
                    category: 'authz',
                    eventType: 'authz.denied',
                    message: `Access denied on sensitive path (${statusCode}).`,
                    metadata: { statusCode, path }
                });
            }
        });

        return next();
    });
}

module.exports = {
    registerSecurityMiddleware
};
