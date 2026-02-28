const { hasPermissionForRequest } = require('../rbac');
const {
    getAdminApiRatePlanSettingKey,
    normalizeAdminApiRatePlan,
    createAdminApiRateLimiter
} = require('../helpers/admin-api-rate-plans');

function extractRequestIp(req) {
    return (req.headers['x-forwarded-for'] || req.ip || req.connection && req.connection.remoteAddress || '')
        .toString()
        .split(',')[0]
        .trim()
        .slice(0, 120);
}

function extractRequestGeo(req) {
    const countryRaw = [
        req.headers['cf-ipcountry'],
        req.headers['x-vercel-ip-country'],
        req.headers['x-country-code'],
        req.headers['x-appengine-country'],
        req.headers['x-geo-country']
    ].find((value) => value !== undefined && value !== null && String(value).trim() !== '');
    const cityRaw = [
        req.headers['cf-ipcity'],
        req.headers['x-vercel-ip-city'],
        req.headers['x-geo-city']
    ].find((value) => value !== undefined && value !== null && String(value).trim() !== '');

    const country = String(countryRaw || '').trim().slice(0, 32);
    const city = String(cityRaw || '').trim().slice(0, 64);
    if (country && city) return `${country}/${city}`.slice(0, 160);
    if (country) return country.slice(0, 160);
    if (city) return city.slice(0, 160);
    return null;
}

function createRequireAdminApiPermission(deps) {
    const {
        User,
        AdminApiKey,
        AdminApiKeyAudit,
        Settings,
        secretKey,
        parseAdminApiBearerToken,
        hashAdminApiKeyToken,
        isAdminApiKeyIpAllowed,
        getAdminApiKeyInactiveReason,
        isAdminApiKeyActive,
        hasAdminApiKeyPermission
    } = deps;
    const rateLimiter = createAdminApiRateLimiter();
    let ratePlansFeatureCache = { value: false, ts: 0 };
    const ratePlanCache = new Map(); // keyId -> { ts, plan }

    async function isRatePlansFeatureEnabled() {
        if (!Settings) return false;
        const now = Date.now();
        if (now - ratePlansFeatureCache.ts < 10000) {
            return Boolean(ratePlansFeatureCache.value);
        }
        const row = await Settings.findByPk('featureAdminApiRatePlansEnabled');
        const enabled = row && ['1', 'true', 'on', 'yes'].includes(String(row.value || '').trim().toLowerCase());
        ratePlansFeatureCache = { value: enabled, ts: now };
        return enabled;
    }

    async function getRatePlanForKey(adminApiKeyId) {
        const keyId = Number.parseInt(adminApiKeyId, 10) || 0;
        if (keyId <= 0 || !Settings) return normalizeAdminApiRatePlan({});
        const now = Date.now();
        const cached = ratePlanCache.get(keyId);
        if (cached && (now - cached.ts) < 10000) {
            return cached.plan;
        }

        const row = await Settings.findByPk(getAdminApiRatePlanSettingKey(keyId));
        const plan = normalizeAdminApiRatePlan(row ? row.value : null);
        ratePlanCache.set(keyId, { ts: now, plan });
        return plan;
    }

    return function requireAdminApiPermission(permission) {
        const neededPermission = String(permission || '').trim();

        return async (req, res, next) => {
            try {
                let sessionAuthFailure = null;
                const sessionUserId = Number.parseInt(req.session && req.session.user ? req.session.user.id : NaN, 10);
                if (Number.isInteger(sessionUserId) && sessionUserId > 0) {
                    const user = await User.findByPk(sessionUserId);
                    if (!user) {
                        sessionAuthFailure = { status: 401, error: 'Authentication required.' };
                    } else if (!user.isAdmin) {
                        sessionAuthFailure = { status: 403, error: 'Admin access required.' };
                    } else if (!(await hasPermissionForRequest(user, neededPermission, { Settings }))) {
                        sessionAuthFailure = { status: 403, error: 'Missing admin permission.' };
                    } else {
                        req.permissionUser = user;
                        req.adminApiAuth = {
                            type: 'session',
                            permission: neededPermission
                        };
                        return next();
                    }
                }

                const parsedBearer = parseAdminApiBearerToken(req.headers.authorization || '');
                if (!parsedBearer || !parsedBearer.token) {
                    if (sessionAuthFailure) {
                        return res.status(sessionAuthFailure.status).json({ error: sessionAuthFailure.error });
                    }
                    return res.status(401).json({ error: 'Missing valid admin API key.' });
                }

                const tokenHash = hashAdminApiKeyToken(parsedBearer.token, secretKey);
                if (!tokenHash) {
                    return res.status(401).json({ error: 'Invalid admin API key.' });
                }

                const apiKey = await AdminApiKey.findOne({
                    where: { keyHash: tokenHash }
                });
                if (!apiKey) {
                    return res.status(401).json({ error: 'Admin API key is inactive or invalid.' });
                }

                const inactiveReason = typeof getAdminApiKeyInactiveReason === 'function'
                    ? getAdminApiKeyInactiveReason(apiKey)
                    : (!isAdminApiKeyActive(apiKey) ? 'inactive' : null);
                if (inactiveReason) {
                    return res.status(401).json({
                        error: 'Admin API key is inactive or invalid.',
                        reason: inactiveReason
                    });
                }

                const requestIp = extractRequestIp(req);
                if (typeof isAdminApiKeyIpAllowed === 'function' && !isAdminApiKeyIpAllowed(apiKey, requestIp)) {
                    return res.status(403).json({ error: 'Request IP is not allowed for this admin API key.' });
                }
                if (!hasAdminApiKeyPermission(apiKey, neededPermission)) {
                    return res.status(403).json({ error: 'Admin API key lacks required permission.' });
                }

                const requestGeo = extractRequestGeo(req);
                req.adminApiKey = apiKey;
                req.adminApiAuth = {
                    type: 'api_key',
                    permission: neededPermission
                };

                if (await isRatePlansFeatureEnabled()) {
                    const plan = await getRatePlanForKey(apiKey.id);
                    const rateEval = rateLimiter.consume(apiKey.id, plan, Date.now());
                    if (!rateEval.ok) {
                        if (rateEval.headers && typeof rateEval.headers === 'object') {
                            Object.entries(rateEval.headers).forEach(([headerKey, headerValue]) => {
                                if (headerValue !== undefined && headerValue !== null && headerValue !== '') {
                                    res.setHeader(headerKey, String(headerValue));
                                }
                            });
                        }

                        if (AdminApiKeyAudit) {
                            AdminApiKeyAudit.create({
                                adminApiKeyId: apiKey.id,
                                method: String(req.method || '').toUpperCase().slice(0, 10) || null,
                                path: String(req.originalUrl || req.url || '').slice(0, 255) || null,
                                permission: neededPermission || null,
                                statusCode: 429,
                                ip: requestIp || null,
                                userAgent: String(req.headers['user-agent'] || '').slice(0, 2000) || null,
                                metadata: {
                                    reason: 'admin_api_rate_limited',
                                    scope: rateEval.scope || null,
                                    retryAfterSeconds: rateEval.retryAfterSeconds || 0,
                                    geo: requestGeo || null
                                }
                            }).catch(() => {
                                // Ignore rate limit audit write failures.
                            });
                        }

                        return res.status(429).json({
                            error: 'Admin API rate limit exceeded.',
                            scope: rateEval.scope || null,
                            retryAfterSeconds: rateEval.retryAfterSeconds || 0
                        });
                    }
                    if (rateEval.headers && typeof rateEval.headers === 'object') {
                        Object.entries(rateEval.headers).forEach(([headerKey, headerValue]) => {
                            if (headerValue !== undefined && headerValue !== null && headerValue !== '') {
                                res.setHeader(headerKey, String(headerValue));
                            }
                        });
                    }
                }

                apiKey.update({
                    lastUsedAt: new Date(),
                    lastUsedIp: requestIp || null,
                    lastUsedGeo: requestGeo || null
                }).catch(() => {
                    // Ignore key metadata update failures.
                });

                if (AdminApiKeyAudit) {
                    res.on('finish', () => {
                        AdminApiKeyAudit.create({
                            adminApiKeyId: apiKey.id,
                            method: String(req.method || '').toUpperCase().slice(0, 10) || null,
                            path: String(req.originalUrl || req.url || '').slice(0, 255) || null,
                            permission: neededPermission || null,
                            statusCode: Number.isInteger(res.statusCode) ? res.statusCode : null,
                            ip: requestIp || null,
                            userAgent: String(req.headers['user-agent'] || '').slice(0, 2000) || null,
                            metadata: {
                                query: req.query || {},
                                params: req.params || {},
                                geo: requestGeo || null
                            }
                        }).catch(() => {
                            // Ignore admin API key usage audit write failures.
                        });
                    });
                }

                return next();
            } catch (error) {
                return next(error);
            }
        };
    };
}

module.exports = {
    createRequireAdminApiPermission
};
