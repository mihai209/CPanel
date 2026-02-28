const DEFAULT_USER_PERMISSIONS = [
    'server.view',
    'server.console',
    'server.power',
    'server.files',
    'server.startup',
    'server.backups.view'
];

const ADMIN_WILDCARD = '*';
const ADMIN_RBAC_V2_SETTING_KEY = 'featureAdminRbacV2Enabled';
const ADMIN_RBAC_V2_STRICT_SETTING_KEY = 'featureAdminRbacV2StrictEnabled';
const ADMIN_V2_DEFAULT_PERMISSIONS = [
    'admin.observability.view',
    'admin.jobs.view',
    'admin.jobs.manage',
    'admin.audit.view',
    'admin.rbac.view',
    'admin.rbac.manage',
    'admin.backups.view',
    'admin.backups.manage',
    'admin.incidents.view',
    'admin.incidents.manage'
];

let rbacV2Cache = {
    ts: 0,
    enabled: false,
    strict: false
};

function normalizePermissions(rawPermissions) {
    if (!rawPermissions) return [];

    if (Array.isArray(rawPermissions)) {
        return rawPermissions.map((entry) => String(entry || '').trim()).filter(Boolean);
    }

    if (typeof rawPermissions === 'object') {
        return Object.entries(rawPermissions)
            .filter(([, enabled]) => Boolean(enabled))
            .map(([key]) => String(key || '').trim())
            .filter(Boolean);
    }

    return String(rawPermissions)
        .split(/[\n,; ]+/g)
        .map((entry) => entry.trim())
        .filter(Boolean);
}

function resolveEffectivePermissions(user, options = {}) {
    if (!user) return new Set();
    const adminWildcard = options.adminWildcard !== false;
    if (user.isAdmin && adminWildcard) return new Set([ADMIN_WILDCARD]);

    const raw = user.permissions;
    const normalized = normalizePermissions(raw);
    if (user.isAdmin && !adminWildcard) {
        if (normalized.includes(ADMIN_WILDCARD)) {
            return new Set([ADMIN_WILDCARD]);
        }
        if (normalized.length > 0) {
            return new Set(normalized);
        }
        if (options.strictAdmin === true) {
            return new Set();
        }
        return new Set(ADMIN_V2_DEFAULT_PERMISSIONS);
    }
    if (normalized.length === 0) {
        return new Set(DEFAULT_USER_PERMISSIONS);
    }
    return new Set(normalized);
}

function hasPermission(user, permission, options = {}) {
    const normalizedPermission = String(permission || '').trim();
    if (!normalizedPermission) return false;

    const perms = resolveEffectivePermissions(user, options);
    return perms.has(ADMIN_WILDCARD) || perms.has(normalizedPermission);
}

function parseSettingBool(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

async function getAdminRbacV2State(Settings) {
    if (!Settings) return { enabled: false, strict: false };

    const now = Date.now();
    if ((now - rbacV2Cache.ts) < 10_000) {
        return {
            enabled: Boolean(rbacV2Cache.enabled),
            strict: Boolean(rbacV2Cache.strict)
        };
    }

    const [enabledRow, strictRow] = await Promise.all([
        Settings.findByPk(ADMIN_RBAC_V2_SETTING_KEY),
        Settings.findByPk(ADMIN_RBAC_V2_STRICT_SETTING_KEY)
    ]);

    const next = {
        enabled: parseSettingBool(enabledRow && enabledRow.value),
        strict: parseSettingBool(strictRow && strictRow.value)
    };
    rbacV2Cache = { ...next, ts: now };
    return next;
}

async function resolveEffectivePermissionsForRequest(user, deps = {}) {
    const state = await getAdminRbacV2State(deps.Settings);
    return resolveEffectivePermissions(user, {
        adminWildcard: !state.enabled,
        strictAdmin: state.enabled && state.strict
    });
}

async function hasPermissionForRequest(user, permission, deps = {}) {
    const normalizedPermission = String(permission || '').trim();
    if (!normalizedPermission) return false;

    const perms = await resolveEffectivePermissionsForRequest(user, deps);
    return perms.has(ADMIN_WILDCARD) || perms.has(normalizedPermission);
}

function createRequirePermission({ User, Settings }) {
    return function requirePermission(permission) {
        return async (req, res, next) => {
            if (!req.session || !req.session.user) {
                return res.status(401).send('Authentication required');
            }

            try {
                const user = await User.findByPk(req.session.user.id);
                if (!user) {
                    return res.status(401).send('Authentication required');
                }

                if (!(await hasPermissionForRequest(user, permission, { Settings }))) {
                    return res.status(403).send('Access denied - missing permission');
                }

                req.permissionUser = user;
                next();
            } catch (error) {
                next(error);
            }
        };
    };
}

module.exports = {
    DEFAULT_USER_PERMISSIONS,
    ADMIN_WILDCARD,
    ADMIN_RBAC_V2_SETTING_KEY,
    ADMIN_RBAC_V2_STRICT_SETTING_KEY,
    ADMIN_V2_DEFAULT_PERMISSIONS,
    normalizePermissions,
    resolveEffectivePermissions,
    hasPermission,
    getAdminRbacV2State,
    resolveEffectivePermissionsForRequest,
    hasPermissionForRequest,
    createRequirePermission
};
