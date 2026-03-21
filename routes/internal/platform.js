const os = require('os');
const {
    DEFAULT_USER_PERMISSIONS,
    ADMIN_V2_DEFAULT_PERMISSIONS,
    getAdminRbacV2State
} = require('../../core/rbac');
const {
    getIncidentCenterRecords,
    updateIncidentCenterRecordStatus,
    clearIncidentCenterRecords,
    clearResolvedIncidentCenterRecords
} = require('../../core/incidents');

const EXTENSION_INCIDENTS_SETTING_KEY = 'extensionIncidentsRecords';

function parseBooleanInput(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function parsePermissionsInput(input) {
    const finalize = (entries) => Array.from(new Set(entries.map((entry) => String(entry || '').trim()).filter(Boolean))).sort();

    if (Array.isArray(input)) {
        return finalize(input);
    }

    if (typeof input === 'string') {
        return finalize(input.split(/[\n,; ]+/g));
    }

    return [];
}

function resolveApiActorUserId(req) {
    if (req.permissionUser && Number.isInteger(Number.parseInt(req.permissionUser.id, 10))) {
        return Number.parseInt(req.permissionUser.id, 10);
    }
    if (req.session && req.session.user && Number.isInteger(Number.parseInt(req.session.user.id, 10))) {
        return Number.parseInt(req.session.user.id, 10);
    }
    return null;
}

function resolveApiActorLabel(req) {
    if (req.adminApiAuth && req.adminApiAuth.type === 'api_key' && req.adminApiKey) {
        return `api_key:${req.adminApiKey.name}`;
    }
    const userId = resolveApiActorUserId(req);
    return userId ? `user:${userId}` : 'unknown';
}

function parseExtensionIncidentRecords(raw) {
    if (!raw) return [];
    let parsed = [];
    try {
        parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
        parsed = [];
    }
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => ({
            id: String(entry && entry.id || '').trim(),
            title: String(entry && entry.title || '').trim().slice(0, 140),
            message: String(entry && entry.message || '').trim().slice(0, 3000),
            severity: ['normal', 'warning', 'critical'].includes(String(entry && entry.severity || '').trim().toLowerCase())
                ? String(entry.severity).trim().toLowerCase()
                : 'normal',
            status: String(entry && entry.status || '').trim().toLowerCase() === 'resolved' ? 'resolved' : 'open',
            createdAtMs: Number.parseInt(entry && entry.createdAtMs, 10) || 0,
            updatedAtMs: Number.parseInt(entry && entry.updatedAtMs, 10) || 0,
            resolvedAtMs: Number.parseInt(entry && entry.resolvedAtMs, 10) || 0
        }))
        .filter((entry) => entry.title)
        .sort((a, b) => Number(b.createdAtMs || 0) - Number(a.createdAtMs || 0));
}

async function buildDiagnosticsBundle({
    sequelize,
    jobQueue,
    Job,
    AuditLog,
    Server,
    User,
    Connector,
    Settings
}) {
    const [queue, serverCount, userCount, connectorCount, openIncidentCount, recentJobs, recentAudit, incidentCenter] = await Promise.all([
        jobQueue.getStats(),
        Server.count(),
        User.count(),
        Connector ? Connector.count() : 0,
        (async () => {
            const records = await getIncidentCenterRecords(Settings);
            return records.filter((entry) => entry.status !== 'resolved').length;
        })(),
        Job.findAll({ order: [['createdAt', 'DESC']], limit: 50 }),
        AuditLog.findAll({ order: [['createdAt', 'DESC']], limit: 100 }),
        getIncidentCenterRecords(Settings)
    ]);

    const extIncidentRow = await Settings.findByPk(EXTENSION_INCIDENTS_SETTING_KEY);
    const extensionIncidents = parseExtensionIncidentRecords(extIncidentRow && extIncidentRow.value ? extIncidentRow.value : '[]');

    return {
        generatedAt: new Date().toISOString(),
        node: {
            hostname: os.hostname(),
            pid: process.pid,
            uptimeSeconds: Math.floor(process.uptime()),
            memory: process.memoryUsage(),
            version: process.version
        },
        database: {
            dialect: sequelize.getDialect()
        },
        queue,
        totals: {
            servers: serverCount,
            users: userCount,
            connectors: connectorCount
        },
        incidents: {
            openCount: openIncidentCount,
            incidentCenter: incidentCenter.slice(0, 200),
            extensionIncidents: extensionIncidents.slice(0, 200)
        },
        connectorStatus: global.connectorStatus || {},
        recentJobs,
        recentAudit
    };
}

function registerPlatformRoutes(deps) {
    const {
        app,
        requireAuth,
        requireAdmin,
        requirePermission,
        requireAdminApiPermission,
        Job,
        AuditLog,
        Server,
        User,
        Connector,
        Settings,
        ServerBackupPolicy,
        ServerBackup,
        jobQueue,
        bootInfo,
        sequelize
    } = deps;

    app.get('/admin/platform', requireAuth, requireAdmin, requirePermission('admin.observability.view'), async (req, res) => {
        const [servers, users, rbacState] = await Promise.all([
            Server.findAll({
                attributes: ['id', 'name', 'containerId', 'status'],
                order: [['name', 'ASC']]
            }),
            User.findAll({
                attributes: ['id', 'username', 'email', 'isAdmin', 'permissions'],
                order: [['id', 'ASC']]
            }),
            getAdminRbacV2State(Settings)
        ]);

        res.render('admin/platform-ops', {
            user: req.session.user,
            path: '/admin/platform',
            title: 'Platform Ops',
            servers,
            users,
            defaultUserPermissions: DEFAULT_USER_PERMISSIONS,
            defaultAdminPermissions: ADMIN_V2_DEFAULT_PERMISSIONS,
            rbacState,
            success: req.query.success || null,
            error: req.query.error || null
        });
    });

    app.get('/admin/incidents', requireAuth, requireAdmin, requirePermission('admin.incidents.view'), async (req, res) => {
        const [incidentCenter, extensionIncidentRow] = await Promise.all([
            getIncidentCenterRecords(Settings),
            Settings.findByPk(EXTENSION_INCIDENTS_SETTING_KEY)
        ]);
        const extensionIncidents = parseExtensionIncidentRecords(extensionIncidentRow && extensionIncidentRow.value ? extensionIncidentRow.value : '[]');

        res.render('admin/incidents', {
            user: req.session.user,
            path: '/admin/incidents',
            title: 'Incident Center',
            incidentCenter,
            extensionIncidents,
            success: req.query.success || null,
            error: req.query.error || null
        });
    });

    app.post('/admin/incidents/:id/resolve', requireAuth, requireAdmin, requirePermission('admin.incidents.manage'), async (req, res) => {
        const id = String(req.params.id || '').trim();
        if (!id) {
            return res.redirect('/admin/incidents?error=' + encodeURIComponent('Invalid incident id.'));
        }
        const updated = await updateIncidentCenterRecordStatus(Settings, id, 'resolved');
        if (!updated) {
            return res.redirect('/admin/incidents?error=' + encodeURIComponent('Incident not found.'));
        }
        return res.redirect('/admin/incidents?success=' + encodeURIComponent('Incident resolved.'));
    });

    app.post('/admin/incidents/:id/reopen', requireAuth, requireAdmin, requirePermission('admin.incidents.manage'), async (req, res) => {
        const id = String(req.params.id || '').trim();
        if (!id) {
            return res.redirect('/admin/incidents?error=' + encodeURIComponent('Invalid incident id.'));
        }
        const updated = await updateIncidentCenterRecordStatus(Settings, id, 'open');
        if (!updated) {
            return res.redirect('/admin/incidents?error=' + encodeURIComponent('Incident not found.'));
        }
        return res.redirect('/admin/incidents?success=' + encodeURIComponent('Incident reopened.'));
    });

    app.post('/admin/incidents/clear', requireAuth, requireAdmin, requirePermission('admin.incidents.manage'), async (req, res) => {
        await clearIncidentCenterRecords(Settings);
        return res.redirect('/admin/incidents?success=' + encodeURIComponent('Incident Center cleared.'));
    });

    app.post('/admin/incidents/clear-resolved', requireAuth, requireAdmin, requirePermission('admin.incidents.manage'), async (req, res) => {
        const remaining = await clearResolvedIncidentCenterRecords(Settings);
        const removed = Math.max(0, (remaining ? 0 : 0));
        return res.redirect('/admin/incidents?success=' + encodeURIComponent('Resolved incidents cleared.'));
    });

    app.get('/admin/incidents/export.json', requireAuth, requireAdmin, requirePermission('admin.incidents.view'), async (req, res) => {
        const incidentCenter = await getIncidentCenterRecords(Settings);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename="incident-center.json"');
        return res.send(JSON.stringify(incidentCenter || [], null, 2));
    });

    app.get('/admin/incidents/export.html', requireAuth, requireAdmin, requirePermission('admin.incidents.view'), async (req, res) => {
        const incidentCenter = await getIncidentCenterRecords(Settings);
        const rows = (incidentCenter || []).map((item) => ({
            id: item.id,
            title: item.title,
            message: item.message || '',
            severity: item.severity,
            status: item.status,
            source: item.source || 'runtime',
            serverId: item.serverId || '',
            createdAt: new Date(Number(item.createdAtMs || Date.now())).toLocaleString(),
            updatedAt: new Date(Number(item.updatedAtMs || Date.now())).toLocaleString()
        }));

        const escapeHtml = (value) => String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');

        const htmlRows = rows.map((row) => `
            <tr>
                <td>${escapeHtml(row.id)}</td>
                <td>${escapeHtml(row.title)}</td>
                <td>${escapeHtml(row.message)}</td>
                <td>${escapeHtml(row.severity)}</td>
                <td>${escapeHtml(row.status)}</td>
                <td>${escapeHtml(row.source)}</td>
                <td>${escapeHtml(row.serverId)}</td>
                <td>${escapeHtml(row.createdAt)}</td>
                <td>${escapeHtml(row.updatedAt)}</td>
            </tr>
        `).join('');

        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Incident Center Export</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 24px; background: #111827; color: #e5e7eb; }
        h1 { font-size: 20px; margin-bottom: 16px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th, td { border: 1px solid #374151; padding: 6px 8px; vertical-align: top; }
        th { background: #1f2937; text-align: left; }
        tr:nth-child(even) td { background: #111827; }
    </style>
</head>
<body>
    <h1>Incident Center Export</h1>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Message</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Source</th>
                <th>Server</th>
                <th>Created</th>
                <th>Updated</th>
            </tr>
        </thead>
        <tbody>
            ${htmlRows}
        </tbody>
    </table>
</body>
</html>`;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="incident-center.html"');
        return res.send(html);
    });

    app.get('/admin/platform/diagnostics', requireAuth, requireAdmin, requirePermission('admin.observability.view'), async (req, res) => {
        const bundle = await buildDiagnosticsBundle({
            sequelize,
            jobQueue,
            Job,
            AuditLog,
            Server,
            User,
            Connector,
            Settings
        });
        return res.json(bundle);
    });

    app.get('/admin/platform/diagnostics/download', requireAuth, requireAdmin, requirePermission('admin.observability.view'), async (req, res) => {
        const bundle = await buildDiagnosticsBundle({
            sequelize,
            jobQueue,
            Job,
            AuditLog,
            Server,
            User,
            Connector,
            Settings
        });
        const fileStamp = new Date().toISOString().replace(/[:]/g, '-');
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="cpanel-diagnostics-${fileStamp}.json"`);
        return res.send(JSON.stringify(bundle, null, 2));
    });

    app.get('/api/admin/diagnostics/bundle', requireAdminApiPermission('admin.observability.view'), async (req, res) => {
        const bundle = await buildDiagnosticsBundle({
            sequelize,
            jobQueue,
            Job,
            AuditLog,
            Server,
            User,
            Connector,
            Settings
        });
        return res.json(bundle);
    });

    app.get('/api/admin/jobs', requireAdminApiPermission('admin.jobs.view'), async (req, res) => {
        const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
        const jobs = await Job.findAll({ order: [['createdAt', 'DESC']], limit });
        res.json({ jobs });
    });

    app.get('/api/admin/jobs/:id', requireAdminApiPermission('admin.jobs.view'), async (req, res) => {
        const id = Number.parseInt(req.params.id, 10);
        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({ error: 'Invalid job id' });
        }

        const job = await Job.findByPk(id);
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }

        return res.json({ job });
    });

    app.post('/api/admin/jobs', requireAdminApiPermission('admin.jobs.manage'), async (req, res) => {
        const type = String(req.body.type || '').trim();
        if (!type) {
            return res.status(400).json({ error: 'type is required' });
        }

        const payload = req.body.payload && typeof req.body.payload === 'object' ? req.body.payload : {};
        const priority = Number.parseInt(req.body.priority, 10) || 0;
        const maxAttempts = Number.parseInt(req.body.maxAttempts, 10) || 3;

        const job = await jobQueue.enqueue({
            type,
            payload,
            priority,
            maxAttempts,
            createdByUserId: resolveApiActorUserId(req)
        });

        res.json({ success: true, job });
    });

    app.get('/api/admin/audit-logs', requireAdminApiPermission('admin.audit.view'), async (req, res) => {
        const limit = Math.min(500, Math.max(1, Number.parseInt(req.query.limit, 10) || 100));
        const logs = await AuditLog.findAll({
            include: [{ model: User, as: 'actor', attributes: ['id', 'username', 'email'] }],
            order: [['createdAt', 'DESC']],
            limit
        });
        res.json({ logs });
    });

    app.get('/api/admin/rbac/users', requireAdminApiPermission('admin.rbac.view'), async (req, res) => {
        const [users, state] = await Promise.all([
            User.findAll({
            attributes: ['id', 'username', 'email', 'isAdmin', 'permissions'],
            order: [['id', 'ASC']]
            }),
            getAdminRbacV2State(Settings)
        ]);
        res.json({
            users,
            rbacV2: state,
            defaults: {
                user: DEFAULT_USER_PERMISSIONS,
                admin: ADMIN_V2_DEFAULT_PERMISSIONS
            }
        });
    });

    app.post('/api/admin/rbac/users/:id', requireAdminApiPermission('admin.rbac.manage'), async (req, res) => {
        const userId = Number.parseInt(req.params.id, 10);
        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: 'Invalid user id' });
        }

        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const rbacState = await getAdminRbacV2State(Settings);
        if (user.isAdmin && !rbacState.enabled) {
            return res.status(400).json({ error: 'Enable RBAC v2 to manage admin-scoped permissions.' });
        }

        const permissions = parsePermissionsInput(req.body.permissions);
        await user.update({ permissions });

        res.json({ success: true, user: { id: user.id, username: user.username, permissions: user.permissions } });
    });

    app.get('/api/admin/rbac/settings', requireAdminApiPermission('admin.rbac.view'), async (req, res) => {
        const state = await getAdminRbacV2State(Settings);
        return res.json({
            success: true,
            featureAdminRbacV2Enabled: state.enabled,
            featureAdminRbacV2StrictEnabled: state.strict
        });
    });

    app.post('/api/admin/rbac/settings', requireAdminApiPermission('admin.rbac.manage'), async (req, res) => {
        const enabled = parseBooleanInput(req.body.featureAdminRbacV2Enabled) ? 'true' : 'false';
        const strict = parseBooleanInput(req.body.featureAdminRbacV2StrictEnabled) ? 'true' : 'false';

        await Promise.all([
            Settings.upsert({ key: 'featureAdminRbacV2Enabled', value: enabled }),
            Settings.upsert({ key: 'featureAdminRbacV2StrictEnabled', value: strict })
        ]);

        return res.json({
            success: true,
            featureAdminRbacV2Enabled: enabled === 'true',
            featureAdminRbacV2StrictEnabled: strict === 'true'
        });
    });

    app.get('/api/admin/backups/policies', requireAdminApiPermission('admin.backups.view'), async (req, res) => {
        return res.status(410).json({
            error: 'Built-in backups are disabled. Use SFTP backup workflow.'
        });
    });

    app.post('/api/admin/backups/policies/:serverId', requireAdminApiPermission('admin.backups.manage'), async (req, res) => {
        return res.status(410).json({
            error: 'Built-in backups are disabled. Use SFTP backup workflow.'
        });
    });

    app.post('/api/admin/backups/run/:serverId', requireAdminApiPermission('admin.backups.manage'), async (req, res) => {
        return res.status(410).json({
            error: 'Built-in backups are disabled. Use SFTP backup workflow.'
        });
    });

    app.get('/api/admin/backups/history/:serverId', requireAdminApiPermission('admin.backups.view'), async (req, res) => {
        return res.status(410).json({
            error: 'Built-in backups are disabled. Use SFTP backup workflow.'
        });
    });

    app.get('/api/admin/metrics', requireAdminApiPermission('admin.observability.view'), async (req, res) => {
        const queue = await jobQueue.getStats();
        const [serverCount, userCount, auditCount, backupCount] = await Promise.all([
            Server.count(),
            User.count(),
            AuditLog.count(),
            ServerBackup.count()
        ]);

        const payload = {
            node: {
                hostname: os.hostname(),
                pid: process.pid,
                uptimeSeconds: Math.floor(process.uptime()),
                memory: process.memoryUsage()
            },
            queue,
            totals: {
                servers: serverCount,
                users: userCount,
                auditLogs: auditCount,
                backups: backupCount
            },
            database: {
                dialect: sequelize.getDialect()
            }
        };

        if (typeof bootInfo === 'function') {
            bootInfo('metrics snapshot requested by actor=%s', resolveApiActorLabel(req));
        }

        res.json(payload);
    });
}

module.exports = {
    registerPlatformRoutes
};
