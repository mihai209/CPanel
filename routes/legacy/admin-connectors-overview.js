const fs = require('fs');
const pathLib = require('path');
const nodeCrypto = require('node:crypto');

const WEB_SERVER_TEMPLATE_FILES = Object.freeze({
    nginx: 'nginx.conf',
    apache2: 'apache2.conf',
    standalone: 'standalone.conf'
});
const DEFAULT_WEB_SERVER_TEMPLATE = 'standalone';

function resolveWebServerTemplateType(rawType) {
    const type = String(rawType || '').trim().toLowerCase();
    return WEB_SERVER_TEMPLATE_FILES[type] ? type : DEFAULT_WEB_SERVER_TEMPLATE;
}

function readWebServerTemplate(type) {
    const filename = WEB_SERVER_TEMPLATE_FILES[type];
    if (!filename) {
        throw new Error(`Unsupported template type: ${type}`);
    }

    const templatePath = pathLib.join(__dirname, '../../conf', filename);
    return fs.readFileSync(templatePath, 'utf8');
}

function renderWebServerTemplate(type, panelUrl) {
    let content = readWebServerTemplate(type);

    let panelHost = 'panel.example.com';
    try {
        panelHost = new URL(panelUrl).host || panelHost;
    } catch {
        // Keep default placeholder host when URL parsing fails.
    }

    content = content.replace(/panel\.example\.com/g, panelHost);

    if (type === 'standalone') {
        content = content.replace(/^app_url\s*=.*$/m, `app_url = ${panelUrl}`);
    }

    return content;
}

function normalizeAllocationNotes(raw) {
    const compact = String(raw || '')
        .replace(/\s+/g, ' ')
        .trim();
    const sliced = compact.slice(0, 20);
    return sliced || null;
}

function normalizeAllocationAlias(raw) {
    const compact = String(raw || '')
        .replace(/\s+/g, ' ')
        .trim();
    const sliced = compact.slice(0, 191);
    return sliced || null;
}

function parseAllocationIds(rawIds, maxItems = 2000) {
    const values = Array.isArray(rawIds) ? rawIds : (rawIds === undefined || rawIds === null ? [] : [rawIds]);
    const seen = new Set();
    const output = [];

    for (const value of values) {
        const parsed = Number.parseInt(value, 10);
        if (!Number.isInteger(parsed) || parsed <= 0 || seen.has(parsed)) continue;
        seen.add(parsed);
        output.push(parsed);
        if (output.length >= maxItems) break;
    }

    return output;
}

function parseServerIds(rawIds, maxItems = 2000) {
    const values = Array.isArray(rawIds) ? rawIds : (rawIds === undefined || rawIds === null ? [] : [rawIds]);
    const seen = new Set();
    const output = [];
    for (const value of values) {
        const parsed = Number.parseInt(value, 10);
        if (!Number.isInteger(parsed) || parsed <= 0 || seen.has(parsed)) continue;
        seen.add(parsed);
        output.push(parsed);
        if (output.length >= maxItems) break;
    }
    return output;
}

function renderAllocationAliasTemplate(template, allocation) {
    const sourceTemplate = String(template || '');
    const currentAlias = String(allocation && allocation.alias || '');
    const rendered = sourceTemplate
        .replace(/\{ip\}/gi, String(allocation && allocation.ip || ''))
        .replace(/\{port\}/gi, String(allocation && allocation.port || ''))
        .replace(/\{id\}/gi, String(allocation && allocation.id || ''))
        .replace(/\{alias\}/gi, currentAlias);

    return normalizeAllocationAlias(rendered);
}

function normalizeBooleanInput(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    const normalized = String(value).trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(normalized);
}

function normalizeNumberInput(value, fallback, min, max) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function parseLinesInput(value) {
    return String(value || '')
        .split(/\r?\n|,/g)
        .map((entry) => entry.trim())
        .filter(Boolean);
}

function registerAdminConnectorsOverviewRoutes(ctx) {
    for (const [key, value] of Object.entries(ctx || {})) {
        try {
            globalThis[key] = value;
        } catch {
            // Ignore non-writable globals (e.g. crypto on newer Node versions).
        }
    }
app.get('/admin/connect-info', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connectors = await Connector.findAll({
            include: [{ model: Location, as: 'location' }]
        });

        // Fetch allocation counts for each connector
        const nodeStats = {};
        for (const conn of connectors) {
            const allocatedUsage = await getConnectorAllocatedUsage(conn.id);
            nodeStats[conn.id] = {
                allocations: await Allocation.count({ where: { connectorId: conn.id } }),
                servers: await Server.count({
                    include: [{
                        model: Allocation,
                        as: 'allocation',
                        where: { connectorId: conn.id }
                    }]
                }),
                memoryAllocatedGb: allocatedUsage.memoryGb,
                diskAllocatedGb: allocatedUsage.diskGb
            };
        }

        res.render('admin/connect-info', {
            user: req.session.user,
            connectors,
            connectorStatus: global.connectorStatus || {},
            nodeStats,
            success: req.query.success || null,
            error: req.query.error || null,
            path: '/admin/connect-info',
            settings: res.locals.settings
        });
    } catch (error) {
        console.error("Error loading connect-info:", error);
        res.redirect('/admin/overview?error=Failed to load node health dashboard');
    }
});

app.get('/admin/connectors', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connectors = await Connector.findAll({ include: [{ model: Location, as: 'location' }] });
        const locations = await Location.findAll();
        const panelOrigin = extractOriginFromUrl(resolvePanelBaseUrl(req));
        const allowedOriginsMap = await getConnectorAllowedOriginsMap(connectors.map((connector) => connector.id), panelOrigin);
        const connectorsView = connectors.map((connector) => {
            const data = connector.toJSON();
            const allowedOrigins = allowedOriginsMap[connector.id] || [];
            data.allowedOrigins = allowedOrigins.join('\n');
            return data;
        });

        console.log('[DEBUG] Server-side connectors:', connectors.map(c => c.name));
        console.log('[DEBUG] Server-side connectorStatus:', global.connectorStatus);
        res.render('admin/connectors', {
            user: req.session.user,
            connectors: connectorsView,
            locations,
            defaultAllowedOrigins: panelOrigin || '',
            connectorStatus: global.connectorStatus || {},
            path: '/admin/connectors',
            success: req.query.success,
            error: req.query.error,
            settings: res.locals.settings
        });
    } catch (err) {
        console.error("Error fetching connectors:", err);
        res.status(500).send("Error fetching connectors");
    }
});

// Admin Connectors (POST - Create)
app.post('/admin/connectors', requireAuth, requireAdmin, [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('fqdn').trim().notEmpty().withMessage('FQDN is required'),
    body('port').isInt().withMessage('Port must be a number'),
    body('sftpPort').isInt().withMessage('SFTP Port must be a number'),
    body('locationId').isInt().withMessage('Location is required'),
    body('fileDirectory').trim().notEmpty().withMessage('File Directory is required'),
    body('totalMemory').isInt().withMessage('Total Memory is required'),
    body('totalDisk').isInt().withMessage('Total Disk is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(`/admin/connectors?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    try {
        const { name, fqdn, port, sftpPort, ssl, isPublic, locationId, fileDirectory, totalMemory, memoryOverAllocation, totalDisk, diskOverAllocation, description, allowedUrls } = req.body;
        const panelOrigin = extractOriginFromUrl(resolvePanelBaseUrl(req));
        const { origins: allowedOrigins, invalid } = parseAllowedOriginsInput(allowedUrls, panelOrigin);
        if (invalid.length > 0) {
            return res.redirect(`/admin/connectors?error=${encodeURIComponent(`Invalid allowed URL(s): ${invalid.join(', ')}`)}`);
        }

        // Generate secure token for connector
        const token = nodeCrypto.randomBytes(32).toString('hex');

        const newConnector = await Connector.create({
            name,
            fqdn,
            port: parseInt(port),
            sftpPort: parseInt(sftpPort),
            ssl: ssl === 'on' || ssl === true || ssl === 'true',
            locationId: parseInt(locationId),
            fileDirectory,
            totalMemory: parseInt(totalMemory),
            memoryOverAllocation: parseInt(memoryOverAllocation) || 0,
            totalDisk: parseInt(totalDisk),
            diskOverAllocation: parseInt(diskOverAllocation) || 0,
            isPublic: normalizeBooleanInput(isPublic, false),
            description,
            token
        });

        await setConnectorAllowedOrigins(newConnector.id, allowedOrigins);

        res.redirect('/admin/connectors?success=Connector created successfully!');
    } catch (error) {
        console.error("Error creating connector:", error);
        res.redirect('/admin/connectors?error=Failed to create connector.');
    }
});

// Admin Connectors (POST - Edit)
app.post('/admin/connectors/edit/:id', requireAuth, requireAdmin, [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('fqdn').trim().notEmpty().withMessage('FQDN is required'),
    body('port').isInt().withMessage('Port must be a number'),
    body('sftpPort').isInt().withMessage('SFTP Port must be a number'),
    body('locationId').isInt().withMessage('Location is required'),
    body('fileDirectory').trim().notEmpty().withMessage('File Directory is required'),
    body('totalMemory').isInt().withMessage('Total Memory is required'),
    body('totalDisk').isInt().withMessage('Total Disk is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(`/admin/connectors?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    try {
        const panelOrigin = extractOriginFromUrl(resolvePanelBaseUrl(req));
        const { origins: allowedOrigins, invalid } = parseAllowedOriginsInput(req.body.allowedUrls, panelOrigin);
        if (invalid.length > 0) {
            return res.redirect(`/admin/connectors?error=${encodeURIComponent(`Invalid allowed URL(s): ${invalid.join(', ')}`)}`);
        }

        await Connector.update({
            name: req.body.name,
            fqdn: req.body.fqdn,
            port: req.body.port,
            sftpPort: req.body.sftpPort,
            ssl: req.body.ssl === 'on' || req.body.ssl === true || req.body.ssl === 'true',
            locationId: req.body.locationId,
            fileDirectory: req.body.fileDirectory,
            totalMemory: req.body.totalMemory,
            memoryOverAllocation: req.body.memoryOverAllocation || 0,
            totalDisk: req.body.totalDisk,
            diskOverAllocation: req.body.diskOverAllocation || 0,
            isPublic: normalizeBooleanInput(req.body.isPublic, false),
            description: req.body.description
        }, { where: { id: req.params.id } });

        await setConnectorAllowedOrigins(req.params.id, allowedOrigins);

        res.redirect('/admin/connectors?success=Connector updated successfully!');
    } catch (error) {
        console.error("Error updating connector:", error);
        res.redirect('/admin/connectors?error=Failed to update connector.');
    }
});

// Admin Connectors (POST - Delete)
app.post('/admin/connectors/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        // Check if connector is used by any server (via allocations)
        const serverCount = await Allocation.count({
            where: {
                connectorId: req.params.id,
                serverId: { [Op.ne]: null }
            }
        });

        if (serverCount > 0) {
            return res.redirect(`/admin/connectors?error=Cannot delete connector because it is currently hosting ${serverCount} server(s).`);
        }

        // Delete all allocations for this connector (they are confirmed to be empty)
        await Allocation.destroy({ where: { connectorId: req.params.id } });
        await Settings.destroy({ where: { key: getConnectorAllowedOriginsSettingKey(req.params.id) } });

        await Connector.destroy({ where: { id: req.params.id } });
        res.redirect('/admin/connectors?success=Connector deleted successfully!');
    } catch (error) {
        console.error("Error deleting connector:", error);
        res.redirect('/admin/connectors?error=Failed to delete connector.');
    }
});
app.get('/admin/connectors/:id/manage', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connector = await Connector.findByPk(req.params.id, { include: [{ model: Location, as: 'location' }] });
        if (!connector) {
            return res.redirect('/admin/connectors?error=Connector not found.');
        }
        const statusData = (global.connectorStatus && global.connectorStatus[req.params.id]) || { status: 'offline', lastSeen: null, usage: null };
        const allocatedUsage = await getConnectorAllocatedUsage(req.params.id);

        res.render('admin/manage-connector', {
            user: req.session.user,
            connector,
            currentTab: 'overview',
            allocations: [],
            statusData,
            allocatedUsage,
            path: '/admin/connectors',
            settings: res.locals.settings
        });
    } catch (err) {
        console.error("Error fetching connector for manage:", err);
        res.redirect('/admin/connectors?error=Error fetching connector.');
    }
});

// Admin Connector Allocations (GET)
app.get('/admin/connectors/:id/allocations', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connector = await Connector.findByPk(req.params.id, { include: [{ model: Location, as: 'location' }] });
        if (!connector) {
            return res.redirect('/admin/connectors?error=Connector not found.');
        }
        const allocations = await Allocation.findAll({
            where: { connectorId: req.params.id },
            order: [['port', 'ASC'], ['id', 'ASC']]
        });
        const allocationIds = allocations
            .map((allocation) => Number.parseInt(allocation && allocation.id, 10))
            .filter((allocationId) => Number.isInteger(allocationId) && allocationId > 0);
        const assignedServerIds = Array.from(new Set(
            allocations
                .map((allocation) => Number.parseInt(allocation && allocation.serverId, 10))
                .filter((serverId) => Number.isInteger(serverId) && serverId > 0)
        ));
        const assignedServers = assignedServerIds.length
            ? await Server.findAll({
                where: { id: assignedServerIds },
                attributes: ['id', 'name', 'containerId'],
                raw: true
            })
            : [];
        const primaryServersByAllocation = allocationIds.length
            ? await Server.findAll({
                where: { allocationId: allocationIds },
                attributes: ['id', 'name', 'containerId', 'allocationId'],
                raw: true
            })
            : [];
        const assignedServerById = new Map(
            assignedServers.map((entry) => [Number.parseInt(entry.id, 10), entry])
        );
        const primaryServerByAllocationId = new Map(
            primaryServersByAllocation
                .map((entry) => {
                    const allocationId = Number.parseInt(entry && entry.allocationId, 10);
                    if (!Number.isInteger(allocationId) || allocationId <= 0) return null;
                    return [allocationId, entry];
                })
                .filter(Boolean)
        );
        allocations.forEach((allocation) => {
            const allocationId = Number.parseInt(allocation && allocation.id, 10);
            const serverId = Number.parseInt(allocation && allocation.serverId, 10);
            const assignedServerByPrimary = Number.isInteger(allocationId)
                ? (primaryServerByAllocationId.get(allocationId) || null)
                : null;
            const assignedServerByLink = Number.isInteger(serverId)
                ? (assignedServerById.get(serverId) || null)
                : null;
            const assignedServer = assignedServerByPrimary || assignedServerByLink || null;
            allocation.setDataValue('assignedServer', assignedServer);
        });
        const statusData = (global.connectorStatus && global.connectorStatus[req.params.id]) || { status: 'offline', lastSeen: null, usage: null };
        const allocatedUsage = await getConnectorAllocatedUsage(req.params.id);

        res.render('admin/manage-connector', {
            user: req.session.user,
            connector,
            currentTab: 'allocations',
            allocations,
            statusData,
            allocatedUsage,
            path: '/admin/connectors',
            settings: res.locals.settings
        });
    } catch (err) {
        console.error("Error fetching allocations:", err);
        res.redirect('/admin/connectors?error=Error fetching allocations.');
    }
});

// Admin Connector Configuration (GET)
app.get('/admin/connectors/:id/configuration', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connector = await Connector.findByPk(req.params.id, { include: [{ model: Location, as: 'location' }] });
        if (!connector) {
            return res.redirect('/admin/connectors?error=Connector not found.');
        }
        const statusData = (global.connectorStatus && global.connectorStatus[req.params.id]) || { status: 'offline', lastSeen: null, usage: null };
        const allocatedUsage = await getConnectorAllocatedUsage(req.params.id);

        const panelUrl = resolvePanelBaseUrl(req);
        const panelOrigin = extractOriginFromUrl(panelUrl);
        const allowedOrigins = await getConnectorAllowedOrigins(connector.id, panelOrigin);
        const settingsMap = res.locals.settings || {};
        const apiHost = String(settingsMap.connectorApiHost || '0.0.0.0').trim() || '0.0.0.0';
        const apiSslEnabled = normalizeBooleanInput(settingsMap.connectorApiSslEnabled, false);
        const apiSslCertPath = String(settingsMap.connectorApiSslCertPath || '').trim();
        const apiSslKeyPath = String(settingsMap.connectorApiSslKeyPath || '').trim();
        const apiTrustedProxies = parseLinesInput(settingsMap.connectorApiTrustedProxies);
        const throttleEnabled = normalizeBooleanInput(settingsMap.connectorConsoleThrottleEnabled, true);
        const throttleLines = normalizeNumberInput(settingsMap.connectorConsoleThrottleLines, 2000, 10, 100000);
        const throttleInterval = normalizeNumberInput(settingsMap.connectorConsoleThrottleIntervalMs, 100, 10, 10000);
        const diskTtlSeconds = normalizeNumberInput(settingsMap.connectorDiskCheckTtlSeconds, 10, 0, 86400);
        const transferDownloadLimit = normalizeNumberInput(settingsMap.connectorTransferDownloadLimit, 0, 0, 100000);
        const sftpReadOnly = normalizeBooleanInput(settingsMap.connectorSftpReadOnly, false);
        const rootlessEnabled = normalizeBooleanInput(settingsMap.connectorRootlessEnabled, false);
        const rootlessUid = normalizeNumberInput(settingsMap.connectorRootlessContainerUid, 0, 0, 65535);
        const rootlessGid = normalizeNumberInput(settingsMap.connectorRootlessContainerGid, 0, 0, 65535);
        const configJson = {
            panel: {
                url: panelUrl,
                ssl: connector.ssl,
                allowedUrls: allowedOrigins
            },
            api: {
                host: apiHost,
                port: connector.port,
                allowedOrigins,
                trustedProxies: apiTrustedProxies,
                ssl: {
                    enabled: apiSslEnabled,
                    cert: apiSslCertPath,
                    key: apiSslKeyPath
                }
            },
            connector: {
                id: connector.id,
                token: connector.token,
                name: connector.name
            },
            sftp: {
                port: connector.sftpPort,
                directory: connector.fileDirectory,
                readOnly: sftpReadOnly
            },
            docker: {
                rootless: {
                    enabled: rootlessEnabled,
                    container_uid: rootlessUid,
                    container_gid: rootlessGid
                }
            },
            system: {
                diskCheckTtlSeconds: diskTtlSeconds
            },
            transfers: {
                downloadLimit: transferDownloadLimit
            },
            throttles: {
                enabled: throttleEnabled,
                lines: throttleLines,
                lineResetInterval: throttleInterval
            }
        };
        const webServerTemplateType = resolveWebServerTemplateType(req.query.webServerTemplate);
        let webServerTemplateContent = '';
        try {
            webServerTemplateContent = renderWebServerTemplate(webServerTemplateType, panelUrl);
        } catch (templateError) {
            console.error('Failed to render web server template for configuration page:', templateError);
        }

        res.render('admin/manage-connector', {
            user: req.session.user,
            connector,
            currentTab: 'configuration',
            configJson: JSON.stringify(configJson, null, 4),
            webServerTemplateType,
            webServerTemplateContent,
            allowedOrigins,
            allocations: [],
            statusData,
            allocatedUsage,
            path: '/admin/connectors',
            settings: res.locals.settings
        });
    } catch (err) {
        console.error("Error fetching connector configuration:", err);
        res.redirect('/admin/connectors?error=Error fetching connector.');
    }
});

// Admin Connector Webserver Template (GET - preview/download)
app.get('/admin/connectors/:id/webserver-template', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connector = await Connector.findByPk(req.params.id);
        if (!connector) {
            return res.status(404).json({ success: false, error: 'Connector not found.' });
        }

        const type = resolveWebServerTemplateType(req.query.type);
        const panelUrl = resolvePanelBaseUrl(req);
        const content = renderWebServerTemplate(type, panelUrl);
        const filename = `connector-${connector.id}-${type}.conf`;

        if (String(req.query.download || '') === '1') {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(content);
        }

        return res.json({
            success: true,
            type,
            filename,
            content
        });
    } catch (error) {
        console.error('Error serving web server template:', error);
        return res.status(500).json({ success: false, error: 'Failed to load web server template.' });
    }
});

// Admin Connector Allocations (POST - Create)
app.post('/admin/connectors/:id/allocations', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { ip, port, portEnd, alias } = req.body;
        const normalizedAlias = normalizeAllocationAlias(alias);
        const notes = normalizeAllocationNotes(req.body.notes);

        // Check if it's a port range
        if (portEnd && parseInt(portEnd) > parseInt(port)) {
            const startPort = parseInt(port);
            const endPort = parseInt(portEnd);
            const allocations = [];

            for (let p = startPort; p <= endPort; p++) {
                allocations.push({
                    ip,
                    port: p,
                    alias: normalizedAlias,
                    notes,
                    connectorId: req.params.id
                });
            }

            await Allocation.bulkCreate(allocations);
            res.redirect(`/admin/connectors/${req.params.id}/allocations?success=Created ${allocations.length} allocations successfully!`);
        } else {
            // Single allocation
            await Allocation.create({
                ip,
                port: parseInt(port),
                alias: normalizedAlias,
                notes,
                connectorId: req.params.id
            });
            res.redirect(`/admin/connectors/${req.params.id}/allocations?success=Allocation created successfully!`);
        }
    } catch (error) {
        console.error("Error creating allocation:", error);
        res.redirect(`/admin/connectors/${req.params.id}/allocations?error=Failed to create allocation.`);
    }
});

// Admin Connector Allocations (POST - Delete)
app.post('/admin/connectors/:id/allocations/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        let ids = req.body['ids[]'] || req.body.ids;
        if (!ids) {
            return res.redirect(`/admin/connectors/${req.params.id}/allocations?error=No allocations selected.`);
        }
        const idsArray = Array.isArray(ids) ? ids : [ids];
        await Allocation.destroy({ where: { id: idsArray } });
        res.redirect(`/admin/connectors/${req.params.id}/allocations?success=Allocations deleted successfully!`);
    } catch (error) {
        console.error("Error deleting allocations:", error);
        res.redirect(`/admin/connectors/${req.params.id}/allocations?error=Failed to delete allocations.`);
    }
});

// Admin Connector Allocations (POST - Update Alias)
app.post('/admin/connectors/:id/allocations/:allocId/alias', requireAuth, requireAdmin, async (req, res) => {
    try {
        const alias = normalizeAllocationAlias(req.body.alias);
        await Allocation.update(
            { alias },
            { where: { id: req.params.allocId, connectorId: req.params.id } }
        );
        res.json({ success: true, alias });
    } catch (error) {
        console.error("Error updating alias:", error);
        res.status(500).json({ success: false, error: 'Failed to update alias' });
    }
});

app.post('/admin/connectors/:id/allocations/alias/bulk', requireAuth, requireAdmin, async (req, res) => {
    try {
        const ids = parseAllocationIds(req.body['ids[]'] || req.body.ids);
        if (ids.length === 0) {
            return res.status(400).json({ success: false, error: 'No allocations selected.' });
        }

        const modeRaw = String(req.body.mode || 'set').trim().toLowerCase();
        const mode = modeRaw === 'clear' ? 'clear' : 'set';

        const allocations = await Allocation.findAll({
            where: { connectorId: req.params.id, id: ids },
            attributes: ['id', 'ip', 'port', 'alias']
        });
        if (!allocations.length) {
            return res.status(404).json({ success: false, error: 'No matching allocations found.' });
        }

        if (mode === 'clear') {
            await Allocation.update(
                { alias: null },
                { where: { connectorId: req.params.id, id: allocations.map((entry) => entry.id) } }
            );
            return res.json({
                success: true,
                mode,
                updated: allocations.map((entry) => ({ id: entry.id, alias: null }))
            });
        }

        const template = normalizeAllocationAlias(req.body.alias);
        if (!template) {
            return res.status(400).json({ success: false, error: 'Alias template is required.' });
        }

        const updates = allocations.map((entry) => ({
            id: entry.id,
            alias: renderAllocationAliasTemplate(template, entry)
        }));

        await Promise.all(updates.map((entry) => Allocation.update(
            { alias: entry.alias },
            { where: { connectorId: req.params.id, id: entry.id } }
        )));

        return res.json({
            success: true,
            mode,
            updated: updates
        });
    } catch (error) {
        console.error('Error bulk-updating allocation aliases:', error);
        return res.status(500).json({ success: false, error: 'Failed to bulk update aliases.' });
    }
});

app.post('/admin/connectors/:id/allocations/:allocId/notes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const notes = normalizeAllocationNotes(req.body.notes);
        await Allocation.update(
            { notes },
            { where: { id: req.params.allocId, connectorId: req.params.id } }
        );
        res.json({ success: true, notes });
    } catch (error) {
        console.error('Error updating allocation notes:', error);
        res.status(500).json({ success: false, error: 'Failed to update notes' });
    }
});

app.get('/admin/allocations/drift', requireAuth, requireAdmin, async (req, res) => {
    try {
        const allocations = await Allocation.findAll({
            include: [
                { model: Connector, as: 'connector', attributes: ['id', 'name'] },
                { model: Server, as: 'server', attributes: ['id', 'name', 'containerId'] }
            ],
            order: [['ip', 'ASC'], ['port', 'ASC']]
        });
        const servers = await Server.findAll({
            include: [{ model: Allocation, as: 'allocation', attributes: ['id', 'ip', 'port', 'serverId'] }],
            order: [['id', 'ASC']]
        });

        const serverById = new Map(servers.map((srv) => [Number(srv.id), srv]));
        const allocationById = new Map(allocations.map((alloc) => [Number(alloc.id), alloc]));

        const missingServerAllocations = allocations.filter((alloc) => alloc.serverId && !serverById.has(Number(alloc.serverId)));
        const missingAllocationServers = servers.filter((srv) => srv.allocationId && !allocationById.has(Number(srv.allocationId)));
        const mismatchedAllocations = servers.filter((srv) => {
            if (!srv.allocationId || !allocationById.has(Number(srv.allocationId))) return false;
            const alloc = allocationById.get(Number(srv.allocationId));
            return Number(alloc.serverId || 0) !== Number(srv.id);
        });

        const duplicates = [];
        const duplicateMap = new Map();
        allocations.forEach((alloc) => {
            const key = `${alloc.ip}:${alloc.port}`;
            if (!duplicateMap.has(key)) duplicateMap.set(key, []);
            duplicateMap.get(key).push(alloc);
        });
        duplicateMap.forEach((list, key) => {
            if (list.length > 1) {
                duplicates.push({ key, allocations: list });
            }
        });

        return res.render('admin/allocations-drift', {
            user: req.session.user,
            path: '/admin/allocations/drift',
            missingServerAllocations,
            missingAllocationServers,
            mismatchedAllocations,
            duplicates,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading allocation drift page:', error);
        return res.redirect('/admin/overview?error=' + encodeURIComponent('Failed to load allocation drift.'));
    }
});

app.post('/admin/allocations/drift/unassign', requireAuth, requireAdmin, async (req, res) => {
    try {
        const allocationIds = parseAllocationIds(req.body.allocationIds);
        if (!allocationIds.length) {
            return res.redirect('/admin/allocations/drift?error=' + encodeURIComponent('Select allocations to unassign.'));
        }

        await Allocation.update({ serverId: null }, { where: { id: allocationIds } });
        return res.redirect('/admin/allocations/drift?success=' + encodeURIComponent(`Unassigned ${allocationIds.length} allocation(s).`));
    } catch (error) {
        console.error('Error unassigning allocations:', error);
        return res.redirect('/admin/allocations/drift?error=' + encodeURIComponent('Failed to unassign allocations.'));
    }
});

app.post('/admin/allocations/drift/clear', requireAuth, requireAdmin, async (req, res) => {
    try {
        const serverIds = parseServerIds(req.body.serverIds);
        if (!serverIds.length) {
            return res.redirect('/admin/allocations/drift?error=' + encodeURIComponent('Select servers to clear allocation.'));
        }

        await Server.update({ allocationId: null }, { where: { id: serverIds } });
        return res.redirect('/admin/allocations/drift?success=' + encodeURIComponent(`Cleared allocation for ${serverIds.length} server(s).`));
    } catch (error) {
        console.error('Error clearing server allocations:', error);
        return res.redirect('/admin/allocations/drift?error=' + encodeURIComponent('Failed to clear server allocations.'));
    }
});

app.post('/admin/allocations/drift/reassign', requireAuth, requireAdmin, async (req, res) => {
    try {
        const serverIds = parseServerIds(req.body.serverIds);
        if (!serverIds.length) {
            return res.redirect('/admin/allocations/drift?error=' + encodeURIComponent('Select servers to reassign.'));
        }

        const servers = await Server.findAll({
            where: { id: serverIds },
            attributes: ['id', 'allocationId']
        });
        const updates = [];
        servers.forEach((srv) => {
            if (!srv.allocationId) return;
            updates.push(Allocation.update({ serverId: srv.id }, { where: { id: srv.allocationId } }));
        });
        await Promise.all(updates);

        return res.redirect('/admin/allocations/drift?success=' + encodeURIComponent(`Reassigned allocations for ${updates.length} server(s).`));
    } catch (error) {
        console.error('Error reassigning allocations:', error);
        return res.redirect('/admin/allocations/drift?error=' + encodeURIComponent('Failed to reassign allocations.'));
    }
});

// Admin Connector Config (GET - Download config file)
app.get('/admin/connectors/:id/config', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connector = await Connector.findByPk(req.params.id);
        if (!connector) {
            return res.status(404).json({ error: 'Connector not found' });
        }

        const panelUrl = resolvePanelBaseUrl(req);
        const panelOrigin = extractOriginFromUrl(panelUrl);
        const allowedOrigins = await getConnectorAllowedOrigins(connector.id, panelOrigin);
        const config = {
            panel: {
                url: panelUrl,
                ssl: connector.ssl,
                allowedUrls: allowedOrigins
            },
            api: {
                allowedOrigins
            },
            connector: {
                id: connector.id,
                token: connector.token,
                name: connector.name
            },
            sftp: {
                port: connector.sftpPort,
                directory: connector.fileDirectory
            }
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="connector-${connector.id}-config.json"`);
        res.json(config);
    } catch (error) {
        console.error("Error generating config:", error);
        res.status(500).json({ error: 'Failed to generate config' });
    }
});

// Admin Connector Token (POST - Regenerate token)
app.post('/admin/connectors/:id/regenerate-token', requireAuth, requireAdmin, async (req, res) => {
    try {
        const connector = await Connector.findByPk(req.params.id);
        if (!connector) {
            return res.redirect('/admin/connectors?error=Connector not found.');
        }

        const newToken = nodeCrypto.randomBytes(32).toString('hex');
        await connector.update({ token: newToken });

        const liveSocket = connectorConnections.get(connector.id);
        if (liveSocket && liveSocket.readyState === WebSocket.OPEN) {
            try {
                liveSocket.send(JSON.stringify({
                    type: 'auth_fail',
                    error: 'Connector token was regenerated. Update connector config and restart connector.'
                }));
            } catch (sendErr) {
                console.warn(`Failed sending token-regenerated auth_fail to connector ${connector.id}:`, sendErr.message);
            }

            try {
                liveSocket.close(4003, 'Connector token regenerated');
            } catch (closeErr) {
                console.warn(`Failed closing connector ${connector.id} after token regeneration:`, closeErr.message);
            }
        }

        res.redirect(`/admin/connectors/${req.params.id}/configuration?success=Token regenerated successfully!`);
    } catch (error) {
        console.error("Error regenerating token:", error);
        res.redirect(`/admin/connectors/${req.params.id}/configuration?error=Failed to regenerate token.`);
    }
});

// API Connector Heartbeat
app.post('/api/connector/heartbeat', async (req, res) => {
    try {
        const { id, token, status, usage } = req.body;

        if (!id || !token) {
            return res.status(400).json({ error: 'Missing ID or Token' });
        }

        const connector = await Connector.findByPk(id);
        if (!connector || connector.token !== token) {
            return res.status(401).json({ error: 'Invalid Connector or Token' });
        }

        // Cache usage data (in a real app, you might save this to DB or Redis)
        // For now, we'll store it in a global object or just log it
        // To make it persistent in the session/view, let's add fields to the Connector model if we want history
        // But for "Live" status, we just need the last heartbeat time.

        // We'll update the 'lastSeen' if we had such a field, or just assume it's live if this matches.
        // Let's at least update the memory/disk fields if they've changed significantly, 
        // though usually those fields in Connector model represent limits.

        // Dynamic status caching
        if (!global.connectorStatus) global.connectorStatus = {};
        global.connectorStatus[id] = {
            status,
            usage,
            lastSeen: new Date()
        };

        res.json({ success: true });
    } catch (error) {
        console.error("Heartbeat error:", error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/overview', requireAuth, requireAdmin, async (req, res) => {
    try {
        const stats = {
            users: await User.count(),
            servers: await Server.count(),
            locations: await Location.count(),
            databases: await DatabaseHost.count(),
            nodes: await Connector.count()
        };

        const redisInfo = typeof getRedisRuntimeInfo === 'function'
            ? getRedisRuntimeInfo()
            : { enabled: false, ready: false };
        const connectorStatus = global.connectorStatus || {};
        const hasOnlineConnector = Object.values(connectorStatus).some((entry) => {
            if (!entry) return false;
            if (typeof entry.status === 'string' && entry.status.toLowerCase() === 'online') return true;
            return Boolean(entry.lastSeen);
        });
        const redisPrompt = stats.nodes > 0 && hasOnlineConnector && !(redisInfo && redisInfo.ready);

        const currentVersion = require('../../package.json').version;
        let versionStatus = {
            message: `Panel up to date v${currentVersion}`,
            type: 'success'
        };

        try {
            const versionResponse = await axios.get('https://cpanel-rocky.netlify.app/version.json', { timeout: 5000 });
            const remoteVersion = versionResponse.data.version;

            if (currentVersion !== remoteVersion) {
                versionStatus = {
                    message: `Your panel is not up-to-date, you are running v${currentVersion}, and the latest version is v${remoteVersion}`,
                    type: 'warning'
                };
            }
        } catch (error) {
            console.error("Error fetching remote version:", error.message);
            versionStatus = {
                message: "Sorry seems like Rocky crashed the website while he was playing with the backend code, please try again later",
                type: 'error'
            };
        }

        res.render('admin/overview', {
            user: req.session.user,
            stats,
            versionStatus,
            redisPrompt,
            redisInfo,
            success: null,
            error: null,
            path: '/admin/overview'
        });
    } catch (error) {
        console.error("Error fetching overview stats:", error);
        res.render('admin/overview', {
            user: req.session.user,
            stats: { users: 0, servers: 0, locations: 0, databases: 0, nodes: 0 },
            versionStatus: { message: 'Database statistics unavailable', type: 'error' },
            redisPrompt: false,
            redisInfo: { enabled: false, ready: false },
            success: null,
            error: 'Failed to fetch dashboard statistics.',
            path: '/admin/overview'
        });
    }
});
}

module.exports = { registerAdminConnectorsOverviewRoutes };
