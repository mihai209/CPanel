const {
    GOOGLE_DRIVE_BACKUP_DEST,
    performGoogleDriveBackup
} = require('../backups/google-drive');

function registerDefaultJobHandlers(jobQueue, deps) {
    const {
        Server,
        Allocation,
        Connector,
        ServerBackupPolicy,
        ServerBackup,
        Settings,
        getPanelFeatureFlagsFromMap,
        dispatchServerLogCleanup,
        pendingMigrationFileImports,
        connectorConnections,
        resolveModrinthVersionForInstall,
        createWsRequestId,
        waitForConnectorDownloadResult,
        parseServerAddonPath,
        upsertServerMinecraftInstallRecord,
        bootInfo
    } = deps;

    let featureFlagsCache = { ts: 0, flags: null };
    const FEATURE_FLAGS_TTL_MS = 10 * 1000;

    async function getJobFeatureFlags() {
        if (!Settings || typeof Settings.findAll !== 'function') {
            return getPanelFeatureFlagsFromMap ? getPanelFeatureFlagsFromMap({}) : { remoteDownloadEnabled: true };
        }
        const now = Date.now();
        if (featureFlagsCache.flags && now - featureFlagsCache.ts < FEATURE_FLAGS_TTL_MS) {
            return featureFlagsCache.flags;
        }
        const rows = await Settings.findAll({
            where: { key: ['featureRemoteDownloadEnabled'] },
            attributes: ['key', 'value']
        });
        const map = {};
        rows.forEach((row) => {
            map[row.key] = row.value;
        });
        const flags = getPanelFeatureFlagsFromMap ? getPanelFeatureFlagsFromMap(map) : { remoteDownloadEnabled: String(map.featureRemoteDownloadEnabled || 'true') === 'true' };
        featureFlagsCache = { ts: now, flags };
        return flags;
    }

    function getConnectorSocket(connectorId) {
        const socket = connectorConnections && connectorConnections.get
            ? connectorConnections.get(connectorId)
            : null;
        if (!socket) return null;
        if (socket.readyState !== 1) return null; // WebSocket.OPEN
        return socket;
    }

    jobQueue.registerHandler('server.log_cleanup', async (job) => {
        const serverId = Number.parseInt(job.payload && job.payload.serverId, 10);
        if (!Number.isInteger(serverId) || serverId <= 0) {
            throw new Error('Invalid serverId for server.log_cleanup job');
        }

        const server = await Server.findByPk(serverId, {
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) {
            throw new Error(`Server ${serverId} not found`);
        }

        const dispatched = await dispatchServerLogCleanup(server, true);
        return { serverId, dispatched };
    });

    async function executeGoogleDriveBackupJob(job) {
        const payload = (job && job.payload) || {};
        const serverId = Number.parseInt(payload.serverId, 10);
        const trigger = String(payload.trigger || 'manual').trim().toLowerCase();
        const isAuto = trigger === 'auto';
        if (!Number.isInteger(serverId) || serverId <= 0) {
            throw new Error('Invalid serverId for backup job.');
        }

        const server = await Server.findByPk(serverId, {
            include: [{
                model: Allocation,
                as: 'allocation',
                include: [{ model: Connector, as: 'connector' }]
            }]
        });
        if (!server) throw new Error(`Server ${serverId} not found.`);
        if (server.isSuspended) throw new Error('Server is suspended.');

        const connector = server.allocation && server.allocation.connector
            ? server.allocation.connector
            : null;
        if (!connector) throw new Error('Server connector details are missing.');

        const policy = await ServerBackupPolicy.findOne({ where: { serverId } });
        if (isAuto) {
            if (!policy || !policy.enabled || String(policy.destinationPath || '') !== GOOGLE_DRIVE_BACKUP_DEST) {
                return {
                    success: false,
                    skipped: true,
                    reason: 'Policy disabled or not configured for Google Drive.'
                };
            }
        }

        try {
            const result = await performGoogleDriveBackup({
                server,
                connector,
                Settings
            });

            await ServerBackup.create({
                serverId,
                status: 'completed',
                filePath: `gdrive://${result.fileId}`,
                sizeBytes: result.sizeBytes || 0,
                checksum: result.checksum || null,
                metadata: {
                    provider: 'google_drive',
                    trigger,
                    folderId: result.folderId || null,
                    fileId: result.fileId || null,
                    fileName: result.fileName || null,
                    sourceDir: result.sourceDir || null,
                    deletedOldCount: Number.isFinite(Number(result.deletedOldCount)) ? Number(result.deletedOldCount) : 0,
                    webViewLink: result.webViewLink || null,
                    webContentLink: result.webContentLink || null
                }
            });

            if (policy) {
                await policy.update({ lastRunAt: new Date() });
            }

            return {
                success: true,
                serverId,
                provider: 'google_drive',
                trigger,
                backup: {
                    fileId: result.fileId || null,
                    fileName: result.fileName || null,
                    sizeBytes: result.sizeBytes || 0,
                    folderId: result.folderId || null,
                    deletedOldCount: Number.isFinite(Number(result.deletedOldCount)) ? Number(result.deletedOldCount) : 0
                }
            };
        } catch (error) {
            await ServerBackup.create({
                serverId,
                status: 'failed',
                filePath: 'gdrive://error',
                sizeBytes: null,
                checksum: null,
                metadata: {
                    provider: 'google_drive',
                    trigger,
                    error: error && error.message ? String(error.message) : String(error)
                }
            }).catch(() => {});

            if (policy && isAuto) {
                await policy.update({ lastRunAt: new Date() }).catch(() => {});
            }
            throw error;
        }
    }

    jobQueue.registerHandler('server.backup.create', executeGoogleDriveBackupJob);
    jobQueue.registerHandler('server.backup.google_drive', executeGoogleDriveBackupJob);

    jobQueue.registerHandler('server.install.dispatch', async (job) => {
        const payload = job.payload || {};
        const serverId = Number.parseInt(payload.serverId, 10);
        const isFinalAttempt = (Number.parseInt(job.attempts, 10) + 1) >= Number.parseInt(job.maxAttempts, 10);
        if (!Number.isInteger(serverId) || serverId <= 0) {
            throw new Error('Invalid serverId for server.install.dispatch job');
        }

        const server = await Server.findByPk(serverId, {
            include: [{ model: Allocation, as: 'allocation' }]
        });
        if (!server) throw new Error(`Server ${serverId} not found`);
        if (!server.allocation || !server.allocation.connectorId) {
            if (isFinalAttempt) {
                await server.update({ status: 'error' }).catch(() => {});
            }
            throw new Error(`Server ${serverId} has no connector allocation`);
        }

        const connectorWs = getConnectorSocket(server.allocation.connectorId);
        if (!connectorWs) {
            if (isFinalAttempt) {
                await server.update({ status: 'error' }).catch(() => {});
            }
            throw new Error(`Connector ${server.allocation.connectorId} is offline`);
        }

        try {
            connectorWs.send(JSON.stringify({
                type: 'install_server',
                serverId,
                reinstall: Boolean(payload.reinstall),
                config: payload.config || {}
            }));
        } catch (sendError) {
            if (isFinalAttempt) {
                await server.update({ status: 'error' }).catch(() => {});
            }
            throw new Error(`Failed to dispatch install to connector: ${sendError.message}`);
        }

        if (payload.pendingFileImport && pendingMigrationFileImports && pendingMigrationFileImports.set) {
            pendingMigrationFileImports.set(serverId, payload.pendingFileImport);
        }

        const updatePayload = { status: 'installing' };
        if (payload.resolvedVariables && typeof payload.resolvedVariables === 'object') {
            updatePayload.variables = payload.resolvedVariables;
        }
        if (payload.clearSuspended === true) {
            updatePayload.isSuspended = false;
        }
        await server.update(updatePayload);

        return {
            serverId,
            connectorId: server.allocation.connectorId,
            dispatched: true
        };
    });

    jobQueue.registerHandler('server.minecraft.install', async (job) => {
        const payload = job.payload || {};
        const serverId = Number.parseInt(payload.serverId, 10);
        if (!Number.isInteger(serverId) || serverId <= 0) {
            throw new Error('Invalid serverId for server.minecraft.install job');
        }

        const flags = await getJobFeatureFlags();
        if (flags && flags.remoteDownloadEnabled === false) {
            throw new Error('Remote downloads are disabled by admin.');
        }

        const server = await Server.findByPk(serverId, {
            include: [{ model: Allocation, as: 'allocation' }]
        });

        if (!server) throw new Error('Server not found.');
        if (server.isSuspended) throw new Error('Server is suspended.');
        if (!server.allocation || !server.allocation.connectorId) {
            throw new Error('Server allocation is missing.');
        }

        const connectorWs = getConnectorSocket(server.allocation.connectorId);
        if (!connectorWs) throw new Error('Connector is offline.');

        const versionData = await resolveModrinthVersionForInstall({
            projectId: String(payload.projectId || '').trim(),
            versionId: String(payload.versionId || '').trim(),
            loader: String(payload.loader || '').trim(),
            gameVersion: String(payload.gameVersion || '').trim(),
            userAgent: String(payload.userAgent || 'CPanel/1.0')
        });

        const targetDirectory = String(payload.targetDirectory || '/plugins');
        const requestId = createWsRequestId();
        connectorWs.send(JSON.stringify({
            type: 'download_file',
            serverId: server.id,
            requestId,
            directory: targetDirectory,
            url: versionData.fileUrl,
            fileName: versionData.fileName
        }));

        const installResult = await waitForConnectorDownloadResult(connectorWs, server.id, requestId, 45000);
        if (!installResult.success) {
            throw new Error(installResult.error || 'Connector failed to install file.');
        }

        const fallbackPath = `${targetDirectory}/${installResult.fileName || versionData.fileName}`;
        const installedPath = parseServerAddonPath(installResult.path || fallbackPath) || {
            directory: targetDirectory,
            fileName: installResult.fileName || versionData.fileName,
            path: targetDirectory === '/'
                ? `/${installResult.fileName || versionData.fileName}`
                : fallbackPath
        };

        await upsertServerMinecraftInstallRecord(server.id, {
            path: installedPath.path,
            directory: installedPath.directory,
            fileName: installedPath.fileName,
            kind: String(payload.kind || 'plugin'),
            loader: String(payload.loader || ''),
            gameVersion: String(payload.gameVersion || ''),
            projectId: versionData.projectId,
            projectTitle: String(payload.projectTitle || '').trim().slice(0, 120),
            versionId: versionData.versionId,
            versionNumber: versionData.versionNumber,
            installedAt: new Date().toISOString()
        });

        return {
            success: true,
            message: 'Addon installed successfully.',
            installed: {
                projectId: versionData.projectId,
                versionId: versionData.versionId,
                versionNumber: versionData.versionNumber,
                fileName: installedPath.fileName,
                path: installedPath.path,
                size: Number.isFinite(installResult.size) ? installResult.size : 0
            }
        };
    });
}

module.exports = {
    registerDefaultJobHandlers
};
