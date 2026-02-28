function registerDefaultJobHandlers(jobQueue, deps) {
    const {
        Server,
        Allocation,
        Connector,
        ServerBackupPolicy,
        ServerBackup,
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

    jobQueue.registerHandler('server.backup.create', async (job) => {
        throw new Error('Built-in backup jobs are disabled. Use SFTP backup workflow.');
    });

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
