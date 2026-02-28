function toInt(value, fallback = 0) {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function toNum(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function isConnectorOnline(connectorStatusMap, connectorId, nowMs = Date.now(), staleMs = 30000) {
    const status = connectorStatusMap && connectorStatusMap[connectorId] ? connectorStatusMap[connectorId] : null;
    if (!status || String(status.status || '').toLowerCase() !== 'online') return false;
    const lastSeenMs = new Date(status.lastSeen || 0).getTime();
    return Number.isFinite(lastSeenMs) && lastSeenMs > 0 && (nowMs - lastSeenMs) < staleMs;
}

function resolveConnectorFromAllocation(allocation) {
    if (!allocation) return null;
    if (allocation.connector && typeof allocation.connector === 'object') return allocation.connector;
    if (allocation.Connector && typeof allocation.Connector === 'object') return allocation.Connector;
    return null;
}

function resolveConnectorLocationId(connector) {
    return toInt(connector && connector.locationId, 0);
}

function buildCapacitySnapshot(connector, usage, requestedMemoryMb, requestedDiskMb) {
    const totalMemoryGb = Math.max(0, toNum(connector && connector.totalMemory, 0));
    const totalDiskGb = Math.max(0, toNum(connector && connector.totalDisk, 0));
    const memoryOverAllocationPct = Math.max(0, toNum(connector && connector.memoryOverAllocation, 0));
    const diskOverAllocationPct = Math.max(0, toNum(connector && connector.diskOverAllocation, 0));

    const maxMemoryMb = (totalMemoryGb * 1024) * (1 + (memoryOverAllocationPct / 100));
    const maxDiskMb = (totalDiskGb * 1024) * (1 + (diskOverAllocationPct / 100));

    const usedMemoryMb = Math.max(0, toNum(usage && usage.memoryMb, 0));
    const usedDiskMb = Math.max(0, toNum(usage && usage.diskMb, 0));

    const projectedMemoryMb = usedMemoryMb + Math.max(0, toNum(requestedMemoryMb, 0));
    const projectedDiskMb = usedDiskMb + Math.max(0, toNum(requestedDiskMb, 0));

    const fitsMemory = projectedMemoryMb <= maxMemoryMb;
    const fitsDisk = projectedDiskMb <= maxDiskMb;
    const memoryHeadroomMb = Math.max(0, maxMemoryMb - projectedMemoryMb);
    const diskHeadroomMb = Math.max(0, maxDiskMb - projectedDiskMb);
    const memoryHeadroomPct = maxMemoryMb > 0 ? (memoryHeadroomMb / maxMemoryMb) * 100 : 0;
    const diskHeadroomPct = maxDiskMb > 0 ? (diskHeadroomMb / maxDiskMb) * 100 : 0;

    return {
        maxMemoryMb,
        maxDiskMb,
        usedMemoryMb,
        usedDiskMb,
        projectedMemoryMb,
        projectedDiskMb,
        fitsMemory,
        fitsDisk,
        memoryHeadroomMb,
        diskHeadroomMb,
        memoryHeadroomPct,
        diskHeadroomPct
    };
}

function scoreAllocationCandidate({
    allocation,
    connector,
    connectorStatusMap,
    usageByConnector,
    requestedMemoryMb,
    requestedDiskMb,
    preferredConnectorId,
    preferredLocationId,
    nowMs
}) {
    const connectorId = toInt(connector && connector.id, toInt(allocation && allocation.connectorId, 0));
    if (connectorId <= 0) {
        return { ok: false, reason: 'missing_connector' };
    }

    const isOnline = isConnectorOnline(connectorStatusMap, connectorId, nowMs);
    if (!isOnline) {
        return { ok: false, reason: 'connector_offline' };
    }

    const connectorLocationId = resolveConnectorLocationId(connector);
    if (preferredConnectorId > 0 && connectorId !== preferredConnectorId) {
        return { ok: false, reason: 'connector_filter_mismatch' };
    }
    if (preferredLocationId > 0 && connectorLocationId !== preferredLocationId) {
        return { ok: false, reason: 'location_filter_mismatch' };
    }

    const usage = usageByConnector && usageByConnector[connectorId] ? usageByConnector[connectorId] : {};
    const cap = buildCapacitySnapshot(connector, usage, requestedMemoryMb, requestedDiskMb);
    if (!cap.fitsMemory) {
        return { ok: false, reason: 'insufficient_memory', cap };
    }
    if (!cap.fitsDisk) {
        return { ok: false, reason: 'insufficient_disk', cap };
    }

    const status = connectorStatusMap && connectorStatusMap[connectorId] ? connectorStatusMap[connectorId] : {};
    const cpuUsage = clamp(toNum(status && status.usage && status.usage.cpu, 0), 0, 100);

    let score = 0;
    score += cap.memoryHeadroomPct * 0.45;
    score += cap.diskHeadroomPct * 0.35;
    score += (100 - cpuUsage) * 0.20;

    if (preferredConnectorId > 0 && connectorId === preferredConnectorId) {
        score += 25;
    }
    if (preferredLocationId > 0 && connectorLocationId === preferredLocationId) {
        score += 10;
    }
    if (allocation && allocation.alias) {
        score += 1.5;
    }

    return {
        ok: true,
        score: Number(score.toFixed(4)),
        connectorId,
        connectorLocationId,
        cpuUsage,
        cap
    };
}

function pickSmartAllocation({
    allocations = [],
    connectorStatusMap = {},
    usageByConnector = {},
    requestedMemoryMb = 1024,
    requestedDiskMb = 10240,
    preferredConnectorId = 0,
    preferredLocationId = 0,
    nowMs = Date.now()
} = {}) {
    const list = Array.isArray(allocations) ? allocations : [];
    const reqMemory = Math.max(64, toInt(requestedMemoryMb, 1024));
    const reqDisk = Math.max(512, toInt(requestedDiskMb, 10240));
    const connectorFilter = Math.max(0, toInt(preferredConnectorId, 0));
    const locationFilter = Math.max(0, toInt(preferredLocationId, 0));

    const eligible = [];
    const rejected = [];

    for (const allocation of list) {
        if (!allocation) continue;
        if (allocation.serverId) {
            rejected.push({ allocationId: toInt(allocation.id, 0), reason: 'allocation_occupied' });
            continue;
        }

        const connector = resolveConnectorFromAllocation(allocation);
        const evaluated = scoreAllocationCandidate({
            allocation,
            connector,
            connectorStatusMap,
            usageByConnector,
            requestedMemoryMb: reqMemory,
            requestedDiskMb: reqDisk,
            preferredConnectorId: connectorFilter,
            preferredLocationId: locationFilter,
            nowMs
        });

        if (!evaluated.ok) {
            rejected.push({
                allocationId: toInt(allocation.id, 0),
                connectorId: evaluated.connectorId || toInt(allocation.connectorId, 0),
                reason: evaluated.reason
            });
            continue;
        }

        eligible.push({
            allocation,
            connector,
            score: evaluated.score,
            cpuUsage: evaluated.cpuUsage,
            cap: evaluated.cap
        });
    }

    eligible.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        const aId = toInt(a && a.allocation && a.allocation.id, 0);
        const bId = toInt(b && b.allocation && b.allocation.id, 0);
        return aId - bId;
    });

    if (eligible.length === 0) {
        return {
            ok: false,
            reason: 'No eligible allocation found for the requested resources and filters.',
            best: null,
            meta: {
                considered: list.length,
                eligible: 0,
                rejected
            }
        };
    }

    return {
        ok: true,
        reason: null,
        best: eligible[0],
        candidates: eligible,
        meta: {
            considered: list.length,
            eligible: eligible.length,
            rejected
        }
    };
}

module.exports = {
    isConnectorOnline,
    pickSmartAllocation
};
