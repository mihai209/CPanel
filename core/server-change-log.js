function normalizeComparableValue(value) {
    if (value === undefined) return null;
    if (value === null) return null;
    if (Array.isArray(value)) {
        return value.map((entry) => normalizeComparableValue(entry));
    }
    if (value && typeof value === 'object') {
        const normalized = {};
        Object.keys(value).sort().forEach((key) => {
            normalized[key] = normalizeComparableValue(value[key]);
        });
        return normalized;
    }
    return value;
}

function stableStringify(value) {
    return JSON.stringify(normalizeComparableValue(value));
}

function areValuesDifferent(beforeValue, afterValue) {
    return stableStringify(beforeValue) !== stableStringify(afterValue);
}

async function recordServerChange(ServerChangeLog, payload = {}) {
    if (!ServerChangeLog) return null;
    const beforeValue = normalizeComparableValue(payload.beforeValue);
    const afterValue = normalizeComparableValue(payload.afterValue);
    if (!areValuesDifferent(beforeValue, afterValue)) return null;

    return ServerChangeLog.create({
        serverId: payload.serverId,
        actorUserId: payload.actorUserId || null,
        category: String(payload.category || 'server').slice(0, 40),
        changeKey: String(payload.changeKey || 'state').slice(0, 80),
        summary: String(payload.summary || 'Server state changed').slice(0, 255),
        beforeValue,
        afterValue,
        metadata: payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : null
    });
}

module.exports = {
    normalizeComparableValue,
    areValuesDifferent,
    recordServerChange
};
