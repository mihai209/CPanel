const crypto = require('crypto');

const INCIDENT_CENTER_SETTING_KEY = 'incidentCenterRecords';
const INCIDENT_CENTER_MAX_RECORDS = 500;

function parseJsonSafe(raw, fallback) {
    if (raw === undefined || raw === null || raw === '') return fallback;
    try {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return parsed === undefined || parsed === null ? fallback : parsed;
    } catch {
        return fallback;
    }
}

function normalizeIncidentSeverity(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'critical' || normalized === 'warning') return normalized;
    return 'normal';
}

function normalizeIncidentStatus(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return normalized === 'resolved' ? 'resolved' : 'open';
}

function parseTimestamp(value, fallback) {
    const fallbackMs = Number.isFinite(Number(fallback)) ? Number(fallback) : Date.now();
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) return Math.floor(value);
    const parsed = new Date(String(value || '')).getTime();
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
    return fallbackMs;
}

function buildIncidentId() {
    try {
        return crypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }
}

function normalizeIncidentRecord(entry) {
    const nowMs = Date.now();
    const createdAtMs = parseTimestamp(entry && entry.createdAtMs, nowMs);
    const updatedAtMs = parseTimestamp(entry && entry.updatedAtMs, createdAtMs);
    const status = normalizeIncidentStatus(entry && entry.status);
    return {
        id: String(entry && entry.id || '').trim() || buildIncidentId(),
        title: String(entry && entry.title || '').trim().slice(0, 140) || 'Incident',
        message: String(entry && entry.message || '').trim().slice(0, 3000),
        severity: normalizeIncidentSeverity(entry && entry.severity),
        status,
        source: String(entry && entry.source || 'system').trim().slice(0, 60) || 'system',
        serverId: Number.parseInt(entry && entry.serverId, 10) || null,
        connectorId: Number.parseInt(entry && entry.connectorId, 10) || null,
        action: String(entry && entry.action || '').trim().slice(0, 120),
        metadata: entry && typeof entry.metadata === 'object' ? entry.metadata : {},
        createdAtMs,
        updatedAtMs,
        resolvedAtMs: status === 'resolved' ? parseTimestamp(entry && entry.resolvedAtMs, updatedAtMs) : 0
    };
}

function normalizeIncidentRecords(raw) {
    const parsed = parseJsonSafe(raw, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
        .map((entry) => normalizeIncidentRecord(entry))
        .sort((a, b) => b.createdAtMs - a.createdAtMs)
        .slice(0, INCIDENT_CENTER_MAX_RECORDS);
}

async function getIncidentCenterRecords(Settings) {
    if (!Settings) return [];
    const row = await Settings.findByPk(INCIDENT_CENTER_SETTING_KEY);
    return normalizeIncidentRecords(row && row.value ? row.value : '[]');
}

async function setIncidentCenterRecords(Settings, records) {
    if (!Settings) return [];
    const normalized = normalizeIncidentRecords(records);
    await Settings.upsert({
        key: INCIDENT_CENTER_SETTING_KEY,
        value: JSON.stringify(normalized)
    });
    return normalized;
}

async function appendIncidentCenterRecord(Settings, payload) {
    const existing = await getIncidentCenterRecords(Settings);
    const nextRecord = normalizeIncidentRecord({
        ...payload,
        id: payload && payload.id ? payload.id : buildIncidentId(),
        status: payload && payload.status ? payload.status : 'open',
        createdAtMs: payload && payload.createdAtMs ? payload.createdAtMs : Date.now(),
        updatedAtMs: Date.now()
    });

    existing.unshift(nextRecord);
    const saved = await setIncidentCenterRecords(Settings, existing);
    return saved[0] || nextRecord;
}

async function updateIncidentCenterRecordStatus(Settings, id, status) {
    const normalizedId = String(id || '').trim();
    if (!normalizedId) return null;

    const list = await getIncidentCenterRecords(Settings);
    const target = list.find((entry) => entry.id === normalizedId);
    if (!target) return null;

    const nowMs = Date.now();
    const nextStatus = normalizeIncidentStatus(status);
    target.status = nextStatus;
    target.updatedAtMs = nowMs;
    target.resolvedAtMs = nextStatus === 'resolved' ? nowMs : 0;

    await setIncidentCenterRecords(Settings, list);
    return target;
}

module.exports = {
    INCIDENT_CENTER_SETTING_KEY,
    INCIDENT_CENTER_MAX_RECORDS,
    normalizeIncidentSeverity,
    normalizeIncidentStatus,
    normalizeIncidentRecord,
    normalizeIncidentRecords,
    getIncidentCenterRecords,
    setIncidentCenterRecords,
    appendIncidentCenterRecord,
    updateIncidentCenterRecordStatus
};
