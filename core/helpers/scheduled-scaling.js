const crypto = require('crypto');

const SERVER_SCHEDULED_SCALING_KEY_PREFIX = 'server_scheduled_scaling_';

function toSafeInt(value, fallback = 0, min = 0, max = 1000000000) {
    const parsed = Number.parseInt(String(value === undefined || value === null ? '' : value).trim(), 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
}

function parseBoolean(value, fallback = false) {
    if (value === undefined || value === null) return fallback;
    if (Array.isArray(value)) {
        for (const entry of value) {
            if (parseBoolean(entry, false)) return true;
        }
        return false;
    }
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) return fallback;
    return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function createRuleId() {
    try {
        return crypto.randomBytes(6).toString('hex');
    } catch {
        return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }
}

function getServerScheduledScalingSettingKey(serverId) {
    return `${SERVER_SCHEDULED_SCALING_KEY_PREFIX}${Number.parseInt(serverId, 10) || 0}`;
}

function normalizeDaysList(daysRaw) {
    const input = Array.isArray(daysRaw)
        ? daysRaw
        : String(daysRaw || '').split(',').map((entry) => entry.trim());
    const set = new Set();
    input.forEach((value) => {
        const day = toSafeInt(value, -1, 0, 6);
        if (day >= 0 && day <= 6) set.add(day);
    });
    if (set.size === 0) {
        return [0, 1, 2, 3, 4, 5, 6];
    }
    return Array.from(set).sort((a, b) => a - b);
}

function normalizeScheduledScalingRule(rawRule) {
    const source = rawRule && typeof rawRule === 'object' ? rawRule : {};
    return {
        id: String(source.id || '').trim() || createRuleId(),
        name: String(source.name || '').trim().slice(0, 120) || 'Scaling Rule',
        enabled: parseBoolean(source.enabled, true),
        timezone: String(source.timezone || 'UTC').trim().slice(0, 80) || 'UTC',
        daysOfWeek: normalizeDaysList(source.daysOfWeek),
        hour: toSafeInt(source.hour, 0, 0, 23),
        minute: toSafeInt(source.minute, 0, 0, 59),
        memory: toSafeInt(source.memory, 0, 0, 1000000000),
        cpu: toSafeInt(source.cpu, 0, 0, 1000000000),
        disk: toSafeInt(source.disk, 0, 0, 1000000000),
        swapLimit: toSafeInt(source.swapLimit, 0, 0, 1000000000),
        ioWeight: toSafeInt(source.ioWeight, 500, 10, 1000),
        pidsLimit: toSafeInt(source.pidsLimit, 512, 0, 4194304),
        oomKillDisable: parseBoolean(source.oomKillDisable, false),
        oomScoreAdj: toSafeInt(source.oomScoreAdj, 0, -1000, 1000),
        lastAppliedSlot: String(source.lastAppliedSlot || '').trim().slice(0, 80)
    };
}

function normalizeServerScheduledScalingConfig(rawConfig) {
    let source = rawConfig;
    if (typeof source === 'string') {
        try {
            source = JSON.parse(source);
        } catch {
            source = {};
        }
    }
    if (!source || typeof source !== 'object') source = {};

    const rules = Array.isArray(source.rules)
        ? source.rules.map((entry) => normalizeScheduledScalingRule(entry)).slice(0, 200)
        : [];

    return {
        enabled: parseBoolean(source.enabled, false),
        timezone: String(source.timezone || 'UTC').trim().slice(0, 80) || 'UTC',
        rules,
        updatedAtMs: toSafeInt(source.updatedAtMs, Date.now(), 0, 9999999999999)
    };
}

function getRuleSlotKey(nowMs, rule) {
    const source = rule && typeof rule === 'object' ? rule : {};
    const timezone = String(source.timezone || 'UTC').trim() || 'UTC';
    const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: timezone,
        hour12: false,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        weekday: 'short'
    });

    const parts = formatter.formatToParts(new Date(nowMs));
    const map = {};
    parts.forEach((part) => {
        map[part.type] = part.value;
    });
    const weekdayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    const dayOfWeek = weekdayMap[map.weekday] ?? -1;

    const year = String(map.year || '0000');
    const month = String(map.month || '00');
    const day = String(map.day || '00');
    const hour = toSafeInt(map.hour, -1, 0, 23);
    const minute = toSafeInt(map.minute, -1, 0, 59);

    return {
        slot: `${year}-${month}-${day}-${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`,
        dayOfWeek,
        hour,
        minute
    };
}

function isRuleDueNow(rule, nowMs = Date.now()) {
    const normalized = normalizeScheduledScalingRule(rule);
    if (!normalized.enabled) return { due: false, slot: '' };

    const slotData = getRuleSlotKey(nowMs, normalized);
    if (slotData.dayOfWeek < 0) return { due: false, slot: '' };
    if (!normalized.daysOfWeek.includes(slotData.dayOfWeek)) return { due: false, slot: slotData.slot };
    if (slotData.hour !== normalized.hour || slotData.minute !== normalized.minute) {
        return { due: false, slot: slotData.slot };
    }
    if (normalized.lastAppliedSlot && normalized.lastAppliedSlot === slotData.slot) {
        return { due: false, slot: slotData.slot };
    }

    return { due: true, slot: slotData.slot };
}

module.exports = {
    SERVER_SCHEDULED_SCALING_KEY_PREFIX,
    toSafeInt,
    parseBoolean,
    getServerScheduledScalingSettingKey,
    normalizeDaysList,
    normalizeScheduledScalingRule,
    normalizeServerScheduledScalingConfig,
    getRuleSlotKey,
    isRuleDueNow
};
