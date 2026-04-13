const NOTIFICATION_DELIVERY_SETTING_KEY = 'notificationDeliveryConfig';
const RESEND_CONFIG_SETTING_KEY = 'resendConfig';

function parseJson(value, fallback) {
    try {
        const parsed = typeof value === 'string' ? JSON.parse(value) : value;
        return parsed && typeof parsed === 'object' ? parsed : fallback;
    } catch {
        return fallback;
    }
}

function normalizeBool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function normalizeNotificationDeliveryConfig(raw) {
    const parsed = parseJson(raw, {});
    return {
        browserEnabled: normalizeBool(parsed.browserEnabled, true),
        resendEnabled: normalizeBool(parsed.resendEnabled, false),
        senderName: String(parsed.senderName || '').trim(),
        replyTo: String(parsed.replyTo || '').trim()
    };
}

function normalizeResendConfig(raw) {
    const parsed = parseJson(raw, {});
    return {
        apiKey: String(process.env.RESEND_API_KEY || parsed.apiKey || '').trim(),
        fromEmail: String(process.env.RESEND_FROM_EMAIL || parsed.fromEmail || '').trim(),
        fromName: String(process.env.RESEND_FROM_NAME || parsed.fromName || '').trim()
    };
}

async function getNotificationSettings(Settings) {
    const [deliveryRow, resendRow] = await Promise.all([
        Settings.findByPk(NOTIFICATION_DELIVERY_SETTING_KEY),
        Settings.findByPk(RESEND_CONFIG_SETTING_KEY)
    ]);
    const delivery = normalizeNotificationDeliveryConfig(deliveryRow && deliveryRow.value ? deliveryRow.value : {});
    const resend = normalizeResendConfig(resendRow && resendRow.value ? resendRow.value : {});
    return {
        delivery,
        resend,
        resendConfigured: Boolean(resend.apiKey && resend.fromEmail)
    };
}

function maskSecret(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (raw.length <= 8) return `${raw.slice(0, 2)}***`;
    return `${raw.slice(0, 3)}***${raw.slice(-3)}`;
}

function resolveSender(settings) {
    const resend = settings && settings.resend ? settings.resend : normalizeResendConfig({});
    const delivery = settings && settings.delivery ? settings.delivery : normalizeNotificationDeliveryConfig({});
    const senderName = String(delivery.senderName || resend.fromName || 'CPanel').trim() || 'CPanel';
    const fromEmail = String(resend.fromEmail || '').trim();
    return {
        from: fromEmail ? `${senderName} <${fromEmail}>` : '',
        replyTo: String(delivery.replyTo || '').trim() || undefined
    };
}

function createResendClient(settings) {
    const resend = settings && settings.resend ? settings.resend : normalizeResendConfig({});
    if (!resend.apiKey || !resend.fromEmail) {
        throw new Error('Resend is not configured. Set RESEND_API_KEY and RESEND_FROM_EMAIL, or save them in Admin -> Notifications.');
    }
    let ResendCtor = null;
    try {
        ({ Resend: ResendCtor } = require('resend'));
    } catch (error) {
        throw new Error(`Resend package is not installed. ${error.message || error}`);
    }
    return new ResendCtor(resend.apiKey);
}

module.exports = {
    NOTIFICATION_DELIVERY_SETTING_KEY,
    RESEND_CONFIG_SETTING_KEY,
    normalizeNotificationDeliveryConfig,
    normalizeResendConfig,
    getNotificationSettings,
    maskSecret,
    resolveSender,
    createResendClient
};
