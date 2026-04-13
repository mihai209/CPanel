const { Op } = require('sequelize');
const { sendToUserUI, getUserUiConnectionCount } = require('../websocket-runtime');
const {
    getNotificationSettings,
    resolveSender,
    createResendClient
} = require('./resend-client');

function normalizeBool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function sanitizeSeverity(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (['success', 'warning', 'danger', 'info'].includes(normalized)) return normalized;
    return 'info';
}

function sanitizeCategory(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return normalized ? normalized.slice(0, 40) : 'general';
}

function sanitizeText(value, maxLength, fallback = '') {
    const text = String(value || '').trim();
    if (!text) return fallback;
    return text.slice(0, maxLength);
}

function sanitizeLinkUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    if (raw.startsWith('/')) return raw.slice(0, 512);
    try {
        const parsed = new URL(raw);
        const protocol = String(parsed.protocol || '').toLowerCase();
        if (protocol !== 'http:' && protocol !== 'https:') return null;
        return parsed.toString().slice(0, 512);
    } catch {
        return null;
    }
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function buildNotificationPayload(row) {
    const data = row && typeof row.toJSON === 'function' ? row.toJSON() : row;
    return {
        id: data.id,
        title: data.title,
        message: data.message,
        severity: data.severity || 'info',
        category: data.category || 'general',
        linkUrl: data.linkUrl || null,
        isRead: Boolean(data.isRead),
        readAt: data.readAt || null,
        createdAt: data.createdAt || null,
        sourceType: data.sourceType || 'admin_manual'
    };
}

function buildEmailHtml(notification, brandName) {
    const title = escapeHtml(notification.title);
    const message = escapeHtml(notification.message).replace(/\n/g, '<br>');
    const severity = escapeHtml(String(notification.severity || 'info').toUpperCase());
    const link = notification.linkUrl
        ? `<p style="margin:24px 0 0;"><a href="${escapeHtml(notification.linkUrl)}" style="display:inline-block;padding:12px 18px;border-radius:12px;background:#2563eb;color:#fff;text-decoration:none;font-weight:700;">Open notification</a></p>`
        : '';
    return [
        '<div style="font-family:Segoe UI,Arial,sans-serif;background:#0f172a;padding:32px;color:#e5eefb;">',
        '<div style="max-width:640px;margin:0 auto;background:#111827;border:1px solid rgba(148,163,184,0.18);border-radius:20px;padding:28px;">',
        `<div style="font-size:12px;letter-spacing:0.12em;text-transform:uppercase;color:#93c5fd;margin-bottom:12px;">${escapeHtml(brandName)} Notification</div>`,
        `<h1 style="margin:0 0 12px;font-size:26px;line-height:1.2;color:#f8fafc;">${title}</h1>`,
        `<div style="display:inline-block;padding:6px 10px;border-radius:999px;background:#1e293b;color:#bfdbfe;font-size:12px;font-weight:700;">${severity}</div>`,
        `<p style="margin:20px 0 0;font-size:15px;line-height:1.7;color:#cbd5e1;">${message}</p>`,
        link,
        '<p style="margin:28px 0 0;font-size:12px;line-height:1.6;color:#94a3b8;">This message was sent from the panel notification center.</p>',
        '</div>',
        '</div>'
    ].join('');
}

async function createNotificationLogEntry(NotificationDeliveryLog, payload) {
    return NotificationDeliveryLog.create({
        channel: sanitizeText(payload.channel, 32, 'unknown'),
        status: sanitizeText(payload.status, 16, 'failed'),
        target: payload.target ? sanitizeText(payload.target, 512) : null,
        templateKey: payload.templateKey ? sanitizeText(payload.templateKey, 64) : null,
        eventKey: payload.eventKey ? sanitizeText(payload.eventKey, 64) : null,
        requestPayload: payload.requestPayload || null,
        responsePayload: payload.responsePayload || null,
        errorText: payload.errorText ? sanitizeText(payload.errorText, 5000) : null,
        attemptedByUserId: payload.attemptedByUserId || null,
        retriedFromId: payload.retriedFromId || null,
        metadata: payload.metadata || null
    });
}

async function resolveRecipients(User, mode, userIds) {
    if (mode === 'all') {
        return User.findAll({
            attributes: ['id', 'username', 'email'],
            order: [['username', 'ASC']]
        });
    }
    const normalizedIds = Array.from(new Set((Array.isArray(userIds) ? userIds : [userIds])
        .map((entry) => Number.parseInt(entry, 10))
        .filter((entry) => Number.isInteger(entry) && entry > 0)));
    if (normalizedIds.length === 0) return [];
    return User.findAll({
        where: { id: { [Op.in]: normalizedIds } },
        attributes: ['id', 'username', 'email'],
        order: [['username', 'ASC']]
    });
}

async function createUserNotifications(deps) {
    const {
        User,
        UserNotification,
        NotificationDeliveryLog,
        payload
    } = deps;
    const targetMode = String(payload.targetMode || '').trim().toLowerCase();
    const recipients = await resolveRecipients(User, targetMode, payload.userIds);
    if (recipients.length === 0) {
        throw new Error('No valid recipients were selected.');
    }

    const title = sanitizeText(payload.title, 160);
    const message = sanitizeText(payload.message, 8000);
    if (!title || !message) {
        throw new Error('Title and message are required.');
    }

    const browserEligible = Boolean(payload.sendBrowser);
    const emailEligible = Boolean(payload.sendEmail);
    const rows = await UserNotification.bulkCreate(recipients.map((user) => ({
        userId: user.id,
        title,
        message,
        severity: sanitizeSeverity(payload.severity),
        category: sanitizeCategory(payload.category),
        linkUrl: sanitizeLinkUrl(payload.linkUrl),
        sourceType: 'admin_manual',
        createdByUserId: payload.createdByUserId || null,
        isRead: false,
        browserEligible,
        emailEligible
    })), { returning: true });

    await Promise.all(rows.map((row) => createNotificationLogEntry(NotificationDeliveryLog, {
        channel: 'panel',
        status: 'sent',
        target: `user:${row.userId}`,
        templateKey: 'admin_manual',
        eventKey: 'admin_user_notification',
        attemptedByUserId: payload.createdByUserId || null,
        requestPayload: {
            notificationId: row.id,
            targetMode,
            browserEligible,
            emailEligible
        },
        metadata: {
            sourceType: 'admin_manual'
        }
    })));

    const notificationIds = rows
        .map((row) => Number.parseInt(row.id, 10))
        .filter((entry) => Number.isInteger(entry) && entry > 0);
    const createdRows = await UserNotification.findAll({
        where: { id: { [Op.in]: notificationIds } },
        include: [{ model: User, as: 'user', attributes: ['id', 'username', 'email'] }],
        order: [['createdAt', 'DESC']]
    });

    return {
        notifications: createdRows,
        recipients
    };
}

async function deliverBrowserNotifications(deps) {
    const {
        UserNotification,
        UserBrowserSubscription,
        NotificationDeliveryLog,
        notifications,
        attemptedByUserId,
        settings
    } = deps;
    const deliveryEnabled = Boolean(settings && settings.delivery && settings.delivery.browserEnabled);
    const summary = { attempted: notifications.length, sent: 0, failed: 0, skipped: 0, error: '' };

    for (const notification of notifications) {
        const payload = buildNotificationPayload(notification);
        const activeSubscriptionCount = await UserBrowserSubscription.count({
            where: {
                userId: notification.userId,
                revokedAt: null
            }
        });
        const activeSocketCount = getUserUiConnectionCount(notification.userId);
        if (!deliveryEnabled) {
            summary.skipped += 1;
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'browser',
                status: 'skipped',
                target: `user:${notification.userId}`,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: 'Browser delivery is disabled in settings.'
            });
            continue;
        }
        if (activeSubscriptionCount <= 0 || activeSocketCount <= 0) {
            summary.skipped += 1;
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'browser',
                status: 'skipped',
                target: `user:${notification.userId}`,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: activeSubscriptionCount <= 0
                    ? 'User has not granted browser notifications.'
                    : 'User has no active panel session.'
            });
            continue;
        }

        try {
            const delivered = sendToUserUI(notification.userId, {
                type: 'notification:new',
                notification: payload,
                browserDelivery: true
            });
            sendToUserUI(notification.userId, {
                type: 'notification:unread_count',
                unreadCount: await countUnreadNotifications(UserNotification, notification.userId)
            });
            if (delivered > 0) {
                summary.sent += 1;
                await UserBrowserSubscription.update(
                    { lastSeenAt: new Date() },
                    { where: { userId: notification.userId, revokedAt: null } }
                ).catch(() => {});
                await createNotificationLogEntry(NotificationDeliveryLog, {
                    channel: 'browser',
                    status: 'sent',
                    target: `user:${notification.userId}`,
                    templateKey: 'admin_manual',
                    eventKey: 'admin_user_notification',
                    attemptedByUserId,
                    requestPayload: { notificationId: notification.id },
                    responsePayload: { sockets: delivered }
                });
            } else {
                summary.skipped += 1;
                await createNotificationLogEntry(NotificationDeliveryLog, {
                    channel: 'browser',
                    status: 'skipped',
                    target: `user:${notification.userId}`,
                    templateKey: 'admin_manual',
                    eventKey: 'admin_user_notification',
                    attemptedByUserId,
                    requestPayload: { notificationId: notification.id },
                    errorText: 'No active UI socket available.'
                });
            }
        } catch (error) {
            summary.failed += 1;
            summary.error = summary.error || String(error.message || error);
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'browser',
                status: 'failed',
                target: `user:${notification.userId}`,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: String(error.message || error)
            });
        }
    }

    return summary;
}

async function deliverEmailNotifications(deps) {
    const {
        NotificationDeliveryLog,
        notifications,
        attemptedByUserId,
        settings,
        brandName
    } = deps;
    const summary = { attempted: notifications.length, sent: 0, failed: 0, skipped: 0, error: '' };
    if (!settings || !settings.delivery || !settings.delivery.resendEnabled) {
        for (const notification of notifications) {
            summary.skipped += 1;
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'email',
                status: 'skipped',
                target: notification.user && notification.user.email ? notification.user.email : `user:${notification.userId}`,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: 'Resend delivery is disabled in settings.'
            });
        }
        return summary;
    }

    let resendClient = null;
    let sender = null;
    try {
        resendClient = createResendClient(settings);
        sender = resolveSender(settings);
    } catch (error) {
        summary.error = String(error.message || error);
        for (const notification of notifications) {
            summary.failed += 1;
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'email',
                status: 'failed',
                target: notification.user && notification.user.email ? notification.user.email : `user:${notification.userId}`,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: summary.error
            });
        }
        return summary;
    }

    for (const notification of notifications) {
        const email = sanitizeText(notification.user && notification.user.email ? notification.user.email : '', 255);
        if (!email) {
            summary.skipped += 1;
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'email',
                status: 'skipped',
                target: `user:${notification.userId}`,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: 'User does not have an email address.'
            });
            continue;
        }

        try {
            const response = await resendClient.emails.send({
                from: sender.from,
                to: [email],
                replyTo: sender.replyTo,
                subject: notification.title,
                html: buildEmailHtml(notification, brandName)
            });
            if (response && response.error) {
                throw new Error(response.error.message || 'Resend returned an unknown error.');
            }
            summary.sent += 1;
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'email',
                status: 'sent',
                target: email,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                responsePayload: response && response.data ? response.data : response || null
            });
        } catch (error) {
            summary.failed += 1;
            summary.error = summary.error || String(error.message || error);
            await createNotificationLogEntry(NotificationDeliveryLog, {
                channel: 'email',
                status: 'failed',
                target: email,
                templateKey: 'admin_manual',
                eventKey: 'admin_user_notification',
                attemptedByUserId,
                requestPayload: { notificationId: notification.id },
                errorText: String(error.message || error)
            });
        }
    }

    return summary;
}

async function countUnreadNotifications(UserNotification, userId) {
    return UserNotification.count({
        where: {
            userId,
            isRead: false
        }
    });
}

async function markNotificationRead(UserNotification, notificationId, userId) {
    const notification = await UserNotification.findOne({
        where: {
            id: notificationId,
            userId
        }
    });
    if (!notification) return null;
    if (!notification.isRead) {
        notification.isRead = true;
        notification.readAt = new Date();
        await notification.save();
    }
    return notification;
}

async function markAllNotificationsRead(UserNotification, userId) {
    return UserNotification.update({
        isRead: true,
        readAt: new Date()
    }, {
        where: {
            userId,
            isRead: false
        }
    });
}

async function listNotifications(UserNotification, userId, limit = 20) {
    const safeLimit = Math.max(1, Math.min(100, Number.parseInt(limit, 10) || 20));
    const rows = await UserNotification.findAll({
        where: { userId },
        order: [['createdAt', 'DESC']],
        limit: safeLimit
    });
    return rows.map(buildNotificationPayload);
}

async function saveNotificationSettings(Settings, payload) {
    const deliveryValue = {
        browserEnabled: normalizeBool(payload.browserEnabled, true),
        resendEnabled: normalizeBool(payload.resendEnabled, false),
        senderName: sanitizeText(payload.senderName, 120, ''),
        replyTo: sanitizeText(payload.replyTo, 255, '')
    };
    const resendValue = {
        apiKey: sanitizeText(payload.resendApiKey, 255, ''),
        fromEmail: sanitizeText(payload.resendFromEmail, 255, ''),
        fromName: sanitizeText(payload.resendFromName, 120, '')
    };
    const current = await getNotificationSettings(Settings);
    if (!resendValue.apiKey && current && current.resend && !process.env.RESEND_API_KEY) {
        resendValue.apiKey = current.resend.apiKey;
    }
    if (!resendValue.fromEmail && current && current.resend && !process.env.RESEND_FROM_EMAIL) {
        resendValue.fromEmail = current.resend.fromEmail;
    }
    if (!resendValue.fromName && current && current.resend && !process.env.RESEND_FROM_NAME) {
        resendValue.fromName = current.resend.fromName;
    }
    await Promise.all([
        Settings.upsert({ key: 'notificationDeliveryConfig', value: JSON.stringify(deliveryValue) }),
        Settings.upsert({ key: 'resendConfig', value: JSON.stringify(resendValue) })
    ]);
    return getNotificationSettings(Settings);
}

module.exports = {
    getNotificationSettings,
    createUserNotifications,
    deliverBrowserNotifications,
    deliverEmailNotifications,
    countUnreadNotifications,
    markNotificationRead,
    markAllNotificationsRead,
    listNotifications,
    saveNotificationSettings,
    sanitizeLinkUrl,
    buildNotificationPayload
};
