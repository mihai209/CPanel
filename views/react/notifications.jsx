import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import GlobalStatusModal from './components/GlobalStatusModal.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'notifications';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function getSeverityTheme(severity) {
    const s = String(severity || 'info').toLowerCase();
    if (s === 'danger' || s === 'error' || s === 'critical') {
        return { icon: 'bi-exclamation-octagon-fill', color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/20' };
    }
    if (s === 'warning') {
        return { icon: 'bi-exclamation-triangle-fill', color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' };
    }
    if (s === 'success') {
        return { icon: 'bi-check-circle-fill', color: 'text-green-500', bg: 'bg-green-500/10', border: 'border-green-500/20' };
    }
    return { icon: 'bi-info-circle-fill', color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/20' };
}

export function NotificationsPage({ pageData = data }) {
    const [notifications, setNotifications] = React.useState(Array.isArray(pageData.notifications) ? pageData.notifications : []);
    const [unreadCount, setUnreadCount] = React.useState(Number(pageData.unreadCount || 0));
    const [processing, setProcessing] = React.useState(false);

    const markRead = async (id) => {
        try {
            const response = await fetch(`/api/account/notifications/${id}/read`, { method: 'POST' });
            const result = await response.json();
            if (response.ok) {
                setNotifications(prev => prev.map(n => n.id === id ? { ...n, isRead: true } : n));
                setUnreadCount(result.unreadCount);
                
                // Update the Header unread badge if global state allows (currently session-based on reload, 
                // but we can update local state if we had a global context. 
                // For now, it stays synced with this value).
            }
        } catch (error) {
            console.error('Failed to mark notification as read:', error);
        }
    };

    const markAllRead = async () => {
        if (processing) return;
        setProcessing(true);
        try {
            const response = await fetch('/api/account/notifications/read-all', { method: 'POST' });
            const result = await response.json();
            if (response.ok) {
                setNotifications(prev => prev.map(n => ({ ...n, isRead: true })));
                setUnreadCount(0);
            }
        } catch (error) {
            console.error('Failed to mark all as read:', error);
        } finally {
            setProcessing(false);
        }
    };

    return (
        <ReactAppShell pageData={{ ...pageData, user: { ...pageData.user, notificationUnreadCount: unreadCount } }} subtitle="User Notifications">
            <PageContentBlock 
                title="Notifications" 
                description="Stay informed about your servers, security events, and platform updates."
            >
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
                    <div>
                        <div className="flex items-center gap-3">
                            <h2 className="text-2xl font-black text-white uppercase tracking-tight">Activity Feed</h2>
                            {unreadCount > 0 && (
                                <span className="bg-primary-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full uppercase tracking-widest animate-pulse">
                                    {unreadCount} Unread
                                </span>
                            )}
                        </div>
                        <p className="text-xs text-neutral-500 font-bold uppercase tracking-widest mt-1">
                            Viewing your 100 most recent alerts
                        </p>
                    </div>
                    <div className="flex gap-2 w-full sm:w-auto">
                        <button 
                            onClick={markAllRead}
                            disabled={unreadCount === 0 || processing}
                            className={`flex-1 sm:flex-none px-6 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all border ${unreadCount > 0 ? 'bg-neutral-800 border-neutral-700 text-white hover:bg-neutral-700 active:scale-95' : 'bg-neutral-900 border-neutral-800 text-neutral-700 cursor-not-allowed'}`}
                        >
                            {processing ? 'Processing...' : 'Mark All Read'}
                        </button>
                        <a 
                            href="/account"
                            className="px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-xl text-neutral-400 hover:text-white transition-colors flex items-center justify-center"
                            title="Notification Settings"
                        >
                            <i className="bi bi-gear-fill"></i>
                        </a>
                    </div>
                </div>

                <div className="space-y-3">
                    {notifications.length === 0 ? (
                        <div className="py-24 flex flex-col items-center justify-center bg-neutral-800/20 border border-neutral-800/50 border-dashed rounded-[2.5rem]">
                            <div className="w-20 h-20 bg-neutral-800 rounded-3xl flex items-center justify-center mb-6 shadow-2xl">
                                <i className="bi bi-bell-slash text-3xl text-neutral-600"></i>
                            </div>
                            <h3 className="text-lg font-bold text-neutral-400 uppercase tracking-widest">Peace and Quiet</h3>
                            <p className="text-xs text-neutral-600 font-bold uppercase tracking-[0.15em] mt-2 text-center max-w-xs">
                                No new notifications at the moment. We'll alert you if anything requires your attention.
                            </p>
                        </div>
                    ) : (
                        notifications.map((notif, idx) => {
                            const theme = getSeverityTheme(notif.severity);
                            return (
                                <div 
                                    key={notif.id || idx}
                                    className={`group relative overflow-hidden bg-neutral-800/40 border transition-all duration-300 rounded-2xl p-5 sm:p-6 ${notif.isRead ? 'border-neutral-800/50 opacity-60' : `${theme.border} hover:border-neutral-600 shadow-xl`}`}
                                >
                                    {/* Unread Glow Indicator */}
                                    {!notif.isRead && (
                                        <div className={`absolute top-0 left-0 w-1 h-full ${theme.color.replace('text', 'bg')}`}></div>
                                    )}

                                    <div className="flex gap-5 items-start">
                                        <div className={`shrink-0 w-12 h-12 rounded-xl flex items-center justify-center text-xl ${theme.bg} ${theme.color} border ${theme.border} transition-transform group-hover:scale-110`}>
                                            <i className={`bi ${theme.icon}`}></i>
                                        </div>

                                        <div className="flex-1 min-w-0">
                                            <div className="flex flex-wrap items-center gap-3 mb-2">
                                                <h4 className={`text-sm font-black uppercase tracking-widest truncate ${notif.isRead ? 'text-neutral-400' : 'text-white'}`}>
                                                    {notif.title}
                                                </h4>
                                                <span className="text-[10px] font-bold text-neutral-600 uppercase tracking-widest">
                                                    {new Date(notif.createdAt).toLocaleString()}
                                                </span>
                                            </div>

                                            <div className={`text-xs leading-relaxed font-medium mb-4 whitespace-pre-wrap ${notif.isRead ? 'text-neutral-500' : 'text-neutral-300'}`}>
                                                {notif.message}
                                            </div>

                                            <div className="flex flex-wrap items-center gap-4">
                                                {notif.linkUrl && (
                                                    <a 
                                                        href={notif.linkUrl}
                                                        className="px-4 py-1.5 bg-primary-600/10 hover:bg-primary-600/20 text-primary-400 text-[10px] font-black uppercase tracking-widest rounded-lg transition-colors border border-primary-500/20"
                                                    >
                                                        View Details
                                                    </a>
                                                )}
                                                {!notif.isRead && (
                                                    <button 
                                                        onClick={() => markRead(notif.id)}
                                                        className="text-[10px] font-black text-neutral-500 hover:text-white uppercase tracking-[0.2em] transition-colors"
                                                    >
                                                        Mark as Read
                                                    </button>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })
                    )}
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default NotificationsPage;

if (root) {
    root.render(
        <BrowserRouter>
            <NotificationsPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
