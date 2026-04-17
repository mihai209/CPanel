import React, { useState, useEffect, useRef } from 'react';

export default function NotificationBell() {
    const [unreadCount, setUnreadCount] = useState(0);
    const [notifications, setNotifications] = useState([]);
    const [isOpen, setIsOpen] = useState(false);
    const [loading, setLoading] = useState(false);
    const dropdownRef = useRef(null);

    const fetchNotifications = async () => {
        setLoading(true);
        try {
            const res = await fetch('/api/account/notifications?limit=8', {
                headers: { 'Accept': 'application/json' }
            });
            const payload = await res.json();
            if (res.ok) {
                setNotifications(payload.notifications || []);
                setUnreadCount(payload.unreadCount || 0);
            }
        } catch (err) {
            console.error('Failed to fetch notifications:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchNotifications();

        // WebSocket listener
        let ws;
        const connectWs = () => {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws/ui`);
            
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'notification:unread_count') {
                        setUnreadCount(data.unreadCount || 0);
                    }
                    if (data.type === 'notification:new' || data.type === 'notification:read') {
                        fetchNotifications();
                    }
                } catch (e) {}
            };

            ws.onclose = () => setTimeout(connectWs, 5000);
        };

        connectWs();

        // Click outside listener
        const handleClickOutside = (event) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            if (ws) ws.close();
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);

    const markRead = async (id) => {
        try {
            const res = await fetch(`/api/account/notifications/${id}/read`, { method: 'POST' });
            if (res.ok) {
                const payload = await res.json();
                setUnreadCount(payload.unreadCount || 0);
                fetchNotifications();
            }
        } catch (err) {}
    };

    const markAllRead = async () => {
        try {
            const res = await fetch('/api/account/notifications/read-all', { method: 'POST' });
            if (res.ok) {
                setUnreadCount(0);
                fetchNotifications();
            }
        } catch (err) {}
    };

    return (
        <div className="relative" ref={dropdownRef}>
            <button 
                onClick={() => setIsOpen(!isOpen)}
                className={`relative p-2 rounded-full transition-all duration-300 ${isOpen ? 'bg-primary-500/10 text-primary-400' : 'text-neutral-400 hover:text-neutral-100 hover:bg-neutral-800'}`}
            >
                <i className="bi bi-bell text-lg"></i>
                {unreadCount > 0 && (
                    <span className="absolute top-1.5 right-1.5 flex h-4 w-4">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-4 w-4 bg-red-500 text-[9px] font-black text-white items-center justify-center border-2 border-neutral-800">
                            {unreadCount > 9 ? '9+' : unreadCount}
                        </span>
                    </span>
                )}
            </button>

            {isOpen && (
                <div className="absolute right-0 mt-3 w-80 lg:w-96 bg-neutral-900/95 backdrop-blur-xl border border-neutral-800 rounded-2xl shadow-2xl overflow-hidden z-[100] animate-in slide-in-from-top-2 duration-200">
                    <div className="px-5 py-4 border-b border-neutral-800 flex items-center justify-between bg-neutral-900/50">
                        <span className="text-xs font-black uppercase tracking-widest text-neutral-100">Notifications</span>
                        <button 
                            onClick={markAllRead}
                            className="text-[10px] font-bold text-primary-400 hover:text-primary-300 uppercase tracking-widest transition-colors"
                        >
                            Mark all read
                        </button>
                    </div>

                    <div className="max-h-[400px] overflow-y-auto no-scrollbar">
                        {loading && notifications.length === 0 ? (
                            <div className="p-8 text-center">
                                <div className="w-6 h-6 border-2 border-neutral-700 border-t-primary-500 rounded-full animate-spin mx-auto mb-2"></div>
                                <span className="text-[10px] text-neutral-500 uppercase font-black">Syncing...</span>
                            </div>
                        ) : notifications.length === 0 ? (
                            <div className="p-10 text-center flex flex-col items-center gap-3">
                                <div className="w-12 h-12 bg-neutral-800/50 rounded-full flex items-center justify-center">
                                    <i className="bi bi-bell-slash text-2xl text-neutral-600"></i>
                                </div>
                                <span className="text-xs font-bold text-neutral-600 uppercase tracking-widest">No notifications</span>
                            </div>
                        ) : (
                            <div className="divide-y divide-neutral-800/50">
                                {notifications.map((n) => (
                                    <div 
                                        key={n.id} 
                                        className={`p-4 transition-colors hover:bg-neutral-800/30 ${!n.isRead ? 'bg-primary-500/5 border-l-2 border-primary-500' : ''}`}
                                    >
                                        <div className="flex justify-between items-start gap-4">
                                            <div className="flex-1 min-w-0">
                                                <h4 className="text-xs font-bold text-neutral-200 mb-1 truncate">{n.title}</h4>
                                                <p className="text-[11px] text-neutral-500 leading-relaxed mb-2 whitespace-pre-wrap">{n.message}</p>
                                                <div className="flex items-center gap-3">
                                                    <span className="text-[9px] font-bold text-neutral-600 uppercase tracking-widest">
                                                        {new Date(n.createdAt).toLocaleDateString()}
                                                    </span>
                                                    {n.linkUrl && (
                                                        <a 
                                                            href={n.linkUrl} 
                                                            className="text-[9px] font-black text-primary-400 hover:text-primary-300 uppercase tracking-widest"
                                                        >
                                                            Open Link
                                                        </a>
                                                    )}
                                                </div>
                                            </div>
                                            {!n.isRead && (
                                                <button 
                                                    onClick={() => markRead(n.id)}
                                                    className="w-2 h-2 rounded-full bg-primary-500 mt-1"
                                                    title="Mark as read"
                                                ></button>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <a 
                        href="/notifications" 
                        className="block w-full py-3 bg-neutral-900/80 border-t border-neutral-800 text-center text-[10px] font-black uppercase tracking-[0.2em] text-neutral-500 hover:text-neutral-100 hover:bg-neutral-800 transition-all"
                    >
                        View All Activity
                    </a>
                </div>
            )}
        </div>
    );
}
