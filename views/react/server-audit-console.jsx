import React, { useState, useEffect, useRef } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerAuditConsolePage({ pageData = {} }) {
    const { server = {}, logs: initialLogs = [] } = pageData;
    const [logs, setLogs] = useState(initialLogs);
    const [loading, setLoading] = useState(false);
    const scrollRef = useRef(null);

    const getActionClass = (action) => {
        if (action.startsWith('server:console')) return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
        if (action.startsWith('server:power') || action.startsWith('server:ack')) return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
        return 'bg-neutral-800 text-neutral-400 border-neutral-700';
    };

    const fetchNewLogs = async () => {
        const lastId = logs.length > 0 ? Math.max(...logs.map(l => l.id)) : 0;
        try {
            const res = await fetch(`/server/${server.containerId}/audit-console/feed?afterId=${lastId}`);
            const data = await res.json();
            if (data.success && data.logs?.length > 0) {
                setLogs(prev => [...prev, ...data.logs]);
            }
        } catch (err) {
            console.error('Audit poll error:', err);
        }
    };

    useEffect(() => {
        const int = setInterval(fetchNewLogs, 4500);
        return () => clearInterval(int);
    }, [logs]);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    return (
        <ReactAppShell pageData={pageData} subtitle="Audit Console">
            <div className="max-w-7xl mx-auto h-[calc(100vh-180px)] flex flex-col">
                <div className="bg-neutral-900 border border-neutral-800 rounded-2xl flex flex-col h-full overflow-hidden shadow-2xl">
                    {/* Header */}
                    <div className="px-6 py-4 bg-neutral-900/50 border-b border-neutral-800 flex items-center justify-between">
                        <div>
                            <h2 className="text-sm font-black text-neutral-500 uppercase tracking-widest flex items-center gap-2">
                                <i className="bi bi-shield-shaded text-primary-400"></i>
                                Immutable Security Tape
                            </h2>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="px-3 py-1 rounded-full bg-neutral-950 border border-neutral-800 text-[10px] font-black text-neutral-500 uppercase tracking-tighter">
                                {logs.length} Total Events
                            </span>
                            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.5)]"></div>
                        </div>
                    </div>

                    {/* Content */}
                    <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-2 bg-[#0c0c0f] font-mono no-scrollbar">
                        {logs.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center text-center opacity-30 select-none">
                                <i className="bi bi-broadcast text-6xl mb-4"></i>
                                <p className="text-sm uppercase tracking-[0.2em] font-black">Waiting for audit heartbeat...</p>
                            </div>
                        ) : (
                            logs.slice(-500).map((log, i) => {
                                const meta = log.metadata || {};
                                return (
                                    <div key={log.id} className="group flex gap-4 p-3 rounded-xl hover:bg-neutral-900/40 transition-all border border-transparent hover:border-neutral-800/50">
                                        <div className="w-16 shrink-0 text-[10px] font-black text-neutral-700 tabular-nums pt-1">
                                            #{log.id}
                                        </div>
                                        <div className="flex-1 space-y-2">
                                            <div className="flex flex-wrap items-center gap-3">
                                                <span className={`px-2 py-0.5 rounded border text-[9px] font-black uppercase tracking-widest ${getActionClass(log.action)}`}>
                                                    {log.action.replace('server:', '')}
                                                </span>
                                                <span className="text-[10px] font-bold text-neutral-600">
                                                    {new Date(log.createdAt).toLocaleTimeString()}
                                                </span>
                                                <span className="text-[10px] font-black text-primary-500 uppercase tracking-tighter">
                                                    @{log.actor?.username || 'system'}
                                                </span>
                                            </div>
                                            
                                            <div className="text-xs leading-relaxed break-all">
                                                {meta.command ? (
                                                    <div className="flex gap-2 items-start">
                                                        <span className="text-neutral-600 shrink-0">$</span>
                                                        <code className="text-blue-300 bg-blue-500/5 px-2 py-0.5 rounded-md border border-blue-500/10 select-all">{meta.command}</code>
                                                    </div>
                                                ) : meta.powerAction ? (
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-neutral-600">power_intent:</span>
                                                        <span className="text-yellow-500 font-black uppercase text-[10px]">{meta.powerAction}</span>
                                                    </div>
                                                ) : meta.message ? (
                                                    <span className="text-neutral-400 italic">"{meta.message}"</span>
                                                ) : (
                                                    <span className="text-neutral-700 italic">No further details captured</span>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })
                        )}
                    </div>

                    {/* Footer */}
                    <div className="px-6 py-3 bg-neutral-950 border-t border-neutral-800 flex items-center justify-between">
                        <div className="text-[10px] font-black text-neutral-600 uppercase tracking-widest flex items-center gap-2">
                            <i className="bi bi-info-circle text-blue-500"></i>
                            Audit entries are permanent and cannot be deleted by any user level.
                        </div>
                        <div className="text-[9px] font-mono text-neutral-700">
                            SESSION_BUF: {logs.length} / 500
                        </div>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}
