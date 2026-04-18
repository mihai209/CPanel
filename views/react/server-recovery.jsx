import React, { useState } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerRecoveryPage({ pageData = {} }) {
    const { server = {}, debugEvents = [], latestDebug = null, latestMeta = {}, issueHint = '', connectorOnline = false, canPower = false, canConsole = false } = pageData;
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const handleAction = async (action) => {
        setLoading(true);
        setStatus({ type: 'idle', message: '' });
        try {
            const res = await fetch(`/server/${server.containerId}/recovery/action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ action })
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || `Failed to run action: ${action}`);
            
            setStatus({ type: 'success', message: `Action "${action}" triggered successfully.` });
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Recovery Assistant">
            <div className="max-w-7xl mx-auto space-y-6 pb-24">
                {/* ── Status Messages ─────────────────────────────────── */}
                {status.message && (
                    <div className={`p-4 rounded-xl border flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300 ${
                        status.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 
                        status.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 
                        'bg-blue-500/10 border-blue-500/20 text-blue-400'
                    }`}>
                        <i className={`bi ${status.type === 'error' ? 'bi-exclamation-triangle-fill' : status.type === 'success' ? 'bi-check-circle-fill' : 'bi-info-circle-fill'}`}></i>
                        <span className="text-sm font-medium">{status.message}</span>
                    </div>
                )}

                <div className="grid lg:grid-cols-2 gap-6">
                    {/* ── Left Column: Diagnosis ────────────────────────── */}
                    <div className="space-y-6">
                        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 overflow-hidden shadow-sm">
                            <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <i className="bi bi-heart-pulse-fill text-red-400"></i>
                                    <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">Diagnosis</h3>
                                </div>
                                <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest ${connectorOnline ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                                    {connectorOnline ? 'Connector Online' : 'Connector Offline'}
                                </span>
                            </div>
                            <div className="p-6 space-y-4">
                                <div className="p-4 bg-neutral-950 border border-neutral-800 rounded-xl">
                                    <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest block mb-1">Issue Hint</span>
                                    <p className="text-sm text-neutral-200 font-medium m-0">{issueHint}</p>
                                </div>

                                {latestDebug ? (
                                    <div className="p-4 bg-neutral-950/50 border border-neutral-800 rounded-xl space-y-3">
                                        <div className="flex justify-between items-center text-[10px] font-black text-neutral-600 uppercase tracking-widest">
                                            <span>Latest Event</span>
                                            <span>{new Date(latestDebug.createdAt).toLocaleString()}</span>
                                        </div>
                                        <code className="block bg-neutral-900 p-2 rounded border border-neutral-800 text-primary-400 text-xs font-mono">
                                            {latestDebug.action}
                                        </code>
                                        {latestMeta && latestMeta.error && (
                                            <div className="text-xs text-orange-400 bg-orange-500/5 p-3 rounded-lg border border-orange-500/10 leading-relaxed">
                                                <i className="bi bi-exclamation-circle me-2"></i>
                                                {String(latestMeta.error)}
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="text-center py-6">
                                        <i className="bi bi-shield-check text-4xl text-neutral-800 mb-3 block"></i>
                                        <p className="text-sm text-neutral-500 italic m-0">No debug events recorded yet.</p>
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 overflow-hidden shadow-sm">
                            <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center gap-3">
                                <i className="bi bi-lightning-charge-fill text-yellow-400"></i>
                                <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">Recovery Actions</h3>
                            </div>
                            <div className="p-6">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                    {canPower && (
                                        <>
                                            <button onClick={() => handleAction('start')} disabled={loading} className="flex flex-col items-center gap-2 p-4 rounded-xl bg-green-500/10 border border-green-500/20 text-green-400 hover:bg-green-500/20 transition-all font-bold">
                                                <i className="bi bi-play-fill text-xl"></i>
                                                <span className="text-[10px] uppercase tracking-widest">Start</span>
                                            </button>
                                            <button onClick={() => handleAction('restart')} disabled={loading} className="flex flex-col items-center gap-2 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 hover:bg-yellow-500/20 transition-all font-bold">
                                                <i className="bi bi-arrow-clockwise text-xl"></i>
                                                <span className="text-[10px] uppercase tracking-widest">Restart</span>
                                            </button>
                                            <button onClick={() => handleAction('stop')} disabled={loading} className="flex flex-col items-center gap-2 p-4 rounded-xl bg-neutral-800 border border-neutral-700 text-neutral-300 hover:bg-neutral-700 transition-all font-bold">
                                                <i className="bi bi-stop-fill text-xl"></i>
                                                <span className="text-[10px] uppercase tracking-widest">Stop</span>
                                            </button>
                                            <button onClick={() => handleAction('kill')} disabled={loading} className="flex flex-col items-center gap-2 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all font-bold">
                                                <i className="bi bi-lightning-fill text-xl"></i>
                                                <span className="text-[10px] uppercase tracking-widest">Kill</span>
                                            </button>
                                        </>
                                    )}
                                    {canConsole && (
                                        <button onClick={() => handleAction('save-all')} disabled={loading} className="col-span-2 flex flex-col items-center gap-2 p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 hover:bg-blue-500/20 transition-all font-bold">
                                            <i className="bi bi-floppy text-xl"></i>
                                            <span className="text-[10px] uppercase tracking-widest">Run save-all (MC)</span>
                                        </button>
                                    )}
                                </div>

                                <div className="mt-6 flex flex-wrap gap-2">
                                    <a href={`/server/${server.containerId}/debug-logs`} className="flex-1 text-center py-2.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold transition-all border border-neutral-700">Debug Logs</a>
                                    <a href={`/server/${server.containerId}/startup`} className="flex-1 text-center py-2.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold transition-all border border-neutral-700">Startup Config</a>
                                    <a href={`/server/${server.containerId}/files`} className="flex-1 text-center py-2.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold transition-all border border-neutral-700">FileManager</a>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* ── Right Column: Log Table ────────────────────────── */}
                    <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 overflow-hidden shadow-sm flex flex-col">
                        <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <i className="bi bi-list-nested text-primary-400"></i>
                                <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">Recent Debug Events</h3>
                            </div>
                            <span className="text-[10px] font-black text-neutral-700 uppercase tracking-widest">Last 30</span>
                        </div>
                        <div className="flex-1 overflow-auto max-h-[600px]">
                            <table className="w-full text-left border-collapse">
                                <thead className="sticky top-0 bg-neutral-900 border-b border-neutral-800">
                                    <tr>
                                        <th className="px-6 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest">When</th>
                                        <th className="px-6 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest">Action</th>
                                        <th className="px-6 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest">Details</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-neutral-800/50">
                                    {!debugEvents || debugEvents.length === 0 ? (
                                        <tr>
                                            <td colSpan="3" className="px-6 py-8 text-center text-sm text-neutral-500 italic">No debug events recorded yet.</td>
                                        </tr>
                                    ) : (
                                        debugEvents.map((entry, idx) => {
                                            const meta = entry.metadata && typeof entry.metadata === 'object' ? entry.metadata : {};
                                            return (
                                                <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                    <td className="px-6 py-4 whitespace-nowrap text-[11px] font-medium text-neutral-400">
                                                        {new Date(entry.createdAt).toLocaleString()}
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <code className="text-[11px] font-mono text-primary-400">{entry.action}</code>
                                                    </td>
                                                    <td className="px-6 py-4 text-[11px] text-neutral-300">
                                                        {meta.error ? (
                                                            <span className="text-red-400/80">{String(meta.error).slice(0, 160)}</span>
                                                        ) : meta.message ? (
                                                            <span>{String(meta.message).slice(0, 160)}</span>
                                                        ) : meta.exitCode !== undefined ? (
                                                            <span className="px-2 py-0.5 rounded bg-neutral-800 text-[10px] font-bold">Exit: {meta.exitCode}</span>
                                                        ) : (
                                                            <span className="text-neutral-600">-</span>
                                                        )}
                                                    </td>
                                                </tr>
                                            );
                                        })
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}
