import React, { useState } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerDebugLogsPage({ pageData = {} }) {
    const { 
        server = {}, 
        logs = [], 
        canFixPermissions = false 
    } = pageData;

    const [loading, setLoading] = useState(false);
    const [mirrorCheck, setMirrorCheck] = useState({
        visible: false,
        status: 'idle',
        summary: 'Run a check to validate mirror DNS/connectivity and container network state.',
        container: '-',
        network: '-',
        reachable: '-',
        mirrors: []
    });
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const handleFixPermissions = async () => {
        if (!canFixPermissions || !window.confirm('Attempt to fix file permissions for this server?')) return;
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const res = await fetch(`/server/${server.containerId}/fix-permissions`, { method: 'POST' });
            if (res.redirected) { window.location.href = res.url; return; }
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to fix permissions');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const runMirrorCheck = async () => {
        setMirrorCheck(prev => ({ ...prev, visible: true, status: 'running', summary: 'Running dependency mirror diagnostics...' }));
        
        try {
            const response = await fetch(`/server/${server.containerId}/debug-logs/dependency-mirror-check`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}'
            });
            const payload = await response.json();
            
            if (!response.ok || !payload.success) {
                setMirrorCheck(prev => ({
                    ...prev,
                    status: 'failed',
                    summary: payload.error || `Request failed (${response.status})`,
                    mirrors: payload.mirrors || []
                }));
                return;
            }

            const { container = {}, summary = {}, mirrors = [] } = payload;
            setMirrorCheck({
                visible: true,
                status: 'completed',
                summary: summary.likelyRootCause || 'Diagnostics completed.',
                container: container.exists ? (container.running ? `Running (${container.status})` : `Stopped (${container.status})`) : 'Missing',
                network: Array.isArray(container.networks) ? container.networks.join(', ') : 'No network',
                reachable: `${summary.reachableMirrors || 0} / ${summary.totalMirrors || 0}`,
                mirrors
            });
        } catch (err) {
            setMirrorCheck(prev => ({ ...prev, status: 'failed', summary: 'Check failed: ' + err.message }));
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Debug Logs & Recovery">
            <div className="max-w-7xl mx-auto space-y-6">
                {/* ── Action Bar ─────────────────────────────────────── */}
                <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 shadow-sm">
                    <div className="flex-1 min-w-[200px]">
                        <h2 className="text-sm font-black text-neutral-500 uppercase tracking-widest px-1">Maintenance Tools</h2>
                    </div>
                    <div className="flex flex-wrap gap-2">
                        {canFixPermissions && (
                            <button 
                                onClick={handleFixPermissions}
                                disabled={loading}
                                className="px-4 py-2 rounded-xl bg-orange-500/10 text-orange-400 border border-orange-500/20 hover:bg-orange-500/20 transition-all text-xs font-bold flex items-center gap-2"
                            >
                                <i className="bi bi-shield-lock-fill"></i>
                                Fix Permissions
                            </button>
                        )}
                        <button 
                            onClick={runMirrorCheck}
                            disabled={loading || mirrorCheck.status === 'running'}
                            className="px-4 py-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 transition-all text-xs font-bold flex items-center gap-2"
                        >
                            <i className={`bi bi-diagram-3-fill ${mirrorCheck.status === 'running' ? 'animate-pulse' : ''}`}></i>
                            Mirror Diagnostic
                        </button>
                    </div>
                </div>

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

                {/* ── Dependency Mirror Check Card ────────────────────── */}
                {mirrorCheck.visible && (
                    <div className="bg-neutral-900 border border-neutral-700 rounded-2xl p-6 shadow-2xl animate-in zoom-in-95 duration-300">
                        <div className="flex items-center justify-between mb-6">
                            <div className="flex items-center gap-3">
                                <div className={`w-2 h-2 rounded-full ${mirrorCheck.status === 'running' ? 'bg-blue-500 animate-pulse' : mirrorCheck.status === 'failed' ? 'bg-red-500' : 'bg-green-500'}`}></div>
                                <h3 className="font-bold text-white uppercase tracking-wide">Dependency Diagnostics</h3>
                            </div>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-widest ${
                                mirrorCheck.status === 'completed' ? 'bg-green-500/10 text-green-500' : 'bg-neutral-800 text-neutral-500'
                            }`}>
                                {mirrorCheck.status}
                            </span>
                        </div>

                        <div className="grid md:grid-cols-3 gap-4 mb-6">
                            {[
                                { label: 'Container', val: mirrorCheck.container },
                                { label: 'Network', val: mirrorCheck.network },
                                { label: 'Connectivity', val: mirrorCheck.reachable }
                            ].map(item => (
                                <div key={item.label} className="p-3 rounded-xl bg-neutral-950 border border-neutral-800">
                                    <div className="text-[9px] font-black text-neutral-600 uppercase tracking-widest mb-1">{item.label}</div>
                                    <div className="text-xs font-bold text-neutral-300 truncate">{item.val}</div>
                                </div>
                            ))}
                        </div>

                        <div className="overflow-x-auto no-scrollbar">
                            <table className="w-full text-left border-separate border-spacing-y-1">
                                <thead>
                                    <tr className="text-[10px] text-neutral-600 font-black uppercase tracking-widest">
                                        <th className="pb-3 pl-2">Mirror Host</th>
                                        <th className="pb-3 px-2">DNS</th>
                                        <th className="pb-3 px-2">TCP</th>
                                        <th className="pb-3 px-2">Latency</th>
                                        <th className="pb-3 pr-2">Error</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {mirrorCheck.mirrors.length === 0 ? (
                                        <tr><td colSpan="5" className="py-4 text-center text-xs text-neutral-600 italic">No results yet...</td></tr>
                                    ) : (
                                        mirrorCheck.mirrors.map((m, i) => {
                                            const ok = m.reachable;
                                            return (
                                                <tr key={i} className="bg-neutral-950/40 group">
                                                    <td className="py-2.5 pl-2 rounded-l-lg font-mono text-[11px] text-blue-300">{m.host}</td>
                                                    <td className={`py-2.5 px-2 text-[10px] font-black ${m.dnsResolved ? 'text-green-500' : 'text-red-500'}`}>{m.dnsResolved ? 'OK' : 'FAIL'}</td>
                                                    <td className={`py-2.5 px-2 text-[10px] font-black ${ok ? 'text-green-500' : 'text-red-500'}`}>{ok ? 'OK' : 'FAIL'}</td>
                                                    <td className="py-2.5 px-2 text-[10px] font-mono text-neutral-500">{m.latencyMs ? `${m.latencyMs}ms` : '-'}</td>
                                                    <td className="py-2.5 pr-2 rounded-r-lg text-[10px] text-red-400 font-medium truncate max-w-[200px]" title={m.error}>{m.error || '-'}</td>
                                                </tr>
                                            );
                                        })
                                    )}
                                </tbody>
                            </table>
                        </div>
                        <p className="mt-4 text-[11px] font-medium text-neutral-500 bg-neutral-950/50 p-3 rounded-xl border border-neutral-800 italic">
                            {mirrorCheck.summary}
                        </p>
                    </div>
                )}

                {/* ── Log Entries ───────────────────────────────────── */}
                <div className="space-y-4">
                    {logs.length === 0 ? (
                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-20 text-center">
                            <i className="bi bi-stack text-5xl text-neutral-800 mb-6 block"></i>
                            <h3 className="text-lg font-bold text-neutral-300">Clean Slate</h3>
                            <p className="text-sm text-neutral-500 mt-2 max-w-md mx-auto leading-relaxed">
                                No debug entries recorded yet. Debug snapshots are automatically captured when the server crashes, hits OOM, or fails to install.
                            </p>
                        </div>
                    ) : (
                        logs.map((entry) => (
                            <div key={entry.id} className="bg-neutral-900/50 rounded-2xl border border-neutral-800 overflow-hidden shadow-sm group hover:border-neutral-700 transition-all">
                                <div className="p-4 bg-neutral-900/50 border-b border-neutral-800 flex flex-wrap items-center gap-3">
                                    <span className={`px-2.5 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest ${
                                        entry.severity === 'danger' ? 'bg-red-500/10 text-red-500' : 
                                        entry.severity === 'warning' ? 'bg-orange-500/10 text-orange-500' : 
                                        'bg-blue-500/10 text-blue-400'
                                    }`}>
                                        {entry.action.replace('server:debug.', '')}
                                    </span>
                                    <div className="text-[11px] font-bold text-neutral-500 flex items-center gap-2">
                                        <i className="bi bi-clock"></i>
                                        {new Date(entry.createdAt).toLocaleString()}
                                    </div>
                                    <div className="flex-1"></div>
                                    <div className="flex flex-wrap gap-2">
                                        {entry.metadata?.state?.exitCode !== undefined && (
                                            <span className="px-2 py-0.5 rounded bg-neutral-950 border border-neutral-800 text-[10px] font-mono text-neutral-400">Exit: {entry.metadata.state.exitCode}</span>
                                        )}
                                        {entry.metadata?.state?.oomKilled && (
                                            <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-[9px] font-black uppercase">OOM-Killed</span>
                                        )}
                                        {entry.metadata?.powerIntent && (
                                            <span className="px-2 py-0.5 rounded bg-neutral-950 border border-neutral-800 text-[10px] font-bold text-neutral-500 uppercase tracking-tighter">Intent: {entry.metadata.powerIntent}</span>
                                        )}
                                    </div>
                                </div>

                                <div className="p-5 space-y-4">
                                    {entry.metadata?.message && (
                                        <div className="flex gap-3">
                                            <div className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0"></div>
                                            <p className="text-sm font-medium text-neutral-300">{entry.metadata.message}</p>
                                        </div>
                                    )}
                                    {entry.metadata?.error && (
                                        <div className="p-3 rounded-xl bg-red-500/5 border border-red-500/10 text-xs font-bold text-red-400 font-mono">
                                            {entry.metadata.error}
                                        </div>
                                    )}

                                    {entry.logTail ? (
                                        <div className="relative group/log">
                                            <div className="absolute top-2 right-4 text-[9px] font-black text-neutral-700 uppercase tracking-widest group-hover/log:text-neutral-500 transition-colors">Console Snapshot</div>
                                            <pre className="p-5 bg-neutral-950 border border-neutral-800/50 rounded-xl text-[11px] leading-relaxed font-mono whitespace-pre-wrap word-break text-neutral-400 max-h-[400px] overflow-auto no-scrollbar">
                                                {entry.logTail}
                                            </pre>
                                        </div>
                                    ) : (
                                        <div className="text-[11px] text-neutral-600 italic px-1 lowercase">no console buffer captured for this event.</div>
                                    )}
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </ReactAppShell>
    );
}
